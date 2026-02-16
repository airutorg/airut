# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Configuration for email gateway service.

Server configuration is loaded from a YAML file.  The default location
follows the XDG Base Directory Specification:

    ``$XDG_CONFIG_HOME/airut/airut.yaml``
    (typically ``~/.config/airut/airut.yaml``)

``!env`` tags resolve values from environment variables.

The server config defines global settings (execution limits, dashboard) and
per-repo settings (email credentials, authorization, secrets).  Each repo
entry under ``repos:`` becomes a ``RepoServerConfig``.

Repo configuration (behaviour) is loaded from ``.airut/airut.yaml`` in each
repo's git mirror with support for ``!secret`` tags resolved against the
per-repo secrets pool.  ``!env`` is **not** allowed in repo config.

The module is self-contained (no dependency on ``airut/config.py``) so the
email gateway can be deployed independently.
"""

import logging
import os
import secrets as secrets_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, overload

import yaml
from platformdirs import user_config_path, user_state_path

from airut.gateway.dotenv_loader import load_dotenv_once
from airut.logging import SecretFilter


if TYPE_CHECKING:
    from airut.git_mirror import GitMirrorCache


logger = logging.getLogger(__name__)

#: Application name for XDG path resolution.
_APP_NAME = "airut"


def get_config_path() -> Path:
    """Return the default server config file path.

    Uses XDG: ``$XDG_CONFIG_HOME/airut/airut.yaml`` (typically
    ``~/.config/airut/airut.yaml``).

    Returns:
        Path to the config file.
    """
    return user_config_path(_APP_NAME) / "airut.yaml"


def get_dotenv_path() -> Path:
    """Return the default ``.env`` file path inside the XDG config directory.

    Uses XDG: ``$XDG_CONFIG_HOME/airut/.env`` (typically
    ``~/.config/airut/.env``).

    Returns:
        Path to the ``.env`` file.
    """
    return user_config_path(_APP_NAME) / ".env"


def get_storage_dir(repo_id: str) -> Path:
    """Return the storage directory for a repository.

    Uses XDG: ``$XDG_STATE_HOME/airut/<repo_id>`` (typically
    ``~/.local/state/airut/<repo_id>``).

    Args:
        repo_id: Repository identifier.

    Returns:
        Path to the repo's storage directory.
    """
    return user_state_path(_APP_NAME) / repo_id


#: Signing type identifier for AWS SigV4/SigV4A credential re-signing.
SIGNING_TYPE_AWS_SIGV4 = "aws-sigv4"

_BOOL_TRUTHY = frozenset({"true", "1", "yes", "on"})
_BOOL_FALSY = frozenset({"false", "0", "no", "off"})


class ConfigError(Exception):
    """Base exception for configuration errors."""


# ---------------------------------------------------------------------------
# Masked secrets (token replacement)
# ---------------------------------------------------------------------------

#: Fixed surrogate length for session tokens (STS tokens vary 400–1200+).
_SESSION_TOKEN_SURROGATE_LENGTH = 512


@dataclass(frozen=True)
class MaskedSecret:
    """A secret with scope restrictions for proxy-level replacement.

    Masked secrets are not injected directly into containers. Instead,
    a surrogate token is injected and the proxy swaps it for the real
    value only when the request host matches a scope pattern.

    Attributes:
        value: The real secret value.
        scopes: Fnmatch patterns for allowed hosts (e.g., "api.github.com").
        headers: Fnmatch patterns for headers to scan (e.g., "Authorization",
            "*" for all headers).
    """

    value: str
    scopes: frozenset[str]
    headers: tuple[str, ...]


@dataclass(frozen=True)
class ReplacementEntry:
    """Entry in the replacement map for proxy token swapping.

    Attributes:
        real_value: The actual secret to substitute.
        scopes: Fnmatch patterns for hosts where replacement is allowed.
        headers: Fnmatch patterns for headers to scan.
    """

    real_value: str
    scopes: tuple[str, ...]
    headers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            "value": self.real_value,
            "scopes": list(self.scopes),
            "headers": list(self.headers),
        }


@dataclass(frozen=True)
class SigningCredentialField:
    """A single field in a signing credential with name/value pair.

    The ``name`` is the secret name visible to repo config (via ``!secret``),
    and ``value`` is the real credential.
    """

    name: str
    value: str


@dataclass(frozen=True)
class SigningCredential:
    """AWS-style signing credential for proxy re-signing.

    Unlike masked secrets (simple token replacement), signing credentials
    require the proxy to re-sign requests using the real secret key.

    Each field has a ``name``/``value`` structure. The name declares the
    secret name visible to repo config; the repo uses plain ``!secret``
    references without knowing about signing credentials.

    Attributes:
        access_key_id: Access key ID with name/value.
        secret_access_key: Secret access key with name/value.
        session_token: Optional STS session token with name/value.
        scopes: Fnmatch patterns for allowed hosts.
    """

    access_key_id: SigningCredentialField
    secret_access_key: SigningCredentialField
    session_token: SigningCredentialField | None
    scopes: frozenset[str]


@dataclass(frozen=True)
class SigningCredentialEntry:
    """Entry in the replacement map for AWS-style signing credentials.

    Keyed by the surrogate access key ID. The proxy detects requests
    signed with the surrogate key ID and re-signs with real credentials.

    Attributes:
        access_key_id: Real access key ID.
        secret_access_key: Real secret access key.
        session_token: Real session token (optional).
        surrogate_session_token: Surrogate session token (for swapping).
        scopes: Fnmatch patterns for hosts where re-signing is allowed.
    """

    access_key_id: str
    secret_access_key: str
    session_token: str | None
    surrogate_session_token: str | None
    scopes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            "type": SIGNING_TYPE_AWS_SIGV4,
            "access_key_id": self.access_key_id,
            "secret_access_key": self.secret_access_key,
            "session_token": self.session_token,
            "surrogate_session_token": self.surrogate_session_token,
            "scopes": list(self.scopes),
        }


#: Mapping of surrogate token to replacement entry.
ReplacementMap = dict[str, ReplacementEntry | SigningCredentialEntry]


# Known token prefixes to preserve during surrogate generation.
_TOKEN_PREFIXES = (
    "github_pat_",  # GitHub fine-grained PAT
    "ghp_",  # GitHub personal access token
    "gho_",  # GitHub OAuth token
    "ghs_",  # GitHub server-to-server token
    "ghr_",  # GitHub refresh token
    "sk-ant-",  # Anthropic API key
    "sk-",  # OpenAI API key
    "xoxb-",  # Slack bot token
    "xoxp-",  # Slack user token
    "AKIA",  # AWS long-term access key ID
    "ASIA",  # AWS temporary access key ID (STS)
)


def generate_surrogate(original: str) -> str:
    """Generate a surrogate token that mimics the original's format.

    Preserves:
    - Exact length
    - Character set (uppercase, lowercase, digits, common special chars)
    - Known prefixes (ghp_, sk-ant-, etc.)

    Args:
        original: The original secret value.

    Returns:
        A random surrogate with matching format.
    """
    # Detect and preserve known prefix
    prefix = ""
    suffix_source = original
    for known in _TOKEN_PREFIXES:
        if original.startswith(known):
            prefix = known
            suffix_source = original[len(known) :]
            break

    # Analyze character set of the suffix
    has_upper = any(c.isupper() for c in suffix_source)
    has_lower = any(c.islower() for c in suffix_source)
    has_digit = any(c.isdigit() for c in suffix_source)
    has_special = any(not c.isalnum() for c in suffix_source)

    # Build charset for surrogate generation
    charset = ""
    if has_upper:
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if has_lower:
        charset += "abcdefghijklmnopqrstuvwxyz"
    if has_digit:
        charset += "0123456789"
    if has_special:
        # Use only safe special chars common in tokens
        charset += "-_"

    # Fallback if charset detection failed (e.g., empty suffix)
    if not charset:
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"

    # Generate random suffix of matching length
    suffix_len = len(suffix_source)
    random_suffix = "".join(
        secrets_module.choice(charset) for _ in range(suffix_len)
    )

    return prefix + random_suffix


def generate_session_token_surrogate() -> str:
    """Generate a fixed-length surrogate for AWS STS session tokens.

    STS tokens vary in length (400–1200+ chars). The surrogate uses a
    fixed length to avoid leaking information about the real token.

    Returns:
        A random 512-character alphanumeric string.
    """
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(
        secrets_module.choice(charset)
        for _ in range(_SESSION_TOKEN_SURROGATE_LENGTH)
    )


# ---------------------------------------------------------------------------
# YAML tag placeholders
# ---------------------------------------------------------------------------


class _EnvVar:
    """Placeholder for an unresolved ``!env VAR_NAME`` tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name


class _SecretRef:
    """Placeholder for ``!secret`` or ``!secret?`` tag in repo config.

    Attributes:
        name: The secret name to look up in the server's secrets pool.
        optional: If True (from ``!secret?``), missing secrets are silently
            skipped rather than raising an error.
    """

    def __init__(self, name: str, *, optional: bool = False) -> None:
        self.name = name
        self.optional = optional


def _env_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> _EnvVar:
    """Handle ``!env VAR_NAME`` in YAML."""
    value = loader.construct_scalar(node)
    return _EnvVar(str(value))


def _secret_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> _SecretRef:
    """Handle ``!secret NAME`` in YAML (required secret)."""
    value = loader.construct_scalar(node)
    return _SecretRef(str(value), optional=False)


def _secret_optional_constructor(
    loader: yaml.SafeLoader, node: yaml.Node
) -> _SecretRef:
    """Handle ``!secret? NAME`` in YAML (optional secret)."""
    value = loader.construct_scalar(node)
    return _SecretRef(str(value), optional=True)


def _reject_env_constructor(
    loader: yaml.SafeLoader, node: yaml.Node
) -> NoReturn:
    """Reject ``!env`` tags in repo config."""
    value = loader.construct_scalar(node)
    raise ConfigError(
        f"!env tags are not allowed in repo config "
        f"(found !env {value}). Use !secret to reference "
        f"server-provided secrets instead."
    )


def _make_loader() -> type[yaml.SafeLoader]:
    """Create a YAML loader that understands ``!env``."""

    class EnvLoader(yaml.SafeLoader):
        pass

    EnvLoader.add_constructor("!env", _env_constructor)
    return EnvLoader


def _make_repo_loader() -> type[yaml.SafeLoader]:
    """Create a YAML loader for repo config.

    Handles:
        - ``!secret NAME`` — required secret (error if missing)
        - ``!secret? NAME`` — optional secret (skip if missing)
        - ``!env`` — rejected (not allowed in repo config)
    """

    class RepoLoader(yaml.SafeLoader):
        pass

    RepoLoader.add_constructor("!secret", _secret_constructor)
    RepoLoader.add_constructor("!secret?", _secret_optional_constructor)
    RepoLoader.add_constructor("!env", _reject_env_constructor)
    return RepoLoader


# ---------------------------------------------------------------------------
# Value resolution
# ---------------------------------------------------------------------------


def _coerce_bool(value: object) -> bool:
    """Coerce a value to bool, handling string representations."""
    if isinstance(value, bool):
        return value
    s = str(value).lower().strip()
    if s in _BOOL_TRUTHY:
        return True
    if s in _BOOL_FALSY:
        return False
    raise ConfigError(f"Cannot convert {value!r} to bool")


def _raw_resolve(value: object) -> str | None:
    """Resolve an ``_EnvVar`` to its string value, or stringify literals.

    Returns None if the value is None or the env var is not set.
    Returns empty string if the env var is set to empty string.
    """
    if isinstance(value, _EnvVar):
        raw = os.environ.get(value.var_name)
        if raw is None:
            return None
        return raw
    if value is None:
        return None
    return str(value)


_MISSING = object()


@overload
def _resolve[T](value: object, coerce: type[T], *, default: T) -> T: ...


@overload
def _resolve[T](
    value: object,
    coerce: type[T],
    *,
    required: str,
) -> T: ...


@overload
def _resolve[T](value: object, coerce: type[T]) -> T | None: ...


def _resolve(
    value: object,
    coerce: type[Any],
    *,
    default: object = _MISSING,
    required: str = "",
) -> Any:
    """Resolve a YAML value, handling ``!env`` tags and type coercion.

    This is the single entry point for reading any config value.  It
    resolves ``_EnvVar`` placeholders, applies a default when the value
    is missing, and coerces to the target type.

    Args:
        value: Raw value from YAML (may be ``_EnvVar``, None, or a
            literal already parsed by PyYAML).
        coerce: Target type (``str``, ``int``, ``bool``, ``Path``).
        default: Default when value is absent.  Not allowed together
            with *required*.
        required: Human-readable field name.  When set, raises
            ``ConfigError`` if the value is absent.

    Returns:
        The resolved, coerced value, or None when optional and absent.
    """
    # For non-EnvVar values that PyYAML already parsed to the right
    # type (e.g. bool, int), skip string round-tripping when possible.
    if not isinstance(value, _EnvVar) and value is not None:
        if coerce is bool:
            return _coerce_bool(value)
        if isinstance(value, coerce):
            return value

    resolved = _raw_resolve(value)

    # Handle missing / empty
    if resolved is None:
        if required:
            if isinstance(value, _EnvVar):
                raise ConfigError(
                    f"Required config '{required}': environment variable "
                    f"'{value.var_name}' is not set"
                )
            raise ConfigError(f"Required config '{required}' is missing")
        if default is not _MISSING:
            return default
        return None

    # Coerce
    if coerce is bool:
        return _coerce_bool(resolved)
    if coerce is Path:
        return Path(resolved).expanduser()
    return coerce(resolved)


def _resolve_secrets(raw_secrets: dict) -> dict[str, str]:
    """Resolve a secrets mapping (``!env`` values from server config).

    Args:
        raw_secrets: Raw mapping from YAML (values may be ``_EnvVar``).

    Returns:
        Resolved mapping.  Entries whose value resolves to None (unset
        env var, missing YAML value) are excluded.  Empty strings are
        preserved — they represent intentionally empty values.
    """
    secrets: dict[str, str] = {}
    for key, value in raw_secrets.items():
        resolved = _raw_resolve(value)
        if resolved is not None:
            secrets[str(key)] = resolved
    return secrets


def _resolve_string_list(value: object, *, required: str = "") -> list[str]:
    """Resolve a list of strings, handling ``!env`` for each element.

    Args:
        value: Raw value from YAML (should be a list, may contain ``_EnvVar``).
        required: Human-readable field name.  When set, raises
            ``ConfigError`` if the value is absent or empty.

    Returns:
        List of resolved strings (non-empty values only).

    Raises:
        ConfigError: If value is not a list, or required and empty.
    """
    if value is None:
        if required:
            raise ConfigError(f"Required config '{required}' is missing")
        return []

    if not isinstance(value, list):
        raise ConfigError(
            f"Config '{required}' must be a list, got {type(value).__name__}"
        )

    result: list[str] = []
    for item in value:
        resolved = _raw_resolve(item)
        if resolved:
            result.append(resolved)

    if required and not result:
        raise ConfigError(f"Required config '{required}' is empty")

    return result


# ---------------------------------------------------------------------------
# Server configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GlobalConfig:
    """Global server settings shared across all repositories.

    Attributes:
        max_concurrent_executions: Max parallel Claude containers (global).
        shutdown_timeout_seconds: Graceful shutdown timeout.
        conversation_max_age_days: Max age before conversations are GC'd.
        dashboard_enabled: Enable dashboard server.
        dashboard_host: Dashboard bind address.
        dashboard_port: Dashboard server port.
        dashboard_base_url: Public URL for dashboard links in emails.
        container_command: Container runtime command (podman or docker).
        upstream_dns: Upstream DNS server for proxy container resolution.
            ``None`` means auto-detect from ``/etc/resolv.conf``.
    """

    max_concurrent_executions: int = 3
    shutdown_timeout_seconds: int = 60
    conversation_max_age_days: int = 7
    dashboard_enabled: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5200
    dashboard_base_url: str | None = None
    container_command: str = "podman"
    upstream_dns: str | None = None

    def __post_init__(self) -> None:
        """Validate configuration.

        Raises:
            ValueError: If configuration is invalid.
        """
        if self.max_concurrent_executions < 1:
            raise ValueError(
                f"Max concurrent executions must be >= 1: "
                f"{self.max_concurrent_executions}"
            )
        if self.shutdown_timeout_seconds < 1:
            raise ValueError(
                f"Shutdown timeout must be >= 1s: "
                f"{self.shutdown_timeout_seconds}"
            )
        if self.conversation_max_age_days < 1:
            raise ValueError(
                f"Conversation max age must be >= 1 day: "
                f"{self.conversation_max_age_days}"
            )


@dataclass(frozen=True)
class RepoServerConfig:
    """Per-repo server-side configuration.

    Contains email credentials, authorization, and secrets for a single
    repository.  Loaded from the ``repos.<name>`` section of the server
    config file.

    Storage location is determined by ``get_storage_dir(repo_id)`` using
    XDG state directory conventions.

    Attributes:
        repo_id: Repository identifier (key from ``repos`` mapping).
        git_repo_url: Git repository URL to clone from.
        imap_server: IMAP server hostname.
        imap_port: IMAP port.
        smtp_server: SMTP server hostname.
        smtp_port: SMTP port.
        email_username: Email account username.
        email_password: Email account password (auto-redacted in logs).
        email_from: From address for outgoing emails.
        authorized_senders: List of email patterns allowed to send commands.
            Supports wildcards (e.g., ``*@company.com``).
        trusted_authserv_id: The authserv-id to trust in
            Authentication-Results headers.  Set to empty string for
            Microsoft 365 / EOP which omits the authserv-id.
        poll_interval_seconds: Seconds between IMAP polls.
        use_imap_idle: Whether to use IMAP IDLE instead of polling.
        idle_reconnect_interval_seconds: Reconnect interval for IDLE mode.
        smtp_require_auth: Whether SMTP requires authentication.
        secrets: Per-repo secrets pool for ``!secret`` resolution.
        masked_secrets: Secrets with scope restrictions for proxy replacement.
        network_sandbox_enabled: Server-side override for the network sandbox.
            Effective sandbox state is the logical AND of this value and the
            repo config's ``network.sandbox_enabled``.  Defaults to ``True``.
        microsoft_internal_auth_fallback: When True and no
            ``Authentication-Results`` header is present, accept
            messages with ``X-MS-Exchange-Organization-AuthAs: Internal``
            as authenticated.  Covers intra-org email in Microsoft 365
            where EOP omits external authentication headers.
        microsoft_oauth2_tenant_id: Azure AD tenant ID for OAuth2 client
            credentials flow.  When set (along with client_id and
            client_secret), XOAUTH2 is used instead of password auth.
        microsoft_oauth2_client_id: Azure AD application (client) ID.
        microsoft_oauth2_client_secret: Azure AD client secret value
            (auto-redacted in logs).
    """

    repo_id: str
    git_repo_url: str
    imap_server: str
    imap_port: int
    smtp_server: str
    smtp_port: int
    email_username: str
    email_password: str
    email_from: str
    authorized_senders: list[str]
    trusted_authserv_id: str
    poll_interval_seconds: int = 60
    use_imap_idle: bool = True
    idle_reconnect_interval_seconds: int = 29 * 60
    smtp_require_auth: bool = True
    secrets: dict[str, str] = field(default_factory=dict)
    masked_secrets: dict[str, MaskedSecret] = field(default_factory=dict)
    signing_credentials: dict[str, SigningCredential] = field(
        default_factory=dict
    )
    network_sandbox_enabled: bool = True
    microsoft_internal_auth_fallback: bool = False
    microsoft_oauth2_tenant_id: str | None = None
    microsoft_oauth2_client_id: str | None = None
    microsoft_oauth2_client_secret: str | None = None

    def __post_init__(self) -> None:
        """Validate configuration and register secrets.

        Raises:
            ValueError: If configuration is invalid.
        """
        SecretFilter.register_secret(self.email_password)

        # Register Microsoft OAuth2 client secret for log redaction
        if self.microsoft_oauth2_client_secret:
            SecretFilter.register_secret(self.microsoft_oauth2_client_secret)

        # Validate Microsoft OAuth2: all three fields must be set or all None
        oauth2_fields = (
            self.microsoft_oauth2_tenant_id,
            self.microsoft_oauth2_client_id,
            self.microsoft_oauth2_client_secret,
        )
        oauth2_set = [f for f in oauth2_fields if f is not None]
        if 0 < len(oauth2_set) < 3:
            raise ValueError(
                f"Repo '{self.repo_id}': microsoft_oauth2 requires all three "
                f"fields (tenant_id, client_id, client_secret) to be set"
            )

        for value in self.secrets.values():
            if value:
                SecretFilter.register_secret(value)

        # Register masked secret real values for log redaction
        for masked in self.masked_secrets.values():
            if masked.value:
                SecretFilter.register_secret(masked.value)

        # Register signing credential real values for log redaction
        for signing in self.signing_credentials.values():
            SecretFilter.register_secret(signing.access_key_id.value)
            SecretFilter.register_secret(signing.secret_access_key.value)
            if signing.session_token:
                SecretFilter.register_secret(signing.session_token.value)

        if not self.git_repo_url:
            raise ValueError(
                f"Repo '{self.repo_id}': git.repo_url cannot be empty"
            )
        if not (1 <= self.imap_port <= 65535):
            raise ValueError(
                f"Repo '{self.repo_id}': invalid IMAP port: {self.imap_port}"
            )
        if not (1 <= self.smtp_port <= 65535):
            raise ValueError(
                f"Repo '{self.repo_id}': invalid SMTP port: {self.smtp_port}"
            )
        if self.poll_interval_seconds < 1:
            raise ValueError(
                f"Repo '{self.repo_id}': poll interval must be >= 1s: "
                f"{self.poll_interval_seconds}"
            )
        if self.idle_reconnect_interval_seconds < 60:
            raise ValueError(
                f"Repo '{self.repo_id}': IDLE reconnect interval must be "
                f">= 60s: {self.idle_reconnect_interval_seconds}"
            )

        logger.info(
            "Repo '%s' config loaded: imap=%s:%d, smtp=%s:%d, authorized=%s",
            self.repo_id,
            self.imap_server,
            self.imap_port,
            self.smtp_server,
            self.smtp_port,
            self.authorized_senders,
        )

    @property
    def storage_dir(self) -> Path:
        """Return the XDG state directory for this repo's persistent data."""
        return get_storage_dir(self.repo_id)


@dataclass(frozen=True)
class ServerConfig:
    """Complete server configuration.

    Combines global settings with per-repo configurations.

    Attributes:
        global_config: Global settings shared across all repos.
        repos: Per-repo server-side configurations keyed by repo ID.
    """

    global_config: GlobalConfig
    repos: dict[str, RepoServerConfig]

    def __post_init__(self) -> None:
        """Validate cross-repo constraints.

        Raises:
            ConfigError: If validation fails.
        """
        if not self.repos:
            raise ConfigError("At least one repo must be configured")

        # Validate no duplicate IMAP inboxes
        seen_inboxes: dict[tuple[str, str], str] = {}
        for repo_id, repo in self.repos.items():
            inbox_key = (repo.imap_server.lower(), repo.email_username.lower())
            if inbox_key in seen_inboxes:
                raise ConfigError(
                    f"Repo '{repo_id}' and repo '{seen_inboxes[inbox_key]}' "
                    f"share the same IMAP inbox "
                    f"({repo.imap_server}/{repo.email_username}). "
                    f"Each repo must have its own inbox."
                )
            seen_inboxes[inbox_key] = repo_id

        logger.info(
            "Server config loaded: %d repos, max_concurrent=%d",
            len(self.repos),
            self.global_config.max_concurrent_executions,
        )

    @classmethod
    def from_yaml(cls, config_path: Path | None = None) -> "ServerConfig":
        """Load configuration from a YAML file.

        Values tagged with ``!env VAR_NAME`` are resolved from the
        environment at load time.  A ``.env`` file is loaded first if
        present.

        Args:
            config_path: Path to YAML config file.  Defaults to
                ``~/.config/airut/airut.yaml`` (XDG).

        Returns:
            ServerConfig instance.

        Raises:
            ConfigError: If the file is missing or required values are absent.
        """
        load_dotenv_once()

        if config_path is None:
            config_path = get_config_path()

        if not config_path.exists():
            raise ConfigError(f"Config file not found: {config_path}")

        with open(config_path) as f:
            raw = yaml.load(f, Loader=_make_loader())

        if not isinstance(raw, dict):
            raise ConfigError(
                f"Config file must be a YAML mapping: {config_path}"
            )

        return cls._from_raw(raw)

    @classmethod
    def _from_raw(cls, raw: dict) -> "ServerConfig":
        """Build config from parsed (but unresolved) YAML dict."""
        execution = raw.get("execution", {})
        dashboard = raw.get("dashboard", {})

        network = raw.get("network", {})

        global_config = GlobalConfig(
            max_concurrent_executions=_resolve(
                execution.get("max_concurrent"), int, default=3
            ),
            shutdown_timeout_seconds=_resolve(
                execution.get("shutdown_timeout"), int, default=60
            ),
            conversation_max_age_days=_resolve(
                execution.get("conversation_max_age_days"), int, default=7
            ),
            dashboard_enabled=_resolve(
                dashboard.get("enabled"), bool, default=True
            ),
            dashboard_host=_resolve(
                dashboard.get("host"), str, default="127.0.0.1"
            ),
            dashboard_port=_resolve(dashboard.get("port"), int, default=5200),
            dashboard_base_url=_resolve(dashboard.get("base_url"), str),
            container_command=_resolve(
                raw.get("container_command"), str, default="podman"
            ),
            upstream_dns=_resolve(network.get("upstream_dns"), str),
        )

        # Parse repos
        raw_repos = raw.get("repos", {})
        if not isinstance(raw_repos, dict):
            raise ConfigError("'repos' must be a YAML mapping")

        repos: dict[str, RepoServerConfig] = {}
        for repo_id, repo_raw in raw_repos.items():
            repo_id = str(repo_id)
            if not isinstance(repo_raw, dict):
                raise ConfigError(f"repos.{repo_id} must be a YAML mapping")
            repos[repo_id] = _parse_repo_server_config(repo_id, repo_raw)

        return cls(global_config=global_config, repos=repos)


def _parse_repo_server_config(repo_id: str, raw: dict) -> RepoServerConfig:
    """Parse a single repo's server-side configuration.

    Args:
        repo_id: Repository identifier (key from ``repos``).
        raw: Raw YAML dict for this repo.

    Returns:
        RepoServerConfig instance.
    """
    email = raw.get("email", {})
    imap = raw.get("imap", {})
    network = raw.get("network", {})
    prefix = f"repos.{repo_id}"

    # Resolve per-repo secrets
    raw_secrets = raw.get("secrets", {})
    secrets = _resolve_secrets(raw_secrets)

    # Resolve masked secrets
    raw_masked = raw.get("masked_secrets", {})
    masked_secrets = _resolve_masked_secrets(raw_masked, prefix)

    # Resolve Microsoft OAuth2 config (optional block)
    ms_oauth2 = email.get("microsoft_oauth2", {})
    ms_tenant_id: str | None = (
        _resolve(ms_oauth2.get("tenant_id"), str) if ms_oauth2 else None
    )
    ms_client_id: str | None = (
        _resolve(ms_oauth2.get("client_id"), str) if ms_oauth2 else None
    )
    ms_client_secret: str | None = (
        _resolve(ms_oauth2.get("client_secret"), str) if ms_oauth2 else None
    )

    has_oauth2 = ms_tenant_id or ms_client_id or ms_client_secret

    # Resolve signing credentials
    raw_signing = raw.get("signing_credentials", {})
    signing_credentials = _resolve_signing_credentials(raw_signing, prefix)

    return RepoServerConfig(
        repo_id=repo_id,
        git_repo_url=_resolve(
            raw.get("git", {}).get("repo_url"),
            str,
            required=f"{prefix}.git.repo_url",
        ),
        imap_server=_resolve(
            email.get("imap_server"),
            str,
            required=f"{prefix}.email.imap_server",
        ),
        imap_port=_resolve(email.get("imap_port"), int, default=993),
        smtp_server=_resolve(
            email.get("smtp_server"),
            str,
            required=f"{prefix}.email.smtp_server",
        ),
        smtp_port=_resolve(email.get("smtp_port"), int, default=587),
        email_username=_resolve(
            email.get("username"),
            str,
            required=f"{prefix}.email.username",
        ),
        # email.password is required only when OAuth2 is not configured
        email_password=(
            _resolve(email.get("password"), str, default="")
            if has_oauth2
            else _resolve(
                email.get("password"),
                str,
                required=f"{prefix}.email.password",
            )
        ),
        email_from=_resolve(
            email.get("from"), str, required=f"{prefix}.email.from"
        ),
        authorized_senders=_resolve_string_list(
            raw.get("authorized_senders"),
            required=f"{prefix}.authorized_senders",
        ),
        trusted_authserv_id=_resolve(
            raw.get("trusted_authserv_id"),
            str,
            required=f"{prefix}.trusted_authserv_id",
        ),
        poll_interval_seconds=_resolve(
            imap.get("poll_interval"), int, default=60
        ),
        use_imap_idle=_resolve(imap.get("use_idle"), bool, default=True),
        idle_reconnect_interval_seconds=_resolve(
            imap.get("idle_reconnect_interval"), int, default=29 * 60
        ),
        secrets=secrets,
        masked_secrets=masked_secrets,
        signing_credentials=signing_credentials,
        network_sandbox_enabled=_resolve(
            network.get("sandbox_enabled"), bool, default=True
        ),
        microsoft_internal_auth_fallback=_resolve(
            raw.get("microsoft_internal_auth_fallback"), bool, default=False
        ),
        microsoft_oauth2_tenant_id=ms_tenant_id,
        microsoft_oauth2_client_id=ms_client_id,
        microsoft_oauth2_client_secret=ms_client_secret,
    )


def _resolve_masked_secrets(
    raw_masked: dict,
    prefix: str,
) -> dict[str, MaskedSecret]:
    """Resolve masked_secrets from server config.

    Args:
        raw_masked: Raw masked_secrets mapping from YAML.
        prefix: Config path prefix for error messages.

    Returns:
        Mapping of secret name to MaskedSecret.

    Raises:
        ConfigError: If structure is invalid or required fields missing.
    """
    result: dict[str, MaskedSecret] = {}

    for name, config in raw_masked.items():
        name = str(name)
        key = f"{prefix}.masked_secrets.{name}"

        if not isinstance(config, dict):
            raise ConfigError(
                f"{key} must be a mapping with 'value', 'scopes', and 'headers'"
            )

        # Resolve value (supports !env)
        raw_value = config.get("value")
        value = _raw_resolve(raw_value)

        # Skip if value is None (env var unset / YAML null)
        if value is None:
            continue

        # Parse scopes (required)
        raw_scopes = config.get("scopes")
        if raw_scopes is None:
            raise ConfigError(f"{key}.scopes is required")
        if not isinstance(raw_scopes, list):
            raise ConfigError(f"{key}.scopes must be a list")
        if not raw_scopes:
            raise ConfigError(f"{key}.scopes cannot be empty")

        scopes = frozenset(str(s) for s in raw_scopes)

        # Parse headers (required, supports fnmatch patterns like "*")
        raw_headers = config.get("headers")
        if raw_headers is None:
            raise ConfigError(f"{key}.headers is required")
        if not isinstance(raw_headers, list):
            raise ConfigError(f"{key}.headers must be a list")
        if not raw_headers:
            raise ConfigError(f"{key}.headers cannot be empty")

        headers = tuple(str(h) for h in raw_headers)

        result[name] = MaskedSecret(value=value, scopes=scopes, headers=headers)

    return result


# ---------------------------------------------------------------------------
def _resolve_signing_credential_field(
    raw: Any,
    field_path: str,
    *,
    required: bool = True,
) -> SigningCredentialField | None:
    """Resolve a signing credential field with name/value structure.

    Args:
        raw: Raw YAML value (should be a dict with 'name' and 'value').
        field_path: Config path for error messages.
        required: Whether the field is required.

    Returns:
        SigningCredentialField or None if optional and not present.
    """
    if raw is None:
        if required:
            raise ConfigError(f"{field_path} is required")
        return None

    if not isinstance(raw, dict):
        raise ConfigError(f"{field_path} must be a mapping with 'name'/'value'")

    name = raw.get("name")
    if not name:
        raise ConfigError(f"{field_path}.name is required")
    name = str(name)

    raw_value = raw.get("value")
    value = _raw_resolve(raw_value)
    if not value:
        if required:
            raise ConfigError(f"{field_path}.value is required")
        return None

    return SigningCredentialField(name=name, value=value)


def _resolve_signing_credentials(
    raw_signing: dict,
    prefix: str,
) -> dict[str, SigningCredential]:
    """Resolve signing_credentials from server config.

    Each credential field uses a ``name``/``value`` structure where
    ``name`` declares the secret name visible to repo config, and
    ``value`` provides the real credential.

    Args:
        raw_signing: Raw signing_credentials mapping from YAML.
        prefix: Config path prefix for error messages.

    Returns:
        Mapping of credential name to SigningCredential.

    Raises:
        ConfigError: If structure is invalid or required fields missing.
    """
    result: dict[str, SigningCredential] = {}

    for name, config in raw_signing.items():
        name = str(name)
        key = f"{prefix}.signing_credentials.{name}"

        if not isinstance(config, dict):
            raise ConfigError(f"{key} must be a mapping")

        # Validate type
        cred_type = config.get("type")
        if cred_type != SIGNING_TYPE_AWS_SIGV4:
            raise ConfigError(
                f"{key}.type must be 'aws-sigv4', got {cred_type!r}"
            )

        # Resolve access_key_id (required)
        access_key_id = _resolve_signing_credential_field(
            config.get("access_key_id"), f"{key}.access_key_id"
        )
        assert access_key_id is not None  # required field

        # Resolve secret_access_key (required)
        secret_access_key = _resolve_signing_credential_field(
            config.get("secret_access_key"), f"{key}.secret_access_key"
        )
        assert secret_access_key is not None  # required field

        # Resolve session_token (optional)
        session_token = _resolve_signing_credential_field(
            config.get("session_token"),
            f"{key}.session_token",
            required=False,
        )

        # Parse scopes (required)
        raw_scopes = config.get("scopes")
        if raw_scopes is None:
            raise ConfigError(f"{key}.scopes is required")
        if not isinstance(raw_scopes, list):
            raise ConfigError(f"{key}.scopes must be a list")
        if not raw_scopes:
            raise ConfigError(f"{key}.scopes cannot be empty")

        scopes = frozenset(str(s) for s in raw_scopes)

        result[name] = SigningCredential(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            scopes=scopes,
        )

    return result


# Repo configuration (loaded from .airut/airut.yaml in git mirror)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RepoConfig:
    """Repo-specific configuration loaded from ``.airut/airut.yaml``.

    Loaded from the git mirror at the start of each task.  Values tagged
    with ``!secret NAME`` are resolved from the server's secrets pool.
    ``!env`` tags are rejected.

    Attributes:
        default_model: Default Claude model when not specified via
            email subaddressing.
        timeout: Max container execution time in seconds.
        network_sandbox_enabled: Whether to enable the network sandbox.
        container_env: Environment variables passed to Claude containers.
            All values are redacted from logs.
    """

    default_model: str = "opus"
    timeout: int = 300
    network_sandbox_enabled: bool = True
    container_env: dict[str, str] = field(default_factory=dict)

    #: Path to the repo config file inside the repository.
    CONFIG_PATH = ".airut/airut.yaml"

    def __post_init__(self) -> None:
        """Validate configuration and register secrets.

        Raises:
            ValueError: If configuration is invalid.
        """
        for value in self.container_env.values():
            if value:
                SecretFilter.register_secret(value)

        if self.timeout < 10:
            raise ValueError(f"Timeout must be >= 10s: {self.timeout}")

    @classmethod
    def from_mirror(
        cls,
        mirror: "GitMirrorCache",
        server_secrets: dict[str, str],
        masked_secrets: dict[str, MaskedSecret] | None = None,
        signing_credentials: dict[str, SigningCredential] | None = None,
        *,
        server_sandbox_enabled: bool = True,
    ) -> tuple["RepoConfig", ReplacementMap]:
        """Load repo config from the git mirror.

        Reads ``.airut/airut.yaml`` from the mirror's default branch,
        parses it with ``!secret`` tag support, and resolves secret
        references against the server's secrets pool.

        When ``masked_secrets`` is provided, secrets found in that pool
        are replaced with surrogates, and a replacement map is returned
        for the proxy to swap them back for authorized hosts.

        When ``signing_credentials`` is provided, ``!secret`` references
        whose names match signing credential field names are resolved
        with surrogates. A ``SigningCredentialEntry`` is added to the
        replacement map for the proxy to re-sign requests.

        Args:
            mirror: Git mirror cache to read the file from.
            server_secrets: Server's secrets pool (name -> value).
            masked_secrets: Server's masked secrets pool with scope info.
            signing_credentials: Server's signing credentials pool.
            server_sandbox_enabled: Server-side network sandbox setting.
                The effective sandbox state is the logical AND of this
                value and the repo config's ``network.sandbox_enabled``.

        Returns:
            Tuple of (RepoConfig, ReplacementMap). The ReplacementMap
            will be empty if no masked secrets were referenced.

        Raises:
            ConfigError: If the file is missing, malformed, or references
                unknown secrets.
        """
        try:
            data = mirror.read_file(cls.CONFIG_PATH)
        except Exception as e:
            raise ConfigError(
                f"Failed to read repo config from mirror: {e}"
            ) from e

        raw = yaml.load(data, Loader=_make_repo_loader())

        if not isinstance(raw, dict):
            raise ConfigError(
                f"Repo config must be a YAML mapping: {cls.CONFIG_PATH}"
            )

        return cls._from_raw(
            raw,
            server_secrets,
            masked_secrets or {},
            signing_credentials=signing_credentials or {},
            server_sandbox_enabled=server_sandbox_enabled,
        )

    @classmethod
    def _from_raw(
        cls,
        raw: dict,
        server_secrets: dict[str, str],
        masked_secrets: dict[str, MaskedSecret],
        *,
        signing_credentials: dict[str, SigningCredential] | None = None,
        server_sandbox_enabled: bool = True,
    ) -> tuple["RepoConfig", ReplacementMap]:
        """Build repo config from parsed YAML dict."""
        # Reject !secret tags outside container_env — they would be
        # silently stringified by _resolve/_raw_resolve.
        _reject_stray_secret_refs(raw)

        network_raw = raw.get("network", {})

        # Resolve container_env: inline values + !secret references
        raw_container_env = raw.get("container_env", {})
        container_env, replacement_map = _resolve_container_env(
            raw_container_env,
            server_secrets,
            masked_secrets,
            signing_credentials=signing_credentials or {},
        )

        repo_sandbox = _resolve(
            network_raw.get("sandbox_enabled"), bool, default=True
        )
        # Effective sandbox = logical AND of server and repo settings.
        # Either side can disable it independently.
        effective_sandbox = server_sandbox_enabled and repo_sandbox

        if not effective_sandbox:
            logger.warning(
                "Network sandbox disabled (server=%s, repo=%s)",
                server_sandbox_enabled,
                repo_sandbox,
            )

        if not effective_sandbox and replacement_map:
            logger.warning(
                "Network sandbox is disabled but masked secrets are "
                "configured. Masked secrets require the proxy to swap "
                "surrogates for real values — they will not work without "
                "the sandbox. Consider using plain secrets instead, or "
                "re-enable the sandbox."
            )

        config = cls(
            default_model=_resolve(
                raw.get("default_model"), str, default="opus"
            ),
            timeout=_resolve(raw.get("timeout"), int, default=300),
            network_sandbox_enabled=effective_sandbox,
            container_env=container_env,
        )

        return config, replacement_map


def _reject_stray_secret_refs(raw: dict) -> None:
    """Raise if ``_SecretRef`` objects appear outside ``container_env``.

    The YAML loader creates ``_SecretRef`` for every ``!secret`` /
    ``!secret?`` tag, but only ``container_env`` knows how to resolve
    them.  Anywhere else they'd be silently stringified to garbage.
    """
    for key, value in raw.items():
        if key == "container_env":
            continue
        _check_secret_ref(value, key)


def _check_secret_ref(value: object, path: str) -> None:
    """Recursively check for ``_SecretRef`` in a parsed YAML value."""
    if isinstance(value, _SecretRef):
        tag = "!secret?" if value.optional else "!secret"
        raise ConfigError(
            f"{path}: {tag} '{value.name}' outside container_env — "
            f"!secret tags are only supported inside container_env"
        )
    if isinstance(value, dict):
        for k, v in value.items():
            _check_secret_ref(v, f"{path}.{k}")
    if isinstance(value, list):
        for i, v in enumerate(value):
            _check_secret_ref(v, f"{path}[{i}]")


@dataclass(frozen=True)
class _SigningSecretInfo:
    """Internal: links a secret name to its signing credential group."""

    cred_name: str
    field_name: str  # "access_key_id" | "secret_access_key" | "session_token"
    real_value: str
    credential: SigningCredential


def _build_signing_secret_map(
    signing_credentials: dict[str, SigningCredential],
) -> dict[str, _SigningSecretInfo]:
    """Build a mapping from secret name to signing credential info.

    This enables transparent ``!secret`` resolution — the repo config
    references secret names (e.g., ``AWS_ACCESS_KEY_ID``) without knowing
    they belong to a signing credential group.

    Args:
        signing_credentials: Resolved signing credentials from server config.

    Returns:
        Mapping of secret name to signing credential info.
    """
    result: dict[str, _SigningSecretInfo] = {}

    for cred_name, cred in signing_credentials.items():
        for field_name, field_obj in [
            ("access_key_id", cred.access_key_id),
            ("secret_access_key", cred.secret_access_key),
            ("session_token", cred.session_token),
        ]:
            if field_obj is None:
                continue
            result[field_obj.name] = _SigningSecretInfo(
                cred_name=cred_name,
                field_name=field_name,
                real_value=field_obj.value,
                credential=cred,
            )

    return result


def _resolve_container_env(
    raw_env: dict,
    server_secrets: dict[str, str],
    masked_secrets: dict[str, MaskedSecret],
    *,
    signing_credentials: dict[str, SigningCredential] | None = None,
) -> tuple[dict[str, str], ReplacementMap]:
    """Resolve container_env entries from repo config.

    Inline string values pass through.  ``_SecretRef`` placeholders
    are resolved from the server's secrets pool or masked_secrets pool.

    For masked secrets, a surrogate token is generated and added to the
    replacement map. The container receives the surrogate; the proxy
    swaps it for the real value when the request host matches the scopes.

    Signing credentials are resolved transparently: the repo config uses
    plain ``!secret`` references (e.g., ``!secret AWS_ACCESS_KEY_ID``),
    and the resolver detects that the secret name belongs to a signing
    credential group. Surrogates are generated and a
    ``SigningCredentialEntry`` is added to the replacement map keyed by
    the surrogate access key ID.

    Args:
        raw_env: Raw container_env mapping from YAML.
        server_secrets: Server's plain secrets pool.
        masked_secrets: Server's masked secrets pool with scope info.
        signing_credentials: Server's signing credentials pool.

    Returns:
        Tuple of (resolved env vars, replacement map for proxy).

    Raises:
        ConfigError: If a required ``!secret`` reference (not ``!secret?``)
            is not in either secrets pool.
    """
    resolved: dict[str, str] = {}
    replacement_map: ReplacementMap = {}
    signing_secret_map = _build_signing_secret_map(signing_credentials or {})

    # Track signing credentials that have been referenced so we can
    # build a single SigningCredentialEntry per credential set.
    # Maps credential name -> {field_name: (env_key, surrogate)}
    signing_refs: dict[str, dict[str, tuple[str, str]]] = {}

    for key, value in raw_env.items():
        if isinstance(value, _SecretRef):
            # Check if secret name belongs to a signing credential
            signing_info = signing_secret_map.get(value.name)
            if signing_info is not None:
                # Generate surrogate for the signing credential field
                if signing_info.field_name == "session_token":
                    surrogate = generate_session_token_surrogate()
                else:
                    surrogate = generate_surrogate(signing_info.real_value)

                resolved[str(key)] = surrogate

                # Track for building SigningCredentialEntry later
                cred_name = signing_info.cred_name
                if cred_name not in signing_refs:
                    signing_refs[cred_name] = {}
                signing_refs[cred_name][signing_info.field_name] = (
                    str(key),
                    surrogate,
                )
                continue

            # Check masked_secrets first
            if value.name in masked_secrets:
                masked = masked_secrets[value.name]
                if masked.value:
                    # Non-empty masked secret: generate surrogate
                    surrogate = generate_surrogate(masked.value)
                    resolved[str(key)] = surrogate
                    replacement_map[surrogate] = ReplacementEntry(
                        real_value=masked.value,
                        scopes=tuple(sorted(masked.scopes)),
                        headers=masked.headers,
                    )
                else:
                    # Empty string is a valid configured value
                    resolved[str(key)] = ""
                continue

            # Fall back to plain secrets
            if value.name in server_secrets:
                resolved[str(key)] = server_secrets[value.name]
                continue

            # Not found in any pool
            if value.optional:
                # !secret? — gracefully skip missing optional secrets
                continue
            raise ConfigError(
                f"container_env.{key}: !secret '{value.name}' "
                f"not found in server secrets pool"
            )
        else:
            # Inline value
            str_value = _raw_resolve(value)
            if str_value is not None:
                resolved[str(key)] = str_value

    # Build SigningCredentialEntry for each referenced signing credential.
    # Keyed by the surrogate access_key_id so the proxy can detect it.
    for cred_name, fields in signing_refs.items():
        signing_creds = signing_credentials or {}
        cred = signing_creds[cred_name]

        if "access_key_id" not in fields:
            raise ConfigError(
                f"Signing credential '{cred_name}' referenced but "
                f"'access_key_id' field not mapped in container_env"
            )

        surrogate_key_id = fields["access_key_id"][1]
        surrogate_session_token = (
            fields["session_token"][1] if "session_token" in fields else None
        )

        replacement_map[surrogate_key_id] = SigningCredentialEntry(
            access_key_id=cred.access_key_id.value,
            secret_access_key=cred.secret_access_key.value,
            session_token=(
                cred.session_token.value if cred.session_token else None
            ),
            surrogate_session_token=surrogate_session_token,
            scopes=tuple(sorted(cred.scopes)),
        )

    return resolved, replacement_map
