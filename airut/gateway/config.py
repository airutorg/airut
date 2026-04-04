# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Configuration for gateway service.

Server configuration is loaded from a YAML file.  The default location
follows the XDG Base Directory Specification:

    ``$XDG_CONFIG_HOME/airut/airut.yaml``
    (typically ``~/.config/airut/airut.yaml``)

``!env`` tags resolve values from environment variables.

The server config defines global settings (execution limits, dashboard) and
per-repo settings (channel credentials, authorization, secrets, model,
resource limits, container environment).  Each repo entry under ``repos:``
becomes a ``RepoServerConfig``.

The module is self-contained (no dependency on ``airut/config.py``) so the
gateway can be deployed independently.
"""

import logging
import secrets as secrets_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, overload

from platformdirs import user_config_path, user_state_path

from airut._json_types import JsonDict
from airut.config.schema import Scope, meta
from airut.gateway.channel import ChannelConfig
from airut.logging import SecretFilter
from airut.sandbox.types import ResourceLimits
from airut.yaml_env import EnvVar, YamlValue, raw_resolve


if TYPE_CHECKING:
    from airut.config.snapshot import ConfigSnapshot
    from airut.config.source import ConfigSource
    from airut.gateway.slack.config import SlackChannelConfig


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

#: Credential type identifier for GitHub App proxy-managed token rotation.
CREDENTIAL_TYPE_GITHUB_APP = "github-app"

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
        scopes: Host patterns where replacement applies
            (e.g., ``"api.github.com"``).
        headers: Header patterns to scan for surrogates
            (e.g., ``"Authorization"``, ``"*"`` for all headers).
        allow_foreign_credentials: If False (default), headers matching the
            scope+header patterns that do NOT contain the surrogate are
            stripped entirely. This prevents attacker-supplied credentials
            from reaching allowlisted hosts.
    """

    value: str = field(metadata=meta("Secret value", Scope.TASK, secret=True))
    scopes: frozenset[str] = field(
        metadata=meta(
            "Host patterns where replacement applies (e.g. api.github.com)",
            Scope.TASK,
        ),
    )
    headers: tuple[str, ...] = field(
        metadata=meta(
            "Header patterns to scan for surrogates"
            " (e.g. Authorization, or * for all)",
            Scope.TASK,
        ),
    )
    allow_foreign_credentials: bool = field(
        default=False,
        metadata=meta(
            "Allow non-surrogate credentials on scoped hosts"
            " (off = strip unrecognized tokens)",
            Scope.TASK,
        ),
    )


@dataclass(frozen=True)
class ReplacementEntry:
    """Entry in the replacement map for proxy token swapping.

    Attributes:
        real_value: The actual secret to substitute.
        scopes: Host patterns (fnmatch) where replacement is allowed.
        headers: Header patterns (fnmatch) to scan.
        allow_foreign_credentials: If False (default), headers matching
            scope+header patterns that do NOT contain the surrogate are
            stripped. Prevents attacker-supplied credentials on scoped hosts.
    """

    real_value: str
    scopes: tuple[str, ...]
    headers: tuple[str, ...]
    allow_foreign_credentials: bool = False

    def to_dict(self) -> JsonDict:
        """Serialize to dict for JSON export."""
        d: JsonDict = {
            "value": self.real_value,
            "scopes": list(self.scopes),
            "headers": list(self.headers),
        }
        if self.allow_foreign_credentials:
            d["allow_foreign_credentials"] = True
        return d


@dataclass(frozen=True)
class SigningCredentialField:
    """A single field in a signing credential with name/value pair.

    The ``name`` is the environment variable name injected into the container,
    and ``value`` is the real credential.
    """

    name: str = field(
        metadata=meta(
            "Environment variable name for the container", Scope.TASK
        ),
    )
    value: str = field(
        metadata=meta(
            "Credential value (proxy uses this to re-sign)",
            Scope.TASK,
            secret=True,
        ),
    )


@dataclass(frozen=True)
class SigningCredential:
    """AWS-style signing credential for proxy re-signing.

    Unlike masked secrets (simple token replacement), signing credentials
    require the proxy to re-sign requests using the real secret key.

    Each field has a ``name``/``value`` structure. The name declares the
    environment variable name injected into the container; the value is the
    real credential used by the proxy for re-signing.

    Attributes:
        access_key_id: Access key ID with name/value.
        secret_access_key: Secret access key with name/value.
        session_token: Optional STS session token with name/value.
        scopes: Host patterns (fnmatch) for allowed hosts.
    """

    access_key_id: SigningCredentialField = field(
        metadata=meta("AWS access key ID", Scope.TASK, secret=True),
    )
    secret_access_key: SigningCredentialField = field(
        metadata=meta("AWS secret access key", Scope.TASK, secret=True),
    )
    scopes: frozenset[str] = field(
        metadata=meta(
            "Host patterns where re-signing applies"
            " (e.g. bedrock.us-east-1.amazonaws.com)",
            Scope.TASK,
        ),
    )
    session_token: SigningCredentialField | None = field(
        default=None,
        metadata=meta(
            "STS session token (for temporary credentials)",
            Scope.TASK,
            secret=True,
        ),
    )


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
        scopes: Host patterns (fnmatch) where re-signing is allowed.
    """

    access_key_id: str
    secret_access_key: str
    session_token: str | None
    surrogate_session_token: str | None
    scopes: tuple[str, ...]

    def to_dict(self) -> JsonDict:
        """Serialize to dict for JSON export."""
        return {
            "type": SIGNING_TYPE_AWS_SIGV4,
            "access_key_id": self.access_key_id,
            "secret_access_key": self.secret_access_key,
            "session_token": self.session_token,
            "surrogate_session_token": self.surrogate_session_token,
            "scopes": list(self.scopes),
        }


@dataclass(frozen=True)
class GitHubAppCredential:
    """GitHub App credential for proxy-managed token rotation.

    The proxy holds the private key and generates short-lived installation
    access tokens on demand.  The container sees only a stable surrogate.

    Attributes:
        app_id: GitHub App Client ID or numeric App ID.
        private_key: PEM-encoded RSA private key.
        installation_id: Installation ID for the target org/user.
        scopes: Fnmatch patterns for hosts where token replacement applies.
        allow_foreign_credentials: If False (default), non-surrogate
            Authorization headers on scoped hosts are stripped.
        base_url: GitHub API base URL (default: https://api.github.com).
        permissions: Optional token permission restrictions.
        repositories: Optional token repository restrictions.
    """

    app_id: str = field(
        metadata=meta("GitHub App Client ID or numeric App ID", Scope.TASK),
    )
    private_key: str = field(
        metadata=meta("PEM-encoded RSA private key", Scope.TASK, secret=True),
    )
    installation_id: int = field(
        metadata=meta("Installation ID for the target org/user", Scope.TASK),
    )
    scopes: frozenset[str] = field(
        metadata=meta(
            "Host patterns where token replacement applies"
            " (e.g. api.github.com)",
            Scope.TASK,
        ),
    )
    allow_foreign_credentials: bool = field(
        default=False,
        metadata=meta(
            "Allow non-surrogate credentials on scoped hosts"
            " (off = strip unrecognized tokens)",
            Scope.TASK,
        ),
    )
    base_url: str = field(
        default="https://api.github.com",
        metadata=meta(
            "GitHub API base URL (change for GitHub Enterprise)", Scope.TASK
        ),
    )
    permissions: dict[str, str] | None = field(
        default=None,
        metadata=meta(
            "Restrict token permissions (e.g. contents: read)", Scope.TASK
        ),
    )
    repositories: tuple[str, ...] | None = field(
        default=None,
        metadata=meta("Restrict token to specific repositories", Scope.TASK),
    )


@dataclass(frozen=True)
class GitHubAppEntry:
    """Entry in the replacement map for GitHub App credentials.

    Keyed by the surrogate ``ghs_``-prefixed token.  The proxy detects
    requests with the surrogate in the Authorization header and replaces
    it with a real installation access token (generating/refreshing as
    needed).

    Attributes:
        app_id: GitHub App Client ID or numeric App ID.
        private_key: PEM-encoded RSA private key.
        installation_id: Installation ID for the target org/user.
        base_url: GitHub API base URL.
        scopes: Host patterns where replacement is allowed.
        allow_foreign_credentials: Whether to allow non-surrogate credentials.
        permissions: Optional token permission restrictions.
        repositories: Optional token repository restrictions.
    """

    app_id: str
    private_key: str
    installation_id: int
    base_url: str
    scopes: tuple[str, ...]
    allow_foreign_credentials: bool = False
    permissions: dict[str, str] | None = None
    repositories: tuple[str, ...] | None = None

    def to_dict(self) -> JsonDict:
        """Serialize to dict for JSON export."""
        d: JsonDict = {
            "type": CREDENTIAL_TYPE_GITHUB_APP,
            "app_id": self.app_id,
            "private_key": self.private_key,
            "installation_id": self.installation_id,
            "base_url": self.base_url,
            "scopes": list(self.scopes),
        }
        if self.allow_foreign_credentials:
            d["allow_foreign_credentials"] = True
        if self.permissions is not None:
            d["permissions"] = dict(self.permissions)
        if self.repositories is not None:
            d["repositories"] = list(self.repositories)
        return d


#: Mapping of surrogate token to replacement entry.
ReplacementMap = dict[
    str, ReplacementEntry | SigningCredentialEntry | GitHubAppEntry
]


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


# Template for GitHub App surrogates: ghs_ prefix + 36 mixed-case
# alphanumeric chars = 40 chars total (matches real ghs_ token format).
_GITHUB_APP_SURROGATE_TEMPLATE = "ghs_" + "aA0" * 12


def generate_github_app_surrogate() -> str:
    """Generate a ``ghs_``-prefixed surrogate for GitHub App credentials.

    The surrogate mimics a real GitHub installation token format:
    ``ghs_`` prefix followed by 36 alphanumeric characters.

    Returns:
        A random ``ghs_``-prefixed 40-character alphanumeric string.
    """
    return generate_surrogate(_GITHUB_APP_SURROGATE_TEMPLATE)


# ---------------------------------------------------------------------------
# Value resolution
# ---------------------------------------------------------------------------


def _coerce_bool(value: YamlValue) -> bool:
    """Coerce a value to bool, handling string representations."""
    if isinstance(value, bool):
        return value
    s = str(value).lower().strip()
    if s in _BOOL_TRUTHY:
        return True
    if s in _BOOL_FALSY:
        return False
    raise ConfigError(f"Cannot convert {value!r} to bool")


_MISSING = object()


@overload
def _resolve[T](value: YamlValue, coerce: type[T], *, default: T) -> T: ...


@overload
def _resolve[T](
    value: YamlValue,
    coerce: type[T],
    *,
    required: str,
) -> T: ...


@overload
def _resolve[T](value: YamlValue, coerce: type[T]) -> T | None: ...


def _resolve(
    value: YamlValue,
    coerce: type,
    *,
    default: object = _MISSING,
    required: str = "",
):
    """Resolve a YAML value, handling ``!env`` tags and type coercion.

    This is the single entry point for reading any config value.  It
    resolves ``EnvVar`` placeholders, applies a default when the value
    is missing, and coerces to the target type.

    Args:
        value: Raw value from YAML (may be ``EnvVar``, None, or a
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
    if not isinstance(value, EnvVar) and value is not None:
        if coerce is bool:
            return _coerce_bool(value)
        if isinstance(value, coerce):
            return value

    resolved = raw_resolve(value)

    # Handle missing / empty
    if resolved is None:
        if required:
            if isinstance(value, EnvVar):
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
        raw_secrets: Raw mapping from YAML (values may be ``EnvVar``).

    Returns:
        Resolved mapping.  Entries whose value resolves to None (unset
        env var, missing YAML value) are excluded.  Empty strings are
        preserved — they represent intentionally empty values.
    """
    secrets: dict[str, str] = {}
    for key, value in raw_secrets.items():
        resolved = raw_resolve(value)
        if resolved is not None:
            secrets[str(key)] = resolved
    return secrets


def _resolve_string_list(value: YamlValue, *, required: str = "") -> list[str]:
    """Resolve a list of strings, handling ``!env`` for each element.

    Args:
        value: Raw value from YAML (should be a list, may contain ``EnvVar``).
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
    for item in cast(list[YamlValue], value):
        resolved = raw_resolve(item)
        if resolved:
            result.append(resolved)

    if required and not result:
        raise ConfigError(f"Required config '{required}' is empty")

    return result


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------


def _parse_resource_limits(raw: dict | None) -> ResourceLimits | None:
    """Parse a ``resource_limits`` YAML block.

    Args:
        raw: Raw mapping from YAML, or None.

    Returns:
        ResourceLimits instance, or None if input is None/empty.
    """
    if not raw:
        return None

    return ResourceLimits(
        timeout=_resolve(raw.get("timeout"), int),
        memory=_resolve(raw.get("memory"), str),
        cpus=_resolve(raw.get("cpus"), float),
        pids_limit=_resolve(raw.get("pids_limit"), int),
    )


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
        image_prune: Prune dangling container images during GC.
        dashboard_enabled: Enable dashboard server.
        dashboard_host: Dashboard bind address.
        dashboard_port: Dashboard server port.
        dashboard_base_url: Public URL for dashboard links in emails.
            ``None`` means links are omitted.
        container_command: Container runtime command (test-only; production
            requires podman).
        upstream_dns: Upstream DNS server for proxy container resolution.
            ``None`` means auto-detect from ``/etc/resolv.conf``.
    """

    max_concurrent_executions: int = field(
        default=3,
        metadata=meta(
            "Maximum parallel Claude containers across all repos",
            Scope.SERVER,
        ),
    )
    shutdown_timeout_seconds: int = field(
        default=60,
        metadata=meta(
            "Seconds to wait for running tasks during graceful shutdown",
            Scope.SERVER,
        ),
    )
    conversation_max_age_days: int = field(
        default=7,
        metadata=meta(
            "Max age in days before conversations are garbage-collected",
            Scope.SERVER,
        ),
    )
    image_prune: bool = field(
        default=True,
        metadata=meta(
            "Prune dangling container images during garbage collection",
            Scope.SERVER,
        ),
    )
    dashboard_enabled: bool = field(
        default=True,
        metadata=meta(
            "Enable the web dashboard for task monitoring",
            Scope.SERVER,
        ),
    )
    dashboard_host: str = field(
        default="127.0.0.1",
        metadata=meta("Dashboard HTTP server bind address", Scope.SERVER),
    )
    dashboard_port: int = field(
        default=5200,
        metadata=meta("Dashboard HTTP server port", Scope.SERVER),
    )
    dashboard_base_url: str | None = field(
        default=None,
        metadata=meta(
            "Public URL for dashboard links in emails (omitted if empty)",
            Scope.SERVER,
        ),
    )
    container_command: str = field(
        default="podman",
        metadata=meta(
            "Container runtime command (test-only; production requires podman)",
            Scope.SERVER,
            hidden=True,
        ),
    )
    upstream_dns: str | None = field(
        default=None,
        metadata=meta(
            "Upstream DNS server for proxy resolution (auto-detected if empty)",
            Scope.SERVER,
        ),
    )

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
class EmailAccountConfig:
    """Email account credentials.

    Attributes:
        username: Email account username.
        from_address: From address for outgoing emails.
        password: Email account password (auto-redacted in logs).
            Optional when Microsoft OAuth2 is configured.
    """

    username: str = field(
        metadata=meta("Email account username", Scope.REPO),
    )
    from_address: str = field(
        metadata=meta("From address for outgoing emails", Scope.REPO),
    )
    password: str | None = field(
        default=None,
        metadata=meta(
            "Email account password (not required with OAuth2)",
            Scope.REPO,
            secret=True,
        ),
    )


@dataclass(frozen=True)
class ImapConfig:
    """IMAP server configuration.

    Attributes:
        server: IMAP server hostname.
        port: IMAP port.
        connect_retries: Max connection attempts before giving up.
        poll_interval: Seconds between IMAP polls.
        use_idle: Whether to use IMAP IDLE instead of polling.
        idle_reconnect_interval: Reconnect interval in seconds for IDLE
            mode.
    """

    server: str = field(
        metadata=meta("IMAP server hostname", Scope.REPO),
    )
    port: int = field(
        default=993,
        metadata=meta("IMAP port", Scope.REPO),
    )
    connect_retries: int = field(
        default=3,
        metadata=meta(
            "Max IMAP connection attempts before giving up",
            Scope.REPO,
        ),
    )
    poll_interval: float = field(
        default=60,
        metadata=meta("Seconds between IMAP polls", Scope.REPO),
    )
    use_idle: bool = field(
        default=True,
        metadata=meta("Use IMAP IDLE instead of polling", Scope.REPO),
    )
    idle_reconnect_interval: float = field(
        default=29 * 60,
        metadata=meta(
            "IDLE reconnect interval in seconds"
            " (servers may close after 30 min)",
            Scope.REPO,
        ),
    )

    def __post_init__(self) -> None:
        """Validate IMAP configuration."""
        if self.connect_retries < 1:
            raise ValueError(
                f"connect_retries must be >= 1: {self.connect_retries}"
            )
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid IMAP port: {self.port}")
        if self.poll_interval < 0.1:
            raise ValueError(
                f"Poll interval must be >= 0.1s: {self.poll_interval}"
            )
        if self.idle_reconnect_interval < 60:
            raise ValueError(
                f"IDLE reconnect interval must be >= 60s: "
                f"{self.idle_reconnect_interval}"
            )


@dataclass(frozen=True)
class SmtpConfig:
    """SMTP server configuration.

    Attributes:
        server: SMTP server hostname.
        port: SMTP port.
        require_auth: Whether SMTP requires authentication.
    """

    server: str = field(
        metadata=meta("SMTP server hostname", Scope.REPO),
    )
    port: int = field(
        default=587,
        metadata=meta("SMTP port", Scope.REPO),
    )
    require_auth: bool = field(
        default=True,
        metadata=meta("Whether SMTP requires authentication", Scope.REPO),
    )

    def __post_init__(self) -> None:
        """Validate SMTP configuration."""
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid SMTP port: {self.port}")


@dataclass(frozen=True)
class EmailAuthConfig:
    """Email sender authorization configuration.

    Attributes:
        authorized_senders: Email patterns allowed to send commands.
            Supports wildcards (e.g., ``*@company.com``).
        trusted_authserv_id: Trusted authserv-id for DMARC verification.
            Set to empty string for Microsoft 365 / EOP.
        microsoft_internal_fallback: Accept Microsoft 365 intra-org
            messages when DMARC headers are absent.
    """

    authorized_senders: list[str] = field(
        metadata=meta(
            "Email patterns allowed to send commands (e.g. *@company.com)",
            Scope.REPO,
        ),
    )
    trusted_authserv_id: str = field(
        metadata=meta(
            "Trusted authserv-id for DMARC verification"
            " (empty string for Microsoft 365)",
            Scope.REPO,
        ),
    )
    microsoft_internal_fallback: bool = field(
        default=False,
        metadata=meta(
            "Accept Microsoft 365 intra-org messages"
            " when DMARC headers are absent",
            Scope.REPO,
        ),
    )


@dataclass(frozen=True)
class MicrosoftOAuth2Config:
    """Microsoft 365 OAuth2 client credentials configuration.

    All three fields must be set together.

    Attributes:
        tenant_id: Azure AD tenant ID.
        client_id: Azure AD application (client) ID.
        client_secret: Azure AD client secret value (auto-redacted).
    """

    tenant_id: str = field(
        metadata=meta(
            "Azure AD tenant ID for OAuth2 client credentials flow",
            Scope.REPO,
            secret=True,
        ),
    )
    client_id: str = field(
        metadata=meta("Azure AD application (client) ID", Scope.REPO),
    )
    client_secret: str = field(
        metadata=meta(
            "Azure AD client secret value",
            Scope.REPO,
            secret=True,
        ),
    )


@dataclass(frozen=True)
class EmailChannelConfig(ChannelConfig):
    """Email channel configuration (IMAP + SMTP).

    Contains all settings specific to the email channel: mail server
    connectivity, credentials, sender authorization, and polling behaviour.

    Attributes:
        account: Email account credentials (username, password, from).
        imap: IMAP server settings and polling behaviour.
        smtp: SMTP server settings.
        auth: Sender authorization and DMARC verification.
        microsoft_oauth2: Optional Microsoft 365 OAuth2 credentials.
    """

    account: EmailAccountConfig = field(
        metadata=meta("Email account credentials", Scope.REPO),
    )
    imap: ImapConfig = field(
        metadata=meta("IMAP server settings", Scope.REPO),
    )
    smtp: SmtpConfig = field(
        metadata=meta("SMTP server settings", Scope.REPO),
    )
    auth: EmailAuthConfig = field(
        metadata=meta("Sender authorization settings", Scope.REPO),
    )
    microsoft_oauth2: MicrosoftOAuth2Config | None = field(
        default=None,
        metadata=meta("Microsoft 365 OAuth2 credentials", Scope.REPO),
    )

    def __post_init__(self) -> None:
        """Validate email configuration and register secrets.

        Raises:
            ValueError: If configuration is invalid.
        """
        if self.account.password:
            SecretFilter.register_secret(self.account.password)

        if self.microsoft_oauth2:
            if self.microsoft_oauth2.client_secret:
                SecretFilter.register_secret(
                    self.microsoft_oauth2.client_secret
                )
        elif not self.account.password:
            raise ValueError(
                "email.account.password is required when microsoft_oauth2 "
                "is not configured"
            )

    @property
    def channel_type(self) -> str:
        """Return the channel type identifier."""
        return "email"

    @property
    def channel_info(self) -> str:
        """Return a short description for dashboard display."""
        return self.imap.server

    @property
    def channel_detail(self) -> str:
        """Return agent email address for dashboard display."""
        return self.account.from_address


# ---------------------------------------------------------------------------
# Schedule configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScheduleDelivery:
    """Delivery target for a scheduled task result.

    Attributes:
        to: Recipient address (email address).
        channel: Delivery channel type (default: email).
    """

    to: str = field(
        metadata=meta("Recipient address (email address)", Scope.REPO),
    )
    channel: str = field(
        default="email",
        metadata=meta(
            "Delivery channel type (default: email)",
            Scope.REPO,
        ),
    )


@dataclass(frozen=True)
class ScheduleConfig:
    """A single periodic task schedule.

    Exactly one of ``prompt`` or ``trigger_command`` must be set.

    Attributes:
        cron: 5-field cron expression (minute hour dom month dow).
        deliver: Delivery target for task results.
        subject: Override email subject (empty = schedule name).
        timezone: IANA timezone for cron evaluation.
        prompt: Prompt text for prompt mode.
        trigger_command: Shell command for script mode.
        trigger_timeout: Timeout override for trigger command.
        model: Override repo default model.
        effort: Override repo default effort level.
        output_limit: Max script output bytes (default 100KB).
    """

    cron: str = field(
        metadata=meta(
            "5-field cron expression (minute hour dom month dow)", Scope.REPO
        ),
    )
    deliver: ScheduleDelivery = field(
        metadata=meta("Delivery target for task results", Scope.REPO),
    )
    subject: str | None = field(
        default=None,
        metadata=meta(
            "Override email subject line (empty = schedule name)",
            Scope.REPO,
        ),
    )
    timezone: str | None = field(
        default=None,
        metadata=meta(
            "IANA timezone for cron evaluation (empty = server local time)",
            Scope.REPO,
        ),
    )
    prompt: str | None = field(
        default=None,
        metadata=meta(
            "Prompt text (mutually exclusive with trigger_command)",
            Scope.REPO,
        ),
    )
    trigger_command: str | None = field(
        default=None,
        metadata=meta(
            "Shell command for script mode (mutually exclusive with prompt)",
            Scope.REPO,
        ),
    )
    trigger_timeout: int | None = field(
        default=None,
        metadata=meta(
            "Timeout override for trigger command"
            " (empty = repo resource_limits default)",
            Scope.REPO,
        ),
    )
    model: str | None = field(
        default=None,
        metadata=meta("Override repo default model", Scope.TASK),
    )
    effort: str | None = field(
        default=None,
        metadata=meta("Override repo default effort level", Scope.TASK),
    )
    output_limit: int = field(
        default=102400,
        metadata=meta("Max script output bytes (default 100KB)", Scope.REPO),
    )


#: Channel type keys recognized in server config.
#: Extend as new channel types are added.
CHANNEL_KEYS = {"email", "slack"}


@dataclass(frozen=True)
class RepoServerConfig:
    """Per-repo server-side configuration.

    Contains all configuration for a single repository: channel configs,
    credentials, model/effort defaults, resource limits, and container
    environment.  Loaded from the ``repos.<name>`` section of the server
    config file.

    Storage location is determined by ``get_storage_dir(repo_id)`` using
    XDG state directory conventions.

    Attributes:
        repo_id: Repository identifier (key from ``repos`` mapping).
        git_repo_url: Git repository URL to clone from.
        channels: Channel configurations keyed by channel type
            (e.g. ``{"email": EmailChannelConfig(...)}``)
        secrets: Per-repo secrets pool.  Keys become container env var names.
        masked_secrets: Scoped secrets replaced by proxy at request time.
            Keys become container env var names with surrogates injected.
            Requires ``network_sandbox_enabled``.
        signing_credentials: Signing credentials for proxy re-signing.
            Field ``.name`` values become container env var names.
        github_app_credentials: GitHub App credentials for proxy-managed
            token rotation.  Keys become container env var names.
        network_sandbox_enabled: Route container traffic through the
            network proxy and enforce the allowlist.  Required for
            masked, signing, and GitHub App credentials.  Defaults to
            ``True``.
        model: Default Claude model for new conversations.  Channel
            ``model_hint`` overrides this.  Defaults to ``"opus"``.
        effort: Effort level for Claude Code (low, medium, high, max).
            ``None`` omits the flag, letting Claude use its own default.
        resource_limits: Container resource limits (timeout, memory,
            cpus, pids_limit).  Use ``!var`` references for shared defaults.
    """

    repo_id: str = field(
        metadata=meta("Repository identifier", Scope.REPO),
    )
    git_repo_url: str = field(
        metadata=meta("Git repository URL to clone from", Scope.REPO),
    )
    channels: dict[str, ChannelConfig] = field(
        metadata=meta("Channel configurations keyed by type", Scope.REPO),
    )
    secrets: dict[str, str] = field(
        default_factory=dict,
        metadata=meta(
            "Per-repo secrets pool (keys become container env var names)",
            Scope.TASK,
            secret=True,
        ),
    )
    masked_secrets: dict[str, MaskedSecret] = field(
        default_factory=dict,
        metadata=meta(
            "Scoped secrets replaced by proxy at request time"
            " (requires network sandbox)",
            Scope.TASK,
            secret=True,
        ),
    )
    signing_credentials: dict[str, SigningCredential] = field(
        default_factory=dict,
        metadata=meta(
            "AWS SigV4/SigV4A signing credentials for proxy re-signing",
            Scope.TASK,
            secret=True,
        ),
    )
    github_app_credentials: dict[str, GitHubAppCredential] = field(
        default_factory=dict,
        metadata=meta(
            "GitHub App credentials for proxy-managed token rotation",
            Scope.TASK,
            secret=True,
        ),
    )
    network_sandbox_enabled: bool = field(
        default=True,
        metadata=meta(
            "Route container traffic through the network proxy"
            " and enforce the allowlist"
            " (required for masked/signing/GitHub App credentials)",
            Scope.REPO,
        ),
    )
    model: str = field(
        default="opus",
        metadata=meta("Claude model for new conversations", Scope.TASK),
    )
    effort: str | None = field(
        default=None,
        metadata=meta(
            "Effort level: low, medium, high, or max (empty = Claude default)",
            Scope.TASK,
        ),
    )
    resource_limits: ResourceLimits = field(
        default_factory=ResourceLimits,
        metadata=meta(
            "Container resource limits (use !var for shared defaults)",
            Scope.TASK,
        ),
    )
    claude_version: str = field(
        default="latest",
        metadata=meta(
            "Claude Code version (semver, 'latest', or 'stable')",
            Scope.TASK,
        ),
    )
    container_path: str = field(
        default=".airut/container",
        metadata=meta(
            "Path to container directory within the repo"
            " (must contain a Dockerfile)",
            Scope.REPO,
        ),
    )
    schedules: dict[str, ScheduleConfig] = field(
        default_factory=dict,
        metadata=meta(
            "Periodic task schedules keyed by name",
            Scope.REPO,
        ),
    )

    def __post_init__(self) -> None:
        """Validate configuration and register secrets.

        Raises:
            ValueError: If configuration is invalid.
        """
        # Normalize empty strings to defaults (frozen → use object.__setattr__)
        if not self.model:
            object.__setattr__(self, "model", "opus")
        if self.effort is not None and not self.effort:
            object.__setattr__(self, "effort", None)

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

        # Register GitHub App private keys for log redaction
        for gh_app in self.github_app_credentials.values():
            SecretFilter.register_secret(gh_app.private_key)

        if not self.container_path:
            raise ValueError(
                f"Repo '{self.repo_id}': container_path cannot be empty"
            )
        if self.container_path.startswith("/"):
            raise ValueError(
                f"Repo '{self.repo_id}': container_path must be a relative "
                f"path, got '{self.container_path}'"
            )
        if ".." in self.container_path.split("/"):
            raise ValueError(
                f"Repo '{self.repo_id}': container_path must not contain "
                f"'..', got '{self.container_path}'"
            )

        if not self.git_repo_url:
            raise ValueError(f"Repo '{self.repo_id}': repo_url cannot be empty")

        if not self.channels:
            raise ValueError(
                f"Repo '{self.repo_id}': at least one channel must be "
                f"configured"
            )

        unknown = self.channels.keys() - CHANNEL_KEYS
        if unknown:
            raise ValueError(
                f"Repo '{self.repo_id}': unknown channel type(s): "
                f"{', '.join(sorted(unknown))}. "
                f"Supported: {', '.join(sorted(CHANNEL_KEYS))}"
            )

        # Validate schedules
        if self.schedules:
            from zoneinfo import ZoneInfo

            from airut.gateway.scheduler.cron import CronExpression

            for sched_name, sched in self.schedules.items():
                sched_prefix = f"repos.{self.repo_id}.schedules.{sched_name}"
                if sched.prompt is None and sched.trigger_command is None:
                    raise ValueError(
                        f"{sched_prefix}: exactly one of 'prompt' or "
                        f"'trigger_command' must be set"
                    )
                if (
                    sched.prompt is not None
                    and sched.trigger_command is not None
                ):
                    raise ValueError(
                        f"{sched_prefix}: 'prompt' and 'trigger_command'"
                        f" are mutually exclusive"
                    )
                if sched.deliver.channel not in self.channels:
                    raise ValueError(
                        f"{sched_prefix}.deliver.channel: "
                        f"'{sched.deliver.channel}' does not match a "
                        f"configured channel "
                        f"({', '.join(sorted(self.channels))})"
                    )
                try:
                    CronExpression(sched.cron)
                except ValueError as e:
                    raise ValueError(
                        f"{sched_prefix}.cron: invalid expression: {e}"
                    ) from e
                if sched.timezone is not None:
                    try:
                        ZoneInfo(sched.timezone)
                    except Exception as e:
                        raise ValueError(
                            f"{sched_prefix}.timezone: invalid timezone "
                            f"'{sched.timezone}': {e}"
                        ) from e

        from airut.sandbox.claude_binary import validate_version

        validate_version(self.claude_version)

        channel_summary = ", ".join(
            f"{ct}={cc.channel_info}" for ct, cc in self.channels.items()
        )
        logger.info(
            "Repo '%s' config loaded: channels=[%s]",
            self.repo_id,
            channel_summary,
        )

    @property
    def storage_dir(self) -> Path:
        """Return the XDG state directory for this repo's persistent data."""
        return get_storage_dir(self.repo_id)

    def build_task_env(self) -> tuple[dict[str, str], ReplacementMap]:
        """Build container environment and replacement map for a task.

        All credentials from all pools are automatically injected into
        the container environment using their key/name as the env var
        name.  Surrogates are generated fresh per call (each task gets
        unique surrogates).

        Resolution priority (first match wins for duplicate env var names):

        1. Signing credentials (by field ``.name``)
        2. GitHub App credentials (by key)
        3. Masked secrets (by key)
        4. Plain secrets (by key)

        Returns:
            Tuple of (container env vars, replacement map for proxy).
        """
        return _build_task_env(
            self.secrets,
            self.masked_secrets,
            self.signing_credentials,
            self.github_app_credentials,
        )


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
        # Validate no duplicate IMAP inboxes (for email-channel repos)
        seen_inboxes: dict[tuple[str, str], str] = {}
        for repo_id, repo in self.repos.items():
            email_config = repo.channels.get("email")
            if email_config is None or not isinstance(
                email_config, EmailChannelConfig
            ):
                continue
            inbox_key = (
                email_config.imap.server.lower(),
                email_config.account.username.lower(),
            )
            if inbox_key in seen_inboxes:
                raise ConfigError(
                    f"Repo '{repo_id}' and repo '{seen_inboxes[inbox_key]}' "
                    f"share the same IMAP inbox "
                    f"({email_config.imap.server}/"
                    f"{email_config.account.username}). "
                    f"Each repo must have its own inbox."
                )
            seen_inboxes[inbox_key] = repo_id

        logger.info(
            "Server config loaded: %d repos, max_concurrent=%d",
            len(self.repos),
            self.global_config.max_concurrent_executions,
        )

    @classmethod
    def default(cls) -> "ConfigSnapshot[ServerConfig]":
        """Create a default configuration with no repos.

        Used when no config file exists.  Dashboard is enabled so the
        user can configure repos via the web UI.

        Returns:
            ConfigSnapshot wrapping a default ServerConfig instance.
        """
        from airut.config.snapshot import ConfigSnapshot

        instance = cls(global_config=GlobalConfig(), repos={})
        provided = frozenset({"global_config", "repos"})
        return ConfigSnapshot(instance, provided, raw={})

    @classmethod
    def from_source(
        cls,
        source: "ConfigSource",
    ) -> "ConfigSnapshot[ServerConfig]":
        """Load configuration from an arbitrary ``ConfigSource``.

        Loads the raw dict, applies schema migrations, resolves ``!var``
        references, then runs the existing resolution/validation pipeline.
        Returns a ``ConfigSnapshot`` holding both the resolved config and
        the raw YAML document (with ``VarRef``/``EnvVar`` preserved).

        Args:
            source: Config source to load from.

        Returns:
            ConfigSnapshot wrapping a ServerConfig instance.

        Raises:
            ConfigError: If required values are absent or validation fails.
        """
        import copy

        from airut.config.migration import apply_migrations
        from airut.config.snapshot import ConfigSnapshot
        from airut.config.vars import resolve_var_refs, resolve_vars_section

        raw = source.load()
        raw = apply_migrations(raw)

        # Preserve raw document before var resolution (for round-trip)
        doc_raw = copy.deepcopy(raw)

        # Resolve vars: section and !var references
        vars_table = resolve_vars_section(raw)
        raw = resolve_var_refs(raw, vars_table)

        instance = cls._from_raw(raw)
        provided = frozenset({"global_config", "repos"})
        return ConfigSnapshot(instance, provided, raw=doc_raw)

    @classmethod
    def from_yaml(
        cls, config_path: Path | None = None
    ) -> "ConfigSnapshot[ServerConfig]":
        """Load configuration from a YAML file.

        Values tagged with ``!env VAR_NAME`` are resolved from the
        environment at load time.  A ``.env`` file is loaded first if
        present.  ``!var`` references are resolved from the ``vars:``
        section.

        Args:
            config_path: Path to YAML config file.  Defaults to
                ``~/.config/airut/airut.yaml`` (XDG).

        Returns:
            ConfigSnapshot wrapping a ServerConfig instance.

        Raises:
            ConfigError: If the file is missing or required values are absent.
        """
        from airut.config.source import YamlConfigSource

        if config_path is None:
            config_path = get_config_path()

        try:
            source = YamlConfigSource(config_path)
            return cls.from_source(source)
        except FileNotFoundError as e:
            raise ConfigError(f"Config file not found: {config_path}") from e
        except ValueError as e:
            raise ConfigError(str(e)) from e

    @classmethod
    def _from_raw(cls, raw: dict) -> "ServerConfig":
        """Build config from parsed (but unresolved) YAML dict."""
        execution = raw.get("execution", {})
        dashboard = raw.get("dashboard", {})
        network = raw.get("network", {})

        # Build GlobalConfig kwargs.  Only fields present in YAML are
        # passed; absent fields fall through to dataclass defaults.
        gc_overrides = {}
        max_concurrent = _resolve(execution.get("max_concurrent"), int)
        if max_concurrent is not None:
            gc_overrides["max_concurrent_executions"] = max_concurrent
        shutdown_timeout = _resolve(execution.get("shutdown_timeout"), int)
        if shutdown_timeout is not None:
            gc_overrides["shutdown_timeout_seconds"] = shutdown_timeout
        conversation_max_age = _resolve(
            execution.get("conversation_max_age_days"), int
        )
        if conversation_max_age is not None:
            gc_overrides["conversation_max_age_days"] = conversation_max_age
        image_prune = _resolve(execution.get("image_prune"), bool)
        if image_prune is not None:
            gc_overrides["image_prune"] = image_prune
        dashboard_enabled = _resolve(dashboard.get("enabled"), bool)
        if dashboard_enabled is not None:
            gc_overrides["dashboard_enabled"] = dashboard_enabled
        dashboard_host = _resolve(dashboard.get("host"), str)
        if dashboard_host is not None:
            gc_overrides["dashboard_host"] = dashboard_host
        dashboard_port = _resolve(dashboard.get("port"), int)
        if dashboard_port is not None:
            gc_overrides["dashboard_port"] = dashboard_port
        container_command = _resolve(raw.get("container_command"), str)
        if container_command is not None:
            gc_overrides["container_command"] = container_command

        global_config = GlobalConfig(
            **gc_overrides,
            dashboard_base_url=_resolve(dashboard.get("base_url"), str),
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


#: Email-specific fields that must be nested under ``email:``.
#: If found at the repo level, the config parser raises ``ConfigError``
#: with migration instructions.  This is security-critical: silently
#: ignoring a stale ``authorized_senders`` at the repo level could start
#: the gateway with an empty allowlist under ``email:``.
_LEGACY_EMAIL_FIELDS = {
    "authorized_senders",
    "trusted_authserv_id",
    "microsoft_internal_auth_fallback",
    "imap",
}


def _parse_repo_server_config(repo_id: str, raw: dict) -> RepoServerConfig:
    """Parse a single repo's server-side configuration.

    Args:
        repo_id: Repository identifier (key from ``repos``).
        raw: Raw YAML dict for this repo.

    Returns:
        RepoServerConfig instance.

    Raises:
        ConfigError: If email-specific fields are at the repo level instead
            of under ``email:``, or if no channel is configured.
    """
    prefix = f"repos.{repo_id}"

    # Detect legacy field placement (security-critical).
    # Report all misplaced fields at once so the user can fix them
    # in a single pass (important for the airut-update → check flow).
    legacy_found = sorted(_LEGACY_EMAIL_FIELDS & raw.keys())
    if legacy_found:
        listed = ", ".join(f"'{k}'" for k in legacy_found)
        moves = "; ".join(f"'{k}' → {prefix}.email.{k}" for k in legacy_found)
        raise ConfigError(
            f"{prefix}: {listed} must be nested under 'email:'. "
            f"Move: {moves}. "
            f"See config/airut.example.yaml for the current format."
        )

    # Detect channel blocks dynamically instead of hardcoding email
    # as mandatory.  At least one channel must be present.
    if not (CHANNEL_KEYS & raw.keys()):
        hint = " or ".join(f"{k}:" for k in sorted(CHANNEL_KEYS))
        raise ConfigError(
            f"{prefix}: no channel configured "
            f"(add {hint}). "
            f"See config/airut.example.yaml for the current format."
        )

    network = raw.get("network", {})

    # Resolve per-repo secrets
    raw_secrets = raw.get("secrets", {})
    secrets = _resolve_secrets(raw_secrets)

    # Resolve masked secrets
    raw_masked = raw.get("masked_secrets", {})
    masked_secrets = _resolve_masked_secrets(raw_masked, prefix)

    # Resolve signing credentials
    raw_signing = raw.get("signing_credentials", {})
    signing_credentials = _resolve_signing_credentials(raw_signing, prefix)

    # Resolve GitHub App credentials
    raw_github_app = raw.get("github_app_credentials", {})
    github_app_credentials = _resolve_github_app_credentials(
        raw_github_app, prefix
    )

    # Parse each channel block
    channels: dict[str, ChannelConfig] = {}
    if "email" in raw:
        channels["email"] = _parse_email_channel_config(raw["email"], prefix)
    if "slack" in raw:
        channels["slack"] = _parse_slack_channel_config(raw["slack"], prefix)

    # Build optional overrides
    repo_overrides = {}
    sandbox_enabled = _resolve(network.get("sandbox_enabled"), bool)
    if sandbox_enabled is not None:
        repo_overrides["network_sandbox_enabled"] = sandbox_enabled
    model = _resolve(raw.get("model"), str)
    if model is not None:
        repo_overrides["model"] = model
    effort = _resolve(raw.get("effort"), str)
    if effort is not None:
        repo_overrides["effort"] = effort
    parsed_limits = _parse_resource_limits(raw.get("resource_limits"))
    if parsed_limits is not None:
        repo_overrides["resource_limits"] = parsed_limits
    claude_version = _resolve(raw.get("claude_version"), str)
    if claude_version is not None:
        repo_overrides["claude_version"] = claude_version
    container_path = _resolve(raw.get("container_path"), str)
    if container_path is not None:
        repo_overrides["container_path"] = container_path

    # Parse schedules
    raw_schedules = raw.get("schedules", {})
    schedules: dict[str, ScheduleConfig] = {}
    if isinstance(raw_schedules, dict):
        for sched_id, sched_raw in raw_schedules.items():
            sched_id = str(sched_id)
            if not isinstance(sched_raw, dict):
                raise ConfigError(
                    f"{prefix}.schedules.{sched_id} must be a YAML mapping"
                )
            schedules[sched_id] = _parse_schedule_config(
                sched_id, sched_raw, prefix
            )

    return RepoServerConfig(
        repo_id=repo_id,
        git_repo_url=_resolve(
            raw.get("repo_url"),
            str,
            required=f"{prefix}.repo_url",
        ),
        channels=channels,
        secrets=secrets,
        masked_secrets=masked_secrets,
        signing_credentials=signing_credentials,
        github_app_credentials=github_app_credentials,
        schedules=schedules,
        **repo_overrides,
    )


def _parse_email_channel_config(email: dict, prefix: str) -> EmailChannelConfig:
    """Parse an email channel config block.

    Args:
        email: Raw YAML dict for the ``email:`` block.
        prefix: Config path prefix for error messages.

    Returns:
        EmailChannelConfig instance.
    """
    raw_account = email.get("account", {})
    raw_imap = email.get("imap", {})
    raw_smtp = email.get("smtp", {})
    raw_auth = email.get("auth", {})

    # Build EmailAccountConfig
    acct_overrides: dict[str, Any] = {}
    password = _resolve(raw_account.get("password"), str)
    if password is not None:
        acct_overrides["password"] = password
    account = EmailAccountConfig(
        username=_resolve(
            raw_account.get("username"),
            str,
            required=f"{prefix}.email.account.username",
        ),
        from_address=_resolve(
            raw_account.get("from"),
            str,
            required=f"{prefix}.email.account.from",
        ),
        **acct_overrides,
    )

    # Build ImapConfig
    imap_overrides: dict[str, Any] = {}
    imap_port = _resolve(raw_imap.get("port"), int)
    if imap_port is not None:
        imap_overrides["port"] = imap_port
    connect_retries = _resolve(raw_imap.get("connect_retries"), int)
    if connect_retries is not None:
        imap_overrides["connect_retries"] = connect_retries
    poll_interval = _resolve(raw_imap.get("poll_interval"), float)
    if poll_interval is not None:
        imap_overrides["poll_interval"] = poll_interval
    use_idle = _resolve(raw_imap.get("use_idle"), bool)
    if use_idle is not None:
        imap_overrides["use_idle"] = use_idle
    idle_reconnect = _resolve(raw_imap.get("idle_reconnect_interval"), float)
    if idle_reconnect is not None:
        imap_overrides["idle_reconnect_interval"] = idle_reconnect
    imap = ImapConfig(
        server=_resolve(
            raw_imap.get("server"),
            str,
            required=f"{prefix}.email.imap.server",
        ),
        **imap_overrides,
    )

    # Build SmtpConfig
    smtp_overrides: dict[str, Any] = {}
    smtp_port = _resolve(raw_smtp.get("port"), int)
    if smtp_port is not None:
        smtp_overrides["port"] = smtp_port
    smtp_require_auth = _resolve(raw_smtp.get("require_auth"), bool)
    if smtp_require_auth is not None:
        smtp_overrides["require_auth"] = smtp_require_auth
    smtp = SmtpConfig(
        server=_resolve(
            raw_smtp.get("server"),
            str,
            required=f"{prefix}.email.smtp.server",
        ),
        **smtp_overrides,
    )

    # Build EmailAuthConfig
    auth_overrides: dict[str, Any] = {}
    ms_internal_auth = _resolve(
        raw_auth.get("microsoft_internal_fallback"), bool
    )
    if ms_internal_auth is not None:
        auth_overrides["microsoft_internal_fallback"] = ms_internal_auth
    auth = EmailAuthConfig(
        authorized_senders=_resolve_string_list(
            raw_auth.get("authorized_senders"),
            required=f"{prefix}.email.auth.authorized_senders",
        ),
        trusted_authserv_id=_resolve(
            raw_auth.get("trusted_authserv_id"),
            str,
            required=f"{prefix}.email.auth.trusted_authserv_id",
        ),
        **auth_overrides,
    )

    # Build MicrosoftOAuth2Config (optional block)
    raw_ms_oauth2 = email.get("microsoft_oauth2", {})
    microsoft_oauth2: MicrosoftOAuth2Config | None = None
    if raw_ms_oauth2:
        ms_tenant_id = _resolve(raw_ms_oauth2.get("tenant_id"), str)
        ms_client_id = _resolve(raw_ms_oauth2.get("client_id"), str)
        ms_client_secret = _resolve(raw_ms_oauth2.get("client_secret"), str)
        if ms_tenant_id and ms_client_id and ms_client_secret:
            microsoft_oauth2 = MicrosoftOAuth2Config(
                tenant_id=ms_tenant_id,
                client_id=ms_client_id,
                client_secret=ms_client_secret,
            )

    return EmailChannelConfig(
        account=account,
        imap=imap,
        smtp=smtp,
        auth=auth,
        microsoft_oauth2=microsoft_oauth2,
    )


def _parse_slack_channel_config(
    slack: dict, prefix: str
) -> "SlackChannelConfig":
    """Parse a Slack channel config block.

    Args:
        slack: Raw YAML dict for the ``slack:`` block.
        prefix: Config path prefix for error messages.

    Returns:
        SlackChannelConfig instance.
    """
    from airut.gateway.slack.config import SlackChannelConfig

    bot_token = _resolve(
        slack.get("bot_token"),
        str,
        required=f"{prefix}.slack.bot_token",
    )
    app_token = _resolve(
        slack.get("app_token"),
        str,
        required=f"{prefix}.slack.app_token",
    )

    # Parse authorization rules
    raw_authorized = slack.get("authorized")
    if raw_authorized is None:
        raise ConfigError(
            f"{prefix}.slack.authorized is required "
            f"(at least one authorization rule)"
        )
    if not isinstance(raw_authorized, list):
        raise ConfigError(f"{prefix}.slack.authorized must be a list")
    if not raw_authorized:
        raise ConfigError(f"{prefix}.slack.authorized cannot be empty")

    authorized: list[dict[str, str | bool]] = []
    for i, rule in enumerate(raw_authorized):
        if not isinstance(rule, dict) or len(rule) != 1:
            raise ConfigError(
                f"{prefix}.slack.authorized[{i}] must be a single-key "
                f"mapping (workspace_members, user_group, or user_id)"
            )
        items = list(rule.items())
        key = str(items[0][0])
        if key not in ("workspace_members", "user_group", "user_id"):
            raise ConfigError(
                f"{prefix}.slack.authorized[{i}]: unknown rule "
                f"type '{key}' (expected workspace_members, "
                f"user_group, or user_id)"
            )
        value = cast(YamlValue, items[0][1])
        if key == "workspace_members":
            coerced = _coerce_bool(value)
            if not coerced:
                logger.warning(
                    "%s.slack.authorized[%d]: workspace_members: false "
                    "has no effect (rule never matches); remove it or "
                    "set to true",
                    prefix,
                    i,
                )
            authorized.append({key: coerced})
        else:
            resolved = raw_resolve(value)
            if resolved is None:
                raise ConfigError(
                    f"{prefix}.slack.authorized[{i}].{key} value is required"
                )
            authorized.append({key: resolved})

    return SlackChannelConfig(
        bot_token=bot_token,
        app_token=app_token,
        authorized=tuple(authorized),
    )


def _parse_schedule_config(
    schedule_id: str,
    raw: dict,
    prefix: str,
) -> ScheduleConfig:
    """Parse a single schedule config block.

    Args:
        schedule_id: Schedule name (key from ``schedules``).
        raw: Raw YAML dict for this schedule.
        prefix: Config path prefix for error messages.

    Returns:
        ScheduleConfig instance.

    Raises:
        ConfigError: If required fields are missing or invalid.
    """
    key = f"{prefix}.schedules.{schedule_id}"

    cron = _resolve(raw.get("cron"), str, required=f"{key}.cron")

    # Parse deliver block (required)
    raw_deliver = raw.get("deliver")
    if not isinstance(raw_deliver, dict):
        raise ConfigError(f"{key}.deliver is required and must be a mapping")
    deliver = ScheduleDelivery(
        channel=_resolve(raw_deliver.get("channel"), str) or "email",
        to=_resolve(raw_deliver.get("to"), str, required=f"{key}.deliver.to"),
    )

    # Parse optional fields
    subject = _resolve(raw.get("subject"), str)
    timezone = _resolve(raw.get("timezone"), str)
    prompt = _resolve(raw.get("prompt"), str)
    trigger_command = _resolve(raw.get("trigger_command"), str)
    trigger_timeout = _resolve(raw.get("trigger_timeout"), int)
    model = _resolve(raw.get("model"), str)
    effort = _resolve(raw.get("effort"), str)
    output_limit_raw = _resolve(raw.get("output_limit"), int)
    output_limit = output_limit_raw if output_limit_raw is not None else 102400

    return ScheduleConfig(
        cron=cron,
        deliver=deliver,
        subject=subject,
        timezone=timezone,
        prompt=prompt,
        trigger_command=trigger_command,
        trigger_timeout=trigger_timeout,
        model=model,
        effort=effort,
        output_limit=output_limit,
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
        value = raw_resolve(raw_value)

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

        ms_overrides = {}
        raw_allow_foreign = config.get("allow_foreign_credentials")
        if raw_allow_foreign is not None:
            ms_overrides["allow_foreign_credentials"] = bool(raw_allow_foreign)

        result[name] = MaskedSecret(
            value=value,
            scopes=scopes,
            headers=headers,
            **ms_overrides,
        )

    return result


# ---------------------------------------------------------------------------
def _resolve_signing_credential_field(
    raw: YamlValue,
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

    raw_dict = cast(dict[str, YamlValue], raw)
    name = raw_dict.get("name")
    if not name:
        raise ConfigError(f"{field_path}.name is required")
    name = str(name)

    raw_value = raw_dict.get("value")
    value = raw_resolve(raw_value)
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
    ``name`` declares the container environment variable name, and
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


def _resolve_github_app_credentials(
    raw_github_app: dict,
    prefix: str,
) -> dict[str, GitHubAppCredential]:
    """Resolve github_app_credentials from server config.

    Args:
        raw_github_app: Raw github_app_credentials mapping from YAML.
        prefix: Config path prefix for error messages.

    Returns:
        Mapping of credential name to GitHubAppCredential.

    Raises:
        ConfigError: If structure is invalid or required fields missing.
    """
    result: dict[str, GitHubAppCredential] = {}

    for name, config in raw_github_app.items():
        name = str(name)
        key = f"{prefix}.github_app_credentials.{name}"

        if not isinstance(config, dict):
            raise ConfigError(f"{key} must be a mapping")

        # Resolve app_id (required, supports !env)
        raw_app_id = config.get("app_id")
        app_id = raw_resolve(raw_app_id)
        if not app_id:
            raise ConfigError(f"{key}.app_id is required")

        # Resolve private_key (required, supports !env)
        raw_private_key = config.get("private_key")
        private_key = raw_resolve(raw_private_key)
        if not private_key:
            raise ConfigError(f"{key}.private_key is required")

        # Resolve installation_id (required, supports !env, must be numeric)
        installation_id = _resolve(
            config.get("installation_id"),
            int,
            required=f"{key}.installation_id",
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

        # Parse optional fields
        raw_allow_foreign = config.get("allow_foreign_credentials")

        base_url: str | None = None
        raw_base_url = config.get("base_url")
        if raw_base_url is not None:
            base_url = raw_resolve(raw_base_url)
            if base_url and not base_url.startswith("https://"):
                raise ConfigError(f"{key}.base_url must use HTTPS")

        permissions: dict[str, str] | None = None
        raw_permissions = config.get("permissions")
        if raw_permissions is not None:
            if not isinstance(raw_permissions, dict):
                raise ConfigError(f"{key}.permissions must be a mapping")
            permissions = {str(k): str(v) for k, v in raw_permissions.items()}

        repositories: tuple[str, ...] | None = None
        raw_repositories = config.get("repositories")
        if raw_repositories is not None:
            if not isinstance(raw_repositories, list):
                raise ConfigError(f"{key}.repositories must be a list")
            repositories = tuple(str(r) for r in raw_repositories)

        ga_overrides = {}
        if raw_allow_foreign is not None:
            ga_overrides["allow_foreign_credentials"] = bool(raw_allow_foreign)
        if base_url:
            ga_overrides["base_url"] = base_url
        if permissions is not None:
            ga_overrides["permissions"] = permissions
        if repositories is not None:
            ga_overrides["repositories"] = repositories

        result[name] = GitHubAppCredential(
            app_id=app_id,
            private_key=private_key,
            installation_id=installation_id,
            scopes=scopes,
            **ga_overrides,
        )

    return result


# ---------------------------------------------------------------------------
# Task environment builder
# ---------------------------------------------------------------------------


def _build_task_env(
    secrets: dict[str, str],
    masked_secrets: dict[str, MaskedSecret],
    signing_credentials: dict[str, SigningCredential],
    github_app_credentials: dict[str, GitHubAppCredential],
) -> tuple[dict[str, str], ReplacementMap]:
    """Build container environment and replacement map for a task.

    All credentials from all pools are automatically injected into
    the container environment using their key/name as the env var name.
    Surrogates are generated fresh per call.

    Resolution priority (first match wins for duplicate env var names):

    1. Signing credentials (by field ``.name``)
    2. GitHub App credentials (by key)
    3. Masked secrets (by key)
    4. Plain secrets (by key)

    Args:
        secrets: Plain secrets pool (key = env var name).
        masked_secrets: Masked secrets with scope info.
        signing_credentials: Signing credentials for proxy re-signing.
        github_app_credentials: GitHub App credentials for token rotation.

    Returns:
        Tuple of (container env vars, replacement map for proxy).
    """
    resolved: dict[str, str] = {}
    replacement_map: ReplacementMap = {}

    # 1. Signing credentials: each field's .name becomes an env var.
    # Track per-credential group to build a single SigningCredentialEntry.
    signing_refs: dict[str, dict[str, str]] = {}

    for cred_name, cred in signing_credentials.items():
        # Skip entire credential if access_key_id name is already taken.
        # Without access_key_id in the replacement map, the proxy cannot
        # detect the credential set.
        if cred.access_key_id.name in resolved:
            continue

        for field_name, field_obj in [
            ("access_key_id", cred.access_key_id),
            ("secret_access_key", cred.secret_access_key),
            ("session_token", cred.session_token),
        ]:
            if field_obj is None:
                continue
            env_key = field_obj.name
            if env_key in resolved:
                continue

            if field_name == "session_token":
                surrogate = generate_session_token_surrogate()
            else:
                surrogate = generate_surrogate(field_obj.value)

            resolved[env_key] = surrogate

            if cred_name not in signing_refs:
                signing_refs[cred_name] = {}
            signing_refs[cred_name][field_name] = surrogate

    # Build SigningCredentialEntry for each credential set.
    for cred_name, fields in signing_refs.items():
        cred = signing_credentials[cred_name]
        surrogate_key_id = fields["access_key_id"]
        surrogate_session_token = fields.get("session_token")

        replacement_map[surrogate_key_id] = SigningCredentialEntry(
            access_key_id=cred.access_key_id.value,
            secret_access_key=cred.secret_access_key.value,
            session_token=(
                cred.session_token.value if cred.session_token else None
            ),
            surrogate_session_token=surrogate_session_token,
            scopes=tuple(sorted(cred.scopes)),
        )

    # 2. GitHub App credentials: key becomes env var name.
    for name, gh_cred in github_app_credentials.items():
        if name in resolved:
            continue
        surrogate = generate_github_app_surrogate()
        resolved[name] = surrogate
        replacement_map[surrogate] = GitHubAppEntry(
            app_id=gh_cred.app_id,
            private_key=gh_cred.private_key,
            installation_id=gh_cred.installation_id,
            base_url=gh_cred.base_url,
            scopes=tuple(sorted(gh_cred.scopes)),
            allow_foreign_credentials=gh_cred.allow_foreign_credentials,
            permissions=gh_cred.permissions,
            repositories=gh_cred.repositories,
        )

    # 3. Masked secrets: key becomes env var name.
    for name, masked in masked_secrets.items():
        if name in resolved:
            continue
        if masked.value:
            surrogate = generate_surrogate(masked.value)
            resolved[name] = surrogate
            replacement_map[surrogate] = ReplacementEntry(
                real_value=masked.value,
                scopes=tuple(sorted(masked.scopes)),
                headers=masked.headers,
                allow_foreign_credentials=masked.allow_foreign_credentials,
            )
        else:
            resolved[name] = ""

    # 4. Plain secrets: key becomes env var name.
    for name, value in secrets.items():
        if name in resolved:
            continue
        if value:
            resolved[name] = value

    # Register all resolved values for log redaction.
    for value in resolved.values():
        if value:
            SecretFilter.register_secret(value)

    return resolved, replacement_map
