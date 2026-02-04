# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Configuration for email gateway service.

Server configuration is loaded from a YAML file (``config/airut.yaml``)
with support for ``!env`` tags that resolve values from environment variables.

The server config defines global settings (execution limits, dashboard) and
per-repo settings (email credentials, authorization, secrets).  Each repo
entry under ``repos:`` becomes a ``RepoServerConfig``.

Repo configuration (behaviour) is loaded from ``.airut/airut.yaml`` in each
repo's git mirror with support for ``!secret`` tags resolved against the
per-repo secrets pool.  ``!env`` is **not** allowed in repo config.

The module is self-contained (no dependency on ``lib/config.py``) so the
email gateway can be deployed independently.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, overload

import yaml

from lib.gateway.dotenv_loader import load_dotenv_once
from lib.logging import SecretFilter


if TYPE_CHECKING:
    from lib.git_mirror import GitMirrorCache


logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).parent.parent.parent
_DEFAULT_CONFIG_PATH = "config/airut.yaml"

_BOOL_TRUTHY = frozenset({"true", "1", "yes", "on"})
_BOOL_FALSY = frozenset({"false", "0", "no", "off"})


class ConfigError(Exception):
    """Base exception for configuration errors."""


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

    Returns None if the value is None or the env var is unset/empty.
    """
    if isinstance(value, _EnvVar):
        return os.environ.get(value.var_name) or None
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
        Resolved mapping with only non-empty values.
    """
    secrets: dict[str, str] = {}
    for key, value in raw_secrets.items():
        resolved = _raw_resolve(value)
        if resolved:
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
    """

    max_concurrent_executions: int = 3
    shutdown_timeout_seconds: int = 60
    conversation_max_age_days: int = 7
    dashboard_enabled: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5200
    dashboard_base_url: str | None = None
    container_command: str = "podman"

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

    Contains email credentials, authorization, storage, and secrets for a
    single repository.  Loaded from the ``repos.<name>`` section of the
    server config file.

    Attributes:
        repo_id: Repository identifier (key from ``repos`` mapping).
        git_repo_url: Git repository URL to clone from.
        storage_dir: Root directory for this repo's persistent data.
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
            Authentication-Results headers.
        poll_interval_seconds: Seconds between IMAP polls.
        use_imap_idle: Whether to use IMAP IDLE instead of polling.
        idle_reconnect_interval_seconds: Reconnect interval for IDLE mode.
        smtp_require_auth: Whether SMTP requires authentication.
        secrets: Per-repo secrets pool for ``!secret`` resolution.
    """

    repo_id: str
    git_repo_url: str
    storage_dir: Path
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

    def __post_init__(self) -> None:
        """Validate configuration and register secrets.

        Raises:
            ValueError: If configuration is invalid.
        """
        SecretFilter.register_secret(self.email_password)

        for value in self.secrets.values():
            if value:
                SecretFilter.register_secret(value)

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

        # Validate no duplicate storage dirs
        seen_dirs: dict[Path, str] = {}
        for repo_id, repo in self.repos.items():
            resolved = repo.storage_dir.resolve()
            if resolved in seen_dirs:
                raise ConfigError(
                    f"Repo '{repo_id}' and repo '{seen_dirs[resolved]}' "
                    f"share the same storage_dir ({repo.storage_dir}). "
                    f"Each repo must have its own storage directory."
                )
            seen_dirs[resolved] = repo_id

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
                ``config/airut.yaml`` relative to the repo root.

        Returns:
            ServerConfig instance.

        Raises:
            ConfigError: If the file is missing or required values are absent.
        """
        load_dotenv_once()

        if config_path is None:
            config_path = _REPO_ROOT / _DEFAULT_CONFIG_PATH

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
    prefix = f"repos.{repo_id}"

    # Resolve per-repo secrets
    raw_secrets = raw.get("secrets", {})
    secrets = _resolve_secrets(raw_secrets)

    return RepoServerConfig(
        repo_id=repo_id,
        git_repo_url=_resolve(
            raw.get("git", {}).get("repo_url"),
            str,
            required=f"{prefix}.git.repo_url",
        ),
        storage_dir=_resolve(
            raw.get("storage_dir"),
            Path,
            required=f"{prefix}.storage_dir",
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
        email_password=_resolve(
            email.get("password"),
            str,
            required=f"{prefix}.email.password",
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
    )


# ---------------------------------------------------------------------------
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
    ) -> "RepoConfig":
        """Load repo config from the git mirror.

        Reads ``.airut/airut.yaml`` from the mirror's default branch,
        parses it with ``!secret`` tag support, and resolves secret
        references against the server's secrets pool.

        Args:
            mirror: Git mirror cache to read the file from.
            server_secrets: Server's secrets pool (name -> value).

        Returns:
            RepoConfig instance.

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

        return cls._from_raw(raw, server_secrets)

    @classmethod
    def _from_raw(
        cls,
        raw: dict,
        server_secrets: dict[str, str],
    ) -> "RepoConfig":
        """Build repo config from parsed YAML dict."""
        network_raw = raw.get("network", {})

        # Resolve container_env: inline values + !secret references
        raw_container_env = raw.get("container_env", {})
        container_env = _resolve_container_env(
            raw_container_env, server_secrets
        )

        return cls(
            default_model=_resolve(
                raw.get("default_model"), str, default="opus"
            ),
            timeout=_resolve(raw.get("timeout"), int, default=300),
            network_sandbox_enabled=_resolve(
                network_raw.get("sandbox_enabled"), bool, default=True
            ),
            container_env=container_env,
        )


def _resolve_container_env(
    raw_env: dict,
    server_secrets: dict[str, str],
) -> dict[str, str]:
    """Resolve container_env entries from repo config.

    Inline string values pass through.  ``_SecretRef`` placeholders
    are resolved from the server's secrets pool.

    Args:
        raw_env: Raw container_env mapping from YAML.
        server_secrets: Server's secrets pool.

    Returns:
        Resolved environment variable mapping.

    Raises:
        ConfigError: If a required ``!secret`` reference (not ``!secret?``)
            is not in the server pool.
    """
    resolved: dict[str, str] = {}
    for key, value in raw_env.items():
        if isinstance(value, _SecretRef):
            if value.name not in server_secrets:
                if value.optional:
                    # !secret? — gracefully skip missing optional secrets
                    continue
                raise ConfigError(
                    f"container_env.{key}: !secret '{value.name}' "
                    f"not found in server secrets pool"
                )
            secret_value = server_secrets[value.name]
            if secret_value:
                resolved[str(key)] = secret_value
        else:
            # Inline value
            str_value = _raw_resolve(value)
            if str_value:
                resolved[str(key)] = str_value
    return resolved
