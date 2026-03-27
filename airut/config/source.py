# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config source protocol and YAML implementation.

``ConfigSource`` decouples config loading/saving from the serialization
format.  ``YamlConfigSource`` wraps the existing YAML file loading with
``!env`` tag support, and includes ``YAML_*_STRUCTURE`` mappings for
reconstructing nested YAML structure on save.
"""

import hashlib
from pathlib import Path
from typing import Any, Protocol

import yaml

from airut.gateway.dotenv_loader import load_dotenv_once
from airut.yaml_env import EnvVar, VarRef, make_env_loader


class ConfigSource(Protocol):
    """Read/write raw config dicts from any backing store."""

    def load(self) -> dict[str, Any]:
        """Load raw config dict.  Values may contain EnvVar placeholders."""
        ...

    def save(self, data: dict[str, Any]) -> None:
        """Write raw config dict back to the backing store."""
        ...


#: Maps flat GlobalConfig field names to nested YAML paths.
#: Fields not listed map to their own name at the top level.
YAML_GLOBAL_STRUCTURE: dict[str, tuple[str, ...]] = {
    "max_concurrent_executions": ("execution", "max_concurrent"),
    "shutdown_timeout_seconds": ("execution", "shutdown_timeout"),
    "conversation_max_age_days": ("execution", "conversation_max_age_days"),
    "image_prune": ("execution", "image_prune"),
    "dashboard_enabled": ("dashboard", "enabled"),
    "dashboard_host": ("dashboard", "host"),
    "dashboard_port": ("dashboard", "port"),
    "dashboard_base_url": ("dashboard", "base_url"),
    "upstream_dns": ("network", "upstream_dns"),
}

#: Maps flat EmailChannelConfig field names to nested YAML paths
#: within the ``email:`` block.
YAML_EMAIL_STRUCTURE: dict[str, tuple[str, ...]] = {
    "imap_server": ("imap_server",),
    "imap_port": ("imap_port",),
    "smtp_server": ("smtp_server",),
    "smtp_port": ("smtp_port",),
    "username": ("username",),
    "password": ("password",),
    "from_address": ("from",),
    "authorized_senders": ("authorized_senders",),
    "trusted_authserv_id": ("trusted_authserv_id",),
    "imap_connect_retries": ("imap", "connect_retries"),
    "poll_interval_seconds": ("imap", "poll_interval"),
    "use_imap_idle": ("imap", "use_idle"),
    "idle_reconnect_interval_seconds": ("imap", "idle_reconnect_interval"),
    "microsoft_internal_auth_fallback": ("microsoft_internal_auth_fallback",),
    "microsoft_oauth2_tenant_id": ("microsoft_oauth2", "tenant_id"),
    "microsoft_oauth2_client_id": ("microsoft_oauth2", "client_id"),
    "microsoft_oauth2_client_secret": ("microsoft_oauth2", "client_secret"),
}

#: Maps flat RepoServerConfig field names to nested YAML paths
#: within the repo block.
YAML_REPO_STRUCTURE: dict[str, tuple[str, ...]] = {
    "git_repo_url": ("git", "repo_url"),
    "network_sandbox_enabled": ("network", "sandbox_enabled"),
    "container_path": ("container", "path"),
}


def _set_nested(
    target: dict[str, Any],
    path: tuple[str, ...],
    value: object,
) -> None:
    """Set a value in a nested dict structure, creating intermediate dicts."""
    for key in path[:-1]:
        target = target.setdefault(key, {})
    target[path[-1]] = value


def _flat_to_nested(
    flat: dict[str, Any],
    structure: dict[str, tuple[str, ...]],
) -> dict[str, Any]:
    """Convert a flat config dict to nested structure using a mapping.

    Keys present in *structure* are placed at the nested path; keys
    not in *structure* are kept at the top level.

    Args:
        flat: Dict keyed by dataclass field names.
        structure: Mapping of field name to nested path tuple.

    Returns:
        Nested dict matching the target format.
    """
    result: dict[str, Any] = {}
    for key, value in flat.items():
        path = structure.get(key)
        if path is not None:
            _set_nested(result, path, value)
        else:
            result[key] = value
    return result


def flat_to_nested_global(flat: dict[str, Any]) -> dict[str, Any]:
    """Convert a flat GlobalConfig dict to nested YAML structure."""
    return _flat_to_nested(flat, YAML_GLOBAL_STRUCTURE)


def flat_to_nested_email(flat: dict[str, Any]) -> dict[str, Any]:
    """Convert a flat EmailChannelConfig dict to nested YAML structure."""
    return _flat_to_nested(flat, YAML_EMAIL_STRUCTURE)


def flat_to_nested_repo(flat: dict[str, Any]) -> dict[str, Any]:
    """Convert a flat RepoServerConfig dict to nested YAML structure."""
    return _flat_to_nested(flat, YAML_REPO_STRUCTURE)


def _env_representer(dumper: yaml.Dumper, data: EnvVar) -> yaml.Node:
    """Emit ``!env VAR_NAME`` tags when dumping YAML."""
    return dumper.represent_scalar("!env", data.var_name)


def _var_representer(dumper: yaml.Dumper, data: VarRef) -> yaml.Node:
    """Emit ``!var VAR_NAME`` tags when dumping YAML."""
    return dumper.represent_scalar("!var", data.var_name)


def make_tag_dumper() -> type[yaml.Dumper]:
    """Create a YAML ``Dumper`` that preserves ``!env`` and ``!var`` tags."""

    class _TagDumper(yaml.Dumper):
        pass

    _TagDumper.add_representer(EnvVar, _env_representer)
    _TagDumper.add_representer(VarRef, _var_representer)
    return _TagDumper


class YamlConfigSource:
    """Load and save config from/to a YAML file with ``!env`` support.

    Attributes:
        path: Path to the YAML config file.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.last_file_sha256: str | None = None

    def load(self) -> dict[str, Any]:
        """Load raw config dict from YAML, resolving ``!env`` tags.

        Calls ``load_dotenv_once()`` before parsing to ensure ``!env``
        tags can resolve.  Updates ``last_file_sha256`` with the SHA-256
        of the raw file bytes that were loaded.

        Returns:
            Raw config dict with EnvVar placeholders.

        Raises:
            FileNotFoundError: If the YAML file does not exist.
        """
        load_dotenv_once()

        if not self.path.exists():
            raise FileNotFoundError(f"Config file not found: {self.path}")

        raw_bytes = self.path.read_bytes()
        self.last_file_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        raw = yaml.load(raw_bytes, Loader=make_env_loader())

        if not isinstance(raw, dict):
            raise ValueError(f"Config file must be a YAML mapping: {self.path}")

        return raw

    def save(self, data: dict[str, Any]) -> None:
        """Write config dict back to YAML atomically.

        Writes to a temporary file first, then renames it to the target
        path.  This ensures the config file is never partially written.
        The rename is atomic on the same filesystem.

        The data dict uses the nested YAML structure (not flat field
        names).  Callers should use ``flat_to_nested_*`` helpers to
        convert from flat canonical dicts before calling ``save()``.

        Uses a custom Dumper that preserves ``!env`` and ``!var`` tags
        for round-trip fidelity.

        Args:
            data: Config dict in nested YAML format.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".yaml.tmp")
        with open(tmp, "w") as f:
            yaml.dump(
                data,
                f,
                Dumper=make_tag_dumper(),
                default_flow_style=False,
                sort_keys=False,
            )
        tmp.rename(self.path)
