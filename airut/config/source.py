# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config source protocol and YAML implementation.

``ConfigSource`` decouples config loading/saving from the serialization
format.  ``YamlConfigSource`` wraps the existing YAML file loading with
``!env``/``!var``/``!file`` tag support (and their tag-free mapping
spellings), and includes ``YAML_*_STRUCTURE`` mappings for
reconstructing nested YAML structure on save.
"""

import hashlib
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

import yaml

from airut.gateway.dotenv_loader import load_dotenv_once
from airut.yaml_env import EnvVar, FileRef, VarRef, YamlValue, make_env_loader


class ConfigSource(Protocol):
    """Read/write raw config dicts from any backing store."""

    def load(self) -> dict[str, Any]:
        """Load raw config dict.

        Values may contain ``EnvVar``, ``VarRef`` and ``FileRef``
        placeholders.
        """
        ...

    def save(self, data: dict[str, Any]) -> None:
        """Write raw config dict back to the backing store."""
        ...

    def read_only_reason(self) -> str | None:
        """Why ``save()`` is unavailable, or None if it is available."""
        ...


class ConfigReadOnlyError(Exception):
    """Raised when saving to a read-only config source."""


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

#: Maps EmailChannelConfig field names to nested YAML paths
#: within the ``email:`` block.  With the sub-dataclass structure,
#: top-level fields (account, imap, etc.) map directly to their
#: YAML keys — no remapping needed at this level.
YAML_EMAIL_STRUCTURE: dict[str, tuple[str, ...]] = {}

#: Maps EmailAccountConfig field names to YAML keys.
#: Only ``from_address`` differs (keyword ``from``).
YAML_EMAIL_ACCOUNT_STRUCTURE: dict[str, tuple[str, ...]] = {
    "from_address": ("from",),
}

#: Per-class structure mappings for nested dataclass recursion.
#: Used by ``editor_schema._get_nested_fields()`` to resolve YAML keys
#: within sub-dataclasses (e.g. ``from_address`` → ``from``).
YAML_CLASS_STRUCTURES: dict[str, dict[str, tuple[str, ...]]] = {
    "EmailAccountConfig": YAML_EMAIL_ACCOUNT_STRUCTURE,
}

#: Maps flat RepoServerConfig field names to nested YAML paths
#: within the repo block.
YAML_REPO_STRUCTURE: dict[str, tuple[str, ...]] = {
    "git_repo_url": ("repo_url",),
    "network_sandbox_enabled": ("network", "sandbox_enabled"),
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


def _file_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> FileRef:
    """Handle ``!file PATH`` in YAML."""
    return FileRef(str(loader.construct_scalar(node)))


def make_config_loader() -> type[yaml.SafeLoader]:
    """Create the server config loader: ``!env``, ``!var`` and ``!file``."""
    loader = make_env_loader()
    loader.add_constructor("!file", _file_constructor)
    return loader


#: Tag-free spellings: a mapping with the single key ``"!env"``,
#: ``"!var"`` or ``"!file"`` stands for that tag, e.g.
#: ``{"!env": "NAME"}`` for ``!env NAME``.  For generators that cannot
#: emit YAML tags (JSON, Nix's ``pkgs.formats.yaml``).
_TAG_MAPPINGS: dict[str, Callable[[str], EnvVar | VarRef | FileRef]] = {
    "!env": EnvVar,
    "!var": VarRef,
    "!file": FileRef,
}


def resolve_tag_mappings(value: YamlValue, path: str) -> YamlValue:
    """Replace tag-free spellings with tag placeholders, recursively.

    Dicts and lists are updated in place.

    Args:
        value: Raw YAML value below the document root.
        path: Dot-path of *value*, for error messages.

    Returns:
        *value*, or the placeholder it spells.

    Raises:
        ValueError: If a tag mapping's argument is not a string.
    """
    if isinstance(value, dict):
        if len(value) == 1:
            ((key, arg),) = value.items()
            make = _TAG_MAPPINGS.get(key)
            if make is not None:
                if not isinstance(arg, str):
                    raise ValueError(
                        f"{path}: {{{key!r}: ...}} takes a string, "
                        f"not {type(arg).__name__}"
                    )
                return make(arg)
        for key in value:
            value[key] = resolve_tag_mappings(value[key], f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            value[i] = resolve_tag_mappings(item, f"{path}[{i}]")
    return value


def _env_representer(dumper: yaml.Dumper, data: EnvVar) -> yaml.Node:
    """Emit ``!env VAR_NAME`` tags when dumping YAML."""
    return dumper.represent_scalar("!env", data.var_name)


def _var_representer(dumper: yaml.Dumper, data: VarRef) -> yaml.Node:
    """Emit ``!var VAR_NAME`` tags when dumping YAML."""
    return dumper.represent_scalar("!var", data.var_name)


def _file_representer(dumper: yaml.Dumper, data: FileRef) -> yaml.Node:
    """Emit ``!file PATH`` tags when dumping YAML."""
    return dumper.represent_scalar("!file", data.path)


def make_tag_dumper() -> type[yaml.Dumper]:
    """Create a YAML ``Dumper`` preserving ``!env``/``!var``/``!file`` tags."""

    class _TagDumper(yaml.Dumper):
        pass

    _TagDumper.add_representer(EnvVar, _env_representer)
    _TagDumper.add_representer(VarRef, _var_representer)
    _TagDumper.add_representer(FileRef, _file_representer)
    return _TagDumper


class YamlConfigSource:
    """Load and save config from/to a YAML file.

    Supports ``!env``/``!var``/``!file`` tags and their tag-free
    spellings (see :func:`resolve_tag_mappings`).

    The file is read-only when *read_only* is set or when saving would
    not work or would break how the file is managed: the path is a
    symlink (saving would replace the link, e.g. into the Nix store,
    with a plain file), or the file or its directory is not writable.

    Attributes:
        path: Path to the YAML config file.
    """

    def __init__(self, path: Path, *, read_only: bool = False) -> None:
        self.path = path
        self.last_file_sha256: str | None = None
        self._read_only = read_only

    def read_only_reason(self) -> str | None:
        """Why the config file cannot be saved, or None if it can.

        Checked on each call: writability can change at runtime.
        """
        if self._read_only:
            return "the gateway runs with --read-only-config"
        if self.path.is_symlink():
            return f"{self.path} is a symlink, managed elsewhere"
        if self.path.exists() and not os.access(self.path, os.W_OK):
            return f"{self.path} is not writable"
        # Saving writes a temp file next to the config, so the
        # directory (or its nearest existing ancestor, which save()
        # creates the rest of) must be writable too.
        directory = self.path.parent
        while not directory.exists() and directory != directory.parent:
            directory = directory.parent
        if not os.access(directory, os.W_OK):
            return f"{directory} is not writable"
        return None

    def load(self) -> dict[str, Any]:
        """Load raw config dict from YAML, with tag placeholders.

        Calls ``load_dotenv_once()`` before parsing to ensure ``!env``
        tags can resolve.  Tag-free spellings (``{"!env": NAME}``) are
        converted to the same placeholders as the tags.  Updates
        ``last_file_sha256`` with the SHA-256 of the raw file bytes that
        were loaded.

        Returns:
            Raw config dict with ``EnvVar``/``VarRef``/``FileRef``
            placeholders.

        Raises:
            FileNotFoundError: If the YAML file does not exist.
        """
        load_dotenv_once(self.path)

        if not self.path.exists():
            raise FileNotFoundError(f"Config file not found: {self.path}")

        raw_bytes = self.path.read_bytes()
        self.last_file_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        raw = yaml.load(raw_bytes, Loader=make_config_loader())

        if not isinstance(raw, dict):
            raise ValueError(f"Config file must be a YAML mapping: {self.path}")

        # The root is the config mapping itself, never a tag.
        for key in raw:
            raw[key] = resolve_tag_mappings(raw[key], str(key))
        return raw

    def save(self, data: dict[str, Any]) -> None:
        """Write config dict back to YAML atomically.

        Writes to a temporary file first, then renames it to the target
        path.  This ensures the config file is never partially written.
        The rename is atomic on the same filesystem.

        The data dict uses the nested YAML structure (not flat field
        names).  Callers should use ``flat_to_nested_*`` helpers to
        convert from flat canonical dicts before calling ``save()``.

        Uses a custom Dumper that preserves ``!env``, ``!var`` and
        ``!file`` tags for round-trip fidelity.

        Args:
            data: Config dict in nested YAML format.

        Raises:
            ConfigReadOnlyError: If the file is read-only (see
                ``read_only_reason()``).
        """
        reason = self.read_only_reason()
        if reason is not None:
            raise ConfigReadOnlyError(f"Config is read-only: {reason}")
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
