# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor backend: edit buffer and in-memory source.

Provides ``EditBuffer`` for server-side mutable config editing and
``InMemoryConfigSource`` for pre-save validation.

Schema introspection (``EditorFieldSchema``, ``schema_for_editor()``) lives
in ``airut.config.editor_schema`` and is re-exported here for convenience.
"""

from __future__ import annotations

import copy
import dataclasses
import logging
from typing import TYPE_CHECKING, Any

from airut.config.editor_schema import EditorFieldSchema, schema_for_editor
from airut.yaml_env import EnvVar, VarRef


if TYPE_CHECKING:
    from airut.config.snapshot import ConfigSnapshot


# Re-exported from editor_schema for convenience.
__all__ = [
    "MISSING",
    "EditBuffer",
    "EditorFieldSchema",
    "InMemoryConfigSource",
    "collect_leaf_fields",
    "format_raw_value",
    "get_raw_value",
    "raw_values_equal",
    "schema_for_editor",
    "value_source",
]

logger = logging.getLogger(__name__)

# Sentinel for missing defaults (distinct from None).
MISSING = dataclasses.MISSING


def value_source(value: object) -> tuple[str, object]:
    """Determine the source type and underlying value for a raw dict value.

    Returns (source_type, display_value) where source_type is one of:
    ``"literal"``, ``"env"``, ``"var"``, ``"unset"``.
    """
    if isinstance(value, EnvVar):
        return "env", value.var_name
    if isinstance(value, VarRef):
        return "var", value.var_name
    if value is MISSING:
        return "unset", None
    return "literal", value


# ---------------------------------------------------------------------------
# Raw-dict utilities (shared by EditBuffer and handlers_config)
# ---------------------------------------------------------------------------


def get_raw_value(raw: dict[str, Any] | None, path: str) -> object:
    """Navigate a raw dict by dot-path, returning ``MISSING`` if absent."""
    if raw is None:
        return MISSING
    current: Any = raw
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    return current


def raw_values_equal(a: object, b: object) -> bool:
    """Compare two raw config values, handling ``EnvVar``/``VarRef``."""
    if isinstance(a, EnvVar) and isinstance(b, EnvVar):
        return a.var_name == b.var_name
    if isinstance(a, VarRef) and isinstance(b, VarRef):
        return a.var_name == b.var_name
    if type(a) is not type(b):
        return False
    return a == b


def format_raw_value(value: object) -> str:
    """Format a config value for diff display."""
    if value is None or value is MISSING:
        return "(not set)"
    if isinstance(value, EnvVar):
        return f"!env {value.var_name}"
    if isinstance(value, VarRef):
        return f"!var {value.var_name}"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def collect_leaf_fields(
    fields: list[EditorFieldSchema],
) -> list[EditorFieldSchema]:
    """Recursively collect leaf (scalar) fields from the schema."""
    result: list[EditorFieldSchema] = []
    for fs in fields:
        if fs.nested_fields:
            result.extend(collect_leaf_fields(fs.nested_fields))
        else:
            result.append(fs)
    return result


# ---------------------------------------------------------------------------
# In-memory config source (for pre-save validation)
# ---------------------------------------------------------------------------


class InMemoryConfigSource:
    """Read-only ``ConfigSource`` wrapping a pre-built dict.

    Used for pre-save validation:
    ``ServerConfig.from_source(InMemoryConfigSource(d))`` exercises
    the full config pipeline without touching the file.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def load(self) -> dict[str, Any]:
        """Return the in-memory data dict."""
        return self._data

    def save(self, data: dict[str, Any]) -> None:
        """Not supported — in-memory source is read-only."""
        raise NotImplementedError("In-memory source is read-only")


# ---------------------------------------------------------------------------
# Edit buffer
# ---------------------------------------------------------------------------


class EditBuffer:
    """Server-side mutable copy of config for editing.

    A singleton held by the dashboard server — one edit session at a
    time (single-user system).

    Attributes:
        _raw: Mutable deep copy of ``ConfigSnapshot.raw``.
        _generation: ``_config_generation`` at buffer creation.
        _dirty: Whether any mutations have been applied.
    """

    def __init__(self, raw: dict[str, Any], generation: int) -> None:
        """Create an edit buffer from a raw YAML dict.

        Args:
            raw: Deep copy of ``ConfigSnapshot.raw``.
            generation: Current ``_config_generation`` value.
        """
        self._raw = copy.deepcopy(raw)
        self._generation = generation
        self._dirty = False

    @property
    def raw(self) -> dict[str, Any]:
        """The mutable raw dict."""
        return self._raw

    @property
    def generation(self) -> int:
        """Config generation at buffer creation."""
        return self._generation

    @property
    def dirty(self) -> bool:
        """Whether any mutations have been applied."""
        return self._dirty

    def is_stale(self, current_generation: int) -> bool:
        """Check if the buffer's generation is behind the current one."""
        return self._generation != current_generation

    def mark_clean(self) -> None:
        """Reset the dirty flag after a successful save."""
        self._dirty = False

    def mark_dirty(self) -> None:
        """Set the dirty flag (e.g. after a direct raw mutation)."""
        self._dirty = True

    # -- Path navigation helpers --

    @staticmethod
    def _navigate(
        raw: dict[str, Any], parts: list[str], *, create: bool = False
    ) -> tuple[dict[str, Any], str]:
        """Navigate to parent dict and return (parent, final_key).

        Args:
            raw: Root dict.
            parts: Dot-split path parts.
            create: If True, create intermediate dicts.

        Returns:
            Tuple of (parent dict, final key).

        Raises:
            KeyError: If an intermediate key is missing and create=False.
        """
        current = raw
        for part in parts[:-1]:
            if create:
                current = current.setdefault(part, {})
            else:
                current = current[part]
        return current, parts[-1]

    @staticmethod
    def _prune_empty(raw: dict[str, Any], parts: list[str]) -> None:
        """Remove empty parent dicts after a key deletion."""
        # Walk from deepest to shallowest, removing empty dicts
        for depth in range(len(parts) - 1, 0, -1):
            parent = raw
            for part in parts[: depth - 1]:
                parent = parent.get(part, {})
            key = parts[depth - 1]
            child = parent.get(key)
            if isinstance(child, dict) and not child:
                del parent[key]
            else:
                break

    # -- Mutation operations --

    def set_field(
        self,
        path: str,
        source: str,
        value: object = None,
    ) -> None:
        """Set a single scalar field in the buffer.

        Args:
            path: Dot-delimited YAML path.
            source: One of ``"literal"``, ``"env"``, ``"var"``, ``"unset"``.
            value: The value (for literal/env/var sources).
        """
        parts = path.split(".")

        if source == "unset":
            try:
                parent, key = self._navigate(self._raw, parts)
                if key in parent:
                    del parent[key]
                    self._prune_empty(self._raw, parts)
            except KeyError:
                pass  # Already unset
        else:
            parent, key = self._navigate(self._raw, parts, create=True)
            if source == "env":
                parent[key] = EnvVar(str(value))
            elif source == "var":
                parent[key] = VarRef(str(value))
            else:
                # Literal — coerce type
                parent[key] = value

        self._dirty = True

    def add_item(self, path: str, key: str | None = None) -> None:
        """Add an item to a list or keyed collection.

        Args:
            path: Dot-delimited YAML path to the collection.
            key: For keyed collections, the new entry's key.
        """
        parts = path.split(".")
        parent, final = self._navigate(self._raw, parts, create=True)
        target = parent.get(final)

        if key is not None:
            # Keyed collection — create empty dict for the new key
            if not isinstance(target, dict):
                parent[final] = {}
                target = parent[final]
            target[key] = {}
        else:
            # List — append empty string
            if not isinstance(target, list):
                parent[final] = []
                target = parent[final]
            target.append("")

        self._dirty = True

    def remove_item(
        self, path: str, key: str | None = None, index: int | None = None
    ) -> None:
        """Remove an item from a list or keyed collection.

        Args:
            path: Dot-delimited YAML path.
            key: For keyed collections, the entry's key.
            index: For lists, the item index.
        """
        parts = path.split(".")

        if key is not None:
            # Keyed collection — remove by key
            try:
                parent, final = self._navigate(self._raw, parts)
                target = parent.get(final)
                if isinstance(target, dict) and key in target:
                    del target[key]
            except KeyError:
                pass
        elif index is not None:
            # List — remove by index
            try:
                parent, final = self._navigate(self._raw, parts)
                target = parent.get(final)
                if isinstance(target, list) and 0 <= index < len(target):
                    target.pop(index)
            except KeyError:
                pass
        else:
            # Remove the entire path (for channel/repo removal)
            try:
                parent, final = self._navigate(self._raw, parts)
                if final in parent:
                    del parent[final]
                    self._prune_empty(self._raw, parts)
            except KeyError:
                pass

        self._dirty = True

    def get_value(self, path: str) -> object:
        """Get a value at the given path, or MISSING if not set.

        Args:
            path: Dot-delimited YAML path.

        Returns:
            The value, or ``MISSING`` if path does not exist.
        """
        return get_raw_value(self._raw, path)

    def validate(self) -> ConfigSnapshot:
        """Validate the buffer by running through the full config pipeline.

        Returns:
            A ``ConfigSnapshot`` if validation succeeds.

        Raises:
            Exception: Any validation error from ``ServerConfig.from_source()``.
        """
        from airut.gateway.config import ServerConfig

        return ServerConfig.from_source(
            InMemoryConfigSource(copy.deepcopy(self._raw))
        )
