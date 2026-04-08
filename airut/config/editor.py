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
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

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
    "DICT_FIELD_TYPES",
    "collect_leaf_fields",
    "count_dict_field_changes",
    "count_list_field_changes",
    "diff_dict_field",
    "diff_list_field",
    "find_var_references",
    "format_raw_value",
    "get_raw_value",
    "raw_values_equal",
    "rename_var_references",
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
    if isinstance(value, dict):
        if not value:
            return "(empty)"
        return f"({len(value)} entries)"
    if isinstance(value, list):
        if not value:
            return "(empty list)"
        return f"({len(value)} items)"
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


# Dict field types that need per-key diff expansion.
DICT_FIELD_TYPES = frozenset({"dict_str_str", "keyed_collection"})


def _iter_dict_diffs(
    buf_val: object,
    live_val: object,
) -> list[tuple[str, object, object]]:
    """Yield (key, old_val, new_val) for changed keys between two dicts."""
    buf_dict: dict[str, Any] = (
        cast("dict[str, Any]", buf_val) if isinstance(buf_val, dict) else {}
    )
    live_dict: dict[str, Any] = (
        cast("dict[str, Any]", live_val) if isinstance(live_val, dict) else {}
    )
    result: list[tuple[str, object, object]] = []
    for key in sorted(set(buf_dict) | set(live_dict)):
        old = live_dict[key] if key in live_dict else MISSING
        new = buf_dict[key] if key in buf_dict else MISSING
        if not raw_values_equal(old, new):
            result.append((key, old, new))
    return result


def diff_dict_field(
    fs: EditorFieldSchema,
    buf_val: object,
    live_val: object,
) -> list[dict[str, Any]]:
    """Expand a dict-typed field into per-key diff entries.

    Returns a list of change dicts with ``field``, ``scope``, ``old``,
    ``new`` keys — one per changed key.

    For keyed collections with ``item_fields``, each key is further
    expanded into per-sub-field diffs so the review dialog shows
    individual field changes instead of an opaque ``(N entries)``
    summary.
    """
    result: list[dict[str, Any]] = []
    for key, old, new in _iter_dict_diffs(buf_val, live_val):
        if fs.item_fields:
            _expand_item_fields(
                result, f"{fs.path}.{key}", fs.scope, fs.item_fields, old, new
            )
        else:
            result.append(
                {
                    "field": f"{fs.path}.{key}",
                    "scope": fs.scope,
                    "old": format_raw_value(old),
                    "new": format_raw_value(new),
                }
            )
    return result


def _iter_list_diffs(
    buf_val: object,
    live_val: object,
) -> list[tuple[str, object, object]]:
    """Yield (element, old_val, new_val) for changed elements between two lists.

    Treats lists as sets; order is ignored.
    """
    buf_set: set[str] = (
        set(cast("list[str]", buf_val)) if isinstance(buf_val, list) else set()
    )
    live_set: set[str] = (
        set(cast("list[str]", live_val))
        if isinstance(live_val, list)
        else set()
    )
    result: list[tuple[str, object, object]] = []
    for elem in sorted(live_set - buf_set):
        result.append((elem, elem, MISSING))
    for elem in sorted(buf_set - live_set):
        result.append((elem, MISSING, elem))
    return result


def diff_list_field(
    fs: EditorFieldSchema,
    buf_val: object,
    live_val: object,
) -> list[dict[str, Any]]:
    """Expand a list-typed field into per-element diff entries.

    Returns a list of change dicts with ``field``, ``scope``, ``old``,
    ``new`` keys — one per added/removed element.  Lists are compared
    as sets; order changes are ignored.
    """
    result: list[dict[str, Any]] = []
    for elem, old, new in _iter_list_diffs(buf_val, live_val):
        result.append(
            {
                "field": f"{fs.path}.{elem}",
                "scope": fs.scope,
                "old": format_raw_value(old),
                "new": format_raw_value(new),
            }
        )
    return result


def count_list_field_changes(
    buf_val: object,
    live_val: object,
) -> int:
    """Count per-element differences in a list-typed field."""
    return len(_iter_list_diffs(buf_val, live_val))


def _expand_item_fields(
    result: list[dict[str, Any]],
    prefix: str,
    scope: str,
    item_fields: list[EditorFieldSchema],
    old: object,
    new: object,
) -> None:
    """Expand a keyed collection item into per-sub-field diff entries.

    Compares each leaf field of the item and emits one change dict per
    field that differs.  When a side is ``MISSING``, all its leaf
    values are treated as ``MISSING``.
    """
    old_dict: dict[str, Any] = (
        cast("dict[str, Any]", old) if isinstance(old, dict) else {}
    )
    new_dict: dict[str, Any] = (
        cast("dict[str, Any]", new) if isinstance(new, dict) else {}
    )

    for leaf in collect_leaf_fields(item_fields):
        old_v = (
            get_raw_value(old_dict, leaf.path)
            if old is not MISSING
            else MISSING
        )
        new_v = (
            get_raw_value(new_dict, leaf.path)
            if new is not MISSING
            else MISSING
        )
        if not raw_values_equal(old_v, new_v):
            leaf_prefix = f"{prefix}.{leaf.path}"
            if leaf.type_tag == "dict_str_str":
                for key, old_kv, new_kv in _iter_dict_diffs(new_v, old_v):
                    result.append(
                        {
                            "field": f"{leaf_prefix}.{key}",
                            "scope": scope,
                            "old": format_raw_value(old_kv),
                            "new": format_raw_value(new_kv),
                        }
                    )
            elif leaf.type_tag == "list_str":
                for elem, old_ev, new_ev in _iter_list_diffs(new_v, old_v):
                    result.append(
                        {
                            "field": f"{leaf_prefix}.{elem}",
                            "scope": scope,
                            "old": format_raw_value(old_ev),
                            "new": format_raw_value(new_ev),
                        }
                    )
            else:
                result.append(
                    {
                        "field": leaf_prefix,
                        "scope": scope,
                        "old": format_raw_value(old_v),
                        "new": format_raw_value(new_v),
                    }
                )


def count_dict_field_changes(
    buf_val: object,
    live_val: object,
) -> int:
    """Count per-key differences in a dict-typed field."""
    return len(_iter_dict_diffs(buf_val, live_val))


# ---------------------------------------------------------------------------
# Variable cross-reference utilities
# ---------------------------------------------------------------------------


def _walk_var_refs(
    raw: dict[str, Any],
    visitor: Callable[[VarRef, Callable[[VarRef], None], str], None],
) -> None:
    """Walk *raw* (excluding ``vars:``) and call *visitor* on each ``VarRef``.

    Args:
        raw: Root raw config dict.
        visitor: Called with ``(ref, replace_fn, path)`` for each ``VarRef``.
            ``replace_fn`` accepts a new ``VarRef`` to replace the current one
            in-place.
    """

    def _walk(
        obj: Any,  # noqa: ANN401
        prefix: str,
    ) -> None:
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                val = obj[key]
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(val, VarRef):
                    visitor(
                        val,
                        lambda v, _o=obj, _k=key: _o.__setitem__(_k, v),
                        path,
                    )
                elif isinstance(val, (dict, list)):
                    _walk(val, path)
        elif isinstance(obj, list):
            for i, val in enumerate(obj):
                path = f"{prefix}[{i}]"
                if isinstance(val, VarRef):
                    visitor(
                        val, lambda v, _o=obj, _i=i: _o.__setitem__(_i, v), path
                    )
                elif isinstance(val, (dict, list)):
                    _walk(val, path)

    for key, val in raw.items():
        if key == "vars":
            continue
        if isinstance(val, VarRef):
            visitor(val, lambda v, _k=key: raw.__setitem__(_k, v), key)
        elif isinstance(val, (dict, list)):
            _walk(val, key)


def find_var_references(raw: dict[str, Any]) -> dict[str, list[str]]:
    """Walk the raw dict and find all ``VarRef`` objects.

    Returns a mapping of ``{var_name: [dot-paths that reference it]}``.
    The ``vars:`` section itself is excluded from the scan.
    """
    refs: dict[str, list[str]] = {}

    def _collect(
        ref: VarRef, _replace: Callable[[VarRef], None], path: str
    ) -> None:
        refs.setdefault(ref.var_name, []).append(path)

    _walk_var_refs(raw, _collect)
    return refs


def rename_var_references(
    raw: dict[str, Any], old_name: str, new_name: str
) -> int:
    """Rename all ``VarRef`` objects referencing *old_name* to *new_name*.

    The ``vars:`` section itself is excluded.

    Returns the number of references updated.
    """
    count = 0

    def _rename(
        ref: VarRef, replace: Callable[[VarRef], None], _path: str
    ) -> None:
        nonlocal count
        if ref.var_name == old_name:
            replace(VarRef(new_name))
            count += 1

    _walk_var_refs(raw, _rename)
    return count


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

    def set_list_item(self, path: str, index: int, value: str) -> None:
        """Set a single item in a list at the given path.

        Args:
            path: Dot-delimited YAML path to the list.
            index: Index of the item to set.
            value: New value for the item.
        """
        parts = path.split(".")
        try:
            parent, final = self._navigate(self._raw, parts)
        except KeyError:
            return
        target = parent.get(final)
        if isinstance(target, list) and 0 <= index < len(target):
            target[index] = value
            self._dirty = True

    def set_tagged_union_item(
        self, path: str, index: int, key: str, value: str | bool
    ) -> None:
        """Set a tagged union list item at the given path.

        Each item is a single-key dict like ``{"workspace_members": True}``
        or ``{"user_id": "U12345"}``.

        Args:
            path: Dot-delimited YAML path to the list.
            index: Index of the item to set.
            key: The tag key (e.g. ``"workspace_members"``).
            value: The tag value.
        """
        parts = path.split(".")
        try:
            parent, final = self._navigate(self._raw, parts)
        except KeyError:
            return
        target = parent.get(final)
        if isinstance(target, list) and 0 <= index < len(target):
            target[index] = {key: value}
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
