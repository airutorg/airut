# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor form parsing and raw value helpers.

``form_to_raw_dict()`` parses dot-delimited form data into the nested raw
dict format expected by ``YamlConfigSource.save()``.  Handles scalar, list,
dict, tagged union, and keyed collection encodings.

``InMemoryConfigSource`` implements ``ConfigSource`` for pre-save
validation without touching the filesystem.
"""

from typing import Any

from airut.yaml_env import EnvVar, VarRef


# ---------------------------------------------------------------------------
# form_to_raw_dict
# ---------------------------------------------------------------------------


def form_to_raw_dict(form_data: dict[str, Any]) -> dict[str, Any]:
    """Parse dot-delimited form data into a nested raw dict.

    Handles four form encoding patterns:

    * **Scalar/list**: ``path._source`` + ``path._value``
    * **Dict entry**: ``path.{i}.key`` + ``path.{i}.value._source/_value``
    * **Tagged union**: ``path.{i}._tag`` + ``path.{i}._value``
    * **Keyed collection**: ``path.{key}._key`` + sub-field pairs

    Returns a nested dict with ``EnvVar``/``VarRef`` objects for
    indirected values, suitable for ``YamlConfigSource.save()``.

    Args:
        form_data: Flat form data dict from the POST request.

    Returns:
        Nested raw config dict suitable for ``YamlConfigSource.save()``.
    """
    # Phase 1: Classify form fields by suffix
    fields: dict[str, dict[str, str]] = {}
    dict_keys: dict[str, str] = {}
    tagged_union_tags: dict[str, str] = {}
    collection_keys: dict[str, str] = {}

    for key, value in form_data.items():
        if key.startswith("_"):
            continue
        parts = key.rsplit(".", 1)
        if len(parts) != 2:
            continue
        path, suffix = parts

        if suffix in ("_source", "_value"):
            fields.setdefault(path, {})[suffix] = value
        elif suffix == "_tag":
            tagged_union_tags[path] = value
        elif suffix == "_key":
            collection_keys[path] = value
        elif suffix == "key":
            dict_keys[path] = value

    # Phase 2: Build nested dict from source/value pairs
    result: dict[str, Any] = {}

    for path, props in sorted(fields.items()):
        source = props.get("_source", "unset")
        raw_value = props.get("_value", "")

        if source == "unset":
            continue

        if source == "env":
            value: Any = EnvVar(raw_value)
        elif source == "var":
            value = VarRef(raw_value)
        elif source == "literal":
            value = _coerce_form_value(raw_value)
        else:
            continue

        _set_nested_path(result, path.split("."), value)

    # Phase 2b: Set tagged union entries as {tag: value} dicts
    for path, tag in sorted(tagged_union_tags.items()):
        raw_value = fields.get(path, {}).get("_value", "")
        val = _coerce_form_value(raw_value)
        _set_nested_path(result, path.split("."), {tag: val})

    # Phase 3: Post-process structure
    _convert_numeric_keys_to_lists(result)
    _convert_dict_entries(result, dict_keys)
    _rename_collection_keys(result, collection_keys)

    return result


def _coerce_form_value(value: str) -> Any:  # noqa: ANN401 — polymorphic return
    """Coerce a form string value to its natural Python type.

    Boolean strings → bool, numeric strings → int/float, else str.
    """
    lower = value.lower().strip()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False

    try:
        return int(value)
    except ValueError:
        pass

    try:
        return float(value)
    except ValueError:
        pass

    return value


def _set_nested_path(
    target: dict[str, Any],
    parts: list[str],
    value: Any,  # noqa: ANN401
) -> None:
    """Set a value in a nested dict using a list of path parts."""
    for part in parts[:-1]:
        if part not in target:
            target[part] = {}
        elif not isinstance(target[part], dict):
            target[part] = {}
        target = target[part]
    target[parts[-1]] = value


def _convert_numeric_keys_to_lists(d: dict[str, Any]) -> None:
    """Convert dicts with all-numeric keys into lists in-place.

    Form data uses numeric indices (``foo.0``, ``foo.1``) for list items.
    After building the nested dict these appear as ``{"0": v0, "1": v1}``.
    This recursively converts them to ``[v0, v1]``.
    """
    for key, val in list(d.items()):
        if isinstance(val, dict):
            _convert_numeric_keys_to_lists(val)
            if val and all(k.isdigit() for k in val):
                indices = sorted(val.keys(), key=lambda k: int(k))
                d[key] = [val[i] for i in indices]


def _convert_dict_entries(
    d: dict[str, Any],
    dict_keys: dict[str, str],
) -> None:
    """Convert indexed dict entries to proper key-value dicts.

    Dict widgets emit ``path.{i}.key`` and ``path.{i}.value`` fields.
    After initial processing the nested dict contains
    ``{path: [{"value": v}, ...]}`` (already list-converted).
    This converts them to ``{path: {key: v, ...}}`` using the
    collected ``dict_keys`` mapping.
    """
    for key_path, key_name in dict_keys.items():
        # key_path is like "secrets.0" — the parent is "secrets"
        parts = key_path.split(".")
        if len(parts) < 2:
            continue
        parent_parts = parts[:-1]
        index_str = parts[-1]

        # Navigate to the parent
        parent = d
        for p in parent_parts:
            if isinstance(parent, dict) and p in parent:
                parent = parent[p]
            else:
                parent = None
                break

        if parent is None:
            continue

        # Handle already-converted list
        if isinstance(parent, list):
            try:
                idx = int(index_str)
            except ValueError:
                continue
            if 0 <= idx < len(parent):
                entry = parent[idx]
                if isinstance(entry, dict) and "value" in entry:
                    parent[idx] = {
                        "_dict_key": key_name,
                        "_dict_value": entry["value"],
                    }

    # Second pass: convert tagged list entries to proper dicts
    _finalize_dict_entries(d)


def _finalize_dict_entries(d: dict[str, Any]) -> None:
    """Convert lists of ``_dict_key``/``_dict_value`` to proper dicts."""
    for key, val in list(d.items()):
        if isinstance(val, dict):
            _finalize_dict_entries(val)
        elif isinstance(val, list) and val:
            if isinstance(val[0], dict) and "_dict_key" in val[0]:
                new_dict: dict[str, Any] = {}
                for entry in val:
                    if isinstance(entry, dict):
                        k = entry.get("_dict_key", "")
                        v = entry.get("_dict_value", "")
                        if k:
                            new_dict[k] = v
                d[key] = new_dict
            else:
                for item in val:
                    if isinstance(item, dict):
                        _finalize_dict_entries(item)


def _rename_collection_keys(
    d: dict[str, Any],
    collection_keys: dict[str, str],
) -> None:
    """Rename keyed collection entries from temp names to user names.

    Collection widgets emit ``path.{key}._key`` for existing entries
    and ``path._new_{i}._key`` for new entries.  This renames the
    dict keys in the nested structure accordingly.
    """
    for key_path, new_name in collection_keys.items():
        parts = key_path.split(".")
        if len(parts) < 2:
            continue
        parent_parts = parts[:-1]
        old_key = parts[-1]

        # Navigate to the parent dict
        parent = d
        for p in parent_parts:
            if isinstance(parent, dict) and p in parent:
                parent = parent[p]
            else:
                parent = None
                break

        if not isinstance(parent, dict):
            continue

        # Rename old_key → new_name (if different and exists)
        if old_key in parent and new_name and old_key != new_name:
            parent[new_name] = parent.pop(old_key)

        # Remove the _key sentinel from the entry
        entry = parent.get(new_name) or parent.get(old_key)
        if isinstance(entry, dict) and "_key" in entry:
            del entry["_key"]


# ---------------------------------------------------------------------------
# Raw value helpers
# ---------------------------------------------------------------------------


def get_raw_value(
    raw: dict[str, Any] | None,
    yaml_path: tuple[str, ...],
) -> Any:  # noqa: ANN401 — raw values are EnvVar|VarRef|literal
    """Navigate a raw config dict by YAML path to get the stored value.

    Returns the raw value (may be ``EnvVar``, ``VarRef``, or literal),
    or ``None`` if not found.

    Args:
        raw: Raw config dict (from ConfigSnapshot.raw).
        yaml_path: Nested key path.

    Returns:
        The raw value at the path, or ``None``.
    """
    if raw is None:
        return None
    current: Any = raw
    for key in yaml_path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def detect_source(raw_value: Any) -> str:  # noqa: ANN401 — polymorphic input
    """Detect the source type of a raw config value.

    Returns ``"env"``, ``"var"``, ``"literal"``, or ``"unset"``.
    """
    if raw_value is None:
        return "unset"
    if isinstance(raw_value, EnvVar):
        return "env"
    if isinstance(raw_value, VarRef):
        return "var"
    return "literal"


def get_source_ref(raw_value: Any) -> str:  # noqa: ANN401 — polymorphic input
    """Get the reference name for !env or !var values.

    Returns the var_name for EnvVar/VarRef, empty string otherwise.
    """
    if isinstance(raw_value, (EnvVar, VarRef)):
        return raw_value.var_name
    return ""


# ---------------------------------------------------------------------------
# InMemoryConfigSource
# ---------------------------------------------------------------------------


class InMemoryConfigSource:
    """ConfigSource that returns a pre-built dict for validation.

    Used to validate proposed config changes through the full
    ``ServerConfig.from_source()`` pipeline without touching the file.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def load(self) -> dict[str, Any]:
        """Return the pre-built config dict."""
        return self._data

    def save(self, data: dict[str, Any]) -> None:
        """Not supported — in-memory source is read-only."""
        raise NotImplementedError("In-memory source is read-only")
