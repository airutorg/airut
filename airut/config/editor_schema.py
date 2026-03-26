# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor schema introspection.

Provides ``EditorFieldSchema`` for recursive editor-oriented field metadata
and ``schema_for_editor()`` that walks dataclass fields using ``FieldMeta``.
"""

from __future__ import annotations

import dataclasses
import typing
from dataclasses import dataclass
from typing import Any

from airut.config.schema import get_field_meta


# Sentinel for missing defaults (distinct from None).
MISSING = dataclasses.MISSING


# ---------------------------------------------------------------------------
# Per-field overrides that cannot be inferred from FieldMeta / annotations
# ---------------------------------------------------------------------------

FIELD_OVERRIDES: dict[str, dict[str, Any]] = {
    "GitHubAppCredential.private_key": {"multiline": True},
}

TAGGED_UNION_RULES: dict[str, list[tuple[str, str, str]]] = {
    "SlackChannelConfig.authorized": [
        ("workspace_members", "bool", "Allow all workspace members"),
        ("user_group", "str", "User group handle"),
        ("user_id", "str", "Slack user ID"),
    ],
}


# ---------------------------------------------------------------------------
# Editor field schema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EditorFieldSchema:
    """Describes a single field or composite structure for UI rendering.

    Attributes:
        name: Display name (dataclass field name).
        path: Dot-delimited path in the raw YAML dict.
        type_tag: Widget type selector.
        python_type: Human-readable Python type string.
        default: Default value (``MISSING`` if required).
        required: True if no default and not optional.
        doc: Documentation from ``FieldMeta``.
        scope: Reload scope string.
        secret: Whether the field is a secret.
        multiline: Whether to use textarea.
        nested_fields: Sub-fields for ``nested`` type_tag.
        item_class_name: Class name for keyed collection items.
        item_fields: Fields of the item class.
        tagged_union_rules: Rule descriptors for tagged union lists.
        env_eligible: Whether ``!env`` source is available.
        var_eligible: Whether ``!var`` source is available.
    """

    name: str
    path: str
    type_tag: str  # scalar, nested, list_str, etc.
    python_type: str
    default: object
    required: bool
    doc: str
    scope: str
    secret: bool
    multiline: bool = False
    nested_fields: list[EditorFieldSchema] | None = None
    item_class_name: str | None = None
    item_fields: list[EditorFieldSchema] | None = None
    tagged_union_rules: list[tuple[str, str, str]] | None = None
    env_eligible: bool = True
    var_eligible: bool = True


def _strip_optional(annotation: object) -> tuple[object, bool]:
    """Strip ``| None`` from a type annotation.

    Handles both ``typing.Union[X, None]`` and Python 3.10+
    ``X | None`` (``types.UnionType``).

    Returns (inner_type, is_optional).
    """
    import types

    origin = typing.get_origin(annotation)
    if origin is typing.Union or isinstance(annotation, types.UnionType):
        args = typing.get_args(annotation)
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return non_none[0], True
    return annotation, False


def _type_tag_for(annotation: object, qualified_name: str) -> str:
    """Determine the type_tag for a given type annotation."""
    # Check tagged union overrides first
    if qualified_name in TAGGED_UNION_RULES:
        return "tagged_union_list"

    origin = typing.get_origin(annotation)

    # list[str], tuple[str, ...], frozenset[str]
    if origin in (list, tuple, frozenset):
        args = typing.get_args(annotation)
        if args and args[0] is str:
            return "list_str"

    # dict[str, X]
    if origin is dict:
        args = typing.get_args(annotation)
        if args and len(args) == 2 and args[0] is str:
            val_type = args[1]
            if val_type is str:
                return "dict_str_str"
            if dataclasses.is_dataclass(val_type):
                return "keyed_collection"

    # Nested dataclass with FieldMeta
    if dataclasses.is_dataclass(annotation) and isinstance(annotation, type):
        meta_fields = [
            f
            for f in dataclasses.fields(annotation)
            if get_field_meta(f) is not None
        ]
        if meta_fields:
            return "nested"

    return "scalar"


def _python_type_str(annotation: object) -> str:
    """Human-readable type string for an annotation."""
    if isinstance(annotation, type):
        return annotation.__name__
    return str(annotation)


def _get_nested_fields(
    annotation: object,
    path_prefix: str,
    structure: dict[str, tuple[str, ...]] | None,
    owner_cls_name: str,
) -> list[EditorFieldSchema]:
    """Recurse into a dataclass to produce sub-field schemas."""
    if not dataclasses.is_dataclass(annotation) or not isinstance(
        annotation, type
    ):
        return []
    return _walk_fields(annotation, path_prefix, structure, owner_cls_name)


def _walk_fields(
    cls: type,
    path_prefix: str,
    structure: dict[str, tuple[str, ...]] | None,
    owner_cls_name: str | None = None,
    exclude: frozenset[str] | None = None,
) -> list[EditorFieldSchema]:
    """Walk dataclass fields and produce EditorFieldSchema list."""
    result: list[EditorFieldSchema] = []
    hints = typing.get_type_hints(cls)
    cls_name = cls.__name__

    for f in dataclasses.fields(cls):
        fm = get_field_meta(f)
        if fm is None:
            continue
        if exclude and f.name in exclude:
            continue

        annotation = hints.get(f.name, f.type)
        inner_type, is_optional = _strip_optional(annotation)

        qualified = f"{cls_name}.{f.name}"

        # Compute path
        if structure and f.name in structure:
            path_parts = structure[f.name]
            yaml_path = ".".join(
                [path_prefix, *path_parts] if path_prefix else list(path_parts)
            )
        else:
            yaml_path = f"{path_prefix}.{f.name}" if path_prefix else f.name

        type_tag = _type_tag_for(inner_type, qualified)

        # Determine default and required
        has_default = (
            f.default is not MISSING or f.default_factory is not MISSING
        )
        is_required = not has_default and not is_optional

        if f.default is not MISSING:
            default_val = f.default
        elif f.default_factory is not MISSING:
            default_val = f.default_factory()
        else:
            default_val = MISSING

        # Bool fields: no env/var
        python_type = _python_type_str(inner_type)
        env_eligible = python_type != "bool"
        var_eligible = python_type != "bool"

        # Multiline
        multiline = False

        # Nested fields
        nested_fields = None
        item_class_name = None
        item_fields = None
        tagged_union_rules = None

        if type_tag == "nested":
            nested_fields = _get_nested_fields(
                inner_type, yaml_path, None, cls_name
            )
        elif type_tag == "keyed_collection":
            dict_args = typing.get_args(inner_type)
            if dict_args and len(dict_args) == 2:
                item_cls = dict_args[1]
                item_class_name = item_cls.__name__
                item_fields = _walk_fields(item_cls, "", None, cls_name)
        elif type_tag == "tagged_union_list":
            tagged_union_rules = TAGGED_UNION_RULES.get(qualified)

        # Apply overrides
        overrides = FIELD_OVERRIDES.get(qualified, {})
        multiline = overrides.get("multiline", multiline)

        result.append(
            EditorFieldSchema(
                name=f.name,
                path=yaml_path,
                type_tag=type_tag,
                python_type=python_type,
                default=default_val,
                required=is_required,
                doc=fm.doc,
                scope=fm.scope.value,
                secret=fm.secret,
                multiline=multiline,
                nested_fields=nested_fields,
                item_class_name=item_class_name,
                item_fields=item_fields,
                tagged_union_rules=tagged_union_rules,
                env_eligible=env_eligible,
                var_eligible=var_eligible,
            )
        )

    return result


def schema_for_editor(
    config_cls: type,
    path_prefix: str = "",
    structure: dict[str, tuple[str, ...]] | None = None,
    exclude: set[str] | None = None,
) -> list[EditorFieldSchema]:
    """Walk dataclass fields recursively to produce editor schema trees.

    Uses ``FieldMeta`` for metadata and ``YAML_*_STRUCTURE`` mappings
    to compute the ``path`` for each field.

    Args:
        config_cls: A dataclass class annotated with ``FieldMeta``.
        path_prefix: Dot-delimited prefix for paths.
        structure: YAML structure mapping for path computation.
        exclude: Field names to omit from the schema (e.g. computed
            fields like ``repo_id`` that are derived from the YAML key).

    Returns:
        List of ``EditorFieldSchema`` descriptions.
    """
    return _walk_fields(
        config_cls,
        path_prefix,
        structure,
        exclude=frozenset(exclude) if exclude else None,
    )
