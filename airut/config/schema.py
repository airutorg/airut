# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Declarative config field metadata and schema introspection.

Provides ``FieldMeta`` for annotating config dataclass fields with
human-readable documentation, reload scope, and secret flags.
``schema_for_ui()`` extracts UI-friendly metadata from annotated classes.

Usage::

    @dataclass(frozen=True)
    class MyConfig:
        host: str = field(
            default="127.0.0.1",
            metadata=meta("HTTP server bind address", Scope.SERVER),
        )
"""

import dataclasses
import typing
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Scope(Enum):
    """When does a change to this setting take effect?"""

    SERVER = "server"  # Requires full server restart
    REPO = "repo"  # Reloadable per-repo without server restart
    TASK = "task"  # Applied per-task, effective immediately


@dataclass(frozen=True)
class FieldMeta:
    """Declarative metadata for a config field.

    Attributes:
        doc: Human-readable description.
        scope: Reload scope (when changes take effect).
        secret: Informational flag for UI (masking inputs, hiding diffs).
        hidden: Hide from config editor UI (for internal/test-only fields).
        since_version: Schema version that introduced this field.
    """

    doc: str
    scope: Scope
    secret: bool = False
    hidden: bool = False
    since_version: int = 1


#: Metadata dict key to avoid collisions with other metadata consumers.
_META_KEY = "airut_config"


def meta(
    doc: str,
    scope: Scope,
    *,
    secret: bool = False,
    hidden: bool = False,
    since_version: int = 1,
) -> dict[str, FieldMeta]:
    """Attach ``FieldMeta`` via ``dataclass field(metadata=meta(...))``.

    Args:
        doc: Human-readable field description.
        scope: Reload scope.
        secret: Whether this field holds a secret value.
        hidden: Hide from config editor UI.
        since_version: Schema version that introduced this field.

    Returns:
        Metadata dict suitable for ``field(metadata=...)``.
    """
    return {
        _META_KEY: FieldMeta(
            doc=doc,
            scope=scope,
            secret=secret,
            hidden=hidden,
            since_version=since_version,
        )
    }


def get_field_meta(f: dataclasses.Field[Any]) -> FieldMeta | None:
    """Extract ``FieldMeta`` from a dataclass field, or ``None``.

    Args:
        f: A dataclass field.

    Returns:
        The ``FieldMeta`` instance, or ``None`` if not annotated.
    """
    return f.metadata.get(_META_KEY)


@dataclass(frozen=True)
class FieldSchema:
    """UI-consumable field description.

    Attributes:
        name: Field name (dataclass field name).
        type_name: Python annotation as string (e.g. ``"str | None"``).
        default: Default value (``MISSING`` if required).
        required: True if no default.
        doc: Human-readable description.
        scope: Scope value string (``"server"``, ``"repo"``, or ``"task"``).
        secret: Whether the field holds a secret.
    """

    name: str
    type_name: str
    default: Any
    required: bool
    doc: str
    scope: str
    secret: bool


def schema_for_ui(config_cls: type) -> list[FieldSchema]:
    """Extract field metadata for UI rendering.

    Only fields annotated with ``FieldMeta`` are included.  Fields
    without metadata (computed fields, internal state) are excluded.

    Args:
        config_cls: A dataclass class annotated with ``FieldMeta``.

    Returns:
        List of ``FieldSchema`` descriptions for UI consumption.
    """
    result: list[FieldSchema] = []
    hints = typing.get_type_hints(config_cls)
    for f in dataclasses.fields(config_cls):
        fm = get_field_meta(f)
        if fm is None:
            continue
        if fm.hidden:
            continue

        has_default = (
            f.default is not dataclasses.MISSING
            or f.default_factory is not dataclasses.MISSING
        )
        default_value: Any
        if f.default is not dataclasses.MISSING:
            default_value = f.default
        elif f.default_factory is not dataclasses.MISSING:
            default_value = f.default_factory()
        else:
            default_value = dataclasses.MISSING

        # Get the annotation as a human-readable string
        annotation = hints.get(f.name, f.type)
        if isinstance(annotation, str):
            type_name = annotation
        elif isinstance(annotation, type):
            type_name = annotation.__name__
        else:
            type_name = str(annotation)

        result.append(
            FieldSchema(
                name=f.name,
                type_name=type_name,
                default=default_value,
                required=not has_default,
                doc=fm.doc,
                scope=fm.scope.value,
                secret=fm.secret,
            )
        )
    return result
