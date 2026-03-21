# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config diffing utilities.

Compares ``ConfigSnapshot`` instances and groups changes by reload scope.
Diff output contains actual values; consumers must check
``FieldMeta.secret`` and mask values before logging or UI display.
"""

import dataclasses
from typing import Any, cast

from airut.config.schema import Scope, get_field_meta
from airut.config.snapshot import ConfigSnapshot


def diff_configs[T](
    current: ConfigSnapshot[T],
    new: ConfigSnapshot[T],
) -> dict[str, tuple[Any, Any]]:
    """Return ``{field_name: (old_value, new_value)}`` for differing fields.

    Only compares fields that are set in at least one snapshot.
    Both snapshots must wrap the same config type.
    Nested ``ConfigSnapshot`` values are compared by their underlying
    instance equality.

    Args:
        current: The currently active config snapshot.
        new: The freshly loaded config snapshot.

    Returns:
        Dict of changed fields with ``(old, new)`` value tuples.
    """
    result: dict[str, tuple[Any, Any]] = {}

    all_keys = current.provided_keys | new.provided_keys
    fields_by_name = {
        f.name: f for f in dataclasses.fields(cast(Any, current.value))
    }

    for key in sorted(all_keys):
        if key not in fields_by_name:
            continue

        old_val = getattr(current.value, key)
        new_val = getattr(new.value, key)

        # Unwrap ConfigSnapshot for comparison
        if isinstance(old_val, ConfigSnapshot):
            old_val = old_val.value
        if isinstance(new_val, ConfigSnapshot):
            new_val = new_val.value

        if old_val != new_val:
            result[key] = (old_val, new_val)

    return result


def diff_by_scope[T](
    current: ConfigSnapshot[T],
    new: ConfigSnapshot[T],
) -> dict[Scope, dict[str, tuple[Any, Any]]]:
    """Group config changes by their reload scope.

    Returns ``{Scope.SERVER: {...}, Scope.REPO: {...}, Scope.TASK: {...}}``.
    Empty scopes are included with empty dicts.

    Args:
        current: The currently active config snapshot.
        new: The freshly loaded config snapshot.

    Returns:
        Changes grouped by scope.
    """
    changes = diff_configs(current, new)
    grouped: dict[Scope, dict[str, tuple[Any, Any]]] = {
        scope: {} for scope in Scope
    }

    fields_by_name = {
        f.name: f for f in dataclasses.fields(cast(Any, current.value))
    }

    for field_name, change in changes.items():
        f = fields_by_name[field_name]
        fm = get_field_meta(f)
        if fm is None:
            # Fields without metadata default to SERVER scope
            grouped[Scope.SERVER][field_name] = change
        else:
            grouped[fm.scope][field_name] = change

    return grouped
