# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config snapshot tracking which fields were explicitly set.

``ConfigSnapshot`` wraps a frozen config dataclass and records which
fields the user explicitly set in the source data (vs. which fell
through to defaults).  ``to_dict()`` can serialize only user-set
values, preserving round-trip fidelity.
"""

import dataclasses
from typing import Any


class ConfigSnapshot[T]:
    """Wraps a frozen config dataclass, tracking which fields were set.

    Attributes:
        _instance: The underlying config dataclass instance.
        _provided_keys: Field names explicitly set in the source data.
        _raw: Complete raw YAML dict with ``vars:``, ``VarRef``, and
            ``EnvVar`` preserved for round-trip serialization.  ``None``
            when no raw document is available (e.g. synthetic snapshots).
    """

    def __init__(
        self,
        instance: T,
        provided_keys: frozenset[str],
        raw: dict[str, Any] | None = None,
    ) -> None:
        self._instance = instance
        self._provided_keys = provided_keys
        self._raw = raw

    @property
    def value(self) -> T:
        """The underlying config dataclass instance."""
        return self._instance

    @property
    def provided_keys(self) -> frozenset[str]:
        """Field names that were explicitly set in the source data."""
        return self._provided_keys

    @property
    def raw(self) -> dict[str, Any] | None:
        """Raw YAML dict with tags and vars: preserved (for editor / save)."""
        return self._raw

    def to_dict(self, *, include_defaults: bool = False) -> dict[str, Any]:
        """Serialize to flat dict keyed by dataclass field names.

        When ``include_defaults`` is False (the default), only fields in
        ``provided_keys`` are included -- defaults are not baked in.
        Nested ``ConfigSnapshot`` values are serialized recursively.

        Args:
            include_defaults: If True, include all fields (not just
                user-set ones).

        Returns:
            Dict of field name -> value.
        """
        result: dict[str, Any] = {}

        for f in dataclasses.fields(self._instance):  # type: ignore[arg-type]
            if not include_defaults and f.name not in self._provided_keys:
                continue

            value = getattr(self._instance, f.name)
            result[f.name] = _serialize_value(value, include_defaults)

        return result

    def __repr__(self) -> str:
        cls_name = type(self._instance).__name__
        n_provided = len(self._provided_keys)
        n_total = len(dataclasses.fields(self._instance))  # type: ignore[arg-type]
        return f"ConfigSnapshot({cls_name}, provided={n_provided}/{n_total})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConfigSnapshot):
            return NotImplemented
        return (
            type(self._instance) is type(other._instance)
            and self._instance == other._instance
            and self._provided_keys == other._provided_keys
        )


def _serialize_value(value: object, include_defaults: bool) -> object:
    """Recursively serialize a config value for ``to_dict()``.

    Handles nested ``ConfigSnapshot`` instances, dicts, and lists.
    """
    if isinstance(value, ConfigSnapshot):
        return value.to_dict(include_defaults=include_defaults)
    if isinstance(value, dict):
        return {
            k: _serialize_value(v, include_defaults) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_serialize_value(v, include_defaults) for v in value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value
