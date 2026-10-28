# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config variable resolution (``vars:`` / ``!var``).

Resolves the ``vars:`` top-level section and substitutes ``!var`` references
throughout the raw config dict.  Called as a pre-processing step before
``_from_raw()`` — the existing resolution pipeline never sees ``VarRef``.
"""

from typing import Any

from airut.gateway.config import ConfigError
from airut.yaml_env import Unresolved, VarRef, raw_resolve


#: A resolved variable: its value, ``None`` if unset, or (in an offline
#: check) the ``Unresolved`` stand-in for its reference.
type VarValue = str | Unresolved | None


def resolve_vars_section(raw: dict[str, Any]) -> dict[str, VarValue]:
    """Read ``vars:`` from the raw dict and resolve each value.

    Variable values may be literals, ``!env`` or ``!file`` references.  ``!var``
    references inside ``vars:`` are forbidden (no var-to-var).

    Args:
        raw: Raw config dict (may or may not contain ``vars:``).

    Returns:
        Resolved vars table ``{name: resolved_value}``.  Missing env vars
        produce ``None``.  ``Unresolved`` stand-ins are kept as they
        are, so fields referencing the variable see the stand-in.

    Raises:
        ConfigError: If a var value is a ``VarRef`` (var-to-var).
    """
    vars_section = raw.get("vars")
    if vars_section is None:
        return {}

    if not isinstance(vars_section, dict):
        raise ConfigError("'vars' must be a YAML mapping")

    table: dict[str, VarValue] = {}
    for name, value in vars_section.items():
        name = str(name)
        if isinstance(value, VarRef):
            raise ConfigError(
                f"vars.{name}: !var references inside vars: are not allowed "
                f"(no var-to-var)"
            )
        if isinstance(value, (dict, list)):
            raise ConfigError(
                f"vars.{name}: variable values must be scalars, "
                f"not {type(value).__name__}"
            )
        table[name] = (
            value if isinstance(value, Unresolved) else raw_resolve(value)
        )

    return table


def resolve_var_refs(
    raw: dict[str, Any],
    table: dict[str, VarValue],
) -> dict[str, Any]:
    """Walk *raw* and replace every ``VarRef`` with its resolved value.

    Also removes the ``vars:`` key from the dict (consumed by the caller).
    ``EnvVar`` objects are left in place for downstream ``_resolve()``.

    Args:
        raw: Raw config dict (modified in place and returned).
        table: Resolved vars table from :func:`resolve_vars_section`.

    Returns:
        The same *raw* dict with ``VarRef`` replaced and ``vars:`` removed.

    Raises:
        ConfigError: If a ``!var`` references an undefined variable name.
    """
    raw.pop("vars", None)
    _walk(raw, table)
    return raw


def _resolve_ref(
    ref: VarRef,
    table: dict[str, VarValue],
) -> VarValue:
    """Look up a single ``VarRef`` in the vars table."""
    if ref.var_name not in table:
        raise ConfigError(
            f"!var {ref.var_name}: undefined variable (not in vars: section)"
        )
    return table[ref.var_name]


def _walk(
    obj: Any,  # noqa: ANN401 — recursive tree walker needs Any
    table: dict[str, VarValue],
) -> None:
    """Recursively resolve ``VarRef`` in a nested structure (in place)."""
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if isinstance(key, VarRef):
                raise ConfigError(
                    f"!var {key.var_name}: cannot be used as a "
                    f"mapping key (scalar values only)"
                )
            val = obj[key]
            if isinstance(val, VarRef):
                obj[key] = _resolve_ref(val, table)
            elif isinstance(val, (dict, list)):
                _walk(val, table)

    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            if isinstance(val, VarRef):
                obj[i] = _resolve_ref(val, table)
            elif isinstance(val, (dict, list)):
                _walk(val, table)
