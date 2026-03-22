# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""YAML ``!env`` tag resolution for host environment variables.

Shared by the gateway (``airut.gateway.config``) and the sandbox CLI
(``airut.sandbox_cli``).  The gateway adds ``!secret`` and ``!secret?``
tags on top; the sandbox CLI uses ``!env`` only.
"""

import os

import yaml


class EnvVar:
    """Placeholder for an unresolved ``!env VAR_NAME`` tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name

    def __repr__(self) -> str:
        return f"EnvVar({self.var_name!r})"


class VarRef:
    """Placeholder for an unresolved ``!var VAR_NAME`` tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name

    def __repr__(self) -> str:
        return f"VarRef({self.var_name!r})"


#: Type alias for any value produced by YAML parsing with ``!env``/``!var``
#: support.  PyYAML SafeLoader produces str, int, float, bool, None, list,
#: dict; the custom tags produce :class:`EnvVar` and :class:`VarRef`.
type YamlValue = (
    str
    | int
    | float
    | bool
    | EnvVar
    | VarRef
    | None
    | list[YamlValue]
    | dict[str, YamlValue]
)


def env_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> EnvVar:
    """Handle ``!env VAR_NAME`` in YAML."""
    value = loader.construct_scalar(node)
    return EnvVar(str(value))


def var_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> VarRef:
    """Handle ``!var VAR_NAME`` in YAML."""
    value = loader.construct_scalar(node)
    return VarRef(str(value))


def make_env_loader() -> type[yaml.SafeLoader]:
    """Create a YAML ``SafeLoader`` subclass with ``!env``/``!var``."""

    class _EnvLoader(yaml.SafeLoader):
        pass

    _EnvLoader.add_constructor("!env", env_constructor)
    _EnvLoader.add_constructor("!var", var_constructor)
    return _EnvLoader


def raw_resolve(value: YamlValue) -> str | None:
    """Resolve an ``EnvVar`` to its string value, or stringify literals.

    Returns ``None`` if the value is ``None`` or the env var is not set.
    Returns empty string if the env var is set to empty string.
    """
    if isinstance(value, EnvVar):
        return os.environ.get(value.var_name)
    if value is None:
        return None
    return str(value)
