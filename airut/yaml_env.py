# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""YAML ``!env`` tag resolution for host environment variables.

Shared by the gateway (``airut.gateway.config``) and the sandbox CLI
(``airut.sandbox_cli``).  Both use ``!env`` only.
"""

import os

import yaml


class EnvVar:
    """Placeholder for an unresolved ``!env VAR_NAME`` tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name


#: Type alias for any value produced by YAML parsing with ``!env`` support.
#: PyYAML SafeLoader produces str, int, float, bool, None, list, dict;
#: the custom ``!env`` tag produces :class:`EnvVar`.
type YamlValue = (
    str
    | int
    | float
    | bool
    | EnvVar
    | None
    | list[YamlValue]
    | dict[str, YamlValue]
)


def env_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> EnvVar:
    """Handle ``!env VAR_NAME`` in YAML."""
    value = loader.construct_scalar(node)
    return EnvVar(str(value))


def make_env_loader() -> type[yaml.SafeLoader]:
    """Create a YAML ``SafeLoader`` subclass that understands ``!env``."""

    class _EnvLoader(yaml.SafeLoader):
        pass

    _EnvLoader.add_constructor("!env", env_constructor)
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
