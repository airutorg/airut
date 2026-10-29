# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""YAML ``!env`` tag resolution for host environment variables.

Shared by the gateway (``airut.gateway.config``) and the sandbox CLI
(``airut.sandbox_cli``).  The gateway's config loader
(``airut.config.source``) adds ``!file`` on top; the sandbox CLI, which
reads repository-provided config, does not read host files.
"""

import os
import stat
from pathlib import Path

import yaml


class EnvVar:
    """Placeholder for an unresolved ``!env VAR_NAME`` tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name

    def __repr__(self) -> str:
        return f"EnvVar({self.var_name!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EnvVar):
            return self.var_name == other.var_name
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("EnvVar", self.var_name))


class VarRef:
    """Placeholder for an unresolved ``!var VAR_NAME`` tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name

    def __repr__(self) -> str:
        return f"VarRef({self.var_name!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, VarRef):
            return self.var_name == other.var_name
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("VarRef", self.var_name))


class FileRefError(ValueError):
    """A ``!file`` reference that cannot be read."""


class FileRef:
    """Placeholder for an unresolved ``!file PATH`` tag.

    The value is the contents of the file at *path*, read on every
    config load (so a reload picks up a rotated secret).
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def __repr__(self) -> str:
        return f"FileRef({self.path!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FileRef):
            return self.path == other.path
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("FileRef", self.path))

    def read(self) -> str | None:
        """Read the referenced file as UTF-8.

        ``~`` and environment variables (e.g. systemd's
        ``$CREDENTIALS_DIRECTORY``) in the path are expanded; the result
        must be absolute.  Trailing newlines are removed, so files
        written with ``echo`` work.

        Returns:
            The file contents, or None if the file does not exist or the
            path is empty (like an unset or empty ``!env`` variable).

        Raises:
            FileRefError: If the expanded path is relative, or it exists
                but is not a readable regular file.
        """
        if not self.path:
            return None
        path = Path(os.path.expandvars(self.path)).expanduser()
        if not path.is_absolute():
            raise FileRefError(
                f"!file {self.path}: path must be absolute after expanding "
                f"~ and environment variables (got {path})"
            )
        try:
            if stat.S_ISREG(path.stat().st_mode):
                return path.read_text(encoding="utf-8").rstrip("\r\n")
        except (FileNotFoundError, NotADirectoryError):
            return None
        except (OSError, ValueError) as e:  # incl. UnicodeDecodeError
            raise FileRefError(f"!file {self.path}: cannot read: {e}") from e
        # Not a FIFO or device, which could block the config load.
        raise FileRefError(f"!file {self.path}: not a regular file")


#: Type alias for any value produced by YAML parsing with ``!env``/``!var``
#: support.  PyYAML SafeLoader produces str, int, float, bool, None, list,
#: dict; the custom tags produce :class:`EnvVar`, :class:`VarRef` and
#: :class:`FileRef`.
type YamlValue = (
    str
    | int
    | float
    | bool
    | EnvVar
    | VarRef
    | FileRef
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
    """Resolve an ``EnvVar`` or ``FileRef``, or stringify literals.

    Returns ``None`` if the value is ``None``, the env var is not set,
    or the referenced file does not exist.  Returns empty string if the
    env var is set to empty string.

    Raises:
        FileRefError: If a ``FileRef`` cannot be read.
    """
    if isinstance(value, EnvVar):
        return os.environ.get(value.var_name)
    if isinstance(value, FileRef):
        return value.read()
    if value is None:
        return None
    return str(value)
