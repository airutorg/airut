# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Hatch hooks for dynamic versioning and build-time version embedding.

This module provides two hatchling hooks that work together:

1. **Metadata hook** (``GitVersionMetadataHook``) — sets the package
   version dynamically from ``git describe`` so that ``pyproject.toml``
   does not need a static ``version`` field.  The version is derived
   from the nearest ``v*`` tag (e.g. ``v0.9.0`` → ``0.9.0``).

2. **Build hook** (``GitVersionBuildHook``) — generates
   ``lib/_version.py`` with the full version string, short SHA and full
   SHA so that the running service can display version info without
   needing git at runtime.

When building from an sdist (no ``.git`` directory), both hooks fall
back to reading the previously generated ``lib/_version.py``.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from hatchling.builders.hooks.plugin.interface import (  # ty: ignore[unresolved-import]  # build-time dep
        BuildHookInterface,
    )
    from hatchling.metadata.plugin.interface import (  # ty: ignore[unresolved-import]  # build-time dep
        MetadataHookInterface,
    )

    _BuildBase = BuildHookInterface
    _MetaBase = MetadataHookInterface
else:
    try:
        from hatchling.builders.hooks.plugin.interface import (
            BuildHookInterface,
        )

        _BuildBase = BuildHookInterface
    except ImportError:  # pragma: no cover
        _BuildBase = object

    try:
        from hatchling.metadata.plugin.interface import (
            MetadataHookInterface,
        )

        _MetaBase = MetadataHookInterface
    except ImportError:  # pragma: no cover
        _MetaBase = object


_VERSION_TEMPLATE = '''\
"""Auto-generated at build time — do not edit."""

VERSION = {version!r}
GIT_SHA_SHORT = {sha_short!r}
GIT_SHA_FULL = {sha_full!r}
'''


def _run_git(*args: str) -> str:
    """Run a git command and return stripped stdout.

    Raises:
        subprocess.CalledProcessError: If the command fails.
    """
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _git_version_tag() -> str:
    """Get version string from ``git describe``.

    Returns:
        Raw tag string like ``v0.9.0`` or ``v0.9.0-3-gabc1234-dirty``.

    Raises:
        subprocess.CalledProcessError: If no matching tags exist.
    """
    return _run_git("describe", "--tags", "--match", "v*", "--dirty")


def _tag_to_pep440(tag: str) -> str:
    """Convert a git describe tag to a PEP 440 version string.

    Examples:
        ``v0.9.0``                → ``0.9.0``
        ``v0.9.0-3-gabc1234``     → ``0.9.0.dev3+gabc1234``
        ``v0.9.0-dirty``          → ``0.9.0+dirty``
        ``v0.9.0-3-gabc1234-dirty`` → ``0.9.0.dev3+gabc1234.dirty``

    Args:
        tag: Raw output from ``git describe --tags --match v* --dirty``.

    Returns:
        PEP 440 compliant version string.
    """
    # Strip leading 'v'
    tag = tag.lstrip("v")

    # Pattern: BASE[-DISTANCE-gHASH][-dirty]
    m = re.match(
        r"^(?P<base>[^-]+)"
        r"(?:-(?P<distance>\d+)-(?P<hash>g[0-9a-f]+))?"
        r"(?:-(?P<dirty>dirty))?$",
        tag,
    )
    if not m:
        return tag

    version = m.group("base")
    distance = m.group("distance")
    git_hash = m.group("hash")
    dirty = m.group("dirty")

    local_parts: list[str] = []
    if distance:
        version += f".dev{distance}"
        local_parts.append(git_hash)
    if dirty:
        local_parts.append("dirty")
    if local_parts:
        version += "+" + ".".join(local_parts)

    return version


def _read_version_from_file(root: Path) -> str | None:
    """Read VERSION from an existing ``lib/_version.py``.

    Used as fallback when git is unavailable (e.g. building wheel from
    sdist).

    Returns:
        The version string (with ``v`` prefix stripped), or None if the
        file doesn't exist or can't be parsed.
    """
    version_file = root / "lib" / "_version.py"
    if not version_file.exists():
        return None

    content = version_file.read_text()
    m = re.search(r"VERSION\s*=\s*['\"](.+?)['\"]", content)
    if not m:
        return None

    return _tag_to_pep440(m.group(1))


def _get_build_version() -> tuple[str, str, str]:
    """Determine version string and SHAs from git state.

    Returns:
        Tuple of (version, sha_short, sha_full).
    """
    sha_short = _run_git("rev-parse", "--short", "HEAD")
    sha_full = _run_git("rev-parse", "HEAD")

    try:
        version = _git_version_tag()
    except subprocess.CalledProcessError:
        # No matching tags — use 0.0.0 as base with commit ref
        version = f"v0.0.0-0-g{sha_short}"

    return version, sha_short, sha_full


class GitVersionMetadataHook(_MetaBase):
    """Hatch metadata hook that sets version from git tags.

    Reads the version from ``git describe --tags --match v*`` and
    converts it to a PEP 440 version string.  When git is unavailable
    (e.g. building a wheel from an sdist), falls back to reading the
    version from the previously generated ``lib/_version.py``.
    """

    PLUGIN_NAME = "git-version"

    def update(self, metadata: dict[str, Any]) -> None:
        """Set the version in project metadata from git tags."""
        # Try git first
        try:
            tag = _git_version_tag()
            metadata["version"] = _tag_to_pep440(tag)
            return
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Fallback: read from existing _version.py (sdist → wheel)
        version = _read_version_from_file(Path(self.root))
        if version is not None:
            metadata["version"] = version
            return

        # Last resort
        metadata["version"] = "0.0.0"


class GitVersionBuildHook(_BuildBase):
    """Hatch build hook that generates lib/_version.py."""

    PLUGIN_NAME = "git-version"

    def initialize(
        self,
        version: str,
        build_data: dict[str, Any],
    ) -> None:
        """Generate lib/_version.py with embedded version info."""
        version_file = Path(self.root) / "lib" / "_version.py"

        try:
            ver, sha_short, sha_full = _get_build_version()
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Not a git repo or git not installed.  If the file already
            # exists (e.g. building a wheel from an sdist that baked it
            # in), force-include it so hatchling doesn't exclude it via
            # .gitignore patterns.
            if version_file.exists():
                build_data.setdefault("force_include", {})[
                    str(version_file)
                ] = "lib/_version.py"
            return

        version_file.write_text(
            _VERSION_TEMPLATE.format(
                version=ver,
                sha_short=sha_short,
                sha_full=sha_full,
            )
        )
        # Ensure the file is included in the build
        build_data.setdefault("force_include", {})[str(version_file)] = (
            "lib/_version.py"
        )


def get_build_hook() -> type:
    """Disambiguator for hatchling — return the build hook class."""
    return GitVersionBuildHook


def get_metadata_hook() -> type:
    """Disambiguator for hatchling — return the metadata hook class."""
    return GitVersionMetadataHook
