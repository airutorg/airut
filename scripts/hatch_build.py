# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Hatch build hook to embed git version info into lib/_version.py.

At wheel-build time this hook runs ``git describe`` and ``git rev-parse``
to capture the current version and commit SHA, then writes the result as
a Python module that the runtime can import without needing git.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from hatchling.builders.hooks.plugin.interface import (  # ty: ignore[unresolved-import]  # build-time dep
        BuildHookInterface,
    )

    _Base = BuildHookInterface
else:
    try:
        from hatchling.builders.hooks.plugin.interface import (
            BuildHookInterface,
        )

        _Base = BuildHookInterface
    except ImportError:  # pragma: no cover
        _Base = object


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


def _get_build_version() -> tuple[str, str, str]:
    """Determine version string and SHAs from git state.

    Returns:
        Tuple of (version, sha_short, sha_full).
    """
    sha_short = _run_git("rev-parse", "--short", "HEAD")
    sha_full = _run_git("rev-parse", "HEAD")

    try:
        version = _run_git("describe", "--tags", "--match", "v*", "--dirty")
    except subprocess.CalledProcessError:
        # No matching tags — use pyproject version as fallback
        try:
            from importlib.metadata import metadata

            pyproject_version = metadata("airut")["Version"]
        except Exception:
            pyproject_version = "0.0.0"
        version = f"v{pyproject_version}+{sha_short}"

    return version, sha_short, sha_full


class GitVersionBuildHook(_Base):
    """Hatch build hook that generates lib/_version.py."""

    PLUGIN_NAME = "git-version"

    def initialize(
        self,
        version: str,
        build_data: dict[str, Any],
    ) -> None:
        """Generate lib/_version.py with embedded version info."""
        try:
            ver, sha_short, sha_full = _get_build_version()
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Not a git repo or git not installed — skip generation
            return

        version_file = Path(self.root) / "lib" / "_version.py"
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
