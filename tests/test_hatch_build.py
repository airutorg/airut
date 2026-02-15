# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for hatch_build.py build hook."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.hatch_build import (
    GitVersionBuildHook,
    _get_build_version,
    _run_git,
)


def _make_hook(root: str) -> GitVersionBuildHook:
    """Create a GitVersionBuildHook with mocked build config and metadata.

    Works whether or not hatchling is installed in the runtime
    environment: when hatchling is available, passes real constructor
    args; otherwise, falls back to simple attribute injection (since
    _Base = object in that case).
    """
    try:
        import hatchling.builders.hooks.plugin.interface as _iface  # ty: ignore[unresolved-import]

        _has_hatchling = hasattr(_iface, "BuildHookInterface")
    except ImportError:
        _has_hatchling = False

    if _has_hatchling:
        # hatchling available — use real constructor
        hook = GitVersionBuildHook(
            root,
            {},
            MagicMock(),  # BuilderConfigBound
            MagicMock(),  # ProjectMetadata
            "",
            "",
            None,
        )
    else:
        # hatchling not installed — _Base is object
        hook = GitVersionBuildHook()
        hook.root = root
    return hook


class TestRunGit:
    """Tests for _run_git helper."""

    def test_runs_command(self) -> None:
        """Should run git command and return output."""
        result = _run_git("rev-parse", "--short", "HEAD")
        assert len(result) >= 7
        assert all(c in "0123456789abcdef" for c in result)

    def test_raises_on_failure(self) -> None:
        """Should raise CalledProcessError on failure."""
        try:
            _run_git("rev-parse", "--verify", "nonexistent-ref-xyz")
            assert False, "Should have raised"
        except subprocess.CalledProcessError:
            pass


class TestGetBuildVersion:
    """Tests for _get_build_version."""

    def test_returns_three_tuple(self) -> None:
        """Should return (version, sha_short, sha_full)."""
        version, sha_short, sha_full = _get_build_version()
        assert isinstance(version, str)
        assert isinstance(sha_short, str)
        assert isinstance(sha_full, str)
        assert len(sha_full) == 40

    def test_version_from_tag(self) -> None:
        """Version should come from git describe when tags exist."""
        # Call order: rev-parse --short, rev-parse HEAD, describe
        with patch(
            "scripts.hatch_build._run_git",
            side_effect=["abc1234", "a" * 40, "v1.2.3"],
        ):
            version, sha_short, sha_full = _get_build_version()
        assert version == "v1.2.3"
        assert sha_short == "abc1234"
        assert sha_full == "a" * 40

    def test_version_fallback_when_no_tags(self) -> None:
        """Should construct fallback version when git describe fails."""
        call_count = 0

        def mock_run_git(*args: str) -> str:
            nonlocal call_count
            call_count += 1
            # Call order: rev-parse --short, rev-parse HEAD, describe
            if call_count == 1:
                return "abc1234"
            if call_count == 2:
                return "a" * 40
            # Third call is git describe — fails
            raise subprocess.CalledProcessError(128, "git")

        with patch("scripts.hatch_build._run_git", side_effect=mock_run_git):
            version, sha_short, sha_full = _get_build_version()
        assert sha_short == "abc1234"
        assert "+abc1234" in version


class TestGitVersionBuildHook:
    """Tests for GitVersionBuildHook."""

    def test_generates_version_file(self, tmp_path: Path) -> None:
        """Should generate lib/_version.py in the build root."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        hook = _make_hook(str(tmp_path))

        build_data: dict = {}
        with patch(
            "scripts.hatch_build._get_build_version",
            return_value=("v1.0.0", "abc1234", "a" * 40),
        ):
            hook.initialize("0.0.0", build_data)

        version_file = lib_dir / "_version.py"
        assert version_file.exists()

        content = version_file.read_text()
        assert "VERSION = 'v1.0.0'" in content
        assert "GIT_SHA_SHORT = 'abc1234'" in content
        assert f"GIT_SHA_FULL = '{'a' * 40}'" in content

    def test_skips_when_not_git_repo_and_no_existing_file(
        self, tmp_path: Path
    ) -> None:
        """Should skip generation when git unavailable and no _version.py."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        hook = _make_hook(str(tmp_path))

        build_data: dict = {}
        with patch(
            "scripts.hatch_build._get_build_version",
            side_effect=FileNotFoundError("git not found"),
        ):
            hook.initialize("0.0.0", build_data)

        version_file = lib_dir / "_version.py"
        assert not version_file.exists()
        assert "force_include" not in build_data

    def test_preserves_existing_version_file_when_no_git(
        self, tmp_path: Path
    ) -> None:
        """Should force-include existing _version.py when git unavailable.

        Reproduces the PyPI install bug: when building a wheel from an
        sdist, _version.py exists (baked into the sdist) but git is not
        available.  The hook must still add it to force_include so
        hatchling doesn't exclude it via .gitignore patterns.
        """
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        # Simulate _version.py already existing (e.g. from sdist)
        version_file = lib_dir / "_version.py"
        version_file.write_text(
            '"""Auto-generated."""\n'
            "VERSION = 'v0.8.0'\n"
            "GIT_SHA_SHORT = 'abc1234'\n"
            f"GIT_SHA_FULL = '{'a' * 40}'\n"
        )

        hook = _make_hook(str(tmp_path))

        build_data: dict = {}
        with patch(
            "scripts.hatch_build._get_build_version",
            side_effect=FileNotFoundError("git not found"),
        ):
            hook.initialize("0.0.0", build_data)

        # The file should still exist (not deleted)
        assert version_file.exists()
        # And it must be in force_include so hatch doesn't skip it
        assert "force_include" in build_data
        assert "lib/_version.py" in build_data["force_include"].values()

    def test_force_include_in_build_data(self, tmp_path: Path) -> None:
        """Should add version file to force_include in build_data."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        hook = _make_hook(str(tmp_path))

        build_data: dict = {}
        with patch(
            "scripts.hatch_build._get_build_version",
            return_value=("v1.0.0", "abc1234", "a" * 40),
        ):
            hook.initialize("0.0.0", build_data)

        assert "force_include" in build_data
        assert "lib/_version.py" in build_data["force_include"].values()
