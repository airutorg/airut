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
    GitVersionMetadataHook,
    _get_build_version,
    _read_version_from_file,
    _run_git,
    _tag_to_pep440,
    get_build_hook,
    get_metadata_hook,
)


def _make_build_hook(root: str) -> GitVersionBuildHook:
    """Create a GitVersionBuildHook with mocked build config and metadata.

    Works whether or not hatchling is installed in the runtime
    environment: when hatchling is available, passes real constructor
    args; otherwise, falls back to simple attribute injection (since
    _BuildBase = object in that case).
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
        # hatchling not installed — _BuildBase is object
        hook = GitVersionBuildHook()
        hook.root = root
    return hook


def _make_metadata_hook(root: str) -> GitVersionMetadataHook:
    """Create a GitVersionMetadataHook with mocked config.

    Works whether or not hatchling is installed in the runtime
    environment.
    """
    try:
        import hatchling.metadata.plugin.interface as _iface  # ty: ignore[unresolved-import]

        _has_hatchling = hasattr(_iface, "MetadataHookInterface")
    except ImportError:
        _has_hatchling = False

    if _has_hatchling:
        hook = GitVersionMetadataHook(
            root,
            {},
        )
    else:
        hook = GitVersionMetadataHook()
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


class TestTagToPep440:
    """Tests for _tag_to_pep440 conversion."""

    def test_clean_release(self) -> None:
        """Exact tag should produce clean version."""
        assert _tag_to_pep440("v0.9.0") == "0.9.0"

    def test_distance_from_tag(self) -> None:
        """Commits past tag should produce dev version with local hash."""
        assert _tag_to_pep440("v0.9.0-3-gabc1234") == "0.9.0.dev3+gabc1234"

    def test_dirty(self) -> None:
        """Dirty tag should produce local +dirty."""
        assert _tag_to_pep440("v0.9.0-dirty") == "0.9.0+dirty"

    def test_distance_and_dirty(self) -> None:
        """Distance + dirty should produce dev with compound local."""
        assert (
            _tag_to_pep440("v0.9.0-3-gabc1234-dirty")
            == "0.9.0.dev3+gabc1234.dirty"
        )

    def test_no_v_prefix(self) -> None:
        """Tags without v prefix should still parse."""
        assert _tag_to_pep440("1.0.0") == "1.0.0"

    def test_pre_release_tag(self) -> None:
        """Pre-release tags should pass through base."""
        assert _tag_to_pep440("v1.0.0rc1") == "1.0.0rc1"


class TestReadVersionFromFile:
    """Tests for _read_version_from_file."""

    def test_reads_version(self, tmp_path: Path) -> None:
        """Should read and convert VERSION from _version.py."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "_version.py").write_text("VERSION = 'v0.8.0'\n")
        result = _read_version_from_file(tmp_path)
        assert result == "0.8.0"

    def test_returns_none_when_missing(self, tmp_path: Path) -> None:
        """Should return None if file doesn't exist."""
        result = _read_version_from_file(tmp_path)
        assert result is None

    def test_returns_none_when_no_version(self, tmp_path: Path) -> None:
        """Should return None if VERSION line not found."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "_version.py").write_text("# empty\n")
        result = _read_version_from_file(tmp_path)
        assert result is None

    def test_handles_dev_version(self, tmp_path: Path) -> None:
        """Should convert dev version tags correctly."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "_version.py").write_text("VERSION = 'v0.8.0-3-gabc1234'\n")
        result = _read_version_from_file(tmp_path)
        assert result == "0.8.0.dev3+gabc1234"


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
        assert version == "v0.0.0-0-gabc1234"


class TestGitVersionMetadataHook:
    """Tests for GitVersionMetadataHook."""

    def test_sets_version_from_git(self, tmp_path: Path) -> None:
        """Should set version from git describe tag."""
        hook = _make_metadata_hook(str(tmp_path))
        metadata: dict[str, str] = {}
        with patch(
            "scripts.hatch_build._git_version_tag",
            return_value="v1.2.3",
        ):
            hook.update(metadata)
        assert metadata["version"] == "1.2.3"

    def test_sets_dev_version_from_git(self, tmp_path: Path) -> None:
        """Should convert git describe with distance to PEP 440 dev."""
        hook = _make_metadata_hook(str(tmp_path))
        metadata: dict[str, str] = {}
        with patch(
            "scripts.hatch_build._git_version_tag",
            return_value="v1.2.3-5-gabc1234",
        ):
            hook.update(metadata)
        assert metadata["version"] == "1.2.3.dev5+gabc1234"

    def test_fallback_to_version_file(self, tmp_path: Path) -> None:
        """Should read version from _version.py when git unavailable."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "_version.py").write_text("VERSION = 'v0.8.0'\n")

        hook = _make_metadata_hook(str(tmp_path))
        metadata: dict[str, str] = {}
        with patch(
            "scripts.hatch_build._git_version_tag",
            side_effect=FileNotFoundError("git not found"),
        ):
            hook.update(metadata)
        assert metadata["version"] == "0.8.0"

    def test_last_resort_version(self, tmp_path: Path) -> None:
        """Should use 0.0.0 when no git and no _version.py."""
        hook = _make_metadata_hook(str(tmp_path))
        metadata: dict[str, str] = {}
        with patch(
            "scripts.hatch_build._git_version_tag",
            side_effect=FileNotFoundError("git not found"),
        ):
            hook.update(metadata)
        assert metadata["version"] == "0.0.0"


class TestGitVersionBuildHook:
    """Tests for GitVersionBuildHook."""

    def test_generates_version_file(self, tmp_path: Path) -> None:
        """Should generate lib/_version.py in the build root."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        hook = _make_build_hook(str(tmp_path))

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

        hook = _make_build_hook(str(tmp_path))

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

        hook = _make_build_hook(str(tmp_path))

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

        hook = _make_build_hook(str(tmp_path))

        build_data: dict = {}
        with patch(
            "scripts.hatch_build._get_build_version",
            return_value=("v1.0.0", "abc1234", "a" * 40),
        ):
            hook.initialize("0.0.0", build_data)

        assert "force_include" in build_data
        assert "lib/_version.py" in build_data["force_include"].values()


class TestDisambiguators:
    """Tests for get_build_hook and get_metadata_hook."""

    def test_get_build_hook(self) -> None:
        """get_build_hook should return GitVersionBuildHook class."""
        assert get_build_hook() is GitVersionBuildHook

    def test_get_metadata_hook(self) -> None:
        """get_metadata_hook should return GitVersionMetadataHook class."""
        assert get_metadata_hook() is GitVersionMetadataHook
