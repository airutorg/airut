# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/git_version.py."""

import subprocess
from unittest.mock import MagicMock, patch

from lib.git_version import (
    GitVersionInfo,
    _get_git_version_info_live,
    _try_embedded,
    get_git_version_info,
)


class TestGitVersionInfo:
    """Tests for GitVersionInfo dataclass."""

    def test_dataclass_fields(self) -> None:
        """GitVersionInfo should have all expected fields."""
        info = GitVersionInfo(
            version="v0.7.0",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            worktree_clean=True,
            full_status="status output",
        )
        assert info.version == "v0.7.0"
        assert info.sha_short == "abc1234"
        assert info.sha_full == "abc1234567890abcdef1234567890abcdef123456"
        assert info.worktree_clean is True
        assert info.full_status == "status output"

    def test_worktree_not_clean(self) -> None:
        """GitVersionInfo should store worktree_clean=False correctly."""
        info = GitVersionInfo(
            version="",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            worktree_clean=False,
            full_status="status output",
        )
        assert info.worktree_clean is False

    def test_empty_version(self) -> None:
        """GitVersionInfo should accept empty version string."""
        info = GitVersionInfo(
            version="",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            worktree_clean=True,
            full_status="status output",
        )
        assert info.version == ""


class TestTryEmbedded:
    """Tests for _try_embedded function."""

    def test_returns_none_when_no_module(self) -> None:
        """Should return None when lib._version is not importable."""
        import sys

        # Temporarily remove lib._version from sys.modules so the
        # import inside _try_embedded raises ImportError.
        saved = sys.modules.pop("lib._version", None)
        with patch.dict(sys.modules, {"lib._version": None}):
            result = _try_embedded()
        if saved is not None:
            sys.modules["lib._version"] = saved
        assert result is None

    def test_returns_info_when_module_exists(self) -> None:
        """Should return GitVersionInfo when lib._version is importable."""
        mock_module = MagicMock()
        mock_module.VERSION = "v0.7.0"
        mock_module.GIT_SHA_SHORT = "abc1234"
        mock_module.GIT_SHA_FULL = "abc1234567890abcdef1234567890abcdef123456"

        import sys

        with patch.dict(sys.modules, {"lib._version": mock_module}):
            result = _try_embedded()

        assert result is not None
        assert result.version == "v0.7.0"
        assert result.sha_short == "abc1234"
        assert result.sha_full == ("abc1234567890abcdef1234567890abcdef123456")
        assert result.worktree_clean is True
        assert "=== VERSION ===" in result.full_status
        assert "v0.7.0" in result.full_status


class TestGetGitVersionInfo:
    """Tests for get_git_version_info function."""

    def test_returns_git_version_info(self) -> None:
        """get_git_version_info should return GitVersionInfo instance."""
        info = get_git_version_info()
        assert isinstance(info, GitVersionInfo)

    def test_prefers_embedded_when_no_repo_path(self) -> None:
        """Should use embedded info when available and no repo_path."""
        embedded = GitVersionInfo(
            version="v1.0.0",
            sha_short="aaa1111",
            sha_full="a" * 40,
            worktree_clean=True,
            full_status="embedded",
        )
        with patch("lib.git_version._try_embedded", return_value=embedded):
            result = get_git_version_info()
        assert result is embedded

    def test_falls_back_to_git_when_no_embedded(self) -> None:
        """Should use git when embedded module is not available."""
        with patch("lib.git_version._try_embedded", return_value=None):
            info = get_git_version_info()
        assert isinstance(info, GitVersionInfo)
        assert "=== HEAD COMMIT ===" in info.full_status


class TestGetGitVersionInfoLive:
    """Tests for _get_git_version_info_live function."""

    def test_returns_git_version_info(self) -> None:
        """_get_git_version_info_live should return GitVersionInfo."""
        info = _get_git_version_info_live()
        assert isinstance(info, GitVersionInfo)

    def test_sha_short_is_hex(self) -> None:
        """sha_short should be a valid hex string."""
        info = _get_git_version_info_live()
        if info.sha_short != "unknown":
            assert all(c in "0123456789abcdef" for c in info.sha_short.lower())

    def test_sha_full_is_40_chars(self) -> None:
        """sha_full should be a 40-character hex string."""
        info = _get_git_version_info_live()
        if info.sha_full != "unknown":
            assert len(info.sha_full) == 40
            assert all(c in "0123456789abcdef" for c in info.sha_full.lower())

    def test_full_status_contains_sections(self) -> None:
        """full_status should contain HEAD and WORKING TREE sections."""
        info = _get_git_version_info_live()
        assert "=== HEAD COMMIT ===" in info.full_status
        assert "=== WORKING TREE STATUS ===" in info.full_status

    def test_worktree_clean_is_bool(self) -> None:
        """worktree_clean should be a boolean."""
        info = _get_git_version_info_live()
        assert isinstance(info.worktree_clean, bool)

    def test_version_is_string(self) -> None:
        """Version should be a string (possibly empty)."""
        info = _get_git_version_info_live()
        assert isinstance(info.version, str)

    def test_handles_git_command_failure_for_short_sha(self) -> None:
        """Should return 'unknown' for sha_short when git command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")
            info = _get_git_version_info_live()
        assert info.sha_short == "unknown"

    def test_handles_git_command_failure_for_full_sha(self) -> None:
        """Should return 'unknown' for sha_full when git command fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 3:  # Third call is for full SHA
                raise subprocess.CalledProcessError(1, "git")
            result = MagicMock()
            result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.sha_full == "unknown"

    def test_handles_git_command_failure_for_porcelain(self) -> None:
        """Should return worktree_clean=False when git status fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 4:  # Fourth call is for status --porcelain
                raise subprocess.CalledProcessError(1, "git")
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 4 else ""
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.worktree_clean is False

    def test_handles_git_show_failure(self) -> None:
        """Should include error message when git show fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 5:  # Fifth call is for git show
                err = subprocess.CalledProcessError(1, "git")
                err.stderr = "fatal: not a git repo"
                raise err
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 5 else ""
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert "Error:" in info.full_status

    def test_handles_git_status_failure(self) -> None:
        """Should include error message when git status fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 6:  # Sixth call is for git status
                err = subprocess.CalledProcessError(1, "git")
                err.stderr = "fatal: error"
                raise err
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 6 else "HEAD info"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert "Error:" in info.full_status

    def test_clean_worktree_detection(self) -> None:
        """worktree_clean is True when status --porcelain returns empty."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 4:  # Fourth call is for status --porcelain
                result.stdout = ""  # Empty = clean
            else:
                result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.worktree_clean is True

    def test_dirty_worktree_detection(self) -> None:
        """worktree_clean is False when status --porcelain has output."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 4:  # Fourth call is for status --porcelain
                result.stdout = " M file.py\n"  # Modified file
            else:
                result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.worktree_clean is False

    def test_version_from_git_describe(self) -> None:
        """Version should come from git describe when tags exist."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:  # First call is git describe
                result.stdout = "v0.7.0\n"
            else:
                result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.version == "v0.7.0"
        assert "=== VERSION ===" in info.full_status
        assert "v0.7.0" in info.full_status

    def test_version_empty_when_no_tags(self) -> None:
        """Version should be empty when git describe fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # First call is git describe
                raise subprocess.CalledProcessError(128, "git")
            result = MagicMock()
            result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.version == ""
        assert "=== VERSION ===" not in info.full_status

    def test_full_status_includes_version_section_when_tagged(self) -> None:
        """full_status should include VERSION section when tag exists."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:  # git describe
                result.stdout = "v0.7.0-3-gabc1234\n"
            elif call_count == 2:  # rev-parse --short
                result.stdout = "abc1234\n"
            else:
                result.stdout = "mock output\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.version == "v0.7.0-3-gabc1234"
        assert "=== VERSION ===\nv0.7.0-3-gabc1234 (abc1234)" in (
            info.full_status
        )
