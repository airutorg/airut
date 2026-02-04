# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/git_version.py."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from lib.git_version import GitVersionInfo, get_git_version_info


class TestGitVersionInfo:
    """Tests for GitVersionInfo dataclass."""

    def test_dataclass_fields(self) -> None:
        """GitVersionInfo should have all expected fields."""
        info = GitVersionInfo(
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            worktree_clean=True,
            full_status="status output",
        )
        assert info.sha_short == "abc1234"
        assert info.sha_full == "abc1234567890abcdef1234567890abcdef123456"
        assert info.worktree_clean is True
        assert info.full_status == "status output"

    def test_worktree_not_clean(self) -> None:
        """GitVersionInfo should store worktree_clean=False correctly."""
        info = GitVersionInfo(
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            worktree_clean=False,
            full_status="status output",
        )
        assert info.worktree_clean is False


class TestGetGitVersionInfo:
    """Tests for get_git_version_info function."""

    def test_returns_git_version_info(self) -> None:
        """get_git_version_info should return GitVersionInfo instance."""
        info = get_git_version_info()
        assert isinstance(info, GitVersionInfo)

    def test_sha_short_is_hex(self) -> None:
        """sha_short should be a valid hex string."""
        info = get_git_version_info()
        if info.sha_short != "unknown":
            assert all(c in "0123456789abcdef" for c in info.sha_short.lower())

    def test_sha_full_is_40_chars(self) -> None:
        """sha_full should be a 40-character hex string."""
        info = get_git_version_info()
        if info.sha_full != "unknown":
            assert len(info.sha_full) == 40
            assert all(c in "0123456789abcdef" for c in info.sha_full.lower())

    def test_full_status_contains_sections(self) -> None:
        """full_status should contain HEAD and WORKING TREE sections."""
        info = get_git_version_info()
        assert "=== HEAD COMMIT ===" in info.full_status
        assert "=== WORKING TREE STATUS ===" in info.full_status

    def test_worktree_clean_is_bool(self) -> None:
        """worktree_clean should be a boolean."""
        info = get_git_version_info()
        assert isinstance(info.worktree_clean, bool)

    def test_accepts_custom_repo_path(self) -> None:
        """get_git_version_info should accept a custom repo path."""
        repo_path = Path(__file__).parent.parent.parent
        info = get_git_version_info(repo_path)
        assert isinstance(info, GitVersionInfo)

    def test_handles_git_command_failure_for_short_sha(self) -> None:
        """Should return 'unknown' for sha_short when git command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")
            info = get_git_version_info()
        assert info.sha_short == "unknown"

    def test_handles_git_command_failure_for_full_sha(self) -> None:
        """Should return 'unknown' for sha_full when git command fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # Second call is for full SHA
                raise subprocess.CalledProcessError(1, "git")
            result = MagicMock()
            result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = get_git_version_info()
        assert info.sha_full == "unknown"

    def test_handles_git_command_failure_for_porcelain(self) -> None:
        """Should return worktree_clean=False when git status fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 3:  # Third call is for status --porcelain
                raise subprocess.CalledProcessError(1, "git")
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 3 else ""
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = get_git_version_info()
        assert info.worktree_clean is False

    def test_handles_git_show_failure(self) -> None:
        """Should include error message in full_status when git show fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 4:  # Fourth call is for git show
                err = subprocess.CalledProcessError(1, "git")
                err.stderr = "fatal: not a git repo"
                raise err
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 4 else ""
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = get_git_version_info()
        assert "Error:" in info.full_status

    def test_handles_git_status_failure(self) -> None:
        """Should include error message in full_status when git status fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 5:  # Fifth call is for git status
                err = subprocess.CalledProcessError(1, "git")
                err.stderr = "fatal: error"
                raise err
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 5 else "HEAD info"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = get_git_version_info()
        assert "Error:" in info.full_status

    def test_clean_worktree_detection(self) -> None:
        """worktree_clean is True when status --porcelain returns empty."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 3:  # Third call is for status --porcelain
                result.stdout = ""  # Empty = clean
            else:
                result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = get_git_version_info()
        assert info.worktree_clean is True

    def test_dirty_worktree_detection(self) -> None:
        """worktree_clean should be False when status --porcelain has output."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 3:  # Third call is for status --porcelain
                result.stdout = " M file.py\n"  # Modified file
            else:
                result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = get_git_version_info()
        assert info.worktree_clean is False
