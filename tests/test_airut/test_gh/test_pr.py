# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib.gh.pr module."""

import json
import subprocess
from unittest.mock import patch

import pytest

from airut.gh.pr import (
    PRInfo,
    PRState,
    _get_commits_behind,
    get_current_pr,
    get_pr_info,
)


class TestPRInfo:
    """Tests for PRInfo dataclass."""

    def test_has_conflicts_true(self) -> None:
        """Returns True when mergeable is CONFLICTING."""
        pr = PRInfo(
            number=1,
            title="Test",
            state=PRState.OPEN,
            head_ref="feature",
            base_ref="main",
            url="https://github.com/owner/repo/pull/1",
            is_draft=False,
            mergeable="CONFLICTING",
            behind_by=0,
        )
        assert pr.has_conflicts is True

    def test_has_conflicts_false(self) -> None:
        """Returns False when mergeable is MERGEABLE."""
        pr = PRInfo(
            number=1,
            title="Test",
            state=PRState.OPEN,
            head_ref="feature",
            base_ref="main",
            url="https://github.com/owner/repo/pull/1",
            is_draft=False,
            mergeable="MERGEABLE",
            behind_by=0,
        )
        assert pr.has_conflicts is False

    def test_is_behind_true(self) -> None:
        """Returns True when behind_by > 0."""
        pr = PRInfo(
            number=1,
            title="Test",
            state=PRState.OPEN,
            head_ref="feature",
            base_ref="main",
            url="https://github.com/owner/repo/pull/1",
            is_draft=False,
            mergeable="MERGEABLE",
            behind_by=5,
        )
        assert pr.is_behind is True

    def test_is_behind_false(self) -> None:
        """Returns False when behind_by is 0."""
        pr = PRInfo(
            number=1,
            title="Test",
            state=PRState.OPEN,
            head_ref="feature",
            base_ref="main",
            url="https://github.com/owner/repo/pull/1",
            is_draft=False,
            mergeable="MERGEABLE",
            behind_by=0,
        )
        assert pr.is_behind is False


class TestGetCurrentPR:
    """Tests for get_current_pr function."""

    def test_returns_pr_info(self) -> None:
        """Returns PRInfo when PR exists."""
        mock_response = {
            "number": 123,
            "title": "Test PR",
            "state": "OPEN",
            "headRefName": "feature-branch",
            "baseRefName": "main",
            "url": "https://github.com/owner/repo/pull/123",
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "commits": [],
        }

        with (
            patch("airut.gh.pr.subprocess.run") as mock_run,
            patch("airut.gh.pr._get_commits_behind", return_value=0),
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(mock_response),
                stderr="",
            )

            result = get_current_pr()

        assert result is not None
        assert result.number == 123
        assert result.title == "Test PR"
        assert result.state == PRState.OPEN
        assert result.head_ref == "feature-branch"
        assert result.base_ref == "main"

    def test_returns_none_when_no_pr(self) -> None:
        """Returns None when no PR exists for branch."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="no pull requests found for branch",
            )

            result = get_current_pr()

        assert result is None

    def test_raises_on_error(self) -> None:
        """Raises RuntimeError on gh command failure."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="some other error",
            )

            with pytest.raises(RuntimeError, match="gh pr view failed"):
                get_current_pr()

    def test_raises_on_timeout(self) -> None:
        """Raises RuntimeError on timeout."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("gh", 30)

            with pytest.raises(RuntimeError, match="timed out"):
                get_current_pr()

    def test_raises_on_invalid_json(self) -> None:
        """Raises RuntimeError on invalid JSON."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="not valid json",
                stderr="",
            )

            with pytest.raises(RuntimeError, match="Failed to parse"):
                get_current_pr()


class TestGetPRInfo:
    """Tests for get_pr_info function."""

    def test_returns_pr_info(self) -> None:
        """Returns PRInfo for specified PR number."""
        mock_response = {
            "number": 456,
            "title": "Another PR",
            "state": "MERGED",
            "headRefName": "another-branch",
            "baseRefName": "main",
            "url": "https://github.com/owner/repo/pull/456",
            "isDraft": True,
            "mergeable": "UNKNOWN",
            "commits": [],
        }

        with (
            patch("airut.gh.pr.subprocess.run") as mock_run,
            patch("airut.gh.pr._get_commits_behind", return_value=3),
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(mock_response),
                stderr="",
            )

            result = get_pr_info(456)

        assert result.number == 456
        assert result.title == "Another PR"
        assert result.state == PRState.MERGED
        assert result.is_draft is True
        assert result.behind_by == 3

    def test_raises_on_error(self) -> None:
        """Raises RuntimeError on gh command failure."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="PR not found",
            )

            with pytest.raises(RuntimeError, match="gh pr view failed"):
                get_pr_info(999)

    def test_raises_on_timeout(self) -> None:
        """Raises RuntimeError on timeout."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("gh", 30)

            with pytest.raises(RuntimeError, match="timed out"):
                get_pr_info(123)

    def test_raises_on_invalid_json(self) -> None:
        """Raises RuntimeError on invalid JSON."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="{invalid",
                stderr="",
            )

            with pytest.raises(RuntimeError, match="Failed to parse"):
                get_pr_info(123)


class TestGetCommitsBehind:
    """Tests for _get_commits_behind function."""

    def test_returns_count(self) -> None:
        """Returns commit count from git rev-list."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            # First call is git fetch
            mock_run.side_effect = [
                subprocess.CompletedProcess(args=[], returncode=0, stdout=""),
                subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="5\n", stderr=""
                ),
            ]

            result = _get_commits_behind("main")

        assert result == 5

    def test_returns_zero_on_error(self) -> None:
        """Returns 0 on git command error."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.side_effect = [
                subprocess.CompletedProcess(args=[], returncode=0, stdout=""),
                subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr="error"
                ),
            ]

            result = _get_commits_behind("main")

        assert result == 0

    def test_returns_zero_on_timeout(self) -> None:
        """Returns 0 on timeout."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("git", 30)

            result = _get_commits_behind("main")

        assert result == 0

    def test_returns_zero_on_invalid_output(self) -> None:
        """Returns 0 on invalid output."""
        with patch("airut.gh.pr.subprocess.run") as mock_run:
            mock_run.side_effect = [
                subprocess.CompletedProcess(args=[], returncode=0, stdout=""),
                subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="not a number\n", stderr=""
                ),
            ]

            result = _get_commits_behind("main")

        assert result == 0
