# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib.gh.ci module."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from airut.gh.ci import (
    CheckConclusion,
    CheckStatus,
    CICheckResult,
    CIStatus,
    _fetch_checks,
    check_ci_status,
    get_check_failure_logs,
)


class TestCICheckResult:
    """Tests for CICheckResult dataclass."""

    def test_creation(self) -> None:
        """CICheckResult can be created with all fields."""
        check = CICheckResult(
            name="test-check",
            status=CheckStatus.COMPLETED,
            conclusion=CheckConclusion.SUCCESS,
            workflow="CI",
            url="https://github.com/owner/repo/actions/runs/123",
        )
        assert check.name == "test-check"
        assert check.status == CheckStatus.COMPLETED
        assert check.conclusion == CheckConclusion.SUCCESS


class TestCIStatus:
    """Tests for CIStatus dataclass."""

    def test_is_pending_true(self) -> None:
        """Returns True when checks are still running."""
        status = CIStatus(
            pr_number=1,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.IN_PROGRESS,
                    conclusion=CheckConclusion.NONE,
                    workflow="CI",
                ),
            ],
        )
        assert status.is_pending is True

    def test_is_pending_false(self) -> None:
        """Returns False when all checks are complete."""
        status = CIStatus(
            pr_number=1,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )
        assert status.is_pending is False

    def test_is_success_true(self) -> None:
        """Returns True when all checks passed."""
        status = CIStatus(
            pr_number=1,
            checks=[
                CICheckResult(
                    name="test1",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
                CICheckResult(
                    name="test2",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SKIPPED,
                    workflow="CI",
                ),
            ],
        )
        assert status.is_success is True

    def test_is_success_false_no_checks(self) -> None:
        """Returns False when no checks exist."""
        status = CIStatus(pr_number=1, checks=[])
        assert status.is_success is False

    def test_is_success_false_pending(self) -> None:
        """Returns False when checks are still pending."""
        status = CIStatus(
            pr_number=1,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.QUEUED,
                    conclusion=CheckConclusion.NONE,
                    workflow="CI",
                ),
            ],
        )
        assert status.is_success is False

    def test_is_failure_true(self) -> None:
        """Returns True when any check failed."""
        status = CIStatus(
            pr_number=1,
            checks=[
                CICheckResult(
                    name="test1",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
                CICheckResult(
                    name="test2",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.FAILURE,
                    workflow="CI",
                ),
            ],
        )
        assert status.is_failure is True

    def test_is_failure_false(self) -> None:
        """Returns False when no checks failed."""
        status = CIStatus(
            pr_number=1,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )
        assert status.is_failure is False

    def test_failed_checks(self) -> None:
        """Returns list of failed checks."""
        failed = CICheckResult(
            name="failed",
            status=CheckStatus.COMPLETED,
            conclusion=CheckConclusion.FAILURE,
            workflow="CI",
        )
        status = CIStatus(
            pr_number=1,
            checks=[
                CICheckResult(
                    name="passed",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
                failed,
            ],
        )
        assert status.failed_checks == [failed]

    def test_ci_blocked_with_conflicts(self) -> None:
        """Returns True when PR has conflicts."""
        status = CIStatus(pr_number=1, has_conflicts=True)
        assert status.ci_blocked is True

    def test_ci_blocked_without_conflicts(self) -> None:
        """Returns False when PR has no conflicts."""
        status = CIStatus(pr_number=1, has_conflicts=False)
        assert status.ci_blocked is False


class TestCheckCIStatus:
    """Tests for check_ci_status function."""

    def test_uses_current_pr_when_none(self) -> None:
        """Uses current branch's PR when pr_number is None."""
        mock_pr_info = MagicMock()
        mock_pr_info.number = 123
        mock_pr_info.has_conflicts = False
        mock_pr_info.behind_by = 0

        with (
            patch("airut.gh.pr.get_current_pr", return_value=mock_pr_info),
            patch("airut.gh.pr.get_pr_info", return_value=mock_pr_info),
            patch("airut.gh.ci._fetch_checks", return_value=[]),
        ):
            result = check_ci_status()

        assert result.pr_number == 123

    def test_raises_when_no_current_pr(self) -> None:
        """Raises RuntimeError when no PR exists for current branch."""
        with patch("airut.gh.pr.get_current_pr", return_value=None):
            with pytest.raises(RuntimeError, match="No PR found"):
                check_ci_status()

    def test_returns_conflict_error(self) -> None:
        """Returns error message when PR has conflicts."""
        mock_pr_info = MagicMock()
        mock_pr_info.number = 123
        mock_pr_info.has_conflicts = True
        mock_pr_info.behind_by = 0
        mock_pr_info.base_ref = "main"

        with (
            patch("airut.gh.pr.get_pr_info", return_value=mock_pr_info),
            patch("airut.gh.ci._fetch_checks", return_value=[]),
        ):
            result = check_ci_status(pr_number=123)

        assert result.has_conflicts is True
        assert result.error is not None
        assert "merge conflicts" in result.error.lower()

    def test_wait_polls_until_complete(self) -> None:
        """Polls for status until checks complete when wait=True."""
        mock_pr_info = MagicMock()
        mock_pr_info.number = 123
        mock_pr_info.has_conflicts = False
        mock_pr_info.behind_by = 0

        pending_check = CICheckResult(
            name="test",
            status=CheckStatus.IN_PROGRESS,
            conclusion=CheckConclusion.NONE,
            workflow="CI",
        )
        completed_check = CICheckResult(
            name="test",
            status=CheckStatus.COMPLETED,
            conclusion=CheckConclusion.SUCCESS,
            workflow="CI",
        )

        call_count = 0

        def mock_fetch_checks(pr_number: int) -> list[CICheckResult]:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return [pending_check]
            return [completed_check]

        with (
            patch("airut.gh.pr.get_pr_info", return_value=mock_pr_info),
            patch("airut.gh.ci._fetch_checks", side_effect=mock_fetch_checks),
            patch("airut.gh.ci.time.sleep"),
        ):
            result = check_ci_status(pr_number=123, wait=True, poll_interval=1)

        assert result.is_success is True
        assert call_count == 2

    def test_wait_times_out(self) -> None:
        """Returns timeout error when wait exceeds timeout."""
        mock_pr_info = MagicMock()
        mock_pr_info.number = 123
        mock_pr_info.has_conflicts = False
        mock_pr_info.behind_by = 0

        pending_check = CICheckResult(
            name="test",
            status=CheckStatus.IN_PROGRESS,
            conclusion=CheckConclusion.NONE,
            workflow="CI",
        )

        with (
            patch("airut.gh.pr.get_pr_info", return_value=mock_pr_info),
            patch("airut.gh.ci._fetch_checks", return_value=[pending_check]),
            patch("airut.gh.ci.time.sleep"),
            patch("airut.gh.ci.time.time") as mock_time,
        ):
            # Simulate timeout
            mock_time.side_effect = [0, 0, 1000]

            result = check_ci_status(
                pr_number=123, wait=True, poll_interval=1, timeout=10
            )

        assert result.error is not None
        assert "timed out" in result.error.lower()

    def test_wait_retries_when_no_checks_found(self) -> None:
        """Retries with backoff when no checks found initially."""
        mock_pr_info = MagicMock()
        mock_pr_info.number = 123
        mock_pr_info.has_conflicts = False
        mock_pr_info.behind_by = 0

        completed_check = CICheckResult(
            name="test",
            status=CheckStatus.COMPLETED,
            conclusion=CheckConclusion.SUCCESS,
            workflow="CI",
        )

        call_count = 0

        def mock_fetch_checks(pr_number: int) -> list[CICheckResult]:
            nonlocal call_count
            call_count += 1
            # First 2 calls return empty (GitHub initializing)
            if call_count < 3:
                return []
            # Third call returns checks
            return [completed_check]

        with (
            patch("airut.gh.pr.get_pr_info", return_value=mock_pr_info),
            patch("airut.gh.ci._fetch_checks", side_effect=mock_fetch_checks),
            patch("airut.gh.ci.time.sleep") as mock_sleep,
            patch("airut.gh.ci.time.time", side_effect=[0, 1, 3, 7]),
        ):
            result = check_ci_status(pr_number=123, wait=True)

        # Should have retried until checks appeared
        assert result.is_success is True
        assert call_count == 3
        # Should have slept with exponential backoff (2s, then 4s)
        assert mock_sleep.call_count == 2

    def test_wait_gives_up_after_30s_no_checks(self) -> None:
        """Stops retrying after 30s if no checks appear."""
        mock_pr_info = MagicMock()
        mock_pr_info.number = 123
        mock_pr_info.has_conflicts = False
        mock_pr_info.behind_by = 0

        # Time sequence: 0, then keep returning values > 30
        time_values = [0] + [35 + i for i in range(10)]

        with (
            patch("airut.gh.pr.get_pr_info", return_value=mock_pr_info),
            patch("airut.gh.ci._fetch_checks", return_value=[]),
            patch("airut.gh.ci.time.sleep"),
            patch("airut.gh.ci.time.time", side_effect=time_values),
        ):
            result = check_ci_status(pr_number=123, wait=True)

        # Should return with empty checks after giving up
        assert result.checks == []
        assert result.error is None


class TestFetchChecks:
    """Tests for _fetch_checks function."""

    def test_returns_checks(self) -> None:
        """Returns list of CICheckResult from gh output."""
        mock_response = [
            {
                "name": "test1",
                "state": "SUCCESS",
                "workflow": "CI",
                "link": "https://github.com/owner/repo/actions/runs/1",
            },
            {
                "name": "test2",
                "state": "IN_PROGRESS",
                "workflow": "CI",
                "link": "https://github.com/owner/repo/actions/runs/2",
            },
        ]

        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(mock_response),
                stderr="",
            )

            result = _fetch_checks(123)

        assert len(result) == 2
        assert result[0].name == "test1"
        assert result[0].status == CheckStatus.COMPLETED
        assert result[0].conclusion == CheckConclusion.SUCCESS
        assert result[1].name == "test2"
        assert result[1].status == CheckStatus.IN_PROGRESS
        assert result[1].conclusion == CheckConclusion.NONE

    def test_returns_empty_on_no_checks(self) -> None:
        """Returns empty list when no checks exist."""
        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="no checks reported",
            )

            result = _fetch_checks(123)

        assert result == []

    def test_returns_empty_on_timeout(self) -> None:
        """Returns empty list on timeout."""
        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("gh", 30)

            result = _fetch_checks(123)

        assert result == []

    def test_handles_unknown_status(self) -> None:
        """Handles unknown status values."""
        mock_response = [
            {
                "name": "test",
                "state": "UNKNOWN_STATE",
                "workflow": "CI",
            },
        ]

        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(mock_response),
                stderr="",
            )

            result = _fetch_checks(123)

        assert len(result) == 1
        assert result[0].status == CheckStatus.PENDING
        assert result[0].conclusion == CheckConclusion.NONE

    def test_returns_empty_on_other_error(self) -> None:
        """Returns empty list on other gh error (not 'no checks')."""
        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="unexpected error message",
            )

            result = _fetch_checks(123)

        assert result == []

    def test_returns_empty_on_json_error(self) -> None:
        """Returns empty list on JSON parse error."""
        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="not valid json",
                stderr="",
            )

            result = _fetch_checks(123)

        assert result == []


class TestGetCheckFailureLogs:
    """Tests for get_check_failure_logs function."""

    def test_returns_logs(self) -> None:
        """Returns log output for failed check."""
        mock_checks = [
            {
                "name": "test",
                "workflow": "CI",
                "link": "https://github.com/owner/repo/actions/runs/12345/job/67890",
            },
        ]

        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.side_effect = [
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps(mock_checks),
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="test logs\nerror output",
                    stderr="",
                ),
            ]

            result = get_check_failure_logs(123, "test")

        assert result == "test logs\nerror output"

    def test_returns_none_on_check_not_found(self) -> None:
        """Returns None when check not found."""
        mock_checks = [
            {
                "name": "other-check",
                "workflow": "CI",
                "link": "https://github.com/owner/repo/actions/runs/12345",
            },
        ]

        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(mock_checks),
                stderr="",
            )

            result = get_check_failure_logs(123, "test")

        assert result is None

    def test_returns_none_on_error(self) -> None:
        """Returns None on error."""
        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="error",
            )

            result = get_check_failure_logs(123, "test")

        assert result is None

    def test_returns_none_on_timeout(self) -> None:
        """Returns None on timeout."""
        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("gh", 30)

            result = get_check_failure_logs(123, "test")

        assert result is None

    def test_returns_none_when_no_link(self) -> None:
        """Returns None when check has no link."""
        mock_checks = [
            {
                "name": "test",
                "workflow": "CI",
                "link": None,
            },
        ]

        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(mock_checks),
                stderr="",
            )

            result = get_check_failure_logs(123, "test")

        assert result is None

    def test_returns_none_when_no_run_id_in_url(self) -> None:
        """Returns None when URL doesn't contain run ID."""
        mock_checks = [
            {
                "name": "test",
                "workflow": "CI",
                "link": "https://github.com/owner/repo/actions",
            },
        ]

        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(mock_checks),
                stderr="",
            )

            result = get_check_failure_logs(123, "test")

        assert result is None

    def test_returns_none_when_log_fetch_fails(self) -> None:
        """Returns None when log fetch fails."""
        mock_checks = [
            {
                "name": "test",
                "workflow": "CI",
                "link": "https://github.com/owner/repo/actions/runs/12345/job/67890",
            },
        ]

        with patch("airut.gh.ci.subprocess.run") as mock_run:
            mock_run.side_effect = [
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps(mock_checks),
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=1,
                    stdout="",
                    stderr="error",
                ),
            ]

            result = get_check_failure_logs(123, "test")

        assert result is None
