# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/pr.py."""

import argparse
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from scripts.pr import (
    cmd_ci,
    cmd_review,
    format_ci_status,
    format_review_status,
    main,
)

from lib.gh import (
    CheckConclusion,
    CheckStatus,
    CICheckResult,
    CIStatus,
    PRInfo,
    PRState,
    ReviewComment,
    ReviewState,
    ReviewStatus,
)


def make_ci_args(
    pr: int | None = 123,
    wait: bool = False,
    timeout: int = 600,
    verbose: bool = False,
) -> argparse.Namespace:
    """Create args namespace for cmd_ci."""
    ns = argparse.Namespace()
    ns.pr = pr
    ns.wait = wait
    ns.timeout = timeout
    ns.verbose = verbose
    return ns


def make_review_args(
    pr: int | None = 123,
    verbose: bool = False,
) -> argparse.Namespace:
    """Create args namespace for cmd_review."""
    ns = argparse.Namespace()
    ns.pr = pr
    ns.verbose = verbose
    return ns


class TestFormatCIStatus:
    """Tests for format_ci_status function."""

    def test_format_success(self) -> None:
        """Formats successful CI status."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )

        result = format_ci_status(status)

        assert "PR #123" in result
        assert "✓" in result
        assert "All checks passed" in result

    def test_format_failure(self) -> None:
        """Formats failed CI status."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="failing-test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.FAILURE,
                    workflow="CI",
                ),
            ],
        )

        result = format_ci_status(status)

        assert "✗" in result
        assert "Some checks failed" in result
        assert "failing-test" in result

    def test_format_pending(self) -> None:
        """Formats pending CI status."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="running-test",
                    status=CheckStatus.IN_PROGRESS,
                    conclusion=CheckConclusion.NONE,
                    workflow="CI",
                ),
            ],
        )

        result = format_ci_status(status)

        assert "⋯" in result
        assert "in progress" in result.lower()

    def test_format_conflicts(self) -> None:
        """Formats CI status with conflicts."""
        status = CIStatus(
            pr_number=123,
            has_conflicts=True,
            checks=[],
        )

        result = format_ci_status(status)

        assert "BLOCKED" in result
        assert "merge conflicts" in result.lower()
        assert "rebase" in result.lower()

    def test_format_behind(self) -> None:
        """Formats CI status when behind base."""
        status = CIStatus(
            pr_number=123,
            behind_by=5,
            checks=[],
        )

        result = format_ci_status(status)

        assert "5 commit(s) behind" in result

    def test_format_error(self) -> None:
        """Formats CI status with error."""
        status = CIStatus(
            pr_number=123,
            error="Timed out waiting for CI",
            checks=[],
        )

        result = format_ci_status(status)

        assert "Timed out" in result

    def test_format_skipped_check(self) -> None:
        """Formats skipped check with circle indicator."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="optional-check",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SKIPPED,
                    workflow="CI",
                ),
            ],
        )

        result = format_ci_status(status)

        assert "○" in result

    def test_format_verbose_shows_workflow(self) -> None:
        """Verbose mode shows workflow name."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="Code Quality",
                ),
            ],
        )

        result = format_ci_status(status, verbose=True)

        assert "Code Quality" in result

    def test_format_no_checks(self) -> None:
        """Formats status when no checks exist."""
        status = CIStatus(pr_number=123, checks=[])

        result = format_ci_status(status)

        assert "No checks found" in result

    def test_format_ci_blocked(self) -> None:
        """Formats CI blocked status."""
        status = CIStatus(
            pr_number=123,
            has_conflicts=True,
            checks=[],
        )

        result = format_ci_status(status)

        assert "BLOCKED" in result


class TestFormatReviewStatus:
    """Tests for format_review_status function."""

    def test_format_approved(self) -> None:
        """Formats approved review status."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.APPROVED},
        )

        result = format_review_status(status)

        assert "PR #123" in result
        assert "✓" in result
        assert "Approved" in result

    def test_format_changes_requested(self) -> None:
        """Formats changes requested review status."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.CHANGES_REQUESTED},
        )

        result = format_review_status(status)

        assert "✗" in result
        assert "Changes requested" in result

    def test_format_no_reviews(self) -> None:
        """Formats status with no reviews."""
        status = ReviewStatus(pr_number=123, reviews={})

        result = format_review_status(status)

        assert "No reviews yet" in result

    def test_format_pending_review(self) -> None:
        """Formats status with pending review."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.COMMENTED},
        )

        result = format_review_status(status)

        assert "Pending review" in result

    def test_format_error(self) -> None:
        """Formats status with error."""
        status = ReviewStatus(
            pr_number=123,
            error="API error",
        )

        result = format_review_status(status)

        assert "API error" in result

    def test_format_unresolved_threads(self) -> None:
        """Formats unresolved thread count."""
        status = ReviewStatus(
            pr_number=123,
            pending_review_threads=3,
        )

        result = format_review_status(status)

        assert "Unresolved review threads: 3" in result

    def test_format_comments(self) -> None:
        """Formats review comments."""
        status = ReviewStatus(
            pr_number=123,
            comments=[
                ReviewComment(
                    author="user1",
                    body="Please fix this",
                    path="src/file.py",
                    line=42,
                    created_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
                ),
            ],
        )

        result = format_review_status(status)

        assert "Comments (1)" in result
        assert "user1" in result
        assert "src/file.py:42" in result
        assert "Please fix this" in result

    def test_format_comments_truncated(self) -> None:
        """Truncates long comments in non-verbose mode."""
        long_body = "x" * 150
        status = ReviewStatus(
            pr_number=123,
            comments=[
                ReviewComment(
                    author="user1",
                    body=long_body,
                    path=None,
                    line=None,
                    created_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
                ),
            ],
        )

        result = format_review_status(status, verbose=False)

        assert "..." in result

    def test_format_comments_full_in_verbose(self) -> None:
        """Shows full comments in verbose mode."""
        multiline_body = "Line 1\nLine 2\nLine 3"
        status = ReviewStatus(
            pr_number=123,
            comments=[
                ReviewComment(
                    author="user1",
                    body=multiline_body,
                    path=None,
                    line=None,
                    created_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
                ),
            ],
        )

        result = format_review_status(status, verbose=True)

        assert "Line 1" in result
        assert "Line 2" in result
        assert "Line 3" in result

    def test_format_dismissed_review(self) -> None:
        """Formats dismissed review with circle indicator."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.DISMISSED},
        )

        result = format_review_status(status)

        assert "○" in result
        assert "DISMISSED" in result

    def test_format_commented_review(self) -> None:
        """Formats commented review with comment indicator."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.COMMENTED},
        )

        result = format_review_status(status)

        assert "💬" in result
        assert "COMMENTED" in result


class TestCmdCI:
    """Tests for cmd_ci function."""

    def test_success_returns_0(self) -> None:
        """Returns 0 when CI passes."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )

        with patch("scripts.pr.check_ci_status", return_value=status):
            args = make_ci_args()
            result = cmd_ci(args)

        assert result == 0

    def test_failure_returns_1(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 when CI fails and suggests local CI."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.FAILURE,
                    workflow="CI",
                ),
            ],
        )

        with patch("scripts.pr.check_ci_status", return_value=status):
            args = make_ci_args()
            result = cmd_ci(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "uv run scripts/ci.py" in captured.out

    def test_blocked_returns_2(self) -> None:
        """Returns 2 when CI is blocked."""
        status = CIStatus(
            pr_number=123,
            has_conflicts=True,
            checks=[],
        )

        with patch("scripts.pr.check_ci_status", return_value=status):
            args = make_ci_args()
            result = cmd_ci(args)

        assert result == 2

    def test_pending_returns_1(self) -> None:
        """Returns 1 when CI is still pending."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.IN_PROGRESS,
                    conclusion=CheckConclusion.NONE,
                    workflow="CI",
                ),
            ],
        )

        with patch("scripts.pr.check_ci_status", return_value=status):
            args = make_ci_args()
            result = cmd_ci(args)

        assert result == 1

    def test_error_returns_2(self) -> None:
        """Returns 2 on error."""
        with patch(
            "scripts.pr.check_ci_status",
            side_effect=RuntimeError("No PR found"),
        ):
            args = make_ci_args(pr=None)
            result = cmd_ci(args)

        assert result == 2

    def test_verbose_fetches_logs(self) -> None:
        """Fetches failure logs in verbose mode."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="failing-test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.FAILURE,
                    workflow="CI",
                ),
            ],
        )

        with (
            patch("scripts.pr.check_ci_status", return_value=status),
            patch(
                "scripts.pr.get_check_failure_logs",
                return_value="error logs",
            ) as mock_logs,
        ):
            args = make_ci_args(verbose=True)
            cmd_ci(args)

        mock_logs.assert_called_once_with(123, "failing-test")

    def test_prints_pr_url(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Prints PR URL after status."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )
        pr_info = PRInfo(
            number=123,
            title="Test PR",
            state=PRState.OPEN,
            head_ref="feature",
            base_ref="main",
            url="https://github.com/owner/repo/pull/123",
            is_draft=False,
            mergeable="MERGEABLE",
            behind_by=0,
        )

        with (
            patch("scripts.pr.check_ci_status", return_value=status),
            patch("lib.gh.pr.get_pr_info", return_value=pr_info),
        ):
            args = make_ci_args()
            cmd_ci(args)

        captured = capsys.readouterr()
        assert "PR URL: https://github.com/owner/repo/pull/123" in captured.out

    def test_pr_url_error_does_not_fail(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Does not fail when PR URL cannot be fetched."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )

        with (
            patch("scripts.pr.check_ci_status", return_value=status),
            patch(
                "lib.gh.pr.get_pr_info",
                side_effect=RuntimeError("PR not found"),
            ),
        ):
            args = make_ci_args()
            result = cmd_ci(args)

        # Should still succeed even if PR URL fetch fails
        assert result == 0


class TestCmdReview:
    """Tests for cmd_review function."""

    def test_approved_returns_0(self) -> None:
        """Returns 0 when approved."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.APPROVED},
        )

        with patch("scripts.pr.get_review_status", return_value=status):
            args = make_review_args()
            result = cmd_review(args)

        assert result == 0

    def test_changes_requested_returns_1(self) -> None:
        """Returns 1 when changes requested."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.CHANGES_REQUESTED},
        )

        with patch("scripts.pr.get_review_status", return_value=status):
            args = make_review_args()
            result = cmd_review(args)

        assert result == 1

    def test_no_reviews_returns_0(self) -> None:
        """Returns 0 when no reviews (not an error)."""
        status = ReviewStatus(
            pr_number=123,
            reviews={},
        )

        with patch("scripts.pr.get_review_status", return_value=status):
            args = make_review_args()
            result = cmd_review(args)

        assert result == 0

    def test_error_returns_2(self) -> None:
        """Returns 2 on error."""
        with patch(
            "scripts.pr.get_review_status",
            side_effect=RuntimeError("No PR found"),
        ):
            args = make_review_args(pr=None)
            result = cmd_review(args)

        assert result == 2

    def test_status_error_returns_2(self) -> None:
        """Returns 2 when status contains error."""
        status = ReviewStatus(
            pr_number=123,
            error="API error",
        )

        with patch("scripts.pr.get_review_status", return_value=status):
            args = make_review_args()
            result = cmd_review(args)

        assert result == 2

    def test_prints_pr_url(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Prints PR URL after status."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.APPROVED},
        )
        pr_info = PRInfo(
            number=123,
            title="Test PR",
            state=PRState.OPEN,
            head_ref="feature",
            base_ref="main",
            url="https://github.com/owner/repo/pull/123",
            is_draft=False,
            mergeable="MERGEABLE",
            behind_by=0,
        )

        with (
            patch("scripts.pr.get_review_status", return_value=status),
            patch("lib.gh.pr.get_pr_info", return_value=pr_info),
        ):
            args = make_review_args()
            cmd_review(args)

        captured = capsys.readouterr()
        assert "PR URL: https://github.com/owner/repo/pull/123" in captured.out

    def test_pr_url_error_does_not_fail(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Does not fail when PR URL cannot be fetched."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.APPROVED},
        )

        with (
            patch("scripts.pr.get_review_status", return_value=status),
            patch(
                "lib.gh.pr.get_pr_info",
                side_effect=RuntimeError("PR not found"),
            ),
        ):
            args = make_review_args()
            result = cmd_review(args)

        # Should still succeed even if PR URL fetch fails
        assert result == 0


class TestMain:
    """Tests for main function."""

    def test_ci_command(self) -> None:
        """Dispatches to ci command."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )

        with (
            patch("sys.argv", ["pr.py", "ci", "--pr", "123"]),
            patch("scripts.pr.check_ci_status", return_value=status),
        ):
            result = main()

        assert result == 0

    def test_review_command(self) -> None:
        """Dispatches to review command."""
        status = ReviewStatus(
            pr_number=123,
            reviews={"user1": ReviewState.APPROVED},
        )

        with (
            patch("sys.argv", ["pr.py", "review", "--pr", "123"]),
            patch("scripts.pr.get_review_status", return_value=status),
        ):
            result = main()

        assert result == 0

    def test_ci_with_wait(self) -> None:
        """Passes wait flag to check_ci_status."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.SUCCESS,
                    workflow="CI",
                ),
            ],
        )

        with (
            patch("sys.argv", ["pr.py", "ci", "--wait", "--timeout", "300"]),
            patch(
                "scripts.pr.check_ci_status",
                return_value=status,
            ) as mock_check,
        ):
            main()

        mock_check.assert_called_once_with(
            pr_number=None, wait=True, timeout=300
        )

    def test_verbose_flag(self) -> None:
        """Verbose flag is passed to commands."""
        status = CIStatus(
            pr_number=123,
            checks=[
                CICheckResult(
                    name="test",
                    status=CheckStatus.COMPLETED,
                    conclusion=CheckConclusion.FAILURE,
                    workflow="CI",
                ),
            ],
        )

        with (
            patch("sys.argv", ["pr.py", "ci", "--pr", "123", "-v"]),
            patch("scripts.pr.check_ci_status", return_value=status),
            patch(
                "scripts.pr.get_check_failure_logs",
                return_value=None,
            ) as mock_logs,
        ):
            main()

        # Verbose mode should attempt to fetch logs for failures
        mock_logs.assert_called()

    def test_missing_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Shows help when no command given."""
        with (
            patch("sys.argv", ["pr.py"]),
            pytest.raises(SystemExit),
        ):
            main()
