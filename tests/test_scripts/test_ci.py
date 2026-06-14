# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/ci.py."""

import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest
from scripts.ci import (
    DEFAULT_TIMEOUT_SECONDS,
    FAILURE_OUTPUT_LINES,
    GREEN,
    RESET,
    Step,
    _format_overall_timeout_message,
    _is_transient_failure,
    colorize,
    main,
    run_ci,
    run_step,
    use_color,
)


DEFAULT_STEP_TIMEOUT_SECONDS = 300


class TestUseColor:
    """Tests for use_color function."""

    def test_returns_true_when_tty(self) -> None:
        """use_color returns True when stdout is a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            assert use_color() is True

    def test_returns_false_when_not_tty(self) -> None:
        """use_color returns False when stdout is not a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=False):
            assert use_color() is False


class TestColorize:
    """Tests for colorize function."""

    def test_adds_color_when_tty(self) -> None:
        """Colorize adds ANSI codes when stdout is a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            result = colorize("test", GREEN)
            assert result == f"{GREEN}test{RESET}"

    def test_no_color_when_not_tty(self) -> None:
        """Colorize returns plain text when stdout is not a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=False):
            result = colorize("test", GREEN)
            assert result == "test"


class TestRunStep:
    """Tests for run_step function."""

    def test_command_success(self) -> None:
        """Returns success for passing command."""
        step = Step(name="Test", command="echo hello", workflow="code")
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is True
            assert output == ""  # Non-verbose, success = no output

    def test_command_success_verbose(self) -> None:
        """Returns output on success when verbose."""
        step = Step(name="Test", command="echo hello", workflow="code")
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            success, output = run_step(
                step, fix_mode=False, verbose=True, step_timeout=300
            )
            assert success is True
            assert "hello" in output

    def test_command_failure(self) -> None:
        """Returns failure for failing command."""
        step = Step(name="Test", command="false", workflow="code")
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="error output\n", stderr=""
            )
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            assert "error output" in output

    def test_fix_mode_uses_fix_command(self) -> None:
        """Uses fix_command when fix_mode is True."""
        step = Step(
            name="Test",
            command="ruff check .",
            workflow="code",
            fix_command="ruff check . --fix",
        )
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            run_step(
                step,
                fix_mode=True,
                verbose=False,
                step_timeout=300,
            )
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert "ruff check . --fix" in call_args[0][0]

    def test_output_truncation(self) -> None:
        """Truncates output to last N lines on failure."""
        step = Step(name="Test", command="echo", workflow="code")
        # Generate output with more lines than the limit
        long_output = "\n".join([f"line {i}" for i in range(100)])
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout=long_output, stderr=""
            )
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            lines = output.strip().split("\n")
            assert len(lines) == FAILURE_OUTPUT_LINES

    def test_worktree_clean_check_dirty(self) -> None:
        """Worktree clean check fails with uncommitted changes."""
        step = Step(
            name="Worktree clean check",
            command="git status --porcelain",
            workflow="code",
        )
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=" M file.py\n", stderr=""
            )
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            assert "Uncommitted changes" in output

    def test_timeout_returns_failure(self) -> None:
        """Returns failure when command times out."""
        step = Step(name="Test", command="sleep 999", workflow="code")
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd="sleep 999", timeout=300
            )
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            assert "STEP TIMEOUT" in output
            assert "timed out after 300 seconds" in output
            assert "ALWAYS a bug" in output
            assert "Do NOT ignore" in output
            assert "ci.py --step-timeout 600" in output

    def test_timeout_reports_effective_timeout_with_deadline(
        self,
    ) -> None:
        """Reports effective timeout when capped by deadline."""
        step = Step(name="Test", command="sleep 999", workflow="code")
        # Deadline = 105.0, monotonic returns 100.0 → remaining = 5s
        deadline = 105.0
        with (
            patch("scripts.ci.subprocess.run") as mock_run,
            patch("scripts.ci.time") as mock_time,
        ):
            mock_time.monotonic.return_value = 100.0
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd="sleep 999", timeout=5
            )
            success, output = run_step(
                step,
                fix_mode=False,
                verbose=False,
                step_timeout=300,
                deadline=deadline,
            )
            assert success is False
            assert "timed out after 5 seconds" in output
            # Override hint still uses step_timeout * 2
            assert "ci.py --step-timeout 600" in output

    def test_worktree_clean_check_clean(self) -> None:
        """Worktree clean check succeeds with clean worktree."""
        step = Step(
            name="Worktree clean check",
            command="git status --porcelain",
            workflow="code",
        )
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is True

    def test_deadline_caps_effective_timeout(self) -> None:
        """Deadline caps subprocess timeout to remaining time."""
        step = Step(name="Test", command="echo hello", workflow="code")
        # Set deadline 5 seconds in the future
        deadline = time.monotonic() + 5.0
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            run_step(
                step,
                fix_mode=False,
                verbose=False,
                step_timeout=300,
                deadline=deadline,
            )
            # Effective timeout should be ~5s (capped by deadline), not 300s
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["timeout"] is not None
            assert call_kwargs["timeout"] < 10  # Well under step_timeout

    def test_deadline_with_no_step_timeout(self) -> None:
        """Deadline provides timeout even when step_timeout is 0."""
        step = Step(name="Test", command="echo hello", workflow="code")
        deadline = time.monotonic() + 5.0
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            run_step(
                step,
                fix_mode=False,
                verbose=False,
                step_timeout=0,
                deadline=deadline,
            )
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["timeout"] is not None
            assert call_kwargs["timeout"] < 10

    def test_expired_deadline_uses_minimal_timeout(self) -> None:
        """Expired deadline uses 0.1s timeout to fail fast."""
        step = Step(name="Test", command="echo hello", workflow="code")
        deadline = time.monotonic() - 1.0  # Already expired
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            run_step(
                step,
                fix_mode=False,
                verbose=False,
                step_timeout=300,
                deadline=deadline,
            )
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["timeout"] == pytest.approx(0.1, abs=0.01)

    def test_no_deadline_uses_step_timeout(self) -> None:
        """Without deadline, step_timeout is used directly."""
        step = Step(name="Test", command="echo hello", workflow="code")
        with patch("scripts.ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            run_step(
                step,
                fix_mode=False,
                verbose=False,
                step_timeout=300,
                deadline=None,
            )
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["timeout"] == 300.0


class TestIsTransientFailure:
    """Tests for _is_transient_failure function."""

    @pytest.mark.parametrize(
        "output",
        [
            "Error: service-identity raised exception: Server error "
            "'502 Bad Gateway' for url 'https://pypi.org/pypi/...'",
            "httpx.ConnectError: connection refused",
            "503 Service Unavailable",
            "Connection reset by peer",
            "Temporary failure in name resolution",
        ],
    )
    def test_detects_transient_markers(self, output: str) -> None:
        """Recognizes transient external failures."""
        assert _is_transient_failure(output) is True

    def test_case_insensitive(self) -> None:
        """Matching ignores case."""
        assert _is_transient_failure("502 BAD GATEWAY") is True

    def test_real_failure_not_transient(self) -> None:
        """A real check failure is not treated as transient."""
        output = (
            "Vulnerability found in package foo 1.2.3 (CVE-2026-0001). "
            "1 vulnerability detected."
        )
        assert _is_transient_failure(output) is False


class TestRunStepRetries:
    """Tests for run_step transient-failure retry behavior."""

    def test_retries_transient_then_succeeds(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Retries a transient failure and returns the eventual success."""
        step = Step(
            name="Proxy vulnerability scan",
            command="uv run uv-secure ...",
            workflow="security",
            retries=2,
        )
        with (
            patch("scripts.ci._run_step_once") as mock_once,
            patch("scripts.ci.time.sleep") as mock_sleep,
            patch.object(sys.stdout, "isatty", return_value=False),
        ):
            mock_once.side_effect = [
                (False, "Server error '502 Bad Gateway'"),
                (True, "all good"),
            ]
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
        assert success is True
        assert output == "all good"
        assert mock_once.call_count == 2
        assert mock_sleep.call_count == 1
        captured = capsys.readouterr()
        assert "retrying (1/2)" in captured.out

    def test_exhausts_retries_on_persistent_transient(self) -> None:
        """Returns the final failure after exhausting retries."""
        step = Step(
            name="Vulnerability scan",
            command="uv run uv-secure uv.lock",
            workflow="security",
            retries=2,
        )
        with (
            patch("scripts.ci._run_step_once") as mock_once,
            patch("scripts.ci.time.sleep") as mock_sleep,
            patch.object(sys.stdout, "isatty", return_value=False),
        ):
            mock_once.return_value = (False, "502 Bad Gateway")
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
        assert success is False
        assert "502 Bad Gateway" in output
        assert mock_once.call_count == 3  # 1 initial + 2 retries
        assert mock_sleep.call_count == 2

    def test_does_not_retry_real_failure(self) -> None:
        """A non-transient failure fails fast despite retries > 0."""
        step = Step(
            name="Vulnerability scan",
            command="uv run uv-secure uv.lock",
            workflow="security",
            retries=2,
        )
        with (
            patch("scripts.ci._run_step_once") as mock_once,
            patch("scripts.ci.time.sleep") as mock_sleep,
        ):
            mock_once.return_value = (False, "1 vulnerability detected")
            success, _ = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
        assert success is False
        assert mock_once.call_count == 1
        assert mock_sleep.call_count == 0

    def test_no_retry_when_retries_zero(self) -> None:
        """A step with retries=0 runs once even on transient failure."""
        step = Step(name="Lint", command="ruff check .", workflow="code")
        with (
            patch("scripts.ci._run_step_once") as mock_once,
            patch("scripts.ci.time.sleep") as mock_sleep,
        ):
            mock_once.return_value = (False, "502 Bad Gateway")
            success, _ = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
        assert success is False
        assert mock_once.call_count == 1
        assert mock_sleep.call_count == 0

    def test_stops_retrying_past_deadline(self) -> None:
        """Stops retrying when the overall deadline has already passed."""
        step = Step(
            name="Vulnerability scan",
            command="uv run uv-secure uv.lock",
            workflow="security",
            retries=2,
        )
        with (
            patch("scripts.ci._run_step_once") as mock_once,
            patch("scripts.ci.time") as mock_time,
        ):
            mock_once.return_value = (False, "502 Bad Gateway")
            # Deadline already passed → no retry after first transient failure.
            mock_time.monotonic.return_value = 200.0
            success, _ = run_step(
                step,
                fix_mode=False,
                verbose=False,
                step_timeout=300,
                deadline=100.0,
            )
        assert success is False
        assert mock_once.call_count == 1
        mock_time.sleep.assert_not_called()

    def test_caps_backoff_to_remaining_deadline(self) -> None:
        """Backoff never sleeps past the overall deadline."""
        step = Step(
            name="Vulnerability scan",
            command="uv run uv-secure uv.lock",
            workflow="security",
            retries=2,
        )
        with (
            patch("scripts.ci._run_step_once") as mock_once,
            patch("scripts.ci.time") as mock_time,
        ):
            mock_once.side_effect = [
                (False, "502 Bad Gateway"),
                (True, "ok"),
            ]
            # 2.0s left before the deadline → backoff capped below the 5s base.
            mock_time.monotonic.return_value = 98.0
            success, _ = run_step(
                step,
                fix_mode=False,
                verbose=False,
                step_timeout=300,
                deadline=100.0,
            )
        assert success is True
        mock_time.sleep.assert_called_once_with(2.0)

    def test_real_failure_on_retry_stops(self) -> None:
        """A real failure surfacing on a retry stops further retries."""
        step = Step(
            name="Vulnerability scan",
            command="uv run uv-secure uv.lock",
            workflow="security",
            retries=2,
        )
        with (
            patch("scripts.ci._run_step_once") as mock_once,
            patch("scripts.ci.time.sleep") as mock_sleep,
            patch.object(sys.stdout, "isatty", return_value=False),
        ):
            mock_once.side_effect = [
                (False, "502 Bad Gateway"),
                (False, "1 vulnerability detected"),
            ]
            success, output = run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
        assert success is False
        assert "vulnerability detected" in output
        assert mock_once.call_count == 2
        assert mock_sleep.call_count == 1


class TestFormatOverallTimeoutMessage:
    """Tests for _format_overall_timeout_message function."""

    def test_contains_elapsed_and_timeout(self) -> None:
        """Message includes elapsed time and timeout value."""
        msg = _format_overall_timeout_message(95.0, 90)
        assert "exceeded 90s" in msg
        assert "elapsed: 95s" in msg

    def test_contains_investigation_guidance(self) -> None:
        """Message instructs agent to investigate hangs and flakiness."""
        msg = _format_overall_timeout_message(95.0, 90)
        assert "hanging" in msg.lower()
        assert "flaky" in msg.lower()
        assert "investigated and fixed" in msg

    def test_contains_override_instructions(self) -> None:
        """Message shows how to override and disable timeout."""
        msg = _format_overall_timeout_message(95.0, 90)
        assert "--timeout 180" in msg  # 90 * 2
        assert "--timeout 0" in msg

    def test_contains_update_instructions(self) -> None:
        """Message instructs to update DEFAULT_TIMEOUT_SECONDS."""
        msg = _format_overall_timeout_message(95.0, 90)
        assert "DEFAULT_TIMEOUT_SECONDS" in msg
        assert "50%" in msg


class TestRunCi:
    """Tests for run_ci function."""

    def test_all_steps_pass(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns 0 when all steps pass."""
        with patch("scripts.ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = run_ci()
            assert result == 0
            captured = capsys.readouterr()
            assert "All" in captured.out
            assert "passed" in captured.out

    def test_step_fails(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns 1 when a step fails."""
        with patch("scripts.ci.run_step") as mock_run_step:
            # First step passes, second fails
            mock_run_step.side_effect = [
                (True, ""),
                (False, "error output"),
            ] + [(True, "")] * 20  # Rest pass
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = run_ci()
            assert result == 1
            captured = capsys.readouterr()
            assert "failed" in captured.out

    def test_security_workflow_filter(self) -> None:
        """Filters steps by security workflow."""
        with patch("scripts.ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                run_ci(workflows=["security"])
            # license + vuln scan + proxy scan + screenshots scan
            # + proxy drift + vendor security
            assert mock_run_step.call_count == 6

    def test_invalid_workflow(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns 2 for invalid workflow filter."""
        with patch.object(sys.stdout, "isatty", return_value=False):
            result = run_ci(workflows=["nonexistent"])
        assert result == 2
        captured = capsys.readouterr()
        assert "No steps to run" in captured.out

    def test_fix_mode_passed_to_steps(self) -> None:
        """Passes fix_mode to run_step."""
        with patch("scripts.ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                run_ci(fix_mode=True, workflows=["security"])
            # Check that fix_mode=True was passed
            call_args = mock_run_step.call_args
            assert call_args[0][1] is True  # fix_mode argument

    def test_verbose_mode_passed_to_steps(self) -> None:
        """Passes verbose to run_step."""
        with patch("scripts.ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "output")
            with patch.object(sys.stdout, "isatty", return_value=False):
                run_ci(verbose=True, workflows=["security"])
            # Check that verbose=True was passed
            call_args = mock_run_step.call_args
            assert call_args[0][2] is True  # verbose argument

    def test_prints_command_on_failure(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Prints the command that failed."""
        with patch("scripts.ci.run_step") as mock_run_step:
            # Make lint step fail
            def side_effect(
                step: Step,
                fix_mode: bool,
                verbose: bool,
                step_timeout: int,
                deadline: float | None = None,
            ) -> tuple[bool, str]:
                if step.name == "Lint":
                    return (False, "lint error")
                return (True, "")

            mock_run_step.side_effect = side_effect
            with patch.object(sys.stdout, "isatty", return_value=False):
                run_ci(workflows=["code"])
            captured = capsys.readouterr()
            assert "Command:" in captured.out
            assert "uv run ruff check ." in captured.out

    def test_overall_timeout_before_step(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 with timeout message when deadline exceeded before step."""
        with (
            patch("scripts.ci.run_step") as mock_run_step,
            patch("scripts.ci.time") as mock_time,
        ):
            # Simulate: start at 0, first check at 0, then time jumps to 100
            mock_time.monotonic.side_effect = [
                0.0,  # start_time
                100.0,  # check before first step (elapsed >= timeout)
                100.0,  # elapsed for timeout message
            ]
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = run_ci(workflows=["security"], timeout=90)
            assert result == 1
            assert mock_run_step.call_count == 0
            captured = capsys.readouterr()
            assert "TIMEOUT" in captured.out
            assert "OVERALL CI TIMEOUT" in captured.out

    def test_overall_timeout_during_step(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 with timeout when a step causes deadline to be exceeded."""
        with (
            patch("scripts.ci.run_step") as mock_run_step,
            patch("scripts.ci.time") as mock_time,
        ):
            # Simulate: start at 0, first step passes quickly, second step
            # takes too long (monotonic jumps past deadline after step fails)
            mock_time.monotonic.side_effect = [
                0.0,  # start_time → deadline = 90.0
                10.0,  # check before step 1 (ok)
                10.0,  # check before step 2 (ok)
                95.0,  # check after step 2 failure (past deadline)
                95.0,  # elapsed for timeout message
            ]
            mock_run_step.side_effect = [
                (True, ""),
                (False, "step error"),
            ]
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = run_ci(workflows=["security"], timeout=90)
            assert result == 1
            captured = capsys.readouterr()
            assert "TIMEOUT" in captured.out

    def test_overall_timeout_disabled(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Timeout=0 disables overall timeout."""
        with patch("scripts.ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = run_ci(workflows=["security"], timeout=0)
            assert result == 0
            # Verify deadline=None was passed to run_step
            call_args = mock_run_step.call_args
            assert call_args[0][4] is None  # deadline argument

    def test_elapsed_time_shown_on_success(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Shows elapsed time in success message."""
        with (
            patch("scripts.ci.run_step") as mock_run_step,
            patch("scripts.ci.time") as mock_time,
        ):
            mock_time.monotonic.side_effect = [
                0.0,  # start_time
                5.0,  # check before step 1
                10.0,  # check before step 2
                12.0,  # check before step 3
                13.0,  # check before step 4
                14.0,  # check before step 5
                14.5,  # check before step 6
                15.0,  # elapsed for summary
            ]
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = run_ci(workflows=["security"], timeout=90)
            assert result == 0
            captured = capsys.readouterr()
            assert "15s" in captured.out

    def test_deadline_passed_to_run_step(self) -> None:
        """Passes deadline to run_step when timeout is set."""
        with (
            patch("scripts.ci.run_step") as mock_run_step,
            patch("scripts.ci.time") as mock_time,
        ):
            mock_time.monotonic.side_effect = [
                100.0,  # start_time → deadline = 190.0
                105.0,  # check before step 1
                110.0,  # check before step 2
                112.0,  # check before step 3
                113.0,  # check before step 4
                114.0,  # check before step 5
                114.5,  # check before step 6
                115.0,  # elapsed for summary
            ]
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                run_ci(workflows=["security"], timeout=90)
            # Verify deadline was passed (start_time + timeout = 190.0)
            call_args = mock_run_step.call_args_list[0]
            assert call_args[0][4] == pytest.approx(190.0)


class TestMain:
    """Tests for main function."""

    def test_parses_workflow_argument(self) -> None:
        """Parses --workflow argument."""
        with patch("scripts.ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--workflow", "code"]):
                main()
            mock_run_ci.assert_called_once_with(
                workflows=["code"],
                fix_mode=False,
                verbose=False,
                step_timeout=DEFAULT_STEP_TIMEOUT_SECONDS,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_parses_fix_argument(self) -> None:
        """Parses --fix argument."""
        with patch("scripts.ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--fix"]):
                main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=True,
                verbose=False,
                step_timeout=DEFAULT_STEP_TIMEOUT_SECONDS,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_parses_verbose_argument(self) -> None:
        """Parses --verbose argument."""
        with patch("scripts.ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--verbose"]):
                main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=False,
                verbose=True,
                step_timeout=DEFAULT_STEP_TIMEOUT_SECONDS,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_parses_short_verbose_argument(self) -> None:
        """Parses -v argument."""
        with patch("scripts.ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "-v"]):
                main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=False,
                verbose=True,
                step_timeout=DEFAULT_STEP_TIMEOUT_SECONDS,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_multiple_workflow_arguments(self) -> None:
        """Parses multiple --workflow arguments."""
        with patch("scripts.ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch(
                "sys.argv",
                [
                    "ci.py",
                    "--workflow",
                    "code",
                    "--workflow",
                    "security",
                ],
            ):
                main()
            mock_run_ci.assert_called_once_with(
                workflows=["code", "security"],
                fix_mode=False,
                verbose=False,
                step_timeout=DEFAULT_STEP_TIMEOUT_SECONDS,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_parses_timeout_argument(self) -> None:
        """Parses --timeout argument."""
        with patch("scripts.ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--timeout", "120"]):
                main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=False,
                verbose=False,
                step_timeout=DEFAULT_STEP_TIMEOUT_SECONDS,
                timeout=120,
            )

    def test_parses_timeout_zero(self) -> None:
        """Parses --timeout 0 to disable overall timeout."""
        with patch("scripts.ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--timeout", "0"]):
                main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=False,
                verbose=False,
                step_timeout=DEFAULT_STEP_TIMEOUT_SECONDS,
                timeout=0,
            )
