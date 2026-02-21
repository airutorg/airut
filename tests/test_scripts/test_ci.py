# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/ci.py."""

import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from scripts.ci import (
    DEFAULT_TIMEOUT_SECONDS,
    FAILURE_OUTPUT_LINES,
    GREEN,
    RESET,
    STEPS,
    Step,
    _format_overall_timeout_message,
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
            assert "timed out after 300 seconds" in output
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
            # Should run license check + vulnerability scan
            assert mock_run_step.call_count == 2

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


class TestDriftDetection:
    """Tests that verify ci.py steps match workflow files."""

    def test_code_workflow_steps_match(self) -> None:
        """Verify ci.py covers all steps from code.yml."""
        workflow_path = (
            Path(__file__).parent.parent.parent / ".github/workflows/code.yml"
        )
        with open(workflow_path) as f:
            workflow = yaml.safe_load(f)

        # Extract step names from workflow
        workflow_steps = set()
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                if "name" in step:
                    workflow_steps.add(step["name"])

        # Steps we expect to skip (setup steps, not validation)
        setup_steps = set()  # None currently

        # Get ci.py step names for code workflow
        ci_step_names = {s.name for s in STEPS if s.workflow == "code"}

        # All workflow steps should be in ci.py (minus setup)
        validation_steps = workflow_steps - setup_steps
        missing = validation_steps - ci_step_names
        assert not missing, f"Steps in code.yml not in ci.py: {missing}"

    def test_integration_workflow_steps_match(self) -> None:
        """Verify ci.py covers all test steps from integration.yml."""
        workflow_path = (
            Path(__file__).parent.parent.parent
            / ".github/workflows/integration.yml"
        )
        with open(workflow_path) as f:
            workflow = yaml.safe_load(f)

        # Extract step names from workflow (only "Run" steps)
        workflow_steps = set()
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                name = step.get("name", "")
                if name.startswith("Run "):
                    workflow_steps.add(name)

        # Get ci.py step names for integration workflow
        ci_step_names = {s.name for s in STEPS if s.workflow == "integration"}

        # Map workflow step names to ci.py step names
        expected_ci_names = set()
        for step_name in workflow_steps:
            if "integration" in step_name.lower():
                expected_ci_names.add("Integration tests")

        missing = expected_ci_names - ci_step_names
        assert not missing, f"Steps in integration.yml not in ci.py: {missing}"

    def test_security_workflow_steps_match(self) -> None:
        """Verify ci.py covers all steps from security.yml."""
        workflow_path = (
            Path(__file__).parent.parent.parent
            / ".github/workflows/security.yml"
        )
        with open(workflow_path) as f:
            workflow = yaml.safe_load(f)

        # Extract step names from workflow
        workflow_steps = set()
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                if "name" in step:
                    workflow_steps.add(step["name"])

        # Steps we expect to skip (setup steps, not validation)
        setup_steps = set()  # None currently

        # Get ci.py step names for security workflow
        ci_step_names = {s.name for s in STEPS if s.workflow == "security"}

        # All workflow steps should be in ci.py (minus setup)
        validation_steps = workflow_steps - setup_steps
        missing = validation_steps - ci_step_names
        assert not missing, f"Steps in security.yml not in ci.py: {missing}"
