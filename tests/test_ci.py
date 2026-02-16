# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/ci.py."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml


# Import the module under test
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import ci  # type: ignore[import-not-found]


class TestUseColor:
    """Tests for use_color function."""

    def test_returns_true_when_tty(self) -> None:
        """use_color returns True when stdout is a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            assert ci.use_color() is True

    def test_returns_false_when_not_tty(self) -> None:
        """use_color returns False when stdout is not a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=False):
            assert ci.use_color() is False


class TestColorize:
    """Tests for colorize function."""

    def test_adds_color_when_tty(self) -> None:
        """Colorize adds ANSI codes when stdout is a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=True):
            result = ci.colorize("test", ci.GREEN)
            assert result == f"{ci.GREEN}test{ci.RESET}"

    def test_no_color_when_not_tty(self) -> None:
        """Colorize returns plain text when stdout is not a TTY."""
        with patch.object(sys.stdout, "isatty", return_value=False):
            result = ci.colorize("test", ci.GREEN)
            assert result == "test"


class TestRunStep:
    """Tests for run_step function."""

    def test_command_success(self) -> None:
        """Returns success for passing command."""
        step = ci.Step(name="Test", command="echo hello", workflow="code")
        with patch("ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            success, output = ci.run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is True
            assert output == ""  # Non-verbose, success = no output

    def test_command_success_verbose(self) -> None:
        """Returns output on success when verbose."""
        step = ci.Step(name="Test", command="echo hello", workflow="code")
        with patch("ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="hello\n", stderr=""
            )
            success, output = ci.run_step(
                step, fix_mode=False, verbose=True, step_timeout=300
            )
            assert success is True
            assert "hello" in output

    def test_command_failure(self) -> None:
        """Returns failure for failing command."""
        step = ci.Step(name="Test", command="false", workflow="code")
        with patch("ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="error output\n", stderr=""
            )
            success, output = ci.run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            assert "error output" in output

    def test_fix_mode_uses_fix_command(self) -> None:
        """Uses fix_command when fix_mode is True."""
        step = ci.Step(
            name="Test",
            command="ruff check .",
            workflow="code",
            fix_command="ruff check . --fix",
        )
        with patch("ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            ci.run_step(step, fix_mode=True, verbose=False, step_timeout=300)
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert "ruff check . --fix" in call_args[0][0]

    def test_output_truncation(self) -> None:
        """Truncates output to last N lines on failure."""
        step = ci.Step(name="Test", command="echo", workflow="code")
        # Generate output with more lines than the limit
        long_output = "\n".join([f"line {i}" for i in range(100)])
        with patch("ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout=long_output, stderr=""
            )
            success, output = ci.run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            lines = output.strip().split("\n")
            assert len(lines) == ci.FAILURE_OUTPUT_LINES

    def test_worktree_clean_check_dirty(self) -> None:
        """Worktree clean check fails with uncommitted changes."""
        step = ci.Step(
            name="Worktree clean check",
            command="git status --porcelain",
            workflow="code",
        )
        with patch("ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=" M file.py\n", stderr=""
            )
            success, output = ci.run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            assert "Uncommitted changes" in output

    def test_timeout_returns_failure(self) -> None:
        """Returns failure when command times out."""
        step = ci.Step(name="Test", command="sleep 999", workflow="code")
        with patch("ci.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd="sleep 999", timeout=300
            )
            success, output = ci.run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is False
            assert "timed out after 300 seconds" in output
            assert "ci.py --step-timeout 600" in output

    def test_worktree_clean_check_clean(self) -> None:
        """Worktree clean check succeeds with clean worktree."""
        step = ci.Step(
            name="Worktree clean check",
            command="git status --porcelain",
            workflow="code",
        )
        with patch("ci.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            success, output = ci.run_step(
                step, fix_mode=False, verbose=False, step_timeout=300
            )
            assert success is True


class TestRunCi:
    """Tests for run_ci function."""

    def test_all_steps_pass(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns 0 when all steps pass."""
        with patch("ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = ci.run_ci()
            assert result == 0
            captured = capsys.readouterr()
            assert "All" in captured.out
            assert "passed" in captured.out

    def test_step_fails(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns 1 when a step fails."""
        with patch("ci.run_step") as mock_run_step:
            # First step passes, second fails
            mock_run_step.side_effect = [
                (True, ""),
                (False, "error output"),
            ] + [(True, "")] * 20  # Rest pass
            with patch.object(sys.stdout, "isatty", return_value=False):
                result = ci.run_ci()
            assert result == 1
            captured = capsys.readouterr()
            assert "failed" in captured.out

    def test_security_workflow_filter(self) -> None:
        """Filters steps by security workflow."""
        with patch("ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                ci.run_ci(workflows=["security"])
            # Should run license check + vulnerability scan
            assert mock_run_step.call_count == 2

    def test_invalid_workflow(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns 2 for invalid workflow filter."""
        with patch.object(sys.stdout, "isatty", return_value=False):
            result = ci.run_ci(workflows=["nonexistent"])
        assert result == 2
        captured = capsys.readouterr()
        assert "No steps to run" in captured.out

    def test_fix_mode_passed_to_steps(self) -> None:
        """Passes fix_mode to run_step."""
        with patch("ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "")
            with patch.object(sys.stdout, "isatty", return_value=False):
                ci.run_ci(fix_mode=True, workflows=["security"])
            # Check that fix_mode=True was passed
            call_args = mock_run_step.call_args
            assert call_args[0][1] is True  # fix_mode argument

    def test_verbose_mode_passed_to_steps(self) -> None:
        """Passes verbose to run_step."""
        with patch("ci.run_step") as mock_run_step:
            mock_run_step.return_value = (True, "output")
            with patch.object(sys.stdout, "isatty", return_value=False):
                ci.run_ci(verbose=True, workflows=["security"])
            # Check that verbose=True was passed
            call_args = mock_run_step.call_args
            assert call_args[0][2] is True  # verbose argument

    def test_prints_command_on_failure(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Prints the command that failed."""
        with patch("ci.run_step") as mock_run_step:
            # Make lint step fail
            def side_effect(
                step: ci.Step, fix_mode: bool, verbose: bool, step_timeout: int
            ) -> tuple[bool, str]:
                if step.name == "Lint":
                    return (False, "lint error")
                return (True, "")

            mock_run_step.side_effect = side_effect
            with patch.object(sys.stdout, "isatty", return_value=False):
                ci.run_ci(workflows=["code"])
            captured = capsys.readouterr()
            assert "Command:" in captured.out
            assert "uv run ruff check ." in captured.out


class TestMain:
    """Tests for main function."""

    def test_parses_workflow_argument(self) -> None:
        """Parses --workflow argument."""
        with patch("ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--workflow", "code"]):
                ci.main()
            mock_run_ci.assert_called_once_with(
                workflows=["code"],
                fix_mode=False,
                verbose=False,
                step_timeout=ci.DEFAULT_STEP_TIMEOUT_SECONDS,
            )

    def test_parses_fix_argument(self) -> None:
        """Parses --fix argument."""
        with patch("ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--fix"]):
                ci.main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=True,
                verbose=False,
                step_timeout=ci.DEFAULT_STEP_TIMEOUT_SECONDS,
            )

    def test_parses_verbose_argument(self) -> None:
        """Parses --verbose argument."""
        with patch("ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "--verbose"]):
                ci.main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=False,
                verbose=True,
                step_timeout=ci.DEFAULT_STEP_TIMEOUT_SECONDS,
            )

    def test_parses_short_verbose_argument(self) -> None:
        """Parses -v argument."""
        with patch("ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch("sys.argv", ["ci.py", "-v"]):
                ci.main()
            mock_run_ci.assert_called_once_with(
                workflows=None,
                fix_mode=False,
                verbose=True,
                step_timeout=ci.DEFAULT_STEP_TIMEOUT_SECONDS,
            )

    def test_multiple_workflow_arguments(self) -> None:
        """Parses multiple --workflow arguments."""
        with patch("ci.run_ci") as mock_run_ci:
            mock_run_ci.return_value = 0
            with patch(
                "sys.argv",
                ["ci.py", "--workflow", "code", "--workflow", "security"],
            ):
                ci.main()
            mock_run_ci.assert_called_once_with(
                workflows=["code", "security"],
                fix_mode=False,
                verbose=False,
                step_timeout=ci.DEFAULT_STEP_TIMEOUT_SECONDS,
            )


class TestDriftDetection:
    """Tests that verify ci.py steps match workflow files."""

    def test_code_workflow_steps_match(self) -> None:
        """Verify ci.py covers all steps from code.yml."""
        workflow_path = (
            Path(__file__).parent.parent / ".github/workflows/code.yml"
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
        ci_step_names = {s.name for s in ci.STEPS if s.workflow == "code"}

        # All workflow steps should be in ci.py (minus setup)
        validation_steps = workflow_steps - setup_steps
        missing = validation_steps - ci_step_names
        assert not missing, f"Steps in code.yml not in ci.py: {missing}"

    def test_e2e_workflow_steps_match(self) -> None:
        """Verify ci.py covers all test steps from e2e.yml."""
        workflow_path = (
            Path(__file__).parent.parent / ".github/workflows/e2e.yml"
        )
        with open(workflow_path) as f:
            workflow = yaml.safe_load(f)

        # Extract step names from workflow (only "Run" steps are tests)
        workflow_steps = set()
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                name = step.get("name", "")
                # Only include "Run" steps which are actual test executions
                if name.startswith("Run "):
                    workflow_steps.add(name)

        # Get ci.py step names for e2e workflow
        ci_step_names = {s.name for s in ci.STEPS if s.workflow == "e2e"}

        # Map workflow step names to ci.py step names
        # Workflow uses "Run X tests" format, ci.py uses "E2E X tests"
        expected_ci_names = set()
        for step_name in workflow_steps:
            if "email gateway" in step_name.lower():
                expected_ci_names.add("E2E email gateway tests")

        missing = expected_ci_names - ci_step_names
        assert not missing, f"E2E steps in e2e.yml not in ci.py: {missing}"

    def test_security_workflow_steps_match(self) -> None:
        """Verify ci.py covers all steps from security.yml."""
        workflow_path = (
            Path(__file__).parent.parent / ".github/workflows/security.yml"
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
        ci_step_names = {s.name for s in ci.STEPS if s.workflow == "security"}

        # All workflow steps should be in ci.py (minus setup)
        validation_steps = workflow_steps - setup_steps
        missing = validation_steps - ci_step_names
        assert not missing, f"Steps in security.yml not in ci.py: {missing}"
