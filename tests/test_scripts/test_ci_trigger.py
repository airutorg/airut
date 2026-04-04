# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/ci_trigger.py."""

from unittest.mock import patch

import pytest
from scripts.ci_trigger import CI_FIX_BRANCH, build_prompt, main, run_ci


class TestRunCi:
    """Tests for run_ci function."""

    def test_returns_exit_code_and_output_on_success(self) -> None:
        """run_ci returns exit code 0 and output when CI passes."""
        with patch("scripts.ci_trigger.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "All 7 checks passed (5s)\n"
            mock_run.return_value.stderr = ""

            exit_code, output = run_ci()

            assert exit_code == 0
            assert "All 7 checks passed" in output
            # Verify ci.py is called with --fix and --timeout 0
            cmd = mock_run.call_args[0][0]
            assert "--fix" in cmd
            assert "--timeout" in cmd
            assert cmd[-1] == "0"

    def test_returns_exit_code_and_output_on_failure(self) -> None:
        """run_ci returns non-zero exit code and output when CI fails."""
        with patch("scripts.ci_trigger.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = "Lint failed:\nerror\n"
            mock_run.return_value.stderr = "some warning\n"

            exit_code, output = run_ci()

            assert exit_code == 1
            assert "Lint failed:" in output
            assert "some warning" in output


class TestBuildPrompt:
    """Tests for build_prompt function."""

    def test_includes_ci_output(self) -> None:
        """Prompt includes the CI output."""
        ci_output = "✗ Lint\nSummary: 1 of 7 checks failed\n"
        prompt = build_prompt(ci_output)

        assert ci_output in prompt

    def test_includes_branch_name(self) -> None:
        """Prompt references the fix/ci branch."""
        prompt = build_prompt("some output")

        assert CI_FIX_BRANCH in prompt

    def test_includes_existing_pr_check(self) -> None:
        """Prompt instructs Claude to check for existing PRs."""
        prompt = build_prompt("some output")

        assert "gh pr list" in prompt
        assert "--head" in prompt
        assert "--state open" in prompt

    def test_includes_new_pr_instructions(self) -> None:
        """Prompt instructs Claude to create a new PR if none exists."""
        prompt = build_prompt("some output")

        assert "Create a new branch" in prompt
        assert "Create a PR" in prompt


class TestMain:
    """Tests for main function."""

    def test_ci_passes_returns_0_no_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When CI passes, main returns 0 and produces no output."""
        with patch("scripts.ci_trigger.run_ci") as mock_run_ci:
            mock_run_ci.return_value = (0, "All checks passed\n")

            result = main()

            assert result == 0
            captured = capsys.readouterr()
            assert captured.out == ""

    def test_ci_fails_returns_0_with_prompt(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """When CI fails, main returns 0 and prints prompt to stdout."""
        with patch("scripts.ci_trigger.run_ci") as mock_run_ci:
            ci_output = "✗ Lint\nSummary: 1 of 7 checks failed\n"
            mock_run_ci.return_value = (1, ci_output)

            result = main()

            assert result == 0
            captured = capsys.readouterr()
            assert "CI is failing on main" in captured.out
            assert ci_output in captured.out
