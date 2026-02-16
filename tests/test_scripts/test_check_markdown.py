# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/check_markdown.py."""

from unittest.mock import MagicMock, patch

import pytest
from scripts.check_markdown import main


class TestMain:
    """Tests for main function."""

    def test_clean_run_returns_0(self) -> None:
        """Returns 0 when mdformat passes with no errors."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            with patch("sys.argv", ["check_markdown.py"]):
                result = main()

        assert result == 0
        call_args = mock_run.call_args[0][0]
        assert "--check" in call_args

    def test_fix_mode_omits_check_flag(self) -> None:
        """Does not pass --check when --fix is given."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            with patch("sys.argv", ["check_markdown.py", "--fix"]):
                result = main()

        assert result == 0
        call_args = mock_run.call_args[0][0]
        assert "--check" not in call_args

    def test_custom_paths(self) -> None:
        """Passes custom paths to mdformat."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            with patch(
                "sys.argv",
                ["check_markdown.py", "doc/", "README.md"],
            ):
                result = main()

        assert result == 0
        call_args = mock_run.call_args[0][0]
        assert "doc/" in call_args
        assert "README.md" in call_args
        assert "." not in call_args

    def test_default_path_is_dot(self) -> None:
        """Uses '.' as default path when none given."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            with patch("sys.argv", ["check_markdown.py"]):
                main()

        call_args = mock_run.call_args[0][0]
        assert call_args[-1] == "."

    def test_mdformat_failure_returns_exit_code(self) -> None:
        """Returns mdformat's nonzero exit code on failure."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=2, stdout="file.md\n", stderr=""
            )
            with patch("sys.argv", ["check_markdown.py"]):
                result = main()

        assert result == 2

    def test_code_block_format_error_returns_1(self) -> None:
        """Returns 1 when code block formatting fails."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr=("Failed formatting content of a python code block"),
            )
            with patch("sys.argv", ["check_markdown.py"]):
                result = main()

        assert result == 1

    def test_parse_error_returns_1(self) -> None:
        """Returns 1 when 'error: Failed to parse' in output."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="error: Failed to parse something",
                stderr="",
            )
            with patch("sys.argv", ["check_markdown.py"]):
                result = main()

        assert result == 1

    def test_prints_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Prints mdformat stdout."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="formatted output\n",
                stderr="",
            )
            with patch("sys.argv", ["check_markdown.py"]):
                main()

        captured = capsys.readouterr()
        assert "formatted output" in captured.out

    def test_prints_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Prints mdformat stderr."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="warning message\n",
            )
            with patch("sys.argv", ["check_markdown.py"]):
                main()

        captured = capsys.readouterr()
        assert "warning message" in captured.err

    def test_fix_with_custom_path(self) -> None:
        """Combines --fix with custom path correctly."""
        with patch("scripts.check_markdown.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            with patch(
                "sys.argv",
                ["check_markdown.py", "--fix", "doc/"],
            ):
                main()

        call_args = mock_run.call_args[0][0]
        assert "--check" not in call_args
        # --fix is consumed, not passed to mdformat
        assert "--fix" not in call_args
        assert "doc/" in call_args
