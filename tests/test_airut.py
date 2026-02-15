# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/airut.py."""

from unittest.mock import patch

from lib.airut import cli


def test_cli_calls_main_and_exits() -> None:
    """Test cli() calls gateway main() and passes exit code to sys.exit."""
    with (
        patch("lib.airut.main", return_value=0) as mock_main,
        patch("lib.airut.sys.exit") as mock_exit,
    ):
        cli()

    mock_main.assert_called_once()
    mock_exit.assert_called_once_with(0)


def test_cli_propagates_nonzero_exit_code() -> None:
    """Test cli() propagates non-zero exit codes."""
    with (
        patch("lib.airut.main", return_value=1) as mock_main,
        patch("lib.airut.sys.exit") as mock_exit,
    ):
        cli()

    mock_main.assert_called_once()
    mock_exit.assert_called_once_with(1)
