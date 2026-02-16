# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/airut.py."""


def test_import_exposes_cli() -> None:
    """Importing scripts.airut makes airut.cli.cli available."""
    from scripts.airut import cli

    assert callable(cli)
