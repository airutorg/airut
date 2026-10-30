# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for byte size formatting."""

from airut.units import format_size


class TestFormatSize:
    """Test size formatting."""

    def test_bytes(self) -> None:
        assert format_size(500) == "500B"

    def test_kb(self) -> None:
        assert format_size(2048) == "2KB"

    def test_mb(self) -> None:
        assert format_size(2 * 1024 * 1024) == "2.0MB"
