# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for dashboard formatters module."""

from lib.dashboard.formatters import (
    VersionInfo,
    format_duration,
    format_timestamp,
)


class TestFormatDuration:
    """Tests for format_duration helper function."""

    def test_none(self) -> None:
        """Test formatting None duration."""
        assert format_duration(None) == "-"

    def test_negative(self) -> None:
        """Test formatting negative duration."""
        assert format_duration(-5) == "-"

    def test_seconds_only(self) -> None:
        """Test formatting duration under a minute."""
        assert format_duration(0) == "0s"
        assert format_duration(1) == "1s"
        assert format_duration(45) == "45s"
        assert format_duration(59) == "59s"

    def test_minutes_and_seconds(self) -> None:
        """Test formatting duration with minutes."""
        assert format_duration(60) == "1m 0s"
        assert format_duration(90) == "1m 30s"
        assert format_duration(125) == "2m 5s"
        assert format_duration(3599) == "59m 59s"

    def test_hours_minutes_seconds(self) -> None:
        """Test formatting duration with hours."""
        assert format_duration(3600) == "1h 0m 0s"
        assert format_duration(3661) == "1h 1m 1s"
        assert format_duration(7325) == "2h 2m 5s"


class TestFormatTimestamp:
    """Tests for format_timestamp helper function."""

    def test_none(self) -> None:
        """Test formatting None timestamp."""
        assert format_timestamp(None) == "-"

    def test_valid_timestamp(self) -> None:
        """Test formatting valid timestamp."""
        # Unix timestamp for 2000-01-01 00:00:00 UTC
        ts = 946684800.0
        result = format_timestamp(ts)
        assert result == "2000-01-01 00:00:00 UTC"


class TestVersionInfo:
    """Tests for VersionInfo dataclass."""

    def test_create(self) -> None:
        """Test creating VersionInfo."""
        info = VersionInfo(
            version="v0.7.0",
            git_sha="abc1234",
            git_sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="=== HEAD COMMIT ===\ncommit abc1234",
            started_at=946684800.0,
        )

        assert info.version == "v0.7.0"
        assert info.git_sha == "abc1234"
        assert info.git_sha_full == "abc1234567890abcdef1234567890abcdef123456"
        assert info.full_status == "=== HEAD COMMIT ===\ncommit abc1234"
        assert info.started_at == 946684800.0

    def test_create_without_version(self) -> None:
        """Test creating VersionInfo without a version tag."""
        info = VersionInfo(
            version="",
            git_sha="def5678",
            git_sha_full="def5678901234567890abcdef1234567890abcdef",
            full_status="=== HEAD COMMIT ===\ncommit def5678",
            started_at=1000000000.0,
        )

        assert info.git_sha == "def5678"
