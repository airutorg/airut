# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/network_log.py -- network sandbox log reader."""

from pathlib import Path

from airut.sandbox.network_log import NetworkLog


class TestNetworkLogPath:
    """Tests for NetworkLog.path property."""

    def test_path_property(self, tmp_path: Path) -> None:
        """Path returns the configured log file path."""
        log_path = tmp_path / "network-sandbox.log"
        log = NetworkLog(log_path)
        assert log.path == log_path


class TestNetworkLogExists:
    """Tests for NetworkLog.exists method."""

    def test_exists_when_file_present(self, tmp_path: Path) -> None:
        """Returns True when log file exists."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("some content")
        log = NetworkLog(log_path)
        assert log.exists() is True

    def test_not_exists_when_file_missing(self, tmp_path: Path) -> None:
        """Returns False when log file does not exist."""
        log_path = tmp_path / "network-sandbox.log"
        log = NetworkLog(log_path)
        assert log.exists() is False

    def test_not_exists_for_nonexistent_parent(self, tmp_path: Path) -> None:
        """Returns False when parent directory does not exist."""
        log_path = tmp_path / "nonexistent" / "network-sandbox.log"
        log = NetworkLog(log_path)
        assert log.exists() is False


class TestNetworkLogReadRaw:
    """Tests for NetworkLog.read_raw method."""

    def test_reads_content(self, tmp_path: Path) -> None:
        """Reads raw content from log file."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("ALLOWED api.example.com\nBLOCKED evil.com\n")
        log = NetworkLog(log_path)
        content = log.read_raw()
        assert "ALLOWED api.example.com" in content
        assert "BLOCKED evil.com" in content

    def test_reads_empty_file(self, tmp_path: Path) -> None:
        """Reads empty file and returns empty string."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("")
        log = NetworkLog(log_path)
        assert log.read_raw() == ""

    def test_reads_multiline_content(self, tmp_path: Path) -> None:
        """Reads multi-line log content correctly."""
        log_path = tmp_path / "network-sandbox.log"
        lines = [
            "2026-01-15T12:00:00 ALLOWED GET https://api.github.com/repos",
            "2026-01-15T12:00:01 BLOCKED GET https://evil.com/malware",
            "2026-01-15T12:00:02 ALLOWED POST https://api.anthropic.com/v1",
        ]
        log_path.write_text("\n".join(lines))
        log = NetworkLog(log_path)
        content = log.read_raw()
        for line in lines:
            assert line in content

    def test_returns_empty_when_file_missing(self, tmp_path: Path) -> None:
        """Returns empty string when log file does not exist."""
        log_path = tmp_path / "nonexistent.log"
        log = NetworkLog(log_path)
        assert log.read_raw() == ""


class TestNetworkLogTail:
    """Tests for NetworkLog.tail method."""

    def test_tail_from_start(self, tmp_path: Path) -> None:
        """Reads all lines from byte offset 0."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("line one\nline two\nline three\n")
        log = NetworkLog(log_path)

        lines, offset = log.tail(0)
        assert lines == ["line one", "line two", "line three"]
        assert offset > 0

    def test_tail_incremental(self, tmp_path: Path) -> None:
        """Reads only new lines after initial tail."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("first\n")
        log = NetworkLog(log_path)

        lines, offset = log.tail(0)
        assert lines == ["first"]

        # Append more content
        with log_path.open("a") as f:
            f.write("second\nthird\n")

        lines, new_offset = log.tail(offset)
        assert lines == ["second", "third"]
        assert new_offset > offset

    def test_tail_no_new_content(self, tmp_path: Path) -> None:
        """Returns empty list when no new content."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("first\n")
        log = NetworkLog(log_path)

        _, offset = log.tail(0)

        lines, new_offset = log.tail(offset)
        assert lines == []
        assert new_offset == offset

    def test_tail_file_missing(self, tmp_path: Path) -> None:
        """Returns empty list and offset 0 for missing file."""
        log_path = tmp_path / "nonexistent.log"
        log = NetworkLog(log_path)

        lines, offset = log.tail(0)
        assert lines == []
        assert offset == 0

    def test_tail_empty_file(self, tmp_path: Path) -> None:
        """Returns empty list for empty file."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("")
        log = NetworkLog(log_path)

        lines, offset = log.tail(0)
        assert lines == []

    def test_tail_skips_blank_lines(self, tmp_path: Path) -> None:
        """Skips blank lines in output."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("line one\n\nline two\n")
        log = NetworkLog(log_path)

        lines, _ = log.tail(0)
        assert lines == ["line one", "line two"]

    def test_tail_preserves_offset_on_missing_file(
        self, tmp_path: Path
    ) -> None:
        """Preserves offset when file doesn't exist on subsequent call."""
        log_path = tmp_path / "network-sandbox.log"
        log = NetworkLog(log_path)

        lines, offset = log.tail(42)
        assert lines == []
        assert offset == 0

    def test_tail_handles_os_error(self, tmp_path: Path) -> None:
        """Returns empty and preserves offset on OSError."""
        log_path = tmp_path / "network-sandbox.log"
        # Create the file so exists() returns True
        log_path.write_text("content\n")
        log = NetworkLog(log_path)

        # Remove the file after exists() check will pass
        # by making it a directory so open() fails
        log_path.unlink()
        log_path.mkdir()

        lines, offset = log.tail(0)
        assert lines == []
        assert offset == 0
