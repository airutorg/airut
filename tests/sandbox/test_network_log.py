# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/network_log.py -- network sandbox log reader."""

from pathlib import Path

from lib.sandbox.network_log import NetworkLog


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
