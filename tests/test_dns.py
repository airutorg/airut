# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for system DNS resolver detection."""

from pathlib import Path

import pytest

from airut.dns import SystemResolverError, get_system_resolver


class TestGetSystemResolver:
    """Tests for get_system_resolver()."""

    def test_single_nameserver(self, tmp_path: Path) -> None:
        """Returns the single nameserver entry."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("nameserver 192.168.1.1\n")
        assert get_system_resolver(resolv) == "192.168.1.1"

    def test_multiple_nameservers_returns_first(self, tmp_path: Path) -> None:
        """Returns the first nameserver when multiple are present."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text(
            "nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n"
        )
        assert get_system_resolver(resolv) == "10.0.0.1"

    def test_comments_and_blank_lines(self, tmp_path: Path) -> None:
        """Skips comments and blank lines."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text(
            "# This is a comment\n"
            "\n"
            "search example.com\n"
            "# Another comment\n"
            "nameserver 172.16.0.1\n"
        )
        assert get_system_resolver(resolv) == "172.16.0.1"

    def test_other_directives_skipped(self, tmp_path: Path) -> None:
        """Non-nameserver directives are ignored."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text(
            "domain example.com\n"
            "search example.com local\n"
            "options ndots:5\n"
            "nameserver 8.8.8.8\n"
        )
        assert get_system_resolver(resolv) == "8.8.8.8"

    def test_no_nameserver_entries(self, tmp_path: Path) -> None:
        """Raises SystemResolverError when no nameserver lines exist."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("# Only comments\nsearch example.com\n")
        with pytest.raises(SystemResolverError, match="No nameserver entries"):
            get_system_resolver(resolv)

    def test_empty_file(self, tmp_path: Path) -> None:
        """Raises SystemResolverError for an empty file."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("")
        with pytest.raises(SystemResolverError, match="No nameserver entries"):
            get_system_resolver(resolv)

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Raises SystemResolverError when the file does not exist."""
        resolv = tmp_path / "nonexistent"
        with pytest.raises(SystemResolverError, match="Could not read"):
            get_system_resolver(resolv)

    def test_error_message_mentions_config(self, tmp_path: Path) -> None:
        """Error messages tell the user to set upstream_dns in config."""
        resolv = tmp_path / "nonexistent"
        with pytest.raises(SystemResolverError, match="network.upstream_dns"):
            get_system_resolver(resolv)

    def test_nameserver_with_extra_whitespace(self, tmp_path: Path) -> None:
        """Handles leading/trailing whitespace on nameserver lines."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("  nameserver   1.2.3.4  \n")
        assert get_system_resolver(resolv) == "1.2.3.4"

    def test_malformed_nameserver_line(self, tmp_path: Path) -> None:
        """Skips nameserver lines with no address."""
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("nameserver\nnameserver 5.6.7.8\n")
        assert get_system_resolver(resolv) == "5.6.7.8"
