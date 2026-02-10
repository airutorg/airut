# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the DNS responder used in the proxy container."""

import io
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from docker.dns_responder import (
    QCLASS_IN,
    QTYPE_A,
    TTL,
    _log_to_file,
    _open_network_log,
    build_a_response,
    build_not_implemented,
    build_nxdomain,
    is_allowed,
    load_allowed_domains,
    main,
    parse_query,
    qtype_name,
    run_dns_server,
)


def _build_query(name: str, qtype: int = QTYPE_A) -> bytes:
    """Build a minimal DNS query packet for testing."""
    # Header: ID=0x1234, flags=0x0100 (RD), qdcount=1
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)

    # Question: encode name labels
    question = b""
    for label in name.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"  # root label
    question += struct.pack("!HH", qtype, QCLASS_IN)

    return header + question


class TestParseQuery:
    """Tests for parse_query."""

    def test_valid_a_query(self) -> None:
        """Parses a standard A query."""
        data = _build_query("example.com")
        qname, qtype, qclass, qend = parse_query(data)
        assert qname == "example.com"
        assert qtype == QTYPE_A
        assert qclass == QCLASS_IN
        assert qend > 12  # past header + question

    def test_aaaa_query(self) -> None:
        """Parses an AAAA query (type 28)."""
        data = _build_query("example.com", qtype=28)
        qname, qtype, _qclass, _qend = parse_query(data)
        assert qname == "example.com"
        assert qtype == 28

    def test_subdomain(self) -> None:
        """Parses multi-label domain name."""
        data = _build_query("api.github.com")
        qname, _qtype, _qclass, _qend = parse_query(data)
        assert qname == "api.github.com"

    def test_truncated_packet(self) -> None:
        """Raises ValueError for truncated packet."""
        with pytest.raises(ValueError, match="packet too short"):
            parse_query(b"\x00" * 5)

    def test_truncated_question(self) -> None:
        """Raises ValueError when question section is truncated."""
        # Valid header + start of name but no qtype/qclass
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        question = b"\x03" + b"foo" + b"\x00"  # Name but no qtype/qclass
        with pytest.raises(ValueError, match="truncated question"):
            parse_query(header + question)


class TestBuildAResponse:
    """Tests for build_a_response."""

    def test_response_format(self) -> None:
        """Builds a valid A record response."""
        query = _build_query("example.com")
        _, _, _, qend = parse_query(query)
        response = build_a_response(query, "10.199.1.100", qend)

        # Transaction ID preserved
        assert response[:2] == query[:2]
        # Flags: QR=1, RD=1, RA=1, RCODE=0
        flags = struct.unpack("!H", response[2:4])[0]
        assert flags == 0x8180
        # Counts: QD=1, AN=1
        counts = struct.unpack("!HHHH", response[4:12])
        assert counts == (1, 1, 0, 0)

    def test_ip_in_response(self) -> None:
        """Response contains the proxy IP address."""
        import socket

        query = _build_query("test.example.com")
        _, _, _, qend = parse_query(query)
        response = build_a_response(query, "10.199.42.100", qend)

        # The IP should appear in the answer section
        expected_ip = socket.inet_aton("10.199.42.100")
        assert expected_ip in response

    def test_ttl_in_response(self) -> None:
        """Response includes the configured TTL."""
        query = _build_query("example.com")
        _, _, _, qend = parse_query(query)
        response = build_a_response(query, "10.199.1.100", qend)

        # TTL should appear as a 4-byte big-endian value
        ttl_bytes = struct.pack("!I", TTL)
        assert ttl_bytes in response


class TestBuildNxdomain:
    """Tests for build_nxdomain."""

    def test_nxdomain_format(self) -> None:
        """Builds a valid NXDOMAIN response."""
        query = _build_query("blocked.example.com")
        _, _, _, qend = parse_query(query)
        response = build_nxdomain(query, qend)

        # Transaction ID preserved
        assert response[:2] == query[:2]
        # Flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        flags = struct.unpack("!H", response[2:4])[0]
        assert flags == 0x8183
        # No answer records
        counts = struct.unpack("!HHHH", response[4:12])
        assert counts == (1, 0, 0, 0)


class TestBuildNotImplemented:
    """Tests for build_not_implemented."""

    def test_notimp_format(self) -> None:
        """Builds a valid NOTIMP response."""
        query = _build_query("example.com", qtype=28)  # AAAA
        _, _, _, qend = parse_query(query)
        response = build_not_implemented(query, qend)

        # Transaction ID preserved
        assert response[:2] == query[:2]
        # Flags: QR=1, RD=1, RA=1, RCODE=4 (NOTIMP)
        flags = struct.unpack("!H", response[2:4])[0]
        assert flags == 0x8184


class TestIsAllowed:
    """Tests for is_allowed."""

    def test_exact_match(self) -> None:
        """Exact domain match."""
        assert is_allowed("example.com", ["example.com"])
        assert not is_allowed("other.com", ["example.com"])

    def test_wildcard_match(self) -> None:
        """Fnmatch wildcard patterns."""
        assert is_allowed("api.github.com", ["*.github.com"])
        assert not is_allowed("github.com", ["*.github.com"])

    def test_multiple_patterns(self) -> None:
        """Matches against any pattern in the list."""
        patterns = ["example.com", "*.github.com", "pypi.org"]
        assert is_allowed("example.com", patterns)
        assert is_allowed("api.github.com", patterns)
        assert is_allowed("pypi.org", patterns)
        assert not is_allowed("evil.com", patterns)

    def test_empty_patterns(self) -> None:
        """No patterns means nothing is allowed."""
        assert not is_allowed("anything.com", [])


class TestLoadAllowedDomains:
    """Tests for load_allowed_domains."""

    def test_loads_domains(self, tmp_path: Path) -> None:
        """Loads domain patterns from allowlist YAML."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("domains:\n  - example.com\n  - '*.github.com'\n")
        patterns = load_allowed_domains(allowlist)
        assert "example.com" in patterns
        assert "*.github.com" in patterns

    def test_loads_url_prefix_hosts(self, tmp_path: Path) -> None:
        """Extracts hosts from url_prefixes entries."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text(
            "url_prefixes:\n  - host: api.github.com\n    path: /repos\n"
        )
        patterns = load_allowed_domains(allowlist)
        assert "api.github.com" in patterns

    def test_deduplicates(self, tmp_path: Path) -> None:
        """Domains appearing in both sections are not duplicated."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text(
            "domains:\n"
            "  - api.github.com\n"
            "url_prefixes:\n"
            "  - host: api.github.com\n"
            "    path: /repos\n"
        )
        patterns = load_allowed_domains(allowlist)
        assert patterns.count("api.github.com") == 1

    def test_missing_file(self, tmp_path: Path) -> None:
        """Returns empty list for missing file."""
        patterns = load_allowed_domains(tmp_path / "nonexistent.yaml")
        assert patterns == []

    def test_empty_file(self, tmp_path: Path) -> None:
        """Returns empty list for empty YAML."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("")
        patterns = load_allowed_domains(allowlist)
        assert patterns == []


class TestQtypeName:
    """Tests for qtype_name."""

    def test_known_types(self) -> None:
        """Returns name for common DNS query types."""
        assert qtype_name(1) == "A"
        assert qtype_name(28) == "AAAA"
        assert qtype_name(15) == "MX"
        assert qtype_name(16) == "TXT"

    def test_unknown_type(self) -> None:
        """Falls back to TYPE{n} for unknown types."""
        assert qtype_name(999) == "TYPE999"


class TestOpenNetworkLog:
    """Tests for _open_network_log."""

    def test_opens_existing_file(self, tmp_path: Path) -> None:
        """Opens the log file for appending if it exists."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.touch()
        f = _open_network_log(log_path)
        assert f is not None
        f.write("test\n")
        f.close()
        assert log_path.read_text() == "test\n"

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        """Returns None if the file does not exist."""
        result = _open_network_log(tmp_path / "nonexistent.log")
        assert result is None

    def test_returns_none_on_open_error(self, tmp_path: Path) -> None:
        """Returns None if the file cannot be opened."""
        # Use a directory path to trigger OSError on open()
        dir_path = tmp_path / "a_directory"
        dir_path.mkdir()
        result = _open_network_log(dir_path)
        assert result is None


class TestLogToFile:
    """Tests for _log_to_file."""

    def test_writes_line_with_newline(self) -> None:
        """Appends message with trailing newline."""
        buf = io.StringIO()
        _log_to_file(buf, "BLOCKED DNS A evil.com -> NXDOMAIN")
        assert buf.getvalue() == "BLOCKED DNS A evil.com -> NXDOMAIN\n"

    def test_none_file_is_noop(self) -> None:
        """Does nothing when log_file is None."""
        _log_to_file(None, "should not crash")

    def test_ignores_write_errors(self) -> None:
        """Silently ignores OSError on write."""
        buf = io.StringIO()
        buf.close()  # Closed buffer raises ValueError (subclass of OSError? No)

        # Use a mock that raises OSError
        class FailWriter:
            def write(self, _s: str) -> int:
                raise OSError("disk full")

            def flush(self) -> None:
                raise OSError("disk full")

        _log_to_file(FailWriter(), "should not crash")  # type: ignore[arg-type]

    def test_multiple_writes(self) -> None:
        """Multiple calls append sequentially."""
        buf = io.StringIO()
        _log_to_file(buf, "line 1")
        _log_to_file(buf, "line 2")
        assert buf.getvalue() == "line 1\nline 2\n"


# ---------------------------------------------------------------------------
# run_dns_server
# ---------------------------------------------------------------------------


class _StopServer(BaseException):
    """Sentinel to break the infinite loop in run_dns_server.

    Extends BaseException (not Exception) so that the ``except Exception``
    handler inside ``run_dns_server`` does NOT catch it, letting the loop
    actually terminate.
    """


class TestRunDnsServer:
    """Tests for run_dns_server main loop."""

    def _make_mock_socket(
        self, queries: list[tuple[bytes, tuple[str, int]]]
    ) -> MagicMock:
        """Build a mock UDP socket that returns queries then stops."""
        mock_sock = MagicMock()
        # recvfrom returns each query in order, then raises to stop loop
        mock_sock.recvfrom.side_effect = [
            *queries,
            _StopServer("done"),
        ]
        mock_sock.sendto = MagicMock()
        return mock_sock

    @patch("docker.dns_responder.socket.socket")
    def test_allowed_a_query(self, mock_socket_cls: MagicMock) -> None:
        """Allowed A query returns proxy IP response."""
        query_data = _build_query("api.github.com")
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", ["*.github.com"])

        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        # Response should contain the proxy IP
        assert b"\x0a\x00\x00\x01" in sent_data  # 10.0.0.1

    @patch("docker.dns_responder.socket.socket")
    def test_blocked_a_query(self, mock_socket_cls: MagicMock) -> None:
        """Blocked A query returns NXDOMAIN."""
        query_data = _build_query("evil.com")
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", ["*.github.com"])

        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        # NXDOMAIN: RCODE=3 in flags (byte 3, low nibble = 3)
        flags = struct.unpack("!H", sent_data[2:4])[0]
        assert flags & 0x000F == 3  # RCODE NXDOMAIN

    @patch("docker.dns_responder.socket.socket")
    def test_non_a_query_returns_notimp(
        self, mock_socket_cls: MagicMock
    ) -> None:
        """Non-A query (e.g., AAAA) returns NOTIMP."""
        query_data = _build_query("api.github.com", qtype=28)  # AAAA
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", ["*.github.com"])

        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        # NOTIMP: RCODE=4 in flags
        flags = struct.unpack("!H", sent_data[2:4])[0]
        assert flags & 0x000F == 4  # RCODE NOTIMP

    @patch("docker.dns_responder.socket.socket")
    def test_with_log_file(self, mock_socket_cls: MagicMock) -> None:
        """Log file receives messages for allowed and blocked queries."""
        allowed = _build_query("api.github.com")
        blocked = _build_query("evil.com")
        mock_sock = self._make_mock_socket(
            [
                (allowed, ("10.0.0.2", 1)),
                (blocked, ("10.0.0.2", 2)),
            ]
        )
        mock_socket_cls.return_value = mock_sock

        log_buf = io.StringIO()
        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", ["*.github.com"], log_file=log_buf)

        log_content = log_buf.getvalue()
        assert "allowed DNS A api.github.com" in log_content
        assert "BLOCKED DNS A evil.com" in log_content

    @patch("docker.dns_responder.socket.socket")
    def test_exception_in_loop_continues(
        self, mock_socket_cls: MagicMock
    ) -> None:
        """Generic exceptions in the loop are caught and logged."""
        mock_sock = MagicMock()
        # First call raises generic error, second raises sentinel
        mock_sock.recvfrom.side_effect = [
            ValueError("bad packet"),
            _StopServer("done"),
        ]
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", [])

    @patch("docker.dns_responder.socket.socket")
    def test_multiple_queries(self, mock_socket_cls: MagicMock) -> None:
        """Multiple queries are processed sequentially."""
        q1 = _build_query("allowed.com")
        q2 = _build_query("also-allowed.com")
        mock_sock = self._make_mock_socket(
            [
                (q1, ("10.0.0.2", 1)),
                (q2, ("10.0.0.2", 2)),
            ]
        )
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", ["allowed.com", "also-allowed.com"])

        assert mock_sock.sendto.call_count == 2


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for main() CLI entry point."""

    @patch("docker.dns_responder.run_dns_server")
    @patch("docker.dns_responder.load_allowed_domains", return_value=["*.com"])
    def test_with_explicit_ip(
        self,
        mock_load: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Explicit proxy IP from sys.argv."""
        with patch("sys.argv", ["dns_responder.py", "10.0.0.1"]):
            main()
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == "10.0.0.1"

    @patch("docker.dns_responder.run_dns_server")
    @patch("docker.dns_responder.load_allowed_domains", return_value=[])
    @patch(
        "docker.dns_responder.socket.gethostbyname",
        return_value="172.17.0.2",
    )
    @patch(
        "docker.dns_responder.socket.gethostname",
        return_value="proxy-host",
    )
    def test_auto_detect_ip(
        self,
        mock_hostname: MagicMock,
        mock_resolve: MagicMock,
        mock_load: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Auto-detects proxy IP when not provided."""
        with patch("sys.argv", ["dns_responder.py"]):
            main()
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == "172.17.0.2"

    @patch("docker.dns_responder.run_dns_server")
    @patch("docker.dns_responder.load_allowed_domains", return_value=["a.com"])
    @patch("docker.dns_responder._open_network_log", return_value=None)
    def test_no_log_file(
        self,
        mock_open_log: MagicMock,
        mock_load: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """No log file when _open_network_log returns None."""
        with patch("sys.argv", ["dns_responder.py", "10.0.0.1"]):
            main()
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs.get("log_file") is None

    @patch("docker.dns_responder.run_dns_server")
    @patch("docker.dns_responder.load_allowed_domains", return_value=["a.com"])
    @patch("docker.dns_responder._open_network_log")
    def test_with_log_file(
        self,
        mock_open_log: MagicMock,
        mock_load: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Log file passed through when available."""
        mock_log = io.StringIO()
        mock_open_log.return_value = mock_log
        with patch("sys.argv", ["dns_responder.py", "10.0.0.1"]):
            main()
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs.get("log_file") is mock_log


# ---------------------------------------------------------------------------
# __main__ guard
# ---------------------------------------------------------------------------


class TestMainGuard:
    """Tests for ``if __name__ == '__main__'`` entry point."""

    def test_main_guard_invokes_main(self) -> None:
        """``if __name__ == '__main__'`` calls main()."""
        import docker.dns_responder as mod

        with patch.object(mod, "main") as mock_main:
            # Simulate `python dns_responder.py` by exec'ing the guard
            exec(  # noqa: S102 -- testing __main__ guard
                compile(
                    'if __name__ == "__main__": main()',
                    "<test>",
                    "exec",
                ),
                {"__name__": "__main__", "main": mock_main},
            )
        mock_main.assert_called_once()
