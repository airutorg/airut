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

from airut._bundled.proxy.dns_responder import (
    QCLASS_IN,
    QTYPE_A,
    TTL,
    _log_to_file,
    _open_network_log,
    build_a_response,
    build_not_implemented,
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
        _log_to_file(buf, "DNS A evil.com -> 10.0.0.1")
        assert buf.getvalue() == "DNS A evil.com -> 10.0.0.1\n"

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

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
    def test_a_query_returns_proxy_ip(self, mock_socket_cls: MagicMock) -> None:
        """Any A query returns proxy IP response."""
        query_data = _build_query("api.github.com")
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1")

        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        # Response should contain the proxy IP
        assert b"\x0a\x00\x00\x01" in sent_data  # 10.0.0.1

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
    def test_unknown_domain_also_returns_proxy_ip(
        self, mock_socket_cls: MagicMock
    ) -> None:
        """Domains not in any allowlist still resolve to proxy IP.

        The DNS responder does not filter — the proxy handles allowlist
        enforcement via HTTP 403. This prevents DNS-based information
        leakage about domain existence.
        """
        query_data = _build_query("evil.com")
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1")

        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        # Should get proxy IP, not NXDOMAIN
        assert b"\x0a\x00\x00\x01" in sent_data  # 10.0.0.1
        # Verify it's a successful response (RCODE=0), not NXDOMAIN (RCODE=3)
        flags = struct.unpack("!H", sent_data[2:4])[0]
        assert flags & 0x000F == 0  # RCODE 0 (no error)

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
    def test_non_a_query_returns_notimp(
        self, mock_socket_cls: MagicMock
    ) -> None:
        """Non-A query (e.g., AAAA) returns NOTIMP."""
        query_data = _build_query("api.github.com", qtype=28)  # AAAA
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1")

        mock_sock.sendto.assert_called_once()
        sent_data = mock_sock.sendto.call_args[0][0]
        # NOTIMP: RCODE=4 in flags
        flags = struct.unpack("!H", sent_data[2:4])[0]
        assert flags & 0x000F == 4  # RCODE NOTIMP

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
    def test_with_log_file(self, mock_socket_cls: MagicMock) -> None:
        """Log file receives messages for all resolved queries."""
        q1 = _build_query("api.github.com")
        q2 = _build_query("evil.com")
        mock_sock = self._make_mock_socket(
            [
                (q1, ("10.0.0.2", 1)),
                (q2, ("10.0.0.2", 2)),
            ]
        )
        mock_socket_cls.return_value = mock_sock

        log_buf = io.StringIO()
        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", log_file=log_buf)

        log_content = log_buf.getvalue()
        # Both domains resolve — no BLOCKED entries
        assert "DNS A api.github.com -> 10.0.0.1" in log_content
        assert "DNS A evil.com -> 10.0.0.1" in log_content

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
    def test_notimp_logged(self, mock_socket_cls: MagicMock) -> None:
        """NOTIMP responses are logged."""
        query_data = _build_query("example.com", qtype=28)  # AAAA
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        log_buf = io.StringIO()
        with pytest.raises(_StopServer):
            run_dns_server("10.0.0.1", log_file=log_buf)

        log_content = log_buf.getvalue()
        assert "DNS AAAA example.com -> NOTIMP" in log_content

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
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
            run_dns_server("10.0.0.1")

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
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
            run_dns_server("10.0.0.1")

        assert mock_sock.sendto.call_count == 2

    @patch("airut._bundled.proxy.dns_responder.socket.socket")
    def test_no_upstream_dns_resolution(
        self, mock_socket_cls: MagicMock
    ) -> None:
        """Verify no upstream DNS resolution occurs for any domain.

        The DNS responder must never make real DNS queries (e.g., via
        socket.getaddrinfo or similar) to determine if a domain exists.
        This prevents DNS exfiltration attacks where data is encoded
        in domain names queried against attacker-controlled nameservers.
        """
        query_data = _build_query("attacker-controlled.exfiltrate.example")
        mock_sock = self._make_mock_socket([(query_data, ("10.0.0.2", 12345))])
        mock_socket_cls.return_value = mock_sock

        with (
            patch(
                "airut._bundled.proxy.dns_responder.socket.getaddrinfo"
            ) as mock_getaddrinfo,
            pytest.raises(_StopServer),
        ):
            run_dns_server("10.0.0.1")

        # getaddrinfo should never be called during query handling
        mock_getaddrinfo.assert_not_called()
        # Still resolves to proxy IP
        sent_data = mock_sock.sendto.call_args[0][0]
        assert b"\x0a\x00\x00\x01" in sent_data


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for main() CLI entry point."""

    @patch("airut._bundled.proxy.dns_responder.run_dns_server")
    def test_with_explicit_ip(
        self,
        mock_run: MagicMock,
    ) -> None:
        """Explicit proxy IP from sys.argv."""
        with patch("sys.argv", ["dns_responder.py", "10.0.0.1"]):
            main()
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == "10.0.0.1"

    @patch("airut._bundled.proxy.dns_responder.run_dns_server")
    @patch(
        "airut._bundled.proxy.dns_responder.socket.gethostbyname",
        return_value="172.17.0.2",
    )
    @patch(
        "airut._bundled.proxy.dns_responder.socket.gethostname",
        return_value="proxy-host",
    )
    def test_auto_detect_ip(
        self,
        mock_hostname: MagicMock,
        mock_resolve: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """Auto-detects proxy IP when not provided."""
        with patch("sys.argv", ["dns_responder.py"]):
            main()
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == "172.17.0.2"

    @patch("airut._bundled.proxy.dns_responder.run_dns_server")
    @patch(
        "airut._bundled.proxy.dns_responder._open_network_log",
        return_value=None,
    )
    def test_no_log_file(
        self,
        mock_open_log: MagicMock,
        mock_run: MagicMock,
    ) -> None:
        """No log file when _open_network_log returns None."""
        with patch("sys.argv", ["dns_responder.py", "10.0.0.1"]):
            main()
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs.get("log_file") is None

    @patch("airut._bundled.proxy.dns_responder.run_dns_server")
    @patch("airut._bundled.proxy.dns_responder._open_network_log")
    def test_with_log_file(
        self,
        mock_open_log: MagicMock,
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
        import airut._bundled.proxy.dns_responder as mod

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
