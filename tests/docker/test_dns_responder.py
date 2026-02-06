# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the DNS responder used in the proxy container."""

import struct
from pathlib import Path

import pytest
from docker.dns_responder import (
    QCLASS_IN,
    QTYPE_A,
    TTL,
    build_a_response,
    build_not_implemented,
    build_nxdomain,
    is_allowed,
    load_allowed_domains,
    parse_query,
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
