# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/allowlist.py — typed allowlist parsing and serialization."""

import json
from pathlib import Path

import pytest

from airut.allowlist import (
    Allowlist,
    AllowlistDomain,
    AllowlistUrlPattern,
    parse_allowlist_yaml,
    serialize_allowlist_json,
)


class TestAllowlistDomain:
    """Tests for AllowlistDomain dataclass."""

    def test_basic(self) -> None:
        d = AllowlistDomain(host="api.github.com")
        assert d.host == "api.github.com"

    def test_frozen(self) -> None:
        d = AllowlistDomain(host="example.com")
        with pytest.raises(AttributeError):
            d.host = "other.com"  # type: ignore[misc]


class TestAllowlistUrlPattern:
    """Tests for AllowlistUrlPattern dataclass."""

    def test_defaults(self) -> None:
        p = AllowlistUrlPattern(host="pypi.org")
        assert p.host == "pypi.org"
        assert p.path == ""
        assert p.methods == ()

    def test_all_fields(self) -> None:
        p = AllowlistUrlPattern(
            host="api.github.com",
            path="/repos/org*",
            methods=("GET", "HEAD"),
        )
        assert p.host == "api.github.com"
        assert p.path == "/repos/org*"
        assert p.methods == ("GET", "HEAD")

    def test_frozen(self) -> None:
        p = AllowlistUrlPattern(host="example.com")
        with pytest.raises(AttributeError):
            p.host = "other.com"  # type: ignore[misc]


class TestAllowlist:
    """Tests for Allowlist dataclass."""

    def test_basic(self) -> None:
        al = Allowlist(
            domains=(AllowlistDomain(host="example.com"),),
            url_patterns=(
                AllowlistUrlPattern(host="pypi.org", path="/simple*"),
            ),
        )
        assert len(al.domains) == 1
        assert len(al.url_patterns) == 1

    def test_empty(self) -> None:
        al = Allowlist(domains=(), url_patterns=())
        assert al.domains == ()
        assert al.url_patterns == ()

    def test_frozen(self) -> None:
        al = Allowlist(domains=(), url_patterns=())
        with pytest.raises(AttributeError):
            al.domains = ()  # type: ignore[misc]


class TestParseAllowlistYaml:
    """Tests for parse_allowlist_yaml()."""

    def test_full_allowlist(self) -> None:
        """Parses a complete allowlist with domains and url_prefixes."""
        yaml_data = b"""\
domains:
  - api.anthropic.com
  - "*.github.com"

url_prefixes:
  - host: pypi.org
    path: ""
    methods: [GET, HEAD]
  - host: api.github.com
    path: /repos/org*
  - host: sentry.io
    path: ""
    methods: [POST]
"""
        al = parse_allowlist_yaml(yaml_data)
        assert len(al.domains) == 2
        assert al.domains[0].host == "api.anthropic.com"
        assert al.domains[1].host == "*.github.com"

        assert len(al.url_patterns) == 3
        assert al.url_patterns[0].host == "pypi.org"
        assert al.url_patterns[0].path == ""
        assert al.url_patterns[0].methods == ("GET", "HEAD")
        assert al.url_patterns[1].host == "api.github.com"
        assert al.url_patterns[1].path == "/repos/org*"
        assert al.url_patterns[1].methods == ()
        assert al.url_patterns[2].host == "sentry.io"
        assert al.url_patterns[2].methods == ("POST",)

    def test_domains_only(self) -> None:
        """Parses allowlist with only domains."""
        yaml_data = b"domains:\n  - api.anthropic.com\n"
        al = parse_allowlist_yaml(yaml_data)
        assert len(al.domains) == 1
        assert al.domains[0].host == "api.anthropic.com"
        assert al.url_patterns == ()

    def test_url_prefixes_only(self) -> None:
        """Parses allowlist with only url_prefixes."""
        yaml_data = b"url_prefixes:\n  - host: pypi.org\n    path: /simple*\n"
        al = parse_allowlist_yaml(yaml_data)
        assert al.domains == ()
        assert len(al.url_patterns) == 1
        assert al.url_patterns[0].host == "pypi.org"
        assert al.url_patterns[0].path == "/simple*"

    def test_empty_yaml(self) -> None:
        """Empty YAML returns empty allowlist."""
        al = parse_allowlist_yaml(b"")
        assert al.domains == ()
        assert al.url_patterns == ()

    def test_empty_dict_yaml(self) -> None:
        """YAML with empty dict returns empty allowlist."""
        al = parse_allowlist_yaml(b"{}")
        assert al.domains == ()
        assert al.url_patterns == ()

    def test_empty_lists(self) -> None:
        """YAML with empty lists returns empty allowlist."""
        yaml_data = b"domains: []\nurl_prefixes: []\n"
        al = parse_allowlist_yaml(yaml_data)
        assert al.domains == ()
        assert al.url_patterns == ()

    def test_missing_path_defaults_empty(self) -> None:
        """URL prefix without path key defaults to empty string."""
        yaml_data = b"url_prefixes:\n  - host: example.com\n"
        al = parse_allowlist_yaml(yaml_data)
        assert al.url_patterns[0].path == ""

    def test_missing_methods_defaults_empty(self) -> None:
        """URL prefix without methods key defaults to empty tuple."""
        yaml_data = b"url_prefixes:\n  - host: example.com\n    path: /api\n"
        al = parse_allowlist_yaml(yaml_data)
        assert al.url_patterns[0].methods == ()

    def test_invalid_yaml_raises(self) -> None:
        """Invalid YAML raises ValueError."""
        with pytest.raises(ValueError, match="Invalid allowlist YAML"):
            parse_allowlist_yaml(b"[invalid: yaml: {")

    def test_real_allowlist_file(self) -> None:
        """Parses the actual .airut/network-allowlist.yaml file."""
        allowlist_path = (
            Path(__file__).parent.parent / ".airut" / "network-allowlist.yaml"
        )
        data = allowlist_path.read_bytes()
        al = parse_allowlist_yaml(data)
        # Should have at least one domain and multiple url_prefixes
        assert len(al.domains) >= 1
        assert len(al.url_patterns) >= 1
        # Verify a known entry
        domain_hosts = [d.host for d in al.domains]
        assert "api.anthropic.com" in domain_hosts


class TestSerializeAllowlistJson:
    """Tests for serialize_allowlist_json()."""

    def test_round_trip(self) -> None:
        """Serialize then parse JSON gives expected structure."""
        al = Allowlist(
            domains=(
                AllowlistDomain(host="api.anthropic.com"),
                AllowlistDomain(host="*.github.com"),
            ),
            url_patterns=(
                AllowlistUrlPattern(
                    host="pypi.org", path="/simple*", methods=("GET", "HEAD")
                ),
                AllowlistUrlPattern(host="api.github.com", path="/repos/org*"),
            ),
        )
        result = serialize_allowlist_json(al)
        data = json.loads(result)

        assert data["domains"] == ["api.anthropic.com", "*.github.com"]
        assert len(data["url_prefixes"]) == 2
        assert data["url_prefixes"][0] == {
            "host": "pypi.org",
            "path": "/simple*",
            "methods": ["GET", "HEAD"],
        }
        assert data["url_prefixes"][1] == {
            "host": "api.github.com",
            "path": "/repos/org*",
            "methods": [],
        }

    def test_empty_allowlist(self) -> None:
        """Serializes empty allowlist."""
        al = Allowlist(domains=(), url_patterns=())
        result = serialize_allowlist_json(al)
        data = json.loads(result)
        assert data == {"domains": [], "url_prefixes": []}

    def test_returns_bytes(self) -> None:
        """Result is bytes, not str."""
        al = Allowlist(domains=(), url_patterns=())
        result = serialize_allowlist_json(al)
        assert isinstance(result, bytes)


class TestYamlToJsonRoundTrip:
    """Tests for YAML -> Allowlist -> JSON round-trip."""

    def test_full_round_trip(self) -> None:
        """YAML -> parse -> serialize -> JSON -> parse gives same structure."""
        yaml_data = b"""\
domains:
  - api.anthropic.com

url_prefixes:
  - host: pypi.org
    path: ""
    methods: [GET, HEAD]
  - host: api.github.com
    path: /repos/org*
"""
        al = parse_allowlist_yaml(yaml_data)
        json_bytes = serialize_allowlist_json(al)
        data = json.loads(json_bytes)

        # Verify the JSON matches what proxy_filter expects
        assert data["domains"] == ["api.anthropic.com"]
        assert len(data["url_prefixes"]) == 2
        assert data["url_prefixes"][0]["host"] == "pypi.org"
        assert data["url_prefixes"][0]["path"] == ""
        assert data["url_prefixes"][0]["methods"] == ["GET", "HEAD"]
        assert data["url_prefixes"][1]["host"] == "api.github.com"
        assert data["url_prefixes"][1]["path"] == "/repos/org*"
        assert data["url_prefixes"][1]["methods"] == []
