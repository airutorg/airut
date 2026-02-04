# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for proxy allowlist matching logic.

Tests the _match_pattern function and NetworkAllowlist._is_allowed logic
defined in docker/proxy-allowlist.py. Since the file is a mitmproxy addon,
we test the logic by reimplementing the key functions here to avoid
mitmproxy dependencies.
"""

import fnmatch


def _match_pattern(pattern: str, value: str) -> bool:
    """Match value against pattern using fnmatch if wildcards present.

    This is a copy of the function from docker/proxy-allowlist.py
    for testing purposes (to avoid mitmproxy import dependencies).

    Args:
        pattern: Pattern to match against, may contain * or ? wildcards.
        value: Value to check.

    Returns:
        True if value matches pattern.
    """
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(value, pattern)
    return pattern == value


class MockNetworkAllowlist:
    """Test version of NetworkAllowlist without mitmproxy dependencies.

    Implements the same _is_allowed logic as docker/proxy-allowlist.py.
    """

    def __init__(self) -> None:
        self.domains: list[str] = []
        self.url_prefixes: list[dict[str, str]] = []

    def _is_allowed(self, host: str, path: str) -> bool:
        """Check if a host+path combination is allowed."""
        # Check domain entries (with wildcard support)
        for domain in self.domains:
            if _match_pattern(domain, host):
                return True

        # Check URL pattern entries
        for entry in self.url_prefixes:
            entry_host = entry.get("host", "")
            entry_path = entry.get("path", "")

            if _match_pattern(entry_host, host):
                # Empty path means allow all paths on this host
                if not entry_path or _match_pattern(entry_path, path):
                    return True

        return False


class TestMatchPattern:
    """Tests for _match_pattern function."""

    # --- Exact matching (no wildcards) ---

    def test_exact_match_domain(self) -> None:
        """Exact domain match."""
        assert _match_pattern("api.github.com", "api.github.com") is True

    def test_exact_match_domain_different(self) -> None:
        """Different domains don't match exactly."""
        assert _match_pattern("api.github.com", "uploads.github.com") is False

    def test_exact_match_path(self) -> None:
        """Exact path match."""
        assert _match_pattern("/repos/foo", "/repos/foo") is True

    def test_exact_match_path_different(self) -> None:
        """Different paths don't match exactly."""
        assert _match_pattern("/repos/foo", "/repos/foo/bar") is False
        assert _match_pattern("/repos/foo", "/repos/foobar") is False

    # --- Wildcard * matching ---

    def test_wildcard_subdomain_matches(self) -> None:
        """*.domain matches subdomains."""
        assert _match_pattern("*.github.com", "api.github.com") is True
        assert _match_pattern("*.github.com", "uploads.github.com") is True
        result = _match_pattern("*.github.com", "raw.githubusercontent.com")
        assert result is False

    def test_wildcard_subdomain_does_not_match_apex(self) -> None:
        """*.domain does NOT match the apex domain itself."""
        assert _match_pattern("*.github.com", "github.com") is False

    def test_wildcard_path_suffix(self) -> None:
        """/path/* matches subpaths but not exact path."""
        assert _match_pattern("/repos/foo/*", "/repos/foo/bar") is True
        assert _match_pattern("/repos/foo/*", "/repos/foo/bar/baz") is True
        # Does NOT match the path without trailing component
        assert _match_pattern("/repos/foo/*", "/repos/foo") is False
        assert _match_pattern("/repos/foo/*", "/repos/foo/") is True

    def test_wildcard_path_prefix(self) -> None:
        """/path* matches path and any continuation."""
        assert _match_pattern("/repos/foo*", "/repos/foo") is True
        assert _match_pattern("/repos/foo*", "/repos/foobar") is True
        assert _match_pattern("/repos/foo*", "/repos/foo/bar") is True
        # Does NOT match shorter
        assert _match_pattern("/repos/foo*", "/repos/fo") is False

    def test_wildcard_middle(self) -> None:
        """Wildcard in middle of pattern."""
        assert _match_pattern("/api/*/data", "/api/v1/data") is True
        assert _match_pattern("/api/*/data", "/api/v2/data") is True
        assert _match_pattern("/api/*/data", "/api/v1/other") is False

    # --- Wildcard ? matching ---

    def test_question_mark_single_char(self) -> None:
        """? matches exactly one character."""
        assert _match_pattern("api?.github.com", "api1.github.com") is True
        assert _match_pattern("api?.github.com", "api.github.com") is False
        assert _match_pattern("api?.github.com", "api12.github.com") is False

    def test_question_mark_in_path(self) -> None:
        """? in paths."""
        assert _match_pattern("/v?/api", "/v1/api") is True
        assert _match_pattern("/v?/api", "/v2/api") is True
        assert _match_pattern("/v?/api", "/v10/api") is False

    # --- Edge cases ---

    def test_empty_pattern(self) -> None:
        """Empty pattern matches only empty value."""
        assert _match_pattern("", "") is True
        assert _match_pattern("", "anything") is False

    def test_asterisk_only(self) -> None:
        """Single * matches anything."""
        assert _match_pattern("*", "") is True
        assert _match_pattern("*", "anything") is True
        assert _match_pattern("*", "foo/bar/baz") is True


class TestNetworkAllowlistIsAllowed:
    """Tests for NetworkAllowlist._is_allowed method."""

    def test_domain_exact_match_allows_any_path(self) -> None:
        """Domain entry allows any path on that host."""
        al = MockNetworkAllowlist()
        al.domains = ["api.anthropic.com"]
        al.url_prefixes = []

        assert al._is_allowed("api.anthropic.com", "/v1/messages") is True
        assert al._is_allowed("api.anthropic.com", "/any/path/here") is True
        assert al._is_allowed("api.anthropic.com", "/") is True
        assert al._is_allowed("other.anthropic.com", "/v1/messages") is False

    def test_domain_wildcard_match(self) -> None:
        """Domain with wildcard matches subdomains."""
        al = MockNetworkAllowlist()
        al.domains = ["*.github.com"]
        al.url_prefixes = []

        assert al._is_allowed("api.github.com", "/any") is True
        assert al._is_allowed("uploads.github.com", "/any") is True
        assert al._is_allowed("github.com", "/any") is False

    def test_url_prefix_exact_host_and_path(self) -> None:
        """URL prefix with exact host and path."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "api.github.com", "path": "/graphql"}]

        assert al._is_allowed("api.github.com", "/graphql") is True
        assert al._is_allowed("api.github.com", "/graphql/") is False
        assert al._is_allowed("api.github.com", "/graphql/query") is False
        assert al._is_allowed("api.github.com", "/repos") is False

    def test_url_prefix_with_wildcard_path(self) -> None:
        """URL prefix with wildcard in path."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "api.github.com", "path": "/repos/foo*"}]

        assert al._is_allowed("api.github.com", "/repos/foo") is True
        assert al._is_allowed("api.github.com", "/repos/foobar") is True
        assert al._is_allowed("api.github.com", "/repos/foo/bar") is True
        assert al._is_allowed("api.github.com", "/repos/fo") is False
        assert al._is_allowed("api.github.com", "/other") is False

    def test_url_prefix_with_wildcard_host(self) -> None:
        """URL prefix with wildcard in host."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "*.github.com", "path": "/repos/foo*"}]

        assert al._is_allowed("api.github.com", "/repos/foo") is True
        assert al._is_allowed("uploads.github.com", "/repos/foo/bar") is True
        assert al._is_allowed("github.com", "/repos/foo") is False

    def test_url_prefix_empty_path_allows_all(self) -> None:
        """URL prefix with empty path allows all paths on that host."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "storage.example.com", "path": ""}]

        assert al._is_allowed("storage.example.com", "/any/path") is True
        assert al._is_allowed("storage.example.com", "/") is True
        assert al._is_allowed("storage.example.com", "") is True
        assert al._is_allowed("other.example.com", "/any") is False

    def test_url_prefix_no_path_key_allows_all(self) -> None:
        """URL prefix without path key allows all paths on that host."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "storage.example.com"}]

        assert al._is_allowed("storage.example.com", "/any/path") is True

    def test_multiple_entries(self) -> None:
        """Multiple entries - any match allows."""
        al = MockNetworkAllowlist()
        al.domains = ["pypi.org"]
        al.url_prefixes = [
            {"host": "api.github.com", "path": "/repos/foo*"},
            {"host": "api.github.com", "path": "/graphql"},
        ]

        assert al._is_allowed("pypi.org", "/any") is True
        assert al._is_allowed("api.github.com", "/repos/foo") is True
        assert al._is_allowed("api.github.com", "/graphql") is True
        assert al._is_allowed("api.github.com", "/other") is False
        assert al._is_allowed("other.com", "/") is False

    def test_no_entries_blocks_all(self) -> None:
        """Empty allowlist blocks everything."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = []

        assert al._is_allowed("any.host.com", "/any/path") is False
