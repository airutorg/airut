# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for proxy allowlist matching logic.

Tests the _match_pattern function and NetworkAllowlist._is_allowed logic
defined in lib/_bundled/proxy/proxy_filter.py. Since the file is a
mitmproxy addon, we test the logic by reimplementing the key functions
here to avoid mitmproxy dependencies.
"""

import fnmatch
from typing import TypedDict
from urllib.parse import unquote


def _match_pattern(pattern: str, value: str) -> bool:
    """Match value against pattern using fnmatch if wildcards present.

    This is a copy of the function from airut/_bundled/proxy/proxy_filter.py
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


def _match_host_pattern(pattern: str, hostname: str) -> bool:
    """Match hostname against pattern, case-insensitively.

    This is a copy of the function from airut/_bundled/proxy/proxy_filter.py
    for testing purposes (to avoid mitmproxy import dependencies).

    DNS hostnames are case-insensitive per RFC 4343. This function performs
    case-insensitive matching for both exact matches and fnmatch patterns.

    Args:
        pattern: Pattern to match against
            (e.g., "api.github.com", "*.github.com").
        hostname: Hostname from request (may be any case).

    Returns:
        True if hostname matches pattern case-insensitively.
    """
    pattern_lower = pattern.lower()
    hostname_lower = hostname.lower()

    if "*" in pattern_lower or "?" in pattern_lower:
        return fnmatch.fnmatch(hostname_lower, pattern_lower)
    return pattern_lower == hostname_lower


def _match_header_pattern(pattern: str, header_name: str) -> bool:
    """Match header name against pattern, case-insensitively.

    This is a copy of the function from airut/_bundled/proxy/proxy_filter.py
    for testing purposes (to avoid mitmproxy import dependencies).

    HTTP headers are case-insensitive per RFC 7230. This function performs
    case-insensitive matching for both exact matches and fnmatch patterns.

    Args:
        pattern: Pattern to match against (e.g., "Authorization", "X-*").
        header_name: Header name from request (may be any case).

    Returns:
        True if header_name matches pattern case-insensitively.
    """
    pattern_lower = pattern.lower()
    header_lower = header_name.lower()

    if "*" in pattern_lower or "?" in pattern_lower:
        return fnmatch.fnmatch(header_lower, pattern_lower)
    return pattern_lower == header_lower


class UrlPrefixEntry(TypedDict, total=False):
    """A single entry in the url_prefixes allowlist."""

    host: str
    path: str
    methods: list[str]


class MockNetworkAllowlist:
    """Test version of NetworkAllowlist without mitmproxy dependencies.

    Implements the same _is_allowed logic as proxy/proxy_filter.py.
    """

    def __init__(self) -> None:
        self.domains: list[str] = []
        self.url_prefixes: list[UrlPrefixEntry] = []

    def _is_allowed(self, host: str, path: str, method: str = "") -> bool:
        """Check if a host+path+method combination is allowed."""
        # Decode percent-encoded characters before matching to prevent
        # bypass via encoding differences between proxy and upstream.
        path = unquote(path)

        # Reject null bytes which can cause path truncation mismatches
        # between the proxy's fnmatch and C-based upstream servers.
        if "\x00" in path:
            return False

        # Reject path traversal sequences. Upstream servers normalize
        # `..` segments, so `/allowed/../../secret` would resolve to
        # `/secret` while fnmatch matches the allowed prefix.
        if "/../" in path or path.endswith("/.."):
            return False

        # Check domain entries (with wildcard support)
        # Domain entries allow all methods unconditionally
        for domain in self.domains:
            if _match_host_pattern(domain, host):
                return True

        # Check URL pattern entries
        for entry in self.url_prefixes:
            entry_host = entry.get("host", "")
            entry_path = entry.get("path", "")
            entry_methods = entry.get("methods", [])

            if _match_host_pattern(entry_host, host):
                # Empty path means allow all paths on this host
                if not entry_path or _match_pattern(entry_path, path):
                    # Empty methods means allow all methods.
                    # Empty method arg means "any method" (wildcard).
                    if (
                        not entry_methods
                        or not method
                        or method.upper() in (m.upper() for m in entry_methods)
                    ):
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


class TestMatchHostPattern:
    """Tests for _match_host_pattern (case-insensitive DNS matching)."""

    # --- Exact matching (case-insensitive) ---

    def test_exact_match_same_case(self) -> None:
        """Exact domain match with same case."""
        assert _match_host_pattern("api.github.com", "api.github.com") is True

    def test_exact_match_uppercase_hostname(self) -> None:
        """Uppercase hostname matches lowercase pattern."""
        assert _match_host_pattern("api.github.com", "API.GITHUB.COM") is True

    def test_exact_match_uppercase_pattern(self) -> None:
        """Uppercase pattern matches lowercase hostname."""
        assert _match_host_pattern("API.GITHUB.COM", "api.github.com") is True

    def test_exact_match_mixed_case(self) -> None:
        """Mixed case in both pattern and hostname."""
        assert _match_host_pattern("Api.GitHub.Com", "api.github.com") is True
        assert _match_host_pattern("api.github.com", "Api.GitHub.Com") is True

    def test_exact_match_different_domain(self) -> None:
        """Different domains don't match regardless of case."""
        assert (
            _match_host_pattern("api.github.com", "UPLOADS.GITHUB.COM") is False
        )

    # --- Wildcard * matching (case-insensitive) ---

    def test_wildcard_subdomain_case_insensitive(self) -> None:
        """*.domain matches subdomains case-insensitively."""
        assert _match_host_pattern("*.github.com", "API.GITHUB.COM") is True
        assert _match_host_pattern("*.GITHUB.COM", "api.github.com") is True
        assert _match_host_pattern("*.GitHub.Com", "Uploads.GitHub.Com") is True

    def test_wildcard_subdomain_no_apex_case_insensitive(self) -> None:
        """*.domain does NOT match apex domain regardless of case."""
        assert _match_host_pattern("*.github.com", "GITHUB.COM") is False
        assert _match_host_pattern("*.GITHUB.COM", "github.com") is False

    # --- Wildcard ? matching (case-insensitive) ---

    def test_question_mark_case_insensitive(self) -> None:
        """? matches one character case-insensitively."""
        assert _match_host_pattern("api?.github.com", "API1.GITHUB.COM") is True
        assert _match_host_pattern("API?.GITHUB.COM", "api1.github.com") is True

    # --- Edge cases ---

    def test_empty_pattern(self) -> None:
        """Empty pattern matches only empty value."""
        assert _match_host_pattern("", "") is True
        assert _match_host_pattern("", "anything") is False

    def test_asterisk_only(self) -> None:
        """Single * matches anything regardless of case."""
        assert _match_host_pattern("*", "API.GITHUB.COM") is True
        assert _match_host_pattern("*", "anything") is True


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

    def test_domain_case_insensitive(self) -> None:
        """Domain matching is case-insensitive per RFC 4343."""
        al = MockNetworkAllowlist()
        al.domains = ["api.github.com"]
        al.url_prefixes = []

        assert al._is_allowed("API.GITHUB.COM", "/any") is True
        assert al._is_allowed("Api.GitHub.Com", "/any") is True
        assert al._is_allowed("api.github.com", "/any") is True

    def test_domain_wildcard_case_insensitive(self) -> None:
        """Wildcard domain matching is case-insensitive per RFC 4343."""
        al = MockNetworkAllowlist()
        al.domains = ["*.github.com"]
        al.url_prefixes = []

        assert al._is_allowed("API.GITHUB.COM", "/any") is True
        assert al._is_allowed("Uploads.GitHub.Com", "/any") is True

    def test_url_prefix_host_case_insensitive(self) -> None:
        """URL prefix host matching is case-insensitive per RFC 4343."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "api.github.com", "path": "/graphql"}]

        assert al._is_allowed("API.GITHUB.COM", "/graphql") is True
        assert al._is_allowed("Api.GitHub.Com", "/graphql") is True

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

    def test_percent_encoded_path_decoded_before_match(self) -> None:
        """Percent-encoded paths are decoded before allowlist matching.

        Prevents bypass where encoded characters pass fnmatch but the
        upstream server decodes them differently.
        """
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "api.github.com", "path": "/repos/foo*"}]

        # %2F = '/' — decoded path is /repos/foo/bar, should match
        assert al._is_allowed("api.github.com", "/repos/foo%2Fbar") is True
        # Normal path still works
        assert al._is_allowed("api.github.com", "/repos/foo/bar") is True

    def test_percent_encoded_path_blocked_when_not_matching(self) -> None:
        """Percent-encoded paths that don't match after decoding are blocked."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "api.github.com", "path": "/repos/foo*"}]

        # %2E%2E = '..' — decoded path is /repos/../secret, should NOT match
        assert al._is_allowed("api.github.com", "/repos/%2E%2E/secret") is False

    def test_percent_encoded_hash_in_path(self) -> None:
        """Percent-encoded # (%23) is decoded before matching.

        Without decoding, %23 could pass fnmatch while the upstream
        interprets it as a fragment boundary.
        """
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "example.com", "path": "/api/*"}]

        # %23 = '#' — after decoding, path is /api/foo#bar
        assert al._is_allowed("example.com", "/api/foo%23bar") is True

    def test_double_encoded_path_not_double_decoded(self) -> None:
        """Double-encoded paths are only decoded once.

        %252F decodes to %2F (not /). This ensures we don't over-decode.
        """
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "example.com", "path": "/a/b"}]

        # %252F decodes to %2F (literal), not to /
        # So decoded path is /a%2Fb, which should NOT match /a/b
        assert al._is_allowed("example.com", "/a%252Fb") is False

    def test_percent_encoded_exact_path(self) -> None:
        """Exact path match works with percent-encoded input."""
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "example.com", "path": "/graphql"}]

        # %67 = 'g' — /graphql encoded partially
        assert al._is_allowed("example.com", "/%67raphql") is True

    def test_null_byte_in_path_blocked(self) -> None:
        """Null bytes (%00) in paths are rejected unconditionally.

        Null bytes can cause path truncation in C-based HTTP servers,
        leading to mismatches between proxy matching and upstream
        interpretation.
        """
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [{"host": "example.com", "path": "/allowed*"}]

        # %00 = null byte — should be blocked even though prefix matches
        assert al._is_allowed("example.com", "/allowed%00/../secret") is False
        # Literal null byte also blocked
        assert al._is_allowed("example.com", "/allowed\x00foo") is False

    def test_path_traversal_blocked(self) -> None:
        """Paths containing `..` segments are rejected unconditionally.

        Upstream servers normalize `..` segments, so a path like
        `/repos/org/repo/../../repos/evil/private` resolves to
        `/repos/evil/private` while fnmatch would match the allowed prefix.
        """
        al = MockNetworkAllowlist()
        al.domains = []
        al.url_prefixes = [
            {"host": "api.github.com", "path": "/repos/myorg/myrepo*"}
        ]

        # Direct traversal — fnmatch would match the wildcard prefix
        assert (
            al._is_allowed(
                "api.github.com",
                "/repos/myorg/myrepo/../../repos/evil/private",
            )
            is False
        )
        # Percent-encoded traversal (unquote runs first)
        assert (
            al._is_allowed(
                "api.github.com",
                "/repos/myorg/myrepo/%2e%2e/%2e%2e/repos/evil/private",
            )
            is False
        )
        # Traversal at end of path
        assert (
            al._is_allowed("api.github.com", "/repos/myorg/myrepo/..") is False
        )
        # Normal allowed path still works
        assert (
            al._is_allowed("api.github.com", "/repos/myorg/myrepo/pulls")
            is True
        )
        # Path segment starting with '..' is NOT traversal
        assert (
            al._is_allowed(
                "api.github.com",
                "/repos/myorg/myrepo/..hidden",
            )
            is True
        )


class TestMethodFiltering:
    """Tests for HTTP method filtering in url_prefixes."""

    def test_no_methods_allows_all(self) -> None:
        """Entry without methods field allows all HTTP methods."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [{"host": "api.github.com", "path": "/graphql"}]

        assert al._is_allowed("api.github.com", "/graphql", "GET") is True
        assert al._is_allowed("api.github.com", "/graphql", "POST") is True
        assert al._is_allowed("api.github.com", "/graphql", "DELETE") is True

    def test_empty_methods_allows_all(self) -> None:
        """Entry with empty methods list allows all HTTP methods."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {"host": "api.github.com", "path": "/graphql", "methods": []}
        ]

        assert al._is_allowed("api.github.com", "/graphql", "GET") is True
        assert al._is_allowed("api.github.com", "/graphql", "POST") is True

    def test_specific_methods_allowed(self) -> None:
        """Only listed methods are allowed."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {
                "host": "api.github.com",
                "path": "/graphql",
                "methods": ["POST"],
            }
        ]

        assert al._is_allowed("api.github.com", "/graphql", "POST") is True
        assert al._is_allowed("api.github.com", "/graphql", "GET") is False
        assert al._is_allowed("api.github.com", "/graphql", "DELETE") is False

    def test_multiple_methods(self) -> None:
        """Multiple methods can be listed."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {
                "host": "pypi.org",
                "path": "/simple*",
                "methods": ["GET", "HEAD"],
            }
        ]

        assert al._is_allowed("pypi.org", "/simple/foo", "GET") is True
        assert al._is_allowed("pypi.org", "/simple/foo", "HEAD") is True
        assert al._is_allowed("pypi.org", "/simple/foo", "POST") is False

    def test_method_case_insensitive(self) -> None:
        """Method comparison is case-insensitive."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {
                "host": "api.example.com",
                "path": "/data",
                "methods": ["GET", "POST"],
            }
        ]

        assert al._is_allowed("api.example.com", "/data", "get") is True
        assert al._is_allowed("api.example.com", "/data", "Get") is True
        assert al._is_allowed("api.example.com", "/data", "post") is True
        assert al._is_allowed("api.example.com", "/data", "Post") is True
        assert al._is_allowed("api.example.com", "/data", "delete") is False

    def test_domain_entries_ignore_methods(self) -> None:
        """Domain entries always allow all methods (no method filtering)."""
        al = MockNetworkAllowlist()
        al.domains = ["api.anthropic.com"]

        assert al._is_allowed("api.anthropic.com", "/v1", "GET") is True
        assert al._is_allowed("api.anthropic.com", "/v1", "POST") is True
        assert al._is_allowed("api.anthropic.com", "/v1", "DELETE") is True
        assert al._is_allowed("api.anthropic.com", "/v1", "PATCH") is True

    def test_method_filtering_combined_with_path(self) -> None:
        """Method filtering works alongside path filtering."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {
                "host": "api.github.com",
                "path": "/repos/org/repo*",
                "methods": ["GET"],
            }
        ]

        # Correct host, path, and method
        assert (
            al._is_allowed("api.github.com", "/repos/org/repo", "GET") is True
        )
        # Correct host and path, wrong method
        assert (
            al._is_allowed("api.github.com", "/repos/org/repo", "POST") is False
        )
        # Correct host and method, wrong path
        assert al._is_allowed("api.github.com", "/other", "GET") is False

    def test_multiple_entries_different_methods(self) -> None:
        """Different entries can allow different methods for same host/path."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {
                "host": "api.github.com",
                "path": "/graphql",
                "methods": ["POST"],
            },
            {
                "host": "api.github.com",
                "path": "/repos/org*",
                "methods": ["GET", "HEAD"],
            },
        ]

        # GraphQL: POST only
        assert al._is_allowed("api.github.com", "/graphql", "POST") is True
        assert al._is_allowed("api.github.com", "/graphql", "GET") is False
        # Repos: GET/HEAD only
        assert al._is_allowed("api.github.com", "/repos/org/foo", "GET") is True
        assert (
            al._is_allowed("api.github.com", "/repos/org/foo", "HEAD") is True
        )
        assert (
            al._is_allowed("api.github.com", "/repos/org/foo", "POST") is False
        )

    def test_entry_without_methods_alongside_restricted(self) -> None:
        """Unrestricted entry coexists with method-restricted entries."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {
                "host": "api.github.com",
                "path": "/graphql",
                "methods": ["POST"],
            },
            {
                "host": "api.github.com",
                "path": "/repos*",
            },
        ]

        # GraphQL: POST only
        assert al._is_allowed("api.github.com", "/graphql", "POST") is True
        assert al._is_allowed("api.github.com", "/graphql", "GET") is False
        # Repos: all methods (no methods field)
        assert al._is_allowed("api.github.com", "/repos/foo", "GET") is True
        assert al._is_allowed("api.github.com", "/repos/foo", "POST") is True
        assert al._is_allowed("api.github.com", "/repos/foo", "DELETE") is True

    def test_empty_method_string_allowed_when_no_filter(self) -> None:
        """Empty method string is allowed when no methods filter."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [{"host": "example.com", "path": "/api"}]

        assert al._is_allowed("example.com", "/api", "") is True

    def test_methods_with_lowercase_config(self) -> None:
        """Methods in config can be lowercase and still match."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {
                "host": "api.example.com",
                "path": "/data",
                "methods": ["get", "post"],
            }
        ]

        assert al._is_allowed("api.example.com", "/data", "GET") is True
        assert al._is_allowed("api.example.com", "/data", "POST") is True
        assert al._is_allowed("api.example.com", "/data", "DELETE") is False


class TestWildcardHostMethodFiltering:
    """Tests for wildcard host (*) with method filtering.

    Verifies that ``host: "*"`` can be used with method restrictions to
    allow read-only access (GET/HEAD) to all domains while restricting
    write methods (POST, PUT, DELETE) to specific hosts.  This is useful
    when the sandbox is used primarily for credential masking and the
    repository contains only public material.
    """

    def test_wildcard_host_allows_listed_methods(self) -> None:
        """Wildcard host with methods allows only listed methods."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {"host": "*", "path": "", "methods": ["GET", "HEAD"]},
        ]

        assert al._is_allowed("any-domain.com", "/any/path", "GET") is True
        assert al._is_allowed("any-domain.com", "/any/path", "HEAD") is True
        assert al._is_allowed("example.org", "/foo", "GET") is True

    def test_wildcard_host_blocks_unlisted_methods(self) -> None:
        """Wildcard host with methods blocks methods not in the list."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {"host": "*", "path": "", "methods": ["GET", "HEAD"]},
        ]

        assert al._is_allowed("any-domain.com", "/any/path", "POST") is False
        assert al._is_allowed("example.org", "/foo", "PUT") is False
        assert al._is_allowed("evil.com", "/exfil", "DELETE") is False

    def test_wildcard_host_with_specific_host_override(self) -> None:
        """Specific host entry allows methods beyond the wildcard default.

        When ``host: "*"`` restricts to GET/HEAD, a more specific entry
        can grant additional methods for select hosts.  The proxy checks
        entries sequentially: if the wildcard rejects the method, the
        next matching entry can still allow it.
        """
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {"host": "*", "path": "", "methods": ["GET", "HEAD"]},
            {
                "host": "api.anthropic.com",
                "path": "/v1/messages*",
                "methods": ["POST"],
            },
            {
                "host": "api.github.com",
                "path": "/graphql",
                "methods": ["POST"],
            },
        ]

        # GET/HEAD allowed everywhere
        assert al._is_allowed("random-site.com", "/page", "GET") is True
        assert al._is_allowed("api.anthropic.com", "/v1/models", "GET") is True
        assert al._is_allowed("api.github.com", "/users", "HEAD") is True

        # POST allowed only for specific host+path entries
        assert (
            al._is_allowed("api.anthropic.com", "/v1/messages", "POST") is True
        )
        assert al._is_allowed("api.github.com", "/graphql", "POST") is True

        # POST blocked for hosts/paths without specific entries
        assert al._is_allowed("random-site.com", "/page", "POST") is False
        assert al._is_allowed("evil.com", "/exfil", "POST") is False

    def test_wildcard_host_with_domain_entry_override(self) -> None:
        """Domain entries take precedence and allow all methods.

        Domains are checked before url_prefixes.  A domain entry allows
        all methods unconditionally, overriding the wildcard restriction.
        """
        al = MockNetworkAllowlist()
        al.domains = ["trusted.internal.com"]
        al.url_prefixes = [
            {"host": "*", "path": "", "methods": ["GET", "HEAD"]},
        ]

        # Domain entry: all methods allowed
        assert al._is_allowed("trusted.internal.com", "/api", "POST") is True
        assert al._is_allowed("trusted.internal.com", "/api", "DELETE") is True

        # Non-domain hosts: only GET/HEAD via wildcard
        assert al._is_allowed("other.com", "/api", "GET") is True
        assert al._is_allowed("other.com", "/api", "POST") is False

    def test_wildcard_host_with_path_restriction(self) -> None:
        """Wildcard host can be combined with path patterns."""
        al = MockNetworkAllowlist()
        al.url_prefixes = [
            {"host": "*", "path": "/public*", "methods": ["GET", "HEAD"]},
        ]

        # Matching path: allowed
        assert al._is_allowed("any-site.com", "/public/data", "GET") is True
        # Non-matching path: blocked
        assert al._is_allowed("any-site.com", "/private/data", "GET") is False


class TestMatchHeaderPattern:
    """Tests for _match_header_pattern function (case-insensitive matching)."""

    # --- Exact matching (case-insensitive) ---

    def test_exact_match_same_case(self) -> None:
        """Exact match with same case."""
        assert _match_header_pattern("Authorization", "Authorization") is True

    def test_exact_match_lowercase_pattern(self) -> None:
        """Pattern lowercase, header mixed case."""
        assert _match_header_pattern("authorization", "Authorization") is True

    def test_exact_match_uppercase_pattern(self) -> None:
        """Pattern uppercase, header mixed case."""
        assert _match_header_pattern("AUTHORIZATION", "Authorization") is True

    def test_exact_match_lowercase_header(self) -> None:
        """Pattern mixed case, header lowercase."""
        assert _match_header_pattern("Authorization", "authorization") is True

    def test_exact_match_uppercase_header(self) -> None:
        """Pattern mixed case, header uppercase."""
        assert _match_header_pattern("Authorization", "AUTHORIZATION") is True

    def test_exact_match_different_header(self) -> None:
        """Different headers don't match."""
        assert _match_header_pattern("Authorization", "Content-Type") is False

    def test_x_header_case_variations(self) -> None:
        """X-Api-Key style headers with various cases."""
        assert _match_header_pattern("X-Api-Key", "x-api-key") is True
        assert _match_header_pattern("x-api-key", "X-Api-Key") is True
        assert _match_header_pattern("X-API-KEY", "x-api-key") is True

    # --- Wildcard * matching (case-insensitive) ---

    def test_wildcard_star_matches_all(self) -> None:
        """Single * matches any header."""
        assert _match_header_pattern("*", "Authorization") is True
        assert _match_header_pattern("*", "authorization") is True
        assert _match_header_pattern("*", "AUTHORIZATION") is True
        assert _match_header_pattern("*", "Content-Type") is True
        assert _match_header_pattern("*", "x-custom-header") is True

    def test_wildcard_prefix_case_insensitive(self) -> None:
        """X-* pattern matches X- headers case-insensitively."""
        assert _match_header_pattern("X-*", "X-Api-Key") is True
        assert _match_header_pattern("X-*", "x-api-key") is True
        assert _match_header_pattern("X-*", "X-Custom") is True
        assert _match_header_pattern("x-*", "X-Api-Key") is True
        assert _match_header_pattern("X-*", "Authorization") is False

    def test_wildcard_suffix(self) -> None:
        """*-Token pattern matches headers ending in -Token."""
        assert _match_header_pattern("*-Token", "Private-Token") is True
        assert _match_header_pattern("*-Token", "private-token") is True
        assert _match_header_pattern("*-token", "Private-Token") is True
        assert _match_header_pattern("*-Token", "Authorization") is False

    # --- Wildcard ? matching (case-insensitive) ---

    def test_question_mark_single_char(self) -> None:
        """? matches exactly one character, case-insensitively."""
        assert _match_header_pattern("X-?-Key", "X-A-Key") is True
        assert _match_header_pattern("X-?-Key", "x-a-key") is True
        assert _match_header_pattern("X-?-Key", "X-AB-Key") is False

    # --- Real-world header patterns ---

    def test_gitlab_private_token(self) -> None:
        """GitLab uses Private-Token header."""
        assert _match_header_pattern("Private-Token", "Private-Token") is True
        assert _match_header_pattern("Private-Token", "private-token") is True
        assert _match_header_pattern("Private-Token", "PRIVATE-TOKEN") is True

    def test_content_type_not_matched_by_auth_pattern(self) -> None:
        """Ensure unrelated headers don't match auth patterns."""
        assert _match_header_pattern("Authorization", "Content-Type") is False
        assert _match_header_pattern("X-Api-Key", "Content-Type") is False
        assert _match_header_pattern("Private-Token", "Content-Length") is False
