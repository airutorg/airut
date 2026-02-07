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

    This is a copy of the function from docker/proxy-filter.py
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


def _match_header_pattern(pattern: str, header_name: str) -> bool:
    """Match header name against pattern, case-insensitively.

    This is a copy of the function from docker/proxy-filter.py
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


class MockNetworkAllowlist:
    """Test version of NetworkAllowlist without mitmproxy dependencies.

    Implements the same _is_allowed logic as docker/proxy-filter.py.
    """

    def __init__(self) -> None:
        self.domains: list[str] = []
        self.url_prefixes: list[dict[str, str | list[str]]] = []

    def _is_allowed(self, host: str, path: str, method: str = "") -> bool:
        """Check if a host+path+method combination is allowed."""
        # Check domain entries (with wildcard support)
        # Domain entries allow all methods unconditionally
        for domain in self.domains:
            if _match_pattern(domain, host):
                return True

        # Check URL pattern entries
        for entry in self.url_prefixes:
            entry_host = str(entry.get("host", ""))
            entry_path = str(entry.get("path", ""))
            raw_methods = entry.get("methods", [])
            entry_methods: list[str] = (
                raw_methods if isinstance(raw_methods, list) else []
            )

            if _match_pattern(entry_host, host):
                # Empty path means allow all paths on this host
                if not entry_path or _match_pattern(entry_path, path):
                    # Empty methods means allow all methods
                    if not entry_methods or method.upper() in (
                        m.upper() for m in entry_methods
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
