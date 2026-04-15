# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the proxy filter mitmproxy addon.

Tests the actual ``airut/_bundled/proxy/proxy_filter.py`` module with
mitmproxy mocked out via ``conftest.py``.  This gives proper coverage
measurement unlike the ``test_proxy_allowlist.py`` tests which exercise
reimplemented copies.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from mitmproxy.http import (  # ty:ignore[unresolved-import]
    MockError,
    MockHTTPFlow,
    MockRequest,
    MockResponse,
)
from tests.proxy.vectors import (
    REAL_ACCESS_KEY_ID,
    SIGNING_REPLACEMENT,
    SIGV4_AUTH,
    SIGV4A_AUTH,
    SIGV4A_BEDROCK_AUTH,
    SURROGATE_ACCESS_KEY_ID,
)

from airut._bundled.proxy.proxy_filter import (
    ProxyFilter,
    _decode_basic_auth,
    _encode_basic_auth,
    _match_header_pattern,
    _match_pattern,
)


# ---------------------------------------------------------------------------
# Helper to build flows
# ---------------------------------------------------------------------------


def _flow(
    *,
    method: str = "GET",
    host: str = "example.com",
    url_host: str | None = None,
    path: str = "/",
    url: str | None = None,
    headers: dict[str, str] | None = None,
    content: bytes = b"",
    response_code: int | None = None,
    response_content: bytes = b"",
    error_msg: str | None = None,
) -> MockHTTPFlow:
    """Build a MockHTTPFlow for testing."""
    if url is None:
        url = f"https://{host}{path}"
    req = MockRequest(
        method=method,
        url=url,
        host=host,
        url_host=url_host,
        path=path,
        headers=headers,
        content=content,
    )
    resp = (
        MockResponse(response_code, content=response_content)
        if response_code is not None
        else None
    )
    err = MockError(error_msg) if error_msg is not None else None
    return MockHTTPFlow(request=req, response=resp, error=err)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


class TestMatchPattern:
    """Tests for _match_pattern (actual function, not a copy)."""

    def test_exact_match(self) -> None:
        assert _match_pattern("api.github.com", "api.github.com") is True

    def test_exact_no_match(self) -> None:
        assert _match_pattern("api.github.com", "other.com") is False

    def test_wildcard_star(self) -> None:
        assert _match_pattern("*.github.com", "api.github.com") is True
        assert _match_pattern("*.github.com", "github.com") is False

    def test_wildcard_question(self) -> None:
        assert _match_pattern("api?.com", "api1.com") is True
        assert _match_pattern("api?.com", "api12.com") is False


class TestMatchHeaderPattern:
    """Tests for _match_header_pattern (case-insensitive)."""

    def test_case_insensitive_exact(self) -> None:
        assert _match_header_pattern("Authorization", "authorization") is True
        assert _match_header_pattern("AUTHORIZATION", "Authorization") is True

    def test_case_insensitive_wildcard(self) -> None:
        assert _match_header_pattern("X-*", "x-api-key") is True
        assert _match_header_pattern("X-*", "Authorization") is False

    def test_no_match(self) -> None:
        assert _match_header_pattern("Authorization", "Content-Type") is False


class TestDecodeBasicAuth:
    """Tests for _decode_basic_auth."""

    def test_valid_basic_auth(self) -> None:
        import base64

        encoded = base64.b64encode(b"user:pass").decode()
        result = _decode_basic_auth(f"Basic {encoded}")
        assert result == ("user", "pass")

    def test_not_basic_prefix(self) -> None:
        assert _decode_basic_auth("Bearer token") is None

    def test_invalid_base64(self) -> None:
        assert _decode_basic_auth("Basic not-valid!!!") is None

    def test_no_colon(self) -> None:
        import base64

        encoded = base64.b64encode(b"nocolon").decode()
        assert _decode_basic_auth(f"Basic {encoded}") is None


class TestEncodeBasicAuth:
    """Tests for _encode_basic_auth."""

    def test_roundtrip(self) -> None:
        result = _encode_basic_auth("user", "pass")
        assert result.startswith("Basic ")
        decoded = _decode_basic_auth(result)
        assert decoded == ("user", "pass")


# ---------------------------------------------------------------------------
# ProxyFilter initialization and loading
# ---------------------------------------------------------------------------


class TestProxyFilterInit:
    """Tests for ProxyFilter.__init__."""

    def test_defaults(self) -> None:
        pf = ProxyFilter()
        assert pf.domains == []
        assert pf.url_prefixes == []
        assert pf.replacements == {}
        assert pf._log_file is None


class TestProxyFilterLoad:
    """Tests for ProxyFilter.load() and sub-methods."""

    def test_load_calls_all_setup(self) -> None:
        """load() calls all setup helpers."""
        pf = ProxyFilter()
        with (
            patch.object(pf, "_setup_file_logging") as mock_log,
            patch.object(pf, "_load_allowlist") as mock_allow,
            patch.object(pf, "_load_replacements") as mock_repl,
        ):
            pf.load(None)
            mock_log.assert_called_once()
            mock_allow.assert_called_once()
            mock_repl.assert_called_once()

    def test_setup_file_logging_creates_log(self, tmp_path: Path) -> None:
        """Opens log file and writes header when path exists."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.touch()
        pf = ProxyFilter()
        with patch(
            "airut._bundled.proxy.proxy_filter.NETWORK_LOG_PATH", log_path
        ):
            pf._setup_file_logging()
        assert pf._log_file is not None
        pf._log_file.close()
        content = log_path.read_text()
        assert "=== TASK START" in content

    def test_setup_file_logging_no_path(self, tmp_path: Path) -> None:
        """No log file when path doesn't exist."""
        pf = ProxyFilter()
        with patch(
            "airut._bundled.proxy.proxy_filter.NETWORK_LOG_PATH",
            tmp_path / "nonexistent.log",
        ):
            pf._setup_file_logging()
        assert pf._log_file is None

    def test_setup_file_logging_oserror(self, tmp_path: Path) -> None:
        """Handles OSError when opening log file."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.touch()
        pf = ProxyFilter()
        with (
            patch(
                "airut._bundled.proxy.proxy_filter.NETWORK_LOG_PATH", log_path
            ),
            patch("builtins.open", side_effect=OSError("denied")),
        ):
            pf._setup_file_logging()
        assert pf._log_file is None

    def test_load_allowlist_from_file(self, tmp_path: Path) -> None:
        """Loads domains and url_prefixes from JSON."""
        config_path = tmp_path / "network-allowlist.json"
        config_path.write_text(
            json.dumps(
                {
                    "domains": ["api.github.com"],
                    "url_prefixes": [
                        {"host": "pypi.org", "path": "/simple*", "methods": []}
                    ],
                }
            )
        )
        pf = ProxyFilter()
        with patch(
            "airut._bundled.proxy.proxy_filter.Path", return_value=config_path
        ):
            pf._load_allowlist()
        assert "api.github.com" in pf.domains
        assert len(pf.url_prefixes) == 1

    def test_load_allowlist_missing_file(self) -> None:
        """Missing allowlist file leaves empty lists."""
        pf = ProxyFilter()
        with patch.object(Path, "exists", return_value=False):
            pf._load_allowlist()
        assert pf.domains == []

    def test_load_allowlist_invalid_json(self, tmp_path: Path) -> None:
        """Invalid JSON leaves empty lists."""
        config_path = tmp_path / "network-allowlist.json"
        config_path.write_text("not valid json{{{")
        pf = ProxyFilter()
        with patch(
            "airut._bundled.proxy.proxy_filter.Path", return_value=config_path
        ):
            pf._load_allowlist()
        assert pf.domains == []
        assert pf.url_prefixes == []

    def test_load_replacements_from_file(self, tmp_path: Path) -> None:
        """Loads replacement map from JSON."""
        repl_path = tmp_path / "replacements.json"
        repl_data = {
            "ghp_surr": {
                "value": "ghp_real",
                "scopes": ["api.github.com"],
                "headers": ["Authorization"],
            }
        }
        repl_path.write_text(json.dumps(repl_data))
        pf = ProxyFilter()
        with patch(
            "airut._bundled.proxy.proxy_filter.REPLACEMENTS_PATH", repl_path
        ):
            pf._load_replacements()
        assert "ghp_surr" in pf.replacements

    def test_load_replacements_missing_file(self, tmp_path: Path) -> None:
        """Missing file leaves empty replacements."""
        pf = ProxyFilter()
        with patch(
            "airut._bundled.proxy.proxy_filter.REPLACEMENTS_PATH",
            tmp_path / "nonexistent.json",
        ):
            pf._load_replacements()
        assert pf.replacements == {}

    def test_load_replacements_invalid_json(self, tmp_path: Path) -> None:
        """Invalid JSON leaves empty replacements."""
        repl_path = tmp_path / "replacements.json"
        repl_path.write_text("not json!")
        pf = ProxyFilter()
        with patch(
            "airut._bundled.proxy.proxy_filter.REPLACEMENTS_PATH", repl_path
        ):
            pf._load_replacements()
        assert pf.replacements == {}


# ---------------------------------------------------------------------------
# ProxyFilter._log
# ---------------------------------------------------------------------------


class TestProxyFilterLog:
    """Tests for ProxyFilter._log and _log_loud."""

    def test_log_writes_to_file_only(self, tmp_path: Path) -> None:
        """_log writes to file but not to mitmproxy/stdout."""
        log_path = tmp_path / "test.log"
        pf = ProxyFilter()
        pf._log_file = open(log_path, "w")
        try:
            pf._log("test message")
        finally:
            pf._log_file.close()
        assert "test message" in log_path.read_text()

    def test_log_without_file(self) -> None:
        """_log is a no-op when no file."""
        pf = ProxyFilter()
        pf._log("test")  # Should not raise

    def test_log_file_oserror(self) -> None:
        """Handles OSError on file write gracefully."""
        pf = ProxyFilter()
        pf._log_file = MagicMock()
        pf._log_file.write.side_effect = OSError("disk full")
        pf._log("test")  # Should not raise

    def test_log_loud_writes_to_ctx_and_file(self, tmp_path: Path) -> None:
        """_log_loud writes to both mitmproxy (stdout) and file."""
        log_path = tmp_path / "test.log"
        pf = ProxyFilter()
        pf._log_file = open(log_path, "w")
        try:
            pf._log_loud("denied message")
        finally:
            pf._log_file.close()
        assert "denied message" in log_path.read_text()

    def test_log_loud_without_file(self) -> None:
        """_log_loud logs to ctx.log even when no file."""
        pf = ProxyFilter()
        pf._log_loud("test")  # Should not raise


# ---------------------------------------------------------------------------
# ProxyFilter._is_allowed
# ---------------------------------------------------------------------------


class TestProxyFilterIsAllowed:
    """Tests for ProxyFilter._is_allowed."""

    def test_domain_match(self) -> None:
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        assert pf._is_allowed("api.github.com", "/any") is True
        assert pf._is_allowed("other.com", "/any") is False

    def test_domain_wildcard(self) -> None:
        pf = ProxyFilter()
        pf.domains = ["*.github.com"]
        assert pf._is_allowed("api.github.com", "/") is True
        assert pf._is_allowed("github.com", "/") is False

    def test_url_prefix_host_and_path(self) -> None:
        pf = ProxyFilter()
        pf.url_prefixes = [{"host": "api.github.com", "path": "/graphql"}]
        assert pf._is_allowed("api.github.com", "/graphql") is True
        assert pf._is_allowed("api.github.com", "/other") is False

    def test_url_prefix_empty_path(self) -> None:
        pf = ProxyFilter()
        pf.url_prefixes = [{"host": "api.github.com", "path": ""}]
        assert pf._is_allowed("api.github.com", "/any/path") is True

    def test_url_prefix_method_filter(self) -> None:
        pf = ProxyFilter()
        pf.url_prefixes = [
            {"host": "api.github.com", "path": "/api", "methods": ["GET"]}
        ]
        assert pf._is_allowed("api.github.com", "/api", "GET") is True
        assert pf._is_allowed("api.github.com", "/api", "POST") is False

    def test_url_prefix_empty_methods_allows_all(self) -> None:
        pf = ProxyFilter()
        pf.url_prefixes = [
            {"host": "api.github.com", "path": "/api", "methods": []}
        ]
        assert pf._is_allowed("api.github.com", "/api", "POST") is True

    def test_nothing_allowed(self) -> None:
        pf = ProxyFilter()
        assert pf._is_allowed("any.com", "/") is False


# ---------------------------------------------------------------------------
# ProxyFilter._replace_in_header
# ---------------------------------------------------------------------------


class TestReplaceInHeader:
    """Tests for ProxyFilter._replace_in_header."""

    def test_direct_replacement(self) -> None:
        pf = ProxyFilter()
        new_val, replaced = pf._replace_in_header(
            "Authorization", "Bearer surr123", "surr123", "real456"
        )
        assert replaced is True
        assert new_val == "Bearer real456"

    def test_no_match(self) -> None:
        pf = ProxyFilter()
        new_val, replaced = pf._replace_in_header(
            "Authorization", "Bearer other", "surr123", "real456"
        )
        assert replaced is False
        assert new_val == "Bearer other"

    def test_basic_auth_password_replacement(self) -> None:
        pf = ProxyFilter()
        import base64

        encoded = base64.b64encode(b"user:surr123").decode()
        new_val, replaced = pf._replace_in_header(
            "Authorization", f"Basic {encoded}", "surr123", "real456"
        )
        assert replaced is True
        decoded = _decode_basic_auth(new_val)
        assert decoded == ("user", "real456")

    def test_basic_auth_username_replacement(self) -> None:
        pf = ProxyFilter()
        import base64

        encoded = base64.b64encode(b"surr123:pass").decode()
        new_val, replaced = pf._replace_in_header(
            "Authorization", f"Basic {encoded}", "surr123", "real456"
        )
        assert replaced is True
        decoded = _decode_basic_auth(new_val)
        assert decoded == ("real456", "pass")

    def test_basic_auth_no_match(self) -> None:
        pf = ProxyFilter()
        import base64

        encoded = base64.b64encode(b"user:pass").decode()
        new_val, replaced = pf._replace_in_header(
            "Authorization", f"Basic {encoded}", "surr123", "real456"
        )
        assert replaced is False

    def test_non_auth_header_no_basic_check(self) -> None:
        pf = ProxyFilter()
        new_val, replaced = pf._replace_in_header(
            "X-Custom", "some value", "surr123", "real456"
        )
        assert replaced is False


# ---------------------------------------------------------------------------
# ProxyFilter._replace_tokens
# ---------------------------------------------------------------------------


class TestReplaceTokens:
    """Tests for ProxyFilter._replace_tokens."""

    def test_no_replacements(self) -> None:
        pf = ProxyFilter()
        flow = _flow()
        assert pf._replace_tokens(flow) == (0, 0)

    def test_scope_mismatch(self) -> None:
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["other.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer surr"},
        )
        assert pf._replace_tokens(flow) == (0, 0)

    def test_header_pattern_mismatch(self) -> None:
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["X-Api-Key"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer surr"},
        )
        assert pf._replace_tokens(flow) == (0, 0)

    def test_successful_replacement(self) -> None:
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer surr"},
        )
        replaced, dropped = pf._replace_tokens(flow)
        assert replaced == 1
        assert dropped == 0
        assert flow.request.headers["Authorization"] == "Bearer real"

    def test_wildcard_scope(self) -> None:
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["*.example.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="api.example.com",
            headers={"Authorization": "Bearer surr"},
        )
        assert pf._replace_tokens(flow) == (1, 0)

    def test_wildcard_header(self) -> None:
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["*"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"X-Custom": "Bearer surr"},
        )
        assert pf._replace_tokens(flow) == (1, 0)

    def test_foreign_credential_stripped(self) -> None:
        """Header with non-surrogate value is stripped when in scope."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer attacker_key"},
        )
        replaced, dropped = pf._replace_tokens(flow)
        assert replaced == 0
        assert dropped == 1
        assert "Authorization" not in flow.request.headers

    def test_foreign_credential_allowed_with_flag(self) -> None:
        """Non-surrogate value passes with allow_foreign_credentials."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
                "allow_foreign_credentials": True,
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer attacker_key"},
        )
        pf._replace_tokens(flow)
        assert flow.request.headers["Authorization"] == "Bearer attacker_key"

    def test_foreign_credential_not_stripped_out_of_scope(self) -> None:
        """Headers are not stripped when host is out of scope."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["other.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer attacker_key"},
        )
        pf._replace_tokens(flow)
        assert flow.request.headers["Authorization"] == "Bearer attacker_key"

    def test_replaced_header_not_stripped_by_another_credential(self) -> None:
        """A header replaced by one credential is not stripped by another."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr_a": {
                "value": "real_a",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
            },
            "surr_b": {
                "value": "real_b",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
            },
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer surr_a"},
        )
        replaced, dropped = pf._replace_tokens(flow)
        assert replaced == 1
        assert dropped == 0
        assert flow.request.headers["Authorization"] == "Bearer real_a"

    def test_foreign_credential_strip_logged(self) -> None:
        """Stripping a foreign credential is logged via _log_loud."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer attacker_key"},
        )
        with patch.object(pf, "_log_loud") as mock_log:
            pf._replace_tokens(flow)
            mock_log.assert_called_once()
            assert "STRIPPED" in mock_log.call_args[0][0]
            assert "foreign credential" in mock_log.call_args[0][0]

    def test_signing_credentials_not_stripped(self) -> None:
        """AWS signing creds (aws-sigv4) skipped by _replace_tokens."""
        pf = ProxyFilter()
        pf.replacements = {
            "AKIASURROGATE": {
                "type": "aws-sigv4",
                "access_key_id": "AKIAREAL",
                "secret_access_key": "secret",
                "scopes": ["example.com"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer something"},
        )
        replaced, dropped = pf._replace_tokens(flow)
        assert replaced == 0
        assert dropped == 0
        # Header should NOT be stripped (signing creds handled elsewhere)
        assert flow.request.headers["Authorization"] == "Bearer something"

    def test_foreign_credential_default_strip(self) -> None:
        """Default behavior (no allow_foreign_credentials key) strips."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["X-Api-Key"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"X-Api-Key": "foreign_key_123"},
        )
        pf._replace_tokens(flow)
        assert "X-Api-Key" not in flow.request.headers

    def test_wildcard_header_not_stripped(self) -> None:
        """Glob patterns do not strip non-surrogate headers."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["*"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={
                "Authorization": "Bearer surr",
                "Content-Type": "application/json",
            },
        )
        replaced, dropped = pf._replace_tokens(flow)
        assert replaced == 1
        assert dropped == 0
        assert flow.request.headers["Authorization"] == "Bearer real"
        # Content-Type must NOT be stripped — wildcard means "scan
        # everywhere", not "every header is a credential".
        assert flow.request.headers["Content-Type"] == "application/json"

    def test_glob_prefix_header_not_stripped(self) -> None:
        """Glob prefix patterns (e.g., 'X-*') do not trigger stripping."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["X-*"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"X-Request-Id": "abc123"},
        )
        pf._replace_tokens(flow)
        # Should NOT be stripped — glob pattern, not exact match
        assert flow.request.headers["X-Request-Id"] == "abc123"

    def test_mixed_exact_and_glob_strips_exact_match(self) -> None:
        """Exact pattern in headers list enables stripping even with globs."""
        pf = ProxyFilter()
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["Authorization", "X-*"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={
                "Authorization": "Bearer attacker_key",
                "X-Request-Id": "abc123",
            },
        )
        pf._replace_tokens(flow)
        # Authorization matched exact pattern — should be stripped
        assert "Authorization" not in flow.request.headers
        # X-Request-Id matched glob only — should NOT be stripped
        assert flow.request.headers["X-Request-Id"] == "abc123"


# ---------------------------------------------------------------------------
# ProxyFilter.request — allowlist and token replacement
# ---------------------------------------------------------------------------


class TestProxyFilterRequest:
    """Tests for ProxyFilter.request() hook."""

    def test_blocked_request_host_path(self) -> None:
        """Blocked host/path gets 403 response with host/path message."""
        pf = ProxyFilter()
        flow = _flow(host="blocked.com", path="/api", method="GET")
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "BLOCKED"
        assert flow.response is not None

    def test_blocked_method_specific_message(self) -> None:
        """Method-blocked gives method-specific 403 message."""
        pf = ProxyFilter()
        pf.url_prefixes = [
            {"host": "api.com", "path": "/api", "methods": ["GET"]}
        ]
        # Host+path is allowed (for GET), but DELETE is not
        flow = _flow(host="api.com", path="/api", method="DELETE")
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "BLOCKED"
        # The 403 body should mention the method restriction
        body = json.loads(flow.response._content)
        assert "Method" in body["message"]

    def test_null_byte_in_path_blocked(self) -> None:
        """Paths containing null bytes (%00) are blocked unconditionally."""
        pf = ProxyFilter()
        pf.url_prefixes = [{"host": "example.com", "path": "/allowed*"}]
        flow = _flow(host="example.com", path="/allowed%00/../secret")
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "BLOCKED"

    def test_allowed_request(self) -> None:
        """Allowed request passes through."""
        pf = ProxyFilter()
        pf.domains = ["example.com"]
        flow = _flow(host="example.com")
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "ALLOWED"
        assert flow.metadata["masked_count"] == 0

    def test_allowed_with_replacement(self) -> None:
        """Allowed request with token replacement."""
        pf = ProxyFilter()
        pf.domains = ["example.com"]
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer surr"},
        )
        pf.request(flow)
        assert flow.metadata["masked_count"] == 1
        assert flow.metadata["dropped_count"] == 0

    def test_allowed_with_foreign_credential_dropped(self) -> None:
        """Allowed request with foreign credential sets dropped_count."""
        pf = ProxyFilter()
        pf.domains = ["example.com"]
        pf.replacements = {
            "surr": {
                "value": "real",
                "scopes": ["example.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _flow(
            host="example.com",
            headers={"Authorization": "Bearer attacker_key"},
        )
        pf.request(flow)
        assert flow.metadata["masked_count"] == 0
        assert flow.metadata["dropped_count"] == 1


# ---------------------------------------------------------------------------
# ProxyFilter.response — logging
# ---------------------------------------------------------------------------


class TestProxyFilterResponse:
    """Tests for ProxyFilter.response() hook."""

    def test_blocked_logged_via_log_loud(self) -> None:
        """Blocked requests are logged via _log_loud in response."""
        pf = ProxyFilter()
        flow = _flow(response_code=403)
        flow.metadata["allowlist_action"] = "BLOCKED"
        with patch.object(pf, "_log_loud") as mock_loud:
            pf.response(flow)
            mock_loud.assert_called_once()
            msg = mock_loud.call_args[0][0]
            assert msg.startswith("BLOCKED")
            assert "403" in msg

    def test_allowed_logged(self) -> None:
        """Allowed requests are logged with status code."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "ALLOWED"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            mock_log.assert_called_once()
            msg = mock_log.call_args[0][0]
            assert msg.startswith("ALLOWED")
            assert "200" in msg

    def test_masked_suffix(self) -> None:
        """Masked count is included in log."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["masked_count"] = 2
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            assert "[masked: 2]" in mock_log.call_args[0][0]

    def test_dropped_suffix(self) -> None:
        """Dropped count is included in log."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["dropped_count"] = 1
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            assert "[dropped: 1]" in mock_log.call_args[0][0]

    def test_masked_and_dropped_suffix(self) -> None:
        """Both masked and dropped counts appear in log."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["masked_count"] = 1
        flow.metadata["dropped_count"] = 2
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            log_msg = mock_log.call_args[0][0]
            assert "[masked: 1]" in log_msg
            assert "[dropped: 2]" in log_msg

    def test_no_response(self) -> None:
        """Handles flow with no response (shows ?)."""
        pf = ProxyFilter()
        flow = _flow()
        flow.metadata["allowlist_action"] = "ALLOWED"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            assert "?" in mock_log.call_args[0][0]

    def test_credential_info_suffix(self) -> None:
        """Credential info annotation appears in log line."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["credential_info"] = "github-app: cached, graphql-scoped"
        flow.metadata["masked_count"] = 1
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            msg = mock_log.call_args[0][0]
            assert "[github-app: cached, graphql-scoped]" in msg
            assert "[masked: 1]" in msg
            assert msg.startswith("ALLOWED")

    def test_blocked_with_credential_info(self) -> None:
        """BLOCKED log includes credential info annotation."""
        pf = ProxyFilter()
        flow = _flow(response_code=403)
        flow.metadata["allowlist_action"] = "BLOCKED"
        flow.metadata["credential_info"] = "github-app: R_evil"
        with patch.object(pf, "_log_loud") as mock_loud:
            pf.response(flow)
            msg = mock_loud.call_args[0][0]
            assert msg.startswith("BLOCKED")
            assert "[github-app: R_evil]" in msg
            assert "403" in msg

    def test_no_action_skips_logging(self) -> None:
        """Flows without allowlist_action are not logged."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        with (
            patch.object(pf, "_log") as mock_log,
            patch.object(pf, "_log_loud") as mock_loud,
        ):
            pf.response(flow)
            mock_log.assert_not_called()
            mock_loud.assert_not_called()

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_aws_error_body_logged_on_4xx(self) -> None:
        """AWS re-signed requests log response body on 4xx."""
        body = b'{"message":"AccessDeniedException"}'
        pf = ProxyFilter()
        flow = _flow(response_code=403, response_content=body)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["aws_resigned"] = True
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert any("aws-error-body:" in c for c in calls)
            assert any("AccessDeniedException" in c for c in calls)

    def test_aws_error_body_not_logged_without_debug(self) -> None:
        """AWS error body is not logged when DEBUG_SIGNING is off."""
        body = b'{"message":"AccessDeniedException"}'
        pf = ProxyFilter()
        flow = _flow(response_code=403, response_content=body)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["aws_resigned"] = True
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert not any("aws-error-body:" in c for c in calls)

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_aws_error_body_not_logged_on_2xx(self) -> None:
        """AWS re-signed requests don't log body on success."""
        pf = ProxyFilter()
        flow = _flow(response_code=200, response_content=b"ok")
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["aws_resigned"] = True
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert not any("aws-error-body:" in c for c in calls)

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_aws_error_body_not_logged_without_resign(self) -> None:
        """Non-AWS requests don't log error body."""
        pf = ProxyFilter()
        flow = _flow(response_code=500, response_content=b"error")
        flow.metadata["allowlist_action"] = "ALLOWED"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert not any("aws-error-body:" in c for c in calls)

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_aws_error_body_truncated(self) -> None:
        """Large error bodies are truncated to prevent log flooding."""
        body = b"X" * 8000
        pf = ProxyFilter()
        flow = _flow(response_code=403, response_content=body)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["aws_resigned"] = True
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            error_calls = [c for c in calls if "aws-error-body:" in c]
            assert len(error_calls) == 1
            assert "...(truncated)" in error_calls[0]
            # Should contain at most 4096 chars of body + prefix + suffix
            assert len(error_calls[0]) < 4300

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_aws_error_body_empty_not_logged(self) -> None:
        """Empty response body is not logged."""
        pf = ProxyFilter()
        flow = _flow(response_code=403, response_content=b"")
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["aws_resigned"] = True
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert not any("aws-error-body:" in c for c in calls)

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_aws_error_body_invalid_utf8(self) -> None:
        """Invalid UTF-8 response body is silently skipped."""
        body = b"\xff\xfe\x00\x01"  # Invalid UTF-8 bytes
        pf = ProxyFilter()
        flow = _flow(response_code=403, response_content=body)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["aws_resigned"] = True
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert not any("aws-error-body:" in c for c in calls)


# ---------------------------------------------------------------------------
# ProxyFilter.error — error logging
# ---------------------------------------------------------------------------


class TestProxyFilterError:
    """Tests for ProxyFilter.error() hook."""

    def test_no_action_not_logged(self) -> None:
        """Requests with no allowlist_action are not logged."""
        pf = ProxyFilter()
        flow = _flow(error_msg="connection failed")
        with patch.object(pf, "_log_loud") as mock_log:
            pf.error(flow)
            mock_log.assert_not_called()

    def test_allowed_error_logged(self) -> None:
        """Allowed requests' errors are logged to stdout."""
        pf = ProxyFilter()
        flow = _flow(error_msg="connection refused")
        flow.metadata["allowlist_action"] = "ALLOWED"
        with patch.object(pf, "_log_loud") as mock_log:
            pf.error(flow)
            mock_log.assert_called_once()
            assert "connection refused" in mock_log.call_args[0][0]

    def test_blocked_error_logged(self) -> None:
        """Blocked requests' errors are also logged."""
        pf = ProxyFilter()
        flow = _flow(error_msg="connection reset")
        flow.metadata["allowlist_action"] = "BLOCKED"
        with patch.object(pf, "_log_loud") as mock_log:
            pf.error(flow)
            mock_log.assert_called_once()
            assert "connection reset" in mock_log.call_args[0][0]

    def test_no_error_object(self) -> None:
        """Handles flow with no error object."""
        pf = ProxyFilter()
        flow = _flow()
        flow.error = None
        flow.metadata["allowlist_action"] = "ALLOWED"
        with patch.object(pf, "_log_loud") as mock_log:
            pf.error(flow)
            assert "unknown error" in mock_log.call_args[0][0]


# ---------------------------------------------------------------------------
# Module-level addons list
# ---------------------------------------------------------------------------


class TestAddons:
    """Tests for module-level addons list."""

    def test_addons_contains_proxy_filter(self) -> None:
        from airut._bundled.proxy.proxy_filter import addons

        assert len(addons) == 1
        assert isinstance(addons[0], ProxyFilter)


# ---------------------------------------------------------------------------
# AWS re-signing helpers
# ---------------------------------------------------------------------------


def _aws_flow(
    *,
    host: str = "mybucket.s3.amazonaws.com",
    path: str = "/key",
    method: str = "GET",
    auth: str = SIGV4_AUTH,
    content_sha256: str = "UNSIGNED-PAYLOAD",
    extra_headers: dict[str, str] | None = None,
) -> MockHTTPFlow:
    """Build a flow with AWS-style headers."""
    headers: dict[str, str] = {
        "Host": host,
        "x-amz-date": "20260101T000000Z",
        "x-amz-content-sha256": content_sha256,
    }
    if auth:
        headers["Authorization"] = auth
    if extra_headers:
        headers.update(extra_headers)
    url = f"https://{host}{path}"
    return _flow(method=method, host=host, path=path, url=url, headers=headers)


def _pf_with_signing() -> ProxyFilter:
    """Build a ProxyFilter with signing credential replacements."""
    pf = ProxyFilter()
    pf.domains = ["*.amazonaws.com", "*.r2.cloudflarestorage.com"]
    # SigningReplacement values (str | list[str]) are valid
    # _JsonValue subtypes; ty cannot prove TypedDict compat.
    pf.replacements = {  # ty:ignore[invalid-assignment]
        SURROGATE_ACCESS_KEY_ID: SIGNING_REPLACEMENT,
    }
    return pf


# ---------------------------------------------------------------------------
# ProxyFilter._try_resign_aws
# ---------------------------------------------------------------------------


class TestTryResignAws:
    """Tests for ProxyFilter._try_resign_aws."""

    def test_header_auth_resigns(self) -> None:
        """Resign via Authorization header."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        result = pf._try_resign_aws(flow)
        assert result is not None
        assert REAL_ACCESS_KEY_ID in flow.request.headers["Authorization"]

    def test_no_auth_no_presigned(self) -> None:
        """Returns None when no Authorization and no presigned URL."""
        pf = _pf_with_signing()
        flow = _aws_flow(auth="")
        # Remove Authorization header
        flow.request.headers.pop("Authorization", None)
        result = pf._try_resign_aws(flow)
        assert result is None

    def test_presigned_url_path(self) -> None:
        """Falls through to presigned URL when no Authorization header."""
        pf = _pf_with_signing()
        query = (
            "X-Amz-Algorithm=AWS4-HMAC-SHA256"
            f"&X-Amz-Credential={SURROGATE_ACCESS_KEY_ID}/20260101/us-east-1/s3/aws4_request"
            "&X-Amz-Date=20260101T000000Z"
            "&X-Amz-Expires=3600"
            "&X-Amz-SignedHeaders=host"
            "&X-Amz-Signature=oldsig"
        )
        path = f"/key?{query}"
        url = f"https://mybucket.s3.amazonaws.com{path}"
        flow = _flow(
            method="GET",
            host="mybucket.s3.amazonaws.com",
            path=path,
            url=url,
            headers={
                "Host": "mybucket.s3.amazonaws.com",
                "x-amz-date": "20260101T000000Z",
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        )
        result = pf._try_resign_aws(flow)
        assert result is not None


# ---------------------------------------------------------------------------
# ProxyFilter._resign_header_auth
# ---------------------------------------------------------------------------


class TestResignHeaderAuth:
    """Tests for ProxyFilter._resign_header_auth."""

    def test_non_aws_auth(self) -> None:
        """Returns None for non-AWS Authorization header."""
        pf = _pf_with_signing()
        flow = _aws_flow(auth="Bearer some_token")
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", "Bearer some_token"
        )
        assert result is None

    def test_unknown_key_id(self) -> None:
        """Returns None when key ID not in replacements."""
        pf = _pf_with_signing()
        auth = SIGV4_AUTH.replace(SURROGATE_ACCESS_KEY_ID, "AKIA_UNKNOWN")
        result = pf._resign_header_auth(
            _aws_flow(auth=auth),
            "mybucket.s3.amazonaws.com",
            auth,
        )
        assert result is None

    def test_scope_mismatch(self) -> None:
        """Returns None when host doesn't match scopes."""
        pf = _pf_with_signing()
        flow = _aws_flow(host="other.example.com")
        result = pf._resign_header_auth(flow, "other.example.com", SIGV4_AUTH)
        assert result is None

    def test_not_signing_type(self) -> None:
        """Returns None when replacement is not a signing credential."""
        pf = ProxyFilter()
        pf.replacements = {
            SURROGATE_ACCESS_KEY_ID: {
                "value": "real",
                "scopes": ["*.amazonaws.com"],
                "headers": ["Authorization"],
            }
        }
        flow = _aws_flow()
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
        )
        assert result is None

    def test_successful_resign(self) -> None:
        """Successfully re-signs and replaces Authorization header."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
        )
        assert result is not None
        assert REAL_ACCESS_KEY_ID in flow.request.headers["Authorization"]
        assert result.region == "us-east-1"

    def test_session_token_replacement(self) -> None:
        """Session token header is replaced on re-sign."""
        pf = _pf_with_signing()
        flow = _aws_flow(
            extra_headers={"x-amz-security-token": "surr_session_token"}
        )
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
        )
        assert result is not None
        assert (
            flow.request.headers["x-amz-security-token"]
            == "real_session_token_value"
        )

    def test_clock_skew_warning(self) -> None:
        """Logs warning when clock skew detected (to stdout)."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        # Override the x-amz-date with old timestamp
        flow.request.headers["x-amz-date"] = "20200101T000000Z"
        with patch.object(pf, "_log_loud") as mock_log:
            pf._resign_header_auth(
                flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
            )
            assert any(
                "clock skew" in str(c).lower() for c in mock_log.call_args_list
            )

    def test_resign_exception_returns_none(self) -> None:
        """Returns None when resign_request raises."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        with patch(
            "airut._bundled.proxy.proxy_filter.resign_request",
            side_effect=ValueError("boom"),
        ):
            result = pf._resign_header_auth(
                flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
            )
            assert result is None

    def test_chunked_sets_up_resigner(self) -> None:
        """Chunked streaming upload triggers resigner setup."""
        pf = _pf_with_signing()
        flow = _aws_flow(
            method="PUT",
            content_sha256="STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        )
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
        )
        assert result is not None
        assert result.is_chunked
        assert "chunked_resigner" in flow.metadata

    def test_query_string_in_path(self) -> None:
        """Path with query string is split correctly."""
        pf = _pf_with_signing()
        flow = _aws_flow(path="/key?param=val")
        flow.request.path = "/key?param=val"
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
        )
        assert result is not None

    def test_pre_encoded_bedrock_path_sigv4a(self) -> None:
        """SigV4A re-signing with pre-encoded Bedrock path.

        Cross-region Bedrock model IDs contain a colon (v1:0) which the
        SDK encodes to %3A. The signing computation double-encodes (to
        %253A) per the SigV4 spec, but flow.request.path must stay
        unchanged — only the Authorization header is rewritten.
        """
        bedrock_path = (
            "/model/eu.anthropic.claude-3-haiku-20240307-v1%3A0/invoke"
        )
        bedrock_host = "bedrock-runtime.eu-west-1.amazonaws.com"
        pf = _pf_with_signing()
        flow = _aws_flow(
            host=bedrock_host,
            path=bedrock_path,
            method="POST",
            auth=SIGV4A_BEDROCK_AUTH,
        )
        original_path = flow.request.path
        original_url = flow.request.url

        result = pf._resign_header_auth(flow, bedrock_host, SIGV4A_BEDROCK_AUTH)

        assert result is not None
        assert "AWS4-ECDSA-P256-SHA256" in flow.request.headers["Authorization"]
        assert REAL_ACCESS_KEY_ID in flow.request.headers["Authorization"]
        # Path and URL must NOT be modified during header auth re-signing
        assert flow.request.path == original_path
        assert flow.request.url == original_url
        # Wire path keeps %3A (single-encoded) — only canonical URI
        # used in signing gets double-encoded
        assert "%3A" in flow.request.path

    def test_pre_encoded_bedrock_path_sigv4(self) -> None:
        """SigV4 re-signing with pre-encoded Bedrock path.

        Regional Bedrock uses SigV4. The wire path (%3A) must be
        preserved; signing uses double-encoded canonical URI (%253A).
        """
        bedrock_path = "/model/anthropic.claude-3-haiku-20240307-v1%3A0/invoke"
        bedrock_host = "bedrock-runtime.us-east-1.amazonaws.com"
        bedrock_auth = (
            "AWS4-HMAC-SHA256 "
            f"Credential={SURROGATE_ACCESS_KEY_ID}"
            "/20260101/us-east-1/bedrock/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
            "Signature=aa00bb11cc22dd33ee44ff5500661177"
        )
        pf = _pf_with_signing()
        flow = _aws_flow(
            host=bedrock_host,
            path=bedrock_path,
            method="POST",
            auth=bedrock_auth,
        )
        original_path = flow.request.path
        original_url = flow.request.url

        result = pf._resign_header_auth(flow, bedrock_host, bedrock_auth)

        assert result is not None
        assert REAL_ACCESS_KEY_ID in flow.request.headers["Authorization"]
        # Path and URL must NOT be modified
        assert flow.request.path == original_path
        assert flow.request.url == original_url
        assert "%3A" in flow.request.path


# ---------------------------------------------------------------------------
# ProxyFilter._setup_chunked_resigner
# ---------------------------------------------------------------------------


class TestSetupChunkedResigner:
    """Tests for ProxyFilter._setup_chunked_resigner."""

    def test_sigv4_chunked(self) -> None:
        """SigV4 chunked upload creates resigner with signing_key."""
        pf = _pf_with_signing()
        flow = _aws_flow(
            method="PUT",
            content_sha256="STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        )
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
        )
        assert result is not None
        resigner = flow.metadata.get("chunked_resigner")
        assert resigner is not None
        assert not resigner._is_sigv4a

    def test_sigv4a_chunked(self) -> None:
        """SigV4A chunked upload creates resigner with ecdsa_key."""
        pf = _pf_with_signing()
        flow = _aws_flow(
            method="PUT",
            auth=SIGV4A_AUTH,
            content_sha256="STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
        )
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4A_AUTH
        )
        assert result is not None
        resigner = flow.metadata.get("chunked_resigner")
        assert resigner is not None
        assert resigner._is_sigv4a

    def test_trailer_mode(self) -> None:
        """TRAILER content-sha256 sets has_trailer on resigner."""
        pf = _pf_with_signing()
        flow = _aws_flow(
            method="PUT",
            content_sha256="STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        )
        result = pf._resign_header_auth(
            flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
        )
        assert result is not None
        resigner = flow.metadata.get("chunked_resigner")
        assert resigner is not None
        assert resigner._has_trailer


# ---------------------------------------------------------------------------
# ProxyFilter debug signing logs
# ---------------------------------------------------------------------------


class TestDebugSigningLogs:
    """Tests for DEBUG_SIGNING-gated diagnostic logging."""

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_perform_resign_logs_context(self) -> None:
        """Pre-signing context is logged when DEBUG_SIGNING is on."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        with patch.object(pf, "_log") as mock_log:
            pf._resign_header_auth(
                flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
            )
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert any("re-sign: service=s3" in c for c in calls)
            assert any("creq_hash=" in c for c in calls)
            assert any("canonical_request=" in c for c in calls)

    def test_perform_resign_no_logs_without_debug(self) -> None:
        """Signing context is not logged when DEBUG_SIGNING is off."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        with patch.object(pf, "_log") as mock_log:
            pf._resign_header_auth(
                flow, "mybucket.s3.amazonaws.com", SIGV4_AUTH
            )
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert not any("re-sign: service=" in c for c in calls)
            assert not any("creq_hash=" in c for c in calls)
            assert not any("canonical_request=" in c for c in calls)

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_deferred_resign_logs_with_debug(self) -> None:
        """Deferred signing is logged when DEBUG_SIGNING is on."""
        pf = _pf_with_signing()
        flow = _bedrock_flow_no_content_sha(body=b"")
        with patch.object(pf, "_log") as mock_log:
            pf.requestheaders(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert any("deferred" in c for c in calls)

    def test_deferred_resign_no_logs_without_debug(self) -> None:
        """Deferred signing is not logged when DEBUG_SIGNING is off."""
        pf = _pf_with_signing()
        flow = _bedrock_flow_no_content_sha(body=b"")
        with patch.object(pf, "_log") as mock_log:
            pf.requestheaders(flow)
            calls = [c[0][0] for c in mock_log.call_args_list]
            assert not any("deferred" in c for c in calls)

    @patch("airut._bundled.proxy.proxy_filter.DEBUG_SIGNING", True)
    def test_debug_log_normalizes_authority(self) -> None:
        """Debug log normalizes :authority to host in signed_headers."""
        pf = _pf_with_signing()
        bedrock_host = "bedrock-runtime.eu-central-1.amazonaws.com"
        bedrock_path = "/model/invoke"
        bedrock_auth = (
            "AWS4-HMAC-SHA256 "
            f"Credential={SURROGATE_ACCESS_KEY_ID}"
            "/20260101/eu-central-1/bedrock-runtime"
            "/aws4_request, "
            "SignedHeaders="
            ":authority;content-type;"
            "x-amz-content-sha256;x-amz-date, "
            "Signature=aa00bb11cc22dd33ee44ff5500661177"
        )
        headers: dict[str, str] = {
            "Host": bedrock_host,
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
            "x-amz-content-sha256": "abc123",
            "Authorization": bedrock_auth,
        }
        url = f"https://{bedrock_host}{bedrock_path}"
        flow = _flow(
            method="POST",
            host=bedrock_host,
            path=bedrock_path,
            url=url,
            headers=headers,
        )
        with patch.object(pf, "_log") as mock_log:
            pf._resign_header_auth(flow, bedrock_host, bedrock_auth)
            calls = [c[0][0] for c in mock_log.call_args_list]
            # :authority should be normalized to host in log
            signing_log = [c for c in calls if "signed_headers=" in c]
            assert len(signing_log) >= 1
            assert "host" in signing_log[0]
            assert ":authority" not in signing_log[0]


# ---------------------------------------------------------------------------
# ProxyFilter._resign_presigned
# ---------------------------------------------------------------------------


class TestResignPresigned:
    """Tests for ProxyFilter._resign_presigned."""

    def _presigned_flow(
        self,
        *,
        host: str = "mybucket.s3.amazonaws.com",
        key_id: str = SURROGATE_ACCESS_KEY_ID,
        with_session_token: bool = False,
    ) -> MockHTTPFlow:
        """Build a flow with presigned URL query parameters."""
        query_parts = [
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            f"X-Amz-Credential={key_id}/20260101/us-east-1/s3/aws4_request",
            "X-Amz-Date=20260101T000000Z",
            "X-Amz-Expires=3600",
            "X-Amz-SignedHeaders=host",
            "X-Amz-Signature=oldsig",
        ]
        if with_session_token:
            query_parts.append("X-Amz-Security-Token=surr_session_token")
        query = "&".join(query_parts)
        path = f"/key?{query}"
        url = f"https://{host}{path}"
        return _flow(
            method="GET",
            host=host,
            path=path,
            url=url,
            headers={"Host": host},
        )

    def test_no_presigned_params(self) -> None:
        """Returns None when no presigned URL params."""
        pf = _pf_with_signing()
        flow = _flow(host="mybucket.s3.amazonaws.com", path="/key")
        result = pf._resign_presigned(flow, "mybucket.s3.amazonaws.com")
        assert result is None

    def test_unknown_key_id(self) -> None:
        """Returns None when key ID not in replacements."""
        pf = _pf_with_signing()
        flow = self._presigned_flow(key_id="AKIA_UNKNOWN")
        result = pf._resign_presigned(flow, "mybucket.s3.amazonaws.com")
        assert result is None

    def test_scope_mismatch(self) -> None:
        """Returns None when host doesn't match scopes."""
        pf = _pf_with_signing()
        flow = self._presigned_flow(host="other.example.com")
        result = pf._resign_presigned(flow, "other.example.com")
        assert result is None

    def test_successful_resign(self) -> None:
        """Re-signs presigned URL and replaces credential/signature."""
        pf = _pf_with_signing()
        flow = self._presigned_flow()
        result = pf._resign_presigned(flow, "mybucket.s3.amazonaws.com")
        assert result is not None
        assert REAL_ACCESS_KEY_ID in flow.request.url
        assert "oldsig" not in flow.request.url
        assert result.region == "us-east-1"

    def test_session_token_replacement(self) -> None:
        """Surrogate session token in URL is replaced with real."""
        pf = _pf_with_signing()
        flow = self._presigned_flow(with_session_token=True)
        result = pf._resign_presigned(flow, "mybucket.s3.amazonaws.com")
        assert result is not None
        assert "real_session_token_value" in flow.request.url
        assert "surr_session_token" not in flow.request.url

    def test_malformed_credential(self) -> None:
        """Returns None when X-Amz-Credential has no /."""
        pf = _pf_with_signing()
        path = (
            "/key?X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=noslash"
            "&X-Amz-Date=20260101T000000Z"
            "&X-Amz-Expires=3600"
            "&X-Amz-SignedHeaders=host"
            "&X-Amz-Signature=oldsig"
        )
        url = f"https://mybucket.s3.amazonaws.com{path}"
        flow = _flow(
            method="GET",
            host="mybucket.s3.amazonaws.com",
            path=path,
            url=url,
            headers={"Host": "mybucket.s3.amazonaws.com"},
        )
        result = pf._resign_presigned(flow, "mybucket.s3.amazonaws.com")
        assert result is None

    def test_resign_exception_returns_none(self) -> None:
        """Returns None when resign_presigned_url raises."""
        pf = _pf_with_signing()
        flow = self._presigned_flow()
        with patch(
            "airut._bundled.proxy.proxy_filter.resign_presigned_url",
            side_effect=ValueError("boom"),
        ):
            result = pf._resign_presigned(flow, "mybucket.s3.amazonaws.com")
            assert result is None


# ---------------------------------------------------------------------------
# ProxyFilter.requestheaders
# ---------------------------------------------------------------------------


class TestRequestHeaders:
    """Tests for ProxyFilter.requestheaders() hook."""

    def test_blocked_returns_early(self) -> None:
        """Blocked request doesn't attempt AWS re-signing."""
        pf = ProxyFilter()  # No domains allowed
        flow = _aws_flow()
        pf.requestheaders(flow)
        assert "aws_resigned" not in flow.metadata

    def test_allowed_with_aws_resigning(self) -> None:
        """Allowed request with AWS header triggers re-signing."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        pf.requestheaders(flow)
        assert flow.metadata.get("aws_resigned") is True
        assert flow.metadata.get("masked_count") == 1

    def test_chunked_enables_streaming(self) -> None:
        """Chunked re-signed request enables streaming mode."""
        pf = _pf_with_signing()
        flow = _aws_flow(
            method="PUT",
            content_sha256="STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        )
        pf.requestheaders(flow)
        assert flow.request.stream is True

    def test_non_chunked_no_streaming(self) -> None:
        """Non-chunked re-signed request doesn't enable streaming."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        pf.requestheaders(flow)
        assert flow.request.stream is False

    def test_bedrock_sigv4a_pre_encoded_path(self) -> None:
        """Full requestheaders flow with pre-encoded Bedrock path.

        Exercises the complete re-signing path: requestheaders() ->
        _try_resign_aws() -> _resign_header_auth() -> resign_request()
        with a SigV4A Bedrock request containing %3A in the model ID.
        Wire path must be preserved even though the signing canonical
        URI double-encodes to %253A internally.
        """
        bedrock_path = (
            "/model/eu.anthropic.claude-3-haiku-20240307-v1%3A0/invoke"
        )
        bedrock_host = "bedrock-runtime.eu-west-1.amazonaws.com"
        pf = _pf_with_signing()
        flow = _aws_flow(
            host=bedrock_host,
            path=bedrock_path,
            method="POST",
            auth=SIGV4A_BEDROCK_AUTH,
        )
        original_path = flow.request.path
        original_url = flow.request.url

        pf.requestheaders(flow)

        assert flow.metadata.get("aws_resigned") is True
        assert flow.metadata.get("masked_count") == 1
        # Wire path preserved (signing double-encodes internally only)
        assert flow.request.path == original_path
        assert flow.request.url == original_url
        assert "%3A" in flow.request.path


# ---------------------------------------------------------------------------
# Deferred re-signing (non-S3: no x-amz-content-sha256 header)
# ---------------------------------------------------------------------------


def _bedrock_flow_no_content_sha(
    *,
    body: bytes = b'{"prompt": "hello"}',
) -> MockHTTPFlow:
    """Build a Bedrock flow WITHOUT x-amz-content-sha256 header.

    Non-S3 SDKs (botocore SigV4Auth) don't send this header.
    The SDK signs with sha256(body) internally but doesn't expose
    it as a header.
    """
    bedrock_host = "bedrock-runtime.eu-central-1.amazonaws.com"
    bedrock_path = "/model/anthropic.claude-3-haiku-v1/invoke"
    bedrock_auth = (
        "AWS4-HMAC-SHA256 "
        f"Credential={SURROGATE_ACCESS_KEY_ID}"
        "/20260101/eu-central-1/bedrock-runtime/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-date, "
        "Signature=aa00bb11cc22dd33ee44ff5500661177"
    )
    headers: dict[str, str] = {
        "Host": bedrock_host,
        "x-amz-date": "20260101T000000Z",
        "Content-Type": "application/json",
        "Authorization": bedrock_auth,
    }
    url = f"https://{bedrock_host}{bedrock_path}"
    return _flow(
        method="POST",
        host=bedrock_host,
        path=bedrock_path,
        url=url,
        headers=headers,
    )


class TestDeferredResigning:
    """Tests for deferred re-signing when x-amz-content-sha256 is absent."""

    def test_requestheaders_defers_without_content_sha(self) -> None:
        """requestheaders() defers signing when no content-sha header."""
        pf = _pf_with_signing()
        flow = _bedrock_flow_no_content_sha()
        pf.requestheaders(flow)

        # Should NOT be marked as resigned yet
        assert "aws_resigned" not in flow.metadata
        # Should have deferred context stored
        assert "aws_deferred_resign" in flow.metadata

    def test_request_completes_deferred_resign(self) -> None:
        """request() completes deferred re-signing with body hash."""
        pf = _pf_with_signing()
        body = b'{"prompt": "hello"}'
        flow = _bedrock_flow_no_content_sha(body=body)

        # Phase 1: requestheaders defers
        pf.requestheaders(flow)
        assert "aws_deferred_resign" in flow.metadata
        assert "aws_resigned" not in flow.metadata

        # Set body content (available in request() hook)
        flow.request.content = body

        # Phase 2: request() completes signing
        pf.request(flow)
        assert flow.metadata.get("aws_resigned") is True
        assert flow.metadata.get("masked_count") == 1
        assert REAL_ACCESS_KEY_ID in flow.request.headers["Authorization"]

    def test_deferred_resign_uses_body_hash(self) -> None:
        """Deferred re-sign uses sha256(body), not UNSIGNED-PAYLOAD."""
        import hashlib

        from airut._bundled.proxy.aws_signing import (
            build_canonical_request,
            build_sigv4_string_to_sign,
            derive_sigv4_signing_key,
            sigv4_sign,
        )

        pf = _pf_with_signing()
        body = b'{"prompt": "hello"}'
        body_hash = hashlib.sha256(body).hexdigest()
        flow = _bedrock_flow_no_content_sha(body=body)

        pf.requestheaders(flow)
        flow.request.content = body
        pf.request(flow)

        # Extract the signature the proxy computed
        auth = flow.request.headers["Authorization"]
        proxy_sig = auth.split("Signature=")[1]

        # Independently compute what the signature should be
        # using the actual body hash
        headers = {
            "Host": "bedrock-runtime.eu-central-1.amazonaws.com",
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
        }
        creq = build_canonical_request(
            method="POST",
            path="/model/anthropic.claude-3-haiku-v1/invoke",
            query="",
            headers=headers,
            signed_headers="content-type;host;x-amz-date",
            payload_hash=body_hash,
        )
        scope = "20260101/eu-central-1/bedrock-runtime/aws4_request"
        sts = build_sigv4_string_to_sign("20260101T000000Z", scope, creq)
        signing_key = derive_sigv4_signing_key(
            SIGNING_REPLACEMENT["secret_access_key"],
            "20260101",
            "eu-central-1",
            "bedrock-runtime",
        )
        expected_sig = sigv4_sign(signing_key, sts)

        assert proxy_sig == expected_sig, (
            f"Signature mismatch: proxy used wrong payload hash. "
            f"proxy_sig={proxy_sig}, expected={expected_sig}"
        )

    def test_deferred_resign_str_body(self) -> None:
        """Deferred re-sign handles str body (encodes to UTF-8)."""
        import hashlib

        pf = _pf_with_signing()
        body_str = '{"prompt": "hello"}'
        flow = _bedrock_flow_no_content_sha(body=b"")

        pf.requestheaders(flow)
        # Simulate mitmproxy providing body as str instead of bytes
        flow.request.content = body_str
        pf.request(flow)

        assert flow.metadata.get("aws_resigned") is True

        # Verify signature uses UTF-8 encoded body hash
        auth = flow.request.headers["Authorization"]
        proxy_sig = auth.split("Signature=")[1]

        from airut._bundled.proxy.aws_signing import (
            build_canonical_request,
            build_sigv4_string_to_sign,
            derive_sigv4_signing_key,
            sigv4_sign,
        )

        body_hash = hashlib.sha256(body_str.encode("utf-8")).hexdigest()
        headers = {
            "Host": "bedrock-runtime.eu-central-1.amazonaws.com",
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
        }
        creq = build_canonical_request(
            method="POST",
            path="/model/anthropic.claude-3-haiku-v1/invoke",
            query="",
            headers=headers,
            signed_headers="content-type;host;x-amz-date",
            payload_hash=body_hash,
        )
        scope = "20260101/eu-central-1/bedrock-runtime/aws4_request"
        sts = build_sigv4_string_to_sign("20260101T000000Z", scope, creq)
        signing_key = derive_sigv4_signing_key(
            SIGNING_REPLACEMENT["secret_access_key"],
            "20260101",
            "eu-central-1",
            "bedrock-runtime",
        )
        expected_sig = sigv4_sign(signing_key, sts)
        assert proxy_sig == expected_sig

    def test_s3_with_content_sha_not_deferred(self) -> None:
        """S3 requests (with x-amz-content-sha256) are not deferred."""
        pf = _pf_with_signing()
        flow = _aws_flow()  # Has x-amz-content-sha256 header
        pf.requestheaders(flow)

        # Should be immediately resigned, not deferred
        assert flow.metadata.get("aws_resigned") is True
        assert "aws_deferred_resign" not in flow.metadata

    def test_authority_pseudo_header_deferred_resign(self) -> None:
        """HTTP/2 :authority in SignedHeaders works with deferred re-sign.

        When the SDK uses HTTP/2, SignedHeaders contains :authority instead
        of host.  mitmproxy converts :authority → Host, so the headers dict
        has Host.  The proxy must normalize :authority → host when building
        the canonical request.
        """
        import hashlib

        from airut._bundled.proxy.aws_signing import (
            build_canonical_request,
            build_sigv4_string_to_sign,
            derive_sigv4_signing_key,
            sigv4_sign,
        )

        pf = _pf_with_signing()
        bedrock_host = "bedrock-runtime.eu-central-1.amazonaws.com"
        bedrock_path = "/model/anthropic.claude-3-haiku-v1/invoke"
        body = b'{"prompt": "hello"}'

        # SDK signs with :authority (HTTP/2 pseudo-header)
        bedrock_auth = (
            "AWS4-HMAC-SHA256 "
            f"Credential={SURROGATE_ACCESS_KEY_ID}"
            "/20260101/eu-central-1/bedrock-runtime/aws4_request, "
            "SignedHeaders=:authority;content-type;x-amz-date, "
            "Signature=aa00bb11cc22dd33ee44ff5500661177"
        )
        # mitmproxy converts :authority → Host
        headers: dict[str, str] = {
            "Host": bedrock_host,
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
            "Authorization": bedrock_auth,
        }
        url = f"https://{bedrock_host}{bedrock_path}"
        flow = _flow(
            method="POST",
            host=bedrock_host,
            path=bedrock_path,
            url=url,
            headers=headers,
        )

        # Phase 1: requestheaders defers (no x-amz-content-sha256)
        pf.requestheaders(flow)
        assert "aws_deferred_resign" in flow.metadata

        # Phase 2: request() completes with body
        flow.request.content = body
        pf.request(flow)
        assert flow.metadata.get("aws_resigned") is True

        # Verify signature: must match what AWS expects with host
        # (not :authority)
        auth = flow.request.headers["Authorization"]
        proxy_sig = auth.split("Signature=")[1]

        body_hash = hashlib.sha256(body).hexdigest()
        expected_headers = {
            "Host": bedrock_host,
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
        }
        creq = build_canonical_request(
            method="POST",
            path=bedrock_path,
            query="",
            headers=expected_headers,
            signed_headers="content-type;host;x-amz-date",
            payload_hash=body_hash,
        )
        scope = "20260101/eu-central-1/bedrock-runtime/aws4_request"
        sts = build_sigv4_string_to_sign("20260101T000000Z", scope, creq)
        signing_key = derive_sigv4_signing_key(
            SIGNING_REPLACEMENT["secret_access_key"],
            "20260101",
            "eu-central-1",
            "bedrock-runtime",
        )
        expected_sig = sigv4_sign(signing_key, sts)
        assert proxy_sig == expected_sig

        # The output auth header must use host, not :authority
        assert "SignedHeaders=content-type;host;x-amz-date" in auth

    def test_bedrock_http2_full_scenario(self) -> None:
        """Full real-world scenario: HTTP/2 Bedrock with encoded model ID.

        Exercises all three fixes simultaneously:
        1. :authority → host normalization
        2. Deferred re-signing (body hash computation)
        3. Double URI encoding for non-S3 (%3A → %253A)
        """
        import hashlib

        from airut._bundled.proxy.aws_signing import (
            build_sigv4_string_to_sign,
            canonical_uri,
            derive_sigv4_signing_key,
            sigv4_sign,
        )

        pf = _pf_with_signing()
        bedrock_host = "bedrock-runtime.eu-central-1.amazonaws.com"
        # Wire path has %3A (SDK percent-encodes the colon)
        bedrock_path = (
            "/model/eu.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke"
        )
        body = b'{"prompt": "hello"}'

        # SDK uses HTTP/2 → :authority in SignedHeaders
        bedrock_auth = (
            "AWS4-HMAC-SHA256 "
            f"Credential={SURROGATE_ACCESS_KEY_ID}"
            "/20260101/eu-central-1/bedrock-runtime/aws4_request, "
            "SignedHeaders=:authority;content-type;x-amz-date, "
            "Signature=aa00bb11cc22dd33ee44ff5500661177"
        )
        # mitmproxy converts :authority → Host
        headers: dict[str, str] = {
            "Host": bedrock_host,
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
            "Authorization": bedrock_auth,
        }
        url = f"https://{bedrock_host}{bedrock_path}"
        flow = _flow(
            method="POST",
            host=bedrock_host,
            path=bedrock_path,
            url=url,
            headers=headers,
        )

        # Phase 1: deferred (no x-amz-content-sha256)
        pf.requestheaders(flow)
        assert "aws_deferred_resign" in flow.metadata

        # Phase 2: body available
        flow.request.content = body
        pf.request(flow)
        assert flow.metadata.get("aws_resigned") is True

        auth = flow.request.headers["Authorization"]
        proxy_sig = auth.split("Signature=")[1]

        # Verify: canonical URI must be double-encoded
        c_uri = canonical_uri(bedrock_path, is_s3=False)
        assert "%253A" in c_uri

        # Independently compute expected signature
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_headers = (
            f"content-type:application/json\n"
            f"host:{bedrock_host}\n"
            f"x-amz-date:20260101T000000Z\n"
        )
        creq = "\n".join(
            [
                "POST",
                c_uri,
                "",
                canonical_headers,
                "content-type;host;x-amz-date",
                body_hash,
            ]
        )
        scope = "20260101/eu-central-1/bedrock-runtime/aws4_request"
        sts = build_sigv4_string_to_sign("20260101T000000Z", scope, creq)
        signing_key = derive_sigv4_signing_key(
            SIGNING_REPLACEMENT["secret_access_key"],
            "20260101",
            "eu-central-1",
            "bedrock-runtime",
        )
        expected_sig = sigv4_sign(signing_key, sts)
        assert proxy_sig == expected_sig, (
            f"Full scenario signature mismatch: "
            f"proxy={proxy_sig}, expected={expected_sig}"
        )
        assert "SignedHeaders=content-type;host;x-amz-date" in auth

    def test_authority_empty_host_header(self) -> None:
        """Empty Host header with :authority uses :authority value.

        Regression test: mitmproxy's requestheaders hook may deliver
        an empty Host header for HTTP/2 connections while :authority
        contains the real hostname. The proxy must use :authority's
        value for the host canonical header.
        """
        import hashlib

        from airut._bundled.proxy.aws_signing import (
            build_sigv4_string_to_sign,
            derive_sigv4_signing_key,
            sigv4_sign,
        )

        pf = _pf_with_signing()
        bedrock_host = "bedrock-runtime.eu-central-1.amazonaws.com"
        bedrock_path = "/model/invoke"
        body = b'{"prompt": "hello"}'

        bedrock_auth = (
            "AWS4-HMAC-SHA256 "
            f"Credential={SURROGATE_ACCESS_KEY_ID}"
            "/20260101/eu-central-1/bedrock/aws4_request, "
            "SignedHeaders="
            ":authority;content-type;x-amz-date, "
            "Signature=aa00bb11cc22dd33ee44ff5500661177"
        )
        # Simulate mitmproxy: empty Host, :authority has real value
        headers: dict[str, str] = {
            "Host": "",
            ":authority": bedrock_host,
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
            "Authorization": bedrock_auth,
        }
        url = f"https://{bedrock_host}{bedrock_path}"
        flow = _flow(
            method="POST",
            host=bedrock_host,
            path=bedrock_path,
            url=url,
            headers=headers,
        )

        # Phase 1: deferred (no x-amz-content-sha256)
        pf.requestheaders(flow)
        assert "aws_deferred_resign" in flow.metadata

        # Phase 2: body available
        flow.request.content = body
        pf.request(flow)
        assert flow.metadata.get("aws_resigned") is True

        auth = flow.request.headers["Authorization"]
        proxy_sig = auth.split("Signature=")[1]

        # Expected: canonical request has host:bedrock-runtime...
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_headers = (
            f"content-type:application/json\n"
            f"host:{bedrock_host}\n"
            f"x-amz-date:20260101T000000Z\n"
        )
        creq = "\n".join(
            [
                "POST",
                "/model/invoke",
                "",
                canonical_headers,
                "content-type;host;x-amz-date",
                body_hash,
            ]
        )
        scope = "20260101/eu-central-1/bedrock/aws4_request"
        sts = build_sigv4_string_to_sign("20260101T000000Z", scope, creq)
        signing_key = derive_sigv4_signing_key(
            SIGNING_REPLACEMENT["secret_access_key"],
            "20260101",
            "eu-central-1",
            "bedrock",
        )
        expected_sig = sigv4_sign(signing_key, sts)
        assert proxy_sig == expected_sig, (
            f"Signature mismatch with empty Host header: "
            f"proxy={proxy_sig}, expected={expected_sig}"
        )
        assert "SignedHeaders=content-type;host;x-amz-date" in auth

    def test_js_sdk_empty_host_header(self) -> None:
        """JS SDK signs with host (not :authority) but Host is empty.

        Regression test: aws-sdk-js/3.x signs with host in
        SignedHeaders. mitmproxy's requestheaders hook delivers an
        empty Host header for HTTP/2 connections. The proxy must
        populate host from flow.request.pretty_host.
        """
        import hashlib

        from airut._bundled.proxy.aws_signing import (
            build_sigv4_string_to_sign,
            derive_sigv4_signing_key,
            sigv4_sign,
        )

        pf = _pf_with_signing()
        bedrock_host = "bedrock-runtime.eu-central-1.amazonaws.com"
        bedrock_path = "/model/invoke"
        body = b'{"prompt": "hello"}'

        # JS SDK signs with host, not :authority
        bedrock_auth = (
            "AWS4-HMAC-SHA256 "
            f"Credential={SURROGATE_ACCESS_KEY_ID}"
            "/20260101/eu-central-1/bedrock/aws4_request, "
            "SignedHeaders="
            "content-type;host;x-amz-date, "
            "Signature=aa00bb11cc22dd33ee44ff5500661177"
        )
        # mitmproxy HTTP/2: empty Host header
        headers: dict[str, str] = {
            "Host": "",
            "x-amz-date": "20260101T000000Z",
            "Content-Type": "application/json",
            "Authorization": bedrock_auth,
        }
        url = f"https://{bedrock_host}{bedrock_path}"
        flow = _flow(
            method="POST",
            host=bedrock_host,
            path=bedrock_path,
            url=url,
            headers=headers,
        )

        # Phase 1: deferred (no x-amz-content-sha256)
        pf.requestheaders(flow)
        assert "aws_deferred_resign" in flow.metadata

        # Phase 2: body available
        flow.request.content = body
        pf.request(flow)
        assert flow.metadata.get("aws_resigned") is True

        auth = flow.request.headers["Authorization"]
        proxy_sig = auth.split("Signature=")[1]

        # Expected: host populated from pretty_host
        body_hash = hashlib.sha256(body).hexdigest()
        canonical_headers = (
            f"content-type:application/json\n"
            f"host:{bedrock_host}\n"
            f"x-amz-date:20260101T000000Z\n"
        )
        creq = "\n".join(
            [
                "POST",
                "/model/invoke",
                "",
                canonical_headers,
                "content-type;host;x-amz-date",
                body_hash,
            ]
        )
        scope = "20260101/eu-central-1/bedrock/aws4_request"
        sts = build_sigv4_string_to_sign("20260101T000000Z", scope, creq)
        signing_key = derive_sigv4_signing_key(
            SIGNING_REPLACEMENT["secret_access_key"],
            "20260101",
            "eu-central-1",
            "bedrock",
        )
        expected_sig = sigv4_sign(signing_key, sts)
        assert proxy_sig == expected_sig, (
            f"Signature mismatch with JS SDK empty Host: "
            f"proxy={proxy_sig}, expected={expected_sig}"
        )


# ---------------------------------------------------------------------------
# ProxyFilter.request — AWS re-signed skip
# ---------------------------------------------------------------------------


class TestRequestAwsSkip:
    """Tests for request() skipping token replacement after AWS re-sign."""

    def test_aws_resigned_skips_replace_tokens(self) -> None:
        """When aws_resigned is set, _replace_tokens is not called."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        flow.metadata["aws_resigned"] = True
        # Set allowlist so request passes
        pf.request(flow)
        assert flow.metadata.get("allowlist_action") == "ALLOWED"


# ---------------------------------------------------------------------------
# ProxyFilter.request_data
# ---------------------------------------------------------------------------


class TestRequestData:
    """Tests for ProxyFilter.request_data() hook."""

    def test_no_resigner_passthrough(self) -> None:
        """Data passes through when no chunked_resigner in metadata."""
        pf = ProxyFilter()
        flow = _flow()
        result = pf.request_data(flow, b"raw data")
        assert result == b"raw data"

    def test_resigner_processes_data(self) -> None:
        """Data is processed by the resigner when present."""
        from airut._bundled.proxy.aws_signing import (
            ChunkedResigner,
            derive_sigv4_signing_key,
        )

        pf = ProxyFilter()
        flow = _flow()
        signing_key = derive_sigv4_signing_key(
            "secret", "20260101", "us-east-1", "s3"
        )
        resigner = ChunkedResigner(
            signing_key=signing_key,
            ecdsa_key=None,
            seed_signature="seed_sig",
            timestamp="20260101T000000Z",
            scope="20260101/us-east-1/s3/aws4_request",
            is_sigv4a=False,
            has_trailer=False,
        )
        flow.metadata["chunked_resigner"] = resigner
        body = b"0;chunk-signature=aabb\r\n"
        result = pf.request_data(flow, body)
        assert b"chunk-signature=" in result

    def test_resigner_exception_passthrough(self) -> None:
        """On exception, data passes through and resigner is removed."""
        pf = ProxyFilter()
        flow = _flow()
        mock_resigner = MagicMock()
        mock_resigner.process.side_effect = ValueError("parse error")
        flow.metadata["chunked_resigner"] = mock_resigner
        result = pf.request_data(flow, b"raw data")
        assert result == b"raw data"
        assert "chunked_resigner" not in flow.metadata


# ---------------------------------------------------------------------------
# ProxyFilter.response — AWS region suffix
# ---------------------------------------------------------------------------


class TestWebSocketUpgrade:
    """Tests for WebSocket upgrade requests subject to allowlist.

    WebSocket connections begin as HTTP upgrade requests. mitmproxy routes
    these through the same ``request()`` hook, so allowlist enforcement
    applies identically.  These tests verify that WebSocket upgrade
    headers do not interfere with normal allowlist processing.
    """

    @staticmethod
    def _ws_headers(host: str = "ws.example.com") -> dict[str, str]:
        """Return standard WebSocket upgrade request headers."""
        return {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Host": host,
        }

    def test_websocket_blocked_by_allowlist(self) -> None:
        """WebSocket upgrade to non-allowlisted host is blocked with 403."""
        pf = ProxyFilter()
        # No domains configured — everything is blocked
        flow = _flow(
            method="GET",
            host="ws.evil.com",
            path="/",
            headers=self._ws_headers("ws.evil.com"),
        )
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "BLOCKED"
        assert flow.response is not None
        body = json.loads(flow.response._content)
        assert body["error"] == "blocked_by_network_allowlist"

    def test_websocket_allowed_by_domain(self) -> None:
        """WebSocket upgrade to allowlisted domain passes through."""
        pf = ProxyFilter()
        pf.domains = ["ws.example.com"]
        flow = _flow(
            method="GET",
            host="ws.example.com",
            path="/stream",
            headers=self._ws_headers("ws.example.com"),
        )
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "ALLOWED"
        assert flow.response is None

    def test_websocket_allowed_by_url_prefix(self) -> None:
        """WebSocket upgrade matching url_prefixes entry is allowed."""
        pf = ProxyFilter()
        pf.url_prefixes = [{"host": "api.example.com", "path": "/ws/*"}]
        flow = _flow(
            method="GET",
            host="api.example.com",
            path="/ws/events",
            headers=self._ws_headers("api.example.com"),
        )
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "ALLOWED"

    def test_websocket_blocked_wrong_path(self) -> None:
        """WebSocket upgrade to wrong path on allowlisted host is blocked."""
        pf = ProxyFilter()
        pf.url_prefixes = [{"host": "api.example.com", "path": "/ws/*"}]
        flow = _flow(
            method="GET",
            host="api.example.com",
            path="/admin/ws",
            headers=self._ws_headers("api.example.com"),
        )
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "BLOCKED"

    def test_websocket_method_restriction(self) -> None:
        """WebSocket upgrade blocked when GET not in allowed methods."""
        pf = ProxyFilter()
        pf.url_prefixes = [
            {"host": "api.example.com", "path": "/ws", "methods": ["POST"]}
        ]
        flow = _flow(
            method="GET",
            host="api.example.com",
            path="/ws",
            headers=self._ws_headers("api.example.com"),
        )
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "BLOCKED"
        body = json.loads(flow.response._content)
        assert "Method" in body["message"]

    def test_websocket_with_wildcard_domain(self) -> None:
        """WebSocket upgrade allowed via wildcard domain pattern."""
        pf = ProxyFilter()
        pf.domains = ["*.example.com"]
        flow = _flow(
            method="GET",
            host="ws.example.com",
            path="/",
            headers=self._ws_headers("ws.example.com"),
        )
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "ALLOWED"

    def test_websocket_token_replacement(self) -> None:
        """Token replacement works on WebSocket upgrade requests."""
        pf = ProxyFilter()
        pf.domains = ["ws.example.com"]
        pf.replacements = {
            "surr_token": {
                "value": "real_token",
                "scopes": ["ws.example.com"],
                "headers": ["Authorization"],
            }
        }
        headers = self._ws_headers("ws.example.com")
        headers["Authorization"] = "Bearer surr_token"
        flow = _flow(
            method="GET",
            host="ws.example.com",
            path="/stream",
            headers=headers,
        )
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "ALLOWED"
        assert flow.metadata["masked_count"] == 1
        assert flow.request.headers["Authorization"] == "Bearer real_token"


# ---------------------------------------------------------------------------
# ProxyFilter.response — AWS region suffix
# ---------------------------------------------------------------------------


class TestResponseAwsRegion:
    """Tests for response() including AWS region in log."""

    def test_region_suffix(self) -> None:
        """Region is appended to log when aws_region is set."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "ALLOWED"
        flow.metadata["masked_count"] = 1
        flow.metadata["aws_region"] = "us-west-2"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            msg = mock_log.call_args[0][0]
            assert "[region: us-west-2]" in msg
            assert "[masked: 1]" in msg


# ---------------------------------------------------------------------------
# ProxyFilter.http_connect — CONNECT tunnel blocking
# ---------------------------------------------------------------------------


class TestHttpConnect:
    """Tests for ProxyFilter.http_connect() hook (defense-in-depth).

    mitmproxy would MITM a CONNECT tunnel and still apply request hooks,
    so the allowlist is not actually bypassed.  The proxy blocks CONNECT
    anyway because it is never needed in the DNS-spoofing architecture
    and eliminating it simplifies security reasoning.
    """

    def test_connect_blocked_for_non_allowed_host(self) -> None:
        """CONNECT to a non-allowed host is blocked with 403."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        flow = _flow(method="CONNECT", host="evil.com", path="/")
        pf.http_connect(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response._content)
        assert body["error"] == "blocked_by_network_allowlist"
        assert "CONNECT" in body["message"]

    def test_connect_blocked_for_allowed_host(self) -> None:
        """CONNECT blocked even for allowed hosts."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        flow = _flow(method="CONNECT", host="api.github.com", path="/")
        pf.http_connect(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response._content)
        assert body["error"] == "blocked_by_network_allowlist"

    def test_connect_blocked_with_no_allowlist(self) -> None:
        """CONNECT is blocked even when no allowlist is configured."""
        pf = ProxyFilter()
        flow = _flow(method="CONNECT", host="anything.com", path="/")
        pf.http_connect(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_connect_includes_port_in_host(self) -> None:
        """Blocked CONNECT response includes host:port target."""
        pf = ProxyFilter()
        flow = _flow(method="CONNECT", host="evil.com", path="/")
        pf.http_connect(flow)
        body = json.loads(flow.response._content)
        assert ":" in body["host"]

    def test_connect_logged(self) -> None:
        """Blocked CONNECT is logged via _log_loud."""
        pf = ProxyFilter()
        flow = _flow(method="CONNECT", host="evil.com", path="/")
        with patch.object(pf, "_log_loud") as mock_log:
            pf.http_connect(flow)
            mock_log.assert_called_once()
            assert "CONNECT" in mock_log.call_args[0][0]
            assert "evil.com" in mock_log.call_args[0][0]


class TestHostHeaderMismatch:
    """Tests for Host header vs URL host mismatch blocking (#pentest-4).

    In regular proxy mode, HTTP requests with absolute-form URIs
    (e.g., GET http://target.com/path) are routed by mitmproxy to the
    URL host, but pretty_host returns the Host header value.  When these
    differ, the allowlist can be bypassed for routing purposes.

    The fix blocks any request where pretty_host != host (Host header
    disagrees with URL host).
    """

    def test_mismatched_host_blocked_in_request(self) -> None:
        """Request with Host header differing from URL host is blocked."""
        pf = ProxyFilter()
        pf.domains = ["pypi.org"]
        # Host header says pypi.org (allowed), but URL host is airut.org
        flow = _flow(
            host="pypi.org",
            url_host="airut.org",
            path="/canary.txt",
            url="http://airut.org/canary.txt",
            headers={"Host": "pypi.org"},
        )
        pf.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response._content)
        assert body["error"] == "blocked_by_network_allowlist"
        assert "host mismatch" in body["message"].lower()

    def test_mismatched_host_blocked_in_requestheaders(self) -> None:
        """Mismatch is also blocked early in requestheaders hook."""
        pf = ProxyFilter()
        pf.domains = ["pypi.org"]
        flow = _flow(
            host="pypi.org",
            url_host="evil.com",
            path="/",
            url="http://evil.com/",
            headers={"Host": "pypi.org"},
        )
        pf.requestheaders(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_matching_hosts_allowed(self) -> None:
        """Request with matching Host header and URL host proceeds."""
        pf = ProxyFilter()
        pf.domains = ["pypi.org"]
        flow = _flow(
            host="pypi.org",
            url_host="pypi.org",
            path="/simple/",
            headers={"Host": "pypi.org"},
        )
        pf.request(flow)
        assert flow.response is None
        assert flow.metadata["allowlist_action"] == "ALLOWED"

    def test_default_host_match(self) -> None:
        """When url_host is not set, host and pretty_host match."""
        pf = ProxyFilter()
        pf.domains = ["pypi.org"]
        flow = _flow(host="pypi.org", path="/simple/")
        pf.request(flow)
        assert flow.response is None
        assert flow.metadata["allowlist_action"] == "ALLOWED"

    def test_mismatch_logged(self) -> None:
        """Host mismatch is logged via _log_loud."""
        pf = ProxyFilter()
        pf.domains = ["pypi.org"]
        flow = _flow(
            host="pypi.org",
            url_host="evil.com",
            path="/",
            url="http://evil.com/",
            headers={"Host": "pypi.org"},
        )
        with patch.object(pf, "_log_loud") as mock_log:
            pf.request(flow)
            mock_log.assert_called_once()
            assert "mismatch" in mock_log.call_args[0][0].lower()

    def test_mismatch_with_url_prefix_allowlist(self) -> None:
        """Mismatch blocked even when Host header matches url_prefixes."""
        pf = ProxyFilter()
        pf.url_prefixes = [{"host": "pypi.org", "path": "/*"}]
        flow = _flow(
            host="pypi.org",
            url_host="evil.com",
            path="/packages/foo",
            url="http://evil.com/packages/foo",
            headers={"Host": "pypi.org"},
        )
        pf.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_case_insensitive_match_allowed(self) -> None:
        """Case-differing but equal hosts are not treated as mismatch."""
        pf = ProxyFilter()
        # Allowlist both case variants so _is_allowed passes
        pf.domains = ["pypi.org", "PyPI.org"]
        flow = _flow(
            host="PyPI.org",
            url_host="pypi.org",
            path="/simple/",
            headers={"Host": "PyPI.org"},
        )
        pf.request(flow)
        # Should NOT be blocked as mismatch (case-insensitive match)
        assert flow.response is None
        assert flow.metadata["allowlist_action"] == "ALLOWED"

    def test_both_hosts_disallowed_mismatch_takes_priority(self) -> None:
        """When both hosts are disallowed, mismatch error takes priority."""
        pf = ProxyFilter()
        pf.domains = ["trusted.com"]
        flow = _flow(
            host="evil1.com",
            url_host="evil2.com",
            path="/",
            url="http://evil2.com/",
            headers={"Host": "evil1.com"},
        )
        pf.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response._content)
        assert "host mismatch" in body["message"].lower()


# ---------------------------------------------------------------------------
# GitHub App token replacement
# ---------------------------------------------------------------------------


def _github_app_replacement(
    surrogate: str = "ghs_SurrogateTokenValue1234567890abcde",
    *,
    app_id: str = "Iv23liTestApp",
    private_key: str = "test-private-key",
    installation_id: int = 12345,
    base_url: str = "https://api.github.com",
    scopes: list[str] | None = None,
    allow_foreign_credentials: bool = False,
    permissions: dict[str, str] | None = None,
    repositories: list[str] | None = None,
) -> dict:
    """Build a GitHub App replacement map entry."""
    entry: dict = {
        "type": "github-app",
        "app_id": app_id,
        "private_key": private_key,
        "installation_id": installation_id,
        "base_url": base_url,
        "scopes": scopes or ["api.github.com"],
        "allow_foreign_credentials": allow_foreign_credentials,
    }
    if permissions is not None:
        entry["permissions"] = permissions
    if repositories is not None:
        entry["repositories"] = repositories
    return entry


class TestGitHubAppTokenReplacement:
    """Tests for GitHub App token replacement in proxy filter."""

    _SURROGATE = "ghs_SurrogateTokenValue1234567890abcde"

    def test_replaces_surrogate_with_real_token(self) -> None:
        """Surrogate in Authorization header is replaced with real token."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(self._SURROGATE),
        }

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with (
            patch(
                "airut._bundled.proxy.proxy_filter.generate_jwt",
                return_value="fake-jwt",
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_token",
                return_value=("ghs_real_token_value", 9999999999.0),
            ),
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        assert (
            flow.request.headers["Authorization"]
            == "Bearer ghs_real_token_value"
        )
        assert flow.metadata["masked_count"] == 1

    def test_uses_cached_token(self) -> None:
        """Cached token is used without calling fetch_installation_token."""
        import time as time_mod

        from airut._bundled.proxy.github_app import CachedToken

        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(self._SURROGATE),
        }
        pf._github_app_cache[self._SURROGATE] = CachedToken(
            token="ghs_cached_token",
            expires_at=time_mod.time() + 3600,
        )

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with patch(
            "airut._bundled.proxy.proxy_filter.fetch_installation_token"
        ) as mock_fetch:
            pf.requestheaders(flow)
            pf.request(flow)

        mock_fetch.assert_not_called()
        assert (
            flow.request.headers["Authorization"] == "Bearer ghs_cached_token"
        )

    def test_refreshes_expired_token(self) -> None:
        """Expired cached token triggers a refresh."""
        import time as time_mod

        from airut._bundled.proxy.github_app import CachedToken

        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(self._SURROGATE),
        }
        pf._github_app_cache[self._SURROGATE] = CachedToken(
            token="ghs_expired",
            expires_at=time_mod.time() - 100,
        )

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with (
            patch(
                "airut._bundled.proxy.proxy_filter.generate_jwt",
                return_value="fresh-jwt",
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_token",
                return_value=("ghs_fresh_token", time_mod.time() + 3600),
            ),
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer ghs_fresh_token"
        assert pf._github_app_cache[self._SURROGATE].token == "ghs_fresh_token"

    def test_returns_502_on_refresh_failure(self) -> None:
        """Returns 502 when token refresh fails."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(self._SURROGATE),
        }

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with patch(
            "airut._bundled.proxy.proxy_filter.generate_jwt",
            side_effect=Exception("key error"),
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 502
        body = json.loads(flow.response._content)
        assert body["error"] == "github_app_token_refresh_failed"
        assert flow.metadata["credential_info"] == "github-app: refresh-failed"
        assert flow.metadata.get("masked_count", 0) == 0

    def test_scope_mismatch_skips_replacement(self) -> None:
        """No replacement when host doesn't match scopes."""
        pf = ProxyFilter()
        pf.domains = ["other-api.example.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE,
                scopes=["api.github.com"],
            ),
        }

        flow = _flow(
            host="other-api.example.com",
            path="/",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )
        pf.requestheaders(flow)
        pf.request(flow)

        # Surrogate should still be in the header (not replaced)
        assert self._SURROGATE in flow.request.headers["Authorization"]

    def test_strips_foreign_credentials(self) -> None:
        """Strips Authorization header with non-surrogate on scoped host."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE,
                allow_foreign_credentials=False,
            ),
        }

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": "Bearer foreign-token"},
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert "Authorization" not in flow.request.headers

    def test_allows_foreign_credentials_when_enabled(self) -> None:
        """Keeps Authorization header when allow_foreign_credentials is True."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE,
                allow_foreign_credentials=True,
            ),
        }

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": "Bearer foreign-token"},
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer foreign-token"

    def test_skipped_in_replace_tokens(self) -> None:
        """GitHub App entries are skipped by _replace_tokens."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(self._SURROGATE),
        }

        flow = _flow(
            host="api.github.com",
            path="/",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        # Call _replace_tokens directly — should not replace anything
        replaced, dropped = pf._replace_tokens(flow)
        assert replaced == 0
        assert self._SURROGATE in flow.request.headers["Authorization"]

    def test_wildcard_scopes(self) -> None:
        """Wildcard scopes match subdomains."""
        pf = ProxyFilter()
        pf.domains = ["uploads.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE,
                scopes=["*.github.com"],
            ),
        }

        flow = _flow(
            host="uploads.github.com",
            path="/repos/org/repo/releases",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with (
            patch(
                "airut._bundled.proxy.proxy_filter.generate_jwt",
                return_value="fake-jwt",
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_token",
                return_value=("ghs_wildcard_token", 9999999999.0),
            ),
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        assert (
            flow.request.headers["Authorization"] == "Bearer ghs_wildcard_token"
        )

    def test_passes_permissions_and_repositories(self) -> None:
        """Permissions and repositories are passed to fetch function."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE,
                permissions={"contents": "write"},
                repositories=["my-repo"],
            ),
        }

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with (
            patch(
                "airut._bundled.proxy.proxy_filter.generate_jwt",
                return_value="fake-jwt",
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_token",
                return_value=("ghs_scoped", 9999999999.0),
            ) as mock_fetch,
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        mock_fetch.assert_called_once_with(
            "https://api.github.com",
            "12345",
            "fake-jwt",
            permissions={"contents": "write"},
            repositories=["my-repo"],
        )

    def test_replaces_surrogate_in_basic_auth(self) -> None:
        """Surrogate in Basic Auth password is replaced (git push)."""
        import base64

        pf = ProxyFilter()
        pf.domains = ["github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE, scopes=["github.com"]
            ),
        }

        # git credential helpers send Basic Auth: x-access-token:<token>
        basic = base64.b64encode(
            f"x-access-token:{self._SURROGATE}".encode()
        ).decode()
        flow = _flow(
            host="github.com",
            path="/org/repo.git/info/refs",
            headers={"Authorization": f"Basic {basic}"},
        )

        with (
            patch(
                "airut._bundled.proxy.proxy_filter.generate_jwt",
                return_value="fake-jwt",
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_token",
                return_value=("ghs_real_token_value", 9999999999.0),
            ),
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        # Verify the header was re-encoded as Basic Auth with real token
        expected_basic = base64.b64encode(
            b"x-access-token:ghs_real_token_value"
        ).decode()
        assert (
            flow.request.headers["Authorization"] == f"Basic {expected_basic}"
        )
        assert flow.metadata["masked_count"] == 1

    def test_basic_auth_uses_cached_token(self) -> None:
        """Cached token is used for Basic Auth without refresh."""
        import base64
        import time as time_mod

        from airut._bundled.proxy.github_app import CachedToken

        pf = ProxyFilter()
        pf.domains = ["github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE, scopes=["github.com"]
            ),
        }
        pf._github_app_cache[self._SURROGATE] = CachedToken(
            token="ghs_cached_basic",
            expires_at=time_mod.time() + 3600,
        )

        basic = base64.b64encode(
            f"x-access-token:{self._SURROGATE}".encode()
        ).decode()
        flow = _flow(
            host="github.com",
            path="/org/repo.git/git-receive-pack",
            headers={"Authorization": f"Basic {basic}"},
        )

        with patch(
            "airut._bundled.proxy.proxy_filter.fetch_installation_token"
        ) as mock_fetch:
            pf.requestheaders(flow)
            pf.request(flow)

        mock_fetch.assert_not_called()
        expected_basic = base64.b64encode(
            b"x-access-token:ghs_cached_basic"
        ).decode()
        assert (
            flow.request.headers["Authorization"] == f"Basic {expected_basic}"
        )


# ---------------------------------------------------------------------------
# GitHub App GraphQL repository scoping
# ---------------------------------------------------------------------------


class TestGitHubAppGraphQLScoping:
    """Tests for GraphQL repository scoping in _try_github_app()."""

    _SURROGATE = "ghs_SurrogateTokenValue1234567890abcde"
    _REPO_NODE_IDS = frozenset({"R_kgDORH34qw", "R_kgDORm2NDQ"})

    def _setup_filter_with_cached_token(
        self,
        repo_node_ids: frozenset[str] | None = None,
    ) -> "ProxyFilter":
        """Create a ProxyFilter with a cached GitHub App token."""
        import time as time_mod

        from airut._bundled.proxy.github_app import CachedToken

        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(self._SURROGATE),
        }
        pf._github_app_cache[self._SURROGATE] = CachedToken(
            token="ghs_real_token",
            expires_at=time_mod.time() + 3600,
            repo_node_ids=repo_node_ids
            if repo_node_ids is not None
            else self._REPO_NODE_IDS,
        )
        return pf

    def test_blocks_out_of_scope_graphql_mutation(self) -> None:
        """GraphQL mutation with out-of-scope repositoryId returns 403."""
        pf = self._setup_filter_with_cached_token()

        body = json.dumps(
            {
                "query": (
                    "mutation($input: CreateIssueInput!) {"
                    "  createIssue(input: $input) { issue { id } }"
                    "}"
                ),
                "variables": {
                    "input": {
                        "repositoryId": "R_evil",
                        "title": "exfil",
                    }
                },
            }
        ).encode()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
            content=body,
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        resp_body = json.loads(flow.response._content)
        assert resp_body["error"] == "graphql_repo_scope_blocked"
        assert resp_body["detail"] == "R_evil"
        # Scope block overrides allowlist_action and stores credential info
        assert flow.metadata["allowlist_action"] == "BLOCKED"
        assert flow.metadata["credential_info"] == "github-app: R_evil"
        assert flow.metadata.get("masked_count", 0) == 0

    def test_allows_in_scope_graphql_mutation(self) -> None:
        """GraphQL mutation with in-scope repositoryId proceeds."""
        pf = self._setup_filter_with_cached_token()

        body = json.dumps(
            {
                "query": (
                    "mutation($input: CreateIssueInput!) {"
                    "  createIssue(input: $input) { issue { id } }"
                    "}"
                ),
                "variables": {
                    "input": {
                        "repositoryId": "R_kgDORH34qw",
                        "title": "legit",
                    }
                },
            }
        ).encode()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
            content=body,
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer ghs_real_token"
        # Credential info includes graphql-scoped tag
        assert "graphql-scoped" in flow.metadata.get("credential_info", "")
        assert flow.metadata["masked_count"] == 1

    def test_rest_api_skips_graphql_check(self) -> None:
        """Non-GraphQL REST API requests skip body inspection."""
        pf = self._setup_filter_with_cached_token()

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer ghs_real_token"

    def test_graphql_query_no_repo_id_allowed(self) -> None:
        """GraphQL query with no repositoryId proceeds normally."""
        pf = self._setup_filter_with_cached_token()

        body = json.dumps({"query": "query { viewer { login } }"}).encode()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
            content=body,
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer ghs_real_token"

    def test_403_body_contains_blocked_repo_id(self) -> None:
        """403 response body contains the blocked repositoryId."""
        pf = self._setup_filter_with_cached_token()

        body = json.dumps(
            {
                "query": (
                    "mutation { createIssue(input: "
                    '{repositoryId: "R_attacker", title: "x"}'
                    ") { issue { id } } }"
                ),
            }
        ).encode()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
            content=body,
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response.status_code == 403
        resp_body = json.loads(flow.response._content)
        assert "R_attacker" in resp_body["message"]
        assert resp_body["detail"] == "R_attacker"

    def test_repo_node_ids_populated_during_refresh(self) -> None:
        """repo_node_ids populated during token refresh."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(
                self._SURROGATE,
                repositories=["airut"],
            ),
        }

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with (
            patch(
                "airut._bundled.proxy.proxy_filter.generate_jwt",
                return_value="fake-jwt",
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_token",
                return_value=("ghs_real", 9999999999.0),
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_repos",
                return_value=frozenset({"R_kgDORH34qw"}),
            ) as mock_repos,
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        mock_repos.assert_called_once_with(
            "https://api.github.com",
            "ghs_real",
            configured_repos=["airut"],
        )
        cached = pf._github_app_cache[self._SURROGATE]
        assert cached.repo_node_ids == frozenset({"R_kgDORH34qw"})

    def test_malformed_graphql_returns_403(self) -> None:
        """Malformed GraphQL body returns 403 (fail-secure)."""
        pf = self._setup_filter_with_cached_token()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
            content=b"not json",
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        resp_body = json.loads(flow.response._content)
        assert resp_body["error"] == "graphql_repo_scope_blocked"
        assert resp_body["detail"] == "<unparseable>"

    def test_empty_repo_node_ids_blocks_graphql_with_repo_id(self) -> None:
        """Empty node IDs block GraphQL with repositoryId."""
        pf = self._setup_filter_with_cached_token(repo_node_ids=frozenset())

        body = json.dumps(
            {
                "query": (
                    "mutation($input: CreateIssueInput!) {"
                    "  createIssue(input: $input) { issue { id } }"
                    "}"
                ),
                "variables": {
                    "input": {
                        "repositoryId": "R_evil",
                        "title": "exfil",
                    }
                },
            }
        ).encode()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
            content=body,
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        resp_body = json.loads(flow.response._content)
        assert resp_body["error"] == "graphql_repo_scope_blocked"

    def test_empty_repo_node_ids_allows_graphql_without_repo_id(
        self,
    ) -> None:
        """Empty repo_node_ids allows GraphQL queries without repositoryId."""
        pf = self._setup_filter_with_cached_token(repo_node_ids=frozenset())

        body = json.dumps({"query": "query { viewer { login } }"}).encode()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
            content=body,
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer ghs_real_token"

    def test_repo_resolution_failure_degrades_to_empty(self) -> None:
        """fetch_installation_repos failure sets empty node IDs."""
        pf = ProxyFilter()
        pf.domains = ["api.github.com"]
        pf.replacements = {
            self._SURROGATE: _github_app_replacement(self._SURROGATE),
        }

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )

        with (
            patch(
                "airut._bundled.proxy.proxy_filter.generate_jwt",
                return_value="fake-jwt",
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_token",
                return_value=("ghs_real", 9999999999.0),
            ),
            patch(
                "airut._bundled.proxy.proxy_filter.fetch_installation_repos",
                side_effect=Exception("API error"),
            ),
        ):
            pf.requestheaders(flow)
            pf.request(flow)

        # REST (non-graphql) still works with token replacement
        assert flow.request.headers["Authorization"] == "Bearer ghs_real"
        # Node IDs are empty from failed resolution
        cached = pf._github_app_cache[self._SURROGATE]
        assert cached.repo_node_ids == frozenset()

    def test_graphql_with_query_params_blocked(self) -> None:
        """GraphQL requests with URL query parameters return 403."""
        pf = self._setup_filter_with_cached_token()

        flow = _flow(
            method="POST",
            host="api.github.com",
            path="/graphql?query={viewer{login}}",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        resp_body = json.loads(flow.response._content)
        assert resp_body["error"] == "graphql_repo_scope_blocked"
        assert resp_body["detail"] == "query-params"
        assert flow.metadata["allowlist_action"] == "BLOCKED"
        assert flow.metadata.get("masked_count", 0) == 0

    def test_graphql_get_with_query_params_blocked(self) -> None:
        """GET /graphql?query=... is blocked regardless of method."""
        pf = self._setup_filter_with_cached_token()

        flow = _flow(
            method="GET",
            host="api.github.com",
            path="/graphql?query={viewer{login}}",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_non_graphql_path_with_query_params_unaffected(self) -> None:
        """Non-graphql paths with query params are not rejected."""
        pf = self._setup_filter_with_cached_token()

        flow = _flow(
            host="api.github.com",
            path="/repos/org/repo?per_page=100",
            headers={"Authorization": f"Bearer {self._SURROGATE}"},
        )
        pf.requestheaders(flow)
        pf.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer ghs_real_token"
