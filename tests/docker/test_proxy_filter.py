# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the proxy filter mitmproxy addon.

Tests the actual ``docker/proxy_filter.py`` module with mitmproxy mocked
out via ``conftest.py``.  This gives proper coverage measurement unlike
the ``test_proxy_allowlist.py`` tests which exercise reimplemented copies.
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from docker.proxy_filter import (
    ProxyFilter,
    _decode_basic_auth,
    _encode_basic_auth,
    _match_header_pattern,
    _match_pattern,
)
from mitmproxy.http import (  # type: ignore[attr-defined]
    MockError,
    MockHTTPFlow,
    MockRequest,
    MockResponse,
)


# ---------------------------------------------------------------------------
# Helper to build flows
# ---------------------------------------------------------------------------


def _flow(
    *,
    method: str = "GET",
    host: str = "example.com",
    path: str = "/",
    url: str | None = None,
    headers: dict[str, str] | None = None,
    response_code: int | None = None,
    error_msg: str | None = None,
) -> Any:
    """Build a MockHTTPFlow for testing."""
    if url is None:
        url = f"https://{host}{path}"
    req = MockRequest(
        method=method,
        url=url,
        host=host,
        path=path,
        headers=headers,
    )
    resp = MockResponse(response_code) if response_code is not None else None
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
        with patch("docker.proxy_filter.NETWORK_LOG_PATH", log_path):
            pf._setup_file_logging()
        assert pf._log_file is not None
        pf._log_file.close()
        content = log_path.read_text()
        assert "=== TASK START" in content

    def test_setup_file_logging_no_path(self, tmp_path: Path) -> None:
        """No log file when path doesn't exist."""
        pf = ProxyFilter()
        with patch(
            "docker.proxy_filter.NETWORK_LOG_PATH",
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
            patch("docker.proxy_filter.NETWORK_LOG_PATH", log_path),
            patch("builtins.open", side_effect=OSError("denied")),
        ):
            pf._setup_file_logging()
        assert pf._log_file is None

    def test_load_allowlist_from_file(self, tmp_path: Path) -> None:
        """Loads domains and url_prefixes from YAML."""
        config_path = tmp_path / "network-allowlist.yaml"
        config_path.write_text(
            "domains:\n  - api.github.com\nurl_prefixes:\n"
            "  - host: pypi.org\n    path: /simple*\n"
        )
        pf = ProxyFilter()
        with patch("docker.proxy_filter.Path", return_value=config_path):
            pf._load_allowlist()
        assert "api.github.com" in pf.domains
        assert len(pf.url_prefixes) == 1

    def test_load_allowlist_missing_file(self) -> None:
        """Missing allowlist file leaves empty lists."""
        pf = ProxyFilter()
        with patch.object(Path, "exists", return_value=False):
            pf._load_allowlist()
        assert pf.domains == []

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
        with patch("docker.proxy_filter.REPLACEMENTS_PATH", repl_path):
            pf._load_replacements()
        assert "ghp_surr" in pf.replacements

    def test_load_replacements_missing_file(self, tmp_path: Path) -> None:
        """Missing file leaves empty replacements."""
        pf = ProxyFilter()
        with patch(
            "docker.proxy_filter.REPLACEMENTS_PATH",
            tmp_path / "nonexistent.json",
        ):
            pf._load_replacements()
        assert pf.replacements == {}

    def test_load_replacements_invalid_json(self, tmp_path: Path) -> None:
        """Invalid JSON leaves empty replacements."""
        repl_path = tmp_path / "replacements.json"
        repl_path.write_text("not json!")
        pf = ProxyFilter()
        with patch("docker.proxy_filter.REPLACEMENTS_PATH", repl_path):
            pf._load_replacements()
        assert pf.replacements == {}


# ---------------------------------------------------------------------------
# ProxyFilter._log
# ---------------------------------------------------------------------------


class TestProxyFilterLog:
    """Tests for ProxyFilter._log."""

    def test_log_to_ctx_and_file(self, tmp_path: Path) -> None:
        """Logs to both ctx.log and file."""
        log_path = tmp_path / "test.log"
        pf = ProxyFilter()
        pf._log_file = open(log_path, "w")
        try:
            pf._log("test message")
        finally:
            pf._log_file.close()
        assert "test message" in log_path.read_text()

    def test_log_without_file(self) -> None:
        """Logs to ctx.log only when no file."""
        pf = ProxyFilter()
        pf._log("test")  # Should not raise

    def test_log_file_oserror(self) -> None:
        """Handles OSError on file write gracefully."""
        pf = ProxyFilter()
        pf._log_file = MagicMock()
        pf._log_file.write.side_effect = OSError("disk full")
        pf._log("test")  # Should not raise


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
        assert pf._replace_tokens(flow) == 0

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
        assert pf._replace_tokens(flow) == 0

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
        assert pf._replace_tokens(flow) == 0

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
        count = pf._replace_tokens(flow)
        assert count == 1
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
        assert pf._replace_tokens(flow) == 1

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
        assert pf._replace_tokens(flow) == 1


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

    def test_allowed_request(self) -> None:
        """Allowed request passes through."""
        pf = ProxyFilter()
        pf.domains = ["example.com"]
        flow = _flow(host="example.com")
        pf.request(flow)
        assert flow.metadata["allowlist_action"] == "allowed"
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


# ---------------------------------------------------------------------------
# ProxyFilter.response — logging
# ---------------------------------------------------------------------------


class TestProxyFilterResponse:
    """Tests for ProxyFilter.response() hook."""

    def test_blocked_not_logged(self) -> None:
        """Blocked requests are not logged in response."""
        pf = ProxyFilter()
        flow = _flow(response_code=403)
        flow.metadata["allowlist_action"] = "BLOCKED"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            mock_log.assert_not_called()

    def test_allowed_logged(self) -> None:
        """Allowed requests are logged with status code."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "allowed"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            mock_log.assert_called_once()
            assert "200" in mock_log.call_args[0][0]

    def test_masked_suffix(self) -> None:
        """Masked count is included in log."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "allowed"
        flow.metadata["masked_count"] = 2
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            assert "[masked: 2]" in mock_log.call_args[0][0]

    def test_no_response(self) -> None:
        """Handles flow with no response (shows ?)."""
        pf = ProxyFilter()
        flow = _flow()
        flow.metadata["allowlist_action"] = "allowed"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            assert "?" in mock_log.call_args[0][0]


# ---------------------------------------------------------------------------
# ProxyFilter.error — error logging
# ---------------------------------------------------------------------------


class TestProxyFilterError:
    """Tests for ProxyFilter.error() hook."""

    def test_blocked_not_logged(self) -> None:
        """Blocked requests' errors are not logged."""
        pf = ProxyFilter()
        flow = _flow(error_msg="connection failed")
        flow.metadata["allowlist_action"] = "BLOCKED"
        with patch.object(pf, "_log") as mock_log:
            pf.error(flow)
            mock_log.assert_not_called()

    def test_allowed_error_logged(self) -> None:
        """Allowed requests' errors are logged."""
        pf = ProxyFilter()
        flow = _flow(error_msg="connection refused")
        flow.metadata["allowlist_action"] = "allowed"
        with patch.object(pf, "_log") as mock_log:
            pf.error(flow)
            mock_log.assert_called_once()
            assert "connection refused" in mock_log.call_args[0][0]

    def test_no_error_object(self) -> None:
        """Handles flow with no error object."""
        pf = ProxyFilter()
        flow = _flow()
        flow.error = None
        flow.metadata["allowlist_action"] = "allowed"
        with patch.object(pf, "_log") as mock_log:
            pf.error(flow)
            assert "unknown error" in mock_log.call_args[0][0]


# ---------------------------------------------------------------------------
# Module-level addons list
# ---------------------------------------------------------------------------


class TestAddons:
    """Tests for module-level addons list."""

    def test_addons_contains_proxy_filter(self) -> None:
        from docker.proxy_filter import addons

        assert len(addons) == 1
        assert isinstance(addons[0], ProxyFilter)
