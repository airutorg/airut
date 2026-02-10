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
from tests.docker.vectors import (
    REAL_ACCESS_KEY_ID,
    SIGNING_REPLACEMENT,
    SIGV4_AUTH,
    SIGV4A_AUTH,
    SURROGATE_ACCESS_KEY_ID,
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
) -> Any:
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
    pf.replacements = {SURROGATE_ACCESS_KEY_ID: SIGNING_REPLACEMENT}
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
        """Logs warning when clock skew detected."""
        pf = _pf_with_signing()
        flow = _aws_flow()
        # Override the x-amz-date with old timestamp
        flow.request.headers["x-amz-date"] = "20200101T000000Z"
        with patch.object(pf, "_log") as mock_log:
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
            "docker.proxy_filter.resign_request",
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
    ) -> Any:
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
            "docker.proxy_filter.resign_presigned_url",
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
        assert flow.metadata.get("allowlist_action") == "allowed"


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
        from docker.aws_signing import ChunkedResigner, derive_sigv4_signing_key

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


class TestResponseAwsRegion:
    """Tests for response() including AWS region in log."""

    def test_region_suffix(self) -> None:
        """Region is appended to log when aws_region is set."""
        pf = ProxyFilter()
        flow = _flow(response_code=200)
        flow.metadata["allowlist_action"] = "allowed"
        flow.metadata["masked_count"] = 1
        flow.metadata["aws_region"] = "us-west-2"
        with patch.object(pf, "_log") as mock_log:
            pf.response(flow)
            msg = mock_log.call_args[0][0]
            assert "[region: us-west-2]" in msg
            assert "[masked: 1]" in msg
