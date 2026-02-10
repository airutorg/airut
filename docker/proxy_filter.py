# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""mitmproxy addon for network allowlist, token masking, and AWS re-signing.

Enforces a network allowlist and performs token replacement for masked
secrets. Blocked requests receive an HTTP 403 response. Allowed requests
have masked secret surrogates swapped for real values when the host matches
the secret's scope.

Token replacement handles both direct tokens (e.g., Bearer tokens) and
Base64-encoded credentials (e.g., Basic Auth). For Basic Auth, the addon
decodes the credential, performs replacement, and re-encodes.

AWS SigV4/SigV4A re-signing: When a signing credential entry is detected
(by matching the surrogate access key ID in the Authorization header or
presigned URL), the proxy re-signs the request with real credentials.

Supports fnmatch-style wildcards (* and ?) in both domain and path patterns:
- "*.github.com" matches "api.github.com" but NOT "github.com"
- "/api/*" matches "/api/foo" but NOT "/api"
- "/api" matches only "/api" exactly (no implicit prefix matching)

Usage:
    mitmdump -s docker/proxy_filter.py
"""

import base64
import fnmatch
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO, TypedDict

import yaml
from aws_signing import (
    SIGNING_TYPE_AWS_SIGV4,
    ChunkedResigner,
    ResignResult,
    canonical_uri,
    check_clock_skew,
    derive_sigv4_signing_key,
    derive_sigv4a_key,
    parse_auth_header,
    parse_presigned_url_params,
    resign_presigned_url,
    resign_request,
)
from mitmproxy import ctx, http


class UrlPrefixEntry(TypedDict, total=False):
    """A single entry in the url_prefixes allowlist."""

    host: str
    path: str
    methods: list[str]


# Path to optional session log file (mounted by proxy container)
NETWORK_LOG_PATH = Path("/network-sandbox.log")

# Path to replacement map (mounted by proxy container)
REPLACEMENTS_PATH = Path("/replacements.json")

# Enable verbose signing diagnostics (canonical request, hashes, etc.)
DEBUG_SIGNING = os.environ.get("DEBUG_SIGNING", "").lower() in (
    "1",
    "true",
    "yes",
)


def _match_pattern(pattern: str, value: str) -> bool:
    """Match value against pattern using fnmatch if wildcards present.

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


def _decode_basic_auth(auth_value: str) -> tuple[str, str] | None:
    """Decode a Basic Auth header value.

    Args:
        auth_value: Full Authorization header value (e.g., "Basic ...").

    Returns:
        Tuple of (username, password) if valid Basic Auth, None otherwise.
    """
    if not auth_value.startswith("Basic "):
        return None

    try:
        encoded = auth_value[6:]  # Strip "Basic "
        decoded = base64.b64decode(encoded).decode("utf-8")
        if ":" not in decoded:
            return None
        username, password = decoded.split(":", 1)
        return username, password
    except (ValueError, UnicodeDecodeError):
        return None


def _encode_basic_auth(username: str, password: str) -> str:
    """Encode username and password as Basic Auth header value.

    Args:
        username: Username part.
        password: Password part.

    Returns:
        Full Authorization header value (e.g., "Basic dXNlcjpwYXNz").
    """
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


class ProxyFilter:
    """mitmproxy addon for network allowlist and token masking."""

    def __init__(self) -> None:
        self.domains: list[str] = []
        self.url_prefixes: list[UrlPrefixEntry] = []
        self.replacements: dict[str, dict[str, Any]] = {}
        self._log_file: TextIO | None = None

    def load(self, options: object) -> None:  # noqa: ARG002
        """Load configuration on startup."""
        self._setup_file_logging()
        self._load_allowlist()
        self._load_replacements()

    def _setup_file_logging(self) -> None:
        """Set up file logging if log path exists."""
        if NETWORK_LOG_PATH.exists():
            try:
                self._log_file = open(NETWORK_LOG_PATH, "a")
                timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                self._log_file.write(f"=== TASK START {timestamp} ===\n")
                self._log_file.flush()
            except OSError as e:
                ctx.log.warn(f"Could not open log file {NETWORK_LOG_PATH}: {e}")

    def _load_allowlist(self) -> None:
        """Load allowlist from configuration file."""
        config_path = Path("/network-allowlist.yaml")
        if not config_path.exists():
            ctx.log.error(
                f"Allowlist config not found: {config_path}. "
                "All requests will be blocked."
            )
            return

        with open(config_path) as f:
            config = yaml.safe_load(f)

        self.domains = list(config.get("domains", []))
        self.url_prefixes = config.get("url_prefixes", [])

        ctx.log.info(
            f"Loaded allowlist: {len(self.domains)} domains, "
            f"{len(self.url_prefixes)} URL patterns"
        )

    def _load_replacements(self) -> None:
        """Load replacement map for masked secrets."""
        if not REPLACEMENTS_PATH.exists():
            ctx.log.info("No replacement map found, token masking disabled")
            return

        try:
            with open(REPLACEMENTS_PATH) as f:
                self.replacements = json.load(f)
            ctx.log.info(f"Loaded {len(self.replacements)} token replacements")
        except (OSError, json.JSONDecodeError) as e:
            ctx.log.warn(f"Failed to load replacements: {e}")
            self.replacements = {}

    def _log(self, message: str) -> None:
        """Log message to both mitmproxy and optional file."""
        ctx.log.info(message)
        if self._log_file is not None:
            try:
                self._log_file.write(message + "\n")
                self._log_file.flush()
            except OSError:
                pass  # Best effort file logging

    def _is_allowed(self, host: str, path: str, method: str = "") -> bool:
        """Check if a host+path+method combination is allowed.

        Uses fnmatch-style pattern matching for both domains and paths.
        Patterns containing * or ? are matched with fnmatch; others require
        exact match.

        Domain entries allow all methods unconditionally. URL prefix entries
        can optionally restrict allowed HTTP methods via a ``methods`` list.

        Args:
            host: Request hostname (e.g. "api.github.com").
            path: Request path (e.g. "/repos/your-org/your-repo/pulls").
            method: HTTP method (e.g. "GET", "POST"). Empty means any.

        Returns:
            True if the request is allowed, False otherwise.
        """
        # Check domain entries (with wildcard support)
        # Domain entries allow all methods unconditionally
        for domain in self.domains:
            if _match_pattern(domain, host):
                return True

        # Check URL pattern entries
        for entry in self.url_prefixes:
            entry_host = entry.get("host", "")
            entry_path = entry.get("path", "")
            entry_methods: list[str] = entry.get("methods", [])

            if _match_pattern(entry_host, host):
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

    def _replace_in_header(
        self,
        header_name: str,
        header_value: str,
        surrogate: str,
        real_value: str,
    ) -> tuple[str, bool]:
        """Replace surrogate with real value in a header.

        Handles both direct replacement and Base64-encoded Basic Auth.

        Args:
            header_name: Name of the header (e.g., "Authorization").
            header_value: Current header value.
            surrogate: Surrogate token to find.
            real_value: Real value to substitute.

        Returns:
            Tuple of (new_header_value, was_replaced).
        """
        # Try direct replacement first
        if surrogate in header_value:
            return header_value.replace(surrogate, real_value), True

        # For Authorization header, try Basic Auth decoding
        if header_name.lower() == "authorization":
            credentials = _decode_basic_auth(header_value)
            if credentials is not None:
                username, password = credentials
                replaced = False

                # Check if surrogate is in username or password
                if surrogate in username:
                    username = username.replace(surrogate, real_value)
                    replaced = True
                if surrogate in password:
                    password = password.replace(surrogate, real_value)
                    replaced = True

                if replaced:
                    return _encode_basic_auth(username, password), True

        return header_value, False

    def _replace_tokens(self, flow: http.HTTPFlow) -> int:
        """Replace surrogate tokens with real values in request headers.

        Only replaces tokens when the request host matches the secret's
        scope patterns. Handles both direct tokens and Base64-encoded
        Basic Auth credentials.

        Args:
            flow: The HTTP flow to modify.

        Returns:
            Number of replacements made.
        """
        if not self.replacements:
            return 0

        host = flow.request.pretty_host
        count = 0

        for surrogate, config in self.replacements.items():
            scopes = config.get("scopes", [])
            real_value = config.get("value", "")

            # Check if host matches any scope pattern
            if not any(_match_pattern(scope, host) for scope in scopes):
                continue

            # Get header patterns to scan (supports fnmatch, e.g., "*")
            header_patterns = config.get("headers", [])

            # Scan request headers that match any pattern (case-insensitive)
            for header in flow.request.headers:
                if not any(
                    _match_header_pattern(p, header) for p in header_patterns
                ):
                    continue

                current_value = flow.request.headers[header]
                new_value, replaced = self._replace_in_header(
                    header, current_value, surrogate, real_value
                )
                if replaced:
                    flow.request.headers[header] = new_value
                    count += 1

        return count

    def _try_resign_aws(self, flow: http.HTTPFlow) -> ResignResult | None:
        """Attempt to re-sign an AWS-signed request.

        Checks Authorization header for AWS SigV4/SigV4A, looks up the
        key ID in the replacement map, and re-signs if it's a signing
        credential. Also handles presigned URLs.

        Args:
            flow: The HTTP flow to modify.

        Returns:
            ResignResult if re-signing was performed, None otherwise.
        """
        host = flow.request.pretty_host
        auth_value = flow.request.headers.get("Authorization", "")

        if auth_value:
            return self._resign_header_auth(flow, host, auth_value)

        # Check for presigned URL
        return self._resign_presigned(flow, host)

    def _prepare_signing_context(
        self,
        flow: http.HTTPFlow,
        host: str,
        auth_value: str,
    ) -> dict[str, Any] | None:
        """Look up signing credentials and prepare context for re-signing.

        Parses the Authorization header, looks up the key ID in the
        replacement map, verifies scopes, checks clock skew, and extracts
        request components needed for re-signing.

        Args:
            flow: The HTTP flow.
            host: Request host.
            auth_value: Authorization header value.

        Returns:
            Dict with parsed auth, credentials, and request components,
            or None if not a re-signable request.
        """
        parsed = parse_auth_header(auth_value)
        if parsed is None:
            return None

        config = self.replacements.get(parsed.key_id)
        if config is None or config.get("type") != SIGNING_TYPE_AWS_SIGV4:
            return None

        # Verify host matches scopes
        scopes = config.get("scopes", [])
        if not any(_match_pattern(scope, host) for scope in scopes):
            return None

        # Check clock skew
        amz_date = flow.request.headers.get("x-amz-date", "")
        if amz_date:
            is_skewed, drift_minutes = check_clock_skew(amz_date)
            if is_skewed:
                proxy_time = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                self._log(
                    f"WARNING: Container clock skew detected: "
                    f"x-amz-date={amz_date}, proxy-time={proxy_time} "
                    f"(drift={drift_minutes}m). Upstream rejection likely."
                )

        # Parse path and query
        url_path = flow.request.path
        query = ""
        if "?" in url_path:
            url_path, query = url_path.split("?", 1)

        # Build headers dict, ensuring host is populated.
        # mitmproxy's requestheaders hook may deliver an empty Host
        # header for HTTP/2 connections; use pretty_host which is
        # always available regardless of HTTP version.
        hdrs = dict(flow.request.headers)
        host_val = ""
        for k, v in hdrs.items():
            if k.lower() == "host":
                host_val = v
                break
        if not host_val.strip():
            # Remove empty Host variants, set correct value
            for k in list(hdrs):
                if k.lower() == "host":
                    del hdrs[k]
            hdrs["host"] = host

        return {
            "parsed": parsed,
            "real_key_id": config["access_key_id"],
            "real_secret_key": config["secret_access_key"],
            "real_session_token": config.get("session_token"),
            "surrogate_session_token": config.get("surrogate_session_token"),
            "content_sha256": flow.request.headers.get(
                "x-amz-content-sha256", "UNSIGNED-PAYLOAD"
            ),
            "headers": hdrs,
            "url_path": url_path,
            "query": query,
        }

    def _resign_header_auth(
        self,
        flow: http.HTTPFlow,
        host: str,
        auth_value: str,
    ) -> ResignResult | None:
        """Re-sign a request with Authorization header.

        If ``x-amz-content-sha256`` is present in the request headers,
        re-signing happens immediately using the header value as the
        payload hash.  Otherwise, signing is deferred to the
        ``request()`` hook where the body is available and the payload
        hash can be computed from the actual content.
        """
        ctx_data = self._prepare_signing_context(flow, host, auth_value)
        if ctx_data is None:
            return None

        # If no x-amz-content-sha256 header, defer signing to request()
        # so we can compute sha256(body).  Non-S3 SDKs (Bedrock, STS,
        # DynamoDB, etc.) sign the payload but don't send this header.
        has_content_sha = "x-amz-content-sha256" in (
            h.lower() for h in flow.request.headers
        )
        if not has_content_sha:
            flow.metadata["aws_deferred_resign"] = ctx_data
            if DEBUG_SIGNING:
                self._log("re-sign: deferred (no x-amz-content-sha256 header)")
            return ResignResult(auth_header="", region="", is_chunked=False)

        return self._perform_resign(flow, ctx_data)

    def _perform_resign(
        self,
        flow: http.HTTPFlow,
        ctx_data: dict[str, Any],
    ) -> ResignResult | None:
        """Execute the actual re-signing with the given context."""
        parsed = ctx_data["parsed"]
        real_key_id: str = ctx_data["real_key_id"]
        real_secret_key: str = ctx_data["real_secret_key"]
        real_session_token: str | None = ctx_data["real_session_token"]
        surrogate_session_token: str | None = ctx_data[
            "surrogate_session_token"
        ]

        # Verbose signing diagnostics (only with DEBUG_SIGNING=1).
        if DEBUG_SIGNING:
            scope_parts = parsed.scope_parts
            service = scope_parts[-2] if len(scope_parts) >= 2 else "?"
            is_s3 = service == "s3"
            c_uri = canonical_uri(ctx_data["url_path"], is_s3=is_s3)
            log_signed = parsed.signed_headers
            if ":authority" in log_signed.split(";"):
                sh_parts = log_signed.split(";")
                sh_parts = [
                    "host" if p == ":authority" else p for p in sh_parts
                ]
                log_signed = ";".join(sorted(set(sh_parts)))
            self._log(
                f"re-sign: service={service} is_s3={is_s3} "
                f"path={ctx_data['url_path']} "
                f"canonical_uri={c_uri} "
                f"signed_headers={log_signed} "
                f"payload_hash={ctx_data['content_sha256']}"
            )

        try:
            result = resign_request(
                method=flow.request.method,
                path=ctx_data["url_path"],
                query=ctx_data["query"],
                headers=ctx_data["headers"],
                parsed_auth=parsed,
                real_key_id=real_key_id,
                real_secret_key=real_secret_key,
                content_sha256=ctx_data["content_sha256"],
            )
        except (ValueError, KeyError, ImportError, RuntimeError) as e:
            ctx.log.error(f"AWS re-signing failed: {e}")
            return None

        if DEBUG_SIGNING:
            self._log(
                f"re-sign: creq_hash="
                f"{result.canonical_request_hash} "
                f"output_signed_headers="
                f"{result.signed_headers}"
            )
            self._log(
                f"re-sign: canonical_request={repr(result.canonical_request)}"
            )

        # Replace Authorization header
        flow.request.headers["Authorization"] = result.auth_header

        # Replace session token if present
        if (
            real_session_token
            and surrogate_session_token
            and "x-amz-security-token"
            in (h.lower() for h in flow.request.headers)
        ):
            for header_name in list(flow.request.headers.keys()):
                if header_name.lower() == "x-amz-security-token":
                    flow.request.headers[header_name] = real_session_token

        # Set up streaming for chunked requests
        if result.is_chunked:
            self._setup_chunked_resigner(
                flow, parsed, real_key_id, real_secret_key, result
            )

        # Store region for response logging
        flow.metadata["aws_region"] = result.region

        return result

    def _setup_chunked_resigner(
        self,
        flow: http.HTTPFlow,
        parsed: Any,
        real_key_id: str,
        real_secret_key: str,
        result: ResignResult,
    ) -> None:
        """Set up streaming body re-signing for chunked uploads."""
        content_sha256 = flow.request.headers.get("x-amz-content-sha256", "")
        has_trailer = content_sha256.endswith("-TRAILER")
        timestamp = flow.request.headers.get("x-amz-date", "")

        # Extract the new seed signature from the result
        # The signature is the last component of the auth header
        new_sig = result.auth_header.rsplit("Signature=", 1)[1]

        if parsed.is_sigv4a:
            ecdsa_key = derive_sigv4a_key(real_secret_key, real_key_id)
            resigner = ChunkedResigner(
                signing_key=None,
                ecdsa_key=ecdsa_key,
                seed_signature=new_sig,
                timestamp=timestamp,
                scope=parsed.scope,
                is_sigv4a=True,
                has_trailer=has_trailer,
            )
        else:
            scope_parts = parsed.scope_parts
            date = scope_parts[0]
            region = scope_parts[1] if len(scope_parts) >= 3 else ""
            service = scope_parts[2] if len(scope_parts) >= 3 else ""
            signing_key = derive_sigv4_signing_key(
                real_secret_key, date, region, service
            )
            resigner = ChunkedResigner(
                signing_key=signing_key,
                ecdsa_key=None,
                seed_signature=new_sig,
                timestamp=timestamp,
                scope=parsed.scope,
                is_sigv4a=False,
                has_trailer=has_trailer,
            )

        flow.metadata["chunked_resigner"] = resigner

    def _resign_presigned(
        self,
        flow: http.HTTPFlow,
        host: str,
    ) -> ResignResult | None:
        """Re-sign a presigned URL request."""
        url_path = flow.request.path
        query = ""
        if "?" in url_path:
            url_path, query = url_path.split("?", 1)

        params = parse_presigned_url_params(query)
        if params is None:
            return None

        # Extract key ID from X-Amz-Credential
        credential = params.get("X-Amz-Credential", "")
        if "/" not in credential:
            return None
        key_id = credential.split("/")[0]

        config = self.replacements.get(key_id)
        if config is None or config.get("type") != SIGNING_TYPE_AWS_SIGV4:
            return None

        # Verify host matches scopes
        scopes = config.get("scopes", [])
        if not any(_match_pattern(scope, host) for scope in scopes):
            return None

        real_key_id: str = config["access_key_id"]
        real_secret_key: str = config["secret_access_key"]
        real_session_token: str | None = config.get("session_token")
        surrogate_session_token: str | None = config.get(
            "surrogate_session_token"
        )

        headers = dict(flow.request.headers)

        try:
            new_query = resign_presigned_url(
                method=flow.request.method,
                path=url_path,
                query=query,
                headers=headers,
                params=params,
                real_key_id=real_key_id,
                real_secret_key=real_secret_key,
            )
        except (ValueError, KeyError, ImportError, RuntimeError) as e:
            ctx.log.error(f"AWS presigned URL re-signing failed: {e}")
            return None

        # Replace session token in query if present
        if real_session_token and surrogate_session_token:
            new_query = new_query.replace(
                surrogate_session_token, real_session_token
            )

        # Reconstruct URL with new query string
        flow.request.url = flow.request.url.split("?")[0] + "?" + new_query

        # Extract region from credential scope
        scope = credential.split("/", 1)[1] if "/" in credential else ""
        scope_parts = scope.split("/")
        region = scope_parts[1] if len(scope_parts) >= 3 else ""
        flow.metadata["aws_region"] = region

        return ResignResult(auth_header="", region=region, is_chunked=False)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """Handle AWS re-signing before body arrives.

        For chunked uploads, this enables streaming mode so the body
        can be re-signed chunk by chunk without buffering.

        For requests without ``x-amz-content-sha256`` (non-S3 services
        like Bedrock), signing is deferred to ``request()`` where the
        body is available for computing the payload hash.
        """
        # Allowlist check happens here for all requests
        host = flow.request.pretty_host
        path = flow.request.path
        method = flow.request.method

        if not self._is_allowed(host, path, method):
            return  # Will be blocked in request() hook

        # Try AWS re-signing
        result = self._try_resign_aws(flow)
        if result is not None:
            # Deferred signing stores context in metadata and returns
            # an empty ResignResult.  Don't mark as fully resigned yet.
            if "aws_deferred_resign" in flow.metadata:
                return
            flow.metadata["aws_resigned"] = True
            flow.metadata["masked_count"] = 1
            if result.is_chunked:
                flow.request.stream = True

    def request(self, flow: http.HTTPFlow) -> None:
        """Check allowlist, perform deferred re-signing, and token replacement.

        Deferred re-signing handles non-S3 AWS services where the SDK
        does not send ``x-amz-content-sha256`` and the payload hash must
        be computed from the actual request body.
        """
        host = flow.request.pretty_host
        path = flow.request.path
        method = flow.request.method

        if not self._is_allowed(host, path, method):
            # Block the request
            flow.metadata["allowlist_action"] = "BLOCKED"
            url = flow.request.pretty_url
            self._log(f"BLOCKED {method} {url} -> 403")

            # Distinguish method-blocked from host/path-blocked for
            # actionable agent feedback
            if self._is_allowed(host, path):
                message = (
                    f"Method {method} is not allowed for this URL. "
                    "To request access, add the method to the entry's "
                    "'methods' list in "
                    ".airut/network-allowlist.yaml and submit a PR."
                )
            else:
                message = (
                    "This host/path is not in the network allowlist. "
                    "To request access, edit "
                    ".airut/network-allowlist.yaml and submit a PR."
                )

            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "error": "blocked_by_network_allowlist",
                        "host": host,
                        "path": path,
                        "method": method,
                        "message": message,
                    }
                ),
                {"Content-Type": "application/json"},
            )
            return

        # Request is allowed
        flow.metadata["allowlist_action"] = "allowed"

        # If already re-signed in requestheaders(), skip token replacement
        if flow.metadata.get("aws_resigned"):
            return

        # Handle deferred re-signing (non-S3: body hash needed)
        deferred = flow.metadata.pop("aws_deferred_resign", None)
        if deferred is not None:
            # Compute sha256 of actual body
            body = getattr(flow.request, "content", b"") or b""
            if isinstance(body, str):
                body = body.encode("utf-8")
            body_hash = hashlib.sha256(body).hexdigest()
            deferred["content_sha256"] = body_hash
            result = self._perform_resign(flow, deferred)
            if result is not None:
                flow.metadata["aws_resigned"] = True
                flow.metadata["masked_count"] = 1
            return

        replaced = self._replace_tokens(flow)
        flow.metadata["masked_count"] = replaced

    def request_data(self, flow: http.HTTPFlow, data: bytes) -> bytes:
        """Re-sign streaming chunked body data.

        Called per TCP segment when flow.request.stream is True.

        Args:
            flow: The HTTP flow.
            data: Raw body bytes for this segment.

        Returns:
            Re-signed body bytes.
        """
        resigner = flow.metadata.get("chunked_resigner")
        if resigner is None:
            return data

        try:
            return resigner.process(data)
        except (ValueError, ImportError, RuntimeError) as e:
            ctx.log.error(f"Chunked re-signing failed: {e}")
            # On failure, pass through remaining data as-is
            flow.metadata.pop("chunked_resigner", None)
            return data

    def response(self, flow: http.HTTPFlow) -> None:
        """Log allowed requests with their response status."""
        if flow.metadata.get("allowlist_action") != "allowed":
            return

        code = flow.response.status_code if flow.response else "?"
        url = flow.request.pretty_url

        # Append masking info if tokens were replaced
        masked = flow.metadata.get("masked_count", 0)
        suffix = f" [masked: {masked}]" if masked else ""

        # Append region info for AWS re-signed requests
        region = flow.metadata.get("aws_region")
        if region:
            suffix += f" [region: {region}]"

        self._log(f"allowed {flow.request.method} {url} -> {code}{suffix}")

        # Log response body for failed AWS re-signed requests when
        # DEBUG_SIGNING is enabled.  Reveals the specific AWS error
        # type (SignatureDoesNotMatch, AccessDeniedException, etc.).
        if (
            DEBUG_SIGNING
            and flow.metadata.get("aws_resigned")
            and flow.response is not None
            and flow.response.status_code >= 400
        ):
            body = getattr(flow.response, "content", None)
            if body:
                try:
                    text = (
                        body.decode("utf-8")
                        if isinstance(body, bytes)
                        else body
                    )
                    # Truncate to avoid flooding logs
                    if len(text) > 4096:
                        text = text[:4096] + "...(truncated)"
                    self._log(f"aws-error-body: {text}")
                except (UnicodeDecodeError, AttributeError):
                    pass

    def error(self, flow: http.HTTPFlow) -> None:
        """Log upstream connection errors (e.g. DNS resolution failure)."""
        if flow.metadata.get("allowlist_action") != "allowed":
            return

        url = flow.request.pretty_url
        msg = flow.error.msg if flow.error else "unknown error"
        self._log(f"ERROR {flow.request.method} {url} -> {msg}")


addons = [ProxyFilter()]
