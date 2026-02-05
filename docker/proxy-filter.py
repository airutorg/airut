# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""mitmproxy addon for network allowlist and token masking.

Enforces a network allowlist and performs token replacement for masked
secrets. Blocked requests receive an HTTP 403 response. Allowed requests
have masked secret surrogates swapped for real values when the host matches
the secret's scope.

Token replacement handles both direct tokens (e.g., Bearer tokens) and
Base64-encoded credentials (e.g., Basic Auth). For Basic Auth, the addon
decodes the credential, performs replacement, and re-encodes.

Supports fnmatch-style wildcards (* and ?) in both domain and path patterns:
- "*.github.com" matches "api.github.com" but NOT "github.com"
- "/api/*" matches "/api/foo" but NOT "/api"
- "/api" matches only "/api" exactly (no implicit prefix matching)

Usage:
    mitmdump -s docker/proxy-filter.py
"""

import base64
import fnmatch
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

import yaml
from mitmproxy import ctx, http


# Path to optional session log file (mounted by proxy container)
NETWORK_LOG_PATH = Path("/network-sandbox.log")

# Path to replacement map (mounted by proxy container)
REPLACEMENTS_PATH = Path("/replacements.json")


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
        self.url_prefixes: list[dict[str, str]] = []
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

    def _is_allowed(self, host: str, path: str) -> bool:
        """Check if a host+path combination is allowed.

        Uses fnmatch-style pattern matching for both domains and paths.
        Patterns containing * or ? are matched with fnmatch; others require
        exact match.

        Args:
            host: Request hostname (e.g. "api.github.com").
            path: Request path (e.g. "/repos/your-org/your-repo/pulls").

        Returns:
            True if the request is allowed, False otherwise.
        """
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

    def request(self, flow: http.HTTPFlow) -> None:
        """Check allowlist and perform token replacement."""
        host = flow.request.pretty_host
        path = flow.request.path

        if not self._is_allowed(host, path):
            # Block the request
            flow.metadata["allowlist_action"] = "BLOCKED"
            url = flow.request.pretty_url
            self._log(f"BLOCKED {flow.request.method} {url} -> 403")
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "error": "blocked_by_network_allowlist",
                        "host": host,
                        "path": path,
                        "message": (
                            "This host is not in the network allowlist. "
                            "To request access, edit "
                            ".airut/network-allowlist.yaml and submit a PR."
                        ),
                    }
                ),
                {"Content-Type": "application/json"},
            )
            return

        # Request is allowed - perform token replacement
        flow.metadata["allowlist_action"] = "allowed"
        replaced = self._replace_tokens(flow)
        flow.metadata["masked_count"] = replaced

    def response(self, flow: http.HTTPFlow) -> None:
        """Log allowed requests with their response status."""
        if flow.metadata.get("allowlist_action") != "allowed":
            return

        code = flow.response.status_code if flow.response else "?"
        url = flow.request.pretty_url

        # Append masking info if tokens were replaced
        masked = flow.metadata.get("masked_count", 0)
        suffix = f" [masked: {masked}]" if masked else ""

        self._log(f"allowed {flow.request.method} {url} -> {code}{suffix}")


addons = [ProxyFilter()]
