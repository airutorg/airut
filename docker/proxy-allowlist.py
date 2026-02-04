# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""mitmproxy addon that enforces a network allowlist.

Loads a YAML allowlist from .airut/network-allowlist.yaml and blocks any
HTTP/HTTPS request whose host+path is not in the allowlist.

Blocked requests receive an HTTP 403 response with a JSON body instructing
the agent how to request access.

Supports fnmatch-style wildcards (* and ?) in both domain and path patterns:
- "*.github.com" matches "api.github.com" but NOT "github.com"
- "/api/*" matches "/api/foo" but NOT "/api"
- "/api" matches only "/api" exactly (no implicit prefix matching)

Usage:
    mitmdump -s docker/proxy-allowlist.py
"""

import fnmatch
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

import yaml
from mitmproxy import ctx, http


# Path to optional session log file (mounted by proxy container)
NETWORK_LOG_PATH = Path("/network-sandbox.log")


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


class NetworkAllowlist:
    """mitmproxy addon that enforces a network allowlist."""

    def __init__(self) -> None:
        self.domains: list[str] = []
        self.url_prefixes: list[dict[str, str]] = []
        self._log_file: TextIO | None = None

    def load(self, options: object) -> None:  # noqa: ARG002
        """Load allowlist configuration on startup."""
        self._setup_file_logging()
        self._load_allowlist()

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

    def request(self, flow: http.HTTPFlow) -> None:
        """Check each request against the allowlist."""
        host = flow.request.pretty_host
        path = flow.request.path

        if self._is_allowed(host, path):
            # Mark as allowed for response hook logging
            flow.metadata["allowlist_action"] = "allowed"
            return

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

    def response(self, flow: http.HTTPFlow) -> None:
        """Log allowed requests with their response status."""
        if flow.metadata.get("allowlist_action") != "allowed":
            return
        code = flow.response.status_code if flow.response else "?"
        url = flow.request.pretty_url
        self._log(f"allowed {flow.request.method} {url} -> {code}")


addons = [NetworkAllowlist()]
