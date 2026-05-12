# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared host-pattern matching and allowlist entry shape.

Used by both ``proxy_filter`` and ``tool_domains`` to keep their
matching semantics identical without introducing a circular import.
"""

from __future__ import annotations

import fnmatch
from typing import TypedDict


class UrlPrefixEntry(TypedDict, total=False):
    """A single entry in the ``url_prefixes`` allowlist."""

    host: str
    path: str
    methods: list[str]
    graphql: dict[str, list[str]]


def match_host_pattern(pattern: str, hostname: str) -> bool:
    """Match hostname against pattern, case-insensitively.

    DNS hostnames are case-insensitive per RFC 4343. This function
    performs case-insensitive matching for both exact matches and
    fnmatch patterns.

    Args:
        pattern: Pattern to match against
            (e.g., ``"api.github.com"``, ``"*.github.com"``).
        hostname: Hostname from request (may be any case).

    Returns:
        True if hostname matches pattern case-insensitively.
    """
    pattern_lower = pattern.lower()
    hostname_lower = hostname.lower()
    if "*" in pattern_lower or "?" in pattern_lower:
        return fnmatch.fnmatch(hostname_lower, pattern_lower)
    return pattern_lower == hostname_lower
