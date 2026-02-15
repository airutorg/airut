# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Formatting utilities and data classes for dashboard.

Provides utility functions for formatting timestamps and durations,
plus data classes for version information.
"""

import time
from dataclasses import dataclass


@dataclass
class VersionInfo:
    """Version information captured at service startup.

    Attributes:
        version: Human-readable version string (e.g. "v0.7.0").
            Empty string when no version tag is available.
        git_sha: Short git commit SHA (7-8 characters).
        git_sha_full: Full 40-character git commit SHA.
        worktree_clean: True if working tree was clean at startup.
        full_status: Full git status output for /.version endpoint.
        started_at: Unix timestamp when service started.
    """

    version: str
    git_sha: str
    git_sha_full: str
    worktree_clean: bool
    full_status: str
    started_at: float


def format_duration(seconds: float | None) -> str:
    """Format a duration in human-readable form.

    Args:
        seconds: Duration in seconds, or None.

    Returns:
        Formatted string like "5m 32s" or "-" if None.
    """
    if seconds is None:
        return "-"
    if seconds < 0:
        return "-"

    total_seconds = int(seconds)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    secs = total_seconds % 60

    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_timestamp(ts: float | None) -> str:
    """Format a Unix timestamp as ISO 8601.

    Args:
        ts: Unix timestamp, or None.

    Returns:
        ISO 8601 formatted string or "-" if None.
    """
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
