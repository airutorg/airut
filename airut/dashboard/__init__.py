# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Dashboard subsystem for monitoring tasks.

Provides a web-based dashboard for viewing task queue status, execution
progress, and completed task history.
"""

from airut.dashboard.formatters import (
    VersionInfo,
    format_duration,
    format_timestamp,
)
from airut.dashboard.server import DashboardServer
from airut.dashboard.sse import SSEConnectionManager
from airut.dashboard.tracker import (
    BootPhase,
    BootState,
    ChannelInfo,
    RepoState,
    RepoStatus,
    TaskState,
    TaskStatus,
    TaskTracker,
)
from airut.dashboard.versioned import (
    VersionClock,
    Versioned,
    VersionedStore,
)


__all__ = [
    "BootPhase",
    "BootState",
    "ChannelInfo",
    "DashboardServer",
    "RepoState",
    "RepoStatus",
    "SSEConnectionManager",
    "TaskState",
    "TaskStatus",
    "TaskTracker",
    "Versioned",
    "VersionClock",
    "VersionInfo",
    "VersionedStore",
    "format_duration",
    "format_timestamp",
]
