# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Dashboard subsystem for monitoring tasks.

Provides a web-based dashboard for viewing task queue status, execution
progress, and completed task history.
"""

from lib.dashboard.formatters import (
    VersionInfo,
    format_duration,
    format_timestamp,
)
from lib.dashboard.server import DashboardServer
from lib.dashboard.tracker import (
    BootPhase,
    BootState,
    RepoState,
    RepoStatus,
    TaskState,
    TaskStatus,
    TaskTracker,
)


__all__ = [
    "BootPhase",
    "BootState",
    "DashboardServer",
    "RepoState",
    "RepoStatus",
    "TaskState",
    "TaskStatus",
    "TaskTracker",
    "VersionInfo",
    "format_duration",
    "format_timestamp",
]
