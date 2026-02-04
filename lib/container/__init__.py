# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Container execution subsystem.

Manages Claude Code execution in Podman containers, including image builds,
network proxy management, and session storage layout.
"""

from lib.container.executor import (
    ClaudeExecutor,
    ContainerTimeoutError,
    ExecutionResult,
    ExecutorError,
    ImageBuildError,
    JSONParseError,
    extract_error_summary,
)
from lib.container.network import get_network_args
from lib.container.proxy import (
    ProxyError,
    ProxyManager,
    TaskProxy,
)
from lib.container.session import (
    SessionMetadata,
    SessionReply,
    SessionStore,
)
from lib.container.session_layout import (
    SessionLayout,
    create_session_layout,
    get_container_mounts,
    prepare_session,
)


__all__ = [
    # executor
    "ClaudeExecutor",
    "ContainerTimeoutError",
    "ExecutionResult",
    "ExecutorError",
    "ImageBuildError",
    "JSONParseError",
    "extract_error_summary",
    # network
    "get_network_args",
    # proxy
    "ProxyError",
    "ProxyManager",
    "TaskProxy",
    # session
    "SessionMetadata",
    "SessionReply",
    "SessionStore",
    # session_layout
    "SessionLayout",
    "create_session_layout",
    "get_container_mounts",
    "prepare_session",
]
