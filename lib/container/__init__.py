# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Container execution subsystem.

Manages Claude Code execution in Podman containers, including image builds,
network proxy management, and conversation directory layout.
"""

from lib.container.conversation_layout import (
    ConversationLayout,
    create_conversation_layout,
    get_container_mounts,
    prepare_conversation,
)
from lib.container.dns import (
    SystemResolverError,
    get_system_resolver,
)
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


__all__ = [
    # dns
    "SystemResolverError",
    "get_system_resolver",
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
    # conversation_layout
    "ConversationLayout",
    "create_conversation_layout",
    "get_container_mounts",
    "prepare_conversation",
]
