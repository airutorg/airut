# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Container utilities for conversation layout and DNS resolution.

Provides conversation directory layout management and system DNS
resolver detection. Container execution, proxy management, session
persistence, and network sandbox are in ``lib/sandbox/``.
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


__all__ = [
    # dns
    "SystemResolverError",
    "get_system_resolver",
    # conversation_layout
    "ConversationLayout",
    "create_conversation_layout",
    "get_container_mounts",
    "prepare_conversation",
]
