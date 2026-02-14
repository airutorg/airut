# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Conversation directory layout and preparation.

Manages the per-conversation directory structure (workspace, inbox, outbox,
storage, Claude session state) and generates container mount configuration.
"""

from lib.conversation.conversation_layout import (
    ConversationLayout,
    create_conversation_layout,
    get_container_mounts,
    prepare_conversation,
)


__all__ = [
    "ConversationLayout",
    "create_conversation_layout",
    "get_container_mounts",
    "prepare_conversation",
]
