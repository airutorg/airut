# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Conversation directory layout, preparation, and metadata storage.

Manages the per-conversation directory structure (workspace, inbox, outbox,
storage, Claude session state) and generates container mount configuration.

Also provides ConversationStore for conversation metadata persistence
(model, reply summaries, session IDs for resumption).
"""

from airut.conversation.conversation_layout import (
    ConversationLayout,
    create_conversation_layout,
    get_container_mounts,
    prepare_conversation,
)
from airut.conversation.conversation_store import (
    CONVERSATION_FILE_NAME,
    ConversationMetadata,
    ConversationStore,
    ReplySummary,
)


__all__ = [
    "ConversationLayout",
    "create_conversation_layout",
    "get_container_mounts",
    "prepare_conversation",
    "CONVERSATION_FILE_NAME",
    "ConversationMetadata",
    "ConversationStore",
    "ReplySummary",
]
