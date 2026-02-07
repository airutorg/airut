# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Conversation directory layout and preparation for Airut email gateway.

Manages the directory structure for each conversation and generates
the container mount configuration. All conversation-specific directories
(claude state, inbox, outbox, storage) live outside the git workspace to
keep it clean.

Layout::

    conversations/{id}/         # conversation_dir
      session.json              # host-only metadata (not mounted)
      workspace/                # git clone
      claude/                   # claude session state
      inbox/                    # email attachments
      outbox/                   # files to send back via email
      storage/                  # conversation-scoped persistent storage
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConversationLayout:
    """Paths for a conversation directory.

    All paths are derived from ``conversation_dir``. The workspace is a git
    checkout; all other directories live alongside it in the conversation
    directory to avoid polluting the git repo.
    """

    conversation_dir: Path
    workspace: Path
    claude: Path
    inbox: Path
    outbox: Path
    storage: Path


def create_conversation_layout(conversation_dir: Path) -> ConversationLayout:
    """Derive all conversation paths from a conversation directory.

    Args:
        conversation_dir: Root directory for this conversation.

    Returns:
        ConversationLayout with all paths populated.
    """
    return ConversationLayout(
        conversation_dir=conversation_dir,
        workspace=conversation_dir / "workspace",
        claude=conversation_dir / "claude",
        inbox=conversation_dir / "inbox",
        outbox=conversation_dir / "outbox",
        storage=conversation_dir / "storage",
    )


def prepare_conversation(layout: ConversationLayout) -> None:
    """Create directories for a conversation.

    Creates the claude, inbox, outbox, and storage directories. Does NOT
    create the workspace directory (that is the git clone's responsibility).

    Args:
        layout: Conversation layout with all paths.
    """
    for directory in [
        layout.claude,
        layout.inbox,
        layout.outbox,
        layout.storage,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug("Created/verified directory: %s", directory)


def get_container_mounts(layout: ConversationLayout) -> list[str]:
    """Return podman volume mount strings for a conversation.

    Args:
        layout: Conversation layout with all paths.

    Returns:
        List of volume mount strings for podman ``-v`` flags.
    """
    return [
        f"{layout.workspace}:/workspace:rw",
        f"{layout.claude}:/root/.claude:rw",
        f"{layout.inbox}:/inbox:rw",
        f"{layout.outbox}:/outbox:rw",
        f"{layout.storage}:/storage:rw",
    ]
