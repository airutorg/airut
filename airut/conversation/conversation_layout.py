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
      conversation.json         # host-only metadata (not mounted)
      events.jsonl              # append-only event log (not mounted)
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


def write_inbox_file(inbox_dir: Path, safe_name: str, data: bytes) -> Path:
    """Save an attachment in *inbox_dir* without overwriting anything.

    Channels save attachments into a shared inbox directory.  When two
    files carry the same name — within one message, across a coalesced
    burst, across replayed thread history, or across conversation turns —
    a direct write would silently clobber the earlier file and lose data.
    The file is created exclusively instead, inserting a ``-N`` counter
    before the extension until a free name is found, so every attachment
    is preserved.

    Exclusive creation also means nothing already at a path is written
    through, in particular a symlink, even a dangling one: the inbox is
    writable from the container, and writing through a link the task
    planted would create a file wherever it points on the host.

    Args:
        inbox_dir: Directory to save the file in (must exist).
        safe_name: Sanitized basename (caller is responsible for stripping
            path components and rejecting traversal sequences).
        data: File content.

    Returns:
        The path the file was saved to.

    Raises:
        OSError: If the file cannot be written for any other reason.
    """
    stem = Path(safe_name).stem
    suffix = Path(safe_name).suffix
    candidate = inbox_dir / safe_name
    counter = 0
    while True:
        try:
            with open(candidate, "xb") as f:
                f.write(data)
            return candidate
        except FileExistsError:
            counter += 1
            candidate = inbox_dir / f"{stem}-{counter}{suffix}"


def list_outbox_files(outbox_dir: Path) -> list[Path]:
    """Return the deliverable files in *outbox_dir*, ordered by name.

    Only regular files in the outbox root are deliverable — channels send
    flat files — so sub-directories are skipped.  Sorting keeps
    attachment order stable instead of following directory order.

    Symlinks are skipped too: the gateway resolves them on the host,
    where the same path means something different than it did inside the
    container, so a link is either dangling or points at a host file the
    conversation was never given (a symlink to the server config would
    otherwise be delivered verbatim).

    Args:
        outbox_dir: Conversation outbox directory (need not exist).

    Returns:
        Paths of the files to deliver, empty if there are none.
    """
    if not outbox_dir.exists():
        return []
    files: list[Path] = []
    for path in outbox_dir.iterdir():
        if path.is_symlink():
            logger.warning("Skipping symlink in outbox: %s", path)
            continue
        if path.is_file():
            files.append(path)
    return sorted(files)


def clear_outbox(outbox_dir: Path) -> None:
    """Delete the outbox entries once the reply has been delivered.

    Called by the gateway after a channel adapter has delivered a reply,
    so the outbox — which lives as long as the conversation — does not
    hand the same files to the next turn.  Removes everything
    :func:`list_outbox_files` offered for delivery plus the symlinks it
    refused (which would otherwise be re-reported every turn);
    sub-directories are left alone.  Unlink failures are logged rather
    than raised, since a file that cannot be removed is not worth
    failing a delivered reply over.

    Args:
        outbox_dir: Conversation outbox directory (need not exist).
    """
    if not outbox_dir.exists():
        return
    removed = 0
    for path in outbox_dir.iterdir():
        # Only a real directory is kept; a symlink to one is unlinked
        # (which removes the link, never the target).
        if path.is_dir() and not path.is_symlink():
            continue
        try:
            path.unlink()
        except OSError as e:
            logger.warning("Failed to delete outbox file %s: %s", path, e)
        else:
            removed += 1
    if removed:
        logger.info("Cleared %d file(s) from outbox %s", removed, outbox_dir)


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
