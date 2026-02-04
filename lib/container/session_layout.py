# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Session directory layout and preparation for Airut email gateway.

Manages the directory structure for each conversation session and generates
the container mount configuration. All session-specific directories (claude
state, inbox, outbox) live outside the git workspace to keep it clean.

Layout::

    sessions/{id}/              # session_dir
      session.json              # host-only metadata (not mounted)
      workspace/                # git clone
      claude/                   # claude session state
      inbox/                    # email attachments
      outbox/                   # files to send back via email
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SessionLayout:
    """Paths for a conversation session directory.

    All paths are derived from ``session_dir``. The workspace is a git
    checkout; all other directories live alongside it in the session
    directory to avoid polluting the git repo.
    """

    session_dir: Path
    workspace: Path
    claude: Path
    inbox: Path
    outbox: Path


def create_session_layout(session_dir: Path) -> SessionLayout:
    """Derive all session paths from a session directory.

    Args:
        session_dir: Root directory for this conversation session.

    Returns:
        SessionLayout with all paths populated.
    """
    return SessionLayout(
        session_dir=session_dir,
        workspace=session_dir / "workspace",
        claude=session_dir / "claude",
        inbox=session_dir / "inbox",
        outbox=session_dir / "outbox",
    )


def prepare_session(layout: SessionLayout) -> None:
    """Create directories for a session.

    Creates the claude, inbox, and outbox directories. Does NOT create
    the workspace directory (that is the git clone's responsibility).

    Args:
        layout: Session layout with all paths.
    """
    for directory in [
        layout.claude,
        layout.inbox,
        layout.outbox,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug("Created/verified directory: %s", directory)


def get_container_mounts(layout: SessionLayout) -> list[str]:
    """Return podman volume mount strings for a session.

    Args:
        layout: Session layout with all paths.

    Returns:
        List of volume mount strings for podman ``-v`` flags.
    """
    return [
        f"{layout.workspace}:/workspace:rw",
        f"{layout.claude}:/root/.claude:rw",
        f"{layout.inbox}:/inbox:rw",
        f"{layout.outbox}:/outbox:rw",
    ]
