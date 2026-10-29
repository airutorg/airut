# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Outbox cleanup after a reply is delivered.

Delivered files are deleted so they are not sent again with later
replies.  Files the channel could not deliver are set aside in storage
instead, and named to the agent with the next message.
"""

import logging

from airut.conversation import (
    UNDELIVERED_DIR,
    ConversationLayout,
    ConversationStore,
    clear_outbox,
    set_aside_undelivered,
)
from airut.gateway.channel import UndeliveredFile


logger = logging.getLogger(__name__)


def finish_delivery(
    layout: ConversationLayout,
    conversation_id: str,
    undelivered: list[UndeliveredFile],
) -> None:
    """Set aside the outbox files a reply did not deliver; clear the rest.

    Files the channel could not deliver move to ``storage/undelivered/``
    and are recorded, so the next message in the conversation tells the
    agent (see ``undelivered_note``).  Everything else in the outbox went
    out and is deleted.

    Args:
        layout: Conversation layout.
        conversation_id: Conversation the reply belongs to.
        undelivered: Outbox files the channel did not deliver.
    """
    moved = set_aside_undelivered(layout, [f.path for f in undelivered])
    files = {moved[f.path]: f.reason for f in undelivered if f.path in moved}
    if files:
        store = ConversationStore(layout.conversation_dir)
        try:
            store.record_undelivered(conversation_id, files)
        except OSError as e:
            # The reply is out; the files are still in storage even if
            # the agent will not be told about them.
            logger.warning("Failed to record undelivered files: %s", e)
    clear_outbox(layout.outbox)


def undelivered_note(files: dict[str, str]) -> str:
    """Render the prompt note about files a previous reply set aside.

    Args:
        files: Reason each file was not delivered, by its name in
            ``storage/undelivered/``.

    Returns:
        The note, starting with a space to follow the channel context.
    """
    listed = ", ".join(f"{name} ({reason})" for name, reason in files.items())
    return (
        " Some files you left in /outbox last time did not reach the "
        f"user, so I have moved them to /storage/{UNDELIVERED_DIR}/: "
        f"{listed}."
    )
