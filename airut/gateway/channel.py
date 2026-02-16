# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Channel adapter protocol and message types.

Defines the interface between the protocol-agnostic gateway core and
channel-specific implementations (email, Slack, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class ParsedMessage:
    """Protocol-agnostic parsed message.

    Produced by the channel adapter after authentication and parsing.
    The core processes this without knowing the underlying protocol.
    """

    sender: str
    """Authenticated sender identifier (email address, Slack user ID, etc.)."""

    body: str
    """Extracted message body (quotes stripped, markup converted)."""

    conversation_id: str | None
    """Existing conversation ID if this is a reply.

    None for new conversations."""

    model_hint: str | None
    """Model override from the channel (subaddressing, command, etc.).

    Only used for new conversations; ignored on resume."""

    attachments: list[str] = field(default_factory=list)
    """Filenames of attachments saved to the inbox directory by the adapter.

    The adapter writes attachment files to the conversation's inbox directory
    during authenticate_and_parse(). These files persist across conversation
    turns as part of the conversation state (the inbox directory is mounted
    into the container at /inbox). No cleanup is needed -- files accumulate
    naturally and are garbage-collected with the conversation."""

    channel_context: str = ""
    """Channel-specific context instructions prepended to the prompt.
    E.g., 'User is interacting via email interface...'"""


class ChannelAdapter(Protocol):
    """Interface for channel-specific message handling.

    Implementations handle authentication, parsing, and response delivery
    for a specific messaging protocol (email, Slack, etc.).
    """

    def authenticate_and_parse(self, raw_message: Any) -> ParsedMessage | None:
        """Authenticate the sender and parse the message.

        Returns a ParsedMessage if authentication and authorization succeed,
        or None if the message should be rejected (with appropriate logging).

        This combines authentication, authorization, and parsing into a single
        call because the details are deeply protocol-specific (DMARC headers,
        MIME structure, Slack request signatures, etc.) and there's no benefit
        to the core knowing about these intermediate steps.
        """
        ...

    def save_attachments(
        self, parsed: ParsedMessage, inbox_dir: Path
    ) -> list[str]:
        """Save message attachments to the inbox directory.

        Called by the core after the conversation layout is created,
        when the inbox directory is available. The adapter extracts
        attachments from whatever internal state it retains and writes
        them to ``inbox_dir``.

        Args:
            parsed: The parsed message (may be a channel-specific subclass).
            inbox_dir: Path to save attachments to.

        Returns:
            List of saved filenames (empty if no attachments).
        """
        ...

    def send_acknowledgment(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        model: str,
        dashboard_url: str | None,
    ) -> None:
        """Send a 'working on it' notification to the user."""
        ...

    def send_reply(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        response_text: str,
        usage_footer: str,
        outbox_files: list[Path],
    ) -> None:
        """Send the final response with optional file attachments."""
        ...

    def send_error(
        self,
        parsed: ParsedMessage,
        conversation_id: str | None,
        error_message: str,
    ) -> None:
        """Send an error notification to the user."""
        ...

    def send_rejection(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        reason: str,
        dashboard_url: str | None,
    ) -> None:
        """Send a rejection notification when a message cannot be processed.

        Called when a duplicate message arrives for a conversation that
        already has an active task.
        """
        ...
