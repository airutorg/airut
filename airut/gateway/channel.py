# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Channel adapter protocol and message types.

Defines the interface between the protocol-agnostic gateway core and
channel-specific implementations (email, Slack, etc.).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


class AuthenticationError(Exception):
    """Raised when authentication or authorization fails.

    Carries structured information about the failure so the gateway
    core can update the task tracker without protocol-specific knowledge.

    Attributes:
        sender: Raw sender identifier (e.g. email From header) for
            dashboard visibility.  May be empty if the sender could
            not be determined.
        reason: Human-readable rejection reason (e.g. "DMARC
            verification failed", "sender not authorized").
    """

    def __init__(self, *, sender: str = "", reason: str = "") -> None:
        self.sender = sender
        self.reason = reason
        super().__init__(reason or "authentication failed")


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

    display_title: str = ""
    """Short display title for the task tracker (e.g. email subject line,
    first line of Slack message).

    Shown on the dashboard to identify the task. If empty, the tracker
    falls back to a generic placeholder."""

    channel_context: str = ""
    """Channel-specific context instructions prepended to the prompt.
    E.g., 'User is interacting via email interface...'"""


@dataclass
class RawMessage[ContentT]:
    """Channel-agnostic raw message envelope.

    Wraps a channel-specific payload with standard metadata that the
    gateway core can use before authentication completes (e.g. for
    task tracker display).

    Type parameter ``ContentT`` is the channel-specific payload type
    (e.g. ``email.message.Message`` for email). The gateway core uses
    ``RawMessage[Any]``; channel adapters narrow to their concrete type.

    Attributes:
        sender: Raw sender identity as presented by the channel
            (e.g. email From header, Slack user ID). Not yet verified.
        content: Channel-specific payload (e.g. ``email.message.Message``).
        display_title: Optional display title (e.g. email subject line).
            Used by the task tracker before authentication completes.
            Falls back to a truncated ``sender`` if empty.
    """

    sender: str
    content: ContentT
    display_title: str = ""


class ChannelHealth(Enum):
    """Health state of a channel listener.

    Attributes:
        STARTING: Not yet connected.
        CONNECTED: Healthy, receiving messages.
        DEGRADED: Temporarily lost connection, internally retrying.
        FAILED: Hard failure, will not retry.
    """

    STARTING = "starting"
    CONNECTED = "connected"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass(frozen=True)
class ChannelStatus:
    """Current status of a channel listener.

    Attributes:
        health: Current health state.
        message: Human-readable status description
            (e.g. "IMAP reconnecting (attempt 2/5)").
        error_type: Exception type name if degraded or failed.
    """

    health: ChannelHealth
    message: str = ""
    error_type: str | None = None


class ChannelConfig(Protocol):
    """Interface for channel-specific configuration.

    Channel config implementations must provide ``channel_type`` and
    ``channel_info`` properties so the gateway core and dashboard can
    identify and display channels without protocol-specific knowledge.
    """

    @property
    def channel_type(self) -> str:
        """Return the channel type identifier (e.g. ``"email"``)."""
        ...

    @property
    def channel_info(self) -> str:
        """Return a short description for dashboard display."""
        ...


class ChannelListener(Protocol):
    """Interface for channel-specific message listening.

    Implementations manage their own threads and connection lifecycle.
    ``start()`` may block for initial connection setup, then runs the
    message loop in a background thread. ``stop()`` blocks until
    shutdown is complete.
    """

    def start(self, submit: Callable[[RawMessage[Any]], bool]) -> None:
        """Connect to the channel and start the listener thread.

        Initial connection is synchronous and may block (e.g. IMAP
        connect with retries). The polling/IDLE loop runs in a
        background thread after the connection succeeds.

        Args:
            submit: Callback to invoke with each RawMessage. Returns
                True if the message was accepted for processing.

        Raises:
            Exception: If the initial connection fails.
        """
        ...

    def stop(self) -> None:
        """Stop listening and release all resources.

        Blocks until internal threads have terminated.
        """
        ...

    @property
    def status(self) -> ChannelStatus:
        """Current health of this listener."""
        ...


class ChannelAdapter(Protocol):
    """Interface for channel-specific message handling.

    Implementations handle authentication, parsing, response delivery,
    and message listening for a specific messaging protocol (email,
    Slack, etc.).
    """

    @property
    def listener(self) -> ChannelListener:
        """Channel listener for message lifecycle management."""
        ...

    def authenticate_and_parse(
        self, raw_message: RawMessage[Any]
    ) -> ParsedMessage:
        """Authenticate the sender and parse the message.

        Returns a ParsedMessage if authentication and authorization
        succeed.

        Raises:
            AuthenticationError: If authentication or authorization
                fails. The exception carries ``sender`` (raw sender
                identity for dashboard visibility) and ``reason``
                (human-readable rejection reason).

        This combines authentication, authorization, and parsing into
        a single call because the details are deeply protocol-specific
        (DMARC headers, MIME structure, Slack request signatures, etc.)
        and there's no benefit to the core knowing about these
        intermediate steps.
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

        Called when the per-conversation pending queue is full and the
        message cannot be accepted.
        """
        ...

    def cleanup_conversations(self, active_conversation_ids: set[str]) -> None:
        """Remove adapter state for conversations not in the active set.

        Called by the garbage collector after pruning old conversations.
        Adapters that maintain per-conversation state (e.g. thread
        mappings) should discard entries referencing conversation IDs
        not present in *active_conversation_ids*.

        Adapters without per-conversation state may implement this as
        a no-op.

        Args:
            active_conversation_ids: Conversation IDs that still exist.
                Any adapter state referencing IDs outside this set
                should be cleaned up.
        """
        ...
