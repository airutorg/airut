# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Claude session metadata storage for email conversations.

This module provides persistent storage of Claude session metadata (session_id,
usage stats, cost tracking) for email conversations. Each conversation stores
its session history in session.json file outside the workspace.
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


SESSION_FILE_NAME = "session.json"


def _extract_session_id_from_events(events: list[dict[str, Any]]) -> str | None:
    """Extract session_id from init event in events list.

    When Claude execution is interrupted (e.g., by API error 529), the result
    event is never emitted and session_id in the output is empty. However, the
    session_id IS present in the init event. This function extracts it.

    Args:
        events: List of streaming JSON events from Claude execution.

    Returns:
        session_id from init event, or None if not found.
    """
    for event in events:
        if (
            isinstance(event, dict)
            and event.get("type") == "system"
            and event.get("subtype") == "init"
        ):
            session_id = event.get("session_id")
            if session_id and isinstance(session_id, str):
                return session_id
    return None


@dataclass
class SessionReply:
    """Metadata from a single Claude reply.

    Attributes:
        session_id: Claude's session ID for conversation continuity.
        timestamp: ISO 8601 timestamp when reply was received.
        duration_ms: Execution time in milliseconds.
        total_cost_usd: Cumulative cost in USD.
        num_turns: Number of agentic turns.
        is_error: Whether the response was an error.
        usage: Token usage breakdown.
        request_text: The prompt text sent to Claude (optional).
        response_text: Claude's response text (optional).
        events: Full streaming JSON events from Claude execution (optional).
            Each event is a dict with 'type' field (system, assistant, user,
            result).
    """

    session_id: str
    timestamp: str
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    is_error: bool
    usage: dict[str, Any] = field(default_factory=dict)
    request_text: str | None = None
    response_text: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    def get_session_id(self) -> str | None:
        """Get session_id, falling back to init event if top-level is empty.

        When execution completes normally, session_id comes from the result
        event and is stored in self.session_id. But when execution is
        interrupted (e.g., API error 529), there's no result event and
        session_id is empty. In that case, extract it from the init event.

        Returns:
            session_id string, or None if unavailable from any source.
        """
        if self.session_id:
            return self.session_id
        return _extract_session_id_from_events(self.events)


@dataclass
class SessionMetadata:
    """Session metadata for an email conversation.

    Stores the full history of Claude replies for a conversation,
    enabling session resumption and usage tracking.

    Attributes:
        conversation_id: 8-character hex conversation ID.
        replies: List of replies in chronological order.
        model: Claude model to use for this conversation
            (e.g., "opus", "sonnet"). Set via email subaddressing.
    """

    conversation_id: str
    replies: list[SessionReply] = field(default_factory=list)
    model: str | None = None

    @property
    def latest_session_id(self) -> str | None:
        """Get the most recent valid session_id for resumption.

        Walks backwards through replies to find the most recent reply
        with a valid session_id. For each reply, first checks the
        top-level session_id (from result event), then falls back to
        extracting from init event in the events array.

        This handles the case where execution was interrupted by API
        errors (e.g., 529 overloaded): the result event is never emitted
        so top-level session_id is empty, but the init event still has
        the session_id needed for resumption.

        Returns:
            Latest valid session_id, or None if unavailable.
        """
        for reply in reversed(self.replies):
            session_id = reply.get_session_id()
            if session_id:
                return session_id
        return None

    @property
    def total_cost_usd(self) -> float:
        """Get total cost of all replies.

        Returns:
            Sum of total_cost_usd from all replies, or 0.0 if no replies.
        """
        return sum(reply.total_cost_usd for reply in self.replies)

    @property
    def total_turns(self) -> int:
        """Get total number of agentic turns across all replies.

        Returns:
            Sum of num_turns from all replies.
        """
        return sum(reply.num_turns for reply in self.replies)


class SessionStore:
    """Manages session metadata storage for a conversation.

    Reads and writes session.json files outside the workspace directory,
    tracking Claude session IDs for conversation resumption.

    Attributes:
        session_dir: Path to the session directory (contains session.json).
    """

    def __init__(self, session_dir: Path) -> None:
        """Initialize session store for a conversation.

        Args:
            session_dir: Path to session directory (parent of workspace/).
                         Example: /storage/sessions/abc12345/
                         Session file: /storage/sessions/abc12345/session.json
                         Workspace: /storage/sessions/abc12345/workspace/
        """
        self.session_dir = session_dir
        self._file_path = session_dir / SESSION_FILE_NAME

    def load(self) -> SessionMetadata | None:
        """Load session metadata from file.

        Returns:
            SessionMetadata if file exists and is valid, None otherwise.
        """
        if not self._file_path.exists():
            logger.debug("No session file found at %s", self._file_path)
            return None

        try:
            with self._file_path.open("r") as f:
                data = json.load(f)

            replies = [
                SessionReply(
                    session_id=r["session_id"],
                    timestamp=r["timestamp"],
                    duration_ms=r["duration_ms"],
                    total_cost_usd=r["total_cost_usd"],
                    num_turns=r["num_turns"],
                    is_error=r["is_error"],
                    usage=r.get("usage", {}),
                    request_text=r.get("request_text"),
                    response_text=r.get("response_text"),
                    events=r.get("events", []),
                )
                for r in data.get("replies", [])
            ]

            metadata = SessionMetadata(
                conversation_id=data["conversation_id"],
                replies=replies,
                model=data.get("model"),
            )

            logger.debug(
                "Loaded session metadata with %d replies, model=%s, "
                "latest session_id=%s",
                len(replies),
                metadata.model,
                metadata.latest_session_id,
            )
            return metadata

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(
                "Failed to parse session file %s: %s",
                self._file_path,
                e,
            )
            return None

    def save(self, metadata: SessionMetadata) -> None:
        """Save session metadata to file.

        Args:
            metadata: Session metadata to persist.
        """
        data: dict[str, Any] = {
            "conversation_id": metadata.conversation_id,
            "replies": [asdict(reply) for reply in metadata.replies],
        }
        if metadata.model:
            data["model"] = metadata.model

        with self._file_path.open("w") as f:
            json.dump(data, f, indent=2)

        logger.debug(
            "Saved session metadata with %d replies to %s",
            len(metadata.replies),
            self._file_path,
        )

    def update_or_add_reply(
        self,
        conversation_id: str,
        claude_output: dict[str, Any],
        request_text: str | None = None,
        response_text: str | None = None,
    ) -> SessionMetadata:
        """Update the last reply or add a new one if none exists.

        Used for streaming updates: updates the current reply in-place
        rather than creating multiple replies for the same execution.

        When resuming a conversation, this method detects whether we're:
        - Starting a new execution (different request_text) → ADD
        - Continuing to stream the current execution (same) → UPDATE

        Args:
            conversation_id: 8-character hex conversation ID.
            claude_output: Parsed JSON output from claude --output-format json.
            request_text: The prompt text sent to Claude.
            response_text: Claude's response text.

        Returns:
            Updated SessionMetadata.
        """
        # Load or create metadata
        metadata = self.load()
        if metadata is None:
            metadata = SessionMetadata(conversation_id=conversation_id)

        # Extract reply data from Claude output
        reply = SessionReply(
            session_id=claude_output.get("session_id", ""),
            timestamp=datetime.now(UTC).isoformat(),
            duration_ms=claude_output.get("duration_ms", 0),
            total_cost_usd=claude_output.get("total_cost_usd", 0.0),
            num_turns=claude_output.get("num_turns", 0),
            is_error=claude_output.get("is_error", False),
            usage=claude_output.get("usage", {}),
            request_text=request_text,
            response_text=response_text,
            events=claude_output.get("events", []),
        )

        # Determine whether to update or add:
        # - If no replies exist, add new reply
        # - If last reply has same request_text, update it (streaming)
        # - If last reply has different request_text, add new reply (resume)
        should_add = (
            not metadata.replies
            or metadata.replies[-1].request_text != request_text
        )

        if should_add:
            metadata.replies.append(reply)
            logger.info(
                "Added new session reply for conversation %s (%d total)",
                conversation_id,
                len(metadata.replies),
            )
        else:
            metadata.replies[-1] = reply
            logger.debug(
                "Updated session reply for conversation %s: %d events",
                conversation_id,
                len(reply.events),
            )

        self.save(metadata)
        return metadata

    def add_reply(
        self,
        conversation_id: str,
        claude_output: dict[str, Any],
        request_text: str | None = None,
        response_text: str | None = None,
    ) -> SessionMetadata:
        """Record a Claude reply and return updated metadata.

        Loads existing metadata (or creates new), appends the reply,
        and saves to file.

        Args:
            conversation_id: 8-character hex conversation ID.
            claude_output: Parsed JSON output from claude --output-format json.
            request_text: The prompt text sent to Claude.
            response_text: Claude's response text.

        Returns:
            Updated SessionMetadata.
        """
        # Load or create metadata
        metadata = self.load()
        if metadata is None:
            metadata = SessionMetadata(conversation_id=conversation_id)

        # Extract reply data from Claude output
        reply = SessionReply(
            session_id=claude_output.get("session_id", ""),
            timestamp=datetime.now(UTC).isoformat(),
            duration_ms=claude_output.get("duration_ms", 0),
            total_cost_usd=claude_output.get("total_cost_usd", 0.0),
            num_turns=claude_output.get("num_turns", 0),
            is_error=claude_output.get("is_error", False),
            usage=claude_output.get("usage", {}),
            request_text=request_text,
            response_text=response_text,
            events=claude_output.get("events", []),
        )

        metadata.replies.append(reply)
        self.save(metadata)

        logger.info(
            "Recorded session reply for conversation %s: "
            "session_id=%s, cost=$%.4f",
            conversation_id,
            reply.session_id,
            reply.total_cost_usd,
        )

        return metadata

    def get_session_id_for_resume(self) -> str | None:
        """Get session_id to use for --resume flag.

        Convenience method that loads metadata and returns the
        latest session_id, or None if unavailable.

        Returns:
            Session ID string for --resume, or None.
        """
        metadata = self.load()
        if metadata is None:
            return None
        return metadata.latest_session_id

    def get_last_successful_response(self) -> str | None:
        """Get the response text from the last successful (non-error) reply.

        Used for context recovery when a session can no longer be resumed
        (e.g., prompt too long after context compaction).

        Returns:
            Response text from the last successful reply, or None.
        """
        metadata = self.load()
        if metadata is None:
            return None
        for reply in reversed(metadata.replies):
            if not reply.is_error and reply.response_text:
                return reply.response_text
        return None

    def get_model(self) -> str | None:
        """Get the model configured for this conversation.

        Returns:
            Model name string, or None if not set.
        """
        metadata = self.load()
        if metadata is None:
            return None
        return metadata.model

    def set_model(self, conversation_id: str, model: str) -> None:
        """Set the model for this conversation.

        Creates metadata if it doesn't exist, or updates existing.

        Args:
            conversation_id: 8-character hex conversation ID.
            model: Model name (e.g., "opus", "sonnet").
        """
        metadata = self.load()
        if metadata is None:
            metadata = SessionMetadata(conversation_id=conversation_id)
        metadata.model = model
        self.save(metadata)
        logger.info("Set model=%s for conversation %s", model, conversation_id)
