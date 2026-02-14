# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Claude session metadata storage.

Provides persistent storage of Claude session metadata (session_id,
usage stats, cost tracking). Each execution context stores its session
history in context.json inside the session directory.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lib.claude_output import (
    StreamEvent,
    extract_result_summary,
    extract_session_id,
    parse_event_dict,
)
from lib.claude_output.types import _KNOWN_USAGE_KEYS, Usage


logger = logging.getLogger(__name__)


SESSION_FILE_NAME = "context.json"


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
        events: Typed streaming events from Claude execution.
    """

    session_id: str
    timestamp: str
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    is_error: bool
    usage: Usage = field(default_factory=Usage)
    request_text: str | None = None
    response_text: str | None = None
    events: list[StreamEvent] = field(default_factory=list)

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
        return extract_session_id(self.events)


@dataclass
class SessionMetadata:
    """Session metadata for an execution context.

    Stores the full history of Claude replies for an execution context,
    enabling session resumption and usage tracking.

    Attributes:
        execution_context_id: Execution context identifier.
        replies: List of replies in chronological order.
        model: Claude model to use for this execution context.
    """

    execution_context_id: str
    replies: list[SessionReply] = field(default_factory=list)
    model: str | None = None

    @property
    def latest_session_id(self) -> str | None:
        """Get the most recent valid session_id for resumption.

        Walks backwards through replies to find the most recent reply
        with a valid session_id. For each reply, first checks the
        top-level session_id (from result event), then falls back to
        extracting from init event in the events array.

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
    """Manages session metadata storage for an execution context.

    Reads and writes context.json files in the session directory,
    tracking Claude session IDs for session resumption.

    Attributes:
        session_dir: Path to the session directory (contains context.json).
    """

    def __init__(self, session_dir: Path) -> None:
        """Initialize session store for an execution context.

        Args:
            session_dir: Path to session directory. Session file stored
                as context.json in this directory.
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
                    usage=_deserialize_usage(r.get("usage", {})),
                    request_text=r.get("request_text"),
                    response_text=r.get("response_text"),
                    events=_deserialize_events(r.get("events", [])),
                )
                for r in data.get("replies", [])
            ]

            ctx_id = data.get("execution_context_id", "")

            metadata = SessionMetadata(
                execution_context_id=ctx_id,
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
            "execution_context_id": metadata.execution_context_id,
            "replies": [_serialize_reply(reply) for reply in metadata.replies],
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
        execution_context_id: str,
        events: list[StreamEvent],
        *,
        request_text: str | None = None,
        response_text: str | None = None,
        is_error: bool | None = None,
    ) -> SessionMetadata:
        """Update the last reply or add a new one if none exists.

        Used for streaming updates: updates the current reply in-place
        rather than creating multiple replies for the same execution.

        When resuming an execution context, this method detects whether
        we're:
        - Starting a new execution (different request_text) -> ADD
        - Continuing to stream the current execution (same) -> UPDATE

        Args:
            execution_context_id: Execution context identifier.
            events: Typed streaming events from Claude execution.
            request_text: The prompt text sent to Claude.
            response_text: Claude's response text.
            is_error: Override error flag (used when no result event).

        Returns:
            Updated SessionMetadata.
        """
        # Load or create metadata
        metadata = self.load()
        if metadata is None:
            metadata = SessionMetadata(
                execution_context_id=execution_context_id
            )

        reply = _build_reply(
            events,
            request_text=request_text,
            response_text=response_text,
            is_error=is_error,
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
                "Added new session reply for context %s (%d total)",
                execution_context_id,
                len(metadata.replies),
            )
        else:
            metadata.replies[-1] = reply
            logger.debug(
                "Updated session reply for context %s: %d events",
                execution_context_id,
                len(reply.events),
            )

        self.save(metadata)
        return metadata

    def add_reply(
        self,
        execution_context_id: str,
        events: list[StreamEvent],
        *,
        request_text: str | None = None,
        response_text: str | None = None,
        is_error: bool | None = None,
    ) -> SessionMetadata:
        """Record a Claude reply and return updated metadata.

        Loads existing metadata (or creates new), appends the reply,
        and saves to file.

        Args:
            execution_context_id: Execution context identifier.
            events: Typed streaming events from Claude execution.
            request_text: The prompt text sent to Claude.
            response_text: Claude's response text.
            is_error: Override error flag (used when no result event).

        Returns:
            Updated SessionMetadata.
        """
        # Load or create metadata
        metadata = self.load()
        if metadata is None:
            metadata = SessionMetadata(
                execution_context_id=execution_context_id
            )

        reply = _build_reply(
            events,
            request_text=request_text,
            response_text=response_text,
            is_error=is_error,
        )

        metadata.replies.append(reply)
        self.save(metadata)

        logger.info(
            "Recorded session reply for context %s: session_id=%s, cost=$%.4f",
            execution_context_id,
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
        """Get the model configured for this execution context.

        Returns:
            Model name string, or None if not set.
        """
        metadata = self.load()
        if metadata is None:
            return None
        return metadata.model

    def set_model(self, execution_context_id: str, model: str) -> None:
        """Set the model for this execution context.

        Creates metadata if it doesn't exist, or updates existing.

        Args:
            execution_context_id: Execution context identifier.
            model: Model name (e.g., "opus", "sonnet").
        """
        metadata = self.load()
        if metadata is None:
            metadata = SessionMetadata(
                execution_context_id=execution_context_id
            )
        metadata.model = model
        self.save(metadata)
        logger.info("Set model=%s for context %s", model, execution_context_id)


def _build_reply(
    events: list[StreamEvent],
    *,
    request_text: str | None = None,
    response_text: str | None = None,
    is_error: bool | None = None,
) -> SessionReply:
    """Build a SessionReply from typed events.

    Extracts metadata from the result event if present, otherwise uses
    defaults.

    Args:
        events: Typed streaming events from Claude execution.
        request_text: The prompt text sent to Claude.
        response_text: Claude's response text.
        is_error: Override error flag (used when no result event).

    Returns:
        Populated SessionReply.
    """
    summary = extract_result_summary(events)
    if summary is not None:
        return SessionReply(
            session_id=summary.session_id,
            timestamp=datetime.now(UTC).isoformat(),
            duration_ms=summary.duration_ms,
            total_cost_usd=summary.total_cost_usd,
            num_turns=summary.num_turns,
            is_error=is_error if is_error is not None else summary.is_error,
            usage=summary.usage,
            request_text=request_text,
            response_text=response_text,
            events=events,
        )

    # No result event -- use session_id from init if available
    session_id = extract_session_id(events) or ""
    return SessionReply(
        session_id=session_id,
        timestamp=datetime.now(UTC).isoformat(),
        duration_ms=0,
        total_cost_usd=0.0,
        num_turns=0,
        is_error=is_error if is_error is not None else True,
        usage=Usage(),
        request_text=request_text,
        response_text=response_text,
        events=events,
    )


def _serialize_reply(reply: SessionReply) -> dict[str, Any]:
    """Serialize a SessionReply to a JSON-compatible dict."""
    return {
        "session_id": reply.session_id,
        "timestamp": reply.timestamp,
        "duration_ms": reply.duration_ms,
        "total_cost_usd": reply.total_cost_usd,
        "num_turns": reply.num_turns,
        "is_error": reply.is_error,
        "usage": {
            "input_tokens": reply.usage.input_tokens,
            "output_tokens": reply.usage.output_tokens,
            "cache_creation_input_tokens": (
                reply.usage.cache_creation_input_tokens
            ),
            "cache_read_input_tokens": reply.usage.cache_read_input_tokens,
            **reply.usage.extra,
        },
        "request_text": reply.request_text,
        "response_text": reply.response_text,
        "events": [json.loads(e.raw) for e in reply.events],
    }


def _deserialize_events(raw_events: list[Any]) -> list[StreamEvent]:
    """Deserialize a list of raw event dicts into typed StreamEvents."""
    events: list[StreamEvent] = []
    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        event = parse_event_dict(raw)
        if event is not None:
            events.append(event)
    return events


def _deserialize_usage(raw_usage: Any) -> Usage:
    """Deserialize a usage dict into a typed Usage."""
    if not isinstance(raw_usage, dict):
        return Usage()
    return Usage(
        input_tokens=raw_usage.get("input_tokens", 0),
        output_tokens=raw_usage.get("output_tokens", 0),
        cache_creation_input_tokens=raw_usage.get(
            "cache_creation_input_tokens", 0
        ),
        cache_read_input_tokens=raw_usage.get("cache_read_input_tokens", 0),
        extra={
            k: v for k, v in raw_usage.items() if k not in _KNOWN_USAGE_KEYS
        },
    )
