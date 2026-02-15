# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Conversation metadata storage.

Provides persistent storage of conversation metadata (model, reply summaries,
session IDs for resumption). Each conversation stores its metadata in
conversation.json inside the conversation directory.

This module does NOT store raw streaming events — those live in events.jsonl,
managed by the sandbox's EventLog.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lib.claude_output.types import _KNOWN_USAGE_KEYS, Usage


logger = logging.getLogger(__name__)


CONVERSATION_FILE_NAME = "conversation.json"


@dataclass
class ReplySummary:
    """Metadata from a single Claude reply.

    Contains summary data extracted from execution results. Does not
    contain raw streaming events (those are in events.jsonl).

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


@dataclass
class ConversationMetadata:
    """Conversation-level state.

    Stores the full history of reply summaries for a conversation,
    enabling session resumption and usage tracking.

    Attributes:
        conversation_id: Conversation identifier.
        replies: List of reply summaries in chronological order.
        model: Claude model to use for this conversation.
        pending_request_text: Prompt text for a reply that is currently
            being executed. Set before execution starts so the dashboard
            can display it; cleared when the reply completes.
    """

    conversation_id: str
    replies: list[ReplySummary] = field(default_factory=list)
    model: str | None = None
    pending_request_text: str | None = None

    @property
    def latest_session_id(self) -> str | None:
        """Get the most recent valid session_id for resumption.

        Walks backwards through replies to find the most recent reply
        with a non-empty session_id.

        Returns:
            Latest valid session_id, or None if unavailable.
        """
        for reply in reversed(self.replies):
            if reply.session_id:
                return reply.session_id
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


class ConversationStore:
    """Manages conversation metadata storage.

    Reads and writes conversation.json files in the conversation directory,
    tracking reply summaries and session IDs for resumption.

    Written at state transitions only (not during streaming). For real-time
    event data, see EventLog in lib/sandbox/.

    Attributes:
        conversation_dir: Path to the conversation directory.
    """

    def __init__(self, conversation_dir: Path) -> None:
        """Initialize conversation store.

        Args:
            conversation_dir: Path to conversation directory.
                conversation.json stored in this directory.
        """
        self.conversation_dir = conversation_dir
        self._file_path = conversation_dir / CONVERSATION_FILE_NAME

    def load(self) -> ConversationMetadata | None:
        """Load conversation metadata from file.

        Returns:
            ConversationMetadata if file exists and is valid, None otherwise.
        """
        if not self._file_path.exists():
            logger.debug("No conversation file found at %s", self._file_path)
            return None

        try:
            with self._file_path.open("r") as f:
                data = json.load(f)

            replies = [
                ReplySummary(
                    session_id=r["session_id"],
                    timestamp=r["timestamp"],
                    duration_ms=r["duration_ms"],
                    total_cost_usd=r["total_cost_usd"],
                    num_turns=r["num_turns"],
                    is_error=r["is_error"],
                    usage=_deserialize_usage(r.get("usage", {})),
                    request_text=r.get("request_text"),
                    response_text=r.get("response_text"),
                )
                for r in data.get("replies", [])
            ]

            conv_id = data.get("conversation_id", "")

            metadata = ConversationMetadata(
                conversation_id=conv_id,
                replies=replies,
                model=data.get("model"),
                pending_request_text=data.get("pending_request_text"),
            )

            logger.debug(
                "Loaded conversation metadata with %d replies, model=%s, "
                "latest session_id=%s",
                len(replies),
                metadata.model,
                metadata.latest_session_id,
            )
            return metadata

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(
                "Failed to parse conversation file %s: %s",
                self._file_path,
                e,
            )
            return None

    def save(self, metadata: ConversationMetadata) -> None:
        """Save conversation metadata to file.

        Args:
            metadata: Conversation metadata to persist.
        """
        data: dict[str, Any] = {
            "conversation_id": metadata.conversation_id,
            "replies": [_serialize_reply(reply) for reply in metadata.replies],
        }
        if metadata.model:
            data["model"] = metadata.model
        if metadata.pending_request_text is not None:
            data["pending_request_text"] = metadata.pending_request_text

        with self._file_path.open("w") as f:
            json.dump(data, f, indent=2)

        logger.debug(
            "Saved conversation metadata with %d replies to %s",
            len(metadata.replies),
            self._file_path,
        )

    def set_pending_request(
        self,
        conversation_id: str,
        request_text: str,
    ) -> None:
        """Record the prompt for a reply that is about to start.

        Persists the request text to conversation.json so the dashboard
        can display it while execution is in progress. Cleared
        automatically when the reply completes via ``add_reply``.

        Args:
            conversation_id: Conversation identifier.
            request_text: The prompt text being sent to Claude.
        """
        metadata = self.load()
        if metadata is None:
            metadata = ConversationMetadata(conversation_id=conversation_id)

        metadata.pending_request_text = request_text
        self.save(metadata)

    def add_reply(
        self,
        conversation_id: str,
        reply: ReplySummary,
    ) -> ConversationMetadata:
        """Append a reply summary and save.

        Loads existing metadata (or creates new), appends the reply,
        and saves to file. Clears ``pending_request_text`` since the
        reply is now complete.

        Args:
            conversation_id: Conversation identifier.
            reply: Reply summary to append.

        Returns:
            Updated ConversationMetadata.
        """
        metadata = self.load()
        if metadata is None:
            metadata = ConversationMetadata(conversation_id=conversation_id)

        metadata.replies.append(reply)
        metadata.pending_request_text = None
        self.save(metadata)

        logger.info(
            "Recorded reply for conversation %s: session_id=%s, cost=$%.4f",
            conversation_id,
            reply.session_id,
            reply.total_cost_usd,
        )

        return metadata

    def update_last_reply(
        self,
        conversation_id: str,
        reply: ReplySummary,
    ) -> ConversationMetadata:
        """Update the last reply in place.

        Used when a reply was previously added (e.g., for a timeout) and
        the final data needs to be filled in.

        If no replies exist, falls back to appending.

        Args:
            conversation_id: Conversation identifier.
            reply: Updated reply summary.

        Returns:
            Updated ConversationMetadata.
        """
        metadata = self.load()
        if metadata is None or not metadata.replies:
            return self.add_reply(conversation_id, reply)

        metadata.replies[-1] = reply
        self.save(metadata)

        logger.debug(
            "Updated last reply for conversation %s",
            conversation_id,
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
            conversation_id: Conversation identifier.
            model: Model name (e.g., "opus", "sonnet").
        """
        metadata = self.load()
        if metadata is None:
            metadata = ConversationMetadata(conversation_id=conversation_id)
        metadata.model = model
        self.save(metadata)
        logger.info("Set model=%s for conversation %s", model, conversation_id)


def _serialize_reply(reply: ReplySummary) -> dict[str, Any]:
    """Serialize a ReplySummary to a JSON-compatible dict."""
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
    }


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
