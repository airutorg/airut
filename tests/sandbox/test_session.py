# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SessionStore and session metadata management."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from lib.claude_output import StreamEvent, parse_stream_events
from lib.claude_output.types import Usage
from lib.sandbox.session import (
    SESSION_FILE_NAME,
    SessionMetadata,
    SessionReply,
    SessionStore,
)


def _parse_events(*raw_events: dict) -> list[StreamEvent]:
    """Parse raw event dicts into typed StreamEvents."""
    stdout = "\n".join(json.dumps(e) for e in raw_events)
    return parse_stream_events(stdout)


class TestSessionReply:
    """Tests for SessionReply dataclass."""

    def test_create_reply(self) -> None:
        """Create SessionReply with all fields."""
        reply = SessionReply(
            session_id="abc123",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
            usage=Usage(input_tokens=100, output_tokens=50),
        )

        assert reply.session_id == "abc123"
        assert reply.timestamp == "2026-01-15T12:00:00+00:00"
        assert reply.duration_ms == 5000
        assert reply.total_cost_usd == 0.05
        assert reply.num_turns == 3
        assert reply.is_error is False
        assert reply.usage == Usage(input_tokens=100, output_tokens=50)

    def test_create_reply_default_usage(self) -> None:
        """Create SessionReply with default empty usage."""
        reply = SessionReply(
            session_id="abc123",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )

        assert reply.usage == Usage()

    def test_create_reply_with_text(self) -> None:
        """Create SessionReply with request/response text."""
        reply = SessionReply(
            session_id="abc123",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
            request_text="Help me with this",
            response_text="I'll help you",
        )

        assert reply.request_text == "Help me with this"
        assert reply.response_text == "I'll help you"

    def test_create_reply_default_text_none(self) -> None:
        """Create SessionReply with default None text."""
        reply = SessionReply(
            session_id="abc123",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )

        assert reply.request_text is None
        assert reply.response_text is None

    def test_create_reply_with_events(self) -> None:
        """Create SessionReply with events."""
        events = _parse_events(
            {"type": "system", "subtype": "init"},
            {
                "type": "assistant",
                "message": {"role": "assistant", "content": []},
            },
            {"type": "result", "subtype": "success"},
        )
        reply = SessionReply(
            session_id="abc123",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
            events=events,
        )

        assert reply.events == events
        assert len(reply.events) == 3

    def test_create_reply_default_events_empty(self) -> None:
        """Create SessionReply with default empty events."""
        reply = SessionReply(
            session_id="abc123",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )

        assert reply.events == []

    def test_get_session_id_returns_top_level(self) -> None:
        """get_session_id returns top-level session_id when available."""
        events = _parse_events(
            {"type": "system", "subtype": "init", "session_id": "init-id"},
        )
        reply = SessionReply(
            session_id="top-level-id",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
            events=events,
        )

        # Should prefer top-level session_id
        assert reply.get_session_id() == "top-level-id"

    def test_get_session_id_falls_back_to_init_event(self) -> None:
        """get_session_id falls back to init event when top-level is empty."""
        events = _parse_events(
            {"type": "system", "subtype": "init", "session_id": "init-id"},
        )
        reply = SessionReply(
            session_id="",  # Empty
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=0,
            total_cost_usd=0.0,
            num_turns=0,
            is_error=True,
            events=events,
        )

        # Should fall back to init event
        assert reply.get_session_id() == "init-id"

    def test_get_session_id_returns_none_when_unavailable(self) -> None:
        """get_session_id returns None when no session_id available."""
        reply = SessionReply(
            session_id="",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=0,
            total_cost_usd=0.0,
            num_turns=0,
            is_error=True,
            events=[],  # No init event
        )

        assert reply.get_session_id() is None


class TestSessionMetadata:
    """Tests for SessionMetadata dataclass."""

    def test_create_metadata_empty(self) -> None:
        """Create SessionMetadata with no replies."""
        metadata = SessionMetadata(execution_context_id="abc12345")

        assert metadata.execution_context_id == "abc12345"
        assert metadata.replies == []
        assert metadata.model is None

    def test_create_metadata_with_model(self) -> None:
        """Create SessionMetadata with model specified."""
        metadata = SessionMetadata(
            execution_context_id="abc12345", model="opus"
        )

        assert metadata.execution_context_id == "abc12345"
        assert metadata.model == "opus"

    def test_latest_session_id_empty(self) -> None:
        """latest_session_id returns None when no replies."""
        metadata = SessionMetadata(execution_context_id="abc12345")

        assert metadata.latest_session_id is None

    def test_latest_session_id_single_reply(self) -> None:
        """latest_session_id returns the only reply's session_id."""
        reply = SessionReply(
            session_id="session-1",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )
        metadata = SessionMetadata(
            execution_context_id="abc12345",
            replies=[reply],
        )

        assert metadata.latest_session_id == "session-1"

    def test_latest_session_id_multiple_replies(self) -> None:
        """latest_session_id returns the most recent reply's session_id."""
        reply1 = SessionReply(
            session_id="session-1",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )
        reply2 = SessionReply(
            session_id="session-2",
            timestamp="2026-01-15T13:00:00+00:00",
            duration_ms=3000,
            total_cost_usd=0.08,
            num_turns=2,
            is_error=False,
        )
        metadata = SessionMetadata(
            execution_context_id="abc12345",
            replies=[reply1, reply2],
        )

        assert metadata.latest_session_id == "session-2"

    def test_latest_session_id_skips_empty_from_interrupted(self) -> None:
        """Falls back to earlier reply when last has empty ID.

        When a task is stopped mid-execution, the result event is
        never emitted and session_id is saved as empty string. The
        property should fall back to the most recent valid one.
        """
        successful_reply = SessionReply(
            session_id="session-valid",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )
        interrupted_reply = SessionReply(
            session_id="",
            timestamp="2026-01-15T13:00:00+00:00",
            duration_ms=1000,
            total_cost_usd=0.01,
            num_turns=1,
            is_error=False,
        )
        metadata = SessionMetadata(
            execution_context_id="abc12345",
            replies=[successful_reply, interrupted_reply],
        )

        assert metadata.latest_session_id == "session-valid"

    def test_latest_session_id_all_empty(self) -> None:
        """Returns None when all replies have empty session_id."""
        reply = SessionReply(
            session_id="",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=1000,
            total_cost_usd=0.01,
            num_turns=1,
            is_error=False,
        )
        metadata = SessionMetadata(
            execution_context_id="abc12345",
            replies=[reply],
        )

        assert metadata.latest_session_id is None

    def test_total_cost_usd_empty(self) -> None:
        """total_cost_usd returns 0.0 when no replies."""
        metadata = SessionMetadata(execution_context_id="abc12345")

        assert metadata.total_cost_usd == 0.0

    def test_total_cost_usd_sums_all_replies(self) -> None:
        """total_cost_usd sums cost from all replies."""
        reply1 = SessionReply(
            session_id="session-1",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )
        reply2 = SessionReply(
            session_id="session-1",
            timestamp="2026-01-15T13:00:00+00:00",
            duration_ms=3000,
            total_cost_usd=0.12,
            num_turns=2,
            is_error=False,
        )
        metadata = SessionMetadata(
            execution_context_id="abc12345",
            replies=[reply1, reply2],
        )

        # 0.05 + 0.12 = 0.17
        assert metadata.total_cost_usd == pytest.approx(0.17)

    def test_total_turns_empty(self) -> None:
        """total_turns returns 0 when no replies."""
        metadata = SessionMetadata(execution_context_id="abc12345")

        assert metadata.total_turns == 0

    def test_total_turns_sums_all(self) -> None:
        """total_turns sums num_turns from all replies."""
        reply1 = SessionReply(
            session_id="session-1",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )
        reply2 = SessionReply(
            session_id="session-2",
            timestamp="2026-01-15T13:00:00+00:00",
            duration_ms=3000,
            total_cost_usd=0.12,
            num_turns=2,
            is_error=False,
        )
        metadata = SessionMetadata(
            execution_context_id="abc12345",
            replies=[reply1, reply2],
        )

        assert metadata.total_turns == 5


class TestSessionStore:
    """Tests for SessionStore class."""

    def test_init_sets_file_path(self, tmp_path: Path) -> None:
        """Initialize SessionStore with correct file path."""
        store = SessionStore(tmp_path)

        assert store.session_dir == tmp_path
        assert store._file_path == tmp_path / SESSION_FILE_NAME

    def test_load_no_file_returns_none(self, tmp_path: Path) -> None:
        """load() returns None when session file doesn't exist."""
        store = SessionStore(tmp_path)

        assert store.load() is None

    def test_load_valid_file(self, tmp_path: Path) -> None:
        """load() parses valid session file."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-1",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "usage": {"input_tokens": 100},
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        assert metadata.execution_context_id == "abc12345"
        assert len(metadata.replies) == 1
        assert metadata.replies[0].session_id == "session-1"
        assert metadata.replies[0].usage == Usage(input_tokens=100)

    def test_load_file_without_usage(self, tmp_path: Path) -> None:
        """load() handles reply without usage field."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-1",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    # No usage field
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        assert metadata.replies[0].usage == Usage()

    def test_load_events_skips_non_dict_items(self, tmp_path: Path) -> None:
        """load() skips non-dict items in events list."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-1",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "usage": {},
                    "events": [
                        "not a dict",
                        42,
                        None,
                        {
                            "type": "result",
                            "subtype": "success",
                            "session_id": "sess_1",
                            "duration_ms": 1000,
                            "total_cost_usd": 0.01,
                            "num_turns": 1,
                            "is_error": False,
                            "usage": {},
                        },
                    ],
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        # Only the valid dict event should be parsed
        assert len(metadata.replies[0].events) == 1

    def test_load_non_dict_usage_returns_default(self, tmp_path: Path) -> None:
        """load() returns default Usage for non-dict usage values."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-1",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "usage": "not a dict",
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        assert metadata.replies[0].usage == Usage()

    def test_usage_extra_fields_round_trip(self, tmp_path: Path) -> None:
        """Extra usage fields survive save/load round-trip."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-1",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "usage": {
                        "input_tokens": 100,
                        "output_tokens": 50,
                        "server_tool_use": {"web_search_requests": 2},
                    },
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        usage = metadata.replies[0].usage
        assert usage.input_tokens == 100
        assert usage.extra == {"server_tool_use": {"web_search_requests": 2}}

        # Save and reload to verify round-trip
        store.save(metadata)
        reloaded = store.load()
        assert reloaded is not None
        usage2 = reloaded.replies[0].usage
        assert usage2.extra == {"server_tool_use": {"web_search_requests": 2}}

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        """load() returns None for invalid JSON."""
        (tmp_path / SESSION_FILE_NAME).write_text("not valid json")

        store = SessionStore(tmp_path)
        assert store.load() is None

    def test_load_missing_required_fields(self, tmp_path: Path) -> None:
        """load() returns None when required fields missing."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-1",
                    # Missing required fields
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        assert store.load() is None

    def test_load_missing_execution_context_id(self, tmp_path: Path) -> None:
        """load() returns metadata with empty ID when key missing."""
        session_data = {
            # Missing execution_context_id
            "replies": [],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()
        assert metadata is not None
        assert metadata.execution_context_id == ""

    def test_save_creates_file(self, tmp_path: Path) -> None:
        """save() creates session file."""
        store = SessionStore(tmp_path)
        metadata = SessionMetadata(execution_context_id="abc12345")

        store.save(metadata)

        assert (tmp_path / SESSION_FILE_NAME).exists()
        data = json.loads((tmp_path / SESSION_FILE_NAME).read_text())
        assert data["execution_context_id"] == "abc12345"
        assert data["replies"] == []

    def test_save_with_replies(self, tmp_path: Path) -> None:
        """save() persists replies."""
        store = SessionStore(tmp_path)
        reply = SessionReply(
            session_id="session-1",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
            usage=Usage(input_tokens=100),
        )
        metadata = SessionMetadata(
            execution_context_id="abc12345",
            replies=[reply],
        )

        store.save(metadata)

        data = json.loads((tmp_path / SESSION_FILE_NAME).read_text())
        assert len(data["replies"]) == 1
        assert data["replies"][0]["session_id"] == "session-1"
        assert data["replies"][0]["usage"]["input_tokens"] == 100

    def test_save_overwrites_existing(self, tmp_path: Path) -> None:
        """save() overwrites existing file."""
        store = SessionStore(tmp_path)

        # Save initial
        metadata1 = SessionMetadata(execution_context_id="abc12345")
        store.save(metadata1)

        # Save updated
        reply = SessionReply(
            session_id="session-2",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=5000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
        )
        metadata2 = SessionMetadata(
            execution_context_id="abc12345",
            replies=[reply],
        )
        store.save(metadata2)

        data = json.loads((tmp_path / SESSION_FILE_NAME).read_text())
        assert len(data["replies"]) == 1
        assert data["replies"][0]["session_id"] == "session-2"

    def test_add_reply_creates_new_metadata(self, tmp_path: Path) -> None:
        """add_reply() creates metadata when none exists."""
        store = SessionStore(tmp_path)
        events = _parse_events(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "new-session-id",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100},
                "result": "done",
            }
        )

        with patch("lib.sandbox.session.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(
                2026, 1, 15, 12, 0, 0, tzinfo=UTC
            )

            metadata = store.add_reply("abc12345", events)

        assert metadata.execution_context_id == "abc12345"
        assert len(metadata.replies) == 1
        assert metadata.replies[0].session_id == "new-session-id"
        assert metadata.replies[0].total_cost_usd == 0.05
        assert metadata.replies[0].usage == Usage(input_tokens=100)

        # Verify persisted
        data = json.loads((tmp_path / SESSION_FILE_NAME).read_text())
        assert data["execution_context_id"] == "abc12345"

    def test_add_reply_appends_to_existing(self, tmp_path: Path) -> None:
        """add_reply() appends to existing metadata."""
        store = SessionStore(tmp_path)

        # Create initial reply
        events1 = _parse_events(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "session-1",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "result": "done",
            }
        )
        store.add_reply("abc12345", events1)

        # Add second reply
        events2 = _parse_events(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "session-2",
                "duration_ms": 3000,
                "total_cost_usd": 0.08,
                "num_turns": 2,
                "is_error": False,
                "result": "done",
            }
        )
        metadata = store.add_reply("abc12345", events2)

        assert len(metadata.replies) == 2
        assert metadata.replies[0].session_id == "session-1"
        assert metadata.replies[1].session_id == "session-2"

    def test_add_reply_handles_empty_events(self, tmp_path: Path) -> None:
        """add_reply() handles empty event list with defaults."""
        store = SessionStore(tmp_path)

        metadata = store.add_reply("abc12345", [])

        assert metadata.replies[0].session_id == ""
        assert metadata.replies[0].duration_ms == 0
        assert metadata.replies[0].total_cost_usd == 0.0
        assert metadata.replies[0].num_turns == 0
        assert metadata.replies[0].is_error is True  # default when no result
        assert metadata.replies[0].usage == Usage()

    def test_update_or_add_reply_creates_first_reply(
        self, tmp_path: Path
    ) -> None:
        """update_or_add_reply() creates first reply when none exists."""
        store = SessionStore(tmp_path)
        events = _parse_events(
            {"type": "system", "subtype": "init", "session_id": "session-1"},
            {
                "type": "result",
                "subtype": "success",
                "session_id": "session-1",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "result": "done",
            },
        )

        metadata = store.update_or_add_reply("abc12345", events)

        assert len(metadata.replies) == 1
        assert metadata.replies[0].session_id == "session-1"
        assert len(metadata.replies[0].events) == 2

    def test_update_or_add_reply_updates_existing(self, tmp_path: Path) -> None:
        """update_or_add_reply() updates last reply instead of appending."""
        store = SessionStore(tmp_path)

        # Create initial reply with 1 event
        events1 = _parse_events(
            {"type": "system", "subtype": "init"},
        )
        store.update_or_add_reply("abc12345", events1)

        # Update with 2 events
        events2 = _parse_events(
            {"type": "system", "subtype": "init"},
            {
                "type": "assistant",
                "message": {"role": "assistant", "content": []},
            },
        )
        metadata = store.update_or_add_reply("abc12345", events2)

        # Should still have only 1 reply, but with updated events
        assert len(metadata.replies) == 1
        assert len(metadata.replies[0].events) == 2

        # Update with final data (3 events + metadata)
        events3 = _parse_events(
            {"type": "system", "subtype": "init"},
            {
                "type": "assistant",
                "message": {"role": "assistant", "content": []},
            },
            {
                "type": "result",
                "subtype": "success",
                "session_id": "session-final",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "result": "done",
            },
        )
        metadata = store.update_or_add_reply(
            "abc12345",
            events3,
            response_text="Final response",
        )

        # Still only 1 reply, fully populated
        assert len(metadata.replies) == 1
        assert len(metadata.replies[0].events) == 3
        assert metadata.replies[0].session_id == "session-final"
        assert metadata.replies[0].response_text == "Final response"

    def test_update_or_add_reply_adds_new_on_different_request(
        self, tmp_path: Path
    ) -> None:
        """update_or_add_reply() adds new reply when request_text differs."""
        store = SessionStore(tmp_path)

        # Create first reply with request_text "First task"
        events1 = _parse_events(
            {"type": "system", "subtype": "init"},
            {
                "type": "result",
                "subtype": "success",
                "session_id": "session-1",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "result": "done",
            },
        )
        store.update_or_add_reply(
            "abc12345",
            events1,
            request_text="First task",
            response_text="First response",
        )

        # Verify first reply was added
        metadata = store.load()
        assert metadata is not None
        assert len(metadata.replies) == 1
        assert metadata.replies[0].request_text == "First task"
        assert metadata.replies[0].response_text == "First response"

        # Add second reply with different request_text
        events2 = _parse_events(
            {"type": "system", "subtype": "init"},
            {
                "type": "result",
                "subtype": "success",
                "session_id": "session-2",
                "duration_ms": 2000,
                "total_cost_usd": 0.02,
                "num_turns": 2,
                "is_error": False,
                "result": "done",
            },
        )
        metadata = store.update_or_add_reply(
            "abc12345",
            events2,
            request_text="Second task",
            response_text="Second response",
        )

        # Should now have 2 replies (not update the first one)
        assert len(metadata.replies) == 2
        assert metadata.replies[0].request_text == "First task"
        assert metadata.replies[0].response_text == "First response"
        assert metadata.replies[1].request_text == "Second task"
        assert metadata.replies[1].response_text == "Second response"

    def test_update_or_add_reply_updates_on_same_request(
        self, tmp_path: Path
    ) -> None:
        """update_or_add_reply() updates reply when request_text is same."""
        store = SessionStore(tmp_path)

        # Create first reply
        events1 = _parse_events(
            {"type": "system", "subtype": "init"},
        )
        store.update_or_add_reply(
            "abc12345",
            events1,
            request_text="Same task",
            response_text="Partial response",
        )

        # Update with same request_text (streaming update)
        events2 = _parse_events(
            {"type": "system", "subtype": "init"},
            {
                "type": "result",
                "subtype": "success",
                "session_id": "session-1",
                "duration_ms": 2000,
                "total_cost_usd": 0.02,
                "num_turns": 2,
                "is_error": False,
                "result": "done",
            },
        )
        metadata = store.update_or_add_reply(
            "abc12345",
            events2,
            request_text="Same task",
            response_text="Complete response",
        )

        # Should still have 1 reply (updated)
        assert len(metadata.replies) == 1
        assert metadata.replies[0].request_text == "Same task"
        assert metadata.replies[0].response_text == "Complete response"
        assert len(metadata.replies[0].events) == 2

    def test_get_session_id_for_resume_no_file(self, tmp_path: Path) -> None:
        """get_session_id_for_resume() returns None when no file."""
        store = SessionStore(tmp_path)

        assert store.get_session_id_for_resume() is None

    def test_get_session_id_for_resume_empty_replies(
        self, tmp_path: Path
    ) -> None:
        """get_session_id_for_resume() returns None for empty replies."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)

        assert store.get_session_id_for_resume() is None

    def test_get_session_id_for_resume_with_replies(
        self, tmp_path: Path
    ) -> None:
        """get_session_id_for_resume() returns latest session_id."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-1",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                },
                {
                    "session_id": "session-2",
                    "timestamp": "2026-01-15T13:00:00+00:00",
                    "duration_ms": 3000,
                    "total_cost_usd": 0.08,
                    "num_turns": 2,
                    "is_error": False,
                },
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)

        assert store.get_session_id_for_resume() == "session-2"

    def test_get_session_id_for_resume_skips_interrupted(
        self, tmp_path: Path
    ) -> None:
        """Falls back when last reply was interrupted.

        Reproduces the amnesia bug: a successful session followed
        by an interrupted execution (empty session_id) should still
        return the valid session_id from the earlier reply.
        """
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "session-good",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                },
                {
                    "session_id": "",
                    "timestamp": "2026-01-15T13:00:00+00:00",
                    "duration_ms": 1000,
                    "total_cost_usd": 0.01,
                    "num_turns": 1,
                    "is_error": False,
                },
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)

        assert store.get_session_id_for_resume() == "session-good"

    def test_get_model_no_file(self, tmp_path: Path) -> None:
        """get_model() returns None when no file exists."""
        store = SessionStore(tmp_path)

        assert store.get_model() is None

    def test_get_model_no_model_in_file(self, tmp_path: Path) -> None:
        """get_model() returns None when model not set in file."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)

        assert store.get_model() is None

    def test_get_model_returns_model(self, tmp_path: Path) -> None:
        """get_model() returns the stored model."""
        session_data = {
            "execution_context_id": "abc12345",
            "model": "opus",
            "replies": [],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)

        assert store.get_model() == "opus"

    def test_set_model_creates_file(self, tmp_path: Path) -> None:
        """set_model() creates new session file with model."""
        store = SessionStore(tmp_path)

        store.set_model("abc12345", "haiku")

        assert (tmp_path / SESSION_FILE_NAME).exists()
        data = json.loads((tmp_path / SESSION_FILE_NAME).read_text())
        assert data.get("execution_context_id") == "abc12345"
        assert data["model"] == "haiku"

    def test_set_model_updates_existing(self, tmp_path: Path) -> None:
        """set_model() updates model in existing file."""
        session_data = {
            "execution_context_id": "abc12345",
            "model": "sonnet",
            "replies": [
                {
                    "session_id": "session-1",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        store.set_model("abc12345", "opus")

        data = json.loads((tmp_path / SESSION_FILE_NAME).read_text())
        assert data["model"] == "opus"
        # Verify replies are preserved
        assert len(data["replies"]) == 1


class TestSessionFileIntegration:
    """Integration tests for session file operations."""

    def test_round_trip_save_load(self, tmp_path: Path) -> None:
        """Save and load session data round-trips correctly."""
        store = SessionStore(tmp_path)

        # Build up session through multiple replies
        events1 = _parse_events(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "c7886694-f2cb-4861-ad3c-fbe0964eb4df",
                "duration_ms": 2900,
                "total_cost_usd": 0.0313825,
                "num_turns": 1,
                "is_error": False,
                "usage": {
                    "input_tokens": 3,
                    "output_tokens": 31,
                },
                "result": "done",
            }
        )
        store.add_reply("abc12345", events1)

        events2 = _parse_events(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "c7886694-f2cb-4861-ad3c-fbe0964eb4df",
                "duration_ms": 2657,
                "total_cost_usd": 0.04216375,
                "num_turns": 1,
                "is_error": False,
                "usage": {
                    "input_tokens": 3,
                    "output_tokens": 9,
                },
                "result": "done",
            }
        )
        store.add_reply("abc12345", events2)

        # Load from fresh store
        fresh_store = SessionStore(tmp_path)
        metadata = fresh_store.load()

        assert metadata is not None
        assert metadata.execution_context_id == "abc12345"
        assert len(metadata.replies) == 2
        assert (
            metadata.latest_session_id == "c7886694-f2cb-4861-ad3c-fbe0964eb4df"
        )
        # Sum of both replies: 0.0313825 + 0.04216375 = 0.07354625
        assert metadata.total_cost_usd == pytest.approx(0.07354625)
        assert metadata.total_turns == 2

    def test_round_trip_with_text(self, tmp_path: Path) -> None:
        """Save and load session data with request/response text."""
        store = SessionStore(tmp_path)

        events = _parse_events(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess-123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "done",
            }
        )
        store.add_reply(
            "abc12345",
            events,
            request_text="Please help me with this task",
            response_text="I'll help you with that.",
        )

        # Load from fresh store
        fresh_store = SessionStore(tmp_path)
        metadata = fresh_store.load()

        assert metadata is not None
        assert len(metadata.replies) == 1
        reply = metadata.replies[0]
        assert reply.request_text == "Please help me with this task"
        assert reply.response_text == "I'll help you with that."

    def test_load_without_text_fields(self, tmp_path: Path) -> None:
        """Load session file without text fields (backwards compat)."""
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "sess-123",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "usage": {},
                    # No request_text or response_text
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        assert metadata.replies[0].request_text is None
        assert metadata.replies[0].response_text is None

    def test_load_without_events_field(self, tmp_path: Path) -> None:
        """Load session file without events field (backwards compat).

        Older session files from before actions history was added won't have
        the events field. New servers should load them with empty events list.
        """
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "sess-123",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "usage": {},
                    "request_text": "Test request",
                    "response_text": "Test response",
                    # No events field - simulates old session file
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        assert len(metadata.replies) == 1
        assert metadata.replies[0].events == []


class TestSessionResumeAfterApiError:
    """Tests for session resumption after API errors (529, etc.).

    When Claude Code execution is interrupted by an API error (like 529
    overloaded), the result event is never emitted. This means:
    - session_id from result event is empty
    - BUT the session_id IS present in the init event within events

    The session module must extract session_id from the init event as a
    fallback, so that subsequent messages can resume the session correctly.
    """

    def test_latest_session_id_extracts_from_init_event_when_result_missing(
        self, tmp_path: Path
    ) -> None:
        """Extracts session_id from init event when result event is missing.

        Reproduces bug where 529 error causes session amnesia:
        - First message gets 529 error, no result event
        - session_id in SessionReply is empty string
        - But init event in events array HAS the session_id
        - latest_session_id should extract it from init event
        """
        # Simulate context.json after 529 error (no result event)
        session_data = {
            "execution_context_id": "3b8952f8",
            "replies": [
                {
                    "session_id": "",  # Empty because no result event
                    "timestamp": "2026-02-02T06:09:56.159112+00:00",
                    "duration_ms": 0,
                    "total_cost_usd": 0.0,
                    "num_turns": 0,
                    "is_error": True,
                    "usage": {},
                    "request_text": "Help me with this task",
                    "response_text": "API Error: 529",
                    "events": [
                        # Init event has the session_id we need
                        {
                            "type": "system",
                            "subtype": "init",
                            "cwd": "/workspace",
                            "session_id": "sess-init-529",
                            "tools": ["Read", "Write"],
                            "model": "claude-opus-4-5-20251101",
                        },
                        # Some assistant events before the error
                        {
                            "type": "assistant",
                            "message": {
                                "role": "assistant",
                                "content": [{"type": "text", "text": "Help"}],
                            },
                            "session_id": "sess-init-529",
                        },
                        # No result event - API error 529 interrupted
                    ],
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        # session_id should be extracted from init event, not top-level
        assert metadata.latest_session_id == "sess-init-529"

    def test_latest_session_id_prefers_result_over_init(
        self, tmp_path: Path
    ) -> None:
        """Prefers session_id from SessionReply when available.

        When execution completes successfully, the result event provides
        session_id which is stored in SessionReply.session_id. This should
        be preferred over extracting from init event.
        """
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                {
                    "session_id": "result-session-id",  # From result event
                    "timestamp": "2026-02-02T06:09:56.159112+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "usage": {},
                    "events": [
                        {
                            "type": "system",
                            "subtype": "init",
                            "session_id": "init-session-id",  # Different ID
                        },
                        {
                            "type": "result",
                            "session_id": "result-session-id",
                        },
                    ],
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        # Should use the top-level session_id (from result event)
        assert metadata.latest_session_id == "result-session-id"

    def test_get_session_id_for_resume_after_api_error(
        self, tmp_path: Path
    ) -> None:
        """get_session_id_for_resume returns ID from init event after error.

        This is the integration test that verifies the full flow:
        - First message fails with 529
        - Second message should resume the same session
        """
        # First reply: failed with 529, has init event with session_id
        session_data = {
            "execution_context_id": "3b8952f8",
            "model": "opus",
            "replies": [
                {
                    "session_id": "",
                    "timestamp": "2026-02-02T06:09:56.159112+00:00",
                    "duration_ms": 0,
                    "total_cost_usd": 0.0,
                    "num_turns": 0,
                    "is_error": True,
                    "usage": {},
                    "request_text": "Please design code review workflow",
                    "response_text": "API Error: 529 overloaded",
                    "events": [
                        {
                            "type": "system",
                            "subtype": "init",
                            "session_id": "sess-init-529",
                        },
                    ],
                }
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)

        # This is what service.py calls before executing Claude
        session_id = store.get_session_id_for_resume()

        # Should return session_id from init event, enabling resume
        assert session_id == "sess-init-529"

    def test_latest_session_id_handles_multiple_interrupted_replies(
        self, tmp_path: Path
    ) -> None:
        """Falls back through multiple interrupted replies to find valid ID.

        Edge case: multiple consecutive 529 errors, each with their own
        init session_id. Should use the most recent valid session_id.
        """
        session_data = {
            "execution_context_id": "abc12345",
            "replies": [
                # First reply: success
                {
                    "session_id": "session-first",
                    "timestamp": "2026-01-15T12:00:00+00:00",
                    "duration_ms": 5000,
                    "total_cost_usd": 0.05,
                    "num_turns": 3,
                    "is_error": False,
                    "events": [],
                },
                # Second reply: 529 error
                {
                    "session_id": "",
                    "timestamp": "2026-01-15T13:00:00+00:00",
                    "duration_ms": 0,
                    "total_cost_usd": 0.0,
                    "num_turns": 0,
                    "is_error": True,
                    "events": [
                        {
                            "type": "system",
                            "subtype": "init",
                            "session_id": "session-second-init",
                        },
                    ],
                },
                # Third reply: another 529 error
                {
                    "session_id": "",
                    "timestamp": "2026-01-15T14:00:00+00:00",
                    "duration_ms": 0,
                    "total_cost_usd": 0.0,
                    "num_turns": 0,
                    "is_error": True,
                    "events": [
                        {
                            "type": "system",
                            "subtype": "init",
                            "session_id": "session-third-init",
                        },
                    ],
                },
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))

        store = SessionStore(tmp_path)
        metadata = store.load()

        assert metadata is not None
        # Should return the most recent valid session_id (from third init)
        assert metadata.latest_session_id == "session-third-init"


class TestGetLastSuccessfulResponse:
    """Tests for SessionStore.get_last_successful_response."""

    def test_returns_none_when_no_session(self, tmp_path: Path) -> None:
        """Returns None when no session file exists."""
        store = SessionStore(tmp_path)
        assert store.get_last_successful_response() is None

    def test_returns_none_when_all_errors(self, tmp_path: Path) -> None:
        """Returns None when all replies are errors."""
        session_data = {
            "execution_context_id": "abc123",
            "replies": [
                {
                    "session_id": "s1",
                    "timestamp": "2025-01-01T00:00:00",
                    "duration_ms": 100,
                    "total_cost_usd": 0.01,
                    "num_turns": 1,
                    "is_error": True,
                    "response_text": "Error occurred",
                },
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))
        store = SessionStore(tmp_path)
        assert store.get_last_successful_response() is None

    def test_returns_last_successful_response(self, tmp_path: Path) -> None:
        """Returns response text from the last non-error reply."""
        session_data = {
            "execution_context_id": "abc123",
            "replies": [
                {
                    "session_id": "s1",
                    "timestamp": "2025-01-01T00:00:00",
                    "duration_ms": 100,
                    "total_cost_usd": 0.01,
                    "num_turns": 1,
                    "is_error": False,
                    "response_text": "First response",
                },
                {
                    "session_id": "s2",
                    "timestamp": "2025-01-01T01:00:00",
                    "duration_ms": 200,
                    "total_cost_usd": 0.02,
                    "num_turns": 2,
                    "is_error": False,
                    "response_text": "Second response",
                },
                {
                    "session_id": "s3",
                    "timestamp": "2025-01-01T02:00:00",
                    "duration_ms": 300,
                    "total_cost_usd": 0.03,
                    "num_turns": 3,
                    "is_error": True,
                    "response_text": "Error message",
                },
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))
        store = SessionStore(tmp_path)
        assert store.get_last_successful_response() == "Second response"

    def test_skips_replies_with_no_response_text(self, tmp_path: Path) -> None:
        """Skips successful replies that have no response text."""
        session_data = {
            "execution_context_id": "abc123",
            "replies": [
                {
                    "session_id": "s1",
                    "timestamp": "2025-01-01T00:00:00",
                    "duration_ms": 100,
                    "total_cost_usd": 0.01,
                    "num_turns": 1,
                    "is_error": False,
                    "response_text": "Has text",
                },
                {
                    "session_id": "s2",
                    "timestamp": "2025-01-01T01:00:00",
                    "duration_ms": 200,
                    "total_cost_usd": 0.02,
                    "num_turns": 2,
                    "is_error": False,
                },
            ],
        }
        (tmp_path / SESSION_FILE_NAME).write_text(json.dumps(session_data))
        store = SessionStore(tmp_path)
        assert store.get_last_successful_response() == "Has text"
