# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib.conversation.conversation_store."""

import json
from pathlib import Path

import pytest

from lib.claude_output.types import Usage
from lib.conversation.conversation_store import (
    CONVERSATION_FILE_NAME,
    ConversationMetadata,
    ConversationStore,
    ReplySummary,
    _deserialize_usage,
    _serialize_reply,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_reply(**overrides: object) -> ReplySummary:
    """Create a ReplySummary with sensible defaults."""
    defaults = {
        "session_id": "session-1",
        "timestamp": "2026-01-15T12:00:00+00:00",
        "duration_ms": 5000,
        "total_cost_usd": 0.05,
        "num_turns": 3,
        "is_error": False,
        "usage": Usage(input_tokens=100, output_tokens=50),
    }
    defaults.update(overrides)
    return ReplySummary(**defaults)  # type: ignore[arg-type]


# ── ReplySummary dataclass tests ─────────────────────────────────────


class TestReplySummary:
    def test_create_reply_all_fields(self) -> None:
        reply = ReplySummary(
            session_id="sess-abc",
            timestamp="2026-01-15T12:00:00+00:00",
            duration_ms=10000,
            total_cost_usd=0.12,
            num_turns=5,
            is_error=False,
            usage=Usage(input_tokens=200, output_tokens=100),
            request_text="Hello",
            response_text="Hi there",
        )
        assert reply.session_id == "sess-abc"
        assert reply.timestamp == "2026-01-15T12:00:00+00:00"
        assert reply.duration_ms == 10000
        assert reply.total_cost_usd == pytest.approx(0.12)
        assert reply.num_turns == 5
        assert reply.is_error is False
        assert reply.usage.input_tokens == 200
        assert reply.usage.output_tokens == 100
        assert reply.request_text == "Hello"
        assert reply.response_text == "Hi there"

    def test_create_reply_defaults(self) -> None:
        reply = ReplySummary(
            session_id="s1",
            timestamp="2026-01-01T00:00:00+00:00",
            duration_ms=100,
            total_cost_usd=0.0,
            num_turns=0,
            is_error=True,
        )
        assert reply.usage.input_tokens == 0
        assert reply.usage.output_tokens == 0
        assert reply.request_text is None
        assert reply.response_text is None


# ── ConversationMetadata tests ───────────────────────────────────────


class TestConversationMetadata:
    def test_create_empty(self) -> None:
        md = ConversationMetadata(conversation_id="abc12345")
        assert md.conversation_id == "abc12345"
        assert md.replies == []
        assert md.model is None
        assert md.latest_session_id is None
        assert md.total_cost_usd == 0.0
        assert md.total_turns == 0

    def test_create_with_model(self) -> None:
        md = ConversationMetadata(conversation_id="abc12345", model="opus")
        assert md.model == "opus"

    def test_latest_session_id_single(self) -> None:
        md = ConversationMetadata(
            conversation_id="abc",
            replies=[_make_reply(session_id="session-42")],
        )
        assert md.latest_session_id == "session-42"

    def test_latest_session_id_multiple(self) -> None:
        md = ConversationMetadata(
            conversation_id="abc",
            replies=[
                _make_reply(session_id="session-1"),
                _make_reply(session_id="session-2"),
                _make_reply(session_id="session-3"),
            ],
        )
        assert md.latest_session_id == "session-3"

    def test_latest_session_id_skips_empty(self) -> None:
        md = ConversationMetadata(
            conversation_id="abc",
            replies=[
                _make_reply(session_id="session-1"),
                _make_reply(session_id=""),
            ],
        )
        assert md.latest_session_id == "session-1"

    def test_latest_session_id_all_empty(self) -> None:
        md = ConversationMetadata(
            conversation_id="abc",
            replies=[_make_reply(session_id="")],
        )
        assert md.latest_session_id is None

    def test_total_cost(self) -> None:
        md = ConversationMetadata(
            conversation_id="abc",
            replies=[
                _make_reply(total_cost_usd=0.05),
                _make_reply(total_cost_usd=0.10),
            ],
        )
        assert md.total_cost_usd == pytest.approx(0.15)

    def test_total_turns(self) -> None:
        md = ConversationMetadata(
            conversation_id="abc",
            replies=[
                _make_reply(num_turns=3),
                _make_reply(num_turns=5),
            ],
        )
        assert md.total_turns == 8


# ── Serialization tests ──────────────────────────────────────────────


class TestSerialization:
    def test_serialize_reply(self) -> None:
        reply = _make_reply(
            request_text="hello",
            response_text="world",
        )
        data = _serialize_reply(reply)
        assert data["session_id"] == "session-1"
        assert data["timestamp"] == "2026-01-15T12:00:00+00:00"
        assert data["duration_ms"] == 5000
        assert data["total_cost_usd"] == pytest.approx(0.05)
        assert data["num_turns"] == 3
        assert data["is_error"] is False
        assert data["usage"]["input_tokens"] == 100
        assert data["usage"]["output_tokens"] == 50
        assert data["request_text"] == "hello"
        assert data["response_text"] == "world"

    def test_serialize_reply_with_extra_usage(self) -> None:
        usage = Usage(
            input_tokens=100,
            output_tokens=50,
            extra={"server_tool_tokens": 10},
        )
        reply = _make_reply(usage=usage)
        data = _serialize_reply(reply)
        assert data["usage"]["server_tool_tokens"] == 10

    def test_deserialize_usage_full(self) -> None:
        raw = {
            "input_tokens": 200,
            "output_tokens": 100,
            "cache_creation_input_tokens": 50,
            "cache_read_input_tokens": 30,
            "extra_field": 42,
        }
        usage = _deserialize_usage(raw)
        assert usage.input_tokens == 200
        assert usage.output_tokens == 100
        assert usage.cache_creation_input_tokens == 50
        assert usage.cache_read_input_tokens == 30
        assert usage.extra == {"extra_field": 42}

    def test_deserialize_usage_empty(self) -> None:
        usage = _deserialize_usage({})
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0

    def test_deserialize_usage_not_dict(self) -> None:
        usage = _deserialize_usage("not a dict")
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0


# ── ConversationStore tests ──────────────────────────────────────────


class TestConversationStore:
    def test_load_no_file(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        assert store.load() is None

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        (tmp_path / CONVERSATION_FILE_NAME).write_text("not json")
        store = ConversationStore(tmp_path)
        assert store.load() is None

    def test_load_missing_required_fields(self, tmp_path: Path) -> None:
        data = {"conversation_id": "abc", "replies": [{"incomplete": True}]}
        (tmp_path / CONVERSATION_FILE_NAME).write_text(json.dumps(data))
        store = ConversationStore(tmp_path)
        assert store.load() is None

    def test_save_and_load(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        metadata = ConversationMetadata(
            conversation_id="abc12345",
            model="opus",
            replies=[_make_reply()],
        )
        store.save(metadata)

        loaded = store.load()
        assert loaded is not None
        assert loaded.conversation_id == "abc12345"
        assert loaded.model == "opus"
        assert len(loaded.replies) == 1
        assert loaded.replies[0].session_id == "session-1"
        assert loaded.replies[0].usage.input_tokens == 100

    def test_save_creates_file(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        metadata = ConversationMetadata(conversation_id="abc")
        store.save(metadata)
        assert (tmp_path / CONVERSATION_FILE_NAME).exists()

    def test_save_overwrites(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)

        m1 = ConversationMetadata(conversation_id="abc", model="opus")
        store.save(m1)

        m2 = ConversationMetadata(conversation_id="abc", model="sonnet")
        store.save(m2)

        loaded = store.load()
        assert loaded is not None
        assert loaded.model == "sonnet"

    def test_add_reply(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        reply = _make_reply()

        result = store.add_reply("abc12345", reply)
        assert len(result.replies) == 1
        assert result.conversation_id == "abc12345"

        # Verify persisted
        loaded = store.load()
        assert loaded is not None
        assert len(loaded.replies) == 1

    def test_add_reply_appends(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)

        store.add_reply("abc", _make_reply(session_id="s1"))
        result = store.add_reply("abc", _make_reply(session_id="s2"))

        assert len(result.replies) == 2
        assert result.replies[0].session_id == "s1"
        assert result.replies[1].session_id == "s2"

    def test_add_reply_preserves_model(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        store.set_model("abc", "opus")

        store.add_reply("abc", _make_reply())

        loaded = store.load()
        assert loaded is not None
        assert loaded.model == "opus"

    def test_update_last_reply(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        store.add_reply("abc", _make_reply(session_id="s1", num_turns=3))

        updated = _make_reply(session_id="s1-updated", num_turns=5)
        result = store.update_last_reply("abc", updated)

        assert len(result.replies) == 1
        assert result.replies[0].session_id == "s1-updated"
        assert result.replies[0].num_turns == 5

    def test_update_last_reply_no_existing(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        reply = _make_reply()

        result = store.update_last_reply("abc", reply)
        assert len(result.replies) == 1

    def test_set_model(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        store.set_model("abc12345", "opus")

        loaded = store.load()
        assert loaded is not None
        assert loaded.model == "opus"
        assert loaded.conversation_id == "abc12345"

    def test_get_model(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        assert store.get_model() is None

        store.set_model("abc", "sonnet")
        assert store.get_model() == "sonnet"

    def test_get_session_id_for_resume(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        assert store.get_session_id_for_resume() is None

        store.add_reply("abc", _make_reply(session_id="sess-42"))
        assert store.get_session_id_for_resume() == "sess-42"

    def test_get_session_id_for_resume_skips_empty(
        self, tmp_path: Path
    ) -> None:
        store = ConversationStore(tmp_path)
        store.add_reply("abc", _make_reply(session_id="sess-1"))
        store.add_reply("abc", _make_reply(session_id=""))
        assert store.get_session_id_for_resume() == "sess-1"

    def test_get_last_successful_response(self, tmp_path: Path) -> None:
        store = ConversationStore(tmp_path)
        assert store.get_last_successful_response() is None

        store.add_reply(
            "abc",
            _make_reply(
                response_text="first reply",
                is_error=False,
            ),
        )
        assert store.get_last_successful_response() == "first reply"

    def test_get_last_successful_response_skips_errors(
        self, tmp_path: Path
    ) -> None:
        store = ConversationStore(tmp_path)
        store.add_reply(
            "abc",
            _make_reply(response_text="good reply", is_error=False),
        )
        store.add_reply(
            "abc",
            _make_reply(response_text="error reply", is_error=True),
        )
        assert store.get_last_successful_response() == "good reply"

    def test_get_last_successful_response_skips_empty_text(
        self, tmp_path: Path
    ) -> None:
        store = ConversationStore(tmp_path)
        store.add_reply(
            "abc",
            _make_reply(response_text="good reply", is_error=False),
        )
        store.add_reply(
            "abc",
            _make_reply(response_text=None, is_error=False),
        )
        assert store.get_last_successful_response() == "good reply"

    def test_get_last_successful_response_all_errors(
        self, tmp_path: Path
    ) -> None:
        store = ConversationStore(tmp_path)
        store.add_reply(
            "abc",
            _make_reply(response_text="error 1", is_error=True),
        )
        store.add_reply(
            "abc",
            _make_reply(response_text="error 2", is_error=True),
        )
        assert store.get_last_successful_response() is None


# ── Round-trip integration tests ─────────────────────────────────────


class TestRoundTrip:
    def test_full_round_trip(self, tmp_path: Path) -> None:
        """Save and load a complete conversation with all fields."""
        store = ConversationStore(tmp_path)
        store.set_model("abc12345", "opus")

        store.add_reply(
            "abc12345",
            ReplySummary(
                session_id="sess-1",
                timestamp="2026-01-15T12:00:00+00:00",
                duration_ms=5000,
                total_cost_usd=0.05,
                num_turns=3,
                is_error=False,
                usage=Usage(
                    input_tokens=200,
                    output_tokens=100,
                    cache_creation_input_tokens=50,
                    cache_read_input_tokens=30,
                    extra={"server_tool_tokens": 10},
                ),
                request_text="Do something",
                response_text="Done!",
            ),
        )

        loaded = store.load()
        assert loaded is not None
        assert loaded.conversation_id == "abc12345"
        assert loaded.model == "opus"
        assert len(loaded.replies) == 1

        reply = loaded.replies[0]
        assert reply.session_id == "sess-1"
        assert reply.timestamp == "2026-01-15T12:00:00+00:00"
        assert reply.duration_ms == 5000
        assert reply.total_cost_usd == pytest.approx(0.05)
        assert reply.num_turns == 3
        assert reply.is_error is False
        assert reply.usage.input_tokens == 200
        assert reply.usage.output_tokens == 100
        assert reply.usage.cache_creation_input_tokens == 50
        assert reply.usage.cache_read_input_tokens == 30
        assert reply.usage.extra == {"server_tool_tokens": 10}
        assert reply.request_text == "Do something"
        assert reply.response_text == "Done!"

    def test_multi_reply_round_trip(self, tmp_path: Path) -> None:
        """Save and load a conversation with multiple replies."""
        store = ConversationStore(tmp_path)
        store.set_model("abc12345", "sonnet")

        for i in range(3):
            store.add_reply(
                "abc12345",
                _make_reply(
                    session_id=f"sess-{i}",
                    total_cost_usd=0.01 * (i + 1),
                    num_turns=i + 1,
                ),
            )

        loaded = store.load()
        assert loaded is not None
        assert len(loaded.replies) == 3
        assert loaded.total_cost_usd == pytest.approx(0.06)
        assert loaded.total_turns == 6
        assert loaded.latest_session_id == "sess-2"

    def test_usage_extra_fields_round_trip(self, tmp_path: Path) -> None:
        """Extra usage fields survive serialization round-trip."""
        store = ConversationStore(tmp_path)
        usage = Usage(
            input_tokens=100,
            extra={"new_api_field": 42, "another_field": "value"},
        )
        store.add_reply("abc", _make_reply(usage=usage))

        loaded = store.load()
        assert loaded is not None
        loaded_usage = loaded.replies[0].usage
        assert loaded_usage.extra["new_api_field"] == 42
        assert loaded_usage.extra["another_field"] == "value"
