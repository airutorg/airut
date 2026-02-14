# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/claude_output/parser.py."""

import json

from lib.claude_output.parser import (
    parse_event,
    parse_event_dict,
    parse_stream_events,
)
from lib.claude_output.types import (
    EventType,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
)


def _make_system_event(
    session_id: str = "sess-123", model: str = "claude-opus-4-5-20251101"
) -> dict:
    return {
        "type": "system",
        "subtype": "init",
        "session_id": session_id,
        "model": model,
        "tools": ["Bash", "Read"],
    }


def _make_assistant_text_event(text: str = "Hello") -> dict:
    return {
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": text}]},
    }


def _make_assistant_tool_event(
    tool_name: str = "Bash", tool_id: str = "t1", tool_input: dict | None = None
) -> dict:
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": tool_id,
                    "name": tool_name,
                    "input": tool_input or {"command": "ls"},
                }
            ]
        },
    }


def _make_user_event(
    tool_id: str = "t1", content: str = "output", is_error: bool = False
) -> dict:
    return {
        "type": "user",
        "message": {
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": content,
                    "is_error": is_error,
                }
            ]
        },
    }


def _make_result_event(
    session_id: str = "sess-123",
    duration_ms: int = 1500,
    total_cost_usd: float = 0.025,
    num_turns: int = 1,
    is_error: bool = False,
    result: str = "Done.",
) -> dict:
    return {
        "type": "result",
        "subtype": "success" if not is_error else "error",
        "session_id": session_id,
        "duration_ms": duration_ms,
        "total_cost_usd": total_cost_usd,
        "num_turns": num_turns,
        "is_error": is_error,
        "usage": {"input_tokens": 100, "output_tokens": 50},
        "result": result,
    }


def _to_stdout(*events: dict) -> str:
    return "\n".join(json.dumps(e) for e in events)


class TestParseStreamEvents:
    def test_empty_string(self) -> None:
        assert parse_stream_events("") == []

    def test_whitespace_only(self) -> None:
        assert parse_stream_events("   \n\n  ") == []

    def test_single_system_event(self) -> None:
        stdout = json.dumps(_make_system_event())
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].event_type == EventType.SYSTEM
        assert events[0].subtype == "init"
        assert events[0].session_id == "sess-123"
        assert events[0].content_blocks == ()

    def test_assistant_text_blocks(self) -> None:
        stdout = json.dumps(_make_assistant_text_event("Hello world"))
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].event_type == EventType.ASSISTANT
        blocks = events[0].content_blocks
        assert len(blocks) == 1
        assert isinstance(blocks[0], TextBlock)
        assert blocks[0].text == "Hello world"

    def test_assistant_tool_use(self) -> None:
        stdout = json.dumps(
            _make_assistant_tool_event("Bash", "t1", {"command": "ls"})
        )
        events = parse_stream_events(stdout)
        assert len(events) == 1
        blocks = events[0].content_blocks
        assert len(blocks) == 1
        assert isinstance(blocks[0], ToolUseBlock)
        assert blocks[0].tool_name == "Bash"
        assert blocks[0].tool_id == "t1"
        assert blocks[0].tool_input == {"command": "ls"}

    def test_user_tool_result(self) -> None:
        stdout = json.dumps(_make_user_event("t1", "file.txt", False))
        events = parse_stream_events(stdout)
        assert len(events) == 1
        blocks = events[0].content_blocks
        assert len(blocks) == 1
        assert isinstance(blocks[0], ToolResultBlock)
        assert blocks[0].tool_id == "t1"
        assert blocks[0].content == "file.txt"
        assert blocks[0].is_error is False

    def test_user_tool_result_error(self) -> None:
        stdout = json.dumps(_make_user_event("t1", "error", True))
        events = parse_stream_events(stdout)
        blocks = events[0].content_blocks
        assert isinstance(blocks[0], ToolResultBlock)
        assert blocks[0].is_error is True

    def test_result_event(self) -> None:
        stdout = json.dumps(_make_result_event())
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].event_type == EventType.RESULT
        assert events[0].subtype == "success"
        assert events[0].session_id == "sess-123"

    def test_full_conversation(self) -> None:
        stdout = _to_stdout(
            _make_system_event(),
            _make_assistant_text_event("I'll help."),
            _make_assistant_tool_event("Bash", "t1"),
            _make_user_event("t1", "output"),
            _make_assistant_text_event("Done."),
            _make_result_event(),
        )
        events = parse_stream_events(stdout)
        assert len(events) == 6
        types = [e.event_type for e in events]
        assert types == [
            EventType.SYSTEM,
            EventType.ASSISTANT,
            EventType.ASSISTANT,
            EventType.USER,
            EventType.ASSISTANT,
            EventType.RESULT,
        ]

    def test_skips_non_json_lines(self) -> None:
        stdout = (
            "not json\n" + json.dumps(_make_system_event()) + "\nalso not json"
        )
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].event_type == EventType.SYSTEM

    def test_skips_non_dict_json(self) -> None:
        stdout = "[1,2,3]\n" + json.dumps(_make_system_event())
        events = parse_stream_events(stdout)
        assert len(events) == 1

    def test_skips_empty_lines(self) -> None:
        stdout = "\n\n" + json.dumps(_make_system_event()) + "\n\n"
        events = parse_stream_events(stdout)
        assert len(events) == 1

    def test_preserves_raw_json(self) -> None:
        original = _make_system_event()
        stdout = json.dumps(original)
        events = parse_stream_events(stdout)
        assert json.loads(events[0].raw) == original

    def test_unknown_event_type_preserved(self) -> None:
        stdout = json.dumps({"type": "unknown_type", "data": "stuff"})
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].event_type == EventType.UNKNOWN
        assert events[0].extra == {"data": "stuff"}

    def test_unknown_event_preserves_message_field(self) -> None:
        stdout = json.dumps(
            {"type": "status", "message": "in progress", "percent": 75}
        )
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].event_type == EventType.UNKNOWN
        assert events[0].extra["message"] == "in progress"
        assert events[0].extra["percent"] == 75

    def test_assistant_event_excludes_message_from_extra(self) -> None:
        stdout = json.dumps(_make_assistant_text_event("Hello"))
        events = parse_stream_events(stdout)
        assert "message" not in events[0].extra

    def test_missing_type_field_skipped(self) -> None:
        stdout = json.dumps({"data": "no type"})
        events = parse_stream_events(stdout)
        assert len(events) == 0

    def test_mixed_content_blocks(self) -> None:
        event = {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "text": "Let me check."},
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "Read",
                        "input": {"file_path": "/tmp/f"},
                    },
                ]
            },
        }
        stdout = json.dumps(event)
        events = parse_stream_events(stdout)
        blocks = events[0].content_blocks
        assert len(blocks) == 2
        assert isinstance(blocks[0], TextBlock)
        assert isinstance(blocks[1], ToolUseBlock)

    def test_no_content_in_message(self) -> None:
        event = {"type": "assistant", "message": {}}
        stdout = json.dumps(event)
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].content_blocks == ()

    def test_non_dict_content_blocks_skipped(self) -> None:
        event = {
            "type": "assistant",
            "message": {
                "content": ["not a dict", {"type": "text", "text": "ok"}]
            },
        }
        stdout = json.dumps(event)
        events = parse_stream_events(stdout)
        assert len(events[0].content_blocks) == 1

    def test_session_id_defaults_to_empty(self) -> None:
        event = {"type": "assistant", "message": {"content": []}}
        stdout = json.dumps(event)
        events = parse_stream_events(stdout)
        assert events[0].session_id == ""

    def test_subtype_defaults_to_empty(self) -> None:
        event = {"type": "assistant", "message": {"content": []}}
        stdout = json.dumps(event)
        events = parse_stream_events(stdout)
        assert events[0].subtype == ""

    def test_non_string_session_id_defaults(self) -> None:
        event = {"type": "system", "subtype": "init", "session_id": 12345}
        stdout = json.dumps(event)
        events = parse_stream_events(stdout)
        assert events[0].session_id == ""

    def test_non_string_subtype_defaults(self) -> None:
        event = {"type": "system", "subtype": 42}
        stdout = json.dumps(event)
        events = parse_stream_events(stdout)
        assert events[0].subtype == ""


class TestParseEvent:
    def test_valid_event(self) -> None:
        line = json.dumps(_make_system_event())
        event = parse_event(line)
        assert event is not None
        assert event.event_type == EventType.SYSTEM

    def test_empty_string(self) -> None:
        assert parse_event("") is None

    def test_whitespace_only(self) -> None:
        assert parse_event("   ") is None

    def test_invalid_json(self) -> None:
        assert parse_event("not json") is None

    def test_non_dict_json(self) -> None:
        assert parse_event("[1,2]") is None

    def test_unknown_type(self) -> None:
        event = parse_event(json.dumps({"type": "bogus"}))
        assert event is not None
        assert event.event_type == EventType.UNKNOWN

    def test_strips_whitespace(self) -> None:
        line = "  " + json.dumps(_make_system_event()) + "  "
        event = parse_event(line)
        assert event is not None
        assert event.event_type == EventType.SYSTEM


class TestParseEventDict:
    def test_valid_event(self) -> None:
        raw = _make_system_event()
        event = parse_event_dict(raw)
        assert event is not None
        assert event.event_type == EventType.SYSTEM
        assert event.session_id == "sess-123"

    def test_raw_field_is_canonical_json(self) -> None:
        raw = _make_system_event()
        event = parse_event_dict(raw)
        assert event is not None
        # raw should be valid JSON that round-trips to the same dict
        assert json.loads(event.raw) == raw

    def test_unknown_type_preserved(self) -> None:
        raw = {"type": "ping", "seq": 42}
        event = parse_event_dict(raw)
        assert event is not None
        assert event.event_type == EventType.UNKNOWN
        assert event.extra == {"seq": 42}

    def test_unknown_type_preserves_message_field(self) -> None:
        raw = {"type": "status", "message": "processing", "progress": 50}
        event = parse_event_dict(raw)
        assert event is not None
        assert event.event_type == EventType.UNKNOWN
        assert event.extra["message"] == "processing"
        assert event.extra["progress"] == 50

    def test_missing_type_returns_none(self) -> None:
        assert parse_event_dict({"data": "no type"}) is None

    def test_non_string_type_returns_none(self) -> None:
        assert parse_event_dict({"type": 123}) is None
