# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/claude_output/extract.py."""

import json

from lib.claude_output.extract import (
    extract_error_summary,
    extract_response_text,
    extract_result_summary,
    extract_session_id,
)
from lib.claude_output.parser import parse_stream_events
from lib.claude_output.types import Usage


def _make_system_event(session_id: str = "sess-123") -> dict:
    return {
        "type": "system",
        "subtype": "init",
        "session_id": session_id,
        "model": "claude-opus-4-5-20251101",
        "tools": ["Bash"],
    }


def _make_assistant_text_event(text: str = "Hello") -> dict:
    return {
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": text}]},
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
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_creation_input_tokens": 10,
            "cache_read_input_tokens": 20,
        },
        "result": result,
    }


def _parse(*events: dict) -> list:
    stdout = "\n".join(json.dumps(e) for e in events)
    return parse_stream_events(stdout)


class TestExtractResultSummary:
    def test_empty_events(self) -> None:
        assert extract_result_summary([]) is None

    def test_no_result_event(self) -> None:
        events = _parse(_make_system_event(), _make_assistant_text_event())
        assert extract_result_summary(events) is None

    def test_extracts_from_result(self) -> None:
        events = _parse(
            _make_system_event(),
            _make_assistant_text_event(),
            _make_result_event(),
        )
        summary = extract_result_summary(events)
        assert summary is not None
        assert summary.session_id == "sess-123"
        assert summary.duration_ms == 1500
        assert summary.total_cost_usd == 0.025
        assert summary.num_turns == 1
        assert summary.is_error is False
        assert summary.result_text == "Done."

    def test_extracts_usage(self) -> None:
        events = _parse(_make_result_event())
        summary = extract_result_summary(events)
        assert summary is not None
        assert summary.usage == Usage(
            input_tokens=100,
            output_tokens=50,
            cache_creation_input_tokens=10,
            cache_read_input_tokens=20,
        )

    def test_preserves_extra_usage_fields(self) -> None:
        event = {
            "type": "result",
            "subtype": "success",
            "session_id": "sess-123",
            "duration_ms": 1500,
            "total_cost_usd": 0.025,
            "num_turns": 1,
            "is_error": False,
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "server_tool_use": {"web_search_requests": 2},
            },
            "result": "Done.",
        }
        events = _parse(event)
        summary = extract_result_summary(events)
        assert summary is not None
        assert summary.usage.input_tokens == 100
        assert summary.usage.extra == {
            "server_tool_use": {"web_search_requests": 2},
        }

    def test_uses_last_result_event(self) -> None:
        events = _parse(
            _make_result_event(session_id="first"),
            _make_result_event(session_id="second"),
        )
        summary = extract_result_summary(events)
        assert summary is not None
        assert summary.session_id == "second"

    def test_error_result(self) -> None:
        events = _parse(_make_result_event(is_error=True, result="Error!"))
        summary = extract_result_summary(events)
        assert summary is not None
        assert summary.is_error is True
        assert summary.result_text == "Error!"


class TestExtractResponseText:
    def test_empty_events(self) -> None:
        assert extract_response_text([]) == "No output received from Claude."

    def test_from_assistant_event(self) -> None:
        events = _parse(
            _make_system_event(),
            _make_assistant_text_event("I completed the task."),
            _make_result_event(),
        )
        assert extract_response_text(events) == "I completed the task."

    def test_last_assistant_event_used(self) -> None:
        events = _parse(
            _make_assistant_text_event("First message"),
            _make_assistant_text_event("Second message"),
            _make_result_event(),
        )
        assert extract_response_text(events) == "Second message"

    def test_multiple_text_blocks_joined(self) -> None:
        event = {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "text": "Part one."},
                    {"type": "text", "text": "Part two."},
                ]
            },
        }
        events = _parse(event)
        assert extract_response_text(events) == "Part one.\n\nPart two."

    def test_fallback_to_result_text(self) -> None:
        events = _parse(_make_result_event(result="Fallback text"))
        assert extract_response_text(events) == "Fallback text"

    def test_fallback_to_result_dict(self) -> None:
        result_event = {
            "type": "result",
            "subtype": "success",
            "session_id": "s1",
            "result": {
                "content": [{"type": "text", "text": "From dict result"}]
            },
        }
        events = _parse(result_event)
        assert extract_response_text(events) == "From dict result"

    def test_skips_tool_use_blocks(self) -> None:
        event = {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "Bash",
                        "input": {},
                    },
                ]
            },
        }
        # Only tool_use, no text - should fall through
        events = _parse(event, _make_result_event(result="Fallback"))
        assert extract_response_text(events) == "Fallback"

    def test_no_content_falls_through(self) -> None:
        event = {"type": "assistant", "message": {"content": []}}
        events = _parse(event)
        assert (
            extract_response_text(events) == "No output received from Claude."
        )


class TestExtractErrorSummary:
    def test_empty_events(self) -> None:
        assert extract_error_summary([]) is None

    def test_extracts_result_text(self) -> None:
        events = _parse(_make_result_event(result="Error occurred"))
        assert extract_error_summary(events) == "Error occurred"

    def test_extracts_assistant_text(self) -> None:
        events = _parse(_make_assistant_text_event("Something went wrong"))
        assert extract_error_summary(events) == "Something went wrong"

    def test_prefers_result_over_assistant(self) -> None:
        events = _parse(
            _make_assistant_text_event("Assistant text"),
            _make_result_event(result="Result text"),
        )
        assert extract_error_summary(events) == "Result text"

    def test_truncates_to_max_lines(self) -> None:
        long_text = "\n".join(f"Line {i}" for i in range(20))
        events = _parse(_make_result_event(result=long_text))
        result = extract_error_summary(events, max_lines=5)
        assert result is not None
        assert len(result.split("\n")) == 5
        assert "Line 19" in result

    def test_no_useful_content_returns_none(self) -> None:
        # System event only — no text or result
        events = _parse(_make_system_event())
        assert extract_error_summary(events) is None

    def test_handles_tool_use_blocks(self) -> None:
        event = {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "Bash",
                        "input": {},
                    },
                ]
            },
        }
        events = _parse(event)
        assert extract_error_summary(events) is None

    def test_empty_result_returns_none(self) -> None:
        events = _parse(_make_result_event(result=""))
        assert extract_error_summary(events) is None

    def test_multiple_assistant_texts_combined(self) -> None:
        events = _parse(
            _make_assistant_text_event("First error"),
            _make_assistant_text_event("Second error"),
        )
        result = extract_error_summary(events)
        assert result is not None
        assert "First error" in result
        assert "Second error" in result

    def test_truncates_assistant_text_blocks(self) -> None:
        long_text = "\n".join(f"Line {i}" for i in range(20))
        events = _parse(_make_assistant_text_event(long_text))
        result = extract_error_summary(events, max_lines=3)
        assert result is not None
        assert len(result.split("\n")) == 3


class TestExtractSessionId:
    def test_empty_events(self) -> None:
        assert extract_session_id([]) is None

    def test_from_result_event(self) -> None:
        events = _parse(_make_result_event(session_id="from-result"))
        assert extract_session_id(events) == "from-result"

    def test_from_init_event(self) -> None:
        events = _parse(_make_system_event(session_id="from-init"))
        assert extract_session_id(events) == "from-init"

    def test_prefers_result_over_init(self) -> None:
        events = _parse(
            _make_system_event(session_id="from-init"),
            _make_result_event(session_id="from-result"),
        )
        assert extract_session_id(events) == "from-result"

    def test_fallback_to_init_when_result_empty(self) -> None:
        result_event = {
            "type": "result",
            "subtype": "success",
            "session_id": "",
            "result": "done",
        }
        events = _parse(
            _make_system_event(session_id="from-init"),
            result_event,
        )
        assert extract_session_id(events) == "from-init"

    def test_no_session_id_anywhere(self) -> None:
        event = {"type": "assistant", "message": {"content": []}}
        events = _parse(event)
        assert extract_session_id(events) is None

    def test_non_init_system_event_ignored(self) -> None:
        event = {"type": "system", "subtype": "other", "session_id": "s1"}
        events = _parse(event)
        assert extract_session_id(events) is None
