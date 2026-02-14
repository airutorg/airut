# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for the typed Claude output pipeline.

Tests that typed events survive the full pipeline:
  parse → EventLog/ConversationStore save → load → render

These tests exercise the real data flow without the email server,
focusing on typed parsing, event/conversation persistence, and
dashboard rendering.
"""

import json
import time
from datetime import UTC, datetime
from pathlib import Path

from lib.claude_output import (
    EventType,
    StreamEvent,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    extract_error_summary,
    extract_response_text,
    extract_result_summary,
    extract_session_id,
    parse_stream_events,
)
from lib.claude_output.types import Usage
from lib.conversation import (
    ConversationStore,
    ReplySummary,
)
from lib.dashboard.views.actions import (
    render_actions_timeline,
    render_events_list,
    render_single_event,
)
from lib.sandbox import EventLog


def _build_stdout(*event_dicts: dict) -> str:
    """Build mock Claude stdout from event dicts."""
    return "\n".join(json.dumps(e) for e in event_dicts)


def _system_event(
    session_id: str = "sess-test-123",
    model: str = "claude-opus-4-5-20251101",
) -> dict:
    return {
        "type": "system",
        "subtype": "init",
        "session_id": session_id,
        "model": model,
        "tools": ["Bash", "Read", "Write"],
    }


def _assistant_text_event(text: str) -> dict:
    return {
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": text}]},
    }


def _assistant_tool_event(
    tool_name: str,
    tool_input: dict,
    tool_id: str | None = None,
) -> dict:
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": tool_id or f"tool_{int(time.time() * 1000)}",
                    "name": tool_name,
                    "input": tool_input,
                }
            ]
        },
    }


def _user_tool_result_event(
    tool_id: str,
    content: str,
    is_error: bool = False,
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


def _result_event(
    session_id: str = "sess-test-123",
    result_text: str = "Done.",
    is_error: bool = False,
    duration_ms: int = 1500,
    total_cost_usd: float = 0.025,
    num_turns: int = 2,
    usage: dict | None = None,
) -> dict:
    return {
        "type": "result",
        "subtype": "error" if is_error else "success",
        "session_id": session_id,
        "duration_ms": duration_ms,
        "total_cost_usd": total_cost_usd,
        "num_turns": num_turns,
        "is_error": is_error,
        "usage": usage or {"input_tokens": 200, "output_tokens": 100},
        "result": result_text,
    }


def _save_reply(
    conversation_dir: Path,
    conversation_id: str,
    events: list[StreamEvent],
    request_text: str,
    response_text: str,
) -> tuple[ConversationStore, EventLog]:
    """Save events and metadata using the new split storage.

    Writes events to EventLog and builds a ReplySummary for
    ConversationStore, mirroring the real pipeline.

    Returns:
        Tuple of (conversation_store, event_log) for further assertions.
    """
    event_log = EventLog(conversation_dir)
    event_log.start_new_reply()
    for e in events:
        event_log.append_event(e)

    session_id = extract_session_id(events) or ""
    summary = extract_result_summary(events)
    if summary:
        reply = ReplySummary(
            session_id=session_id,
            timestamp=datetime.now(tz=UTC).isoformat(),
            duration_ms=summary.duration_ms,
            total_cost_usd=summary.total_cost_usd,
            num_turns=summary.num_turns,
            is_error=summary.is_error,
            usage=summary.usage,
            request_text=request_text,
            response_text=response_text,
        )
    else:
        reply = ReplySummary(
            session_id=session_id,
            timestamp=datetime.now(tz=UTC).isoformat(),
            duration_ms=0,
            total_cost_usd=0.0,
            num_turns=0,
            is_error=False,
            usage=Usage(),
            request_text=request_text,
            response_text=response_text,
        )

    conv_store = ConversationStore(conversation_dir)
    conv_store.add_reply(conversation_id, reply)

    return conv_store, event_log


class TestDashboardRendersTypedEvents:
    """Test that dashboard correctly renders typed events from parsed output."""

    def test_system_event_renders_model_and_tools(self) -> None:
        """System event renders model name and tool list."""
        stdout = _build_stdout(_system_event())
        events = parse_stream_events(stdout)
        html = render_single_event(events[0])

        assert "system:" in html
        assert "claude-opus-4-5-20251101" in html
        assert "Bash" in html
        assert "Read" in html

    def test_assistant_text_renders(self) -> None:
        """Assistant text block renders in dashboard HTML."""
        stdout = _build_stdout(_assistant_text_event("Hello, I'll help you."))
        events = parse_stream_events(stdout)
        html = render_single_event(events[0])

        assert (
            "Hello, I&#x27;ll help you." in html
            or "Hello, I'll help you." in html
        )

    def test_tool_use_renders_tool_name_and_input(self) -> None:
        """Tool use block renders tool name and input."""
        stdout = _build_stdout(
            _assistant_tool_event("Bash", {"command": "ls -la"}, "t1")
        )
        events = parse_stream_events(stdout)
        html = render_single_event(events[0])

        assert "Bash" in html
        assert "ls -la" in html

    def test_user_tool_result_renders(self) -> None:
        """User tool result block renders content."""
        stdout = _build_stdout(
            _user_tool_result_event("t1", "file.txt\nREADME.md")
        )
        events = parse_stream_events(stdout)
        html = render_single_event(events[0])

        assert "file.txt" in html

    def test_result_event_renders_metadata(self) -> None:
        """Result event renders duration, cost, and turns."""
        stdout = _build_stdout(
            _result_event(duration_ms=5000, total_cost_usd=0.042, num_turns=3)
        )
        events = parse_stream_events(stdout)
        html = render_single_event(events[0])

        assert "5000ms" in html
        assert "$0.0420" in html
        assert "3 turns" in html

    def test_full_conversation_renders_timeline(self, tmp_path) -> None:
        """Full conversation parse → save → load → render timeline."""
        stdout = _build_stdout(
            _system_event(),
            _assistant_text_event("I'll list the files."),
            _assistant_tool_event("Bash", {"command": "ls"}, "t1"),
            _user_tool_result_event("t1", "file.txt"),
            _assistant_text_event("Found file.txt."),
            _result_event(result_text="Found file.txt."),
        )

        # Parse
        events = parse_stream_events(stdout)
        assert len(events) == 6

        # Save using split storage
        conversation_dir = tmp_path / "conversations" / "test1234"
        conversation_dir.mkdir(parents=True)
        conv_store, event_log = _save_reply(
            conversation_dir,
            conversation_id="test1234",
            events=events,
            request_text="List the files",
            response_text="Found file.txt.",
        )

        # Load back
        loaded = conv_store.load()
        assert loaded is not None
        assert len(loaded.replies) == 1

        event_groups = event_log.read_all()
        assert len(event_groups) == 1
        assert len(event_groups[0]) == 6

        # Verify event types survived round-trip
        loaded_events = event_groups[0]
        assert loaded_events[0].event_type == EventType.SYSTEM
        assert loaded_events[1].event_type == EventType.ASSISTANT
        assert loaded_events[2].event_type == EventType.ASSISTANT
        assert loaded_events[3].event_type == EventType.USER
        assert loaded_events[4].event_type == EventType.ASSISTANT
        assert loaded_events[5].event_type == EventType.RESULT

        # Verify content blocks survived round-trip
        assert isinstance(loaded_events[1].content_blocks[0], TextBlock)
        assert loaded_events[1].content_blocks[0].text == "I'll list the files."
        assert isinstance(loaded_events[2].content_blocks[0], ToolUseBlock)
        assert loaded_events[2].content_blocks[0].tool_name == "Bash"
        assert isinstance(loaded_events[3].content_blocks[0], ToolResultBlock)
        assert loaded_events[3].content_blocks[0].content == "file.txt"

        # Render timeline from loaded data
        timeline_html = render_actions_timeline(loaded, event_groups)
        assert "Reply #1" in timeline_html
        assert "List the files" in timeline_html
        assert "system:" in timeline_html
        assert "Bash" in timeline_html
        assert "file.txt" in timeline_html


class TestErrorSummaryFromParsedEvents:
    """Test error summary extraction from pre-parsed events."""

    def test_error_summary_from_result_event(self) -> None:
        """Error summary extracts text from result event."""
        stdout = _build_stdout(
            _system_event(),
            _assistant_text_event("Attempting fix..."),
            _result_event(
                is_error=True,
                result_text="Error: permission denied",
            ),
        )
        events = parse_stream_events(stdout)
        summary = extract_error_summary(events)

        assert summary is not None
        assert "permission denied" in summary

    def test_error_summary_from_assistant_text(self) -> None:
        """Error summary falls back to assistant text blocks."""
        stdout = _build_stdout(
            _system_event(),
            _assistant_text_event("I encountered an error: disk full"),
            _result_event(is_error=True, result_text=""),
        )
        events = parse_stream_events(stdout)
        summary = extract_error_summary(events)

        assert summary is not None
        assert "disk full" in summary

    def test_error_summary_truncation(self) -> None:
        """Error summary truncates to max_lines."""
        long_error = "\n".join(f"line {i}" for i in range(20))
        stdout = _build_stdout(
            _system_event(),
            _result_event(is_error=True, result_text=long_error),
        )
        events = parse_stream_events(stdout)
        summary = extract_error_summary(events, max_lines=5)

        assert summary is not None
        lines = summary.strip().split("\n")
        assert len(lines) == 5
        # Should keep the last 5 lines
        assert "line 19" in summary

    def test_error_summary_none_when_no_content(self) -> None:
        """Error summary returns None when no useful content."""
        stdout = _build_stdout(
            _system_event(),
            _result_event(is_error=True, result_text=""),
        )
        events = parse_stream_events(stdout)
        summary = extract_error_summary(events)

        assert summary is None

    def test_error_summary_after_save_load(self, tmp_path) -> None:
        """Error summary works on events that went through save/load."""
        stdout = _build_stdout(
            _system_event(),
            _assistant_text_event("Working on it..."),
            _result_event(
                is_error=True,
                result_text="RuntimeError: connection refused",
            ),
        )
        events = parse_stream_events(stdout)

        # Save and load
        conversation_dir = tmp_path / "conversations" / "err12345"
        conversation_dir.mkdir(parents=True)
        _, event_log = _save_reply(
            conversation_dir,
            conversation_id="err12345",
            events=events,
            request_text="Do the thing",
            response_text="Working on it...",
        )

        event_groups = event_log.read_all()
        assert len(event_groups) == 1

        # Extract error summary from loaded events
        summary = extract_error_summary(event_groups[0])
        assert summary is not None
        assert "connection refused" in summary


class TestUnknownEventsThroughPipeline:
    """Test that unknown event types survive the full pipeline."""

    def test_unknown_event_parsed(self) -> None:
        """Unknown event type is parsed as EventType.UNKNOWN."""
        stdout = _build_stdout(
            {
                "type": "heartbeat",
                "seq": 42,
                "timestamp": "2026-01-01T00:00:00Z",
            }
        )
        events = parse_stream_events(stdout)
        assert len(events) == 1
        assert events[0].event_type == EventType.UNKNOWN
        assert events[0].extra["seq"] == 42

    def test_unknown_event_save_load_round_trip(self, tmp_path) -> None:
        """Unknown events survive EventLog save/load."""
        stdout = _build_stdout(
            _system_event(),
            {"type": "progress", "percent": 50, "message": "halfway"},
            _assistant_text_event("Done."),
            _result_event(),
        )
        events = parse_stream_events(stdout)
        assert len(events) == 4
        assert events[1].event_type == EventType.UNKNOWN

        # Save and load
        conversation_dir = tmp_path / "conversations" / "unk12345"
        conversation_dir.mkdir(parents=True)
        _, event_log = _save_reply(
            conversation_dir,
            conversation_id="unk12345",
            events=events,
            request_text="Test unknown events",
            response_text="Done.",
        )

        event_groups = event_log.read_all()
        assert len(event_groups) == 1

        loaded_events = event_groups[0]
        assert len(loaded_events) == 4
        assert loaded_events[1].event_type == EventType.UNKNOWN
        # Extra fields preserved
        assert loaded_events[1].extra["percent"] == 50
        assert loaded_events[1].extra["message"] == "halfway"

    def test_unknown_event_dashboard_render(self) -> None:
        """Unknown events render as collapsible raw JSON in dashboard."""
        stdout = _build_stdout(
            {"type": "custom_metric", "name": "token_rate", "value": 42.5}
        )
        events = parse_stream_events(stdout)
        html = render_single_event(events[0])

        # Should render as collapsible block with type label
        assert "custom_metric" in html
        assert "event" in html

    def test_unknown_event_full_pipeline_with_render(self, tmp_path) -> None:
        """Unknown events flow through parse → save → load → render."""
        stdout = _build_stdout(
            _system_event(),
            {"type": "thinking", "content": "Let me consider..."},
            _assistant_text_event("Here's my answer."),
            _result_event(),
        )
        events = parse_stream_events(stdout)

        # Save and load
        conversation_dir = tmp_path / "conversations" / "unkfull1"
        conversation_dir.mkdir(parents=True)
        conv_store, event_log = _save_reply(
            conversation_dir,
            conversation_id="unkfull1",
            events=events,
            request_text="Think about this",
            response_text="Here's my answer.",
        )
        loaded = conv_store.load()
        assert loaded is not None

        event_groups = event_log.read_all()

        # Render timeline
        timeline_html = render_actions_timeline(loaded, event_groups)
        assert "thinking" in timeline_html
        assert "system:" in timeline_html
        assert (
            "Here&#x27;s my answer." in timeline_html
            or "Here's my answer." in timeline_html
        )


class TestUsageExtraFieldsThroughPipeline:
    """Test that extra usage fields survive the full pipeline."""

    def test_usage_extra_parsed_from_result(self) -> None:
        """Extra usage fields are captured in ResultSummary."""
        usage = {
            "input_tokens": 500,
            "output_tokens": 200,
            "cache_creation_input_tokens": 50,
            "cache_read_input_tokens": 30,
            "server_tool_use": {"web_search_requests": 3},
            "service_tier": "standard",
        }
        stdout = _build_stdout(
            _system_event(),
            _result_event(usage=usage),
        )
        events = parse_stream_events(stdout)
        summary = extract_result_summary(events)

        assert summary is not None
        assert summary.usage.input_tokens == 500
        assert summary.usage.output_tokens == 200
        assert summary.usage.cache_creation_input_tokens == 50
        assert summary.usage.cache_read_input_tokens == 30
        assert summary.usage.extra["server_tool_use"] == {
            "web_search_requests": 3
        }
        assert summary.usage.extra["service_tier"] == "standard"

    def test_usage_extra_save_load_round_trip(self, tmp_path) -> None:
        """Extra usage fields survive ConversationStore save/load."""
        usage_dict = {
            "input_tokens": 400,
            "output_tokens": 150,
            "server_tool_use": {"web_search_requests": 2},
            "custom_metric": 99,
        }
        stdout = _build_stdout(
            _system_event(),
            _assistant_text_event("Results found."),
            _result_event(usage=usage_dict),
        )
        events = parse_stream_events(stdout)

        # Save
        conversation_dir = tmp_path / "conversations" / "usage123"
        conversation_dir.mkdir(parents=True)
        conv_store, _ = _save_reply(
            conversation_dir,
            conversation_id="usage123",
            events=events,
            request_text="Search for stuff",
            response_text="Results found.",
        )

        # Load
        loaded = conv_store.load()
        assert loaded is not None
        reply = loaded.replies[0]

        # Verify usage extras survived round-trip
        assert reply.usage.input_tokens == 400
        assert reply.usage.output_tokens == 150
        assert reply.usage.extra["server_tool_use"] == {
            "web_search_requests": 2
        }
        assert reply.usage.extra["custom_metric"] == 99

    def test_usage_extra_in_raw_conversation_json(self, tmp_path) -> None:
        """Extra usage fields appear in conversation.json wire format."""
        usage_dict = {
            "input_tokens": 100,
            "output_tokens": 50,
            "new_api_field": {"nested": True},
        }
        stdout = _build_stdout(
            _system_event(),
            _result_event(usage=usage_dict),
        )
        events = parse_stream_events(stdout)

        conversation_dir = tmp_path / "conversations" / "usagejson"
        conversation_dir.mkdir(parents=True)
        _save_reply(
            conversation_dir,
            conversation_id="usagejson",
            events=events,
            request_text="Test",
            response_text="Done.",
        )

        # Read raw JSON to verify wire format
        conversation_file = conversation_dir / "conversation.json"
        with conversation_file.open("r") as f:
            raw = json.load(f)

        reply_usage = raw["replies"][0]["usage"]
        assert reply_usage["input_tokens"] == 100
        assert reply_usage["output_tokens"] == 50
        assert reply_usage["new_api_field"] == {"nested": True}


class TestToolUseEventsThroughPipeline:
    """Test tool use events through parse/save/render cycle."""

    def test_tool_use_content_blocks_preserved(self) -> None:
        """Tool use content blocks parsed correctly."""
        stdout = _build_stdout(
            _assistant_tool_event(
                "Read", {"file_path": "/tmp/test.py"}, "tool_read_1"
            )
        )
        events = parse_stream_events(stdout)
        assert len(events) == 1
        block = events[0].content_blocks[0]
        assert isinstance(block, ToolUseBlock)
        assert block.tool_name == "Read"
        assert block.tool_id == "tool_read_1"
        assert block.tool_input == {"file_path": "/tmp/test.py"}

    def test_tool_result_content_blocks_preserved(self) -> None:
        """Tool result content blocks parsed correctly."""
        stdout = _build_stdout(
            _user_tool_result_event("tool_read_1", "file contents here", False)
        )
        events = parse_stream_events(stdout)
        block = events[0].content_blocks[0]
        assert isinstance(block, ToolResultBlock)
        assert block.tool_id == "tool_read_1"
        assert block.content == "file contents here"
        assert block.is_error is False

    def test_tool_result_error_flag(self) -> None:
        """Tool result error flag is preserved."""
        stdout = _build_stdout(
            _user_tool_result_event("t1", "command failed", True)
        )
        events = parse_stream_events(stdout)
        block = events[0].content_blocks[0]
        assert isinstance(block, ToolResultBlock)
        assert block.is_error is True

    def test_mixed_content_blocks_in_event(self) -> None:
        """Text and tool use blocks in same event are preserved."""
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
        stdout = _build_stdout(event)
        events = parse_stream_events(stdout)
        blocks = events[0].content_blocks
        assert len(blocks) == 2
        assert isinstance(blocks[0], TextBlock)
        assert isinstance(blocks[1], ToolUseBlock)

    def test_tool_events_save_load_render(self, tmp_path) -> None:
        """Tool use events survive save → load → render."""
        stdout = _build_stdout(
            _system_event(),
            _assistant_text_event("I'll read the file."),
            _assistant_tool_event(
                "Read", {"file_path": "/workspace/main.py"}, "t1"
            ),
            _user_tool_result_event("t1", "def main():\n    pass"),
            _assistant_tool_event(
                "Edit",
                {
                    "file_path": "/workspace/main.py",
                    "old_string": "pass",
                    "new_string": "print('hello')",
                },
                "t2",
            ),
            _user_tool_result_event("t2", "File edited successfully"),
            _assistant_text_event("Done editing."),
            _result_event(),
        )
        events = parse_stream_events(stdout)
        assert len(events) == 8

        # Save and load
        conversation_dir = tmp_path / "conversations" / "tool1234"
        conversation_dir.mkdir(parents=True)
        _, event_log = _save_reply(
            conversation_dir,
            conversation_id="tool1234",
            events=events,
            request_text="Edit the file",
            response_text="Done editing.",
        )

        event_groups = event_log.read_all()
        assert len(event_groups) == 1
        loaded_events = event_groups[0]
        assert len(loaded_events) == 8

        # Verify tool use blocks survived
        read_block = loaded_events[2].content_blocks[0]
        assert isinstance(read_block, ToolUseBlock)
        assert read_block.tool_name == "Read"
        assert read_block.tool_input["file_path"] == "/workspace/main.py"

        # Verify tool result blocks survived
        read_result = loaded_events[3].content_blocks[0]
        assert isinstance(read_result, ToolResultBlock)
        assert "def main" in read_result.content

        edit_block = loaded_events[4].content_blocks[0]
        assert isinstance(edit_block, ToolUseBlock)
        assert edit_block.tool_name == "Edit"

        # Render events list
        events_html = render_events_list(loaded_events)
        assert "Read" in events_html
        assert "Edit" in events_html
        assert "main.py" in events_html


class TestExtractionAfterRoundTrip:
    """Test extraction functions work on events after save/load round-trip."""

    def test_extract_response_text_after_round_trip(self, tmp_path) -> None:
        """extract_response_text works on loaded events."""
        stdout = _build_stdout(
            _system_event(),
            _assistant_text_event("Here is the answer."),
            _result_event(result_text="Here is the answer."),
        )
        events = parse_stream_events(stdout)

        conversation_dir = tmp_path / "conversations" / "resp1234"
        conversation_dir.mkdir(parents=True)
        _, event_log = _save_reply(
            conversation_dir,
            conversation_id="resp1234",
            events=events,
            request_text="What's the answer?",
            response_text="Here is the answer.",
        )

        event_groups = event_log.read_all()
        assert len(event_groups) == 1

        text = extract_response_text(event_groups[0])
        assert text == "Here is the answer."

    def test_extract_session_id_after_round_trip(self, tmp_path) -> None:
        """extract_session_id works on loaded events."""
        stdout = _build_stdout(
            _system_event(session_id="sess-abc-xyz"),
            _assistant_text_event("Hello."),
            _result_event(session_id="sess-abc-xyz"),
        )
        events = parse_stream_events(stdout)

        conversation_dir = tmp_path / "conversations" / "sid12345"
        conversation_dir.mkdir(parents=True)
        _, event_log = _save_reply(
            conversation_dir,
            conversation_id="sid12345",
            events=events,
            request_text="Hi",
            response_text="Hello.",
        )

        event_groups = event_log.read_all()
        assert len(event_groups) == 1

        sid = extract_session_id(event_groups[0])
        assert sid == "sess-abc-xyz"

    def test_extract_result_summary_after_round_trip(self, tmp_path) -> None:
        """extract_result_summary works on loaded events."""
        usage = {
            "input_tokens": 300,
            "output_tokens": 150,
            "server_tool_use": {"web_search_requests": 1},
        }
        stdout = _build_stdout(
            _system_event(),
            _result_event(
                duration_ms=2000,
                total_cost_usd=0.035,
                num_turns=4,
                usage=usage,
            ),
        )
        events = parse_stream_events(stdout)

        conversation_dir = tmp_path / "conversations" / "sum12345"
        conversation_dir.mkdir(parents=True)
        _, event_log = _save_reply(
            conversation_dir,
            conversation_id="sum12345",
            events=events,
            request_text="Do stuff",
            response_text="Done.",
        )

        event_groups = event_log.read_all()
        assert len(event_groups) == 1

        summary = extract_result_summary(event_groups[0])
        assert summary is not None
        assert summary.duration_ms == 2000
        assert summary.total_cost_usd == 0.035
        assert summary.num_turns == 4
        assert summary.usage.input_tokens == 300
        assert summary.usage.output_tokens == 150
        assert summary.usage.extra["server_tool_use"] == {
            "web_search_requests": 1
        }
