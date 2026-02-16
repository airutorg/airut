# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/claude_output/types.py."""

from airut.claude_output.types import (
    EventType,
    ResultSummary,
    StreamEvent,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    Usage,
)


class TestEventType:
    def test_values(self) -> None:
        assert EventType.SYSTEM.value == "system"
        assert EventType.ASSISTANT.value == "assistant"
        assert EventType.USER.value == "user"
        assert EventType.RESULT.value == "result"
        assert EventType.UNKNOWN.value == "_unknown"

    def test_from_string(self) -> None:
        assert EventType("system") == EventType.SYSTEM
        assert EventType("result") == EventType.RESULT


class TestTextBlock:
    def test_frozen(self) -> None:
        block = TextBlock(text="hello")
        assert block.text == "hello"

    def test_equality(self) -> None:
        assert TextBlock(text="a") == TextBlock(text="a")
        assert TextBlock(text="a") != TextBlock(text="b")


class TestToolUseBlock:
    def test_fields(self) -> None:
        block = ToolUseBlock(
            tool_id="t1",
            tool_name="Bash",
            tool_input={"command": "ls"},
        )
        assert block.tool_id == "t1"
        assert block.tool_name == "Bash"
        assert block.tool_input == {"command": "ls"}


class TestToolResultBlock:
    def test_string_content(self) -> None:
        block = ToolResultBlock(tool_id="t1", content="output", is_error=False)
        assert block.content == "output"
        assert block.is_error is False

    def test_list_content(self) -> None:
        content = [{"type": "text", "text": "result"}]
        block = ToolResultBlock(tool_id="t1", content=content, is_error=True)
        assert block.content == content
        assert block.is_error is True


class TestUsage:
    def test_defaults(self) -> None:
        usage = Usage()
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0
        assert usage.cache_creation_input_tokens == 0
        assert usage.cache_read_input_tokens == 0
        assert usage.extra == {}

    def test_custom_values(self) -> None:
        usage = Usage(input_tokens=100, output_tokens=50)
        assert usage.input_tokens == 100
        assert usage.output_tokens == 50

    def test_extra_fields_preserved(self) -> None:
        usage = Usage(
            input_tokens=100,
            extra={"server_tool_use": {"web_search_requests": 2}},
        )
        assert usage.extra["server_tool_use"] == {"web_search_requests": 2}


class TestStreamEvent:
    def test_fields(self) -> None:
        event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="",
            content_blocks=(TextBlock(text="hi"),),
            raw='{"type":"assistant"}',
        )
        assert event.event_type == EventType.ASSISTANT
        assert len(event.content_blocks) == 1

    def test_frozen(self) -> None:
        event = StreamEvent(
            event_type=EventType.SYSTEM,
            subtype="init",
            session_id="s1",
            content_blocks=(),
            raw="{}",
        )
        assert event.session_id == "s1"


class TestResultSummary:
    def test_fields(self) -> None:
        summary = ResultSummary(
            session_id="s1",
            duration_ms=1000,
            total_cost_usd=0.05,
            num_turns=3,
            is_error=False,
            usage=Usage(input_tokens=100),
            result_text="done",
        )
        assert summary.session_id == "s1"
        assert summary.duration_ms == 1000
        assert summary.total_cost_usd == 0.05
        assert summary.num_turns == 3
        assert summary.is_error is False
        assert summary.usage.input_tokens == 100
        assert summary.result_text == "done"
