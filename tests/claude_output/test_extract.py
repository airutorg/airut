# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/claude_output/extract.py."""

import json

from airut.claude_output.extract import (
    extract_error_summary,
    extract_response_text,
    extract_result_summary,
    extract_session_id,
)
from airut.claude_output.parser import parse_stream_events
from airut.claude_output.types import Usage


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

    def test_uses_last_result_for_cumulative_fields(self) -> None:
        """Last result's cumulative fields (cost, usage) are used."""
        events = _parse(
            _make_result_event(total_cost_usd=2.52),
            _make_result_event(total_cost_usd=3.46),
        )
        summary = extract_result_summary(events)
        assert summary is not None
        assert summary.total_cost_usd == 3.46

    def test_sums_per_segment_fields(self) -> None:
        """duration_ms and num_turns are summed across all result events.

        These fields are per-segment (not cumulative) when background
        tasks complete after the main result.
        """
        events = _parse(
            _make_result_event(duration_ms=902580, num_turns=75),
            _make_result_event(duration_ms=27122, num_turns=2),
            _make_result_event(duration_ms=11346, num_turns=2),
        )
        summary = extract_result_summary(events)
        assert summary is not None
        assert summary.duration_ms == 902580 + 27122 + 11346
        assert summary.num_turns == 75 + 2 + 2

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

    def test_multiple_results_concatenated(self) -> None:
        """Multiple result events are concatenated.

        When background tasks complete after the main result, Claude
        emits additional result events in the same execution's stdout.
        All result texts must be included in the response.
        """
        events = _parse(
            _make_system_event(),
            _make_assistant_text_event("Main report"),
            _make_result_event(result="Main report"),
            # Background task completes, triggering re-init and follow-up
            {"type": "system", "subtype": "task_notification"},
            _make_system_event(),
            _make_assistant_text_event("Follow-up 1"),
            _make_result_event(result="Follow-up 1"),
        )
        result = extract_response_text(events)
        assert "Main report" in result
        assert "Follow-up 1" in result

    def test_multiple_results_three_results(self) -> None:
        """Three result events are all included in order."""
        events = _parse(
            _make_system_event(),
            _make_assistant_text_event("Report A"),
            _make_result_event(result="Report A"),
            {"type": "system", "subtype": "task_notification"},
            _make_system_event(),
            _make_assistant_text_event("Report B"),
            _make_result_event(result="Report B"),
            {"type": "system", "subtype": "task_notification"},
            _make_system_event(),
            _make_assistant_text_event("Report C"),
            _make_result_event(result="Report C"),
        )
        result = extract_response_text(events)
        assert "Report A" in result
        assert "Report B" in result
        assert "Report C" in result
        # Verify order: A before B before C
        assert result.index("Report A") < result.index("Report B")
        assert result.index("Report B") < result.index("Report C")

    def test_multiple_results_preserves_separator(self) -> None:
        """Multiple results are joined with double newline."""
        events = _parse(
            _make_result_event(result="Part 1"),
            _make_result_event(result="Part 2"),
        )
        assert extract_response_text(events) == "Part 1\n\nPart 2"

    def test_multiple_results_skips_empty(self) -> None:
        """Empty result texts are skipped during concatenation."""
        events = _parse(
            _make_result_event(result="Part 1"),
            _make_result_event(result=""),
            _make_result_event(result="Part 3"),
        )
        assert extract_response_text(events) == "Part 1\n\nPart 3"

    def test_multiple_results_all_empty_text_falls_through(self) -> None:
        """When all result texts are empty, falls through to assistant text."""
        events = _parse(
            _make_assistant_text_event("The real response"),
            _make_result_event(result=""),
            _make_result_event(result=""),
        )
        assert extract_response_text(events) == "The real response"

    def test_substantive_earlier_text_included_before_coda(self) -> None:
        """A substantially longer earlier text is prepended to the coda.

        Models sometimes emit the user-facing reply alongside a
        tool_use and then, after the tool call returns, emit a short
        closing remark. The response should include both so the user
        doesn't lose the real reply.
        """
        long_text = "x" * 800
        events = _parse(
            _make_assistant_text_event(long_text),
            _make_assistant_text_event("Short coda."),
            _make_result_event(result="Short coda."),
        )
        result = extract_response_text(events)
        assert long_text in result
        assert "Short coda." in result
        assert result.index(long_text) < result.index("Short coda.")

    def test_similar_sized_earlier_text_not_included(self) -> None:
        """An earlier text within 4x of the last is not pulled in.

        This keeps the default behavior unchanged when the last text
        is itself substantial — we only trigger when the last text
        looks like a short coda relative to an earlier one.
        """
        events = _parse(
            _make_assistant_text_event("a" * 600),
            _make_assistant_text_event("b" * 400),
            _make_result_event(),
        )
        result = extract_response_text(events)
        assert result == "b" * 400

    def test_substantive_text_outside_window_not_included(self) -> None:
        """Substantive text far back in history is ignored.

        The lookback window caps how far back we search, so long
        mid-task narration from earlier in a long session stays out
        of the response.
        """
        long_early = "x" * 2000
        events = _parse(
            _make_assistant_text_event(long_early),
            # Several short texts push long_early out of the window
            _make_assistant_text_event("noise 1"),
            _make_assistant_text_event("noise 2"),
            _make_assistant_text_event("noise 3"),
            _make_assistant_text_event("noise 4"),
            _make_assistant_text_event("final"),
            _make_result_event(result="final"),
        )
        result = extract_response_text(events)
        assert long_early not in result
        assert result == "final"

    def test_latest_substantive_chosen_over_earliest(self) -> None:
        """When multiple substantive texts exist, the latest is the anchor.

        This minimises the risk of including mid-task narration that
        preceded the real reply.
        """
        preamble = "p" * 1000
        reply = "r" * 900
        events = _parse(
            _make_assistant_text_event(preamble),
            _make_assistant_text_event("tiny interstitial"),
            _make_assistant_text_event(reply),
            _make_assistant_text_event("Coda."),
            _make_result_event(result="Coda."),
        )
        result = extract_response_text(events)
        assert reply in result
        assert "Coda." in result
        assert preamble not in result
        assert "tiny interstitial" not in result


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
