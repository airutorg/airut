# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_output.py -- output parsing integration."""

import json

from lib.claude_output.types import Usage
from lib.sandbox._output import (
    build_execution_result,
    classify_outcome,
    extract_error_summary,
)
from lib.sandbox.types import Outcome


class TestClassifyOutcome:
    """Tests for classify_outcome function."""

    def test_timeout(self) -> None:
        """Returns TIMEOUT when timed_out is True."""
        result = classify_outcome(
            stdout="", stderr="", exit_code=0, timed_out=True
        )
        assert result == Outcome.TIMEOUT

    def test_timeout_takes_precedence(self) -> None:
        """TIMEOUT takes precedence over other conditions."""
        result = classify_outcome(
            stdout="Prompt is too long",
            stderr="",
            exit_code=1,
            timed_out=True,
        )
        assert result == Outcome.TIMEOUT

    def test_success(self) -> None:
        """Returns SUCCESS when exit_code is 0 and not timed out."""
        result = classify_outcome(
            stdout="output", stderr="", exit_code=0, timed_out=False
        )
        assert result == Outcome.SUCCESS

    def test_prompt_too_long(self) -> None:
        """Returns PROMPT_TOO_LONG when stdout contains the message."""
        result = classify_outcome(
            stdout="Error: Prompt is too long for context window",
            stderr="",
            exit_code=1,
            timed_out=False,
        )
        assert result == Outcome.PROMPT_TOO_LONG

    def test_session_corrupted_stdout(self) -> None:
        """Returns SESSION_CORRUPTED when stdout has API 4xx error."""
        result = classify_outcome(
            stdout="API Error: 400 Bad Request",
            stderr="",
            exit_code=1,
            timed_out=False,
        )
        assert result == Outcome.SESSION_CORRUPTED

    def test_session_corrupted_stderr(self) -> None:
        """Returns SESSION_CORRUPTED when stderr has API 4xx error."""
        result = classify_outcome(
            stdout="",
            stderr="API Error: 422 Unprocessable Entity",
            exit_code=1,
            timed_out=False,
        )
        assert result == Outcome.SESSION_CORRUPTED

    def test_container_failed(self) -> None:
        """Returns CONTAINER_FAILED for nonzero exit with no special markers."""
        result = classify_outcome(
            stdout="", stderr="Some error", exit_code=1, timed_out=False
        )
        assert result == Outcome.CONTAINER_FAILED

    def test_container_failed_exit_code_2(self) -> None:
        """Returns CONTAINER_FAILED for exit code 2."""
        result = classify_outcome(
            stdout="", stderr="", exit_code=2, timed_out=False
        )
        assert result == Outcome.CONTAINER_FAILED


class TestBuildExecutionResult:
    """Tests for build_execution_result function."""

    def test_success_with_events(self) -> None:
        """Builds result with parsed events on success."""
        stdout = (
            '{"type": "system", "subtype": "init", "session_id": "s1"}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Done"}]}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Done", "duration_ms": 1500, "total_cost_usd": 0.025, '
            '"num_turns": 1, "is_error": false, "usage": '
            '{"input_tokens": 100, "output_tokens": 50}}'
        )
        result = build_execution_result(
            stdout=stdout,
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_ms=2000,
        )

        assert result.outcome == Outcome.SUCCESS
        assert result.session_id == "s1"
        assert result.response_text == "Done"
        assert len(result.events) == 3
        assert result.total_cost_usd == 0.025
        assert result.num_turns == 1
        assert result.usage.input_tokens == 100
        assert result.usage.output_tokens == 50
        assert result.exit_code == 0
        # duration_ms from result event overrides parameter
        assert result.duration_ms == 1500

    def test_timeout_result(self) -> None:
        """Builds result with TIMEOUT outcome."""
        result = build_execution_result(
            stdout="",
            stderr="",
            exit_code=137,
            timed_out=True,
            duration_ms=300000,
        )

        assert result.outcome == Outcome.TIMEOUT
        assert result.session_id == ""
        assert result.exit_code == 137

    def test_empty_stdout(self) -> None:
        """Handles empty stdout gracefully."""
        result = build_execution_result(
            stdout="",
            stderr="error",
            exit_code=1,
            timed_out=False,
            duration_ms=100,
        )

        assert result.outcome == Outcome.CONTAINER_FAILED
        assert result.events == []
        assert result.session_id == ""
        assert result.response_text == ""

    def test_whitespace_only_stdout(self) -> None:
        """Handles whitespace-only stdout."""
        result = build_execution_result(
            stdout="  \n  \n",
            stderr="",
            exit_code=1,
            timed_out=False,
            duration_ms=100,
        )

        assert result.outcome == Outcome.CONTAINER_FAILED
        assert result.events == []

    def test_session_id_from_init_event(self) -> None:
        """Falls back to session_id from init event when no result."""
        stdout = (
            '{"type": "system", "subtype": "init", "session_id": "init-id"}\n'
        )
        result = build_execution_result(
            stdout=stdout,
            stderr="API Error: 429",
            exit_code=1,
            timed_out=False,
            duration_ms=500,
        )

        assert result.session_id == "init-id"

    def test_preserves_raw_stdout_stderr(self) -> None:
        """Result preserves raw stdout and stderr strings."""
        result = build_execution_result(
            stdout="raw stdout",
            stderr="raw stderr",
            exit_code=0,
            timed_out=False,
            duration_ms=100,
        )

        assert result.stdout == "raw stdout"
        assert result.stderr == "raw stderr"

    def test_default_usage_when_no_result_event(self) -> None:
        """Uses default empty Usage when no result event."""
        result = build_execution_result(
            stdout='{"type": "system", "subtype": "init"}',
            stderr="",
            exit_code=1,
            timed_out=False,
            duration_ms=100,
        )

        assert result.usage == Usage()
        assert result.total_cost_usd == 0.0
        assert result.num_turns == 0

    def test_response_text_only_on_success(self) -> None:
        """Response text is only extracted when outcome is SUCCESS."""
        # Container failed -- even if there's an assistant message,
        # response_text should be empty
        stdout = (
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Some output"}]}}\n'
        )
        result = build_execution_result(
            stdout=stdout,
            stderr="",
            exit_code=1,
            timed_out=False,
            duration_ms=100,
        )

        assert result.outcome == Outcome.CONTAINER_FAILED
        assert result.response_text == ""


class TestExtractErrorSummary:
    """Tests for extract_error_summary function."""

    def test_empty_input_returns_none(self) -> None:
        """Returns None for empty or whitespace input."""
        assert extract_error_summary("") is None
        assert extract_error_summary("   ") is None
        assert extract_error_summary("\n\n") is None

    def test_extracts_result_text(self) -> None:
        """Extracts text from result event."""
        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            '{"type": "result", "result": "Error: Something failed"}'
        )
        result = extract_error_summary(stdout)
        assert result == "Error: Something failed"

    def test_extracts_assistant_text_blocks(self) -> None:
        """Extracts text from assistant messages when no result."""
        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "I encountered an error"}]}}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "The file was not found"}]}}'
        )
        result = extract_error_summary(stdout)
        assert result is not None
        assert "I encountered an error" in result
        assert "The file was not found" in result

    def test_prefers_result_over_assistant_text(self) -> None:
        """Prefers result text over assistant text blocks."""
        stdout = (
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Some assistant text"}]}}\n'
            '{"type": "result", "result": "Final error message"}'
        )
        result = extract_error_summary(stdout)
        assert result == "Final error message"

    def test_truncates_to_max_lines(self) -> None:
        """Truncates output to max_lines, keeping last lines."""
        lines = [f"Line {i}" for i in range(20)]
        result_text = "\n".join(lines)
        stdout = f'{{"type": "result", "result": {json.dumps(result_text)}}}'
        result = extract_error_summary(stdout, max_lines=5)
        assert result is not None
        result_lines = result.split("\n")
        assert len(result_lines) == 5
        assert "Line 15" in result
        assert "Line 19" in result

    def test_handles_non_json_lines(self) -> None:
        """Skips non-JSON lines gracefully."""
        stdout = (
            "Some random text\n"
            '{"type": "result", "result": "Actual error"}\n'
            "More non-json\n"
        )
        result = extract_error_summary(stdout)
        assert result == "Actual error"

    def test_handles_non_dict_json(self) -> None:
        """Skips JSON lines that are not dicts."""
        stdout = (
            "[1, 2, 3]\n"
            '"just a string"\n'
            '{"type": "result", "result": "Real error"}'
        )
        result = extract_error_summary(stdout)
        assert result == "Real error"

    def test_returns_none_if_no_useful_content(self) -> None:
        """Returns None when no text or result found."""
        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            '{"type": "user", "message": "some user message"}'
        )
        result = extract_error_summary(stdout)
        assert result is None

    def test_handles_empty_result(self) -> None:
        """Returns None when result is empty string."""
        stdout = '{"type": "result", "result": ""}'
        result = extract_error_summary(stdout)
        assert result is None

    def test_handles_tool_use_blocks(self) -> None:
        """Ignores tool_use blocks in assistant messages."""
        stdout = (
            '{"type": "assistant", "message": {"content": '
            '[{"type": "tool_use", "name": "some_tool", "input": {}}]}}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Error occurred"}]}}'
        )
        result = extract_error_summary(stdout)
        assert result == "Error occurred"

    def test_skips_empty_lines_in_output(self) -> None:
        """Skips empty lines between JSON events."""
        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            "\n"
            "   \n"
            '{"type": "result", "result": "Error message"}\n'
            "\n"
        )
        result = extract_error_summary(stdout)
        assert result == "Error message"

    def test_truncates_text_blocks_to_max_lines(self) -> None:
        """Truncates text blocks output to max_lines, keeping last lines."""
        stdout = ""
        for i in range(15):
            stdout += (
                f'{{"type": "assistant", "message": {{"content": '
                f'[{{"type": "text", "text": "Line {i}"}}]}}}}\n'
            )
        result = extract_error_summary(stdout, max_lines=5)
        assert result is not None
        result_lines = result.split("\n")
        assert len(result_lines) == 5
        assert "Line 10" in result
        assert "Line 14" in result
        assert "Line 0" not in result
