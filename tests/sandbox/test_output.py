# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_output.py -- ExecutionAccumulator."""

from airut.claude_output import parse_event
from airut.claude_output.types import Usage
from airut.sandbox._output import ExecutionAccumulator
from airut.sandbox.types import Outcome


# ── Helpers ──────────────────────────────────────────────────────────


def _feed_stdout(acc: ExecutionAccumulator, stdout: str) -> None:
    """Feed stdout lines through the accumulator (mimics task.py)."""
    for raw_line in stdout.splitlines(keepends=True):
        acc.on_stdout_line(raw_line)
        event = parse_event(raw_line)
        if event is not None:
            acc.on_event(event)


def _feed_stderr(acc: ExecutionAccumulator, stderr: str) -> None:
    """Feed stderr lines through the accumulator."""
    for raw_line in stderr.splitlines(keepends=True):
        acc.on_stderr_line(raw_line)


def _feed_and_build(
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    timed_out: bool = False,
    duration_ms: int = 100,
):
    """Feed output and build result in one step."""
    acc = ExecutionAccumulator()
    _feed_stdout(acc, stdout)
    _feed_stderr(acc, stderr)
    return acc.build_result(
        exit_code=exit_code, timed_out=timed_out, duration_ms=duration_ms
    )


# ── Outcome classification ──────────────────────────────────────────


class TestOutcomeClassification:
    """Tests for outcome classification via streaming flags."""

    def test_timeout(self) -> None:
        """Returns TIMEOUT when timed_out is True."""
        result = _feed_and_build(timed_out=True)
        assert result.outcome == Outcome.TIMEOUT

    def test_timeout_takes_precedence(self) -> None:
        """TIMEOUT takes precedence over other conditions."""
        stdout = '{"type": "result", "result": "Prompt is too long"}\n'
        result = _feed_and_build(stdout=stdout, exit_code=1, timed_out=True)
        assert result.outcome == Outcome.TIMEOUT

    def test_success(self) -> None:
        """Returns SUCCESS when exit_code is 0 and not timed out."""
        result = _feed_and_build(stdout="output\n", exit_code=0)
        assert result.outcome == Outcome.SUCCESS

    def test_prompt_too_long(self) -> None:
        """Returns PROMPT_TOO_LONG when stdout contains the message."""
        stdout = (
            '{"type": "result", "result": '
            '"Error: Prompt is too long for context window"}\n'
        )
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.outcome == Outcome.PROMPT_TOO_LONG

    def test_prompt_too_long_raw_text(self) -> None:
        """Detects PROMPT_TOO_LONG from non-JSON stdout lines."""
        result = _feed_and_build(stdout="Prompt is too long\n", exit_code=1)
        assert result.outcome == Outcome.PROMPT_TOO_LONG

    def test_session_corrupted_stdout(self) -> None:
        """Returns SESSION_CORRUPTED when stdout has API 4xx error."""
        result = _feed_and_build(
            stdout="API Error: 400 Bad Request\n", exit_code=1
        )
        assert result.outcome == Outcome.SESSION_CORRUPTED

    def test_session_corrupted_stderr(self) -> None:
        """Returns SESSION_CORRUPTED when stderr has API 4xx error."""
        result = _feed_and_build(
            stderr="API Error: 422 Unprocessable Entity\n",
            exit_code=1,
        )
        assert result.outcome == Outcome.SESSION_CORRUPTED

    def test_container_failed(self) -> None:
        """Returns CONTAINER_FAILED for nonzero exit with no markers."""
        result = _feed_and_build(stderr="Some error\n", exit_code=1)
        assert result.outcome == Outcome.CONTAINER_FAILED

    def test_container_failed_exit_code_2(self) -> None:
        """Returns CONTAINER_FAILED for exit code 2."""
        result = _feed_and_build(exit_code=2)
        assert result.outcome == Outcome.CONTAINER_FAILED


# ── Result building ─────────────────────────────────────────────────


class TestBuildResult:
    """Tests for ExecutionAccumulator.build_result()."""

    def test_success_with_events(self) -> None:
        """Builds result with metadata extracted from events."""
        stdout = (
            '{"type": "system", "subtype": "init", "session_id": "s1"}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Done"}]}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Done", "duration_ms": 1500, "total_cost_usd": 0.025, '
            '"num_turns": 1, "is_error": false, "usage": '
            '{"input_tokens": 100, "output_tokens": 50}}'
        )
        result = _feed_and_build(stdout=stdout, duration_ms=2000)

        assert result.outcome == Outcome.SUCCESS
        assert result.session_id == "s1"
        assert result.response_text == "Done"
        assert result.total_cost_usd == 0.025
        assert result.num_turns == 1
        assert result.usage.input_tokens == 100
        assert result.usage.output_tokens == 50
        # duration_ms from result event overrides parameter
        assert result.duration_ms == 1500

    def test_timeout_result(self) -> None:
        """Builds result with TIMEOUT outcome."""
        result = _feed_and_build(timed_out=True, duration_ms=300000)
        assert result.outcome == Outcome.TIMEOUT
        assert result.session_id == ""

    def test_empty_events(self) -> None:
        """Handles empty events gracefully."""
        result = _feed_and_build(exit_code=1, duration_ms=100)
        assert result.outcome == Outcome.CONTAINER_FAILED
        assert result.session_id == ""
        assert result.response_text == ""

    def test_session_id_from_init_event(self) -> None:
        """Falls back to session_id from init event when no result."""
        stdout = (
            '{"type": "system", "subtype": "init", "session_id": "init-id"}\n'
        )
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.session_id == "init-id"

    def test_default_usage_when_no_result_event(self) -> None:
        """Uses default empty Usage when no result event."""
        stdout = '{"type": "system", "subtype": "init"}\n'
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.usage == Usage()
        assert result.total_cost_usd == 0.0
        assert result.num_turns == 0

    def test_response_text_only_on_success(self) -> None:
        """Response text is only extracted when outcome is SUCCESS."""
        stdout = (
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Some output"}]}}\n'
        )
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.outcome == Outcome.CONTAINER_FAILED
        assert result.response_text == ""

    def test_is_error_from_result_event(self) -> None:
        """is_error is extracted from the result event."""
        stdout = (
            '{"type": "result", "subtype": "error", "session_id": "s1", '
            '"result": "Error", "duration_ms": 100, "total_cost_usd": 0.0, '
            '"num_turns": 0, "is_error": true, "usage": {}}'
        )
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.is_error is True

    def test_is_error_false_by_default(self) -> None:
        """is_error is False when no result event has is_error."""
        result = _feed_and_build(timed_out=True)
        assert result.is_error is False

    def test_web_search_and_fetch_counts(self) -> None:
        """Counts WebSearch and WebFetch tool uses from events."""
        stdout = (
            '{"type": "assistant", "message": {"content": ['
            '{"type": "tool_use", "id": "t1", "name": "WebSearch", '
            '"input": {}},'
            '{"type": "tool_use", "id": "t2", "name": "WebFetch", '
            '"input": {}},'
            '{"type": "tool_use", "id": "t3", "name": "WebSearch", '
            '"input": {}},'
            '{"type": "tool_use", "id": "t4", "name": "Bash", '
            '"input": {}}]}}'
        )
        result = _feed_and_build(stdout=stdout)
        assert result.web_search_count == 2
        assert result.web_fetch_count == 1

    def test_error_summary_on_failure(self) -> None:
        """error_summary is extracted for non-success outcomes."""
        stdout = '{"type": "result", "result": "Error: Something failed"}'
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.error_summary == "Error: Something failed"

    def test_error_summary_on_timeout(self) -> None:
        """error_summary is extracted for TIMEOUT outcomes."""
        stdout = '{"type": "result", "result": "Partial work done"}'
        result = _feed_and_build(stdout=stdout, timed_out=True)
        assert result.error_summary == "Partial work done"

    def test_error_summary_none_on_success(self) -> None:
        """error_summary is None for successful executions."""
        stdout = (
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Done", "duration_ms": 100, "total_cost_usd": 0.0, '
            '"num_turns": 1, "is_error": false, "usage": {}}'
        )
        result = _feed_and_build(stdout=stdout)
        assert result.error_summary is None

    def test_error_summary_from_assistant_text(self) -> None:
        """error_summary falls back to assistant text blocks."""
        stdout = (
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Working on it..."}]}}\n'
        )
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.error_summary == "Working on it..."

    def test_result_text_empty_when_none(self) -> None:
        """result_text is empty when result field is None."""
        import json

        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "s1",
                "result": None,
                "duration_ms": 100,
                "total_cost_usd": 0.0,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
            }
        )
        result = _feed_and_build(stdout=stdout)
        # Falls back to "No output received from Claude."
        assert "No output" in result.response_text

    def test_result_text_dict_format(self) -> None:
        """Extracts response text from dict (content-block) format."""
        import json

        result_dict = {
            "content": [
                {"type": "text", "text": "Hello from dict"},
            ]
        }
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "session_id": "s1",
                "result": result_dict,
                "duration_ms": 100,
                "total_cost_usd": 0.0,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
            }
        )
        result = _feed_and_build(stdout=stdout)
        assert result.response_text == "Hello from dict"

    def test_error_summary_truncation(self) -> None:
        """error_summary is truncated to max lines."""
        # Build a result event with > 10 lines of error text
        lines = "\n".join(f"Error line {i}" for i in range(15))
        import json

        stdout = json.dumps({"type": "result", "result": lines})
        result = _feed_and_build(stdout=stdout, exit_code=1)
        assert result.error_summary is not None
        summary_lines = result.error_summary.split("\n")
        assert len(summary_lines) == 10
        # Should keep the LAST 10 lines
        assert summary_lines[0] == "Error line 5"
        assert summary_lines[-1] == "Error line 14"

    def test_substantive_earlier_reply_preserved_over_coda(self) -> None:
        """A long earlier assistant text is prepended to a short coda.

        Mirrors the production failure mode where the model emits the
        real reply alongside a tool_use and then, after tool calls
        return, closes with a short confirmation. Without this, the
        user would only see the coda in the email.
        """
        long_text = "x" * 800
        stdout = (
            '{"type": "assistant", "message": {"content": '
            f'[{{"type": "text", "text": "{long_text}"}}]}}}}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "tool_use", "id": "t1", "name": "Bash", '
            '"input": {}}]}}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Short coda."}]}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Short coda.", "duration_ms": 100, '
            '"total_cost_usd": 0.0, "num_turns": 1, "is_error": false, '
            '"usage": {}}\n'
        )
        result = _feed_and_build(stdout=stdout)
        assert long_text in result.response_text
        assert "Short coda." in result.response_text
        assert result.response_text.index(
            long_text
        ) < result.response_text.index("Short coda.")

    def test_similar_sized_texts_return_only_last(self) -> None:
        """When last text is within 4x of earlier texts, only last is used."""
        stdout = (
            '{"type": "assistant", "message": {"content": '
            f'[{{"type": "text", "text": "{"a" * 600}"}}]}}}}\n'
            '{"type": "assistant", "message": {"content": '
            f'[{{"type": "text", "text": "{"b" * 400}"}}]}}}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "", "duration_ms": 100, "total_cost_usd": 0.0, '
            '"num_turns": 1, "is_error": false, "usage": {}}\n'
        )
        result = _feed_and_build(stdout=stdout)
        assert result.response_text == "b" * 400

    def test_multiple_result_events(self) -> None:
        """Handles multiple result events (background tasks)."""
        stdout = (
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Main result", "duration_ms": 1000, '
            '"total_cost_usd": 0.01, "num_turns": 1, "is_error": false, '
            '"usage": {"input_tokens": 50, "output_tokens": 20}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Background result", "duration_ms": 500, '
            '"total_cost_usd": 0.02, "num_turns": 1, "is_error": false, '
            '"usage": {"input_tokens": 100, "output_tokens": 40}}\n'
        )
        result = _feed_and_build(stdout=stdout)

        assert result.outcome == Outcome.SUCCESS
        # Response text is concatenated from all result events
        assert "Main result" in result.response_text
        assert "Background result" in result.response_text
        # duration_ms and num_turns are summed
        assert result.duration_ms == 1500
        assert result.num_turns == 2
        # total_cost_usd and usage come from the last result
        assert result.total_cost_usd == 0.02
        assert result.usage.input_tokens == 100
