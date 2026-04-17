# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Output parsing integration for the sandbox.

Provides ``ExecutionAccumulator``, a stateful parser that processes
streaming events and raw output lines during execution.  After the
container exits, ``build_result()`` returns a fully populated
``ExecutionResult`` — no re-reading from disk or second pass needed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import cast

from airut._json_types import JsonValue
from airut.claude_output.extract import select_reply_from_texts
from airut.claude_output.types import (
    _KNOWN_USAGE_KEYS,
    EventType,
    StreamEvent,
    TextBlock,
    ToolUseBlock,
    Usage,
)
from airut.sandbox.types import ExecutionResult, Outcome


logger = logging.getLogger(__name__)

_ERROR_SUMMARY_MAX_LINES = 10


@dataclass
class _ResultData:
    """Data extracted from a single result event."""

    session_id: str
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    is_error: bool
    result_text: str
    usage: Usage


class ExecutionAccumulator:
    """Processes streaming events to build ExecutionResult.

    Incrementally accumulates metadata from streaming events and
    raw output lines, so that no raw stdout/stderr or event lists
    need to be retained after execution.

    Three entry points, each processing a different signal source:

    - ``on_event()``:  parsed StreamEvent (metadata extraction)
    - ``on_stdout_line()``:  raw stdout line (outcome pattern detection)
    - ``on_stderr_line()``:  raw stderr line (outcome pattern detection)

    After the container exits, call ``build_result()`` with the exit
    info to get the final ``ExecutionResult``.
    """

    def __init__(self) -> None:
        # Session ID from system/init event (fallback when no result)
        self._init_session_id: str = ""

        # Result events (may be multiple — background tasks completing
        # after the main result)
        self._results: list[_ResultData] = []

        # Joined text per assistant event (for response_text in the
        # single-result case), all assistant text blocks (for
        # error_summary fallback)
        self._assistant_text_events: list[str] = []
        self._all_assistant_texts: list[str] = []

        # Web tool counts
        self._web_search_count: int = 0
        self._web_fetch_count: int = 0

        # Outcome flags (set during streaming, used by build_result)
        self._saw_prompt_too_long: bool = False
        self._saw_api_error_4: bool = False

    # ── Streaming entry points ──────────────────────────────────────

    def on_event(self, event: StreamEvent) -> None:
        """Process a parsed streaming event.

        Call this for each ``StreamEvent`` produced by ``parse_event()``.
        """
        if event.event_type == EventType.SYSTEM:
            if event.subtype == "init" and event.session_id:
                self._init_session_id = event.session_id

        elif event.event_type == EventType.ASSISTANT:
            self._process_assistant(event)

        elif event.event_type == EventType.RESULT:
            self._process_result(event)

    def on_stdout_line(self, line: str) -> None:
        """Check raw stdout line for outcome patterns.

        Does NOT accumulate the line — only sets detection flags.
        """
        if "Prompt is too long" in line:
            self._saw_prompt_too_long = True
        if "API Error: 4" in line:
            self._saw_api_error_4 = True

    def on_stderr_line(self, line: str) -> None:
        """Check raw stderr line for outcome patterns.

        Does NOT accumulate the line — only sets detection flags.
        """
        if "API Error: 4" in line:
            self._saw_api_error_4 = True

    # ── Result building ─────────────────────────────────────────────

    def build_result(
        self,
        *,
        exit_code: int,
        timed_out: bool,
        duration_ms: int,
    ) -> ExecutionResult:
        """Build final ExecutionResult from accumulated state.

        Args:
            exit_code: Container process exit code.
            timed_out: Whether the container was killed by timeout.
            duration_ms: Wall-clock execution duration in milliseconds.

        Returns:
            Fully populated ExecutionResult.
        """
        outcome = self._classify_outcome(exit_code, timed_out)

        # Merge result event data
        session_id = ""
        total_cost_usd = 0.0
        num_turns = 0
        is_error = False
        usage = Usage()

        if self._results:
            last = self._results[-1]
            session_id = last.session_id
            total_cost_usd = last.total_cost_usd
            is_error = last.is_error
            usage = last.usage

            # duration_ms and num_turns are per-segment; sum across all
            # results.  total_cost_usd and usage are cumulative (last).
            result_duration = sum(r.duration_ms for r in self._results)
            num_turns = sum(r.num_turns for r in self._results)
            duration_ms = result_duration or duration_ms

        if not session_id:
            session_id = self._init_session_id

        response_text = (
            self._build_response_text() if outcome == Outcome.SUCCESS else ""
        )

        error_summary = (
            self._build_error_summary() if outcome != Outcome.SUCCESS else None
        )

        return ExecutionResult(
            outcome=outcome,
            session_id=session_id,
            response_text=response_text,
            duration_ms=duration_ms,
            total_cost_usd=total_cost_usd,
            num_turns=num_turns,
            is_error=is_error,
            usage=usage,
            web_search_count=self._web_search_count,
            web_fetch_count=self._web_fetch_count,
            error_summary=error_summary,
        )

    # ── Internal helpers ────────────────────────────────────────────

    def _process_assistant(self, event: StreamEvent) -> None:
        """Extract text blocks and web tool counts from assistant event."""
        text_parts = [
            block.text
            for block in event.content_blocks
            if isinstance(block, TextBlock) and block.text
        ]
        if text_parts:
            self._assistant_text_events.append("\n\n".join(text_parts))
        for text in text_parts:
            stripped = text.strip()
            if stripped:
                self._all_assistant_texts.append(stripped)

        for block in event.content_blocks:
            if isinstance(block, ToolUseBlock):
                if block.tool_name == "WebSearch":
                    self._web_search_count += 1
                elif block.tool_name == "WebFetch":
                    self._web_fetch_count += 1

    def _process_result(self, event: StreamEvent) -> None:
        """Extract metadata from a result event."""
        extra = event.extra
        result_text = _extract_result_text(extra.get("result"))

        usage_raw = extra.get("usage", {})
        usage_dict = usage_raw if isinstance(usage_raw, dict) else {}
        usage_extra = {
            k: v for k, v in usage_dict.items() if k not in _KNOWN_USAGE_KEYS
        }

        self._results.append(
            _ResultData(
                session_id=event.session_id,
                duration_ms=cast(int, extra.get("duration_ms", 0)),
                total_cost_usd=cast(float, extra.get("total_cost_usd", 0.0)),
                num_turns=cast(int, extra.get("num_turns", 0)),
                is_error=cast(bool, extra.get("is_error", False)),
                result_text=result_text,
                usage=Usage(
                    input_tokens=cast(int, usage_dict.get("input_tokens", 0)),
                    output_tokens=cast(int, usage_dict.get("output_tokens", 0)),
                    cache_creation_input_tokens=cast(
                        int,
                        usage_dict.get("cache_creation_input_tokens", 0),
                    ),
                    cache_read_input_tokens=cast(
                        int, usage_dict.get("cache_read_input_tokens", 0)
                    ),
                    extra=usage_extra,
                ),
            )
        )

    def _classify_outcome(self, exit_code: int, timed_out: bool) -> Outcome:
        """Classify the execution outcome from flags and exit info."""
        if timed_out:
            return Outcome.TIMEOUT
        if exit_code == 0:
            return Outcome.SUCCESS
        if self._saw_prompt_too_long:
            return Outcome.PROMPT_TOO_LONG
        if self._saw_api_error_4:
            return Outcome.SESSION_CORRUPTED
        return Outcome.CONTAINER_FAILED

    def _build_response_text(self) -> str:
        """Build response text from accumulated data.

        When multiple result events exist (background tasks completing
        after the main result), concatenates all result texts.
        Otherwise selects an assistant text event via
        :func:`select_reply_from_texts` and falls back to the result
        event.
        """
        if len(self._results) > 1:
            texts = [r.result_text for r in self._results if r.result_text]
            if texts:
                return "\n\n".join(texts)

        reply = select_reply_from_texts(self._assistant_text_events)
        if reply is not None:
            return reply

        # Fall back to result event text
        if self._results and self._results[-1].result_text:
            return self._results[-1].result_text

        return "No output received from Claude."

    def _build_error_summary(self) -> str | None:
        """Build error summary from accumulated data.

        Prefers the last result event's text.  Falls back to
        concatenated text blocks from assistant messages.  Truncates
        to ``_ERROR_SUMMARY_MAX_LINES`` (keeping the last lines).
        """
        # Prefer result event text
        for r in reversed(self._results):
            if r.result_text:
                return _truncate_lines(r.result_text, _ERROR_SUMMARY_MAX_LINES)

        # Fall back to assistant text
        if self._all_assistant_texts:
            combined = "\n".join(self._all_assistant_texts)
            return _truncate_lines(combined, _ERROR_SUMMARY_MAX_LINES)

        return None


def _extract_result_text(result: JsonValue) -> str:
    """Extract text from a result event's ``result`` field.

    Handles both string and dict (content-block) formats.
    """
    if isinstance(result, str) and result:
        return result
    if isinstance(result, dict) and "content" in result:
        content = result["content"]
        if isinstance(content, list):
            text_parts = [
                block["text"]
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            if text_parts:
                return "\n\n".join(text_parts)
    return ""


def _truncate_lines(text: str, max_lines: int) -> str:
    """Keep only the last *max_lines* lines of *text*."""
    lines = text.strip().split("\n")
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(lines)
