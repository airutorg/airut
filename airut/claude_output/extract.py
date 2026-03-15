# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Extraction functions for Claude streaming events.

Higher-level functions that extract specific data from parsed event lists:
result summaries, response text, error summaries, and session IDs.
"""

from __future__ import annotations

import logging

from airut.claude_output.types import (
    _KNOWN_USAGE_KEYS,
    EventType,
    ResultSummary,
    StreamEvent,
    TextBlock,
    Usage,
)


logger = logging.getLogger(__name__)


def extract_result_summary(events: list[StreamEvent]) -> ResultSummary | None:
    """Extract result metadata from the result event(s).

    When multiple result events exist (from background tasks completing
    after the main result), ``duration_ms`` and ``num_turns`` are summed
    across all results (they are per-segment), while ``total_cost_usd``
    and ``usage`` come from the last result (they are cumulative).

    Args:
        events: Parsed stream events.

    Returns:
        Result summary, or ``None`` if no result event is present.
    """
    result_events = [e for e in events if e.event_type == EventType.RESULT]
    if not result_events:
        return None

    last = result_events[-1]
    extra = last.extra
    usage_dict = extra.get("usage", {})

    # Capture any API fields beyond the known token fields
    usage_extra = {
        k: v for k, v in usage_dict.items() if k not in _KNOWN_USAGE_KEYS
    }

    # duration_ms and num_turns are per-segment; sum across all results.
    # total_cost_usd and usage are cumulative; use last result.
    total_duration_ms = sum(
        e.extra.get("duration_ms", 0) for e in result_events
    )
    total_num_turns = sum(e.extra.get("num_turns", 0) for e in result_events)

    return ResultSummary(
        session_id=last.session_id,
        duration_ms=total_duration_ms,
        total_cost_usd=extra.get("total_cost_usd", 0.0),
        num_turns=total_num_turns,
        is_error=extra.get("is_error", False),
        usage=Usage(
            input_tokens=usage_dict.get("input_tokens", 0),
            output_tokens=usage_dict.get("output_tokens", 0),
            cache_creation_input_tokens=usage_dict.get(
                "cache_creation_input_tokens", 0
            ),
            cache_read_input_tokens=usage_dict.get(
                "cache_read_input_tokens", 0
            ),
            extra=usage_extra,
        ),
        result_text=extra.get("result", ""),
    )


def extract_response_text(events: list[StreamEvent]) -> str:
    """Extract Claude's response text from events.

    When multiple result events exist (caused by background tasks
    completing after the main result), concatenates all result texts
    in order.  For a single result, prefers the last assistant event's
    text blocks and falls back to the result event.

    This function always receives events from a single container
    execution, so all result events belong to the same task.

    Args:
        events: Parsed stream events.

    Returns:
        Response text, or a fallback message if nothing found.
    """
    # When multiple result events exist, concatenate all their texts.
    result_events = [e for e in events if e.event_type == EventType.RESULT]

    if len(result_events) > 1:
        result_texts: list[str] = []
        for event in result_events:
            text = _extract_result_text(event)
            if text:
                result_texts.append(text)
        if result_texts:
            return "\n\n".join(result_texts)

    # Single result (or none): try last assistant event first
    for event in reversed(events):
        if event.event_type != EventType.ASSISTANT:
            continue

        text_parts = [
            block.text
            for block in event.content_blocks
            if isinstance(block, TextBlock)
        ]
        if text_parts:
            return "\n\n".join(text_parts)

    # Fall back to result event
    for event in reversed(events):
        if event.event_type != EventType.RESULT:
            continue

        text = _extract_result_text(event)
        if text:
            return text

    return "No output received from Claude."


def _extract_result_text(event: StreamEvent) -> str:
    """Extract text from a single result event.

    Handles both string and dict (content-block) result formats.

    Args:
        event: A result-type stream event.

    Returns:
        Extracted text, or empty string if none found.
    """
    result = event.extra.get("result")
    if isinstance(result, str) and result:
        return result
    if isinstance(result, dict):
        content_blocks = result.get("content", [])
        text_parts = [
            block["text"]
            for block in content_blocks
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        if text_parts:
            return "\n\n".join(text_parts)
    return ""


def extract_error_summary(
    events: list[StreamEvent],
    max_lines: int = 10,
) -> str | None:
    """Extract a human-readable error summary from events.

    Prefers the result event's text. Falls back to concatenated
    text blocks from assistant messages. Truncates to *max_lines*
    (keeping the last lines).

    Args:
        events: Parsed stream events.
        max_lines: Maximum number of lines to include.

    Returns:
        Error summary string, or ``None`` if no useful content found.
    """
    text_blocks: list[str] = []
    result_text: str | None = None

    for event in events:
        if event.event_type == EventType.ASSISTANT:
            for block in event.content_blocks:
                if isinstance(block, TextBlock) and block.text.strip():
                    text_blocks.append(block.text.strip())

        elif event.event_type == EventType.RESULT:
            result = event.extra.get("result", "")
            if result:
                result_text = result

    if result_text:
        lines = result_text.strip().split("\n")
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        return "\n".join(lines)

    if text_blocks:
        combined = "\n".join(text_blocks)
        lines = combined.strip().split("\n")
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        return "\n".join(lines)

    return None


def extract_session_id(events: list[StreamEvent]) -> str | None:
    """Extract session_id from the result or system/init event.

    Prefers the result event's session_id. Falls back to the
    system/init event (needed when execution is interrupted and
    no result event is emitted).

    Args:
        events: Parsed stream events.

    Returns:
        Session ID string, or ``None`` if not found.
    """
    # Try result event first
    for event in reversed(events):
        if event.event_type == EventType.RESULT and event.session_id:
            return event.session_id

    # Fall back to system/init event
    for event in events:
        if (
            event.event_type == EventType.SYSTEM
            and event.subtype == "init"
            and event.session_id
        ):
            return event.session_id

    return None
