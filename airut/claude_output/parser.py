# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Parse Claude's streaming JSON output into typed events."""

from __future__ import annotations

import json
import logging
from typing import Any

from airut.claude_output.types import (
    ContentBlock,
    EventType,
    StreamEvent,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
)


logger = logging.getLogger(__name__)


def parse_stream_events(stdout: str) -> list[StreamEvent]:
    """Parse newline-delimited JSON from Claude into typed events.

    Each line of *stdout* is expected to be a complete JSON object
    produced by ``claude --output-format stream-json --verbose``.
    Non-JSON lines and non-dict JSON values are silently skipped.

    Args:
        stdout: Raw stdout from the Claude process.

    Returns:
        List of parsed events in order of appearance.
    """
    events: list[StreamEvent] = []

    if not stdout or not stdout.strip():
        return events

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            raw_obj = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON line: %s", line[:100])
            continue

        if not isinstance(raw_obj, dict):
            logger.debug("Skipping non-dict JSON value")
            continue

        event = _parse_event(raw_obj, line)
        if event is not None:
            events.append(event)

    return events


def parse_event(raw_json: str) -> StreamEvent | None:
    """Parse a single JSON line into a typed event.

    Useful for real-time streaming where events arrive one at a time.

    Args:
        raw_json: A single JSON line from Claude's output.

    Returns:
        Parsed event, or ``None`` if the line is not valid JSON or
        not a recognized event.
    """
    stripped = raw_json.strip()
    if not stripped:
        return None

    try:
        raw_obj = json.loads(stripped)
    except json.JSONDecodeError:
        return None

    if not isinstance(raw_obj, dict):
        return None

    return _parse_event(raw_obj, stripped)


def parse_event_dict(raw_obj: dict[str, Any]) -> StreamEvent | None:
    """Parse a pre-loaded dict into a typed event.

    Unlike :func:`parse_event`, this avoids a round-trip through
    ``json.dumps`` / ``json.loads`` when the caller already has
    a Python dict (e.g. loaded from a session JSON file).

    The ``raw`` field on the returned event is set to the canonical
    JSON serialization of *raw_obj*.

    Args:
        raw_obj: A dict representing a single Claude event.

    Returns:
        Parsed event, or ``None`` if the dict is not a recognized event.
    """
    return _parse_event(raw_obj, json.dumps(raw_obj, separators=(",", ":")))


_CORE_KEYS = {"type", "subtype", "session_id", "message"}


def _parse_event(raw_obj: dict[str, Any], raw_line: str) -> StreamEvent | None:
    """Convert a raw dict into a typed StreamEvent."""
    type_str = raw_obj.get("type")
    if not isinstance(type_str, str):
        return None

    try:
        event_type = EventType(type_str)
    except ValueError:
        logger.debug("Unknown event type: %s", type_str)
        event_type = EventType.UNKNOWN

    subtype = raw_obj.get("subtype", "")
    if not isinstance(subtype, str):
        subtype = ""

    session_id = raw_obj.get("session_id", "")
    if not isinstance(session_id, str):
        session_id = ""

    content_blocks = _extract_content_blocks(raw_obj, event_type)

    # For event types that parse "message" into content_blocks, exclude it
    # from extra. For unknown events, preserve all non-core keys including
    # "message" since it isn't structurally parsed.
    exclude = (
        _CORE_KEYS
        if event_type
        in (
            EventType.ASSISTANT,
            EventType.USER,
        )
        else _CORE_KEYS - {"message"}
    )
    extra = {k: v for k, v in raw_obj.items() if k not in exclude}

    return StreamEvent(
        event_type=event_type,
        subtype=subtype,
        session_id=session_id,
        content_blocks=tuple(content_blocks),
        raw=raw_line,
        extra=extra,
    )


def _extract_content_blocks(
    raw_obj: dict[str, Any],
    event_type: EventType,
) -> list[ContentBlock]:
    """Extract typed content blocks from an event dict."""
    if event_type not in (EventType.ASSISTANT, EventType.USER):
        return []

    message = raw_obj.get("message")
    if not isinstance(message, dict):
        return []

    content = message.get("content")
    if not isinstance(content, list):
        return []

    blocks: list[ContentBlock] = []
    for block in content:
        if not isinstance(block, dict):
            continue

        block_type = block.get("type")
        if block_type == "text":
            text = block.get("text", "")
            if isinstance(text, str):
                blocks.append(TextBlock(text=text))
        elif block_type == "tool_use":
            blocks.append(
                ToolUseBlock(
                    tool_id=block.get("id", ""),
                    tool_name=block.get("name", ""),
                    tool_input=block.get("input", {}),
                )
            )
        elif block_type == "tool_result":
            blocks.append(
                ToolResultBlock(
                    tool_id=block.get("tool_use_id", ""),
                    content=block.get("content", ""),
                    is_error=bool(block.get("is_error", False)),
                )
            )

    return blocks
