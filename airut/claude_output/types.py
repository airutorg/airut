# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Typed representations for Claude streaming JSON events.

Claude's ``--output-format stream-json --verbose`` produces newline-delimited
JSON with four event types: system/init, assistant, user, and result. This
module provides frozen dataclasses for each event and content block type.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import Enum
from typing import Any


class EventType(Enum):
    """Type of a streaming event.

    The ``UNKNOWN`` member is used for event types not yet recognized by
    the parser, ensuring forward compatibility when the API adds new
    event types.
    """

    SYSTEM = "system"
    ASSISTANT = "assistant"
    USER = "user"
    RESULT = "result"
    UNKNOWN = "_unknown"


@dataclass(frozen=True)
class TextBlock:
    """A text content block from an assistant message."""

    text: str


@dataclass(frozen=True)
class ToolUseBlock:
    """A tool invocation block from an assistant message."""

    tool_id: str
    tool_name: str
    tool_input: dict[str, Any]


@dataclass(frozen=True)
class ToolResultBlock:
    """A tool execution result block from a user message."""

    tool_id: str
    content: str | list[dict[str, Any]]
    is_error: bool


ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock


_KNOWN_USAGE_KEYS = {
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
}


@dataclass(frozen=True)
class Usage:
    """Token usage breakdown from a result event.

    Known fields are exposed as typed attributes. Any additional fields
    returned by the API (e.g. ``server_tool_use``, ``service_tier``)
    are preserved in the ``extra`` dict for forward compatibility.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    extra: dict[str, Any] = dataclass_field(default_factory=dict)


@dataclass(frozen=True)
class StreamEvent:
    """A single parsed event from Claude's streaming JSON output.

    Core fields (``event_type``, ``subtype``, ``session_id``,
    ``content_blocks``) are parsed into typed attributes.

    The ``raw`` field preserves the original JSON line for session file
    persistence and JSON API serialization.

    The ``extra`` dict carries event-type-specific fields not captured
    by the core attributes:

    - System/init events: ``model``, ``tools``
    - Result events: ``duration_ms``, ``total_cost_usd``, ``num_turns``,
      ``is_error``, ``usage``, ``result``
    """

    event_type: EventType
    subtype: str
    session_id: str
    content_blocks: tuple[ContentBlock, ...]
    raw: str
    extra: dict[str, Any] = dataclass_field(default_factory=dict)


@dataclass(frozen=True)
class ResultSummary:
    """Extracted metadata from a result event."""

    session_id: str
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    is_error: bool
    usage: Usage
    result_text: str
