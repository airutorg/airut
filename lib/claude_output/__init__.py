# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Claude output parsing library.

Parses Claude's ``--output-format stream-json --verbose`` newline-delimited
JSON into typed event representations. Shared between the sandbox library
(output parsing during execution) and the gateway (response text extraction,
usage stats, dashboard rendering).
"""

from lib.claude_output.extract import (
    extract_error_summary,
    extract_response_text,
    extract_result_summary,
    extract_session_id,
)
from lib.claude_output.parser import (
    parse_event,
    parse_event_dict,
    parse_stream_events,
)
from lib.claude_output.types import (
    ContentBlock,
    EventType,
    ResultSummary,
    StreamEvent,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    Usage,
)


__all__ = [
    # Types
    "ContentBlock",
    "EventType",
    "ResultSummary",
    "StreamEvent",
    "TextBlock",
    "ToolResultBlock",
    "ToolUseBlock",
    "Usage",
    # Parser
    "parse_event",
    "parse_event_dict",
    "parse_stream_events",
    # Extraction
    "extract_error_summary",
    "extract_response_text",
    "extract_result_summary",
    "extract_session_id",
]
