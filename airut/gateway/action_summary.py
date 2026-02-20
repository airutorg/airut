# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Channel-agnostic action summaries from Claude streaming events.

Produces short one-line descriptions of tool use actions suitable for
display in channel progress indicators (e.g. Slack plan block details).
"""

from __future__ import annotations

from airut.claude_output.types import ToolUseBlock


#: Maximum length for command/path/query strings in summaries.
_MAX_DETAIL_LEN = 80


def _truncate(text: str, max_len: int = _MAX_DETAIL_LEN) -> str:
    """Truncate text to *max_len* characters, adding ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "\u2026"


def summarize_action(block: ToolUseBlock) -> str | None:
    """Produce a one-line summary from a tool use block.

    Returns ``None`` for tool uses that should not be displayed as
    actions (e.g. ``TodoWrite``, which is handled separately via
    ``PlanStreamer.update()``).

    Args:
        block: A ``ToolUseBlock`` from a streaming event.

    Returns:
        Short description string, or ``None`` to skip.
    """
    inp = block.tool_input
    name = block.tool_name

    if name == "TodoWrite":
        return None

    if name == "Bash":
        cmd = inp.get("command", "")
        desc = inp.get("description", "")
        if desc:
            return _truncate(desc)
        if cmd:
            return f"Running: {_truncate(cmd)}"
        return "Running command"

    if name == "Read":
        path = inp.get("file_path", "")
        if path:
            return f"Reading {_truncate(path)}"
        return "Reading file"

    if name == "Write":
        path = inp.get("file_path", "")
        if path:
            return f"Writing {_truncate(path)}"
        return "Writing file"

    if name == "Edit":
        path = inp.get("file_path", "")
        if path:
            return f"Editing {_truncate(path)}"
        return "Editing file"

    if name == "Grep":
        pattern = inp.get("pattern", "")
        if pattern:
            return f'Searching for "{_truncate(pattern, 60)}"'
        return "Searching files"

    if name == "Glob":
        pattern = inp.get("pattern", "")
        if pattern:
            return f"Finding files: {_truncate(pattern, 60)}"
        return "Finding files"

    if name == "Task":
        desc = inp.get("description", "")
        if desc:
            return _truncate(desc)
        return "Running sub-task"

    if name == "WebFetch":
        url = inp.get("url", "")
        if url:
            return f"Fetching {_truncate(url, 60)}"
        return "Fetching URL"

    if name == "WebSearch":
        query = inp.get("query", "")
        if query:
            return f"Searching: {_truncate(query, 60)}"
        return "Web search"

    return f"Using {name}"
