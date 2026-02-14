# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Actions viewer page and event rendering.

Renders the dark-themed terminal-style page that shows the timeline
of Claude streaming events (system, assistant text, tool use/result,
result summaries) for a conversation.
"""

import html
import json
from typing import Any

from lib.claude_output.types import (
    EventType,
    StreamEvent,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
)
from lib.conversation import ConversationMetadata
from lib.dashboard.tracker import TaskState
from lib.dashboard.views.styles import actions_styles


# Maximum lines shown for edit diffs and tool results before truncation.
_EDIT_MAX_LINES = 20


def render_actions_page(
    task: TaskState,
    conversation: ConversationMetadata | None,
    event_groups: list[list[StreamEvent]] | None = None,
) -> str:
    """Render actions viewer page HTML.

    Args:
        task: Task to display.
        conversation: Conversation metadata with reply summaries.
        event_groups: Events grouped by reply from EventLog.

    Returns:
        HTML string for actions page.
    """
    escaped_subject = html.escape(task.subject)

    # Build actions content
    has_replies = conversation is not None and len(conversation.replies) > 0
    has_events = event_groups is not None and len(event_groups) > 0
    if not has_replies and not has_events:
        actions_content = '<div class="no-actions">No actions recorded</div>'
    else:
        actions_content = render_actions_timeline(conversation, event_groups)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Actions - {task.conversation_id}</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {actions_styles()}
    </style>
    <script>
        function toggleEvent(el) {{
            var body = el.parentElement.querySelector('.event-body');
            var icon = el.querySelector('.toggle-icon');
            if (body.classList.contains('expanded')) {{
                body.classList.remove('expanded');
                icon.textContent = '+';
            }} else {{
                body.classList.add('expanded');
                icon.textContent = '-';
            }}
        }}
    </script>
</head>
<body>
    <div class="header">
        <a href="/conversation/{task.conversation_id}">&larr; Back</a>
        <h1>Actions: {task.conversation_id}</h1>
        <span class="subtitle">{escaped_subject}</span>
    </div>
    <div class="terminal">
        {actions_content}
    </div>
    <script>window.scrollTo(0, document.body.scrollHeight);</script>
</body>
</html>"""


def render_actions_timeline(
    conversation: ConversationMetadata | None,
    event_groups: list[list[StreamEvent]] | None = None,
) -> str:
    """Render timeline of actions from conversation and events.

    Renders completed replies from conversation metadata paired with
    their events from the event log. Any event groups beyond the
    completed replies are rendered as in-progress replies (events
    streaming but reply not yet finished).

    Args:
        conversation: Conversation metadata with reply summaries.
        event_groups: Events grouped by reply from EventLog.

    Returns:
        HTML string for actions timeline.
    """
    sections: list[str] = []
    replies = conversation.replies if conversation is not None else []

    for i, reply in enumerate(replies, 1):
        error_class = "error" if reply.is_error else ""
        escaped_timestamp = html.escape(reply.timestamp)

        request_html = ""
        if reply.request_text:
            escaped_request = html.escape(reply.request_text)
            request_html = f"""
            <div class="event">
                <div class="ev-request-label">prompt</div>
                <div class="ev-request">{escaped_request}</div>
            </div>"""

        # Events come from the event log, indexed by reply position
        reply_events: list[StreamEvent] = []
        if event_groups is not None and (i - 1) < len(event_groups):
            reply_events = event_groups[i - 1]

        events_html = render_events_list(reply_events)

        sections.append(f"""
        <div class="reply-section {error_class}">
            <div class="reply-header">
                <span>Reply #{i}</span>
                <span class="reply-timestamp">{escaped_timestamp}</span>
            </div>
            {request_html}
            {events_html}
        </div>""")

    # Render in-progress event groups that don't have a completed reply yet
    if event_groups is not None:
        for j in range(len(replies), len(event_groups)):
            events_html = render_events_list(event_groups[j])
            reply_num = j + 1
            sections.append(f"""
        <div class="reply-section in-progress">
            <div class="reply-header">
                <span>Reply #{reply_num}</span>
                <span class="reply-timestamp">in progress</span>
            </div>
            {events_html}
        </div>""")

    return "".join(sections)


def render_events_list(events: list[StreamEvent]) -> str:
    """Render list of events as collapsible sections.

    Args:
        events: Typed streaming events.

    Returns:
        HTML string for events list.
    """
    if not events:
        return '<div class="no-actions">No events recorded</div>'

    items: list[str] = []

    for event in events:
        event_html = render_single_event(event)
        items.append(event_html)

    return "".join(items)


def render_single_event(event: StreamEvent) -> str:
    """Render a single event in CLI-style streaming format.

    Recognized event types are pretty-printed inline.

    Args:
        event: Typed streaming event.

    Returns:
        HTML string for event.
    """
    if event.event_type == EventType.SYSTEM:
        return _render_system_event(event)
    elif event.event_type == EventType.ASSISTANT:
        return _render_assistant_event(event)
    elif event.event_type == EventType.USER:
        return _render_user_event(event)
    elif event.event_type == EventType.RESULT:
        return _render_result_event(event)
    else:
        return _render_unknown_event(event)


# ── Event type renderers ─────────────────────────────────────────────


def _render_system_event(event: StreamEvent) -> str:
    """Render system event as a dim info line.

    Args:
        event: Typed system event.

    Returns:
        HTML string.
    """
    parts: list[str] = []
    if event.subtype:
        parts.append(html.escape(event.subtype))
    model = event.extra.get("model")
    if model:
        parts.append(f"model={html.escape(str(model))}")
    tools = event.extra.get("tools", [])
    if tools:
        tools_str = ", ".join(html.escape(str(t)) for t in tools[:20])
        if len(tools) > 20:
            tools_str += f"... (+{len(tools) - 20} more)"
        parts.append(f"tools=[{tools_str}]")
    if event.session_id:
        parts.append(f"session={html.escape(event.session_id)}")

    info = " ".join(parts)
    cls = "ev-system"
    return f'<div class="event"><div class="{cls}">system: {info}</div></div>'


def _render_assistant_event(event: StreamEvent) -> str:
    """Render assistant event: text blocks and tool calls.

    Args:
        event: Typed assistant event.

    Returns:
        HTML string.
    """
    if not event.content_blocks:
        return '<div class="event"><em>No content</em></div>'

    blocks: list[str] = []
    for block in event.content_blocks:
        if isinstance(block, TextBlock):
            text = html.escape(block.text)
            blocks.append(f'<div class="ev-text">{text}</div>')
        elif isinstance(block, ToolUseBlock):
            blocks.append(_render_tool_use_block_typed(block))

    if not blocks:
        return '<div class="event"><em>No content</em></div>'

    return '<div class="event">' + "".join(blocks) + "</div>"


def _render_user_event(event: StreamEvent) -> str:
    """Render user event (tool results).

    Args:
        event: Typed user event.

    Returns:
        HTML string.
    """
    if not event.content_blocks:
        return '<div class="event"><em>No content</em></div>'

    blocks: list[str] = []
    has_error = False
    for block in event.content_blocks:
        if isinstance(block, ToolResultBlock):
            blocks.append(_render_tool_result_block_typed(block))
            if block.is_error:
                has_error = True

    if not blocks:
        return '<div class="event"><em>No content</em></div>'

    error_class = " error" if has_error else ""

    return f'<div class="event{error_class}">' + "".join(blocks) + "</div>"


def _render_result_event(event: StreamEvent) -> str:
    """Render result summary event.

    Args:
        event: Typed result event.

    Returns:
        HTML string.
    """
    meta: list[str] = []
    if event.subtype:
        meta.append(html.escape(event.subtype))
    duration_ms = event.extra.get("duration_ms")
    if duration_ms is not None:
        meta.append(f"{duration_ms}ms")
    total_cost = event.extra.get("total_cost_usd")
    if total_cost is not None:
        meta.append(f"${total_cost:.4f}")
    num_turns = event.extra.get("num_turns")
    if num_turns is not None:
        meta.append(f"{num_turns} turns")

    header = "result: " + " | ".join(meta)

    result_text = event.extra.get("result", "")
    if isinstance(result_text, str) and result_text:
        preview = result_text[:500]
        if len(result_text) > 500:
            preview += "..."
        header += "\n" + html.escape(preview)

    cls = "ev-result"
    return f'<div class="event"><div class="{cls}">{header}</div></div>'


def _render_unknown_event(event: StreamEvent) -> str:
    """Render unrecognized event as collapsible raw JSON.

    Used for forward compatibility when the API introduces new event
    types not yet handled by the parser.

    Args:
        event: Event with ``EventType.UNKNOWN``.

    Returns:
        HTML string.
    """
    raw = html.escape(event.raw)
    raw_obj = json.loads(event.raw)
    type_label = html.escape(str(raw_obj.get("type", "unknown")))
    return f"""<div class="event">
            <div class="event-header" onclick="toggleEvent(this)">
                <span class="event-type">{type_label}</span>
                <span class="event-meta"></span>
                <span class="toggle-icon">+</span>
            </div>
            <div class="event-body">
                <div class="ev-raw">{raw}</div>
            </div>
        </div>"""


# ── Tool use / tool result renderers ─────────────────────────────────


def _render_tool_use_block_typed(block: ToolUseBlock) -> str:
    """Render a typed ToolUseBlock with specialized formatting.

    Known tools get purpose-built rendering. Unknown tools fall
    back to the tool name plus raw JSON input.

    Args:
        block: Typed tool use content block.

    Returns:
        HTML string.
    """
    escaped_name = html.escape(block.tool_name)

    renderer = _TOOL_RENDERERS.get(block.tool_name)
    if renderer:
        detail = renderer(block.tool_input)
    else:
        detail = _render_tool_generic(block.tool_input)

    return (
        f'<div class="ev-tool-use">'
        f'<span class="tool-name">{escaped_name}</span>'
        f"{detail}</div>"
    )


def _render_tool_bash(tool_input: dict[str, Any]) -> str:
    """Render Bash tool input.

    Args:
        tool_input: Bash tool input dict.

    Returns:
        HTML detail string.
    """
    cmd = html.escape(tool_input.get("command", ""))
    desc = tool_input.get("description", "")
    timeout = tool_input.get("timeout")

    parts: list[str] = []
    if desc:
        parts.append(f'<span class="tool-desc">{html.escape(desc)}</span>')
    if timeout:
        parts.append(f'<span class="tool-desc">(timeout={timeout}ms)</span>')
    header = "".join(parts)
    return f'{header}<div class="bash-cmd">{cmd}</div>'


def _render_tool_read(tool_input: dict[str, Any]) -> str:
    """Render Read tool input.

    Args:
        tool_input: Read tool input dict.

    Returns:
        HTML detail string.
    """
    path = html.escape(tool_input.get("file_path", ""))
    parts = [f'<span class="tool-desc">{path}</span>']
    offset = tool_input.get("offset")
    limit = tool_input.get("limit")
    if offset or limit:
        range_parts = []
        if offset:
            range_parts.append(f"offset={offset}")
        if limit:
            range_parts.append(f"limit={limit}")
        info = ", ".join(range_parts)
        parts.append(f'<span class="tool-desc">({info})</span>')
    return "".join(parts)


def _render_tool_edit(tool_input: dict[str, Any]) -> str:
    """Render Edit tool input as git-style diff.

    Args:
        tool_input: Edit tool input dict.

    Returns:
        HTML detail string.
    """
    path = html.escape(tool_input.get("file_path", ""))
    old = tool_input.get("old_string", "")
    new = tool_input.get("new_string", "")
    replace_all = tool_input.get("replace_all", False)

    parts = [f'<span class="tool-desc">{path}</span>']
    if replace_all:
        parts.append('<span class="tool-desc">(replace_all)</span>')

    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)

    removed = _format_diff_lines(
        old_lines,
        "-",
        _EDIT_MAX_LINES,
    )
    added = _format_diff_lines(
        new_lines,
        "+",
        _EDIT_MAX_LINES,
    )
    parts.append(
        f'<div class="diff-removed">{removed}</div>'
        f'<div class="diff-added">{added}</div>'
    )
    return "".join(parts)


def _format_diff_lines(
    lines: list[str],
    prefix: str,
    max_lines: int,
) -> str:
    """Format lines with a diff prefix, truncating.

    Args:
        lines: Source lines.
        prefix: '-' or '+'.
        max_lines: Max lines to show.

    Returns:
        HTML-escaped diff text.
    """
    truncated = len(lines) > max_lines
    shown = lines[:max_lines]
    result_parts: list[str] = []
    for line in shown:
        text = line.rstrip("\n\r")
        escaped = html.escape(text)
        result_parts.append(f"{prefix} {escaped}")
    if truncated:
        remaining = len(lines) - max_lines
        result_parts.append(f"... ({remaining} more lines)")
    return "\n".join(result_parts)


def _render_tool_write(tool_input: dict[str, Any]) -> str:
    """Render Write tool input.

    Args:
        tool_input: Write tool input dict.

    Returns:
        HTML detail string.
    """
    path = html.escape(tool_input.get("file_path", ""))
    content = tool_input.get("content", "")
    lines = content.count("\n") + 1 if content else 0
    chars = len(content)
    return (
        f'<span class="tool-desc">{path}</span>'
        f'<span class="tool-desc">'
        f"({lines} lines, {chars} chars)</span>"
    )


def _render_tool_grep(tool_input: dict[str, Any]) -> str:
    """Render Grep tool input.

    Args:
        tool_input: Grep tool input dict.

    Returns:
        HTML detail string.
    """
    pattern = html.escape(tool_input.get("pattern", ""))
    path = html.escape(tool_input.get("path", ""))
    glob = tool_input.get("glob", "")
    parts = [f'<span class="tool-desc">/{pattern}/</span>']
    if path:
        parts.append(f'<span class="tool-desc">{path}</span>')
    if glob:
        parts.append(f'<span class="tool-desc">glob={html.escape(glob)}</span>')
    return "".join(parts)


def _render_tool_glob(tool_input: dict[str, Any]) -> str:
    """Render Glob tool input.

    Args:
        tool_input: Glob tool input dict.

    Returns:
        HTML detail string.
    """
    pattern = html.escape(tool_input.get("pattern", ""))
    return f'<span class="tool-desc">{pattern}</span>'


def _render_tool_task(tool_input: dict[str, Any]) -> str:
    """Render Task tool input.

    Args:
        tool_input: Task tool input dict.

    Returns:
        HTML detail string.
    """
    desc = html.escape(tool_input.get("description", ""))
    return f'<span class="tool-desc">{desc}</span>'


def _render_tool_todowrite(tool_input: dict[str, Any]) -> str:
    """Render TodoWrite tool input.

    Args:
        tool_input: TodoWrite tool input dict.

    Returns:
        HTML detail string.
    """
    todos = tool_input.get("todos", [])
    items: list[str] = []
    for t in todos:
        status = t.get("status", "?")
        content = html.escape(t.get("content", ""))
        items.append(f"[{status}] {content}")
    body = "\n".join(items)
    return f'<div class="tool-detail">{body}</div>'


def _render_tool_generic(tool_input: dict[str, Any]) -> str:
    """Render unknown tool input as JSON.

    Args:
        tool_input: Tool input dict.

    Returns:
        HTML detail string with raw JSON.
    """
    full_json = html.escape(
        json.dumps(tool_input, indent=2, ensure_ascii=False)
    )
    return f'<div class="tool-input-json">{full_json}</div>'


# Map of tool names to their specialized renderers.
_TOOL_RENDERERS: dict[str, Any] = {
    "Bash": _render_tool_bash,
    "Read": _render_tool_read,
    "Write": _render_tool_write,
    "Edit": _render_tool_edit,
    "Grep": _render_tool_grep,
    "Glob": _render_tool_glob,
    "Task": _render_tool_task,
    "TodoWrite": _render_tool_todowrite,
}


def _render_tool_result_block_typed(block: ToolResultBlock) -> str:
    """Render a single typed tool result block.

    Args:
        block: Typed tool result content block.

    Returns:
        HTML string.
    """
    result_content = block.content
    # Content can be a list of content blocks or a string
    if isinstance(result_content, list):
        text_parts = []
        for part in result_content:
            is_text = isinstance(part, dict) and part.get("type") == "text"
            if is_text:
                text_parts.append(part.get("text", ""))
            elif isinstance(part, str):
                text_parts.append(part)
        result_content = "\n".join(text_parts)

    # Truncate large outputs to 20 lines (consistent with Edit tool)
    lines = result_content.split("\n")
    if len(lines) > _EDIT_MAX_LINES:
        result_content = (
            "\n".join(lines[:_EDIT_MAX_LINES])
            + f"\n\n... ({len(lines) - _EDIT_MAX_LINES} more lines)"
        )

    escaped = html.escape(result_content)
    error_class = " error" if block.is_error else ""
    error_note = " (error)" if block.is_error else ""
    label = f'<div class="ev-tool-result-label">Tool Result{error_note}:</div>'

    if not escaped.strip():
        return f'{label}<div class="ev-tool-result{error_class}">(empty)</div>'

    cls = f"ev-tool-result{error_class}"
    return f'{label}<div class="{cls}">{escaped}</div>'
