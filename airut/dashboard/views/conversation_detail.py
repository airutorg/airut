# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Conversation overview page view.

Shows all tasks for a conversation with links to individual task pages,
plus aggregate conversation statistics and full reply history.
"""

import html

from airut.conversation import ConversationMetadata
from airut.dashboard.formatters import format_duration
from airut.dashboard.tracker import (
    CompletionReason,
    TaskState,
    TaskStatus,
)
from airut.dashboard.views.components import (
    render_conversation_replies_section,
)
from airut.dashboard.views.styles import task_detail_styles


def _render_task_row(task: TaskState) -> str:
    """Render a single task row for the conversation task list.

    Args:
        task: Task state to render.

    Returns:
        HTML string for the task row.
    """
    # Status badge
    status_display = task.status.value.replace("_", " ").upper()
    if task.status == TaskStatus.COMPLETED:
        if task.succeeded:
            status_class = "success"
            icon = "&#x2713;"
        elif task.completion_reason in (
            CompletionReason.AUTH_FAILED,
            CompletionReason.UNAUTHORIZED,
            CompletionReason.REJECTED,
        ):
            status_class = "failed"
            icon = "&#x2298;"
        else:
            status_class = "failed"
            icon = "&#x2717;"
    elif task.status == TaskStatus.EXECUTING:
        status_class = "executing"
        icon = "&#x25B6;"
    else:
        status_class = "pending"
        icon = "&#x25CB;"

    # Time info
    if task.status == TaskStatus.EXECUTING:
        time_label = f"Running: {format_duration(task.execution_duration())}"
    elif task.status == TaskStatus.COMPLETED:
        time_label = f"Took: {format_duration(task.execution_duration())}"
    elif task.status == TaskStatus.PENDING:
        time_label = "Queued behind active task"
    else:
        time_label = f"Waiting: {format_duration(task.queue_duration())}"

    escaped_title = html.escape(task.display_title)
    truncated = (
        escaped_title[:50] + "..." if len(escaped_title) > 50 else escaped_title
    )

    return f"""
            <div class="task-row {status_class}">
                <div class="task-row-id">
                    <a href="/task/{task.task_id}">{task.task_id}</a>
                    <span class="status-icon">{icon}</span>
                    <span class="status {task.status.value} {status_class}">
                        {status_display}
                    </span>
                </div>
                <div class="task-row-title" title="{escaped_title}">
                    {truncated}
                </div>
                <div class="task-row-time">{time_label}</div>
            </div>"""


def render_conversation_detail(
    conversation_id: str,
    tasks: list[TaskState],
    conversation: ConversationMetadata | None = None,
) -> str:
    """Render conversation overview page HTML.

    Shows all tasks for the conversation and aggregate statistics.

    Args:
        conversation_id: Conversation identifier.
        tasks: All tasks for this conversation (newest first).
        conversation: Optional conversation metadata.

    Returns:
        HTML string for conversation overview page.
    """
    # Task list
    task_rows = "".join(_render_task_row(t) for t in tasks)

    # Aggregate stats
    cost_display = "-"
    turns_display = "-"
    reply_count = "0"
    model_display = "-"
    if conversation:
        if conversation.replies:
            cost_display = f"${conversation.total_cost_usd:.4f}"
            turns_display = str(conversation.total_turns)
            reply_count = str(len(conversation.replies))
        if conversation.model:
            model_display = conversation.model

    # Full reply history
    replies_section = render_conversation_replies_section(
        conversation_id, conversation
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conversation {conversation_id} - Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {task_detail_styles()}
        .task-row {{
            display: grid;
            grid-template-columns: 1fr 2fr 1fr;
            gap: 12px;
            align-items: center;
            padding: 10px 12px;
            background: #f8f9fa;
            border-radius: 6px;
            margin-bottom: 8px;
            border-left: 3px solid #ddd;
        }}
        .task-row.success {{ border-left-color: #5cb85c; }}
        .task-row.failed {{ border-left-color: #d9534f; }}
        .task-row.executing {{ border-left-color: #5bc0de; }}
        .task-row.pending {{ border-left-color: #f0ad4e; }}
        .task-row-id {{
            font-family: "SF Mono", Consolas, monospace;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .task-row-id a {{ color: #337ab7; text-decoration: none; }}
        .task-row-id a:hover {{ text-decoration: underline; }}
        .task-row-title {{
            font-size: 14px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .task-row-time {{
            font-size: 12px;
            color: #888;
            text-align: right;
        }}
        @media (max-width: 700px) {{
            .task-row {{
                grid-template-columns: 1fr;
                gap: 4px;
            }}
            .task-row-time {{ text-align: left; }}
        }}
    </style>
</head>
<body>
<div class="page">
    <div class="back"><a href="/">&larr; Back to Dashboard</a></div>
    <div class="card">
        <h1>Conversation: {conversation_id}</h1>

        <div class="conversation-summary">
            <div class="summary-item">
                <div class="summary-value">{reply_count}</div>
                <div class="summary-label">Replies</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{cost_display}</div>
                <div class="summary-label">Total Cost</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{turns_display}</div>
                <div class="summary-label">Total Turns</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{model_display}</div>
                <div class="summary-label">Model</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Tasks ({len(tasks)})</h2>
        {task_rows}
    </div>

    {replies_section}
</div>
</body>
</html>"""
