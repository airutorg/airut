# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Task (conversation) detail page view."""

import html

from lib.container.session import SessionMetadata
from lib.dashboard.formatters import format_duration, format_timestamp
from lib.dashboard.tracker import TaskState, TaskStatus
from lib.dashboard.views.components import (
    render_action_buttons,
    render_session_section,
    render_stop_script,
)
from lib.dashboard.views.styles import task_detail_styles


def render_task_detail(
    task: TaskState,
    session: SessionMetadata | None = None,
) -> str:
    """Render task detail page HTML.

    Args:
        task: Task to display.
        session: Optional session metadata to display.

    Returns:
        HTML string for task detail page.
    """
    status_display = task.status.value.replace("_", " ").upper()
    success_text = ""
    if task.status == TaskStatus.COMPLETED:
        success_text = " - Success" if task.success else " - Failed"

    escaped_subject = html.escape(task.subject)

    # Precompute success class for the status span
    if task.success:
        success_class = "success"
    elif task.success is False:
        success_class = "failed"
    else:
        success_class = ""

    # Precompute formatted timestamps and durations
    queued_at = format_timestamp(task.queued_at)
    started_at = format_timestamp(task.started_at)
    completed_at = format_timestamp(task.completed_at)
    queue_time = format_duration(task.queue_duration())
    exec_time = format_duration(task.execution_duration())
    total_time = format_duration(task.total_duration())

    # Get model from task or session metadata
    model_display = task.model
    if not model_display and session:
        model_display = session.model
    model_display = model_display or "-"

    # Build session section if available
    session_section = render_session_section(task.conversation_id, session)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="10">
    <title>Conversation {task.conversation_id} - Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {task_detail_styles()}
    </style>
</head>
<body>
    <div class="back"><a href="/">&larr; Back to Dashboard</a></div>
    <div class="card">
        <h1>Conversation: {task.conversation_id}</h1>

        <div class="field">
            <div class="field-label">Subject</div>
            <div class="field-value">{escaped_subject}</div>
        </div>

        <div class="field">
            <div class="field-label">Repository</div>
            <div class="field-value">{html.escape(task.repo_id) or "-"}</div>
        </div>

        <div class="field">
            <div class="field-label">Sender</div>
            <div class="field-value">{html.escape(task.sender) or "-"}</div>
        </div>

        <div class="field">
            <div class="field-label">Status</div>
            <div class="field-value">
                <span class="status {task.status.value} {success_class}">
                    {status_display}{success_text}
                </span>
            </div>
        </div>

        <div class="field">
            <div class="field-label">Model</div>
            <div class="field-value mono">{model_display}</div>
        </div>

        <div class="field">
            <div class="field-label">Queued At</div>
            <div class="field-value mono">{queued_at}</div>
        </div>

        <div class="field">
            <div class="field-label">Started At</div>
            <div class="field-value mono">{started_at}</div>
        </div>

        <div class="field">
            <div class="field-label">Completed At</div>
            <div class="field-value mono">{completed_at}</div>
        </div>

        <div class="field">
            <div class="field-label">Queue Time</div>
            <div class="field-value mono">{queue_time}</div>
        </div>

        <div class="field">
            <div class="field-label">Execution Time</div>
            <div class="field-value mono">{exec_time}</div>
        </div>

        <div class="field">
            <div class="field-label">Total Time</div>
            <div class="field-value mono">{total_time}</div>
        </div>

        <div class="field">
            <div class="field-label">Messages in Conversation</div>
            <div class="field-value mono">{task.message_count}</div>
        </div>

        {render_action_buttons(task)}
    </div>
    {session_section}
    <div class="refresh-notice">Auto-refreshes every 10 seconds</div>
    {render_stop_script(task)}
</body>
</html>"""
