# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Task (conversation) detail page view."""

import html

from lib.conversation import ConversationMetadata
from lib.dashboard.formatters import format_duration, format_timestamp
from lib.dashboard.tracker import TaskState, TaskStatus
from lib.dashboard.views.components import (
    render_action_buttons,
    render_conversation_section,
    render_stop_script,
)
from lib.dashboard.views.styles import task_detail_styles


def render_task_detail(
    task: TaskState,
    conversation: ConversationMetadata | None = None,
) -> str:
    """Render task detail page HTML.

    Args:
        task: Task to display.
        conversation: Optional conversation metadata to display.

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

    # Get model from task or conversation metadata
    model_display = task.model
    if not model_display and conversation:
        model_display = conversation.model
    model_display = model_display or "-"

    # Build conversation data section if available
    session_section = render_conversation_section(
        task.conversation_id, conversation
    )

    is_active = task.status in (TaskStatus.QUEUED, TaskStatus.IN_PROGRESS)
    sse_script = (
        _sse_task_detail_script(task.conversation_id) if is_active else ""
    )
    status_notice = (
        '<div id="stream-status" class="stream-status">Connecting...</div>'
        if is_active
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conversation {task.conversation_id} - Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {task_detail_styles()}
    </style>
</head>
<body>
<div class="page">
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
                <span id="task-status"
                    class="status {task.status.value} {success_class}">
                    {status_display}{success_text}
                </span>
            </div>
        </div>

        <div class="field">
            <div class="field-label">Model</div>
            <div id="task-model" class="field-value mono">{model_display}</div>
        </div>

        <div class="field">
            <div class="field-label">Queued At</div>
            <div class="field-value mono">{queued_at}</div>
        </div>

        <div class="field">
            <div class="field-label">Started At</div>
            <div id="task-started-at"
                class="field-value mono">{started_at}</div>
        </div>

        <div class="field">
            <div class="field-label">Completed At</div>
            <div id="task-completed-at"
                class="field-value mono">{completed_at}</div>
        </div>

        <div class="field">
            <div class="field-label">Queue Time</div>
            <div id="task-queue-time"
                class="field-value mono">{queue_time}</div>
        </div>

        <div class="field">
            <div class="field-label">Execution Time</div>
            <div id="task-exec-time"
                class="field-value mono">{exec_time}</div>
        </div>

        <div class="field">
            <div class="field-label">Total Time</div>
            <div id="task-total-time"
                class="field-value mono">{total_time}</div>
        </div>

        <div class="field">
            <div class="field-label">Messages in Conversation</div>
            <div id="task-message-count"
                class="field-value mono">{task.message_count}</div>
        </div>

        {render_action_buttons(task)}
    </div>
    {session_section}
</div>
    {status_notice}
    {render_stop_script(task)}
    {sse_script}
</body>
</html>"""


def _sse_task_detail_script(conversation_id: str) -> str:
    """JavaScript for SSE-based live task detail updates.

    Connects to the global state stream and updates the task detail
    fields in real-time when state changes.

    Args:
        conversation_id: Conversation ID to track.

    Returns:
        HTML <script> tag with SSE task detail update logic.
    """
    return f"""
    <script>
        function formatDuration(seconds) {{
            if (seconds == null) return '-';
            var m = Math.floor(seconds / 60);
            var s = Math.floor(seconds % 60);
            if (m > 0) return m + 'm ' + s + 's';
            return s + 's';
        }}

        function formatTimestamp(ts) {{
            if (ts == null) return '-';
            var d = new Date(ts * 1000);
            return d.toISOString();
        }}

        function connectTaskSSE() {{
            var source = new EventSource('/api/events/stream');
            var status = document.getElementById('stream-status');

            source.addEventListener('state', function(e) {{
                try {{
                    var data = JSON.parse(e.data);
                    var tasks = data.tasks || [];
                    var task = null;
                    for (var i = 0; i < tasks.length; i++) {{
                        if (tasks[i].conversation_id === '{conversation_id}') {{
                            task = tasks[i];
                            break;
                        }}
                    }}
                    if (!task) return;

                    // Update status
                    var statusEl = document.getElementById(
                        'task-status');
                    if (statusEl) {{
                        var display = task.status.replace(
                            '_', ' ').toUpperCase();
                        var successText = '';
                        if (task.status === 'completed') {{
                            successText = task.success
                                ? ' - Success' : ' - Failed';
                        }}
                        statusEl.textContent = display
                            + successText;
                        statusEl.className = 'status '
                            + task.status;
                        if (task.success === true) {{
                            statusEl.className += ' success';
                        }}
                        if (task.success === false) {{
                            statusEl.className += ' failed';
                        }}
                    }}

                    // Update model
                    var modelEl = document.getElementById('task-model');
                    if (modelEl) modelEl.textContent = task.model || '-';

                    // Update timestamps
                    var startedEl = document.getElementById(
                        'task-started-at');
                    if (startedEl) {{
                        startedEl.textContent = formatTimestamp(
                            task.started_at);
                    }}

                    var completedEl = document.getElementById(
                        'task-completed-at');
                    if (completedEl) {{
                        completedEl.textContent = formatTimestamp(
                            task.completed_at);
                    }}

                    // Update durations
                    var queueEl = document.getElementById(
                        'task-queue-time');
                    if (queueEl) {{
                        queueEl.textContent = formatDuration(
                            task.queue_duration);
                    }}

                    var execEl = document.getElementById(
                        'task-exec-time');
                    if (execEl) {{
                        execEl.textContent = formatDuration(
                            task.execution_duration);
                    }}

                    var totalEl = document.getElementById(
                        'task-total-time');
                    if (totalEl) {{
                        totalEl.textContent = formatDuration(
                            task.total_duration);
                    }}

                    // Update message count
                    var msgEl = document.getElementById('task-message-count');
                    if (msgEl) msgEl.textContent = task.message_count || 0;

                    // If completed, close stream and reload for full data
                    if (task.status === 'completed') {{
                        source.close();
                        if (status) status.textContent = 'Complete';
                        // Reload to get full conversation data
                        setTimeout(function() {{ location.reload(); }}, 1000);
                    }}

                    if (status) status.textContent = 'Live';
                }} catch (err) {{ /* ignore parse errors */ }}
            }});

            source.onerror = function() {{
                source.close();
                if (status) status.textContent = 'Polling (5s)';
                startTaskPolling();
            }};

            if (status) status.textContent = 'Live';
        }}

        function startTaskPolling() {{
            var status = document.getElementById('stream-status');
            setInterval(function() {{
                fetch('/api/conversations').then(function(resp) {{
                    if (resp.status === 200) return resp.json();
                    return null;
                }}).then(function(tasks) {{
                    if (!tasks) return;
                    var task = null;
                    for (var i = 0; i < tasks.length; i++) {{
                        if (tasks[i].conversation_id === '{conversation_id}') {{
                            task = tasks[i];
                            break;
                        }}
                    }}
                    if (task && task.status === 'completed') {{
                        if (status) status.textContent = 'Complete';
                        window.location.reload();
                    }}
                }}).catch(function() {{ /* ignore fetch errors */ }});
            }}, 5000);
        }}

        connectTaskSSE();
    </script>"""
