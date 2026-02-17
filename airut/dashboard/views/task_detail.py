# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Task (conversation) detail page view."""

import html

from airut.conversation import ConversationMetadata
from airut.dashboard.formatters import format_duration, format_timestamp
from airut.dashboard.tracker import (
    ACTIVE_STATUSES,
    TaskState,
    TaskStatus,
    TodoItem,
    TodoStatus,
)
from airut.dashboard.views.components import (
    render_action_buttons,
    render_conversation_replies_section,
    render_stop_script,
)
from airut.dashboard.views.styles import task_detail_styles


def _render_progress_section(todos: list[TodoItem]) -> str:
    """Render the checklist-style progress section.

    Args:
        todos: List of :class:`TodoItem` instances.

    Returns:
        HTML string for the progress section.
    """
    if not todos:
        return ""

    items: list[str] = []
    for todo in todos:
        content = html.escape(todo.content)
        active_form = html.escape(todo.active_form or todo.content)

        if todo.status == TodoStatus.COMPLETED:
            icon = '<span class="todo-icon completed">&#x2713;</span>'
            css_class = "completed"
            label = content
        elif todo.status == TodoStatus.IN_PROGRESS:
            icon = '<span class="todo-spinner"></span>'
            css_class = "in-progress"
            label = active_form
        else:
            icon = '<span class="todo-icon pending">&#x25CB;</span>'
            css_class = "pending"
            label = content

        items.append(
            f'<div class="todo-item {css_class}">'
            f"{icon}"
            f'<span class="todo-label">{label}</span>'
            f"</div>"
        )

    return f"""
    <div id="progress-section" class="card progress-card">
        <h2>Progress</h2>
        <div id="todo-list" class="todo-list">
            {"".join(items)}
        </div>
    </div>"""


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
        if task.succeeded:
            success_text = " - Success"
        elif task.completion_reason is not None:
            reason_label = task.completion_reason.value.replace(
                "_", " "
            ).title()
            success_text = f" - {reason_label}"
        else:
            success_text = " - Failed"

    escaped_title = html.escape(task.display_title)

    # Precompute success class for the status span
    if task.succeeded:
        success_class = "success"
    elif task.status == TaskStatus.COMPLETED:
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

    # Build conversation cost/turns for the details section
    cost_display = "-"
    turns_display = "-"
    if conversation and conversation.replies:
        cost_display = f"${conversation.total_cost_usd:.4f}"
        turns_display = str(conversation.total_turns)

    # Build conversation replies section
    replies_section = render_conversation_replies_section(
        task.conversation_id, conversation
    )

    # Build progress section from todos
    is_active = task.status in ACTIVE_STATUSES
    progress_section = ""
    if task.todos and is_active:
        progress_section = _render_progress_section(task.todos)

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
            <div class="field-value">{escaped_title}</div>
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

        {render_action_buttons(task)}
    </div>
    {progress_section}
    <div class="card">
        <h2>Task Details</h2>

        <div class="field">
            <div class="field-label">Model</div>
            <div id="task-model" class="field-value mono">{model_display}</div>
        </div>

        <div class="details-grid">
            <div class="detail-item">
                <div class="field-label">Queued At</div>
                <div class="field-value mono">{queued_at}</div>
            </div>
            <div class="detail-item">
                <div class="field-label">Started At</div>
                <div id="task-started-at"
                    class="field-value mono">{started_at}</div>
            </div>
            <div class="detail-item">
                <div class="field-label">Completed At</div>
                <div id="task-completed-at"
                    class="field-value mono">{completed_at}</div>
            </div>
            <div class="detail-item">
                <div class="field-label">Queue Time</div>
                <div id="task-queue-time"
                    class="field-value mono">{queue_time}</div>
            </div>
            <div class="detail-item">
                <div class="field-label">Execution Time</div>
                <div id="task-exec-time"
                    class="field-value mono">{exec_time}</div>
            </div>
            <div class="detail-item">
                <div class="field-label">Total Time</div>
                <div id="task-total-time"
                    class="field-value mono">{total_time}</div>
            </div>
            <div class="detail-item">
                <div class="field-label">Total Cost</div>
                <div class="field-value mono">{cost_display}</div>
            </div>
            <div class="detail-item">
                <div class="field-label">Total Turns</div>
                <div class="field-value mono">{turns_display}</div>
            </div>
        </div>
    </div>
    {replies_section}
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

        function escapeHtml(text) {{
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        function renderTodos(todos) {{
            var section = document.getElementById('progress-section');
            var list = document.getElementById('todo-list');
            if (!todos || todos.length === 0) {{
                if (section) section.style.display = 'none';
                return;
            }}
            // Create section if it doesn't exist yet
            if (!section) {{
                section = document.createElement('div');
                section.id = 'progress-section';
                section.className = 'card progress-card';
                section.innerHTML = '<h2>Progress</h2>'
                    + '<div id="todo-list" class="todo-list"></div>';
                // Insert after the first card
                var cards = document.querySelectorAll('.card');
                if (cards.length > 0) {{
                    cards[0].after(section);
                }}
                list = document.getElementById('todo-list');
            }} else {{
                section.style.display = '';
            }}
            var html = '';
            for (var i = 0; i < todos.length; i++) {{
                var t = todos[i];
                var status = t.status || 'pending';
                var content = escapeHtml(t.content || '');
                var activeForm = escapeHtml(t.activeForm || content);
                var icon, cssClass, label;
                if (status === 'completed') {{
                    icon = '<span class="todo-icon completed">&#x2713;</span>';
                    cssClass = 'completed';
                    label = content;
                }} else if (status === 'in_progress') {{
                    icon = '<span class="todo-spinner"></span>';
                    cssClass = 'in-progress';
                    label = activeForm;
                }} else {{
                    icon = '<span class="todo-icon pending">&#x25CB;</span>';
                    cssClass = 'pending';
                    label = content;
                }}
                html += '<div class="todo-item ' + cssClass + '">'
                    + icon
                    + '<span class="todo-label">' + label + '</span>'
                    + '</div>';
            }}
            list.innerHTML = html;
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

                    updateTaskFromData(task);

                    // If completed, close stream and reload for full data
                    if (task.status === 'completed') {{
                        source.close();
                        if (status) status.textContent = 'Complete';
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

        function updateTaskFromData(task) {{
            // Update status
            var statusEl = document.getElementById('task-status');
            if (statusEl) {{
                var display = task.status.replaceAll('_', ' ').toUpperCase();
                var successText = '';
                if (task.status === 'completed') {{
                    if (task.completion_reason === 'success') {{
                        successText = ' - Success';
                    }} else if (task.completion_reason) {{
                        successText = ' - ' + task.completion_reason
                            .replaceAll('_', ' ');
                    }} else {{
                        successText = ' - Failed';
                    }}
                }}
                statusEl.textContent = display + successText;
                statusEl.className = 'status ' + task.status;
                if (task.completion_reason === 'success') {{
                    statusEl.className += ' success';
                }} else if (task.status === 'completed') {{
                    statusEl.className += ' failed';
                }}
            }}

            // Update model
            var modelEl = document.getElementById('task-model');
            if (modelEl) modelEl.textContent = task.model || '-';

            // Update timestamps
            var startedEl = document.getElementById('task-started-at');
            if (startedEl) {{
                startedEl.textContent = formatTimestamp(task.started_at);
            }}
            var completedEl = document.getElementById('task-completed-at');
            if (completedEl) {{
                completedEl.textContent = formatTimestamp(
                    task.completed_at);
            }}

            // Update durations
            var queueEl = document.getElementById('task-queue-time');
            if (queueEl) {{
                queueEl.textContent = formatDuration(task.queue_duration);
            }}
            var execEl = document.getElementById('task-exec-time');
            if (execEl) {{
                execEl.textContent = formatDuration(
                    task.execution_duration);
            }}
            var totalEl = document.getElementById('task-total-time');
            if (totalEl) {{
                totalEl.textContent = formatDuration(task.total_duration);
            }}

            // Hide stop button when task is no longer executing
            if (task.status !== 'executing') {{
                var stopBtn = document.getElementById('stop-btn');
                if (stopBtn) stopBtn.style.display = 'none';
                var stopResult = document.getElementById('stop-result');
                if (stopResult) {{
                    stopResult.textContent = '';
                    stopResult.className = 'stop-result';
                }}
            }}

            // Update todo progress
            renderTodos(task.todos || null);
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
                    if (!task) return;
                    updateTaskFromData(task);
                    if (task.status === 'completed') {{
                        if (status) status.textContent = 'Complete';
                        setTimeout(function() {{
                            window.location.reload();
                        }}, 1000);
                    }}
                }}).catch(function() {{ /* ignore fetch errors */ }});
            }}, 5000);
        }}

        connectTaskSSE();
    </script>"""
