# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared HTML components for dashboard views.

Reusable fragments used across multiple pages: logo, version info,
boot state banner, repository section, task list, action buttons,
conversation data section, and the local-time JavaScript snippet.
"""

import html
from pathlib import Path

from lib.conversation import ConversationMetadata
from lib.dashboard.formatters import (
    VersionInfo,
    format_duration,
)
from lib.dashboard.tracker import (
    BootPhase,
    BootState,
    RepoState,
    RepoStatus,
    TaskState,
    TaskStatus,
)


# Load logo SVG at module import time. The assets folder is at repo root.
_ASSETS_DIR = Path(__file__).parent.parent.parent.parent / "assets"
_LOGO_SVG = (_ASSETS_DIR / "logo.svg").read_text()


def get_favicon_svg() -> str:
    """Get the raw logo SVG for use as favicon.

    Returns:
        Raw SVG content suitable for serving as favicon.
    """
    return _LOGO_SVG


def render_logo() -> str:
    """Render the Airut logo as an inline SVG.

    The logo inherits the text color via currentColor and scales to match
    the h1 text height.

    Returns:
        HTML string containing the SVG logo element.
    """
    # Add class and aria-label, replace fill color with currentColor
    svg = _LOGO_SVG.replace(
        'viewBox="0 0 2816 1536"',
        'class="logo" viewBox="0 0 2816 1536" aria-label="Airut logo"',
    ).replace('fill="#000000"', 'fill="currentColor"')
    return svg


def render_version_info(version_info: VersionInfo | None) -> str:
    """Render version info HTML fragment.

    Args:
        version_info: Version information to render, or None.

    Returns:
        HTML string for version info section, or empty string if not set.
    """
    if not version_info:
        return ""

    # Format worktree status
    if version_info.worktree_clean:
        status_text = "clean"
        status_class = "clean"
    else:
        status_text = "modified"
        status_class = "modified"

    # Pass raw timestamp for JavaScript to format in local timezone
    started_ts = version_info.started_at
    git_sha = version_info.git_sha

    return f"""
        <div class="version-info">
            <a href="/.version" class="version-sha">{git_sha}</a>
            <span class="version-status {status_class}">{status_text}</span>
            <span class="version-started">Started: <span
                class="local-time"
                data-timestamp="{started_ts}"
            ></span></span>
        </div>"""


def render_repos_section(repo_states: list[RepoState] | None) -> str:
    """Render repository status section.

    Args:
        repo_states: List of repository states, or None.

    Returns:
        HTML string for repos section, or empty string if no repos.
    """
    if not repo_states:
        return ""

    live_count = sum(1 for r in repo_states if r.status == RepoStatus.LIVE)
    failed_count = sum(1 for r in repo_states if r.status == RepoStatus.FAILED)

    repo_cards = []
    for repo in sorted(repo_states, key=lambda r: r.repo_id):
        status_class = repo.status.value
        error_hint = ""
        if repo.status == RepoStatus.FAILED and repo.error_type:
            escaped_type = html.escape(repo.error_type)
            error_hint = f'<span class="repo-error-hint">{escaped_type}</span>'

        repo_cards.append(f"""
            <div class="repo-card">
                <a href="/repo/{html.escape(repo.repo_id)}">
                    <span class="repo-status-indicator {status_class}"></span>
                    <span class="repo-name">{html.escape(repo.repo_id)}</span>
                </a>
                {error_hint}
            </div>""")

    status_summary = f"{live_count} live"
    if failed_count > 0:
        status_summary += f", {failed_count} failed"

    return f"""
    <div id="repos-section" class="repos-section">
        <div class="repos-header">Repositories ({status_summary})</div>
        <div class="repos-grid">
            {"".join(repo_cards)}
        </div>
    </div>"""


def render_boot_state(boot_state: BootState | None) -> str:
    """Render boot state banner HTML fragment.

    Shows a progress banner during boot, or an error banner if boot failed.
    Returns empty string when boot is complete or no boot_state is provided.

    Args:
        boot_state: Current boot state, or None.

    Returns:
        HTML string for boot state section.
    """
    if boot_state is None:
        return ""

    if boot_state.phase == BootPhase.READY:
        return ""

    if boot_state.phase == BootPhase.FAILED:
        error_msg = html.escape(boot_state.error_message or "Unknown error")
        error_type = html.escape(boot_state.error_type or "Error")
        traceback_html = ""
        if boot_state.error_traceback:
            escaped_tb = html.escape(boot_state.error_traceback)
            traceback_html = f'<pre class="boot-traceback">{escaped_tb}</pre>'
        return f"""
    <div id="boot-section" class="boot-banner boot-error">
        <div class="boot-icon">&#x2717;</div>
        <div class="boot-content">
            <div class="boot-title">Boot Failed: {error_type}</div>
            <div class="boot-message">{error_msg}</div>
            {traceback_html}
        </div>
    </div>"""

    # In-progress boot phases
    phase_labels = {
        BootPhase.STARTING: "Initializing",
        BootPhase.PROXY: "Starting proxy",
        BootPhase.REPOS: "Starting repositories",
    }
    phase_label = phase_labels.get(boot_state.phase, "Booting")
    message = html.escape(boot_state.message)

    return f"""
    <div id="boot-section" class="boot-banner boot-progress">
        <div class="boot-spinner"></div>
        <div class="boot-content">
            <div class="boot-title">{phase_label}...</div>
            <div class="boot-message">{message}</div>
        </div>
    </div>"""


def render_task_list(tasks: list[TaskState], status_class: str) -> str:
    """Render list of task cards.

    Args:
        tasks: Tasks to render.
        status_class: CSS class for task status.

    Returns:
        HTML string for task list.
    """
    if not tasks:
        return '<div class="empty">No conversations</div>'

    items = []
    for task in tasks:
        success_class = ""
        status_icon = ""
        time_label = ""

        if task.status == TaskStatus.QUEUED:
            duration = format_duration(task.queue_duration())
            time_label = f"Waiting: {duration}"
        elif task.status == TaskStatus.IN_PROGRESS:
            time_label = (
                f"Running: {format_duration(task.execution_duration())}"
            )
        elif task.status == TaskStatus.COMPLETED:
            if task.success:
                success_class = "success"
                status_icon = '<span class="status-icon">&#x2713;</span>'
            else:
                success_class = "failed"
                status_icon = '<span class="status-icon">&#x2717;</span>'
            time_label = f"Took: {format_duration(task.execution_duration())}"

        escaped_subject = html.escape(task.subject)
        truncated_subject = (
            escaped_subject[:50] + "..."
            if len(escaped_subject) > 50
            else escaped_subject
        )

        repo_badge = ""
        if task.repo_id:
            escaped_repo = html.escape(task.repo_id)
            repo_badge = f'<span class="repo-badge">{escaped_repo}</span> '

        sender_line = ""
        if task.sender:
            escaped_sender = html.escape(task.sender)
            sender_line = f'<div class="task-sender">{escaped_sender}</div>'

        items.append(f"""
            <div class="task {status_class} {success_class}">
                <div class="task-id">
                    <a href="/conversation/{task.conversation_id}">
                        [{task.conversation_id}]
                    </a>
                    {repo_badge}{status_icon}
                </div>
                <div class="task-subject" title="{escaped_subject}">
                    {truncated_subject}
                </div>
                {sender_line}
                <div class="task-time">{time_label}</div>
            </div>
            """)

    return "".join(items)


def render_action_buttons(task: TaskState) -> str:
    """Render action buttons for task detail page.

    Shows View Actions, View Network Logs and View Raw JSON buttons always,
    plus Stop button for in-progress tasks.

    Args:
        task: Task state to render buttons for.

    Returns:
        HTML string for action buttons.
    """
    cid = task.conversation_id
    stop_html = ""
    if task.status == TaskStatus.IN_PROGRESS:
        stop_html = (
            '<button id="stop-btn" class="stop-btn"'
            ' onclick="stopTask()">Stop</button>'
        )

    actions = f"/conversation/{cid}/actions"
    network = f"/conversation/{cid}/network"
    conversation_json = f"/conversation/{cid}/conversation"
    return f"""
        <div class="action-buttons">
            <a href="{actions}" class="action-btn primary"
                >View Actions</a>
            <a href="{network}" class="action-btn primary"
                >View Network Logs</a>
            <a href="{conversation_json}" class="action-btn primary"
                >View Raw JSON</a>
            {stop_html}
        </div>
        <div id="stop-result" class="stop-result"></div>"""


def render_stop_script(task: TaskState) -> str:
    """Render JavaScript for stop button functionality.

    Args:
        task: Task state to render script for.

    Returns:
        HTML script tag with stopTask function, or empty string if task
        not in progress.
    """
    if task.status != TaskStatus.IN_PROGRESS:
        return ""

    return f"""
    <script>
        function stopTask() {{
            var btn = document.getElementById('stop-btn');
            var resultDiv = document.getElementById('stop-result');

            btn.disabled = true;
            btn.textContent = 'Stopping...';
            resultDiv.textContent = '';
            resultDiv.className = 'stop-result';

            fetch('/api/conversation/{task.conversation_id}/stop', {{
                method: 'POST'
            }})
            .then(function(response) {{
                return response.json();
            }})
            .then(function(data) {{
                if (data.success) {{
                    resultDiv.textContent = (
                        'Task stopped successfully. Page will refresh...'
                    );
                    resultDiv.className = 'stop-result success';
                    // Refresh after 2 seconds
                    setTimeout(function() {{
                        window.location.reload();
                    }}, 2000);
                }} else {{
                    var msg = (
                        data.message || data.error || 'Failed to stop task'
                    );
                    resultDiv.textContent = msg;
                    resultDiv.className = 'stop-result error';
                    btn.disabled = false;
                    btn.textContent = 'Stop';
                }}
            }})
            .catch(function(error) {{
                resultDiv.textContent = 'Error: ' + error;
                resultDiv.className = 'stop-result error';
                btn.disabled = false;
                btn.textContent = 'Stop';
            }});
        }}
    </script>"""


def render_conversation_section(
    conversation_id: str,
    conversation: ConversationMetadata | None,
) -> str:
    """Render conversation data section HTML.

    Args:
        conversation_id: Conversation ID for JSON link.
        conversation: Conversation metadata to display, or None.

    Returns:
        HTML string for conversation data section.
    """
    if conversation is None:
        return """
    <div class="card">
        <h2>Conversation Data</h2>
        <div class="no-conversation">No conversation data available</div>
    </div>"""

    # Build summary section
    total_duration_ms = sum(r.duration_ms for r in conversation.replies)
    duration_str = format_duration(total_duration_ms / 1000)

    summary_html = f"""
        <div class="conversation-summary">
            <div class="summary-item">
                <div class="summary-value">\
${conversation.total_cost_usd:.4f}</div>
                <div class="summary-label">Total Cost</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{conversation.total_turns}</div>
                <div class="summary-label">Total Turns</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{len(conversation.replies)}</div>
                <div class="summary-label">Replies</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{duration_str}</div>
                <div class="summary-label">Total Duration</div>
            </div>
        </div>"""

    # Build replies list
    replies_html = ""
    for i, reply in enumerate(conversation.replies, 1):
        error_class = "error" if reply.is_error else ""
        reply_duration = format_duration(reply.duration_ms / 1000)
        escaped_timestamp = html.escape(reply.timestamp)
        cost_display = f"${reply.total_cost_usd:.4f}"
        session_id_full = html.escape(reply.session_id)

        # Build usage grid from typed Usage fields
        usage_html = ""
        usage = reply.usage
        usage_items = []
        token_fields = [
            (usage.input_tokens, "Input"),
            (usage.output_tokens, "Output"),
            (usage.cache_read_input_tokens, "Cache Read"),
            (usage.cache_creation_input_tokens, "Cache Write"),
        ]
        for value, label in token_fields:
            if value:
                formatted = f"{value:,}"
                usage_items.append(f"""
                    <div class="usage-item">
                        <div class="usage-label">{label}</div>
                        <div class="usage-value">{formatted}</div>
                    </div>""")
        if usage_items:
            usage_html = f"""
                <div class="usage-grid">
                    {"".join(usage_items)}
                </div>"""

        # Build request/response text sections
        text_sections_html = ""
        if reply.request_text:
            escaped_request = html.escape(reply.request_text)
            text_sections_html += f"""
                <div class="text-section">
                    <div class="text-section-header">Request</div>
                    <div class="text-content request">{escaped_request}</div>
                </div>"""
        if reply.response_text:
            escaped_response = html.escape(reply.response_text)
            text_sections_html += f"""
                <div class="text-section">
                    <div class="text-section-header">Response</div>
                    <div class="text-content response">{escaped_response}</div>
                </div>"""

        replies_html += f"""
            <div class="reply {error_class}">
                <div class="reply-header">
                    <span class="reply-number">Reply #{i}</span>
                    <span class="reply-timestamp">{escaped_timestamp}</span>
                </div>
                <div class="reply-stats">
                    <div class="reply-stat">
                        <span class="reply-stat-label">Cost</span>
                        <span class="reply-stat-value">{cost_display}</span>
                    </div>
                    <div class="reply-stat">
                        <span class="reply-stat-label">Duration</span>
                        <span class="reply-stat-value">{reply_duration}</span>
                    </div>
                    <div class="reply-stat">
                        <span class="reply-stat-label">Turns</span>
                        <span class="reply-stat-value">{reply.num_turns}</span>
                    </div>
                    <div class="reply-stat">
                        <span class="reply-stat-label">Session ID</span>
                        <span class="reply-stat-value">
                            {session_id_full}
                        </span>
                    </div>
                </div>
                {usage_html}
                {text_sections_html}
            </div>"""

    return f"""
    <div class="card">
        <h2>Conversation Data</h2>
        {summary_html}
        <div class="reply-list">
            <h3 style="font-size: 14px; margin-bottom: 12px; color: #555;">
                Reply History
            </h3>
            {replies_html}
        </div>
    </div>"""


def local_time_script() -> str:
    """JavaScript snippet that formats .local-time elements.

    Returns:
        HTML <script> tag with local-time formatting logic.
    """
    return """
    <script>
        document.querySelectorAll('.local-time').forEach(function(el) {
            var ts = parseFloat(el.dataset.timestamp);
            if (!isNaN(ts)) {
                var d = new Date(ts * 1000);
                var year = d.getFullYear();
                var month = String(d.getMonth() + 1).padStart(2, '0');
                var day = String(d.getDate()).padStart(2, '0');
                var hours = String(d.getHours()).padStart(2, '0');
                var mins = String(d.getMinutes()).padStart(2, '0');
                var secs = String(d.getSeconds()).padStart(2, '0');
                var tz = d.toLocaleTimeString(
                    'en-US', {timeZoneName: 'short'}).split(' ').pop();
                el.textContent = year + '-' + month + '-' + day + ' ' +
                    hours + ':' + mins + ':' + secs + ' ' + tz;
            }
        });
    </script>"""
