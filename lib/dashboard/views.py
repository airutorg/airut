# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""HTML rendering for dashboard views.

Provides functions for rendering all dashboard HTML pages including
the main dashboard, task details, actions timeline, and network logs.
"""

import html
import json
import re
from pathlib import Path
from typing import Any

from lib.container.session import SessionMetadata
from lib.dashboard.formatters import (
    VersionInfo,
    format_duration,
    format_timestamp,
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
_ASSETS_DIR = Path(__file__).parent.parent.parent / "assets"
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
    <div class="repos-section">
        <div class="repos-header">Repositories ({status_summary})</div>
        <div class="repos-grid">
            {"".join(repo_cards)}
        </div>
    </div>"""


def _boot_refresh_interval(boot_state: BootState | None) -> int:
    """Return the auto-refresh interval in seconds.

    During boot (non-READY, non-FAILED), refreshes every 5 seconds.
    Otherwise, uses the normal 30-second interval.

    Args:
        boot_state: Current boot state, or None.

    Returns:
        Refresh interval in seconds.
    """
    if boot_state is None:
        return 30
    if boot_state.phase in (BootPhase.READY, BootPhase.FAILED):
        return 30
    return 5


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
    <div class="boot-banner boot-error">
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
    <div class="boot-banner boot-progress">
        <div class="boot-spinner"></div>
        <div class="boot-content">
            <div class="boot-title">{phase_label}...</div>
            <div class="boot-message">{message}</div>
        </div>
    </div>"""


def render_dashboard(
    counts: dict[str, int],
    queued: list[TaskState],
    in_progress: list[TaskState],
    completed: list[TaskState],
    version_info: VersionInfo | None,
    repo_states: list[RepoState] | None = None,
    boot_state: BootState | None = None,
) -> str:
    """Render main dashboard HTML.

    Args:
        counts: Task counts by status.
        queued: List of queued tasks.
        in_progress: List of in-progress tasks.
        completed: List of completed tasks.
        version_info: Optional version information.
        repo_states: Optional list of repository states.
        boot_state: Optional boot state for progress reporting.

    Returns:
        HTML string for dashboard page.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="{_boot_refresh_interval(boot_state)}">
    <title>Airut Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .title-row {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }}
        h1 {{
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }}
        .logo {{
            height: 1.2em;
            width: auto;
        }}
        .version-info {{
            font-size: 12px;
            color: #666;
            margin-bottom: 20px;
            display: flex;
            gap: 12px;
            align-items: center;
        }}
        .version-sha {{
            font-family: "SF Mono", Consolas, monospace;
            background: #eee;
            padding: 2px 6px;
            border-radius: 3px;
            color: #337ab7;
            text-decoration: none;
        }}
        .version-sha:hover {{
            text-decoration: underline;
            background: #e0e0e0;
        }}
        .version-status {{
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: 500;
        }}
        .version-status.clean {{
            background: #dff0d8;
            color: #3c763d;
        }}
        .version-status.modified {{
            background: #fcf8e3;
            color: #8a6d3b;
        }}
        .version-started {{
            color: #888;
        }}
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            max-width: 1400px;
        }}
        @media (max-width: 900px) {{
            .dashboard {{ grid-template-columns: 1fr; }}
        }}
        .column {{
            background: white;
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .column-header {{
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 2px solid #eee;
        }}
        .column-header.queued {{ border-color: #f0ad4e; color: #8a6d3b; }}
        .column-header.in-progress {{ border-color: #5bc0de; color: #31708f; }}
        .column-header.completed {{ border-color: #5cb85c; color: #3c763d; }}
        .task {{
            padding: 12px;
            margin-bottom: 8px;
            background: #fafafa;
            border-radius: 4px;
            border-left: 3px solid #ddd;
        }}
        .task.queued {{ border-left-color: #f0ad4e; }}
        .task.in-progress {{ border-left-color: #5bc0de; }}
        .task.completed.success {{ border-left-color: #5cb85c; }}
        .task.completed.failed {{ border-left-color: #d9534f; }}
        .task-id {{
            font-family: "SF Mono", Consolas, monospace;
            font-size: 12px;
            color: #666;
            margin-bottom: 4px;
        }}
        .task-id a {{
            color: #337ab7;
            text-decoration: none;
        }}
        .task-id a:hover {{ text-decoration: underline; }}
        .task-subject {{
            font-size: 14px;
            margin-bottom: 4px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .task-time {{
            font-size: 12px;
            color: #888;
        }}
        .task-sender {{
            font-size: 12px;
            color: #888;
        }}
        .repo-badge {{
            display: inline-block;
            background: #e8e8e8;
            color: #555;
            font-size: 11px;
            padding: 1px 6px;
            border-radius: 3px;
            margin-left: 4px;
            vertical-align: middle;
        }}
        .status-icon {{
            font-size: 14px;
            margin-left: 4px;
        }}
        .empty {{
            color: #999;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }}
        .refresh-notice {{
            font-size: 12px;
            color: #999;
            margin-top: 20px;
        }}
        .repos-section {{
            margin-bottom: 24px;
            max-width: 1400px;
        }}
        .repos-header {{
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            color: #666;
        }}
        .repos-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .repo-card {{
            background: white;
            border-radius: 6px;
            padding: 12px 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 200px;
        }}
        .repo-card a {{
            text-decoration: none;
            color: inherit;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .repo-card a:hover {{
            text-decoration: underline;
        }}
        .repo-status-indicator {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .repo-status-indicator.live {{
            background: #5cb85c;
        }}
        .repo-status-indicator.failed {{
            background: #d9534f;
        }}
        .repo-name {{
            font-weight: 500;
            font-size: 14px;
        }}
        .repo-error-hint {{
            font-size: 12px;
            color: #d9534f;
            margin-left: auto;
        }}
        .boot-banner {{
            max-width: 1400px;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .boot-progress {{
            background: #d9edf7;
            border-left: 4px solid #5bc0de;
        }}
        .boot-error {{
            background: #f2dede;
            border-left: 4px solid #d9534f;
        }}
        .boot-icon {{
            font-size: 20px;
            color: #d9534f;
            flex-shrink: 0;
        }}
        .boot-spinner {{
            width: 20px;
            height: 20px;
            border: 3px solid #5bc0de;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            flex-shrink: 0;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        .boot-content {{
            flex: 1;
            min-width: 0;
        }}
        .boot-title {{
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 4px;
        }}
        .boot-error .boot-title {{
            color: #a94442;
        }}
        .boot-progress .boot-title {{
            color: #31708f;
        }}
        .boot-message {{
            font-size: 13px;
            color: #555;
        }}
        .boot-traceback {{
            margin-top: 8px;
            padding: 12px;
            background: #fff;
            border: 1px solid #ebccd1;
            border-radius: 4px;
            font-family: "SF Mono", Consolas, monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 400px;
            overflow-y: auto;
            color: #a94442;
        }}
    </style>
</head>
<body>
    <div class="title-row">
        {render_logo()}
        <h1>Airut Dashboard</h1>
    </div>
    {render_version_info(version_info)}
    {render_boot_state(boot_state)}
    {render_repos_section(repo_states)}
    <div class="dashboard">
        <div class="column">
            <div class="column-header queued">
                Queued ({counts["queued"]})
            </div>
            {render_task_list(queued, "queued")}
        </div>
        <div class="column">
            <div class="column-header in-progress">
                In Progress ({counts["in_progress"]})
            </div>
            {render_task_list(in_progress, "in-progress")}
        </div>
        <div class="column">
            <div class="column-header completed">
                Completed ({counts["completed"]})
            </div>
            {render_task_list(completed, "completed")}
        </div>
    </div>
    <div class="refresh-notice">Auto-refreshes every 30 seconds</div>
    <script>
        document.querySelectorAll('.local-time').forEach(function(el) {{
            var ts = parseFloat(el.dataset.timestamp);
            if (!isNaN(ts)) {{
                var d = new Date(ts * 1000);
                var year = d.getFullYear();
                var month = String(d.getMonth() + 1).padStart(2, '0');
                var day = String(d.getDate()).padStart(2, '0');
                var hours = String(d.getHours()).padStart(2, '0');
                var mins = String(d.getMinutes()).padStart(2, '0');
                var secs = String(d.getSeconds()).padStart(2, '0');
                var tz = d.toLocaleTimeString(
                    'en-US', {{timeZoneName: 'short'}}).split(' ').pop();
                el.textContent = year + '-' + month + '-' + day + ' ' +
                    hours + ':' + mins + ':' + secs + ' ' + tz;
            }}
        }});
    </script>
</body>
</html>"""


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
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
            max-width: 900px;
        }}
        a {{ color: #337ab7; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .back {{ margin-bottom: 20px; }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 16px;
        }}
        h1 {{
            margin: 0 0 20px 0;
            font-size: 20px;
            font-weight: 600;
            font-family: "SF Mono", Consolas, monospace;
        }}
        h2 {{
            margin: 0 0 16px 0;
            font-size: 16px;
            font-weight: 600;
            color: #444;
        }}
        .field {{
            margin-bottom: 16px;
        }}
        .field-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #666;
            margin-bottom: 4px;
        }}
        .field-value {{
            font-size: 14px;
        }}
        .field-value.mono {{
            font-family: "SF Mono", Consolas, monospace;
        }}
        .status {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .status.queued {{ background: #fcf8e3; color: #8a6d3b; }}
        .status.in_progress {{ background: #d9edf7; color: #31708f; }}
        .status.completed.success {{ background: #dff0d8; color: #3c763d; }}
        .status.completed.failed {{ background: #f2dede; color: #a94442; }}
        .session-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }}
        .summary-item {{
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            text-align: center;
        }}
        .summary-value {{
            font-size: 24px;
            font-weight: 600;
            color: #333;
            font-family: "SF Mono", Consolas, monospace;
        }}
        .summary-label {{
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }}
        .reply-list {{
            border-top: 1px solid #eee;
            padding-top: 16px;
        }}
        .reply {{
            background: #f8f9fa;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 12px;
            border-left: 3px solid #5bc0de;
        }}
        .reply.error {{
            border-left-color: #d9534f;
        }}
        .reply-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .reply-number {{
            font-weight: 600;
            color: #333;
        }}
        .reply-timestamp {{
            font-size: 12px;
            color: #666;
            font-family: "SF Mono", Consolas, monospace;
        }}
        .reply-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 12px;
            font-size: 13px;
        }}
        .reply-stat {{
            display: flex;
            flex-direction: column;
        }}
        .reply-stat-label {{
            font-size: 10px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}
        .reply-stat-value {{
            font-family: "SF Mono", Consolas, monospace;
            color: #333;
        }}
        .usage-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 8px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #e0e0e0;
        }}
        .usage-item {{
            font-size: 12px;
        }}
        .usage-label {{
            color: #888;
            font-size: 10px;
        }}
        .usage-value {{
            font-family: "SF Mono", Consolas, monospace;
            color: #555;
        }}
        .json-link {{
            font-size: 12px;
            margin-top: 12px;
        }}
        .action-buttons {{
            display: flex;
            gap: 8px;
            margin-top: 16px;
        }}
        .action-btn {{
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-family: inherit;
            text-decoration: none;
            display: inline-block;
            box-sizing: border-box;
            line-height: 1.2;
        }}
        .action-btn.primary {{
            background: #337ab7;
        }}
        .action-btn.primary:hover {{
            background: #286090;
        }}
        .refresh-notice {{
            font-size: 12px;
            color: #999;
            margin-top: 20px;
        }}
        .stop-btn {{
            background: #d9534f;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-family: inherit;
            box-sizing: border-box;
            line-height: 1.2;
        }}
        .stop-btn:hover {{
            background: #c9302c;
        }}
        .stop-btn:disabled {{
            background: #ccc;
            cursor: not-allowed;
        }}
        .stop-result {{
            margin-top: 12px;
            padding: 12px;
            border-radius: 4px;
            font-size: 14px;
        }}
        .stop-result.success {{
            background: #dff0d8;
            color: #3c763d;
        }}
        .stop-result.error {{
            background: #f2dede;
            color: #a94442;
        }}
        .no-session {{
            color: #888;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }}
        .text-section {{
            margin-top: 12px;
            border-top: 1px solid #e0e0e0;
            padding-top: 12px;
        }}
        .text-section-header {{
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            color: #666;
            margin-bottom: 8px;
        }}
        .text-content {{
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 12px;
            font-family: "SF Mono", Consolas, monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 300px;
            overflow-y: auto;
            color: #333;
        }}
        .text-content.request {{
            border-left: 3px solid #5bc0de;
        }}
        .text-content.response {{
            border-left: 3px solid #5cb85c;
        }}
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


def render_repo_detail(repo: RepoState) -> str:
    """Render repository detail page HTML.

    Args:
        repo: Repository state to display.

    Returns:
        HTML string for repo detail page.
    """
    status_class = repo.status.value
    status_display = repo.status.value.upper()

    error_section = ""
    if repo.status == RepoStatus.FAILED and repo.error_message:
        escaped_error = html.escape(repo.error_message)
        escaped_type = html.escape(repo.error_type or "Unknown")
        error_section = f"""
        <div class="detail-section error-section">
            <div class="detail-label">Error Type</div>
            <div class="detail-value error-type">{escaped_type}</div>
            <div class="detail-label">Error Message</div>
            <div class="detail-value error-message">{escaped_error}</div>
        </div>"""

    escaped_repo_id = html.escape(repo.repo_id)
    escaped_git_url = html.escape(repo.git_repo_url)
    escaped_imap = html.escape(repo.imap_server)
    escaped_storage = html.escape(repo.storage_dir)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>Repo: {escaped_repo_id} - Airut Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .back-link {{
            font-size: 14px;
            margin-bottom: 16px;
        }}
        .back-link a {{ color: #337ab7; text-decoration: none; }}
        .back-link a:hover {{ text-decoration: underline; }}
        .repo-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
        }}
        .repo-header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .status-badge {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .status-badge.live {{
            background: #dff0d8;
            color: #3c763d;
        }}
        .status-badge.failed {{
            background: #f2dede;
            color: #a94442;
        }}
        .detail-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            max-width: 800px;
        }}
        .detail-section {{
            margin-bottom: 20px;
        }}
        .detail-section:last-child {{
            margin-bottom: 0;
        }}
        .detail-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .detail-value {{
            font-size: 14px;
            word-break: break-all;
            margin-bottom: 12px;
        }}
        .detail-value:last-child {{
            margin-bottom: 0;
        }}
        .detail-value.mono {{
            font-family: "SF Mono", Consolas, monospace;
            background: #f5f5f5;
            padding: 8px;
            border-radius: 4px;
        }}
        .error-section {{
            background: #fdf2f2;
            border-left: 3px solid #d9534f;
            padding: 16px;
            border-radius: 4px;
            margin-top: 20px;
        }}
        .error-type {{
            font-family: "SF Mono", Consolas, monospace;
            color: #a94442;
            font-weight: 600;
        }}
        .error-message {{
            font-family: "SF Mono", Consolas, monospace;
            white-space: pre-wrap;
            background: #fff;
            padding: 8px;
            border-radius: 4px;
        }}
        .refresh-notice {{
            font-size: 12px;
            color: #999;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="back-link"><a href="/">&larr; Back to Dashboard</a></div>
    <div class="repo-header">
        <h1>{escaped_repo_id}</h1>
        <span class="status-badge {status_class}">{status_display}</span>
    </div>
    <div class="detail-card">
        <div class="detail-section">
            <div class="detail-label">Git Repository</div>
            <div class="detail-value mono">{escaped_git_url}</div>
        </div>
        <div class="detail-section">
            <div class="detail-label">IMAP Server</div>
            <div class="detail-value mono">{escaped_imap}</div>
        </div>
        <div class="detail-section">
            <div class="detail-label">Storage Directory</div>
            <div class="detail-value mono">{escaped_storage}</div>
        </div>
        {error_section}
    </div>
    <div class="refresh-notice">Auto-refreshes every 30 seconds</div>
</body>
</html>"""


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
    session = f"/conversation/{cid}/session"
    return f"""
        <div class="action-buttons">
            <a href="{actions}" class="action-btn primary"
                >View Actions</a>
            <a href="{network}" class="action-btn primary"
                >View Network Logs</a>
            <a href="{session}" class="action-btn primary"
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


def render_session_section(
    conversation_id: str,
    session: SessionMetadata | None,
) -> str:
    """Render session data section HTML.

    Args:
        conversation_id: Conversation ID for JSON link.
        session: Session metadata to display, or None.

    Returns:
        HTML string for session section.
    """
    if session is None:
        return """
    <div class="card">
        <h2>Session Data</h2>
        <div class="no-session">No session data available</div>
    </div>"""

    # Build summary section
    total_duration_ms = sum(r.duration_ms for r in session.replies)
    duration_str = format_duration(total_duration_ms / 1000)

    summary_html = f"""
        <div class="session-summary">
            <div class="summary-item">
                <div class="summary-value">${session.total_cost_usd:.4f}</div>
                <div class="summary-label">Total Cost</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{session.total_turns}</div>
                <div class="summary-label">Total Turns</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{len(session.replies)}</div>
                <div class="summary-label">Replies</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{duration_str}</div>
                <div class="summary-label">Total Duration</div>
            </div>
        </div>"""

    # Build replies list
    replies_html = ""
    for i, reply in enumerate(session.replies, 1):
        error_class = "error" if reply.is_error else ""
        reply_duration = format_duration(reply.duration_ms / 1000)
        escaped_timestamp = html.escape(reply.timestamp)
        cost_display = f"${reply.total_cost_usd:.4f}"
        session_id_full = html.escape(reply.session_id)

        # Build usage grid if usage data exists (only show token counts)
        usage_html = ""
        if reply.usage:
            usage_items = []
            # Only display numeric token fields, skip nested objects
            token_fields = [
                ("input_tokens", "Input"),
                ("output_tokens", "Output"),
                ("cache_read_input_tokens", "Cache Read"),
                ("cache_creation_input_tokens", "Cache Write"),
            ]
            for field_key, label in token_fields:
                if field_key in reply.usage:
                    value = reply.usage[field_key]
                    if isinstance(value, (int, float)):
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
        <h2>Session Data</h2>
        {summary_html}
        <div class="reply-list">
            <h3 style="font-size: 14px; margin-bottom: 12px; color: #555;">
                Reply History
            </h3>
            {replies_html}
        </div>
    </div>"""


def render_actions_page(
    task: TaskState, session: SessionMetadata | None
) -> str:
    """Render actions viewer page HTML.

    Args:
        task: Task to display.
        session: Session metadata with events.

    Returns:
        HTML string for actions page.
    """
    escaped_subject = html.escape(task.subject)

    # Build actions content
    if session is None or not session.replies:
        actions_content = '<div class="no-actions">No actions recorded</div>'
    else:
        actions_content = render_actions_timeline(session)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Actions - {task.conversation_id}</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: "SF Mono", Consolas, "Liberation Mono", Menlo,
                         monospace;
            margin: 0;
            padding: 0;
            background: #1e1e1e;
            color: #d4d4d4;
            font-size: 13px;
            line-height: 1.5;
        }}
        a {{ color: #569cd6; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .header {{
            background: #252526;
            padding: 12px 20px;
            border-bottom: 1px solid #333;
            position: sticky;
            top: 0;
            z-index: 10;
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        h1 {{
            margin: 0;
            font-size: 14px;
            font-weight: 600;
            color: #e0e0e0;
        }}
        .subtitle {{
            color: #888;
            font-size: 12px;
        }}
        .terminal {{
            padding: 12px 20px 40px 20px;
        }}
        .reply-section {{
            margin-bottom: 16px;
        }}
        .reply-header {{
            color: #569cd6;
            font-weight: 600;
            padding: 8px 0 4px 0;
            border-bottom: 1px solid #333;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .reply-timestamp {{
            font-size: 11px;
            color: #666;
        }}
        .event {{
            margin-bottom: 2px;
            padding: 2px 0;
        }}
        .event.error {{
            background: #3c1f1f;
            border-left: 2px solid #d9534f;
            padding-left: 8px;
        }}
        .ev-system {{
            color: #666;
            font-size: 12px;
            padding: 2px 0;
        }}
        .ev-text {{
            color: #b5cea8;
            padding: 4px 0;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .ev-tool-use {{
            padding: 4px 0;
        }}
        .tool-name {{
            color: #dcdcaa;
            font-weight: 600;
        }}
        .tool-desc {{
            color: #808080;
            margin-left: 8px;
        }}
        .tool-input-json {{
            color: #808080;
            padding: 2px 0 2px 16px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 400px;
            overflow-y: auto;
        }}
        .bash-cmd {{
            color: #ce9178;
            padding: 2px 0 2px 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .tool-detail {{
            color: #9cdcfe;
            padding: 2px 0 2px 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .diff-removed {{
            color: #c97070;
            padding: 0 0 0 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .diff-added {{
            color: #73c991;
            padding: 0 0 0 16px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .tool-detail-dim {{
            color: #666;
            padding: 0 0 0 16px;
            font-size: 12px;
        }}
        .ev-tool-result {{
            padding: 2px 0 2px 16px;
            color: #808080;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .ev-tool-result.error {{
            color: #f48771;
            background: #3c1f1f;
            padding: 4px 8px 4px 16px;
        }}
        .ev-tool-result-label {{
            color: #666;
            font-size: 11px;
        }}
        .ev-result {{
            color: #569cd6;
            padding: 4px 0;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .ev-raw {{
            color: #808080;
            padding: 4px 0;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .ev-request {{
            color: #c586c0;
            padding: 4px 0;
            white-space: pre-wrap;
            word-break: break-word;
            border-left: 2px solid #c586c0;
            padding-left: 8px;
            margin-bottom: 4px;
        }}
        .ev-request-label {{
            color: #888;
            font-size: 11px;
            font-weight: 600;
        }}
        .no-actions {{
            color: #888;
            font-style: italic;
            padding: 40px;
            text-align: center;
        }}
        /* collapsible raw JSON blocks */
        .event-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            padding: 2px 0;
        }}
        .event-type {{
            font-weight: 600;
            font-size: 12px;
        }}
        .event-meta {{
            font-size: 11px;
            color: #666;
        }}
        .event-body {{
            display: none;
        }}
        .event-body.expanded {{
            display: block;
        }}
        .toggle-icon {{
            font-size: 12px;
            color: #666;
        }}
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


def render_network_page(task: TaskState, log_content: str | None) -> str:
    """Render network logs viewer page HTML.

    Args:
        task: Task to display.
        log_content: Raw network log content, or None if unavailable.

    Returns:
        HTML string for network logs page.
    """
    escaped_subject = html.escape(task.subject)

    # Build network logs content
    if log_content is None:
        logs_html = '<div class="no-logs">No network logs available</div>'
    elif not log_content.strip():
        logs_html = '<div class="no-logs">Network log is empty</div>'
    else:
        logs_html = render_network_log_lines(log_content)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Logs - {task.conversation_id}</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: "SF Mono", Consolas, "Liberation Mono", Menlo,
                         monospace;
            margin: 0;
            padding: 0;
            background: #1e1e1e;
            color: #d4d4d4;
            font-size: 13px;
            line-height: 1.5;
        }}
        a {{ color: #569cd6; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .header {{
            background: #252526;
            padding: 12px 20px;
            border-bottom: 1px solid #333;
            position: sticky;
            top: 0;
            z-index: 10;
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        h1 {{
            margin: 0;
            font-size: 14px;
            font-weight: 600;
            color: #e0e0e0;
        }}
        .subtitle {{
            color: #888;
            font-size: 12px;
        }}
        .terminal {{
            padding: 12px 20px 40px 20px;
        }}
        .log-line {{
            padding: 2px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .log-line.allowed {{
            color: #73c991;
        }}
        .log-line.error {{
            color: #e09c5f;
        }}
        .log-line.conn-error {{
            color: #e05f5f;
        }}
        .log-line.blocked {{
            color: #f48771;
            background: #3c1f1f;
            padding: 2px 8px;
            margin: 0 -8px;
        }}
        .log-line.task-start {{
            color: #569cd6;
        }}
        .log-line .highlight {{
            font-weight: bold;
        }}
        .no-logs {{
            color: #888;
            font-style: italic;
            padding: 40px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="header">
        <a href="/conversation/{task.conversation_id}">&larr; Back</a>
        <h1>Network Logs: {task.conversation_id}</h1>
        <span class="subtitle">{escaped_subject}</span>
    </div>
    <div class="terminal">
        {logs_html}
    </div>
    <script>window.scrollTo(0, document.body.scrollHeight);</script>
</body>
</html>"""


# Pattern to extract status code from log lines: "allowed GET ... -> 200"
_STATUS_CODE_PATTERN = re.compile(r"-> (\d{3})(?:\s|$)")


def _is_error_status(status_code: int) -> bool:
    """Check if status code indicates an error (not 2xx or 3xx)."""
    return status_code < 200 or status_code >= 400


def _extract_status_code(line: str) -> int | None:
    """Extract HTTP status code from a log line."""
    match = _STATUS_CODE_PATTERN.search(line)
    if match:
        return int(match.group(1))
    return None


def _highlight_status_code(escaped_line: str, status_code: int) -> str:
    """Wrap the status code in a highlight span."""
    # Status code is already escaped. The arrow -> becomes -&gt; after escaping.
    code_str = str(status_code)
    return escaped_line.replace(
        f"-&gt; {code_str}", f'-&gt; <span class="highlight">{code_str}</span>'
    )


def _highlight_blocked(escaped_line: str) -> str:
    """Wrap 'BLOCKED' in a highlight span."""
    return escaped_line.replace(
        "BLOCKED", '<span class="highlight">BLOCKED</span>', 1
    )


def _highlight_error_prefix(escaped_line: str) -> str:
    """Wrap 'ERROR' in a highlight span."""
    return escaped_line.replace(
        "ERROR", '<span class="highlight">ERROR</span>', 1
    )


def render_network_log_lines(log_content: str) -> str:
    """Render network log lines with appropriate styling.

    Args:
        log_content: Raw log file content.

    Returns:
        HTML string with styled log lines.

    Line types and their styling:
        - Task start headers (=== TASK START ...): blue
        - BLOCKED requests: red with dark red background, BLOCKED in bold
        - ERROR lines (upstream failures): red with dark red background,
          ERROR in bold
        - Allowed requests with error status (4xx/5xx): orange with dark orange
          background, status code in bold
        - Allowed requests with success status (2xx/3xx): green
    """
    lines: list[str] = []
    for line in log_content.splitlines():
        if not line:
            continue

        escaped = html.escape(line)

        # Determine line type and apply appropriate styling
        if line.startswith("=== TASK START"):
            lines.append(f'<div class="log-line task-start">{escaped}</div>')
        elif line.startswith("BLOCKED"):
            # Make BLOCKED bold
            highlighted = _highlight_blocked(escaped)
            lines.append(f'<div class="log-line blocked">{highlighted}</div>')
        elif line.startswith("ERROR"):
            # Upstream connection error - make ERROR bold
            highlighted = _highlight_error_prefix(escaped)
            lines.append(
                f'<div class="log-line conn-error">{highlighted}</div>'
            )
        elif line.startswith("allowed"):
            # Check if this is an error response
            status_code = _extract_status_code(line)
            if status_code is not None and _is_error_status(status_code):
                # Error response - highlight status code in bold
                highlighted = _highlight_status_code(escaped, status_code)
                lines.append(f'<div class="log-line error">{highlighted}</div>')
            else:
                lines.append(f'<div class="log-line allowed">{escaped}</div>')
        else:
            # Unknown format, render as plain text
            lines.append(f'<div class="log-line">{escaped}</div>')

    return "\n".join(lines)


def render_actions_timeline(session: SessionMetadata) -> str:
    """Render timeline of actions from session events.

    Args:
        session: Session metadata with events.

    Returns:
        HTML string for actions timeline.
    """
    sections: list[str] = []

    for i, reply in enumerate(session.replies, 1):
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

        events_html = render_events_list(reply.events)

        sections.append(f"""
        <div class="reply-section {error_class}">
            <div class="reply-header">
                <span>Reply #{i}</span>
                <span class="reply-timestamp">{escaped_timestamp}</span>
            </div>
            {request_html}
            {events_html}
        </div>""")

    return "".join(sections)


def render_events_list(events: list[dict[str, Any]]) -> str:
    """Render list of events as collapsible sections.

    Args:
        events: List of event dicts from streaming JSON.

    Returns:
        HTML string for events list.
    """
    if not events:
        return '<div class="no-actions">No events recorded</div>'

    items: list[str] = []

    for event in events:
        event_type = event.get("type", "unknown")
        event_html = render_single_event(event, event_type)
        items.append(event_html)

    return "".join(items)


def render_single_event(event: dict[str, Any], event_type: str) -> str:
    """Render a single event in CLI-style streaming format.

    Recognized event types are pretty-printed inline. Unrecognized
    types fall back to collapsible raw JSON.

    Args:
        event: Event dict from streaming JSON.
        event_type: Type of event (system, assistant, user, result).

    Returns:
        HTML string for event.
    """
    if event_type == "system":
        return _render_system_event(event)
    elif event_type == "assistant":
        return _render_assistant_event(event)
    elif event_type == "user":
        return _render_user_event(event)
    elif event_type == "result":
        return _render_result_event(event)
    else:
        return _render_unknown_event(event, event_type)


def _render_system_event(event: dict[str, Any]) -> str:
    """Render system event as a dim info line.

    Args:
        event: System event dict.

    Returns:
        HTML string.
    """
    parts: list[str] = []
    subtype = event.get("subtype", "")
    if subtype:
        parts.append(html.escape(subtype))
    if "model" in event:
        parts.append(f"model={html.escape(event['model'])}")
    tools = event.get("tools", [])
    if tools:
        tools_str = ", ".join(html.escape(t) for t in tools[:20])
        if len(tools) > 20:
            tools_str += f"... (+{len(tools) - 20} more)"
        parts.append(f"tools=[{tools_str}]")
    if "session_id" in event:
        parts.append(f"session={html.escape(event['session_id'])}")

    info = " ".join(parts)
    cls = "ev-system"
    return f'<div class="event"><div class="{cls}">system: {info}</div></div>'


def _render_assistant_event(event: dict[str, Any]) -> str:
    """Render assistant event: text blocks and tool calls.

    Args:
        event: Assistant event dict.

    Returns:
        HTML string.
    """
    message = event.get("message", {})
    content = message.get("content", [])

    if not content:
        return '<div class="event"><em>No content</em></div>'

    blocks: list[str] = []
    for block in content:
        block_type = block.get("type")
        if block_type == "text":
            text = html.escape(block.get("text", ""))
            blocks.append(f'<div class="ev-text">{text}</div>')
        elif block_type == "tool_use":
            blocks.append(_render_tool_use_block(block))

    if not blocks:
        return '<div class="event"><em>No content</em></div>'

    return '<div class="event">' + "".join(blocks) + "</div>"


def _render_tool_use_block(block: dict[str, Any]) -> str:
    """Render a tool_use block with specialized formatting.

    Known tools get purpose-built rendering. Unknown tools fall
    back to the tool name plus raw JSON input.

    Args:
        block: Tool use content block.

    Returns:
        HTML string.
    """
    name = block.get("name", "unknown")
    tool_input = block.get("input", {})
    escaped_name = html.escape(name)

    renderer = _TOOL_RENDERERS.get(name)
    if renderer:
        detail = renderer(tool_input)
    else:
        detail = _render_tool_generic(tool_input)

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


_EDIT_MAX_LINES = 20


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


def _render_user_event(event: dict[str, Any]) -> str:
    """Render user event (tool results).

    Args:
        event: User event dict.

    Returns:
        HTML string.
    """
    message = event.get("message", {})
    content = message.get("content", [])

    if not content:
        return '<div class="event"><em>No content</em></div>'

    blocks: list[str] = []
    for block in content:
        if block.get("type") == "tool_result":
            blocks.append(_render_tool_result_block(block))

    if not blocks:
        return '<div class="event"><em>No content</em></div>'

    has_error = any(
        b.get("type") == "tool_result" and b.get("is_error") for b in content
    )
    error_class = " error" if has_error else ""

    return f'<div class="event{error_class}">' + "".join(blocks) + "</div>"


def _render_tool_result_block(block: dict[str, Any]) -> str:
    """Render a single tool result block.

    Args:
        block: Tool result content block.

    Returns:
        HTML string.
    """
    result_content = block.get("content", "")
    # Content can be a list of content blocks or a string
    if isinstance(result_content, list):
        text_parts = []
        for part in result_content:
            is_text_block = (
                isinstance(part, dict) and part.get("type") == "text"
            )
            if is_text_block:
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
    is_error = block.get("is_error", False)
    error_class = " error" if is_error else ""
    error_note = " (error)" if is_error else ""
    label = f'<div class="ev-tool-result-label">Tool Result{error_note}:</div>'

    if not escaped.strip():
        return f'{label}<div class="ev-tool-result{error_class}">(empty)</div>'

    cls = f"ev-tool-result{error_class}"
    return f'{label}<div class="{cls}">{escaped}</div>'


def _render_result_event(event: dict[str, Any]) -> str:
    """Render result summary event.

    Args:
        event: Result event dict.

    Returns:
        HTML string.
    """
    meta: list[str] = []
    subtype = event.get("subtype", "")
    if subtype:
        meta.append(html.escape(subtype))
    if "duration_ms" in event:
        meta.append(f"{event['duration_ms']}ms")
    if "total_cost_usd" in event:
        meta.append(f"${event['total_cost_usd']:.4f}")
    if "num_turns" in event:
        meta.append(f"{event['num_turns']} turns")

    header = "result: " + " | ".join(meta)

    result_text = event.get("result", "")
    if isinstance(result_text, str) and result_text:
        preview = result_text[:500]
        if len(result_text) > 500:
            preview += "..."
        header += "\n" + html.escape(preview)

    cls = "ev-result"
    return f'<div class="event"><div class="{cls}">{header}</div></div>'


def _render_unknown_event(event: dict[str, Any], event_type: str) -> str:
    """Render unrecognized event as collapsible raw JSON.

    Args:
        event: Event dict.
        event_type: Type string.

    Returns:
        HTML string.
    """
    raw = html.escape(json.dumps(event, indent=2, ensure_ascii=False))
    escaped_type = html.escape(event_type)
    return f"""<div class="event">
            <div class="event-header" onclick="toggleEvent(this)">
                <span class="event-type">{escaped_type}</span>
                <span class="event-meta"></span>
                <span class="toggle-icon">+</span>
            </div>
            <div class="event-body">
                <div class="ev-raw">{raw}</div>
            </div>
        </div>"""
