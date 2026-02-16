# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Main dashboard page view."""

from airut.dashboard.formatters import VersionInfo
from airut.dashboard.tracker import BootState, RepoState, TaskState
from airut.dashboard.views.components import (
    local_time_script,
    render_boot_state,
    render_logo,
    render_repos_section,
    render_task_list,
    render_version_info,
    update_check_script,
)
from airut.dashboard.views.styles import dashboard_styles


def _sse_live_script() -> str:
    """JavaScript for SSE-based live dashboard updates.

    Connects to ``/api/events/stream``, replaces dynamic DOM sections
    on each state event. Falls back to ETag polling on SSE failure.

    Returns:
        HTML <script> tag with SSE logic.
    """
    return """
    <script>
        var currentVersion = 0;

        function escapeHtml(text) {
            var div = document.createElement('div');
            div.appendChild(document.createTextNode(text));
            return div.innerHTML;
        }

        function formatDuration(seconds) {
            if (seconds === null || seconds === undefined || seconds < 0)
                return '-';
            var total = Math.floor(seconds);
            var h = Math.floor(total / 3600);
            var m = Math.floor((total % 3600) / 60);
            var s = total % 60;
            if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
            if (m > 0) return m + 'm ' + s + 's';
            return s + 's';
        }

        function renderBootState(boot) {
            if (!boot || boot.phase === 'ready') return '';
            if (boot.phase === 'failed') {
                var errMsg = escapeHtml(boot.error_message || 'Unknown error');
                var errType = escapeHtml(boot.error_type || 'Error');
                var tb = '';
                if (boot.error_traceback) {
                    tb = '<pre class="boot-traceback">' +
                         escapeHtml(boot.error_traceback) + '</pre>';
                }
                return '<div id="boot-section" class="boot-banner boot-error">'
                    + '<div class="boot-icon">&#x2717;</div>'
                    + '<div class="boot-content">'
                    + '<div class="boot-title">Boot Failed: ' + errType
                    + '</div>'
                    + '<div class="boot-message">' + errMsg + '</div>'
                    + tb + '</div></div>';
            }
            var labels = {
                starting: 'Initializing',
                proxy: 'Starting proxy',
                repos: 'Starting repositories'
            };
            var label = labels[boot.phase] || 'Booting';
            var msg = escapeHtml(boot.message || '');
            return '<div id="boot-section" class="boot-banner boot-progress">'
                + '<div class="boot-spinner"></div>'
                + '<div class="boot-content">'
                + '<div class="boot-title">' + label + '...</div>'
                + '<div class="boot-message">' + msg + '</div>'
                + '</div></div>';
        }

        function renderRepos(repos) {
            if (!repos || repos.length === 0) return '';
            var live = 0, failed = 0;
            repos.forEach(function(r) {
                if (r.status === 'live') live++;
                if (r.status === 'failed') failed++;
            });
            var sorted = repos.slice().sort(function(a, b) {
                return (a.repo_id || '').localeCompare(b.repo_id || '');
            });
            var cards = sorted.map(function(r) {
                var sc = r.status || '';
                var hint = '';
                if (sc === 'failed' && r.error_type) {
                    hint = '<span class="repo-error-hint">'
                        + escapeHtml(r.error_type) + '</span>';
                }
                var rid = escapeHtml(r.repo_id || '');
                return '<div class="repo-card">'
                    + '<a href="/repo/' + rid + '">'
                    + '<span class="repo-status-indicator ' + sc + '"></span>'
                    + '<span class="repo-name">' + rid + '</span></a>'
                    + hint + '</div>';
            }).join('');
            var summary = live + ' live';
            if (failed > 0) summary += ', ' + failed + ' failed';
            return '<div id="repos-section" class="repos-section">'
                + '<div class="repos-header">Repositories (' + summary
                + ')</div>'
                + '<div class="repos-grid">' + cards + '</div></div>';
        }

        function renderTaskCard(task, statusClass) {
            var sc = '', icon = '', timeLabel = '';
            var status = task.status || '';
            if (status === 'queued') {
                timeLabel = 'Waiting: '
                    + formatDuration(task.queue_duration);
            } else if (status === 'in_progress') {
                timeLabel = 'Running: '
                    + formatDuration(task.execution_duration);
            } else if (status === 'completed') {
                if (task.success) {
                    sc = 'success';
                    icon = '<span class="status-icon">&#x2713;</span>';
                } else {
                    sc = 'failed';
                    icon = '<span class="status-icon">&#x2717;</span>';
                }
                timeLabel = 'Took: '
                    + formatDuration(task.execution_duration);
            }
            var subject = escapeHtml(task.subject || '');
            var truncated = subject.length > 50
                ? subject.substring(0, 50) + '...' : subject;
            var badge = '';
            if (task.repo_id) {
                badge = '<span class="repo-badge">'
                    + escapeHtml(task.repo_id) + '</span> ';
            }
            var sender = '';
            if (task.sender) {
                sender = '<div class="task-sender">'
                    + escapeHtml(task.sender) + '</div>';
            }
            var cid = task.conversation_id || '';
            return '<div class="task ' + statusClass + ' ' + sc + '">'
                + '<div class="task-id">'
                + '<a href="/conversation/' + cid + '">[' + cid + ']</a>'
                + ' ' + badge + icon + '</div>'
                + '<div class="task-subject" title="' + subject + '">'
                + truncated + '</div>'
                + sender
                + '<div class="task-time">' + timeLabel + '</div></div>';
        }

        function renderTaskList(tasks, statusClass) {
            if (!tasks || tasks.length === 0) {
                return '<div class="empty">No conversations</div>';
            }
            return tasks.map(function(t) {
                return renderTaskCard(t, statusClass);
            }).join('');
        }

        function updateDashboard(state) {
            currentVersion = state.version || 0;

            // Update boot section
            var bootContainer = document.getElementById('boot-container');
            if (bootContainer) {
                bootContainer.innerHTML = renderBootState(state.boot);
            }

            // Update repos section
            var reposContainer = document.getElementById('repos-container');
            if (reposContainer) {
                reposContainer.innerHTML = renderRepos(state.repos);
            }

            // Categorize tasks
            var queued = [], inProgress = [], completed = [];
            (state.tasks || []).forEach(function(t) {
                if (t.status === 'queued') queued.push(t);
                else if (t.status === 'in_progress') inProgress.push(t);
                else if (t.status === 'completed') completed.push(t);
            });

            // Update columns
            var qCol = document.getElementById('queued-header');
            if (qCol) qCol.textContent = 'Queued (' + queued.length + ')';
            var qList = document.getElementById('queued-list');
            if (qList) qList.innerHTML = renderTaskList(queued, 'queued');

            var pCol = document.getElementById('in-progress-header');
            if (pCol) {
                pCol.textContent = (
                    'In Progress (' + inProgress.length + ')'
                );
            }
            var pList = document.getElementById('in-progress-list');
            if (pList) {
                pList.innerHTML = renderTaskList(inProgress, 'in-progress');
            }

            var cCol = document.getElementById('completed-header');
            if (cCol) {
                cCol.textContent = 'Completed (' + completed.length + ')';
            }
            var cList = document.getElementById('completed-list');
            if (cList) {
                cList.innerHTML = renderTaskList(completed, 'completed');
            }

            // Update status notice
            var notice = document.getElementById('status-notice');
            if (notice) notice.textContent = 'Live';
        }

        function connectSSE() {
            var url = '/api/events/stream?version=' + currentVersion;
            var source = new EventSource(url);

            source.addEventListener('state', function(e) {
                try {
                    var state = JSON.parse(e.data);
                    updateDashboard(state);
                } catch (err) { /* ignore parse errors */ }
            });

            source.onerror = function() {
                source.close();
                var notice = document.getElementById('status-notice');
                if (notice) notice.textContent = 'Polling (5s)';
                startPolling();
            };
        }

        function startPolling() {
            var etag = '"v' + currentVersion + '"';
            setInterval(function() {
                fetch('/api/conversations', {
                    headers: {'If-None-Match': etag}
                }).then(function(resp) {
                    if (resp.status === 200) {
                        etag = resp.headers.get('ETag') || etag;
                        // Full page reload on change as fallback
                        window.location.reload();
                    }
                }).catch(function() { /* ignore fetch errors */ });
            }, 5000);
        }

        connectSSE();
    </script>"""


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

    The page is server-rendered initially, then updated in real time
    via SSE from ``/api/events/stream``. If SSE fails, falls back to
    ETag-based polling.

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
    <title>Airut Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {dashboard_styles()}
    </style>
</head>
<body>
<div class="page">
    <div class="title-row">
        {render_logo()}
        <h1>Airut Dashboard</h1>
    </div>
    {render_version_info(version_info)}
    <div id="boot-container">{render_boot_state(boot_state)}</div>
    <div id="repos-container">{render_repos_section(repo_states)}</div>
    <div class="dashboard">
        <div class="column">
            <div id="queued-header" class="column-header queued">
                Queued ({counts["queued"]})
            </div>
            <div id="queued-list">
                {render_task_list(queued, "queued")}
            </div>
        </div>
        <div class="column">
            <div id="in-progress-header" class="column-header in-progress">
                In Progress ({counts["in_progress"]})
            </div>
            <div id="in-progress-list">
                {render_task_list(in_progress, "in-progress")}
            </div>
        </div>
        <div class="column">
            <div id="completed-header" class="column-header completed">
                Completed ({counts["completed"]})
            </div>
            <div id="completed-list">
                {render_task_list(completed, "completed")}
            </div>
        </div>
    </div>
    <div id="status-notice" class="refresh-notice">Connecting...</div>
</div>
    {local_time_script()}
    {update_check_script()}
    {_sse_live_script()}
</body>
</html>"""
