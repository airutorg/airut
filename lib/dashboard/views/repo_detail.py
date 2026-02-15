# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Repository detail page view."""

import html

from lib.dashboard.tracker import RepoState, RepoStatus
from lib.dashboard.views.styles import repo_detail_styles


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
    <title>Repo: {escaped_repo_id} - Airut Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {repo_detail_styles()}
    </style>
</head>
<body>
    <div class="back-link"><a href="/">&larr; Back to Dashboard</a></div>
    <div class="repo-header">
        <h1>{escaped_repo_id}</h1>
        <span id="repo-status"
            class="status-badge {status_class}">{status_display}</span>
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
        <div id="error-section">{error_section}</div>
    </div>
    <div id="stream-status" class="stream-status">Connecting...</div>
    {_sse_repo_detail_script(repo.repo_id)}
</body>
</html>"""


def _sse_repo_detail_script(repo_id: str) -> str:
    """JavaScript for SSE-based live repo detail updates.

    Connects to the global state stream and updates the repo detail
    fields in real-time when state changes.

    Args:
        repo_id: Repository ID to track.

    Returns:
        HTML <script> tag with SSE repo detail update logic.
    """
    return f"""
    <script>
        function escapeHtml(text) {{
            var div = document.createElement('div');
            div.appendChild(document.createTextNode(text));
            return div.innerHTML;
        }}

        function connectRepoSSE() {{
            var source = new EventSource('/api/events/stream');
            var status = document.getElementById('stream-status');

            source.addEventListener('state', function(e) {{
                try {{
                    var data = JSON.parse(e.data);
                    var repos = data.repos || [];
                    var repo = null;
                    for (var i = 0; i < repos.length; i++) {{
                        if (repos[i].repo_id === '{repo_id}') {{
                            repo = repos[i];
                            break;
                        }}
                    }}
                    if (!repo) return;

                    // Update status badge
                    var badge = document.getElementById('repo-status');
                    if (badge) {{
                        badge.textContent = repo.status.toUpperCase();
                        badge.className = 'status-badge ' + repo.status;
                    }}

                    // Update error section
                    var errSection = document.getElementById('error-section');
                    if (errSection) {{
                        if (repo.status === 'failed' && repo.error_message) {{
                            var errType = escapeHtml(
                                repo.error_type || 'Unknown'
                            );
                            var errMsg = escapeHtml(repo.error_message);
                            errSection.innerHTML =
                                '<div class="detail-section error-section">'
                                + '<div class="detail-label">Error Type</div>'
                                + '<div class="detail-value error-type">'
                                    + errType + '</div>'
                                + '<div class="detail-label">'
                                    + 'Error Message</div>'
                                + '<div class="detail-value error-message">'
                                    + errMsg + '</div>'
                                + '</div>';
                        }} else {{
                            errSection.innerHTML = '';
                        }}
                    }}

                    if (status) status.textContent = 'Live';
                }} catch (err) {{ /* ignore parse errors */ }}
            }});

            source.onerror = function() {{
                source.close();
                if (status) status.textContent = 'Polling (5s)';
                startRepoPolling();
            }};

            if (status) status.textContent = 'Live';
        }}

        function startRepoPolling() {{
            var etag = '';
            setInterval(function() {{
                var headers = {{}};
                if (etag) headers['If-None-Match'] = etag;
                fetch('/api/repos', {{
                    headers: headers
                }}).then(function(resp) {{
                    if (resp.status === 200) {{
                        etag = resp.headers.get('ETag') || etag;
                        window.location.reload();
                    }}
                }}).catch(function() {{ /* ignore fetch errors */ }});
            }}, 5000);
        }}

        connectRepoSSE();
    </script>"""
