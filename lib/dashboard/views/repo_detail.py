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
    <meta http-equiv="refresh" content="30">
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
