# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Main dashboard page view."""

from lib.dashboard.formatters import VersionInfo
from lib.dashboard.tracker import BootState, RepoState, TaskState
from lib.dashboard.views.components import (
    boot_refresh_interval,
    local_time_script,
    render_boot_state,
    render_logo,
    render_repos_section,
    render_task_list,
    render_version_info,
)
from lib.dashboard.views.styles import dashboard_styles


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
    <meta http-equiv="refresh" content="{boot_refresh_interval(boot_state)}">
    <title>Airut Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <style>
        {dashboard_styles()}
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
    {local_time_script()}
</body>
</html>"""
