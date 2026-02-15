# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""HTML rendering for dashboard views.

Provides functions for rendering all dashboard HTML pages including
the main dashboard, task details, actions timeline, and network logs.

This package is split into modules by concern:
    - ``styles`` — shared CSS generation
    - ``components`` — reusable HTML fragments
    - ``dashboard`` — main dashboard page
    - ``task_detail`` — conversation detail page
    - ``repo_detail`` — repository detail page
    - ``actions`` — actions viewer and event renderers
    - ``network`` — network logs viewer

All public symbols are re-exported here for backward compatibility.
"""

from lib.dashboard.views.actions import (
    render_actions_page,
    render_actions_timeline,
    render_events_list,
    render_single_event,
)
from lib.dashboard.views.components import (
    get_favicon_svg,
    render_action_buttons,
    render_boot_state,
    render_conversation_section,
    render_logo,
    render_repos_section,
    render_stop_script,
    render_task_list,
    render_version_info,
    update_check_script,
)
from lib.dashboard.views.dashboard import render_dashboard
from lib.dashboard.views.network import (
    render_network_log_line,
    render_network_log_lines,
    render_network_page,
)
from lib.dashboard.views.repo_detail import render_repo_detail
from lib.dashboard.views.task_detail import render_task_detail


__all__ = [
    "get_favicon_svg",
    "render_action_buttons",
    "render_actions_page",
    "render_actions_timeline",
    "render_boot_state",
    "render_dashboard",
    "render_events_list",
    "render_logo",
    "render_network_log_line",
    "render_network_log_lines",
    "render_network_page",
    "render_repo_detail",
    "render_repos_section",
    "render_conversation_section",
    "render_single_event",
    "render_stop_script",
    "render_task_detail",
    "render_task_list",
    "render_version_info",
    "update_check_script",
]
