# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""HTML rendering helpers for dashboard views.

Most page rendering has moved to Jinja2 templates
(``airut.dashboard.templates``).  This package retains
renderers still used by SSE streaming and handler helpers:

    - ``components`` — ``get_favicon_svg``, reply section renderers
    - ``actions`` — event rendering (``render_single_event``, etc.)
    - ``network`` — network log line rendering
"""

from airut.dashboard.views.actions import (
    render_actions_timeline,
    render_events_list,
    render_single_event,
)
from airut.dashboard.views.components import (
    get_favicon_svg,
    render_conversation_replies_section,
    render_single_reply_section,
)
from airut.dashboard.views.network import (
    render_network_log_line,
    render_network_log_lines,
)


__all__ = [
    "get_favicon_svg",
    "render_actions_timeline",
    "render_conversation_replies_section",
    "render_events_list",
    "render_network_log_line",
    "render_network_log_lines",
    "render_single_event",
    "render_single_reply_section",
]
