# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared HTML components for dashboard views.

Most rendering has migrated to Jinja2 templates.  This module retains
the favicon SVG helper and reply-section renderers that are still used
by handlers and SSE code.
"""

import html
from importlib.resources import files

from airut.conversation import ConversationMetadata, ReplySummary
from airut.dashboard.formatters import format_duration
from airut.dashboard.tracker import (
    ACTIVE_STATUSES,
    TaskState,
)


# Load logo SVG at module import time from embedded package data.
_LOGO_SVG = files("airut._bundled.assets").joinpath("logo.svg").read_text()


def get_favicon_svg() -> str:
    """Get the raw logo SVG for use as favicon.

    Returns:
        Raw SVG content suitable for serving as favicon.
    """
    return _LOGO_SVG


def _render_pending_request(request_text: str) -> str:
    """Render a pending request as its own card.

    Args:
        request_text: Raw request text (will be HTML-escaped).

    Returns:
        HTML string for the pending request card.
    """
    escaped = html.escape(request_text)
    return f"""
    <div class="card">
        <h2>Pending Request <span class="reply-meta">in progress</span></h2>
        <div class="text-label">Request</div>
        <div class="text-content request">{escaped}</div>
    </div>"""


def render_single_reply_section(
    task: TaskState,
    conversation: ConversationMetadata | None,
) -> str:
    """Render the reply section for a single task.

    Shows only the reply associated with the task's ``reply_index``,
    or the pending request text if the task is still executing.  Falls
    back to the full reply list for disk-loaded tasks that lack a
    ``reply_index``.

    Args:
        task: Task whose reply to show.
        conversation: Conversation metadata containing replies.

    Returns:
        HTML string for the task's reply section.
    """
    if conversation is None:
        return ""

    # If we have a reply_index, show only that reply
    if task.reply_index is not None and task.reply_index < len(
        conversation.replies
    ):
        reply = conversation.replies[task.reply_index]
        reply_num = task.reply_index + 1
        return _render_reply(reply, reply_num)

    # Task is executing — show pending request text
    if conversation.pending_request_text and task.status in ACTIVE_STATUSES:
        return _render_pending_request(conversation.pending_request_text)

    # Disk-loaded tasks without reply_index: fall back to full list
    if task.reply_index is None and conversation.replies:
        return render_conversation_replies_section(
            task.conversation_id or "", conversation
        )

    return ""


def _render_reply(reply: ReplySummary, reply_num: int) -> str:
    """Render a single reply as its own card.

    Each card has "Reply #N" as title, stats grid, and optional
    request/response sections separated by horizontal dividers.

    Args:
        reply: Reply summary to render.
        reply_num: 1-based reply number.

    Returns:
        HTML string for the reply card.
    """
    error_class = " reply-error" if reply.is_error else ""
    reply_duration = format_duration(reply.duration_ms / 1000)
    escaped_timestamp = html.escape(reply.timestamp)
    cost_display = f"${reply.total_cost_usd:.4f}"
    session_id_full = html.escape(reply.session_id)

    # Build usage grid
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
            usage_items.append(
                f'<div class="usage-item">'
                f'<div class="usage-label">{label}</div>'
                f'<div class="usage-value">{formatted}</div>'
                f"</div>"
            )
    if usage_items:
        usage_html = f'<div class="usage-grid">{"".join(usage_items)}</div>'

    # Build request/response text with dividers
    text_html = ""
    if reply.request_text:
        escaped_request = html.escape(reply.request_text)
        text_html += (
            f'<hr class="reply-divider">'
            f'<div class="text-label">Request</div>'
            f'<div class="text-content request">{escaped_request}</div>'
        )
    if reply.response_text:
        escaped_response = html.escape(reply.response_text)
        text_html += (
            f'<hr class="reply-divider">'
            f'<div class="text-label">Response</div>'
            f'<div class="text-content response">{escaped_response}</div>'
        )

    meta = f'<span class="reply-meta">{escaped_timestamp}</span>'
    return f"""
    <div class="card{error_class}">
        <h2>Reply #{reply_num} {meta}</h2>
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
                <span class="reply-stat-label">Session</span>
                <span class="reply-stat-value">{session_id_full}</span>
            </div>
        </div>
        {usage_html}
        {text_html}
    </div>"""


def render_conversation_replies_section(
    conversation_id: str,
    conversation: ConversationMetadata | None,
) -> str:
    """Render conversation replies as individual cards.

    Each reply gets its own card with title, stats, and
    request/response sections.

    Args:
        conversation_id: Conversation ID for JSON link.
        conversation: Conversation metadata to display, or None.

    Returns:
        HTML string for conversation reply cards.
    """
    if conversation is None or not conversation.replies:
        if conversation and conversation.pending_request_text:
            return _render_pending_request(conversation.pending_request_text)
        return ""

    # Build one card per reply
    parts: list[str] = []
    for i, reply in enumerate(conversation.replies, 1):
        parts.append(_render_reply(reply, i))

    # Append pending request card if in-progress
    if conversation.pending_request_text:
        parts.append(_render_pending_request(conversation.pending_request_text))

    return "".join(parts)
