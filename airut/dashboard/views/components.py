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
        return _render_reply_card(reply, reply_num)

    # Task is executing — show pending request text
    if conversation.pending_request_text and task.status in ACTIVE_STATUSES:
        escaped_pending = html.escape(conversation.pending_request_text)
        return f"""
    <div class="card">
        <h2>Reply</h2>
        <div class="reply-list">
            <div class="reply in-progress">
                <div class="reply-header">
                    <span class="reply-number">Pending Request</span>
                    <span class="reply-timestamp">in progress</span>
                </div>
                <div class="text-section">
                    <div class="text-section-header">Request</div>
                    <div class="text-content request">{escaped_pending}</div>
                </div>
            </div>
        </div>
    </div>"""

    # Disk-loaded tasks without reply_index: fall back to full list
    if task.reply_index is None and conversation.replies:
        return render_conversation_replies_section(
            task.conversation_id or "", conversation
        )

    return ""


def _render_reply_inner(reply: ReplySummary, reply_num: int) -> str:
    """Render the inner HTML for a single reply entry.

    Produces a ``<div class="reply ...">`` element with header, stats,
    usage grid, and request/response text.  Used by both the single-reply
    task detail card and the multi-reply conversation overview section.

    Args:
        reply: Reply summary to render.
        reply_num: 1-based reply number.

    Returns:
        HTML string for the inner reply div.
    """
    error_class = "error" if reply.is_error else ""
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

    return f"""
            <div class="reply {error_class}">
                <div class="reply-header">
                    <span class="reply-number">Reply #{reply_num}</span>
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


def _render_reply_card(reply: ReplySummary, reply_num: int) -> str:
    """Render a single reply as a card section.

    Wraps ``_render_reply_inner`` in a card container for use on the
    per-task detail page.

    Args:
        reply: Reply summary to render.
        reply_num: 1-based reply number.

    Returns:
        HTML string for the reply card.
    """
    inner = _render_reply_inner(reply, reply_num)
    return f"""
    <div class="card">
        <h2>Reply</h2>
        <div class="reply-list">
            {inner}
        </div>
    </div>"""


def render_conversation_replies_section(
    conversation_id: str,
    conversation: ConversationMetadata | None,
) -> str:
    """Render conversation replies section HTML.

    Shows the reply history with per-reply stats, usage, and
    request/response text. Does not include the summary stats
    (cost, turns, duration) — those are shown in the Task Details card.

    Args:
        conversation_id: Conversation ID for JSON link.
        conversation: Conversation metadata to display, or None.

    Returns:
        HTML string for conversation replies section.
    """
    if conversation is None or not conversation.replies:
        if conversation and conversation.pending_request_text:
            # Show pending request even without completed replies
            escaped_pending = html.escape(conversation.pending_request_text)
            return f"""
    <div class="card">
        <h2>Conversation Replies</h2>
        <div class="reply-list">
            <div class="reply in-progress">
                <div class="reply-header">
                    <span class="reply-number">Pending Request</span>
                    <span class="reply-timestamp">in progress</span>
                </div>
                <div class="text-section">
                    <div class="text-section-header">Request</div>
                    <div class="text-content request">{escaped_pending}</div>
                </div>
            </div>
        </div>
    </div>"""
        return ""

    # Build replies list using shared inner renderer
    replies_html = ""
    for i, reply in enumerate(conversation.replies, 1):
        replies_html += _render_reply_inner(reply, i)

    # Show pending request text for in-progress execution
    pending_html = ""
    if conversation.pending_request_text:
        escaped_pending = html.escape(conversation.pending_request_text)
        pending_html = f"""
            <div class="reply in-progress">
                <div class="reply-header">
                    <span class="reply-number">Pending Request</span>
                    <span class="reply-timestamp">in progress</span>
                </div>
                <div class="text-section">
                    <div class="text-section-header">Request</div>
                    <div class="text-content request">{escaped_pending}</div>
                </div>
            </div>"""

    return f"""
    <div class="card">
        <h2>Conversation Replies</h2>
        <div class="reply-list">
            {replies_html}
            {pending_html}
        </div>
    </div>"""
