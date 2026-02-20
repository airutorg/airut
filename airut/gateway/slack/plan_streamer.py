# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack plan streamer for real-time task progress.

Posts a ``mrkdwn``-formatted message to a Slack thread and updates it
in place via ``chat.update`` as tasks progress.  Uses emoji status
indicators for clear, mobile-friendly rendering.

The message is updated only when Claude uses ``TodoWrite`` — individual
tool use events (Read, Bash, etc.) are not streamed to Slack.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

from slack_sdk.errors import SlackApiError

from airut.dashboard.tracker import TodoItem, TodoStatus


if TYPE_CHECKING:
    from slack_sdk import WebClient

logger = logging.getLogger(__name__)

#: Minimum interval between message updates to avoid rate limiting.
#: Slack allows ~1 message/second/channel for updates.
_MIN_UPDATE_INTERVAL_SECONDS = 1.0

#: Maximum text length for a Slack ``section`` block.
_MAX_SECTION_TEXT = 3000

#: Emoji indicators for each task status.
_STATUS_EMOJI: dict[TodoStatus, str] = {
    TodoStatus.PENDING: "\u26aa",  # white circle
    TodoStatus.IN_PROGRESS: "\U0001f504",  # arrows counterclockwise
    TodoStatus.COMPLETED: "\u2705",  # white check mark
}


class SlackPlanStreamer:
    """Displays task progress in a Slack thread via message updates.

    Posts a single message on the first ``update()`` call, then updates
    it in place using ``chat.update`` as tasks progress.  Uses
    ``mrkdwn`` blocks with emoji indicators for clear rendering on
    both desktop and mobile Slack clients.

    Includes debouncing: rapid calls within
    ``_MIN_UPDATE_INTERVAL_SECONDS`` are coalesced, sending only the
    latest state.

    Args:
        client: Slack ``WebClient`` for API calls.
        channel: DM channel ID (``D``-prefixed).
        thread_ts: Thread timestamp for reply threading.
    """

    def __init__(
        self,
        client: WebClient,
        channel: str,
        thread_ts: str,
    ) -> None:
        self._client = client
        self._channel = channel
        self._thread_ts = thread_ts
        self._message_ts: str | None = None
        self._last_update_time: float = 0.0
        self._last_text: str = ""
        self._lock = threading.Lock()

    def update(self, items: list[TodoItem]) -> None:
        """Send updated task list to the Slack thread.

        Posts a new message on the first call.  Subsequent calls update
        the message in place.  Debounces rapid calls to respect rate
        limits.

        Args:
            items: Complete todo list from the latest ``TodoWrite``.
        """
        with self._lock:
            text = _render_plan(items)
            self._send_or_update(text)

    def _send_or_update(self, text: str) -> None:
        """Post or update the plan message with debouncing.

        Caller must hold ``_lock``.
        """
        now = time.monotonic()
        elapsed = now - self._last_update_time

        # Always store the latest text for deferred sending.
        self._last_text = text

        # Debounce: skip the API call if too soon after last update
        # (unless this is the very first call).
        if (
            self._message_ts is not None
            and elapsed < _MIN_UPDATE_INTERVAL_SECONDS
        ):
            return

        self._post_or_update(text)

    def _post_or_update(self, text: str) -> None:
        """Post a new message or update an existing one.

        Caller must hold ``_lock``.
        """
        try:
            blocks = _build_blocks(text)
            fallback = text[:200]
            if self._message_ts is None:
                resp = self._client.chat_postMessage(
                    channel=self._channel,
                    thread_ts=self._thread_ts,
                    blocks=blocks,
                    text=fallback,
                )
                self._message_ts = resp["ts"]
            else:
                self._client.chat_update(
                    channel=self._channel,
                    ts=self._message_ts,
                    blocks=blocks,
                    text=fallback,
                )
            self._last_update_time = time.monotonic()
        except SlackApiError as e:
            logger.warning(
                "Failed to update plan message (non-fatal): %s",
                e,
            )

    def finalize(self) -> None:
        """Flush any pending debounced update.

        Safe to call even if the message was never posted (no-op).
        """
        with self._lock:
            if self._message_ts is None or not self._last_text:
                return

            # Flush the latest debounced state.
            self._post_or_update(self._last_text)


def _build_blocks(text: str) -> list[dict[str, object]]:
    """Build Slack blocks for plan text, respecting size limits.

    A single ``section`` block supports up to 3000 characters.  If
    the rendered plan exceeds this, it is split across multiple
    ``section`` blocks at line boundaries.

    Args:
        text: Rendered mrkdwn plan text.

    Returns:
        List of Slack block dicts.
    """
    if len(text) <= _MAX_SECTION_TEXT:
        return [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text},
            }
        ]

    blocks: list[dict[str, object]] = []
    current = ""

    for line in text.split("\n"):
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > _MAX_SECTION_TEXT:
            if current:
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": current,
                        },
                    }
                )
            current = line[:_MAX_SECTION_TEXT]
        else:
            current = candidate

    if current:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": current},
            }
        )

    return blocks


def _render_plan(items: list[TodoItem]) -> str:
    """Render a todo list as mrkdwn text with emoji indicators.

    Each task gets an emoji prefix based on its status:

    - :white_circle: (``\u26aa``) Pending
    - :arrows_counterclockwise: (``\U0001f504``) In progress
    - :white_check_mark: (``\u2705``) Completed

    Args:
        items: Todo items from Claude's TodoWrite.

    Returns:
        Formatted mrkdwn string.
    """
    lines: list[str] = []

    for item in items:
        emoji = _STATUS_EMOJI.get(
            item.status, _STATUS_EMOJI[TodoStatus.PENDING]
        )
        title = item.active_form or item.content
        lines.append(f"{emoji}  {title}")

    return "\n".join(lines)
