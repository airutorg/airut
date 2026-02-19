# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack plan streamer for real-time TodoWrite progress.

Streams ``TodoItem`` updates to a Slack thread using the
``chat.startStream`` / ``chat.appendStream`` / ``chat.stopStream``
API via the SDK's ``ChatStream`` helper.  Task progress appears as
a plan block in the thread, updated in real time as Claude works.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from slack_sdk.errors import SlackApiError
from slack_sdk.models.messages.chunk import TaskUpdateChunk

from airut.dashboard.tracker import TodoItem, TodoStatus


if TYPE_CHECKING:
    from slack_sdk import WebClient
    from slack_sdk.web.chat_stream import ChatStream

logger = logging.getLogger(__name__)

#: Minimum interval between stream appends to avoid rate limiting.
_MIN_APPEND_INTERVAL_SECONDS = 0.5

#: Map from internal TodoStatus to Slack task_update status strings.
_STATUS_MAP: dict[TodoStatus, str] = {
    TodoStatus.PENDING: "pending",
    TodoStatus.IN_PROGRESS: "in_progress",
    TodoStatus.COMPLETED: "complete",
}


class SlackPlanStreamer:
    """Streams TodoWrite progress to a Slack thread via plan blocks.

    Uses the Slack SDK's ``ChatStream`` helper for automatic buffering
    and state management.  The stream is started lazily on the first
    ``update()`` call, avoiding unnecessary API calls when Claude
    never uses ``TodoWrite``.

    Includes debouncing: rapid ``update()`` calls within
    ``_MIN_APPEND_INTERVAL_SECONDS`` are coalesced, sending only the
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
        self._stream: ChatStream | None = None
        self._last_append_time: float = 0.0

    def _start_stream(self) -> ChatStream:
        """Start the chat stream on first use.

        Returns:
            The ``ChatStream`` instance.
        """
        stream = self._client.chat_stream(
            channel=self._channel,
            thread_ts=self._thread_ts,
            task_display_mode="plan",
        )
        self._stream = stream
        return stream

    def update(self, items: list[TodoItem]) -> None:
        """Send updated task list to the Slack thread.

        Starts the stream lazily on the first call.  Subsequent calls
        append task updates.  Debounces rapid calls to respect rate
        limits.

        Args:
            items: Complete todo list from the latest ``TodoWrite``.
        """
        now = time.monotonic()
        elapsed = now - self._last_append_time

        # Debounce: skip if too soon after last append (unless first call)
        if self._stream is not None and elapsed < _MIN_APPEND_INTERVAL_SECONDS:
            return

        chunks = _build_task_chunks(items)

        try:
            if self._stream is None:
                stream = self._start_stream()
                stream.append(chunks=chunks)
            else:
                self._stream.append(chunks=chunks)
            self._last_append_time = time.monotonic()
        except SlackApiError as e:
            logger.warning("Failed to stream plan update (non-fatal): %s", e)

    def finalize(self) -> None:
        """Stop the stream.

        Safe to call even if the stream was never started (no-op).
        """
        if self._stream is None:
            return

        try:
            self._stream.stop()
        except SlackApiError as e:
            logger.warning("Failed to stop plan stream (non-fatal): %s", e)


def _build_task_chunks(items: list[TodoItem]) -> list[TaskUpdateChunk]:
    """Convert TodoItems to Slack TaskUpdateChunk objects.

    Uses positional index as the task ID.  Since we send the full
    list on every update and Slack replaces the plan view, positional
    IDs are stable within each call.

    Args:
        items: Todo items from Claude's TodoWrite.

    Returns:
        List of ``TaskUpdateChunk`` objects for the streaming API.
    """
    return [
        TaskUpdateChunk(
            id=f"task_{i}",
            title=item.active_form or item.content,
            status=_STATUS_MAP.get(item.status, "pending"),
        )
        for i, item in enumerate(items)
    ]
