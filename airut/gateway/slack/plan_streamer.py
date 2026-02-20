# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack plan streamer for real-time task and action progress.

Streams ``TodoItem`` updates and live action summaries to a Slack
thread using the ``chat.startStream`` / ``chat.appendStream`` /
``chat.stopStream`` API via the SDK's ``ChatStream`` helper.  Task
progress appears as a plan block in the thread, updated in real
time as Claude works.

When Claude uses ``TodoWrite``, the plan block shows the todo list
with a dedicated action task (showing the latest tool use) inserted
after the first in-progress task.  When Claude does *not* use
``TodoWrite``, a single synthetic task provides live activity
feedback (e.g. "Reading src/main.py").

A background keepalive timer re-sends the latest task state
periodically so Slack does not expire the stream during long gaps
between events.
"""

from __future__ import annotations

import hashlib
import logging
import threading
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

#: Slack error returned when ``appendStream`` is called on a message
#: whose streaming session has expired (server-side idle timeout).
_STREAM_EXPIRED_ERROR = "message_not_in_streaming_state"

#: Keepalive interval — re-send the last task state to prevent Slack
#: from expiring the stream during long gaps between TodoWrite events.
#: Must be shorter than Slack's idle timeout (undocumented, likely
#: 30–60 s).
_KEEPALIVE_INTERVAL_SECONDS = 20.0

#: Map from internal TodoStatus to Slack task_update status strings.
_STATUS_MAP: dict[TodoStatus, str] = {
    TodoStatus.PENDING: "pending",
    TodoStatus.IN_PROGRESS: "in_progress",
    TodoStatus.COMPLETED: "complete",
}


class SlackPlanStreamer:
    """Streams task and action progress to a Slack thread via plan blocks.

    Uses the Slack SDK's ``ChatStream`` helper for automatic buffering
    and state management.  The stream is started lazily on the first
    ``update()`` or ``update_action()`` call.

    Two display modes:

    - **Plan mode** (``update()`` called): Todo items appear as a
      plan block.  A dedicated action task showing the latest tool use
      is inserted after the first in-progress task.
    - **No-plan mode** (only ``update_action()`` called): A single
      synthetic task shows live activity (e.g. "Reading src/main.py"),
      marked ``complete`` on ``finalize()``.

    Includes debouncing: rapid calls within
    ``_MIN_APPEND_INTERVAL_SECONDS`` are coalesced, sending only the
    latest state.

    A background keepalive timer re-sends the last task state every
    ``_KEEPALIVE_INTERVAL_SECONDS`` to prevent Slack from expiring
    the stream during long gaps between events.

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
        self._last_chunks: list[TaskUpdateChunk] = []
        self._lock = threading.Lock()
        self._keepalive_timer: threading.Timer | None = None

        # Action tracking state.
        self._todo_items: list[TodoItem] = []
        self._action_summary: str = ""

    def _start_stream(self) -> ChatStream:
        """Start the chat stream on first use.

        Caller must hold ``_lock``.

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

    def _schedule_keepalive(self) -> None:
        """Schedule the next keepalive timer.

        Caller must hold ``_lock``.
        """
        self._cancel_keepalive()
        timer = threading.Timer(
            _KEEPALIVE_INTERVAL_SECONDS,
            self._keepalive_tick,
        )
        timer.daemon = True
        timer.start()
        self._keepalive_timer = timer

    def _cancel_keepalive(self) -> None:
        """Cancel any pending keepalive timer.

        Caller must hold ``_lock``.
        """
        if self._keepalive_timer is not None:
            self._keepalive_timer.cancel()
            self._keepalive_timer = None

    def _keepalive_tick(self) -> None:
        """Timer callback: re-send last task state to keep stream alive."""
        with self._lock:
            if self._stream is None or not self._last_chunks:
                return
            try:
                self._stream.append(chunks=self._last_chunks)
                self._last_append_time = time.monotonic()
                self._schedule_keepalive()
            except SlackApiError:
                # Stream likely expired between scheduling and firing.
                # The next real update() will handle recovery.
                logger.debug("Keepalive append failed; stream may have expired")

    def update(self, items: list[TodoItem]) -> None:
        """Send updated task list to the Slack thread.

        Starts the stream lazily on the first call.  Subsequent calls
        append task updates.  Debounces rapid calls to respect rate
        limits.

        If Slack returns ``message_not_in_streaming_state`` (the
        server expired the stream due to inactivity), the old stream
        is discarded and a fresh one is started so remaining updates
        still reach the user (as a new plan message in the thread).

        After each successful append a keepalive timer is (re)started
        so the stream stays alive during long gaps between
        ``TodoWrite`` events.

        Args:
            items: Complete todo list from the latest ``TodoWrite``.
        """
        with self._lock:
            self._todo_items = list(items)

            now = time.monotonic()
            elapsed = now - self._last_append_time

            chunks = _build_task_chunks(items, self._action_summary)

            # Clear the action summary so it doesn't leak into a
            # newly-started task on the next update().  The next
            # update_action() call will set a fresh summary.
            self._action_summary = ""

            # Debounce: skip the API call if too soon after last append
            # (unless this is the very first call).  Still update
            # _last_chunks so the keepalive always re-sends the latest
            # state, not stale data from the previous successful append.
            if (
                self._stream is not None
                and elapsed < _MIN_APPEND_INTERVAL_SECONDS
            ):
                self._last_chunks = chunks
                return

            self._append_chunks(chunks)

    def update_action(self, summary: str) -> None:
        """Send a live action status to the Slack thread.

        When todo items exist, a dedicated action task is inserted
        after the first in-progress task.  Otherwise, a single
        synthetic task is created to provide activity feedback.

        Args:
            summary: One-line action description.
        """
        with self._lock:
            self._action_summary = summary

            now = time.monotonic()
            elapsed = now - self._last_append_time

            if self._todo_items:
                chunks = _build_task_chunks(
                    self._todo_items, self._action_summary
                )
            else:
                chunks = [
                    TaskUpdateChunk(
                        id="action",
                        title=summary,
                        status="in_progress",
                    )
                ]

            # Debounce: skip the API call if too soon after last
            # append (unless this is the very first call).
            if (
                self._stream is not None
                and elapsed < _MIN_APPEND_INTERVAL_SECONDS
            ):
                self._last_chunks = chunks
                return

            self._append_chunks(chunks)

    def _append_chunks(self, chunks: list[TaskUpdateChunk]) -> None:
        """Send chunks to the stream, handling startup and recovery.

        Caller must hold ``_lock``.
        """
        try:
            if self._stream is None:
                stream = self._start_stream()
                stream.append(chunks=chunks)
            else:
                self._stream.append(chunks=chunks)
            self._last_append_time = time.monotonic()
            self._last_chunks = chunks
            self._schedule_keepalive()
        except SlackApiError as e:
            if _is_stream_expired(e):
                logger.info(
                    "Plan stream expired (idle timeout); starting a new stream"
                )
                self._stream = None
                self._cancel_keepalive()
                try:
                    stream = self._start_stream()
                    stream.append(chunks=chunks)
                    self._last_append_time = time.monotonic()
                    self._last_chunks = chunks
                    self._schedule_keepalive()
                except SlackApiError as retry_err:
                    logger.warning(
                        "Failed to restart plan stream (non-fatal): %s",
                        retry_err,
                    )
            else:
                logger.warning(
                    "Failed to stream plan update (non-fatal): %s",
                    e,
                )

    def finalize(self) -> None:
        """Stop the stream and cancel keepalive timer.

        If the stream was used in no-plan mode (action-only, no
        ``TodoWrite``), the synthetic action task is marked complete
        before stopping.

        Safe to call even if the stream was never started (no-op).
        If the stream already expired server-side, the error is
        silently ignored.
        """
        with self._lock:
            self._cancel_keepalive()

            if self._stream is None:
                return

            try:
                # In no-plan mode, mark the synthetic action task as
                # complete so the UI shows a clean finished state.
                if not self._todo_items and self._action_summary:
                    final_chunks = [
                        TaskUpdateChunk(
                            id="action",
                            title=self._action_summary,
                            status="complete",
                        )
                    ]
                    self._stream.stop(chunks=final_chunks)
                else:
                    self._stream.stop()
            except SlackApiError as e:
                if _is_stream_expired(e):
                    logger.debug("Plan stream already expired; nothing to stop")
                else:
                    logger.warning(
                        "Failed to stop plan stream (non-fatal): %s", e
                    )


def _is_stream_expired(err: SlackApiError) -> bool:
    """Check whether a Slack API error indicates the stream expired.

    Slack auto-expires a streaming session after a period of inactivity.
    Subsequent ``appendStream`` or ``stopStream`` calls return the
    ``message_not_in_streaming_state`` error code.
    """
    try:
        return err.response.data.get("error") == _STREAM_EXPIRED_ERROR
    except AttributeError:
        return False


def _content_id(content: str) -> str:
    """Derive a stable task ID from the item's content string.

    Uses an 8-character hex prefix of the SHA-256 hash.  This keeps
    task IDs stable across ``update()`` calls even when the list is
    reordered, items are inserted, or items are removed — which is
    required by Slack's streaming plan API (it matches tasks by ID
    across ``appendStream`` calls).
    """
    return hashlib.sha256(content.encode()).hexdigest()[:8]


def _build_task_chunks(
    items: list[TodoItem],
    action_summary: str = "",
) -> list[TaskUpdateChunk]:
    """Convert TodoItems to Slack TaskUpdateChunk objects.

    Derives task IDs from each item's ``content`` field so that the
    same logical task keeps the same ID across successive ``update()``
    calls.  Slack's streaming plan API uses the ``id`` to track and
    update individual task cards in place; positional indices would
    break when the list is reordered.

    When *action_summary* is non-empty a dedicated action task
    (``id="action"``, ``status="in_progress"``) is inserted after the
    first in-progress todo task.  This uses the ``title`` field (which
    Slack *replaces* on each append) rather than ``details`` (which
    Slack *appends*), avoiding unbounded text growth.

    Args:
        items: Todo items from Claude's TodoWrite.
        action_summary: Optional one-line action description to
            show as a dedicated task after the first in-progress task.

    Returns:
        List of ``TaskUpdateChunk`` objects for the streaming API.
    """
    seen: set[str] = set()
    chunks: list[TaskUpdateChunk] = []
    action_inserted = False
    for item in items:
        task_id = _content_id(item.content)
        # Handle duplicate content strings by appending a suffix.
        base_id = task_id
        counter = 2
        while task_id in seen:
            task_id = f"{base_id}_{counter}"
            counter += 1
        seen.add(task_id)

        chunks.append(
            TaskUpdateChunk(
                id=task_id,
                title=item.active_form or item.content,
                status=_STATUS_MAP.get(item.status, "pending"),
            )
        )

        # Insert a dedicated action task after the first in-progress
        # todo item.  Uses title (replaced by Slack) not details
        # (appended by Slack).
        if (
            action_summary
            and not action_inserted
            and item.status == TodoStatus.IN_PROGRESS
        ):
            chunks.append(
                TaskUpdateChunk(
                    id="action",
                    title=action_summary,
                    status="in_progress",
                )
            )
            action_inserted = True

    return chunks
