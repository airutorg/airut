# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Server-Sent Events (SSE) support for the dashboard.

Provides SSE message formatting, a connection manager to enforce
concurrent connection limits, and generator functions for streaming
state updates to connected browsers.
"""

import json
import logging
import threading
import time
from collections.abc import Generator
from typing import Any

from airut.claude_output.types import StreamEvent
from airut.dashboard.tracker import (
    BootState,
    RepoState,
    TaskState,
    TaskStatus,
    TaskTracker,
)
from airut.dashboard.versioned import VersionClock, VersionedStore
from airut.sandbox.event_log import EventLog
from airut.sandbox.network_log import NetworkLog


logger = logging.getLogger(__name__)


def format_sse_event(
    event: str,
    data: str,
    event_id: str | None = None,
    retry: int | None = None,
) -> str:
    """Format a Server-Sent Events message.

    Args:
        event: Event type name (e.g., "state", "done").
        data: Event data payload (typically JSON).
        event_id: Optional event ID for reconnection.
        retry: Optional reconnection interval in milliseconds.

    Returns:
        SSE-formatted string ready to send over the wire.
    """
    lines: list[str] = []
    if retry is not None:
        lines.append(f"retry: {retry}")
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    # Data may contain newlines — each line needs a "data:" prefix
    for line in data.split("\n"):
        lines.append(f"data: {line}")
    lines.append("")  # Blank line terminates the event
    lines.append("")
    return "\n".join(lines)


def format_sse_comment(text: str) -> str:
    """Format an SSE comment line (used for heartbeats).

    Args:
        text: Comment text.

    Returns:
        SSE comment string.
    """
    return f": {text}\n\n"


class SSEConnectionManager:
    """Tracks active SSE connections to enforce limits.

    Each SSE connection holds a WSGI thread for its entire lifetime.
    This manager caps the number of concurrent connections to prevent
    thread pool exhaustion.
    """

    def __init__(self, max_connections: int = 8) -> None:
        self._lock = threading.Lock()
        self._active: int = 0
        self._max: int = max_connections

    def try_acquire(self) -> bool:
        """Try to acquire an SSE slot.

        Returns:
            True if a slot was acquired, False if at limit.
        """
        with self._lock:
            if self._active >= self._max:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        """Release an SSE slot."""
        with self._lock:
            self._active = max(0, self._active - 1)

    @property
    def active(self) -> int:
        """Number of active SSE connections."""
        with self._lock:
            return self._active


def _boot_state_to_dict(boot_state: BootState) -> dict[str, Any]:
    """Convert BootState to JSON-serializable dict.

    Args:
        boot_state: Boot state to convert.

    Returns:
        Dict representation suitable for SSE state event.
    """
    result: dict[str, Any] = {
        "phase": boot_state.phase.value,
        "message": boot_state.message,
    }
    if boot_state.error_message:
        result["error_message"] = boot_state.error_message
    if boot_state.error_type:
        result["error_type"] = boot_state.error_type
    if boot_state.error_traceback:
        result["error_traceback"] = boot_state.error_traceback
    result["started_at"] = boot_state.started_at
    result["completed_at"] = boot_state.completed_at
    return result


def _repo_state_to_dict(repo_state: RepoState) -> dict[str, Any]:
    """Convert RepoState to JSON-serializable dict.

    Args:
        repo_state: Repository state to convert.

    Returns:
        Dict representation suitable for SSE state event.
    """
    return {
        "repo_id": repo_state.repo_id,
        "status": repo_state.status.value,
        "error_message": repo_state.error_message,
        "error_type": repo_state.error_type,
        "git_repo_url": repo_state.git_repo_url,
        "channel_info": repo_state.channel_info,
        "storage_dir": repo_state.storage_dir,
        "initialized_at": repo_state.initialized_at,
    }


def _task_state_to_dict(task: TaskState) -> dict[str, Any]:
    """Convert TaskState to JSON-serializable dict for SSE.

    Matches the format used by ``/api/conversations`` for consistency.

    Args:
        task: Task state to convert.

    Returns:
        Dict representation suitable for SSE state event.
    """
    result: dict[str, Any] = {
        "conversation_id": task.conversation_id,
        "subject": task.subject,
        "repo_id": task.repo_id,
        "sender": task.sender,
        "status": task.status.value,
        "queued_at": task.queued_at,
        "started_at": task.started_at,
        "completed_at": task.completed_at,
        "success": task.success,
        "message_count": task.message_count,
        "model": task.model,
        "queue_duration": task.queue_duration(),
        "execution_duration": task.execution_duration(),
        "total_duration": task.total_duration(),
    }
    if task.todos is not None:
        result["todos"] = [t.to_dict() for t in task.todos]
    return result


def build_state_snapshot(
    tracker: TaskTracker,
    boot_store: VersionedStore[BootState] | None,
    repos_store: VersionedStore[tuple[RepoState, ...]] | None,
    version: int,
) -> str:
    """Build the JSON state snapshot for SSE delivery.

    Args:
        tracker: Task tracker for current tasks.
        boot_store: Versioned boot state store.
        repos_store: Versioned repo states store.
        version: Version number to include in the snapshot.

    Returns:
        JSON string containing the full state snapshot.
    """
    tasks = tracker.get_all_tasks()
    task_dicts = [_task_state_to_dict(t) for t in tasks]

    boot_dict: dict[str, Any] | None = None
    if boot_store is not None:
        boot_dict = _boot_state_to_dict(boot_store.get().value)

    repo_dicts: list[dict[str, Any]] = []
    if repos_store is not None:
        repo_dicts = [_repo_state_to_dict(r) for r in repos_store.get().value]

    return json.dumps(
        {
            "version": version,
            "tasks": task_dicts,
            "boot": boot_dict,
            "repos": repo_dicts,
        }
    )


def sse_state_stream(
    clock: VersionClock,
    tracker: TaskTracker,
    boot_store: VersionedStore[BootState] | None,
    repos_store: VersionedStore[tuple[RepoState, ...]] | None,
    client_version: int,
    heartbeat_interval: float = 15.0,
) -> Generator[str]:
    """Generate SSE events for the state stream.

    Yields SSE-formatted strings. Blocks between events using
    ``VersionClock.wait()``. Sends heartbeat comments to detect
    dead connections.

    Args:
        clock: Shared version clock.
        tracker: Task tracker.
        boot_store: Versioned boot state store.
        repos_store: Versioned repo states store.
        client_version: Client's last known version.
        heartbeat_interval: Seconds between heartbeat comments.

    Yields:
        SSE-formatted event strings.
    """
    # Send initial snapshot with retry interval for browser reconnection.
    # Capture version BEFORE yielding so the next iteration uses the
    # correct baseline (the generator suspends at yield).
    known = clock.version
    yield format_sse_event(
        "state",
        build_state_snapshot(tracker, boot_store, repos_store, known),
        event_id=str(known),
        retry=1000,
    )

    while True:
        new_version = clock.wait(known, timeout=heartbeat_interval)

        if new_version is None:
            # Timeout — send heartbeat
            yield format_sse_comment("heartbeat")
            continue

        # State changed — send new snapshot
        known = new_version
        yield format_sse_event(
            "state",
            build_state_snapshot(tracker, boot_store, repos_store, new_version),
            event_id=str(new_version),
        )


def render_events_html(events: list[StreamEvent]) -> str:
    """Render stream events to HTML fragments.

    Args:
        events: List of StreamEvent objects.

    Returns:
        HTML string with all events rendered.
    """
    from airut.dashboard.views.actions import render_single_event

    parts: list[str] = []
    for event in events:
        parts.append(render_single_event(event))
    return "".join(parts)


def sse_events_log_stream(
    event_log: EventLog,
    tracker: TaskTracker,
    conversation_id: str,
    client_offset: int,
    poll_interval: float = 0.5,
    heartbeat_interval: float = 15.0,
) -> Generator[str]:
    """Generate SSE events for a conversation's event log stream.

    Polls ``EventLog.tail()`` for new events and yields them as SSE
    messages containing pre-rendered HTML fragments. Sends a terminal
    ``done`` event when the task completes.

    Args:
        event_log: EventLog instance for the conversation.
        tracker: Task tracker to check task status.
        conversation_id: Conversation ID to monitor.
        client_offset: Client's last known byte offset.
        poll_interval: Seconds between tail() polls.
        heartbeat_interval: Seconds between heartbeat comments.

    Yields:
        SSE-formatted event strings.
    """
    offset = client_offset
    last_heartbeat = time.monotonic()

    # Send initial catch-up with retry interval
    events, offset = event_log.tail(offset)
    html = render_events_html(events) if events else ""
    data = json.dumps({"offset": offset, "html": html})
    yield format_sse_event("html", data, retry=1000)

    while True:
        time.sleep(poll_interval)

        events, new_offset = event_log.tail(offset)
        if events:
            offset = new_offset
            last_heartbeat = time.monotonic()
            html = render_events_html(events)
            data = json.dumps({"offset": offset, "html": html})
            yield format_sse_event("html", data)

        # Check if task is done
        task = tracker.get_task(conversation_id)
        if task is None or task.status == TaskStatus.COMPLETED:
            # Drain any remaining events
            events, offset = event_log.tail(offset)
            if events:
                html = render_events_html(events)
                data = json.dumps({"offset": offset, "html": html})
                yield format_sse_event("html", data)
            yield format_sse_event("done", json.dumps({"offset": offset}))
            return

        # Send heartbeat if idle
        if time.monotonic() - last_heartbeat >= heartbeat_interval:
            yield format_sse_comment("heartbeat")
            last_heartbeat = time.monotonic()


def render_network_lines_html(lines: list[str]) -> str:
    """Render network log lines to HTML fragments.

    Args:
        lines: List of raw log line strings.

    Returns:
        HTML string with all lines rendered.
    """
    from airut.dashboard.views.network import render_network_log_line

    parts: list[str] = []
    for line in lines:
        if line:
            parts.append(render_network_log_line(line))
    return "".join(parts)


def sse_network_log_stream(
    network_log: NetworkLog,
    tracker: TaskTracker,
    conversation_id: str,
    client_offset: int,
    poll_interval: float = 0.5,
    heartbeat_interval: float = 15.0,
) -> Generator[str]:
    """Generate SSE events for a conversation's network log stream.

    Polls ``NetworkLog.tail()`` for new lines and yields them as SSE
    messages containing pre-rendered HTML fragments. Sends a terminal
    ``done`` event when the task completes.

    Args:
        network_log: NetworkLog instance for the conversation.
        tracker: Task tracker to check task status.
        conversation_id: Conversation ID to monitor.
        client_offset: Client's last known byte offset.
        poll_interval: Seconds between tail() polls.
        heartbeat_interval: Seconds between heartbeat comments.

    Yields:
        SSE-formatted event strings.
    """
    offset = client_offset
    last_heartbeat = time.monotonic()

    # Send initial catch-up with retry interval
    lines, offset = network_log.tail(offset)
    html = render_network_lines_html(lines) if lines else ""
    data = json.dumps({"offset": offset, "html": html})
    yield format_sse_event("html", data, retry=1000)

    while True:
        time.sleep(poll_interval)

        lines, new_offset = network_log.tail(offset)
        if lines:
            offset = new_offset
            last_heartbeat = time.monotonic()
            html = render_network_lines_html(lines)
            data = json.dumps({"offset": offset, "html": html})
            yield format_sse_event("html", data)

        # Check if task is done
        task = tracker.get_task(conversation_id)
        if task is None or task.status == TaskStatus.COMPLETED:
            # Drain any remaining lines
            lines, offset = network_log.tail(offset)
            if lines:
                html = render_network_lines_html(lines)
                data = json.dumps({"offset": offset, "html": html})
                yield format_sse_event("html", data)
            yield format_sse_event("done", json.dumps({"offset": offset}))
            return

        # Send heartbeat if idle
        if time.monotonic() - last_heartbeat >= heartbeat_interval:
            yield format_sse_comment("heartbeat")
            last_heartbeat = time.monotonic()
