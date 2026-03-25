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

from airut._json_types import JsonDict
from airut.claude_output.types import StreamEvent
from airut.dashboard.tracker import (
    ACTIVE_STATUSES,
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


def _boot_state_to_dict(boot_state: BootState) -> JsonDict:
    """Convert BootState to JSON-serializable dict.

    Delegates to :meth:`BootState.to_api_dict`.

    Args:
        boot_state: Boot state to convert.

    Returns:
        Dict representation suitable for SSE state event.
    """
    return boot_state.to_api_dict()


def _repo_state_to_dict(repo_state: RepoState) -> JsonDict:
    """Convert RepoState to JSON-serializable dict.

    Delegates to :meth:`RepoState.to_api_dict`.

    Args:
        repo_state: Repository state to convert.

    Returns:
        Dict representation suitable for SSE state event.
    """
    return repo_state.to_api_dict()


def _task_state_to_dict(task: TaskState) -> JsonDict:
    """Convert TaskState to JSON-serializable dict for SSE.

    Delegates to :meth:`TaskState.to_api_dict`.

    Args:
        task: Task state to convert.

    Returns:
        Dict representation suitable for SSE state event.
    """
    return task.to_api_dict()


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

    boot_dict: JsonDict | None = None
    if boot_store is not None:
        boot_dict = _boot_state_to_dict(boot_store.get().value)

    repo_dicts: list[JsonDict] = []
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


def _build_html_state_events(
    tracker: TaskTracker,
    boot_store: VersionedStore[BootState] | None,
    repos_store: VersionedStore[tuple[RepoState, ...]] | None,
    version: int,
    event_id: str | None = None,
    retry: int | None = None,
    task_id: str | None = None,
    repo_id: str | None = None,
) -> str:
    """Build HTML-mode SSE events with separate named events per region.

    Each dashboard region gets its own SSE event name so htmx's
    ``sse-swap`` can target each element independently.

    When ``task_id`` is set, emits task-specific events (``task-status``,
    ``task-progress``, ``task-details``) instead of dashboard events.
    When ``repo_id`` is set, emits repo-specific events (``repo-status``,
    ``repo-error``) instead of dashboard events.

    Args:
        tracker: Task tracker for current tasks.
        boot_store: Versioned boot state store.
        repos_store: Versioned repo states store.
        version: Version number for event ID.
        event_id: Optional event ID override.
        retry: Optional retry interval for initial event.
        task_id: If set, emit task detail events for this task.
        repo_id: If set, emit repo detail events for this repo.

    Returns:
        Concatenated SSE-formatted event strings.
    """
    eid = event_id or str(version)

    if task_id is not None:
        return _build_task_detail_events(tracker, eid, retry, task_id)

    if repo_id is not None:
        return _build_repo_detail_events(repos_store, eid, retry, repo_id)

    return _build_dashboard_events(tracker, boot_store, repos_store, eid, retry)


def _build_task_detail_events(
    tracker: TaskTracker,
    eid: str,
    retry: int | None,
    task_id: str,
) -> str:
    """Build SSE events for the task detail page.

    Emits ``task-status``, ``task-actions``, ``task-progress``, and
    ``task-details`` events matching the ``sse-swap`` attributes in
    the task detail template.

    Args:
        tracker: Task tracker.
        eid: Event ID string.
        retry: Optional retry interval.
        task_id: Task to render events for.

    Returns:
        Concatenated SSE-formatted event strings.
    """
    from airut.dashboard.templating import render_template

    task = tracker.get_task(task_id)
    if task is None:
        return format_sse_event("done", "", event_id=eid, retry=retry)

    parts: list[str] = []
    is_active = task.status in ACTIVE_STATUSES

    # task-status: the status badge
    status_html = render_template(
        "components/task_status_badge.html", task=task, is_active=is_active
    )
    parts.append(
        format_sse_event("task-status", status_html, event_id=eid, retry=retry)
    )

    # task-actions: action buttons (stop, view actions/network)
    actions_html = render_template("components/action_buttons.html", task=task)
    parts.append(format_sse_event("task-actions", actions_html, event_id=eid))

    # task-progress: todo checklist
    progress_html = render_template(
        "components/todo_progress.html", todos=task.todos
    )
    parts.append(format_sse_event("task-progress", progress_html, event_id=eid))

    # task-details: timing and stats card content
    details_html = render_template(
        "components/task_details_card.html",
        task=task,
        model_display=task.model or "-",
    )
    parts.append(format_sse_event("task-details", details_html, event_id=eid))

    # Send done event when task completes
    if task.status == TaskStatus.COMPLETED:
        parts.append(format_sse_event("done", "", event_id=eid))

    return "".join(parts)


def _build_repo_detail_events(
    repos_store: VersionedStore[tuple[RepoState, ...]] | None,
    eid: str,
    retry: int | None,
    repo_id: str,
) -> str:
    """Build SSE events for the repo detail page.

    Emits ``repo-status`` and ``repo-error`` events matching the
    ``sse-swap`` attributes in the repo detail template.

    Args:
        repos_store: Versioned repo states store.
        eid: Event ID string.
        retry: Optional retry interval.
        repo_id: Repository to render events for.

    Returns:
        Concatenated SSE-formatted event strings.
    """
    from airut.dashboard.templating import render_template

    repo_states = list(repos_store.get().value) if repos_store else []
    repo = next((r for r in repo_states if r.repo_id == repo_id), None)
    if repo is None:
        return format_sse_event("done", "", event_id=eid, retry=retry)

    parts: list[str] = []

    # repo-status: the status badge
    status_html = render_template(
        "components/repo_status_badge.html", repo=repo
    )
    parts.append(
        format_sse_event("repo-status", status_html, event_id=eid, retry=retry)
    )

    # repo-error: error details section
    error_html = render_template(
        "components/repo_error_section.html", repo=repo
    )
    parts.append(format_sse_event("repo-error", error_html, event_id=eid))

    return "".join(parts)


def _build_dashboard_events(
    tracker: TaskTracker,
    boot_store: VersionedStore[BootState] | None,
    repos_store: VersionedStore[tuple[RepoState, ...]] | None,
    eid: str,
    retry: int | None,
) -> str:
    """Build SSE events for the main dashboard page.

    Emits per-region events (boot-state, repos, pending-header, etc.)
    matching the ``sse-swap`` attributes in the dashboard template.

    Args:
        tracker: Task tracker for current tasks.
        boot_store: Versioned boot state store.
        repos_store: Versioned repo states store.
        eid: Event ID string.
        retry: Optional retry interval for initial event.

    Returns:
        Concatenated SSE-formatted event strings.
    """
    from airut.dashboard.templating import render_template

    # Gather state
    boot_state = boot_store.get().value if boot_store else None
    repo_states = list(repos_store.get().value) if repos_store else []
    all_tasks = tracker.get_all_tasks()

    pending = [
        t
        for t in all_tasks
        if t.status
        in (TaskStatus.QUEUED, TaskStatus.AUTHENTICATING, TaskStatus.PENDING)
    ]
    executing = [t for t in all_tasks if t.status == TaskStatus.EXECUTING]
    completed = [t for t in all_tasks if t.status == TaskStatus.COMPLETED]

    parts: list[str] = []

    # Boot state
    boot_html = render_template(
        "components/boot_state.html", boot_state=boot_state
    )
    parts.append(
        format_sse_event("boot-state", boot_html, event_id=eid, retry=retry)
    )

    # Repos
    repos_html = render_template(
        "components/repos_section.html", repo_states=repo_states
    )
    parts.append(format_sse_event("repos", repos_html, event_id=eid))

    # Pending header + tasks
    parts.append(
        format_sse_event(
            "pending-header",
            f'<div id="pending-header" class="column-header pending"'
            f' sse-swap="pending-header" hx-swap="outerHTML">'
            f"Pending ({len(pending)})</div>",
            event_id=eid,
        )
    )
    pending_cards = (
        "".join(
            render_template(
                "components/task_card.html",
                task=t,
                status_class="pending",
            )
            for t in pending
        )
        or '<div class="empty">No conversations</div>'
    )
    parts.append(format_sse_event("pending-tasks", pending_cards, event_id=eid))

    # Executing header + tasks
    parts.append(
        format_sse_event(
            "executing-header",
            f'<div id="executing-header" class="column-header executing"'
            f' sse-swap="executing-header" hx-swap="outerHTML">'
            f"Executing ({len(executing)})</div>",
            event_id=eid,
        )
    )
    executing_cards = (
        "".join(
            render_template(
                "components/task_card.html",
                task=t,
                status_class="executing",
            )
            for t in executing
        )
        or '<div class="empty">No conversations</div>'
    )
    parts.append(
        format_sse_event("executing-tasks", executing_cards, event_id=eid)
    )

    # Completed header + tasks
    parts.append(
        format_sse_event(
            "completed-header",
            f'<div id="completed-header" class="column-header completed"'
            f' sse-swap="completed-header" hx-swap="outerHTML">'
            f"Done ({len(completed)})</div>",
            event_id=eid,
        )
    )
    completed_cards = (
        "".join(
            render_template(
                "components/task_card.html",
                task=t,
                status_class="completed",
            )
            for t in completed
        )
        or '<div class="empty">No conversations</div>'
    )
    parts.append(
        format_sse_event("completed-tasks", completed_cards, event_id=eid)
    )

    return "".join(parts)


def sse_state_stream(
    clock: VersionClock,
    tracker: TaskTracker,
    boot_store: VersionedStore[BootState] | None,
    repos_store: VersionedStore[tuple[RepoState, ...]] | None,
    client_version: int,
    heartbeat_interval: float = 15.0,
    html_mode: bool = False,
    task_id: str | None = None,
    repo_id: str | None = None,
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
        html_mode: If True, send pre-rendered HTML fragments as
            separate named SSE events instead of JSON snapshots.
        task_id: If set with html_mode, emit task detail events.
        repo_id: If set with html_mode, emit repo detail events.

    Yields:
        SSE-formatted event strings.
    """
    # Send initial snapshot with retry interval for browser reconnection.
    # Capture version BEFORE yielding so the next iteration uses the
    # correct baseline (the generator suspends at yield).
    known = clock.version

    if html_mode:
        yield _build_html_state_events(
            tracker,
            boot_store,
            repos_store,
            known,
            retry=1000,
            task_id=task_id,
            repo_id=repo_id,
        )
    else:
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
        if html_mode:
            yield _build_html_state_events(
                tracker,
                boot_store,
                repos_store,
                new_version,
                task_id=task_id,
                repo_id=repo_id,
            )
        else:
            yield format_sse_event(
                "state",
                build_state_snapshot(
                    tracker, boot_store, repos_store, new_version
                ),
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

    Sends raw HTML in the ``data:`` field with byte offset in the SSE
    ``id:`` field. The htmx SSE extension uses ``sse-swap="html"`` with
    ``hx-swap="beforeend"`` to append content directly.

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
    yield format_sse_event("html", html, event_id=str(offset), retry=1000)

    while True:
        events, new_offset = event_log.tail(offset)
        if events:
            offset = new_offset
            last_heartbeat = time.monotonic()
            html = render_events_html(events)
            yield format_sse_event("html", html, event_id=str(offset))

        # Check if all tasks for this conversation are done
        tasks = tracker.get_tasks_for_conversation(conversation_id)
        all_done = not tasks or all(
            t.status == TaskStatus.COMPLETED for t in tasks
        )
        if all_done:
            # Drain any remaining events
            events, offset = event_log.tail(offset)
            if events:
                html = render_events_html(events)
                yield format_sse_event("html", html, event_id=str(offset))
            yield format_sse_event("done", "", event_id=str(offset))
            return

        # Send heartbeat if idle
        if time.monotonic() - last_heartbeat >= heartbeat_interval:
            yield format_sse_comment("heartbeat")
            last_heartbeat = time.monotonic()

        time.sleep(poll_interval)


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

    Sends raw HTML in the ``data:`` field with byte offset in the SSE
    ``id:`` field. The htmx SSE extension uses ``sse-swap="html"`` with
    ``hx-swap="beforeend"`` to append content directly.

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
    yield format_sse_event("html", html, event_id=str(offset), retry=1000)

    while True:
        lines, new_offset = network_log.tail(offset)
        if lines:
            offset = new_offset
            last_heartbeat = time.monotonic()
            html = render_network_lines_html(lines)
            yield format_sse_event("html", html, event_id=str(offset))

        # Check if all tasks for this conversation are done
        tasks = tracker.get_tasks_for_conversation(conversation_id)
        all_done = not tasks or all(
            t.status == TaskStatus.COMPLETED for t in tasks
        )
        if all_done:
            # Drain any remaining lines
            lines, offset = network_log.tail(offset)
            if lines:
                html = render_network_lines_html(lines)
                yield format_sse_event("html", html, event_id=str(offset))
            yield format_sse_event("done", "", event_id=str(offset))
            return

        # Send heartbeat if idle
        if time.monotonic() - last_heartbeat >= heartbeat_interval:
            yield format_sse_comment("heartbeat")
            last_heartbeat = time.monotonic()

        time.sleep(poll_interval)
