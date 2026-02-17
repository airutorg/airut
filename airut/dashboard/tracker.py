# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Task tracking for gateway dashboard.

Provides thread-safe in-memory storage of task states for the dashboard
to display pending, executing, and completed tasks.
"""

import copy
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum

from airut.dashboard.versioned import VersionClock, Versioned


# Maximum number of pending messages queued per conversation.
MAX_PENDING_PER_CONVERSATION = 3


class TaskStatus(Enum):
    """Task lifecycle status.

    Tasks progress through: QUEUED → AUTHENTICATING → EXECUTING → COMPLETED.
    If the conversation is busy, an authenticated task enters PENDING before
    EXECUTING.
    """

    QUEUED = "queued"
    AUTHENTICATING = "authenticating"
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"


class CompletionReason(Enum):
    """Why a task reached the COMPLETED state.

    Separates the reason for completion from the completion status itself,
    allowing the dashboard to display different icons and colors for each.
    """

    SUCCESS = "success"
    AUTH_FAILED = "auth_failed"
    UNAUTHORIZED = "unauthorized"
    EXECUTION_FAILED = "execution_failed"
    TIMEOUT = "timeout"
    INTERNAL_ERROR = "internal_error"
    REJECTED = "rejected"


class RepoStatus(Enum):
    """Repository initialization status."""

    LIVE = "live"
    FAILED = "failed"


class BootPhase(Enum):
    """Service boot phase for progress reporting.

    Tracks the current phase of service startup so the dashboard can
    display boot progress.
    """

    STARTING = "starting"
    PROXY = "proxy"
    REPOS = "repos"
    READY = "ready"
    FAILED = "failed"


class TodoStatus(Enum):
    """Status of a single todo item."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


@dataclass(frozen=True)
class TodoItem:
    """A single todo item from Claude's TodoWrite tool.

    Defines the contract for todo progress data tracked by the dashboard.
    Immutable snapshot — new lists replace old ones on each TodoWrite
    event.

    Attributes:
        content: Imperative description of the task (e.g., "Run tests").
        status: Todo item status.
        active_form: Present-continuous form shown during execution
            (e.g., "Running tests").  Defaults to *content* if not
            provided by the tool.
    """

    content: str
    status: TodoStatus
    active_form: str = ""

    def to_dict(self) -> dict[str, str]:
        """Serialize to a JSON-compatible dict.

        Returns:
            Dict with ``content``, ``status``, and ``activeForm`` keys.
        """
        return {
            "content": self.content,
            "status": self.status.value,
            "activeForm": self.active_form or self.content,
        }


@dataclass(frozen=True)
class BootState:
    """Current boot state of the service.

    Immutable snapshot — mutations use ``dataclasses.replace()``.

    Attributes:
        phase: Current boot phase.
        message: Human-readable description of current activity.
        error_message: Error message if boot failed, None otherwise.
        error_type: Exception type name if boot failed, None otherwise.
        error_traceback: Full traceback string if boot failed, None otherwise.
        started_at: Unix timestamp when boot started.
        completed_at: Unix timestamp when boot completed (or failed).
    """

    phase: BootPhase = BootPhase.STARTING
    message: str = "Initializing..."
    error_message: str | None = None
    error_type: str | None = None
    error_traceback: str | None = None
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None


@dataclass(frozen=True)
class RepoState:
    """State of a repository in the gateway.

    Immutable snapshot — mutations use ``dataclasses.replace()``.

    Attributes:
        repo_id: Unique repository identifier.
        status: Current status (live or failed).
        error_message: Human-readable error message if failed, None if live.
        error_type: Exception type name if failed, None if live.
        git_repo_url: URL of the git repository.
        channel_info: Channel-specific connection info (e.g. IMAP server).
        storage_dir: Path to storage directory.
        initialized_at: Unix timestamp when status was recorded.
    """

    repo_id: str
    status: RepoStatus
    error_message: str | None = None
    error_type: str | None = None
    git_repo_url: str = ""
    channel_info: str = ""
    storage_dir: str = ""
    initialized_at: float = field(default_factory=time.time)


ACTIVE_STATUSES: frozenset[TaskStatus] = frozenset(
    {
        TaskStatus.QUEUED,
        TaskStatus.AUTHENTICATING,
        TaskStatus.PENDING,
        TaskStatus.EXECUTING,
    }
)


@dataclass
class TaskState:
    """State of a single task in the queue.

    Attributes:
        conversation_id: Unique 8-char hex conversation identifier.
        display_title: Short display title for the dashboard
            (e.g. email subject line, first line of Slack message).
        repo_id: Repository identifier.
        sender: Raw sender identity (pre-auth) for display.
        authenticated_sender: Verified sender identity, set only after
            authentication succeeds.  Empty if auth failed or not yet
            attempted.
        status: Current task lifecycle status.
        completion_reason: Why the task completed, or None if still active.
        completion_detail: Human-readable detail about the completion
            (e.g. "DMARC verification failed", "timeout after 300s").
        queued_at: Unix timestamp when task was added to queue.
        started_at: Unix timestamp when execution (EXECUTING) began, or None.
        completed_at: Unix timestamp when execution finished, or None.
        message_count: Number of messages in the conversation.
        model: Claude model used for this conversation (e.g., "opus", "sonnet").
        todos: Latest TodoWrite state from Claude, or None if no todos
            have been emitted yet.
    """

    conversation_id: str
    display_title: str
    repo_id: str = ""
    sender: str = ""
    authenticated_sender: str = ""
    status: TaskStatus = TaskStatus.QUEUED
    completion_reason: CompletionReason | None = None
    completion_detail: str = ""
    queued_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    message_count: int = 1
    model: str | None = None
    todos: list[TodoItem] | None = None

    @property
    def is_terminal(self) -> bool:
        """Whether this task has reached a terminal state."""
        return self.status == TaskStatus.COMPLETED

    @property
    def succeeded(self) -> bool:
        """Whether this task completed successfully."""
        return self.completion_reason == CompletionReason.SUCCESS

    def queue_duration(self) -> float:
        """Calculate time spent in queue.

        Returns:
            Seconds from queued_at to started_at (or now if not started).
        """
        end_time = self.started_at if self.started_at else time.time()
        return end_time - self.queued_at

    def execution_duration(self) -> float | None:
        """Calculate execution time.

        Returns:
            Seconds from started_at to completed_at (or now if running),
            or None if not yet started.
        """
        if self.started_at is None:
            return None
        end_time = self.completed_at if self.completed_at else time.time()
        return end_time - self.started_at

    def total_duration(self) -> float:
        """Calculate total time from queue to completion.

        Returns:
            Seconds from queued_at to completed_at (or now if not completed).
        """
        end_time = self.completed_at if self.completed_at else time.time()
        return end_time - self.queued_at


class TaskTracker:
    """Thread-safe task state management.

    Tracks tasks through their lifecycle from queued to completed,
    maintaining a bounded history of completed tasks.

    Integrates with a shared ``VersionClock`` so SSE endpoints wake
    on every mutation.

    Attributes:
        max_completed: Maximum number of completed tasks to retain.
    """

    def __init__(
        self,
        max_completed: int = 100,
        clock: VersionClock | None = None,
    ) -> None:
        """Initialize tracker.

        Args:
            max_completed: Maximum completed tasks to keep in memory.
            clock: Shared version clock. If None, a private clock is created.
        """
        self.max_completed = max_completed
        self._clock = clock or VersionClock()
        self._lock = threading.RLock()
        # OrderedDict maintains insertion order for FIFO eviction
        self._tasks: OrderedDict[str, TaskState] = OrderedDict()

    def add_task(
        self,
        conversation_id: str,
        display_title: str,
        *,
        repo_id: str = "",
        sender: str = "",
        model: str | None = None,
    ) -> None:
        """Record a new task as queued.

        Args:
            conversation_id: Unique conversation identifier.
            display_title: Short display title for the dashboard.
            repo_id: Repository identifier.
            sender: Raw sender identity for display.
            model: Optional Claude model for this conversation.
        """
        with self._lock:
            # Check if task already exists (resuming conversation)
            if conversation_id in self._tasks:
                # Update existing task back to queued state
                task = self._tasks[conversation_id]
                task.status = TaskStatus.QUEUED
                task.queued_at = time.time()
                task.started_at = None
                task.completed_at = None
                task.completion_reason = None
                task.completion_detail = ""
                task.authenticated_sender = ""
                task.message_count += 1
                # Preserve existing model if not provided
                if model is not None:
                    task.model = model
                if repo_id:
                    task.repo_id = repo_id
                if sender:
                    task.sender = sender
                # Move to end (most recent)
                self._tasks.move_to_end(conversation_id)
            else:
                self._tasks[conversation_id] = TaskState(
                    conversation_id=conversation_id,
                    display_title=display_title,
                    repo_id=repo_id,
                    sender=sender,
                    model=model,
                )
            self._evict_old_completed()
            self._clock.tick()

    def set_authenticating(self, conversation_id: str) -> bool:
        """Transition a task from QUEUED to AUTHENTICATING.

        Args:
            conversation_id: Task identifier to update.

        Returns:
            True if the task was found and transitioned, False if missing
            or not in QUEUED state.
        """
        with self._lock:
            if conversation_id not in self._tasks:
                return False
            task = self._tasks[conversation_id]
            if task.status != TaskStatus.QUEUED:
                return False
            task.status = TaskStatus.AUTHENTICATING
            self._clock.tick()
            return True

    def set_pending(self, conversation_id: str) -> bool:
        """Transition a task to PENDING.

        Used when the conversation already has an active task and this
        message must wait.  Valid from AUTHENTICATING state.

        Args:
            conversation_id: Task identifier to update.

        Returns:
            True if the task was found and transitioned, False if missing
            or not in a valid source state.
        """
        with self._lock:
            if conversation_id not in self._tasks:
                return False
            task = self._tasks[conversation_id]
            if task.status != TaskStatus.AUTHENTICATING:
                return False
            task.status = TaskStatus.PENDING
            self._clock.tick()
            return True

    def set_executing(self, conversation_id: str) -> bool:
        """Transition a task to EXECUTING.

        Sets ``started_at`` to the current time.  Valid from
        AUTHENTICATING or PENDING states.

        Args:
            conversation_id: Task identifier to update.

        Returns:
            True if the task was found and transitioned, False if missing
            or not in a valid source state.
        """
        with self._lock:
            if conversation_id not in self._tasks:
                return False
            task = self._tasks[conversation_id]
            if task.status not in (
                TaskStatus.AUTHENTICATING,
                TaskStatus.PENDING,
            ):
                return False
            task.status = TaskStatus.EXECUTING
            task.started_at = time.time()
            self._clock.tick()
            return True

    _COMPLETABLE_STATUSES: frozenset[TaskStatus] = frozenset(
        {
            TaskStatus.AUTHENTICATING,
            TaskStatus.PENDING,
            TaskStatus.EXECUTING,
        }
    )

    def complete_task(
        self,
        conversation_id: str,
        reason: CompletionReason,
        detail: str = "",
        message_count: int | None = None,
    ) -> bool:
        """Mark a task as completed.

        Valid from AUTHENTICATING, PENDING, or EXECUTING states.

        Args:
            conversation_id: Conversation identifier to update.
            reason: Why the task completed.
            detail: Human-readable completion detail.
            message_count: Optional updated message count.

        Returns:
            True if the task was found and completed, False if missing
            or not in a valid source state.
        """
        with self._lock:
            if conversation_id not in self._tasks:
                return False
            task = self._tasks[conversation_id]
            if task.status not in self._COMPLETABLE_STATUSES:
                return False
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            task.completion_reason = reason
            task.completion_detail = detail
            task.todos = None
            if message_count is not None:
                task.message_count = message_count
            self._evict_old_completed()
            self._clock.tick()
            return True

    def update_task_display_title(
        self,
        conversation_id: str,
        display_title: str,
        *,
        sender: str = "",
        authenticated_sender: str = "",
    ) -> bool:
        """Update the display title of an existing task.

        Used after authentication completes to replace the placeholder
        ``(authenticating)`` title with the real title.

        Args:
            conversation_id: Task identifier to update.
            display_title: New display title.
            sender: Raw sender identity to set (if non-empty).
            authenticated_sender: Verified sender identity to set
                (if non-empty).

        Returns:
            True if the task was found and updated, False otherwise.
        """
        with self._lock:
            if conversation_id not in self._tasks:
                return False
            task = self._tasks[conversation_id]
            task.display_title = display_title
            if sender:
                task.sender = sender
            if authenticated_sender:
                task.authenticated_sender = authenticated_sender
            self._clock.tick()
            return True

    def update_task_id(self, old_id: str, new_id: str) -> bool:
        """Update a task's conversation ID.

        Used when a temporary task ID (e.g., "new-...") needs to be replaced
        with the real conversation ID after it's generated.

        Args:
            old_id: Current task ID to update.
            new_id: New conversation ID to assign.

        Returns:
            True if the task was found and updated, False otherwise.
        """
        with self._lock:
            if old_id not in self._tasks:
                return False
            if new_id in self._tasks:
                # New ID already exists, can't update
                return False

            task = self._tasks.pop(old_id)
            task.conversation_id = new_id
            self._tasks[new_id] = task
            self._clock.tick()
            return True

    def reassign_task(self, temp_id: str, conv_id: str) -> bool:
        """Move a temporary task to a (possibly existing) conversation ID.

        Handles two cases:

        - **conv_id is new**: renames ``temp_id`` → ``conv_id`` (like
          ``update_task_id``).
        - **conv_id already exists** (resumed conversation): transfers
          the temp task's state onto the existing task and deletes the
          temp entry, incrementing ``message_count``.

        Args:
            temp_id: Temporary task ID (e.g. ``"new-..."``) to remove.
            conv_id: Real conversation ID to track under.

        Returns:
            True if the reassignment succeeded, False if ``temp_id``
            was not found.
        """
        with self._lock:
            if temp_id not in self._tasks:
                return False

            temp_task = self._tasks[temp_id]

            if conv_id not in self._tasks:
                # Simple rename
                self._tasks.pop(temp_id)
                temp_task.conversation_id = conv_id
                self._tasks[conv_id] = temp_task
            else:
                # Resume: transfer state to existing task
                existing = self._tasks[conv_id]
                existing.status = temp_task.status
                existing.display_title = temp_task.display_title
                existing.sender = temp_task.sender
                existing.authenticated_sender = temp_task.authenticated_sender
                existing.started_at = temp_task.started_at
                existing.completed_at = None
                existing.completion_reason = None
                existing.completion_detail = ""
                existing.message_count += 1
                if temp_task.model is not None:
                    existing.model = temp_task.model
                self._tasks.move_to_end(conv_id)
                del self._tasks[temp_id]

            self._clock.tick()
            return True

    def update_todos(self, conversation_id: str, todos: list[TodoItem]) -> bool:
        """Update the in-progress todo list for a task.

        Called when Claude emits a TodoWrite tool use during execution.

        Args:
            conversation_id: Conversation identifier to update.
            todos: List of ``TodoItem`` instances parsed from the
                TodoWrite tool_input.

        Returns:
            True if the task was found and updated, False otherwise.
        """
        with self._lock:
            if conversation_id not in self._tasks:
                return False
            self._tasks[conversation_id].todos = todos
            self._clock.tick()
            return True

    def set_task_model(self, conversation_id: str, model: str) -> bool:
        """Set the model for a task.

        Args:
            conversation_id: Conversation identifier to update.
            model: Claude model name to set.

        Returns:
            True if the task was found and updated, False otherwise.
        """
        with self._lock:
            if conversation_id not in self._tasks:
                return False
            self._tasks[conversation_id].model = model
            self._clock.tick()
            return True

    def is_task_active(self, conversation_id: str) -> bool:
        """Check if a task is currently active (not completed).

        Returns True for QUEUED, AUTHENTICATING, PENDING, and EXECUTING.

        Args:
            conversation_id: Conversation identifier to check.

        Returns:
            True if task exists and is not COMPLETED, False otherwise.
        """
        with self._lock:
            task = self._tasks.get(conversation_id)
            if task is None:
                return False
            return task.status in ACTIVE_STATUSES

    def get_task(self, conversation_id: str) -> TaskState | None:
        """Get a single task by conversation ID.

        Args:
            conversation_id: Conversation identifier to look up.

        Returns:
            TaskState if found, None otherwise.
        """
        with self._lock:
            return self._tasks.get(conversation_id)

    def get_all_tasks(self) -> list[TaskState]:
        """Get all tasks sorted by queued_at (newest first).

        Returns:
            List of all tracked tasks.
        """
        with self._lock:
            tasks = list(self._tasks.values())
        # Sort by queued_at descending (newest first)
        return sorted(tasks, key=lambda t: t.queued_at, reverse=True)

    def get_tasks_by_status(self, status: TaskStatus) -> list[TaskState]:
        """Get all tasks with a specific status.

        Args:
            status: Status to filter by.

        Returns:
            List of tasks with the given status, newest first.
        """
        with self._lock:
            tasks = [t for t in self._tasks.values() if t.status == status]
        return sorted(tasks, key=lambda t: t.queued_at, reverse=True)

    def get_counts(self) -> dict[str, int]:
        """Get task counts by status.

        Returns:
            Dict mapping status names to counts.
        """
        with self._lock:
            counts = {status.value: 0 for status in TaskStatus}
            for task in self._tasks.values():
                counts[task.status.value] += 1
            return counts

    def get_snapshot(self) -> Versioned[tuple[TaskState, ...]]:
        """Get an atomic snapshot of all tasks with the current version.

        Returns deep copies of tasks to ensure the snapshot is stable.
        Deep copy is required because ``TaskState.todos`` contains
        mutable containers (list of dicts).

        Returns:
            Versioned tuple of TaskState copies, sorted newest first.
        """
        with self._lock:
            tasks = sorted(
                self._tasks.values(),
                key=lambda t: t.queued_at,
                reverse=True,
            )
            return Versioned(
                version=self._clock.version,
                value=tuple(copy.deepcopy(t) for t in tasks),
            )

    def wait_for_completion(
        self,
        conversation_id: str,
        timeout: float = 5.0,
    ) -> TaskState | None:
        """Wait for a task to reach COMPLETED status.

        Args:
            conversation_id: Conversation identifier to wait for.
            timeout: Maximum time to wait in seconds.

        Returns:
            The completed TaskState, or None if timeout or task not found.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                task = self._tasks.get(conversation_id)
                if task and task.status == TaskStatus.COMPLETED:
                    return task
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with self._lock:
                    return self._tasks.get(conversation_id)
            # Wait on the shared clock for any state change
            self._clock.wait(self._clock.version, timeout=remaining)

    def _evict_old_completed(self) -> None:
        """Remove oldest completed tasks if over limit.

        Must be called with lock held.
        """
        completed = [
            cid
            for cid, task in self._tasks.items()
            if task.status == TaskStatus.COMPLETED
        ]
        # Remove oldest completed tasks (first in OrderedDict)
        while len(completed) > self.max_completed:
            oldest = completed.pop(0)
            del self._tasks[oldest]
