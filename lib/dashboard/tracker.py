# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Task tracking for email gateway dashboard.

Provides thread-safe in-memory storage of task states for the dashboard
to display queued, in-progress, and completed tasks.
"""

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum


class TaskStatus(Enum):
    """Task execution status."""

    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class RepoStatus(Enum):
    """Repository initialization status."""

    LIVE = "live"
    FAILED = "failed"


@dataclass
class RepoState:
    """State of a repository in the gateway.

    Attributes:
        repo_id: Unique repository identifier.
        status: Current status (live or failed).
        error_message: Human-readable error message if failed, None if live.
        error_type: Exception type name if failed, None if live.
        git_repo_url: URL of the git repository.
        imap_server: IMAP server hostname.
        storage_dir: Path to storage directory.
        initialized_at: Unix timestamp when status was recorded.
    """

    repo_id: str
    status: RepoStatus
    error_message: str | None = None
    error_type: str | None = None
    git_repo_url: str = ""
    imap_server: str = ""
    storage_dir: str = ""
    initialized_at: float = field(default_factory=time.time)


@dataclass
class TaskState:
    """State of a single task in the queue.

    Attributes:
        conversation_id: Unique 8-char hex conversation identifier.
        subject: Original email subject line.
        status: Current task status.
        queued_at: Unix timestamp when task was added to queue.
        started_at: Unix timestamp when execution began, or None.
        completed_at: Unix timestamp when execution finished, or None.
        success: True if completed successfully, False if failed,
            None if pending.
        message_count: Number of messages in the conversation.
        model: Claude model used for this conversation (e.g., "opus", "sonnet").
    """

    conversation_id: str
    subject: str
    repo_id: str = ""
    sender: str = ""
    status: TaskStatus = TaskStatus.QUEUED
    queued_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    success: bool | None = None
    message_count: int = 1
    model: str | None = None

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

    Attributes:
        max_completed: Maximum number of completed tasks to retain.
    """

    def __init__(self, max_completed: int = 100) -> None:
        """Initialize tracker.

        Args:
            max_completed: Maximum completed tasks to keep in memory.
        """
        self.max_completed = max_completed
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        # OrderedDict maintains insertion order for FIFO eviction
        self._tasks: OrderedDict[str, TaskState] = OrderedDict()

    def add_task(
        self,
        conversation_id: str,
        subject: str,
        *,
        repo_id: str = "",
        sender: str = "",
        model: str | None = None,
    ) -> None:
        """Record a new task as queued.

        Args:
            conversation_id: Unique conversation identifier.
            subject: Original email subject line.
            repo_id: Repository identifier.
            sender: Email address of the sender.
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
                task.success = None
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
                    subject=subject,
                    repo_id=repo_id,
                    sender=sender,
                    model=model,
                )
            self._evict_old_completed()

    def start_task(self, conversation_id: str) -> None:
        """Mark a task as in-progress.

        Args:
            conversation_id: Conversation identifier to update.
        """
        with self._lock:
            if conversation_id in self._tasks:
                task = self._tasks[conversation_id]
                task.status = TaskStatus.IN_PROGRESS
                task.started_at = time.time()

    def complete_task(
        self,
        conversation_id: str,
        success: bool,
        message_count: int | None = None,
    ) -> None:
        """Mark a task as completed.

        Args:
            conversation_id: Conversation identifier to update.
            success: Whether execution succeeded.
            message_count: Optional updated message count.
        """
        with self._lock:
            if conversation_id in self._tasks:
                task = self._tasks[conversation_id]
                task.status = TaskStatus.COMPLETED
                task.completed_at = time.time()
                task.success = success
                if message_count is not None:
                    task.message_count = message_count
                self._evict_old_completed()
                self._condition.notify_all()

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
            return True

    def is_task_active(self, conversation_id: str) -> bool:
        """Check if a task is currently queued or in progress.

        Args:
            conversation_id: Conversation identifier to check.

        Returns:
            True if task exists and is QUEUED or IN_PROGRESS, False otherwise.
        """
        with self._lock:
            task = self._tasks.get(conversation_id)
            if task is None:
                return False
            return task.status in (TaskStatus.QUEUED, TaskStatus.IN_PROGRESS)

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
        with self._condition:
            deadline = time.monotonic() + timeout
            while True:
                task = self._tasks.get(conversation_id)
                if task and task.status == TaskStatus.COMPLETED:
                    return task
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return task
                self._condition.wait(timeout=remaining)

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
