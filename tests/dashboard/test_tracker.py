# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for task tracker module."""

import threading
import time
from unittest.mock import patch

import pytest

from airut.dashboard.tracker import (
    CompletionReason,
    TaskState,
    TaskStatus,
    TaskTracker,
    TodoItem,
    TodoStatus,
)


class TestTaskState:
    """Tests for TaskState dataclass."""

    def test_default_values(self) -> None:
        """Test TaskState has correct defaults."""
        before = time.time()
        task = TaskState(
            conversation_id="abc12345", display_title="Test subject"
        )
        after = time.time()

        assert task.conversation_id == "abc12345"
        assert task.display_title == "Test subject"
        assert task.status == TaskStatus.QUEUED
        assert before <= task.queued_at <= after
        assert task.started_at is None
        assert task.completed_at is None
        assert task.completion_reason is None
        assert task.message_count == 1
        assert task.model is None

    def test_with_model(self) -> None:
        """Test TaskState with model specified."""
        task = TaskState(
            conversation_id="abc12345",
            display_title="Test subject",
            model="opus",
        )

        assert task.model == "opus"

    def test_queue_duration_not_started(self) -> None:
        """Test queue_duration when task hasn't started."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
        )

        # Time advances to 1060 (60 seconds in queue)
        with patch("airut.dashboard.tracker.time.time", return_value=1060.0):
            assert task.queue_duration() == 60.0

    def test_queue_duration_started(self) -> None:
        """Test queue_duration when task has started."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
            started_at=1030.0,
            status=TaskStatus.EXECUTING,
        )

        # Queue duration should be fixed at 30 seconds
        assert task.queue_duration() == 30.0

    def test_execution_duration_not_started(self) -> None:
        """Test execution_duration returns None when not started."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
        )

        assert task.execution_duration() is None

    def test_execution_duration_in_progress(self) -> None:
        """Test execution_duration when task is running."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
            started_at=1030.0,
            status=TaskStatus.EXECUTING,
        )

        with patch("airut.dashboard.tracker.time.time", return_value=1090.0):
            assert task.execution_duration() == 60.0

    def test_execution_duration_completed(self) -> None:
        """Test execution_duration when task is completed."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
            started_at=1030.0,
            completed_at=1130.0,
            status=TaskStatus.COMPLETED,
            completion_reason=CompletionReason.SUCCESS,
        )

        # Should be fixed at 100 seconds
        assert task.execution_duration() == 100.0

    def test_total_duration_pending(self) -> None:
        """Test total_duration for pending task."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
        )

        with patch("airut.dashboard.tracker.time.time", return_value=1120.0):
            assert task.total_duration() == 120.0

    def test_total_duration_completed(self) -> None:
        """Test total_duration for completed task."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
            started_at=1030.0,
            completed_at=1130.0,
            status=TaskStatus.COMPLETED,
            completion_reason=CompletionReason.SUCCESS,
        )

        assert task.total_duration() == 130.0

    def test_is_terminal(self) -> None:
        """Test is_terminal property."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            status=TaskStatus.COMPLETED,
            completion_reason=CompletionReason.SUCCESS,
        )
        assert task.is_terminal is True

        task2 = TaskState(
            conversation_id="def",
            display_title="Test",
            status=TaskStatus.EXECUTING,
        )
        assert task2.is_terminal is False

    def test_succeeded(self) -> None:
        """Test succeeded property."""
        task = TaskState(
            conversation_id="abc",
            display_title="Test",
            completion_reason=CompletionReason.SUCCESS,
        )
        assert task.succeeded is True

        task2 = TaskState(
            conversation_id="def",
            display_title="Test",
            completion_reason=CompletionReason.EXECUTION_FAILED,
        )
        assert task2.succeeded is False

        task3 = TaskState(
            conversation_id="ghi",
            display_title="Test",
        )
        assert task3.succeeded is False


class TestTaskTracker:
    """Tests for TaskTracker class."""

    def test_add_task(self) -> None:
        """Test adding a new task."""
        tracker = TaskTracker()

        before = time.time()
        tracker.add_task("abc12345", "Test subject")
        after = time.time()

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.conversation_id == "abc12345"
        assert task.display_title == "Test subject"
        assert task.status == TaskStatus.QUEUED
        assert before <= task.queued_at <= after
        assert task.model is None

    def test_add_task_with_model(self) -> None:
        """Test adding a new task with model."""
        tracker = TaskTracker()

        tracker.add_task("abc12345", "Test subject", model="opus")

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.model == "opus"

    def test_add_task_with_repo_id_and_sender(self) -> None:
        """Test adding a task with repo_id and sender."""
        tracker = TaskTracker()
        tracker.add_task(
            "abc12345", "Test", repo_id="airut", sender="user@example.com"
        )
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.repo_id == "airut"
        assert task.sender == "user@example.com"

    def test_add_task_resume_updates_repo_id_and_sender(self) -> None:
        """Test resuming a task updates repo_id and sender."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.repo_id == ""
        assert task.sender == ""

        # Mark completed, then resume with repo_id/sender
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)
        tracker.add_task(
            "abc12345", "Test", repo_id="airut", sender="user@example.com"
        )
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.repo_id == "airut"
        assert task.sender == "user@example.com"

    def test_add_task_resume_existing(self) -> None:
        """Test adding a task that already exists (resume)."""
        tracker = TaskTracker()

        # First add
        tracker.add_task("abc12345", "First subject")
        task_initial = tracker.get_task("abc12345")
        assert task_initial is not None
        first_queued_at = task_initial.queued_at

        # Mark as completed
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        # Advance time to ensure queued_at differs on resume
        with patch(
            "airut.dashboard.tracker.time.time",
            return_value=first_queued_at + 1.0,
        ):
            # Resume (add again)
            tracker.add_task("abc12345", "First subject")

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.status == TaskStatus.QUEUED
        assert task.queued_at > first_queued_at
        assert task.started_at is None
        assert task.completed_at is None
        assert task.completion_reason is None
        assert task.message_count == 2

    def test_add_task_resume_with_model_update(self) -> None:
        """Test resuming a task updates model when provided."""
        tracker = TaskTracker()

        # First add with model
        tracker.add_task("abc12345", "First subject", model="sonnet")
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.model == "sonnet"

        # Mark as completed
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        # Resume with new model
        tracker.add_task("abc12345", "First subject", model="opus")

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.model == "opus"

    def test_add_task_resume_preserves_model_when_none(self) -> None:
        """Test resuming a task preserves model when not provided."""
        tracker = TaskTracker()

        # First add with model
        tracker.add_task("abc12345", "First subject", model="opus")
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.model == "opus"

        # Mark as completed
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        # Resume without specifying model
        tracker.add_task("abc12345", "First subject")

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.model == "opus"  # Preserved from original

    def test_set_authenticating(self) -> None:
        """Test transitioning a task to AUTHENTICATING."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        result = tracker.set_authenticating("abc12345")

        assert result is True
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.status == TaskStatus.AUTHENTICATING

    def test_set_authenticating_nonexistent(self) -> None:
        """Test set_authenticating on non-existent task returns False."""
        tracker = TaskTracker()
        assert tracker.set_authenticating("nonexistent") is False

    def test_set_authenticating_rejects_non_queued(self) -> None:
        """set_authenticating only works from QUEUED state."""
        tracker = TaskTracker()
        tracker.add_task("t", "T")
        tracker.set_authenticating("t")
        # Already AUTHENTICATING — can't transition again
        assert tracker.set_authenticating("t") is False

    def test_set_executing(self) -> None:
        """Test transitioning a task to EXECUTING."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")

        before = time.time()
        result = tracker.set_executing("abc12345")
        after = time.time()

        assert result is True
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.status == TaskStatus.EXECUTING
        assert task.started_at is not None
        assert before <= task.started_at <= after

    def test_set_executing_nonexistent(self) -> None:
        """Test set_executing on non-existent task returns False."""
        tracker = TaskTracker()
        assert tracker.set_executing("nonexistent") is False

    def test_set_executing_rejects_queued(self) -> None:
        """set_executing rejects tasks still in QUEUED state."""
        tracker = TaskTracker()
        tracker.add_task("t", "T")
        assert tracker.set_executing("t") is False
        task = tracker.get_task("t")
        assert task is not None
        assert task.status == TaskStatus.QUEUED

    def test_set_executing_rejects_completed(self) -> None:
        """set_executing rejects tasks in COMPLETED state."""
        tracker = TaskTracker()
        tracker.add_task("t", "T")
        tracker.set_authenticating("t")
        tracker.set_executing("t")
        tracker.complete_task("t", CompletionReason.SUCCESS)
        assert tracker.set_executing("t") is False

    def test_set_pending(self) -> None:
        """Test transitioning a task to PENDING."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")

        result = tracker.set_pending("abc12345")

        assert result is True
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.status == TaskStatus.PENDING

    def test_set_pending_nonexistent(self) -> None:
        """Test set_pending on non-existent task returns False."""
        tracker = TaskTracker()
        assert tracker.set_pending("nonexistent") is False

    def test_set_pending_rejects_queued(self) -> None:
        """set_pending only works from AUTHENTICATING state."""
        tracker = TaskTracker()
        tracker.add_task("t", "T")
        assert tracker.set_pending("t") is False
        task = tracker.get_task("t")
        assert task is not None
        assert task.status == TaskStatus.QUEUED

    def test_complete_task_success(self) -> None:
        """Test completing a task successfully."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")

        before = time.time()
        tracker.complete_task(
            "abc12345", CompletionReason.SUCCESS, message_count=3
        )
        after = time.time()

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.completed_at is not None
        assert before <= task.completed_at <= after
        assert task.completion_reason == CompletionReason.SUCCESS
        assert task.succeeded is True
        assert task.message_count == 3

    def test_complete_task_failure(self) -> None:
        """Test completing a task with failure."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.EXECUTION_FAILED)

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is False

    def test_complete_task_nonexistent(self) -> None:
        """Test completing a non-existent task returns False."""
        tracker = TaskTracker()
        result = tracker.complete_task("nonexistent", CompletionReason.SUCCESS)
        assert result is False

    def test_complete_task_from_queued_rejected(self) -> None:
        """Completing a QUEUED task is rejected (invalid transition)."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        result = tracker.complete_task("abc12345", CompletionReason.SUCCESS)
        assert result is False
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.status == TaskStatus.QUEUED

    def test_get_task_nonexistent(self) -> None:
        """Test getting a non-existent task returns None."""
        tracker = TaskTracker()
        assert tracker.get_task("nonexistent") is None

    def test_update_task_id_success(self) -> None:
        """Test updating a task ID successfully."""
        tracker = TaskTracker()
        tracker.add_task("new-12345678", "Test subject")
        tracker.set_authenticating("new-12345678")
        tracker.set_executing("new-12345678")

        result = tracker.update_task_id("new-12345678", "abc12345")

        assert result is True
        assert tracker.get_task("new-12345678") is None
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.conversation_id == "abc12345"
        assert task.display_title == "Test subject"
        assert task.status == TaskStatus.EXECUTING

    def test_update_task_id_old_not_found(self) -> None:
        """Test updating task ID when old ID doesn't exist."""
        tracker = TaskTracker()

        result = tracker.update_task_id("nonexistent", "abc12345")

        assert result is False

    def test_update_task_id_new_already_exists(self) -> None:
        """Test updating task ID when new ID already exists."""
        tracker = TaskTracker()
        tracker.add_task("old-id", "Old task")
        tracker.add_task("new-id", "New task")

        result = tracker.update_task_id("old-id", "new-id")

        assert result is False
        # Both tasks should still exist unchanged
        assert tracker.get_task("old-id") is not None
        assert tracker.get_task("new-id") is not None

    def test_reassign_task_simple_rename(self) -> None:
        """Test reassigning a temp task to a new conv_id (rename)."""
        tracker = TaskTracker()
        tracker.add_task("new-12345678", "Test subject", sender="user@ex.com")
        tracker.set_authenticating("new-12345678")
        tracker.set_executing("new-12345678")

        result = tracker.reassign_task("new-12345678", "abc12345")

        assert result is True
        assert tracker.get_task("new-12345678") is None
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.conversation_id == "abc12345"
        assert task.display_title == "Test subject"
        assert task.sender == "user@ex.com"
        assert task.status == TaskStatus.EXECUTING

    def test_reassign_task_merge_with_existing(self) -> None:
        """Test reassigning temp task to an existing completed conv_id."""
        tracker = TaskTracker()

        # Existing completed task
        tracker.add_task("abc12345", "Original subject", sender="old@ex.com")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)
        existing_task = tracker.get_task("abc12345")
        assert existing_task is not None
        original_msg_count = existing_task.message_count

        # New temp task (executing)
        tracker.add_task("new-temp", "Follow-up", sender="new@ex.com")
        tracker.set_authenticating("new-temp")
        tracker.set_executing("new-temp")

        result = tracker.reassign_task("new-temp", "abc12345")

        assert result is True
        assert tracker.get_task("new-temp") is None
        task = tracker.get_task("abc12345")
        assert task is not None
        # State should be transferred from temp task
        assert task.status == TaskStatus.EXECUTING
        assert task.display_title == "Follow-up"
        assert task.sender == "new@ex.com"
        assert task.completed_at is None
        assert task.completion_reason is None
        assert task.message_count == original_msg_count + 1

    def test_reassign_task_merge_transfers_model(self) -> None:
        """Test model is transferred from temp task during merge."""
        tracker = TaskTracker()

        tracker.add_task("abc12345", "Original")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        tracker.add_task("new-temp", "Follow-up", model="opus")
        tracker.set_authenticating("new-temp")
        tracker.set_executing("new-temp")

        tracker.reassign_task("new-temp", "abc12345")

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.model == "opus"

    def test_reassign_task_temp_not_found(self) -> None:
        """Test reassign returns False when temp_id doesn't exist."""
        tracker = TaskTracker()

        result = tracker.reassign_task("nonexistent", "abc12345")

        assert result is False

    def test_reassign_task_ticks_clock(self) -> None:
        """Test reassign_task ticks the version clock."""
        from airut.dashboard.versioned import VersionClock

        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        tracker.add_task("new-temp", "Test")
        version_before = clock.version

        tracker.reassign_task("new-temp", "abc12345")

        assert clock.version > version_before

    def test_update_task_display_title_success(self) -> None:
        """Test updating a task's display title."""
        tracker = TaskTracker()
        tracker.add_task("new-12345678", "(authenticating)")
        tracker.set_authenticating("new-12345678")
        tracker.set_executing("new-12345678")

        result = tracker.update_task_display_title(
            "new-12345678",
            "Fix the login bug",
            sender="user@example.com",
        )

        assert result is True
        task = tracker.get_task("new-12345678")
        assert task is not None
        assert task.display_title == "Fix the login bug"
        assert task.sender == "user@example.com"

    def test_update_task_display_title_without_sender(self) -> None:
        """Test updating display title without changing sender."""
        tracker = TaskTracker()
        tracker.add_task(
            "abc12345", "(authenticating)", sender="original@example.com"
        )

        result = tracker.update_task_display_title("abc12345", "New subject")

        assert result is True
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.display_title == "New subject"
        assert task.sender == "original@example.com"  # Preserved

    def test_update_task_display_title_nonexistent(self) -> None:
        """Test updating display title on non-existent task."""
        tracker = TaskTracker()

        result = tracker.update_task_display_title("nonexistent", "Subject")

        assert result is False

    def test_update_task_display_title_ticks_clock(self) -> None:
        """Test that update_task_display_title ticks the version clock."""
        from airut.dashboard.versioned import VersionClock

        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        tracker.add_task("abc12345", "(authenticating)")
        version_before = clock.version

        tracker.update_task_display_title("abc12345", "Real subject")

        assert clock.version > version_before

    def test_set_task_model_success(self) -> None:
        """Test setting model on an existing task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test subject")

        result = tracker.set_task_model("abc12345", "opus")

        assert result is True
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.model == "opus"

    def test_set_task_model_nonexistent(self) -> None:
        """Test setting model on non-existent task."""
        tracker = TaskTracker()

        result = tracker.set_task_model("nonexistent", "opus")

        assert result is False

    def test_is_task_active_queued(self) -> None:
        """Test is_task_active returns True for queued task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        assert tracker.is_task_active("abc12345") is True

    def test_is_task_active_executing(self) -> None:
        """Test is_task_active returns True for executing task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")

        assert tracker.is_task_active("abc12345") is True

    def test_is_task_active_authenticating(self) -> None:
        """Test is_task_active returns True for authenticating task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")

        assert tracker.is_task_active("abc12345") is True

    def test_is_task_active_pending(self) -> None:
        """Test is_task_active returns True for pending task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_pending("abc12345")

        assert tracker.is_task_active("abc12345") is True

    def test_is_task_active_completed(self) -> None:
        """Test is_task_active returns False for completed task."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        assert tracker.is_task_active("abc12345") is False

    def test_is_task_active_nonexistent(self) -> None:
        """Test is_task_active returns False for non-existent task."""
        tracker = TaskTracker()

        assert tracker.is_task_active("nonexistent") is False

    def test_get_all_tasks_sorted(self) -> None:
        """Test get_all_tasks returns tasks sorted by queued_at."""
        tracker = TaskTracker()

        # Add tasks with explicit timestamps to control ordering
        tracker._tasks["first"] = TaskState(
            conversation_id="first",
            display_title="First",
            queued_at=1000.0,
        )
        tracker._tasks["second"] = TaskState(
            conversation_id="second",
            display_title="Second",
            queued_at=2000.0,
        )
        tracker._tasks["middle"] = TaskState(
            conversation_id="middle",
            display_title="Middle",
            queued_at=1500.0,
        )

        tasks = tracker.get_all_tasks()
        assert len(tasks) == 3
        assert tasks[0].conversation_id == "second"
        assert tasks[1].conversation_id == "middle"
        assert tasks[2].conversation_id == "first"

    def test_get_tasks_by_status(self) -> None:
        """Test filtering tasks by status."""
        tracker = TaskTracker()

        # Add tasks in different states
        tracker.add_task("queued1", "Queued 1")
        tracker.add_task("queued2", "Queued 2")
        tracker.add_task("exec1", "Exec 1")
        tracker.set_authenticating("exec1")
        tracker.set_executing("exec1")
        tracker.add_task("done1", "Done 1")
        tracker.set_authenticating("done1")
        tracker.set_executing("done1")
        tracker.complete_task("done1", CompletionReason.SUCCESS)

        queued = tracker.get_tasks_by_status(TaskStatus.QUEUED)
        assert len(queued) == 2
        assert {t.conversation_id for t in queued} == {"queued1", "queued2"}

        executing = tracker.get_tasks_by_status(TaskStatus.EXECUTING)
        assert len(executing) == 1
        assert executing[0].conversation_id == "exec1"

        completed = tracker.get_tasks_by_status(TaskStatus.COMPLETED)
        assert len(completed) == 1
        assert completed[0].conversation_id == "done1"

    def test_get_counts(self) -> None:
        """Test getting task counts by status."""
        tracker = TaskTracker()

        tracker.add_task("q1", "Q1")
        tracker.add_task("q2", "Q2")
        tracker.add_task("p1", "P1")
        tracker.set_authenticating("p1")
        tracker.set_executing("p1")
        tracker.add_task("c1", "C1")
        tracker.set_authenticating("c1")
        tracker.set_executing("c1")
        tracker.complete_task("c1", CompletionReason.SUCCESS)

        counts = tracker.get_counts()
        assert counts == {
            "queued": 2,
            "authenticating": 0,
            "pending": 0,
            "executing": 1,
            "completed": 1,
        }

    def test_evict_old_completed(self) -> None:
        """Test eviction of old completed tasks."""
        tracker = TaskTracker(max_completed=3)

        # Add 5 tasks and complete them with explicit timestamps
        for i in range(5):
            tracker._tasks[f"task{i}"] = TaskState(
                conversation_id=f"task{i}",
                display_title=f"Task {i}",
                queued_at=1000.0 + i,
                started_at=1001.0 + i,
                completed_at=1002.0 + i,
                status=TaskStatus.COMPLETED,
                completion_reason=CompletionReason.SUCCESS,
            )
            tracker._evict_old_completed()

        # Should only have the 3 most recent completed
        tasks = tracker.get_all_tasks()
        assert len(tasks) == 3
        ids = {t.conversation_id for t in tasks}
        assert ids == {"task2", "task3", "task4"}

    def test_thread_safety(self) -> None:
        """Test tracker is thread-safe."""
        tracker = TaskTracker()
        errors: list[Exception] = []

        def worker(start_id: int) -> None:
            try:
                for i in range(10):
                    task_id = f"task{start_id}_{i}"
                    tracker.add_task(task_id, f"Subject {task_id}")
                    tracker.set_authenticating(task_id)
                    tracker.set_executing(task_id)
                    tracker.complete_task(task_id, CompletionReason.SUCCESS)
                    tracker.get_task(task_id)
                    tracker.get_all_tasks()
                    tracker.get_counts()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_wait_for_completion_already_completed(self) -> None:
        """Test wait_for_completion returns immediately if completed."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        task = tracker.wait_for_completion("abc12345", timeout=1.0)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is True

    def test_wait_for_completion_blocks_until_complete(self) -> None:
        """Test wait_for_completion blocks and returns on completion."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")

        def complete_later() -> None:
            time.sleep(0.1)
            tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        t = threading.Thread(target=complete_later)
        t.start()

        task = tracker.wait_for_completion("abc12345", timeout=5.0)
        t.join()

        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is True

    def test_wait_for_completion_timeout(self) -> None:
        """Test wait_for_completion returns on timeout."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")

        task = tracker.wait_for_completion("abc12345", timeout=0.1)
        assert task is not None
        assert task.status == TaskStatus.EXECUTING

    def test_wait_for_completion_nonexistent(self) -> None:
        """Test wait_for_completion returns None for non-existent task."""
        tracker = TaskTracker()

        task = tracker.wait_for_completion("nonexistent", timeout=0.1)
        assert task is None

    def test_get_snapshot(self) -> None:
        """Test get_snapshot returns versioned copy of all tasks."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.add_task("t2", "Task 2")
        tracker.set_authenticating("t2")
        tracker.set_executing("t2")

        snap = tracker.get_snapshot()
        assert snap.version > 0
        assert len(snap.value) == 2
        # Sorted newest first
        assert snap.value[0].conversation_id == "t2"
        assert snap.value[1].conversation_id == "t1"
        # Copies are independent of tracker state
        tracker.complete_task("t2", CompletionReason.SUCCESS)
        assert snap.value[0].status == TaskStatus.EXECUTING

    def test_get_snapshot_empty(self) -> None:
        """Test get_snapshot with no tasks."""
        tracker = TaskTracker()
        snap = tracker.get_snapshot()
        assert snap.version == 0
        assert snap.value == ()

    def test_get_snapshot_deep_copies_todos(self) -> None:
        """Test get_snapshot deep copies todos so mutations don't leak."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        todos = [TodoItem(content="Step 1", status=TodoStatus.PENDING)]
        tracker.update_todos("t1", todos)

        snap = tracker.get_snapshot()
        assert snap.value[0].todos == todos
        # Mutate the original list — snapshot should be unaffected
        todos.append(TodoItem(content="Step 2", status=TodoStatus.PENDING))
        assert snap.value[0].todos is not None
        assert len(snap.value[0].todos) == 1

    def test_update_todos_success(self) -> None:
        """Test updating todos on an existing task."""
        from airut.dashboard.versioned import VersionClock

        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        tracker.add_task("abc12345", "Test")
        version_before = clock.version

        todos = [
            TodoItem(content="Run tests", status=TodoStatus.IN_PROGRESS),
            TodoItem(content="Fix bugs", status=TodoStatus.PENDING),
        ]
        result = tracker.update_todos("abc12345", todos)

        assert result is True
        assert clock.version > version_before
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos == todos

    def test_update_todos_nonexistent(self) -> None:
        """Test updating todos on non-existent task returns False."""
        tracker = TaskTracker()
        result = tracker.update_todos(
            "nonexistent",
            [TodoItem(content="X", status=TodoStatus.PENDING)],
        )
        assert result is False

    def test_update_todos_replaces_previous(self) -> None:
        """Test updating todos replaces the previous list."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.update_todos(
            "abc12345",
            [TodoItem(content="A", status=TodoStatus.PENDING)],
        )
        tracker.update_todos(
            "abc12345",
            [TodoItem(content="B", status=TodoStatus.COMPLETED)],
        )
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is not None
        assert len(task.todos) == 1
        assert task.todos[0].content == "B"

    def test_task_state_todos_default_none(self) -> None:
        """Test TaskState.todos defaults to None."""
        task = TaskState(conversation_id="abc", display_title="Test")
        assert task.todos is None

    def test_complete_task_clears_todos(self) -> None:
        """Test that completing a task clears its todos."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.update_todos(
            "abc12345",
            [TodoItem(content="Step 1", status=TodoStatus.IN_PROGRESS)],
        )

        # Verify todos are set
        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is not None

        tracker.complete_task("abc12345", CompletionReason.SUCCESS)

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is None

    def test_complete_task_failure_clears_todos(self) -> None:
        """Test that a failed task also clears its todos."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.update_todos(
            "abc12345",
            [
                TodoItem(content="A", status=TodoStatus.COMPLETED),
                TodoItem(content="B", status=TodoStatus.IN_PROGRESS),
            ],
        )

        tracker.complete_task("abc12345", CompletionReason.EXECUTION_FAILED)

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is None

    def test_complete_task_with_detail(self) -> None:
        """Test completing a task with a detail string."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.set_authenticating("abc12345")
        tracker.set_executing("abc12345")
        tracker.complete_task(
            "abc12345",
            CompletionReason.TIMEOUT,
            detail="timeout after 300s",
        )

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.completion_reason == CompletionReason.TIMEOUT
        assert task.completion_detail == "timeout after 300s"


class TestTodoItem:
    """Tests for TodoItem dataclass."""

    def test_default_active_form(self) -> None:
        """Test active_form defaults to empty string."""
        item = TodoItem(content="Run tests", status=TodoStatus.PENDING)
        assert item.active_form == ""

    def test_to_dict(self) -> None:
        """Test to_dict serialization."""
        item = TodoItem(
            content="Run tests",
            status=TodoStatus.IN_PROGRESS,
            active_form="Running tests",
        )
        d = item.to_dict()
        assert d == {
            "content": "Run tests",
            "status": "in_progress",
            "activeForm": "Running tests",
        }

    def test_to_dict_active_form_defaults_to_content(self) -> None:
        """Test to_dict uses content when active_form is empty."""
        item = TodoItem(content="Deploy", status=TodoStatus.PENDING)
        d = item.to_dict()
        assert d["activeForm"] == "Deploy"

    def test_immutable(self) -> None:
        """Test TodoItem is frozen (immutable)."""
        item = TodoItem(content="Test", status=TodoStatus.PENDING)
        with pytest.raises(AttributeError):
            item.content = "Changed"  # type: ignore[misc]


class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_status_values(self) -> None:
        """Test TaskStatus has expected values."""
        assert TaskStatus.QUEUED.value == "queued"
        assert TaskStatus.AUTHENTICATING.value == "authenticating"
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.EXECUTING.value == "executing"
        assert TaskStatus.COMPLETED.value == "completed"


class TestCompletionReason:
    """Tests for CompletionReason enum."""

    def test_reason_values(self) -> None:
        """Test CompletionReason has expected values."""
        assert CompletionReason.SUCCESS.value == "success"
        assert CompletionReason.AUTH_FAILED.value == "auth_failed"
        assert CompletionReason.UNAUTHORIZED.value == "unauthorized"
        assert CompletionReason.EXECUTION_FAILED.value == "execution_failed"
        assert CompletionReason.TIMEOUT.value == "timeout"
        assert CompletionReason.INTERNAL_ERROR.value == "internal_error"
        assert CompletionReason.REJECTED.value == "rejected"
