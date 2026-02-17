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
            task_id="t1", conversation_id="abc12345", display_title="Test"
        )
        after = time.time()

        assert task.task_id == "t1"
        assert task.conversation_id == "abc12345"
        assert task.display_title == "Test"
        assert task.status == TaskStatus.QUEUED
        assert before <= task.queued_at <= after
        assert task.started_at is None
        assert task.completed_at is None
        assert task.completion_reason is None
        assert task.model is None

    def test_with_model(self) -> None:
        """Test TaskState with model specified."""
        task = TaskState(
            task_id="t1",
            conversation_id="abc12345",
            display_title="Test",
            model="opus",
        )
        assert task.model == "opus"

    def test_queue_duration_not_started(self) -> None:
        """Test queue_duration when task hasn't started."""
        task = TaskState(
            task_id="t1",
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
        )
        with patch("airut.dashboard.tracker.time.time", return_value=1060.0):
            assert task.queue_duration() == 60.0

    def test_queue_duration_started(self) -> None:
        """Test queue_duration when task has started."""
        task = TaskState(
            task_id="t1",
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
            started_at=1030.0,
            status=TaskStatus.EXECUTING,
        )
        assert task.queue_duration() == 30.0

    def test_execution_duration_not_started(self) -> None:
        """Test execution_duration returns None when not started."""
        task = TaskState(
            task_id="t1",
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
        )
        assert task.execution_duration() is None

    def test_execution_duration_in_progress(self) -> None:
        """Test execution_duration when task is running."""
        task = TaskState(
            task_id="t1",
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
            task_id="t1",
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
            started_at=1030.0,
            completed_at=1130.0,
            status=TaskStatus.COMPLETED,
            completion_reason=CompletionReason.SUCCESS,
        )
        assert task.execution_duration() == 100.0

    def test_total_duration_pending(self) -> None:
        """Test total_duration for pending task."""
        task = TaskState(
            task_id="t1",
            conversation_id="abc",
            display_title="Test",
            queued_at=1000.0,
        )
        with patch("airut.dashboard.tracker.time.time", return_value=1120.0):
            assert task.total_duration() == 120.0

    def test_total_duration_completed(self) -> None:
        """Test total_duration for completed task."""
        task = TaskState(
            task_id="t1",
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
            task_id="t1",
            conversation_id="abc",
            display_title="Test",
            status=TaskStatus.COMPLETED,
            completion_reason=CompletionReason.SUCCESS,
        )
        assert task.is_terminal is True

        task2 = TaskState(
            task_id="t2",
            conversation_id="def",
            display_title="Test",
            status=TaskStatus.EXECUTING,
        )
        assert task2.is_terminal is False

    def test_succeeded(self) -> None:
        """Test succeeded property."""
        task = TaskState(
            task_id="t1",
            conversation_id="abc",
            display_title="Test",
            completion_reason=CompletionReason.SUCCESS,
        )
        assert task.succeeded is True

        task2 = TaskState(
            task_id="t2",
            conversation_id="def",
            display_title="Test",
            completion_reason=CompletionReason.EXECUTION_FAILED,
        )
        assert task2.succeeded is False

        task3 = TaskState(
            task_id="t3",
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
        tracker.add_task("task-001", "Test subject")
        after = time.time()

        task = tracker.get_task("task-001")
        assert task is not None
        assert task.task_id == "task-001"
        assert task.conversation_id == ""
        assert task.display_title == "Test subject"
        assert task.status == TaskStatus.QUEUED
        assert before <= task.queued_at <= after
        assert task.model is None

    def test_add_task_with_model(self) -> None:
        """Test adding a new task with model."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test subject", model="opus")

        task = tracker.get_task("task-001")
        assert task is not None
        assert task.model == "opus"

    def test_add_task_with_repo_id_and_sender(self) -> None:
        """Test adding a task with repo_id and sender."""
        tracker = TaskTracker()
        tracker.add_task(
            "task-001", "Test", repo_id="airut", sender="user@example.com"
        )
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.repo_id == "airut"
        assert task.sender == "user@example.com"

    def test_set_conversation_id(self) -> None:
        """Test assigning a conversation ID to a task."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test subject")

        result = tracker.set_conversation_id("task-001", "abc12345")

        assert result is True
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.task_id == "task-001"
        assert task.conversation_id == "abc12345"

    def test_set_conversation_id_nonexistent(self) -> None:
        """Test set_conversation_id returns False for missing task."""
        tracker = TaskTracker()
        result = tracker.set_conversation_id("nonexistent", "abc12345")
        assert result is False

    def test_set_conversation_id_ticks_clock(self) -> None:
        """Test set_conversation_id ticks the version clock."""
        from airut.dashboard.versioned import VersionClock

        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        tracker.add_task("task-001", "Test")
        version_before = clock.version

        tracker.set_conversation_id("task-001", "abc12345")

        assert clock.version > version_before

    def test_set_authenticating(self) -> None:
        """Test transitioning a task to AUTHENTICATING."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")

        result = tracker.set_authenticating("task-001")

        assert result is True
        task = tracker.get_task("task-001")
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
        assert tracker.set_authenticating("t") is False

    def test_set_executing(self) -> None:
        """Test transitioning a task to EXECUTING."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")

        before = time.time()
        result = tracker.set_executing("task-001")
        after = time.time()

        assert result is True
        task = tracker.get_task("task-001")
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

    def test_set_executing_from_pending(self) -> None:
        """Test transitioning from PENDING to EXECUTING."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_pending("task-001")

        result = tracker.set_executing("task-001")

        assert result is True
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.status == TaskStatus.EXECUTING

    def test_set_pending(self) -> None:
        """Test transitioning a task to PENDING."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")

        result = tracker.set_pending("task-001")

        assert result is True
        task = tracker.get_task("task-001")
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
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")

        before = time.time()
        tracker.complete_task("task-001", CompletionReason.SUCCESS)
        after = time.time()

        task = tracker.get_task("task-001")
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.completed_at is not None
        assert before <= task.completed_at <= after
        assert task.completion_reason == CompletionReason.SUCCESS
        assert task.succeeded is True

    def test_complete_task_failure(self) -> None:
        """Test completing a task with failure."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")
        tracker.complete_task("task-001", CompletionReason.EXECUTION_FAILED)

        task = tracker.get_task("task-001")
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
        tracker.add_task("task-001", "Test")
        result = tracker.complete_task("task-001", CompletionReason.SUCCESS)
        assert result is False
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.status == TaskStatus.QUEUED

    def test_get_task_nonexistent(self) -> None:
        """Test getting a non-existent task returns None."""
        tracker = TaskTracker()
        assert tracker.get_task("nonexistent") is None

    def test_get_task_by_task_id_not_conversation_id(self) -> None:
        """Test that get_task uses task_id, not conversation_id."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_conversation_id("task-001", "abc12345")

        # Can find by task_id
        assert tracker.get_task("task-001") is not None
        # Cannot find by conversation_id
        assert tracker.get_task("abc12345") is None

    def test_has_active_task_with_active_task(self) -> None:
        """Test has_active_task returns True when active task exists."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_conversation_id("task-001", "conv-1")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")

        assert tracker.has_active_task("conv-1") is True

    def test_has_active_task_with_completed_task(self) -> None:
        """Test has_active_task returns False when all tasks completed."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_conversation_id("task-001", "conv-1")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")
        tracker.complete_task("task-001", CompletionReason.SUCCESS)

        assert tracker.has_active_task("conv-1") is False

    def test_has_active_task_nonexistent(self) -> None:
        """Test has_active_task returns False for unknown conversation."""
        tracker = TaskTracker()
        assert tracker.has_active_task("nonexistent") is False

    def test_has_active_task_pending(self) -> None:
        """Test has_active_task returns True for pending task."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_conversation_id("task-001", "conv-1")
        tracker.set_authenticating("task-001")
        tracker.set_pending("task-001")

        assert tracker.has_active_task("conv-1") is True

    def test_has_active_task_multiple_tasks(self) -> None:
        """Test has_active_task with mixed completed and active tasks."""
        tracker = TaskTracker()
        # First task: completed
        tracker.add_task("task-001", "First")
        tracker.set_conversation_id("task-001", "conv-1")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")
        tracker.complete_task("task-001", CompletionReason.SUCCESS)

        # Second task: executing
        tracker.add_task("task-002", "Second")
        tracker.set_conversation_id("task-002", "conv-1")
        tracker.set_authenticating("task-002")
        tracker.set_executing("task-002")

        assert tracker.has_active_task("conv-1") is True

    def test_get_tasks_for_conversation(self) -> None:
        """Test getting all tasks for a conversation."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "First")
        tracker.set_conversation_id("task-001", "conv-1")
        tracker.add_task("task-002", "Second")
        tracker.set_conversation_id("task-002", "conv-1")
        tracker.add_task("task-003", "Other conv")
        tracker.set_conversation_id("task-003", "conv-2")

        tasks = tracker.get_tasks_for_conversation("conv-1")
        assert len(tasks) == 2
        task_ids = {t.task_id for t in tasks}
        assert task_ids == {"task-001", "task-002"}

    def test_get_tasks_for_conversation_empty(self) -> None:
        """Test getting tasks for unknown conversation returns empty."""
        tracker = TaskTracker()
        assert tracker.get_tasks_for_conversation("unknown") == []

    def test_get_tasks_for_conversation_newest_first(self) -> None:
        """Test tasks are sorted newest first."""
        tracker = TaskTracker()
        tracker._tasks["t1"] = TaskState(
            task_id="t1",
            conversation_id="conv-1",
            display_title="First",
            queued_at=1000.0,
        )
        tracker._tasks["t2"] = TaskState(
            task_id="t2",
            conversation_id="conv-1",
            display_title="Second",
            queued_at=2000.0,
        )

        tasks = tracker.get_tasks_for_conversation("conv-1")
        assert tasks[0].task_id == "t2"
        assert tasks[1].task_id == "t1"

    def test_has_active_task_empty_string(self) -> None:
        """Empty conversation_id must not match unassigned tasks."""
        tracker = TaskTracker()
        # Create a task with conversation_id="" (not yet assigned)
        tracker.add_task("task-001", "Unassigned")
        assert tracker.has_active_task("") is False

    def test_get_tasks_for_conversation_empty_string(self) -> None:
        """Empty conversation_id must not match unassigned tasks."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Unassigned")
        assert tracker.get_tasks_for_conversation("") == []

    def test_update_task_display_title_success(self) -> None:
        """Test updating a task's display title."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "(authenticating)")
        tracker.set_authenticating("task-001")

        result = tracker.update_task_display_title(
            "task-001",
            "Fix the login bug",
            sender="user@example.com",
        )

        assert result is True
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.display_title == "Fix the login bug"
        assert task.sender == "user@example.com"

    def test_update_task_display_title_with_authenticated_sender(self) -> None:
        """Test updating display title with authenticated sender."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "(authenticating)")

        result = tracker.update_task_display_title(
            "task-001",
            "Subject",
            sender="user@example.com",
            authenticated_sender="user@example.com",
        )

        assert result is True
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.authenticated_sender == "user@example.com"

    def test_update_task_display_title_without_sender(self) -> None:
        """Test updating display title without changing sender."""
        tracker = TaskTracker()
        tracker.add_task(
            "task-001", "(authenticating)", sender="original@example.com"
        )

        result = tracker.update_task_display_title("task-001", "New subject")

        assert result is True
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.display_title == "New subject"
        assert task.sender == "original@example.com"

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
        tracker.add_task("task-001", "(authenticating)")
        version_before = clock.version

        tracker.update_task_display_title("task-001", "Real subject")

        assert clock.version > version_before

    def test_set_task_model_success(self) -> None:
        """Test setting model on an existing task."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test subject")

        result = tracker.set_task_model("task-001", "opus")

        assert result is True
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.model == "opus"

    def test_set_task_model_nonexistent(self) -> None:
        """Test setting model on non-existent task."""
        tracker = TaskTracker()
        result = tracker.set_task_model("nonexistent", "opus")
        assert result is False

    def test_get_all_tasks_sorted(self) -> None:
        """Test get_all_tasks returns tasks sorted by queued_at."""
        tracker = TaskTracker()

        tracker._tasks["first"] = TaskState(
            task_id="first",
            conversation_id="c1",
            display_title="First",
            queued_at=1000.0,
        )
        tracker._tasks["second"] = TaskState(
            task_id="second",
            conversation_id="c2",
            display_title="Second",
            queued_at=2000.0,
        )
        tracker._tasks["middle"] = TaskState(
            task_id="middle",
            conversation_id="c3",
            display_title="Middle",
            queued_at=1500.0,
        )

        tasks = tracker.get_all_tasks()
        assert len(tasks) == 3
        assert tasks[0].task_id == "second"
        assert tasks[1].task_id == "middle"
        assert tasks[2].task_id == "first"

    def test_get_tasks_by_status(self) -> None:
        """Test filtering tasks by status."""
        tracker = TaskTracker()

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
        assert {t.task_id for t in queued} == {"queued1", "queued2"}

        executing = tracker.get_tasks_by_status(TaskStatus.EXECUTING)
        assert len(executing) == 1
        assert executing[0].task_id == "exec1"

        completed = tracker.get_tasks_by_status(TaskStatus.COMPLETED)
        assert len(completed) == 1
        assert completed[0].task_id == "done1"

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

    def test_get_counts_shows_executing_and_pending(self) -> None:
        """Test counts correctly shows executing+pending for same conv."""
        tracker = TaskTracker()

        # First task: executing
        tracker.add_task("task-001", "First")
        tracker.set_conversation_id("task-001", "conv-1")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")

        # Second task: pending for same conversation
        tracker.add_task("task-002", "Second")
        tracker.set_conversation_id("task-002", "conv-1")
        tracker.set_authenticating("task-002")
        tracker.set_pending("task-002")

        counts = tracker.get_counts()
        assert counts["executing"] == 1
        assert counts["pending"] == 1

    def test_evict_old_completed(self) -> None:
        """Test eviction of old completed tasks."""
        tracker = TaskTracker(max_completed=3)

        for i in range(5):
            tracker._tasks[f"task{i}"] = TaskState(
                task_id=f"task{i}",
                conversation_id=f"conv{i}",
                display_title=f"Task {i}",
                queued_at=1000.0 + i,
                started_at=1001.0 + i,
                completed_at=1002.0 + i,
                status=TaskStatus.COMPLETED,
                completion_reason=CompletionReason.SUCCESS,
            )
            tracker._evict_old_completed()

        tasks = tracker.get_all_tasks()
        assert len(tasks) == 3
        ids = {t.task_id for t in tasks}
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
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")
        tracker.complete_task("task-001", CompletionReason.SUCCESS)

        task = tracker.wait_for_completion("task-001", timeout=1.0)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is True

    def test_wait_for_completion_blocks_until_complete(self) -> None:
        """Test wait_for_completion blocks and returns on completion."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")

        def complete_later() -> None:
            time.sleep(0.1)
            tracker.complete_task("task-001", CompletionReason.SUCCESS)

        t = threading.Thread(target=complete_later)
        t.start()

        task = tracker.wait_for_completion("task-001", timeout=5.0)
        t.join()

        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is True

    def test_wait_for_completion_timeout(self) -> None:
        """Test wait_for_completion returns on timeout."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")

        task = tracker.wait_for_completion("task-001", timeout=0.1)
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
        assert snap.value[0].task_id == "t2"
        assert snap.value[1].task_id == "t1"
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
        tracker.add_task("task-001", "Test")
        version_before = clock.version

        todos = [
            TodoItem(content="Run tests", status=TodoStatus.IN_PROGRESS),
            TodoItem(content="Fix bugs", status=TodoStatus.PENDING),
        ]
        result = tracker.update_todos("task-001", todos)

        assert result is True
        assert clock.version > version_before
        task = tracker.get_task("task-001")
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
        tracker.add_task("task-001", "Test")
        tracker.update_todos(
            "task-001",
            [TodoItem(content="A", status=TodoStatus.PENDING)],
        )
        tracker.update_todos(
            "task-001",
            [TodoItem(content="B", status=TodoStatus.COMPLETED)],
        )
        task = tracker.get_task("task-001")
        assert task is not None
        assert task.todos is not None
        assert len(task.todos) == 1
        assert task.todos[0].content == "B"

    def test_task_state_todos_default_none(self) -> None:
        """Test TaskState.todos defaults to None."""
        task = TaskState(task_id="t1", conversation_id="abc", display_title="T")
        assert task.todos is None

    def test_complete_task_clears_todos(self) -> None:
        """Test that completing a task clears its todos."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")
        tracker.update_todos(
            "task-001",
            [TodoItem(content="Step 1", status=TodoStatus.IN_PROGRESS)],
        )

        task = tracker.get_task("task-001")
        assert task is not None
        assert task.todos is not None

        tracker.complete_task("task-001", CompletionReason.SUCCESS)

        task = tracker.get_task("task-001")
        assert task is not None
        assert task.todos is None

    def test_complete_task_failure_clears_todos(self) -> None:
        """Test that a failed task also clears its todos."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")
        tracker.update_todos(
            "task-001",
            [
                TodoItem(content="A", status=TodoStatus.COMPLETED),
                TodoItem(content="B", status=TodoStatus.IN_PROGRESS),
            ],
        )

        tracker.complete_task("task-001", CompletionReason.EXECUTION_FAILED)

        task = tracker.get_task("task-001")
        assert task is not None
        assert task.todos is None

    def test_complete_task_with_detail(self) -> None:
        """Test completing a task with a detail string."""
        tracker = TaskTracker()
        tracker.add_task("task-001", "Test")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")
        tracker.complete_task(
            "task-001",
            CompletionReason.TIMEOUT,
            detail="timeout after 300s",
        )

        task = tracker.get_task("task-001")
        assert task is not None
        assert task.completion_reason == CompletionReason.TIMEOUT
        assert task.completion_detail == "timeout after 300s"

    def test_one_task_per_message(self) -> None:
        """Test each message creates its own task entry."""
        tracker = TaskTracker()

        # First message
        tracker.add_task("task-001", "First message")
        tracker.set_conversation_id("task-001", "conv-1")
        tracker.set_authenticating("task-001")
        tracker.set_executing("task-001")

        # Second message while first is executing
        tracker.add_task("task-002", "Second message")
        tracker.set_conversation_id("task-002", "conv-1")
        tracker.set_authenticating("task-002")
        tracker.set_pending("task-002")

        # Both tasks exist independently
        t1 = tracker.get_task("task-001")
        t2 = tracker.get_task("task-002")
        assert t1 is not None
        assert t2 is not None
        assert t1.status == TaskStatus.EXECUTING
        assert t2.status == TaskStatus.PENDING
        assert t1.conversation_id == "conv-1"
        assert t2.conversation_id == "conv-1"


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
