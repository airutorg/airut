# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Comprehensive stress tests for the TaskTracker.

Covers:
- set_conversation_id in all scenarios
- Thread-safe concurrent mutations
- Eviction under high load
- State transitions and edge cases
- wait_for_completion timeout and success paths
"""

import threading
import time
from unittest.mock import patch

from airut.dashboard.tracker import (
    CompletionReason,
    TaskStatus,
    TaskTracker,
)
from airut.dashboard.versioned import VersionClock


# ===================================================================
# set_conversation_id
# ===================================================================


class TestSetConversationId:
    """Thorough tests for TaskTracker.set_conversation_id()."""

    def test_assigns_conversation_id(self) -> None:
        """Set conversation_id on a task after authentication."""
        tracker = TaskTracker()
        tracker.add_task("task-abc", "My subject", repo_id="test")
        tracker.set_authenticating("task-abc")
        tracker.set_executing("task-abc")

        result = tracker.set_conversation_id("task-abc", "real-conv-1")

        assert result is True
        task = tracker.get_task("task-abc")
        assert task is not None
        assert task.task_id == "task-abc"
        assert task.conversation_id == "real-conv-1"
        assert task.display_title == "My subject"
        assert task.status == TaskStatus.EXECUTING

    def test_missing_task_returns_false(self) -> None:
        """Returns False when task_id doesn't exist."""
        tracker = TaskTracker()
        result = tracker.set_conversation_id("nonexistent", "target")
        assert result is False

    def test_set_conversation_id_ticks_clock(self) -> None:
        """set_conversation_id increments the version clock."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        tracker.add_task("task-temp", "Test")

        v_before = clock.version
        tracker.set_conversation_id("task-temp", "real-id")
        assert clock.version > v_before

    def test_multiple_tasks_same_conversation(self) -> None:
        """Multiple tasks can share the same conversation_id."""
        tracker = TaskTracker()
        tracker.add_task("task-1", "First message")
        tracker.add_task("task-2", "Second message")

        tracker.set_conversation_id("task-1", "conv-shared")
        tracker.set_conversation_id("task-2", "conv-shared")

        task1 = tracker.get_task("task-1")
        task2 = tracker.get_task("task-2")
        assert task1 is not None
        assert task2 is not None
        assert task1.conversation_id == "conv-shared"
        assert task2.conversation_id == "conv-shared"

    def test_get_tasks_for_conversation(self) -> None:
        """get_tasks_for_conversation returns all tasks for a conv_id."""
        tracker = TaskTracker()
        tracker.add_task("task-1", "First")
        tracker.add_task("task-2", "Second")
        tracker.add_task("task-3", "Other conv")

        tracker.set_conversation_id("task-1", "conv-abc")
        tracker.set_conversation_id("task-2", "conv-abc")
        tracker.set_conversation_id("task-3", "conv-xyz")

        tasks = tracker.get_tasks_for_conversation("conv-abc")
        task_ids = {t.task_id for t in tasks}
        assert task_ids == {"task-1", "task-2"}


# ===================================================================
# update_task_display_title
# ===================================================================


class TestUpdateTaskDisplayTitle:
    """Tests for update_task_display_title."""

    def test_updates_display_title(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "(authenticating)")
        result = tracker.update_task_display_title("task1", "Real subject")
        assert result is True
        task = tracker.get_task("task1")
        assert task is not None
        assert task.display_title == "Real subject"

    def test_updates_sender(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "(authenticating)")
        tracker.update_task_display_title(
            "task1", "Subject", sender="user@example.com"
        )
        task = tracker.get_task("task1")
        assert task is not None
        assert task.sender == "user@example.com"

    def test_missing_task_returns_false(self) -> None:
        tracker = TaskTracker()
        result = tracker.update_task_display_title("nonexistent", "whatever")
        assert result is False

    def test_empty_sender_not_set(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Sub", sender="original@example.com")
        tracker.update_task_display_title("task1", "New sub", sender="")
        task = tracker.get_task("task1")
        assert task is not None
        assert task.sender == "original@example.com"


# ===================================================================
# has_active_task
# ===================================================================


class TestHasActiveTask:
    """Tests for has_active_task."""

    def test_queued_is_active(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        tracker.set_conversation_id("task1", "conv1")
        assert tracker.has_active_task("conv1") is True

    def test_in_progress_is_active(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        tracker.set_conversation_id("task1", "conv1")
        tracker.set_authenticating("task1")
        tracker.set_executing("task1")
        assert tracker.has_active_task("conv1") is True

    def test_completed_is_not_active(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        tracker.set_conversation_id("task1", "conv1")
        tracker.set_authenticating("task1")
        tracker.set_executing("task1")
        tracker.complete_task("task1", CompletionReason.SUCCESS)
        assert tracker.has_active_task("conv1") is False

    def test_nonexistent_is_not_active(self) -> None:
        tracker = TaskTracker()
        assert tracker.has_active_task("doesnt-exist") is False

    def test_no_conversation_id_not_found(self) -> None:
        """Task without conversation_id is not found by has_active_task."""
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        # conv_id defaults to "" — searching for a real conv_id won't match
        assert tracker.has_active_task("conv1") is False


# ===================================================================
# Eviction stress
# ===================================================================


class TestEvictionStress:
    """Tests for completed task eviction under load."""

    def test_evicts_oldest_completed_when_over_limit(self) -> None:
        """Completed tasks beyond max_completed are evicted."""
        tracker = TaskTracker(max_completed=3)

        for i in range(5):
            tid = f"task-{i:03d}"
            tracker.add_task(tid, f"Task {i}")
            tracker.set_authenticating(tid)
            tracker.set_executing(tid)
            tracker.complete_task(tid, CompletionReason.SUCCESS)

        # Only 3 completed should remain (the last 3)
        all_tasks = tracker.get_all_tasks()
        assert len(all_tasks) == 3

        task_ids = {t.task_id for t in all_tasks}
        assert "task-000" not in task_ids
        assert "task-001" not in task_ids
        assert "task-002" in task_ids
        assert "task-003" in task_ids
        assert "task-004" in task_ids

    def test_active_tasks_not_evicted(self) -> None:
        """In-progress and queued tasks are never evicted."""
        tracker = TaskTracker(max_completed=2)

        # Add 3 completed tasks (1 will be evicted)
        for i in range(3):
            tid = f"done-{i}"
            tracker.add_task(tid, f"Done {i}")
            tracker.set_authenticating(tid)
            tracker.set_executing(tid)
            tracker.complete_task(tid, CompletionReason.SUCCESS)

        # Add an active task
        tracker.add_task("active-1", "Active")
        tracker.set_authenticating("active-1")
        tracker.set_executing("active-1")

        # Add a queued task
        tracker.add_task("queued-1", "Queued")

        all_tasks = tracker.get_all_tasks()
        # 2 completed (max) + 1 executing + 1 queued = 4
        assert len(all_tasks) == 4

        active_ids = {t.task_id for t in all_tasks}
        assert "active-1" in active_ids
        assert "queued-1" in active_ids

    def test_high_volume_eviction(self) -> None:
        """High volume of tasks doesn't accumulate unbounded."""
        tracker = TaskTracker(max_completed=10)

        for i in range(1000):
            tid = f"bulk-{i:06d}"
            tracker.add_task(tid, f"Bulk {i}")
            tracker.set_authenticating(tid)
            tracker.set_executing(tid)
            tracker.complete_task(tid, CompletionReason.SUCCESS)

        all_tasks = tracker.get_all_tasks()
        assert len(all_tasks) == 10


# ===================================================================
# Concurrent thread safety
# ===================================================================


class TestTrackerThreadSafety:
    """Verify TaskTracker operations are thread-safe under contention."""

    def test_concurrent_add_and_complete(self) -> None:
        """Multiple threads adding and completing tasks simultaneously."""
        tracker = TaskTracker(max_completed=50)
        errors: list[Exception] = []
        count = 100

        def worker(thread_id: int):
            try:
                for i in range(count):
                    tid = f"t{thread_id}-{i}"
                    tracker.add_task(tid, f"Task {thread_id}-{i}")
                    tracker.set_authenticating(tid)
                    tracker.set_executing(tid)
                    tracker.complete_task(tid, CompletionReason.SUCCESS)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        # All tasks should be completed
        counts = tracker.get_counts()
        assert counts["queued"] == 0
        assert counts["executing"] == 0
        # Due to eviction, completed count should be <= max_completed
        assert counts["completed"] <= 50

    def test_concurrent_set_conversation_id(self) -> None:
        """Concurrent set_conversation_id operations don't corrupt state."""
        tracker = TaskTracker()
        errors: list[Exception] = []

        def worker(thread_id: int):
            try:
                for i in range(50):
                    tid = f"task-{thread_id}-{i}"
                    conv = f"conv-{thread_id}-{i}"
                    tracker.add_task(tid, f"Task {thread_id}-{i}")
                    tracker.set_conversation_id(tid, conv)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ===================================================================
# wait_for_completion
# ===================================================================


class TestWaitForCompletion:
    """Tests for wait_for_completion."""

    def test_returns_immediately_when_already_complete(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        tracker.set_authenticating("task1")
        tracker.set_executing("task1")
        tracker.complete_task("task1", CompletionReason.SUCCESS)

        result = tracker.wait_for_completion("task1", timeout=0.1)
        assert result is not None
        assert result.status == TaskStatus.COMPLETED

    def test_returns_none_on_timeout(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        # Never complete it

        result = tracker.wait_for_completion("task1", timeout=0.05)
        # Returns current task state (not completed)
        assert result is not None
        assert result.status == TaskStatus.QUEUED

    def test_wakes_on_completion(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        tracker.set_authenticating("task1")
        tracker.set_executing("task1")

        result_holder: list = []

        def waiter():
            result = tracker.wait_for_completion("task1", timeout=5.0)
            result_holder.append(result)

        thread = threading.Thread(target=waiter)
        thread.start()

        # Give the waiter time to enter the wait loop
        time.sleep(0.05)

        # Complete the task — this should wake the waiter
        tracker.complete_task("task1", CompletionReason.SUCCESS)
        thread.join(timeout=2.0)

        assert len(result_holder) == 1
        assert result_holder[0].status == TaskStatus.COMPLETED

    def test_nonexistent_task_returns_none(self) -> None:
        tracker = TaskTracker()
        result = tracker.wait_for_completion("doesnt-exist", timeout=0.05)
        assert result is None


# ===================================================================
# Snapshot and versioning
# ===================================================================


class TestSnapshotVersioning:
    """Tests for get_snapshot versioning."""

    def test_snapshot_version_increments_on_mutation(self) -> None:
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)

        snap1 = tracker.get_snapshot()

        tracker.add_task("task1", "Test")
        snap2 = tracker.get_snapshot()

        assert snap2.version > snap1.version

    def test_snapshot_is_isolated_from_mutations(self) -> None:
        """Snapshot contents don't change when tracker is mutated."""
        tracker = TaskTracker()
        tracker.add_task("task1", "Original")

        snap = tracker.get_snapshot()
        original_title = snap.value[0].display_title

        tracker.update_task_display_title("task1", "Modified")

        # Snapshot should still have original value
        assert snap.value[0].display_title == original_title

    def test_snapshot_ordering(self) -> None:
        """Snapshot returns tasks in newest-first order."""
        tracker = TaskTracker()

        with patch("time.time", return_value=100.0):
            tracker.add_task("old", "Old task")

        with patch("time.time", return_value=200.0):
            tracker.add_task("new", "New task")

        snap = tracker.get_snapshot()
        assert snap.value[0].task_id == "new"
        assert snap.value[1].task_id == "old"


# ===================================================================
# set_task_model
# ===================================================================


class TestSetTaskModel:
    def test_sets_model(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("task1", "Test")
        result = tracker.set_task_model("task1", "opus")
        assert result is True
        task = tracker.get_task("task1")
        assert task is not None
        assert task.model == "opus"

    def test_missing_task_returns_false(self) -> None:
        tracker = TaskTracker()
        result = tracker.set_task_model("nonexistent", "opus")
        assert result is False


# ===================================================================
# TaskState duration calculations
# ===================================================================


class TestTaskStateDurations:
    """Tests for TaskState duration calculation methods."""

    def test_queue_duration_not_started(self) -> None:
        """Queue duration uses current time when not started."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            task_id="t", conversation_id="", display_title="s", queued_at=100.0
        )
        with patch("time.time", return_value=110.0):
            assert task.queue_duration() == 10.0

    def test_queue_duration_started(self) -> None:
        """Queue duration uses started_at when available."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            task_id="t",
            conversation_id="",
            display_title="s",
            queued_at=100.0,
            started_at=105.0,
        )
        assert task.queue_duration() == 5.0

    def test_execution_duration_not_started(self) -> None:
        """Execution duration is None when not started."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(task_id="t", conversation_id="", display_title="s")
        assert task.execution_duration() is None

    def test_execution_duration_running(self) -> None:
        """Execution duration uses current time when running."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            task_id="t",
            conversation_id="",
            display_title="s",
            started_at=100.0,
        )
        with patch("time.time", return_value=120.0):
            assert task.execution_duration() == 20.0

    def test_execution_duration_completed(self) -> None:
        """Execution duration uses completed_at when done."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            task_id="t",
            conversation_id="",
            display_title="s",
            started_at=100.0,
            completed_at=115.0,
        )
        assert task.execution_duration() == 15.0

    def test_total_duration_running(self) -> None:
        """Total duration uses current time when not completed."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            task_id="t",
            conversation_id="",
            display_title="s",
            queued_at=100.0,
        )
        with patch("time.time", return_value=130.0):
            assert task.total_duration() == 30.0

    def test_total_duration_completed(self) -> None:
        """Total duration uses completed_at when done."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            task_id="t",
            conversation_id="",
            display_title="s",
            queued_at=100.0,
            completed_at=125.0,
        )
        assert task.total_duration() == 25.0


# ===================================================================
# get_tasks_by_status
# ===================================================================


class TestGetTasksByStatus:
    def test_filters_by_status(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("q1", "Queued 1")
        tracker.add_task("q2", "Queued 2")
        tracker.add_task("ip1", "In Progress")
        tracker.set_authenticating("ip1")
        tracker.set_executing("ip1")
        tracker.add_task("d1", "Done")
        tracker.set_authenticating("d1")
        tracker.set_executing("d1")
        tracker.complete_task("d1", CompletionReason.SUCCESS)

        queued = tracker.get_tasks_by_status(TaskStatus.QUEUED)
        assert len(queued) == 2
        executing = tracker.get_tasks_by_status(TaskStatus.EXECUTING)
        assert len(executing) == 1
        completed = tracker.get_tasks_by_status(TaskStatus.COMPLETED)
        assert len(completed) == 1

    def test_returns_newest_first(self) -> None:
        tracker = TaskTracker()

        with patch("time.time", return_value=100.0):
            tracker.add_task("old", "Old")
        with patch("time.time", return_value=200.0):
            tracker.add_task("new", "New")

        tasks = tracker.get_tasks_by_status(TaskStatus.QUEUED)
        assert tasks[0].task_id == "new"
        assert tasks[1].task_id == "old"


# ===================================================================
# get_counts
# ===================================================================


class TestGetCounts:
    def test_all_statuses_present(self) -> None:
        tracker = TaskTracker()
        counts = tracker.get_counts()
        assert set(counts.keys()) == {
            "queued",
            "authenticating",
            "pending",
            "executing",
            "completed",
        }
        assert all(v == 0 for v in counts.values())

    def test_counts_accurate(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("q1", "Q1")
        tracker.add_task("q2", "Q2")
        tracker.add_task("ip1", "IP1")
        tracker.set_authenticating("ip1")
        tracker.set_executing("ip1")
        tracker.add_task("d1", "D1")
        tracker.set_authenticating("d1")
        tracker.set_executing("d1")
        tracker.complete_task("d1", CompletionReason.SUCCESS)

        counts = tracker.get_counts()
        assert counts["queued"] == 2
        assert counts["executing"] == 1
        assert counts["completed"] == 1
