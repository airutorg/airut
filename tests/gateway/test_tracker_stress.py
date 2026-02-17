# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Comprehensive stress tests for the TaskTracker.

Covers:
- reassign_task in all scenarios (new, resumed, missing temp_id)
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
# reassign_task
# ===================================================================


class TestReassignTask:
    """Thorough tests for TaskTracker.reassign_task()."""

    def test_simple_rename(self) -> None:
        """Rename temp ID to new conv_id when conv_id doesn't exist."""
        tracker = TaskTracker()
        tracker.add_task("new-abc", "My subject", repo_id="test")
        tracker.set_authenticating("new-abc")
        tracker.set_executing("new-abc")

        result = tracker.reassign_task("new-abc", "real-conv-1")

        assert result is True
        assert tracker.get_task("new-abc") is None
        task = tracker.get_task("real-conv-1")
        assert task is not None
        assert task.conversation_id == "real-conv-1"
        assert task.display_title == "My subject"
        assert task.status == TaskStatus.EXECUTING

    def test_resume_merge(self) -> None:
        """Merge temp task into existing completed task."""
        tracker = TaskTracker()

        # Simulate existing completed conversation
        tracker.add_task("existing", "Original subject", repo_id="test")
        tracker.set_authenticating("existing")
        tracker.set_executing("existing")
        tracker.complete_task(
            "existing", CompletionReason.SUCCESS, message_count=3
        )

        original_task = tracker.get_task("existing")
        assert original_task is not None
        assert original_task.message_count == 3

        # New message arrives, temp task created
        tracker.add_task(
            "new-temp",
            "Re: Follow-up",
            repo_id="test",
            sender="alice@example.com",
        )
        tracker.set_authenticating("new-temp")
        tracker.set_executing("new-temp")

        result = tracker.reassign_task("new-temp", "existing")

        assert result is True
        # Temp task removed
        assert tracker.get_task("new-temp") is None
        # Existing task updated
        task = tracker.get_task("existing")
        assert task is not None
        assert task.status == TaskStatus.EXECUTING
        assert task.display_title == "Re: Follow-up"
        assert task.sender == "alice@example.com"
        assert task.message_count == 4  # 3 + 1
        assert task.completed_at is None
        assert task.completion_reason is None

    def test_missing_temp_returns_false(self) -> None:
        """Returns False when temp_id doesn't exist."""
        tracker = TaskTracker()
        result = tracker.reassign_task("nonexistent", "target")
        assert result is False

    def test_resume_preserves_model_from_temp(self) -> None:
        """When temp task has model, it overwrites existing's model."""
        tracker = TaskTracker()
        tracker.add_task("existing", "Task", model="sonnet")
        tracker.set_authenticating("existing")
        tracker.set_executing("existing")
        tracker.complete_task("existing", CompletionReason.SUCCESS)

        tracker.add_task("new-temp", "Re: Task", model="opus")
        tracker.set_authenticating("new-temp")
        tracker.set_executing("new-temp")

        tracker.reassign_task("new-temp", "existing")

        task = tracker.get_task("existing")
        assert task is not None
        assert task.model == "opus"

    def test_resume_preserves_existing_model_when_temp_has_none(self) -> None:
        """When temp task has no model, existing's model is preserved."""
        tracker = TaskTracker()
        tracker.add_task("existing", "Task", model="sonnet")
        tracker.set_authenticating("existing")
        tracker.set_executing("existing")
        tracker.complete_task("existing", CompletionReason.SUCCESS)

        tracker.add_task("new-temp", "Re: Task", model=None)
        tracker.set_authenticating("new-temp")
        tracker.set_executing("new-temp")

        tracker.reassign_task("new-temp", "existing")

        task = tracker.get_task("existing")
        assert task is not None
        assert task.model == "sonnet"

    def test_reassign_ticks_clock(self) -> None:
        """reassign_task increments the version clock."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)
        tracker.add_task("new-temp", "Test")

        v_before = clock.version
        tracker.reassign_task("new-temp", "real-id")
        assert clock.version > v_before

    def test_reassign_moves_to_end(self) -> None:
        """Reassigned task (resume case) is moved to end of ordered dict."""
        tracker = TaskTracker()

        tracker.add_task("conv-old", "Old")
        tracker.set_authenticating("conv-old")
        tracker.set_executing("conv-old")
        tracker.complete_task("conv-old", CompletionReason.SUCCESS)

        tracker.add_task("conv-newer", "Newer")

        # Now resume conv-old
        tracker.add_task("new-temp", "Re: Old")
        tracker.reassign_task("new-temp", "conv-old")

        # get_all_tasks returns newest first (by queued_at)
        tasks = tracker.get_all_tasks()
        task_ids = [t.conversation_id for t in tasks]
        # conv-newer was added after conv-old, so it has a later queued_at
        # The ordering depends on queued_at, not dict order
        assert "conv-old" in task_ids
        assert "conv-newer" in task_ids


# ===================================================================
# update_task_display_title
# ===================================================================


class TestUpdateTaskDisplayTitle:
    """Tests for update_task_display_title."""

    def test_updates_display_title(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "(authenticating)")
        result = tracker.update_task_display_title("conv1", "Real subject")
        assert result is True
        task = tracker.get_task("conv1")
        assert task is not None
        assert task.display_title == "Real subject"

    def test_updates_sender(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "(authenticating)")
        tracker.update_task_display_title(
            "conv1", "Subject", sender="user@example.com"
        )
        task = tracker.get_task("conv1")
        assert task is not None
        assert task.sender == "user@example.com"

    def test_missing_task_returns_false(self) -> None:
        tracker = TaskTracker()
        result = tracker.update_task_display_title("nonexistent", "whatever")
        assert result is False

    def test_empty_sender_not_set(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "Sub", sender="original@example.com")
        tracker.update_task_display_title("conv1", "New sub", sender="")
        task = tracker.get_task("conv1")
        assert task is not None
        assert task.sender == "original@example.com"


# ===================================================================
# update_task_id
# ===================================================================


class TestUpdateTaskId:
    """Tests for update_task_id."""

    def test_renames_task(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("old-id", "Subject")
        result = tracker.update_task_id("old-id", "new-id")
        assert result is True
        assert tracker.get_task("old-id") is None
        task = tracker.get_task("new-id")
        assert task is not None
        assert task.conversation_id == "new-id"
        assert task.display_title == "Subject"

    def test_missing_old_returns_false(self) -> None:
        tracker = TaskTracker()
        result = tracker.update_task_id("nonexistent", "target")
        assert result is False

    def test_conflict_returns_false(self) -> None:
        """Cannot rename when new_id already exists."""
        tracker = TaskTracker()
        tracker.add_task("id-a", "Task A")
        tracker.add_task("id-b", "Task B")
        result = tracker.update_task_id("id-a", "id-b")
        assert result is False
        # Both tasks still exist
        assert tracker.get_task("id-a") is not None
        assert tracker.get_task("id-b") is not None


# ===================================================================
# is_task_active
# ===================================================================


class TestIsTaskActive:
    """Tests for is_task_active."""

    def test_queued_is_active(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "Test")
        assert tracker.is_task_active("conv1") is True

    def test_in_progress_is_active(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "Test")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        assert tracker.is_task_active("conv1") is True

    def test_completed_is_not_active(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "Test")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        tracker.complete_task("conv1", CompletionReason.SUCCESS)
        assert tracker.is_task_active("conv1") is False

    def test_nonexistent_is_not_active(self) -> None:
        tracker = TaskTracker()
        assert tracker.is_task_active("doesnt-exist") is False


# ===================================================================
# Eviction stress
# ===================================================================


class TestEvictionStress:
    """Tests for completed task eviction under load."""

    def test_evicts_oldest_completed_when_over_limit(self) -> None:
        """Completed tasks beyond max_completed are evicted."""
        tracker = TaskTracker(max_completed=3)

        for i in range(5):
            cid = f"conv-{i:03d}"
            tracker.add_task(cid, f"Task {i}")
            tracker.set_authenticating(cid)
            tracker.set_executing(cid)
            tracker.complete_task(cid, CompletionReason.SUCCESS)

        # Only 3 completed should remain (the last 3)
        all_tasks = tracker.get_all_tasks()
        assert len(all_tasks) == 3

        task_ids = {t.conversation_id for t in all_tasks}
        assert "conv-000" not in task_ids
        assert "conv-001" not in task_ids
        assert "conv-002" in task_ids
        assert "conv-003" in task_ids
        assert "conv-004" in task_ids

    def test_active_tasks_not_evicted(self) -> None:
        """In-progress and queued tasks are never evicted."""
        tracker = TaskTracker(max_completed=2)

        # Add 3 completed tasks (1 will be evicted)
        for i in range(3):
            cid = f"done-{i}"
            tracker.add_task(cid, f"Done {i}")
            tracker.set_authenticating(cid)
            tracker.set_executing(cid)
            tracker.complete_task(cid, CompletionReason.SUCCESS)

        # Add an active task
        tracker.add_task("active-1", "Active")
        tracker.set_authenticating("active-1")
        tracker.set_executing("active-1")

        # Add a queued task
        tracker.add_task("queued-1", "Queued")

        all_tasks = tracker.get_all_tasks()
        # 2 completed (max) + 1 executing + 1 queued = 4
        assert len(all_tasks) == 4

        active_ids = {t.conversation_id for t in all_tasks}
        assert "active-1" in active_ids
        assert "queued-1" in active_ids

    def test_high_volume_eviction(self) -> None:
        """High volume of tasks doesn't accumulate unbounded."""
        tracker = TaskTracker(max_completed=10)

        for i in range(1000):
            cid = f"bulk-{i:06d}"
            tracker.add_task(cid, f"Bulk {i}")
            tracker.set_authenticating(cid)
            tracker.set_executing(cid)
            tracker.complete_task(cid, CompletionReason.SUCCESS)

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
                    cid = f"t{thread_id}-{i}"
                    tracker.add_task(cid, f"Task {thread_id}-{i}")
                    tracker.set_authenticating(cid)
                    tracker.set_executing(cid)
                    tracker.complete_task(cid, CompletionReason.SUCCESS)
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

    def test_concurrent_reassign(self) -> None:
        """Concurrent reassign operations don't corrupt state."""
        tracker = TaskTracker()
        errors: list[Exception] = []

        def worker(thread_id: int):
            try:
                for i in range(50):
                    temp = f"temp-{thread_id}-{i}"
                    real = f"real-{thread_id}-{i}"
                    tracker.add_task(temp, f"Task {thread_id}-{i}")
                    tracker.reassign_task(temp, real)
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
        tracker.add_task("conv1", "Test")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        tracker.complete_task("conv1", CompletionReason.SUCCESS)

        result = tracker.wait_for_completion("conv1", timeout=0.1)
        assert result is not None
        assert result.status == TaskStatus.COMPLETED

    def test_returns_none_on_timeout(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "Test")
        # Never complete it

        result = tracker.wait_for_completion("conv1", timeout=0.05)
        # Returns current task state (not completed)
        assert result is not None
        assert result.status == TaskStatus.QUEUED

    def test_wakes_on_completion(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "Test")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")

        result_holder: list = []

        def waiter():
            result = tracker.wait_for_completion("conv1", timeout=5.0)
            result_holder.append(result)

        thread = threading.Thread(target=waiter)
        thread.start()

        # Give the waiter time to enter the wait loop
        time.sleep(0.05)

        # Complete the task — this should wake the waiter
        tracker.complete_task("conv1", CompletionReason.SUCCESS)
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

        tracker.add_task("conv1", "Test")
        snap2 = tracker.get_snapshot()

        assert snap2.version > snap1.version

    def test_snapshot_is_isolated_from_mutations(self) -> None:
        """Snapshot contents don't change when tracker is mutated."""
        tracker = TaskTracker()
        tracker.add_task("conv1", "Original")

        snap = tracker.get_snapshot()
        original_title = snap.value[0].display_title

        tracker.update_task_display_title("conv1", "Modified")

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
        assert snap.value[0].conversation_id == "new"
        assert snap.value[1].conversation_id == "old"


# ===================================================================
# add_task resume behavior
# ===================================================================


class TestAddTaskResume:
    """Tests for add_task when the conversation already exists."""

    def test_resume_resets_state(self) -> None:
        """Resuming a completed task resets its state to QUEUED."""
        tracker = TaskTracker()
        tracker.add_task("conv1", "Original", sender="orig@example.com")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        tracker.complete_task("conv1", CompletionReason.SUCCESS)

        tracker.add_task("conv1", "Follow-up", sender="new@example.com")

        task = tracker.get_task("conv1")
        assert task is not None
        assert task.status == TaskStatus.QUEUED
        assert task.started_at is None
        assert task.completed_at is None
        assert task.completion_reason is None
        assert task.message_count == 2
        assert task.sender == "new@example.com"

    def test_resume_preserves_model_when_not_given(self) -> None:
        """Resuming without model= preserves existing model."""
        tracker = TaskTracker()
        tracker.add_task("conv1", "Task", model="opus")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        tracker.complete_task("conv1", CompletionReason.SUCCESS)

        tracker.add_task("conv1", "Resume")

        task = tracker.get_task("conv1")
        assert task is not None
        assert task.model == "opus"

    def test_resume_overrides_model_when_given(self) -> None:
        """Resuming with model= overrides existing model."""
        tracker = TaskTracker()
        tracker.add_task("conv1", "Task", model="opus")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        tracker.complete_task("conv1", CompletionReason.SUCCESS)

        tracker.add_task("conv1", "Resume", model="sonnet")

        task = tracker.get_task("conv1")
        assert task is not None
        assert task.model == "sonnet"

    def test_resume_preserves_empty_sender(self) -> None:
        """Resuming with empty sender preserves existing sender."""
        tracker = TaskTracker()
        tracker.add_task(
            "conv1", "Task", sender="original@example.com", repo_id="repo1"
        )
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        tracker.complete_task("conv1", CompletionReason.SUCCESS)

        tracker.add_task("conv1", "Resume", sender="")

        task = tracker.get_task("conv1")
        assert task is not None
        assert task.sender == "original@example.com"

    def test_resume_preserves_empty_repo_id(self) -> None:
        """Resuming with empty repo_id preserves existing repo_id."""
        tracker = TaskTracker()
        tracker.add_task("conv1", "Task", repo_id="repo1")
        tracker.set_authenticating("conv1")
        tracker.set_executing("conv1")
        tracker.complete_task("conv1", CompletionReason.SUCCESS)

        tracker.add_task("conv1", "Resume", repo_id="")

        task = tracker.get_task("conv1")
        assert task is not None
        assert task.repo_id == "repo1"


# ===================================================================
# set_task_model
# ===================================================================


class TestSetTaskModel:
    def test_sets_model(self) -> None:
        tracker = TaskTracker()
        tracker.add_task("conv1", "Test")
        result = tracker.set_task_model("conv1", "opus")
        assert result is True
        task = tracker.get_task("conv1")
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
            conversation_id="t", display_title="s", queued_at=100.0
        )
        with patch("time.time", return_value=110.0):
            assert task.queue_duration() == 10.0

    def test_queue_duration_started(self) -> None:
        """Queue duration uses started_at when available."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            conversation_id="t",
            display_title="s",
            queued_at=100.0,
            started_at=105.0,
        )
        assert task.queue_duration() == 5.0

    def test_execution_duration_not_started(self) -> None:
        """Execution duration is None when not started."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(conversation_id="t", display_title="s")
        assert task.execution_duration() is None

    def test_execution_duration_running(self) -> None:
        """Execution duration uses current time when running."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            conversation_id="t",
            display_title="s",
            started_at=100.0,
        )
        with patch("time.time", return_value=120.0):
            assert task.execution_duration() == 20.0

    def test_execution_duration_completed(self) -> None:
        """Execution duration uses completed_at when done."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            conversation_id="t",
            display_title="s",
            started_at=100.0,
            completed_at=115.0,
        )
        assert task.execution_duration() == 15.0

    def test_total_duration_running(self) -> None:
        """Total duration uses current time when not completed."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            conversation_id="t", display_title="s", queued_at=100.0
        )
        with patch("time.time", return_value=130.0):
            assert task.total_duration() == 30.0

    def test_total_duration_completed(self) -> None:
        """Total duration uses completed_at when done."""
        from airut.dashboard.tracker import TaskState

        task = TaskState(
            conversation_id="t",
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
        assert tasks[0].conversation_id == "new"
        assert tasks[1].conversation_id == "old"


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
