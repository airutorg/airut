# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for dashboard SSE module."""

import json
import threading

from lib.dashboard.sse import (
    SSEConnectionManager,
    _boot_state_to_dict,
    _repo_state_to_dict,
    _task_state_to_dict,
    build_state_snapshot,
    format_sse_comment,
    format_sse_event,
    sse_state_stream,
)
from lib.dashboard.tracker import (
    BootPhase,
    BootState,
    RepoState,
    RepoStatus,
    TaskState,
    TaskStatus,
    TaskTracker,
)
from lib.dashboard.versioned import VersionClock, VersionedStore


class TestFormatSSEEvent:
    """Tests for SSE event formatting."""

    def test_basic_event(self) -> None:
        """Test formatting a basic SSE event."""
        result = format_sse_event("state", '{"version": 1}')
        assert "event: state\n" in result
        assert 'data: {"version": 1}\n' in result
        # Ends with double newline
        assert result.endswith("\n\n")

    def test_event_with_id(self) -> None:
        """Test formatting with event ID."""
        result = format_sse_event("state", "data", event_id="42")
        assert "id: 42\n" in result
        assert "event: state\n" in result
        assert "data: data\n" in result

    def test_event_with_retry(self) -> None:
        """Test formatting with retry interval."""
        result = format_sse_event("state", "data", retry=1000)
        assert "retry: 1000\n" in result

    def test_event_with_all_fields(self) -> None:
        """Test formatting with all fields."""
        result = format_sse_event("state", "payload", event_id="5", retry=2000)
        assert "retry: 2000\n" in result
        assert "id: 5\n" in result
        assert "event: state\n" in result
        assert "data: payload\n" in result

    def test_multiline_data(self) -> None:
        """Test that multiline data gets correct data: prefixes."""
        result = format_sse_event("msg", "line1\nline2\nline3")
        assert "data: line1\n" in result
        assert "data: line2\n" in result
        assert "data: line3\n" in result


class TestFormatSSEComment:
    """Tests for SSE comment formatting."""

    def test_heartbeat_comment(self) -> None:
        """Test heartbeat comment formatting."""
        result = format_sse_comment("heartbeat")
        assert result == ": heartbeat\n\n"

    def test_arbitrary_comment(self) -> None:
        """Test arbitrary comment text."""
        result = format_sse_comment("keepalive")
        assert result == ": keepalive\n\n"


class TestSSEConnectionManager:
    """Tests for SSE connection limit management."""

    def test_acquire_within_limit(self) -> None:
        """Test acquiring slots within the limit."""
        mgr = SSEConnectionManager(max_connections=3)
        assert mgr.try_acquire() is True
        assert mgr.try_acquire() is True
        assert mgr.try_acquire() is True
        assert mgr.active == 3

    def test_acquire_at_limit(self) -> None:
        """Test acquiring fails at the limit."""
        mgr = SSEConnectionManager(max_connections=2)
        assert mgr.try_acquire() is True
        assert mgr.try_acquire() is True
        assert mgr.try_acquire() is False
        assert mgr.active == 2

    def test_release_frees_slot(self) -> None:
        """Test releasing allows new acquisitions."""
        mgr = SSEConnectionManager(max_connections=1)
        assert mgr.try_acquire() is True
        assert mgr.try_acquire() is False
        mgr.release()
        assert mgr.active == 0
        assert mgr.try_acquire() is True

    def test_release_does_not_go_negative(self) -> None:
        """Test releasing without acquiring doesn't go negative."""
        mgr = SSEConnectionManager(max_connections=2)
        mgr.release()
        assert mgr.active == 0

    def test_thread_safety(self) -> None:
        """Test concurrent acquire/release is thread-safe."""
        mgr = SSEConnectionManager(max_connections=100)
        errors: list[str] = []

        def acquire_release() -> None:
            for _ in range(50):
                if mgr.try_acquire():
                    mgr.release()
                else:
                    errors.append("unexpected rejection")

        threads = [threading.Thread(target=acquire_release) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert mgr.active == 0

    def test_default_max_connections(self) -> None:
        """Test default max connections is 8."""
        mgr = SSEConnectionManager()
        for _ in range(8):
            assert mgr.try_acquire() is True
        assert mgr.try_acquire() is False


class TestBootStateToDictConversion:
    """Tests for BootState to dict conversion."""

    def test_starting_phase(self) -> None:
        """Test converting starting boot state."""
        state = BootState(phase=BootPhase.STARTING, message="Initializing...")
        result = _boot_state_to_dict(state)
        assert result["phase"] == "starting"
        assert result["message"] == "Initializing..."
        assert "error_message" not in result
        assert "error_type" not in result

    def test_failed_phase(self) -> None:
        """Test converting failed boot state with error details."""
        state = BootState(
            phase=BootPhase.FAILED,
            message="Boot failed",
            error_message="Connection refused",
            error_type="RuntimeError",
            error_traceback="Traceback...",
        )
        result = _boot_state_to_dict(state)
        assert result["phase"] == "failed"
        assert result["error_message"] == "Connection refused"
        assert result["error_type"] == "RuntimeError"
        assert result["error_traceback"] == "Traceback..."

    def test_ready_phase(self) -> None:
        """Test converting ready boot state."""
        state = BootState(phase=BootPhase.READY, message="Service ready")
        result = _boot_state_to_dict(state)
        assert result["phase"] == "ready"


class TestRepoStateToDictConversion:
    """Tests for RepoState to dict conversion."""

    def test_live_repo(self) -> None:
        """Test converting live repo state."""
        state = RepoState(
            repo_id="test-repo",
            status=RepoStatus.LIVE,
            git_repo_url="https://github.com/test/repo",
            imap_server="imap.example.com",
            storage_dir="/storage/test",
            initialized_at=1000.0,
        )
        result = _repo_state_to_dict(state)
        assert result["repo_id"] == "test-repo"
        assert result["status"] == "live"
        assert result["git_repo_url"] == "https://github.com/test/repo"
        assert result["initialized_at"] == 1000.0
        assert result["error_message"] is None
        assert result["error_type"] is None

    def test_failed_repo(self) -> None:
        """Test converting failed repo state."""
        state = RepoState(
            repo_id="broken-repo",
            status=RepoStatus.FAILED,
            error_message="Auth failed",
            error_type="IMAPConnectionError",
            git_repo_url="https://github.com/test/repo",
            imap_server="imap.example.com",
            storage_dir="/storage/broken",
        )
        result = _repo_state_to_dict(state)
        assert result["status"] == "failed"
        assert result["error_message"] == "Auth failed"
        assert result["error_type"] == "IMAPConnectionError"


class TestTaskStateToDictConversion:
    """Tests for TaskState to dict conversion."""

    def test_queued_task(self) -> None:
        """Test converting queued task."""
        task = TaskState(
            conversation_id="abc12345",
            subject="Test Task",
            repo_id="repo1",
            sender="user@example.com",
            status=TaskStatus.QUEUED,
            queued_at=1000.0,
        )
        result = _task_state_to_dict(task)
        assert result["conversation_id"] == "abc12345"
        assert result["subject"] == "Test Task"
        assert result["repo_id"] == "repo1"
        assert result["sender"] == "user@example.com"
        assert result["status"] == "queued"
        assert result["queued_at"] == 1000.0
        assert result["started_at"] is None
        assert result["completed_at"] is None
        assert result["success"] is None

    def test_completed_task(self) -> None:
        """Test converting completed task with all fields."""
        task = TaskState(
            conversation_id="abc12345",
            subject="Completed Task",
            status=TaskStatus.COMPLETED,
            queued_at=1000.0,
            started_at=1010.0,
            completed_at=1070.0,
            success=True,
            message_count=3,
            model="claude-3",
        )
        result = _task_state_to_dict(task)
        assert result["status"] == "completed"
        assert result["success"] is True
        assert result["message_count"] == 3
        assert result["model"] == "claude-3"
        assert result["queue_duration"] is not None
        assert result["execution_duration"] is not None
        assert result["total_duration"] is not None


class TestBuildStateSnapshot:
    """Tests for building JSON state snapshots."""

    def test_empty_state(self) -> None:
        """Test snapshot with empty tracker and no stores."""
        tracker = TaskTracker()
        result = json.loads(build_state_snapshot(tracker, None, None, 0))
        assert result["version"] == 0
        assert result["tasks"] == []
        assert result["boot"] is None
        assert result["repos"] == []

    def test_with_tasks(self) -> None:
        """Test snapshot includes all tasks."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.add_task("t2", "Task 2")
        tracker.start_task("t2")

        result = json.loads(build_state_snapshot(tracker, None, None, 5))
        assert result["version"] == 5
        assert len(result["tasks"]) == 2
        task_ids = {t["conversation_id"] for t in result["tasks"]}
        assert task_ids == {"t1", "t2"}

    def test_with_boot_store(self) -> None:
        """Test snapshot includes boot state."""
        tracker = TaskTracker()
        clock = VersionClock()
        boot_store = VersionedStore(
            BootState(phase=BootPhase.PROXY, message="Building proxy..."),
            clock,
        )

        result = json.loads(build_state_snapshot(tracker, boot_store, None, 1))
        assert result["boot"]["phase"] == "proxy"
        assert result["boot"]["message"] == "Building proxy..."

    def test_with_repos_store(self) -> None:
        """Test snapshot includes repo states."""
        tracker = TaskTracker()
        clock = VersionClock()
        repo_states: tuple[RepoState, ...] = (
            RepoState(
                repo_id="repo1",
                status=RepoStatus.LIVE,
                git_repo_url="https://github.com/test/repo1",
                imap_server="imap.example.com",
                storage_dir="/storage/repo1",
            ),
        )
        repos_store: VersionedStore[tuple[RepoState, ...]] = VersionedStore(
            repo_states, clock
        )

        result = json.loads(build_state_snapshot(tracker, None, repos_store, 2))
        assert len(result["repos"]) == 1
        assert result["repos"][0]["repo_id"] == "repo1"
        assert result["repos"][0]["status"] == "live"


class TestSSEStateStream:
    """Tests for the SSE state stream generator."""

    def test_initial_event(self) -> None:
        """Test that the stream yields an initial state event."""
        clock = VersionClock()
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")

        gen = sse_state_stream(clock, tracker, None, None, 0)
        first = next(gen)

        assert "event: state\n" in first
        assert "retry: 1000\n" in first
        assert "id: " in first

        # Parse the data line
        data_lines = [
            line[6:] for line in first.split("\n") if line.startswith("data: ")
        ]
        data = json.loads("".join(data_lines))
        assert "version" in data
        assert len(data["tasks"]) == 1
        assert data["tasks"][0]["conversation_id"] == "t1"

    def test_heartbeat_on_timeout(self) -> None:
        """Test that heartbeat is sent when no changes occur."""
        clock = VersionClock()
        tracker = TaskTracker()

        gen = sse_state_stream(
            clock, tracker, None, None, 0, heartbeat_interval=0.05
        )
        # Consume initial event
        next(gen)

        # Next should be a heartbeat (after 50ms timeout)
        heartbeat = next(gen)
        assert heartbeat == ": heartbeat\n\n"

    def test_heartbeat_then_state_change(self) -> None:
        """Test heartbeat followed by state change covers continue."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)

        gen = sse_state_stream(
            clock, tracker, None, None, 0, heartbeat_interval=0.05
        )
        # Consume initial event
        next(gen)

        # Get heartbeat (timeout, no changes)
        heartbeat = next(gen)
        assert heartbeat == ": heartbeat\n\n"

        # Now trigger a change — next iteration should see it
        tracker.add_task("t1", "After Heartbeat")
        event = next(gen)
        assert "event: state\n" in event
        data_lines = [
            line[6:] for line in event.split("\n") if line.startswith("data: ")
        ]
        data = json.loads("".join(data_lines))
        assert len(data["tasks"]) == 1

    def test_state_update_on_change(self) -> None:
        """Test that state changes trigger a new event."""
        clock = VersionClock()
        tracker = TaskTracker(clock=clock)

        gen = sse_state_stream(
            clock, tracker, None, None, 0, heartbeat_interval=5.0
        )
        # Consume initial event
        next(gen)

        # Trigger a change from another thread
        def add_task() -> None:
            tracker.add_task("t1", "New Task")

        t = threading.Thread(target=add_task)
        t.start()
        t.join()

        event = next(gen)
        assert "event: state\n" in event
        assert "retry:" not in event  # retry only on first event

        data_lines = [
            line[6:] for line in event.split("\n") if line.startswith("data: ")
        ]
        data = json.loads("".join(data_lines))
        assert len(data["tasks"]) == 1
        assert data["tasks"][0]["conversation_id"] == "t1"
