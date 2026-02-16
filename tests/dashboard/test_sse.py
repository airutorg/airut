# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for dashboard SSE module."""

import json
import threading
from pathlib import Path

from airut.dashboard.sse import (
    SSEConnectionManager,
    _boot_state_to_dict,
    _repo_state_to_dict,
    _task_state_to_dict,
    build_state_snapshot,
    format_sse_comment,
    format_sse_event,
    sse_events_log_stream,
    sse_network_log_stream,
    sse_state_stream,
)
from airut.dashboard.tracker import (
    BootPhase,
    BootState,
    RepoState,
    RepoStatus,
    TaskState,
    TaskStatus,
    TaskTracker,
)
from airut.dashboard.versioned import VersionClock, VersionedStore
from airut.sandbox import EventLog, NetworkLog


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
            channel_info="imap.example.com",
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
            channel_info="imap.example.com",
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
                channel_info="imap.example.com",
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


def _parse_sse_data(sse_text: str) -> dict:
    """Extract and parse JSON from an SSE event string."""
    data_lines = [
        line[6:] for line in sse_text.split("\n") if line.startswith("data: ")
    ]
    return json.loads("".join(data_lines))


class TestSSEEventsLogStream:
    """Tests for the events log SSE stream generator."""

    def test_initial_event_empty(self, tmp_path: Path) -> None:
        """Stream yields initial event with empty HTML."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        event_log = EventLog(tmp_path / "t1")
        (tmp_path / "t1").mkdir()

        gen = sse_events_log_stream(
            event_log, tracker, "t1", 0, poll_interval=0.01
        )
        first = next(gen)

        assert "event: html\n" in first
        assert "retry: 1000\n" in first
        data = _parse_sse_data(first)
        assert data["html"] == ""
        assert "offset" in data

    def test_done_event_on_completed_task(self, tmp_path: Path) -> None:
        """Stream sends done event when task is completed."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        gen = sse_events_log_stream(
            event_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Consume initial event
        next(gen)

        # Complete the task
        tracker.complete_task("t1", success=True)

        # Next should be done event
        event = next(gen)
        assert "event: done\n" in event

    def test_done_event_on_missing_task(self, tmp_path: Path) -> None:
        """Stream sends done event when task not found in tracker."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        gen = sse_events_log_stream(
            event_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Consume initial event
        next(gen)

        # Task doesn't exist in tracker -> done
        event = next(gen)
        assert "event: done\n" in event

    def test_streams_new_events(self, tmp_path: Path) -> None:
        """Stream yields new events as pre-rendered HTML."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        # Write some events before starting stream
        event_log.start_new_reply()
        from airut.claude_output import parse_stream_events

        events = parse_stream_events(
            '{"type": "system", "subtype": "init", "session_id": "s1"}'
        )
        for e in events:
            event_log.append_event(e)

        gen = sse_events_log_stream(
            event_log, tracker, "t1", 0, poll_interval=0.01
        )
        first = next(gen)

        data = _parse_sse_data(first)
        assert "system:" in data["html"]
        assert "init" in data["html"]

    def test_heartbeat_on_idle(self, tmp_path: Path) -> None:
        """Stream sends heartbeat when idle."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        gen = sse_events_log_stream(
            event_log,
            tracker,
            "t1",
            0,
            poll_interval=0.01,
            heartbeat_interval=0.02,
        )
        # Consume initial event
        next(gen)

        # Next should be heartbeat (task is still active, no new events)
        heartbeat = next(gen)
        assert heartbeat == ": heartbeat\n\n"

    def test_incremental_events_mid_stream(self, tmp_path: Path) -> None:
        """Stream yields events that arrive after initial snapshot."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        gen = sse_events_log_stream(
            event_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Consume initial (empty)
        next(gen)

        # Write events while stream is running
        from airut.claude_output import parse_stream_events

        events = parse_stream_events(
            '{"type": "system", "subtype": "init", "session_id": "s1"}'
        )
        event_log.start_new_reply()
        for e in events:
            event_log.append_event(e)

        # Next poll should pick up the new events as HTML
        event = next(gen)
        assert "event: html\n" in event
        data = _parse_sse_data(event)
        assert "system:" in data["html"]

        # Now complete the task
        tracker.complete_task("t1", success=True)
        done = next(gen)
        assert "event: done\n" in done

    def test_drain_events_on_completion(self, tmp_path: Path) -> None:
        """Stream drains remaining events when task completes."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        from airut.claude_output import parse_stream_events

        # Write events before starting the stream
        events = parse_stream_events(
            '{"type": "system", "subtype": "init", "session_id": "s1"}'
        )
        event_log.start_new_reply()
        for e in events:
            event_log.append_event(e)

        gen = sse_events_log_stream(
            event_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Initial snapshot includes the existing events as HTML
        first = next(gen)
        data = _parse_sse_data(first)
        assert "system:" in data["html"]

        # Write more events and complete the task simultaneously
        events2 = parse_stream_events(
            '{"type": "system", "subtype": "done", "session_id": "s1"}'
        )
        for e in events2:
            event_log.append_event(e)
        tracker.complete_task("t1", success=True)

        # Collect remaining events (drain + done)
        remaining = []
        for event in gen:
            remaining.append(event)
            if "event: done\n" in event:
                break

        # Should have gotten the drained events and a done
        has_html = any("event: html\n" in e for e in remaining)
        has_done = any("event: done\n" in e for e in remaining)
        assert has_html or has_done  # at minimum done event
        assert has_done

    def test_drain_has_remaining_events(self, tmp_path: Path) -> None:
        """Drain emits events written between poll and done check.

        Uses a mock to simulate events arriving after the regular
        tail() returns empty but before the drain tail() runs.
        """
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        from airut.claude_output import parse_stream_events

        gen = sse_events_log_stream(
            event_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Initial: empty
        next(gen)

        # Write events and complete the task
        events = parse_stream_events(
            '{"type": "system", "subtype": "init", "session_id": "s1"}'
        )
        event_log.start_new_reply()
        for e in events:
            event_log.append_event(e)
        tracker.complete_task("t1", success=True)

        # Make the regular poll return empty by patching tail to return
        # empty first time, then real data on drain
        real_tail = event_log.tail
        call_count = 0

        def fake_tail(offset: int = 0) -> tuple:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Regular poll: return empty
                return [], offset
            # Drain: return actual data
            return real_tail(offset)

        event_log.tail = fake_tail  # type: ignore[assignment]

        # Collect remaining
        remaining = []
        for event in gen:
            remaining.append(event)
            if "event: done\n" in event:
                break

        # Drain should have emitted HTML
        html_msgs = [e for e in remaining if "event: html\n" in e]
        assert len(html_msgs) >= 1
        drain_data = _parse_sse_data(html_msgs[-1])
        assert len(drain_data["html"]) > 0
        assert any("event: done\n" in e for e in remaining)

    def test_heartbeat_resets_timestamp(self, tmp_path: Path) -> None:
        """Heartbeat resets the last_heartbeat timer."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        conv_dir = tmp_path / "t1"
        conv_dir.mkdir()
        event_log = EventLog(conv_dir)

        gen = sse_events_log_stream(
            event_log,
            tracker,
            "t1",
            0,
            poll_interval=0.01,
            heartbeat_interval=0.02,
        )
        # Initial
        next(gen)

        # First heartbeat
        hb1 = next(gen)
        assert hb1 == ": heartbeat\n\n"

        # Second heartbeat (tests that timestamp was reset)
        hb2 = next(gen)
        assert hb2 == ": heartbeat\n\n"


class TestSSENetworkLogStream:
    """Tests for the network log SSE stream generator."""

    def test_initial_event_empty(self, tmp_path: Path) -> None:
        """Stream yields initial event with empty HTML."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log, tracker, "t1", 0, poll_interval=0.01
        )
        first = next(gen)

        assert "event: html\n" in first
        assert "retry: 1000\n" in first
        data = _parse_sse_data(first)
        assert data["html"] == ""

    def test_streams_new_lines(self, tmp_path: Path) -> None:
        """Stream yields new lines as pre-rendered HTML."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("allowed GET https://api.github.com -> 200\n")
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log, tracker, "t1", 0, poll_interval=0.01
        )
        first = next(gen)

        data = _parse_sse_data(first)
        assert "github.com" in data["html"]
        assert "log-line" in data["html"]

    def test_done_event_on_completed_task(self, tmp_path: Path) -> None:
        """Stream sends done event when task is completed."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Consume initial event
        next(gen)

        # Complete the task
        tracker.complete_task("t1", success=True)

        event = next(gen)
        assert "event: done\n" in event

    def test_heartbeat_on_idle(self, tmp_path: Path) -> None:
        """Stream sends heartbeat when idle."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log,
            tracker,
            "t1",
            0,
            poll_interval=0.01,
            heartbeat_interval=0.02,
        )
        # Consume initial event
        next(gen)

        heartbeat = next(gen)
        assert heartbeat == ": heartbeat\n\n"

    def test_incremental_lines_mid_stream(self, tmp_path: Path) -> None:
        """Stream yields lines that arrive after initial snapshot."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Consume initial (empty, file doesn't exist yet)
        next(gen)

        # Write log content while stream is running
        log_path.write_text("allowed GET https://api.github.com -> 200\n")

        # Next poll should pick up the new lines as HTML
        event = next(gen)
        assert "event: html\n" in event
        data = _parse_sse_data(event)
        assert "github.com" in data["html"]
        assert "log-line" in data["html"]

        # Now complete the task
        tracker.complete_task("t1", success=True)
        done = next(gen)
        assert "event: done\n" in done

    def test_drain_lines_on_completion(self, tmp_path: Path) -> None:
        """Stream drains remaining lines when task completes."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("line1\n")
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Consume initial snapshot
        first = next(gen)
        data = _parse_sse_data(first)
        assert "line1" in data["html"]

        # Append more and complete
        with log_path.open("a") as f:
            f.write("line2\n")
        tracker.complete_task("t1", success=True)

        # Collect remaining
        remaining = []
        for event in gen:
            remaining.append(event)
            if "event: done\n" in event:
                break

        has_done = any("event: done\n" in e for e in remaining)
        assert has_done

    def test_drain_has_remaining_lines(self, tmp_path: Path) -> None:
        """Drain emits lines written between poll and done check.

        Uses a mock to simulate lines arriving after the regular
        tail() returns empty but before the drain tail() runs.
        """
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log, tracker, "t1", 0, poll_interval=0.01
        )
        # Initial: empty
        next(gen)

        # Write lines and complete the task
        log_path.write_text("late line\n")
        tracker.complete_task("t1", success=True)

        # Make the regular poll return empty but drain finds data
        real_tail = network_log.tail
        call_count = 0

        def fake_tail(offset: int = 0) -> tuple:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [], offset
            return real_tail(offset)

        network_log.tail = fake_tail  # type: ignore[assignment]

        remaining = []
        for event in gen:
            remaining.append(event)
            if "event: done\n" in event:
                break

        html_msgs = [e for e in remaining if "event: html\n" in e]
        assert len(html_msgs) >= 1
        drain_data = _parse_sse_data(html_msgs[-1])
        assert len(drain_data["html"]) > 0
        assert any("event: done\n" in e for e in remaining)

    def test_heartbeat_resets_timestamp(self, tmp_path: Path) -> None:
        """Heartbeat resets the last_heartbeat timer."""
        tracker = TaskTracker()
        tracker.add_task("t1", "Task 1")
        tracker.start_task("t1")
        log_path = tmp_path / "network-sandbox.log"
        network_log = NetworkLog(log_path)

        gen = sse_network_log_stream(
            network_log,
            tracker,
            "t1",
            0,
            poll_interval=0.01,
            heartbeat_interval=0.02,
        )
        # Initial
        next(gen)

        # First heartbeat
        hb1 = next(gen)
        assert hb1 == ": heartbeat\n\n"

        # Second heartbeat (tests timestamp was reset)
        hb2 = next(gen)
        assert hb2 == ": heartbeat\n\n"
