# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for dashboard request handlers module."""

import json
from pathlib import Path

import pytest
from werkzeug.test import Client

from lib.container.session import SessionStore
from lib.dashboard.server import DashboardServer
from lib.dashboard.tracker import TaskState, TaskStatus, TaskTracker


class TestSessionDataIntegration:
    """Tests for session data display in dashboard."""

    def test_init_with_work_dirs(self, tmp_path: Path) -> None:
        """Test server initialization with work_dirs."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=[tmp_path])

        assert server.work_dirs == [tmp_path]

    def test_load_session_without_work_dirs(self) -> None:
        """Test _load_session returns None when work_dirs not configured."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)  # No work_dirs

        result = server._load_session("abc12345")
        assert result is None

    def test_load_session_conversation_not_found(self, tmp_path: Path) -> None:
        """Test _load_session returns None when conversation doesn't exist."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=[tmp_path])

        result = server._load_session("nonexistent")
        assert result is None

    def test_load_session_no_session_file(self, tmp_path: Path) -> None:
        """Test _load_session returns None when session file doesn't exist."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_session("abc12345")
        assert result is None

    def test_load_session_success(self, tmp_path: Path) -> None:
        """Test _load_session successfully loads session data."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file using SessionStore
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.0123,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_session("abc12345")

        assert result is not None
        assert result.conversation_id == "abc12345"
        assert len(result.replies) == 1
        assert result.replies[0].session_id == "sess_123"
        assert result.total_cost_usd == 0.0123

    def test_task_detail_shows_session_data(self, tmp_path: Path) -> None:
        """Test task detail page includes session data when available."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_xyz789abcdef1234567890",
                "duration_ms": 12345,
                "total_cost_usd": 0.0456,
                "num_turns": 5,
                "is_error": False,
                "usage": {"input_tokens": 200, "output_tokens": 100},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)

        # Check session data is displayed
        assert "Session Data" in html
        assert "$0.0456" in html  # Cost
        assert "5" in html  # Turns
        assert "Reply #1" in html
        # Full session ID
        assert "sess_xyz789abcdef1234567890" in html
        # Token usage labels and values
        assert "Input" in html
        assert "Output" in html
        assert "200" in html  # input_tokens value
        assert "100" in html  # output_tokens value

    def test_task_detail_no_session_data(self) -> None:
        """Test task detail page shows 'no session data' when unavailable."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)  # No work_dirs
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "No session data available" in html

    def test_task_session_json_endpoint(self, tmp_path: Path) -> None:
        """Test /task/<id>/session returns raw JSON."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.0123,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/session")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert data["conversation_id"] == "abc12345"
        assert len(data["replies"]) == 1
        assert data["replies"][0]["session_id"] == "sess_123"

    def test_task_session_json_no_work_dirs(self) -> None:
        """Test /task/<id>/session returns 404 when work_dirs not configured."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)  # No work_dirs
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/session")
        assert response.status_code == 404
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert "error" in data

    def test_task_session_json_no_session_file(self, tmp_path: Path) -> None:
        """Test /task/<id>/session returns 404 when no session file."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/nonexistent/session")
        assert response.status_code == 404
        assert response.content_type == "application/json"

    def test_task_session_json_dir_exists_no_file(self, tmp_path: Path) -> None:
        """Test /task/<id>/session when dir exists but session.json doesn't."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        # No session.json inside

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/session")
        assert response.status_code == 404
        data = response.get_json()
        assert "No session data" in data["error"]

    def test_task_session_json_invalid_json(self, tmp_path: Path) -> None:
        """Test /task/<id>/session handles invalid JSON gracefully."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Write invalid JSON
        session_file = conv_dir / "session.json"
        session_file.write_text("not valid json {{{")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/session")
        assert response.status_code == 500
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert "error" in data

    def test_api_task_includes_session_data(self, tmp_path: Path) -> None:
        """Test /api/task/<id> includes session data when available."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.0123,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/task/abc12345")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert "session" in data
        assert data["session"]["total_cost_usd"] == 0.0123
        assert data["session"]["total_turns"] == 3
        assert data["session"]["reply_count"] == 1
        assert len(data["session"]["replies"]) == 1

    def test_api_task_no_session_data(self) -> None:
        """Test /api/task/<id> has null session when unavailable."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)  # No work_dirs
        client = Client(server._wsgi_app)

        response = client.get("/api/task/abc12345")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert "session" in data
        assert data["session"] is None

    def test_api_tasks_does_not_include_session(self) -> None:
        """Test /api/tasks does not include session data for performance."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/tasks")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert len(data) == 1
        # Session should not be included in bulk listing
        assert "session" not in data[0]

    def test_render_session_error_reply(self, tmp_path: Path) -> None:
        """Test session section shows error styling for error replies."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file with an error reply
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_error",
                "duration_ms": 1000,
                "total_cost_usd": 0.001,
                "num_turns": 1,
                "is_error": True,
                "usage": {},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        html = response.get_data(as_text=True)

        # Check error class is applied
        assert 'class="reply error"' in html

    def test_render_session_multiple_replies(self, tmp_path: Path) -> None:
        """Test session section displays multiple replies correctly."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file with multiple replies
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_1",
                "duration_ms": 5000,
                "total_cost_usd": 0.01,
                "num_turns": 2,
                "is_error": False,
                "usage": {},
            },
        )
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_2",
                "duration_ms": 8000,
                "total_cost_usd": 0.025,
                "num_turns": 4,
                "is_error": False,
                "usage": {},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        html = response.get_data(as_text=True)

        # Check both replies are displayed
        assert "Reply #1" in html
        assert "Reply #2" in html

        # Check summary shows totals (6 turns total)
        assert ">6<" in html  # Total turns

    def test_task_to_dict_with_session(self, tmp_path: Path) -> None:
        """Test _task_to_dict includes session data when requested."""
        tracker = TaskTracker()
        task = TaskState(
            conversation_id="abc12345",
            subject="Test",
            status=TaskStatus.COMPLETED,
            queued_at=1000.0,
            started_at=1030.0,
            completed_at=1090.0,
            success=True,
        )

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 10,
                "is_error": False,
                "usage": {"input_tokens": 500},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._task_to_dict(task, include_session=True)

        assert "session" in result
        assert result["session"]["total_cost_usd"] == 0.05
        assert result["session"]["total_turns"] == 10
        assert result["session"]["reply_count"] == 1
        assert result["session"]["replies"][0]["usage"]["input_tokens"] == 500

    def test_task_to_dict_without_session_flag(self, tmp_path: Path) -> None:
        """Test _task_to_dict excludes session when not requested."""
        tracker = TaskTracker()
        task = TaskState(
            conversation_id="abc12345",
            subject="Test",
            status=TaskStatus.COMPLETED,
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._task_to_dict(task, include_session=False)

        assert "session" not in result

    def test_usage_display_filters_nested_objects(self, tmp_path: Path) -> None:
        """Test usage grid only shows token counts, not nested objects."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session with nested usage data (like real Claude responses)
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 10,
                "is_error": False,
                "usage": {
                    "input_tokens": 19,
                    "cache_creation_input_tokens": 14874,
                    "cache_read_input_tokens": 427112,
                    "output_tokens": 2818,
                    "server_tool_use": {
                        "web_search_requests": 0,
                        "web_fetch_requests": 0,
                    },
                    "service_tier": "standard",
                    "cache_creation": {
                        "ephemeral_1h_input_tokens": 0,
                        "ephemeral_5m_input_tokens": 14874,
                    },
                },
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        html = response.get_data(as_text=True)

        # Check token counts are displayed with labels
        assert "Input" in html
        assert "Output" in html
        assert "Cache Read" in html
        assert "Cache Write" in html
        assert "19" in html  # input_tokens
        assert "2,818" in html  # output_tokens formatted with comma
        assert "427,112" in html  # cache_read formatted with comma

        # Nested objects should NOT be rendered as raw dicts
        assert "web_search_requests" not in html
        assert "web_fetch_requests" not in html
        assert "ephemeral_1h_input_tokens" not in html
        assert "service_tier" not in html

    def test_task_detail_shows_request_response(self, tmp_path: Path) -> None:
        """Test task detail page displays request and response text."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file with request/response text
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
            },
            request_text="Please help me with this task",
            response_text="I'll help you with that task.",
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        html = response.get_data(as_text=True)

        # Check request/response sections are displayed
        assert "Request" in html
        assert "Response" in html
        assert "Please help me with this task" in html
        assert "I&#x27;ll help you with that task." in html  # HTML escaped

    def test_task_detail_no_request_response_text(self, tmp_path: Path) -> None:
        """Test task detail page handles missing request/response text."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file WITHOUT request/response text
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        html = response.get_data(as_text=True)

        # Request/Response sections should not be present
        assert 'class="text-section"' not in html

    def test_api_task_includes_request_response(self, tmp_path: Path) -> None:
        """Test /api/task/<id> includes request/response text."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
            },
            request_text="Test request",
            response_text="Test response",
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/task/abc12345")
        data = json.loads(response.get_data(as_text=True))

        assert data["session"]["replies"][0]["request_text"] == "Test request"
        assert data["session"]["replies"][0]["response_text"] == "Test response"

    def test_api_task_includes_events(self, tmp_path: Path) -> None:
        """Test /api/task/<id> includes events in session data."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {"type": "system", "subtype": "init"},
                    {"type": "result", "subtype": "success"},
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/task/abc12345")
        data = json.loads(response.get_data(as_text=True))

        assert "session" in data
        assert "replies" in data["session"]
        assert "events" in data["session"]["replies"][0]
        assert len(data["session"]["replies"][0]["events"]) == 2

    def test_task_to_dict_with_preloaded_session(self, tmp_path: Path) -> None:
        """Test _task_to_dict uses preloaded session when provided."""
        tracker = TaskTracker()
        task = TaskState(
            conversation_id="abc12345",
            subject="Test",
            status=TaskStatus.COMPLETED,
        )

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 10,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])

        # Load session manually
        session = server._load_session("abc12345")

        # Pass preloaded session
        result = server._task_to_dict(
            task, include_session=True, session=session
        )

        assert result["session"]["total_cost_usd"] == 0.05
        assert result["session"]["total_turns"] == 10


class TestLoadPastTasks:
    """Tests for loading past tasks from disk when not in memory."""

    def test_load_task_from_disk_success(self, tmp_path: Path) -> None:
        """Test loading a past task from disk when not in memory."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file without adding task to tracker
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_from_disk("abc12345")

        assert result is not None
        task, session = result
        assert task.conversation_id == "abc12345"
        assert task.status == TaskStatus.COMPLETED
        assert task.message_count == 1
        assert task.success is True
        assert session is not None
        assert session.conversation_id == "abc12345"

    def test_load_task_from_disk_no_work_dirs(self) -> None:
        """Test _load_task_from_disk returns None when work_dirs not set."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)  # No work_dirs

        result = server._load_task_from_disk("abc12345")
        assert result is None

    def test_load_task_from_disk_invalid_id_format(
        self, tmp_path: Path
    ) -> None:
        """Test _load_task_from_disk rejects invalid conversation IDs."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=[tmp_path])

        # Invalid format: too short
        assert server._load_task_from_disk("abc123") is None
        # Invalid format: not hex
        assert server._load_task_from_disk("gggggggg") is None
        # Invalid format: too long
        assert server._load_task_from_disk("abc123456") is None

    def test_load_task_from_disk_conversation_not_found(
        self, tmp_path: Path
    ) -> None:
        """Test _load_task_from_disk returns None for non-existent conv."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=[tmp_path])

        result = server._load_task_from_disk("abc12345")
        assert result is None

    def test_load_task_from_disk_no_session_file(self, tmp_path: Path) -> None:
        """Test _load_task_from_disk returns None when no session file."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()  # Directory exists but no session file

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_from_disk("abc12345")
        assert result is None

    def test_load_task_from_disk_with_error_reply(self, tmp_path: Path) -> None:
        """Test past task with error reply shows success=False."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_error",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": True,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_from_disk("abc12345")

        assert result is not None
        task, _ = result
        assert task.success is False

    def test_task_detail_loads_past_task_from_disk(
        self, tmp_path: Path
    ) -> None:
        """Test task detail page loads past task not in memory."""
        tracker = TaskTracker()
        # Do NOT add task to tracker - it's a "past" task
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "Task: abc12345" in html
        assert "[Past conversation abc12345]" in html
        assert "COMPLETED" in html
        # Session data should be displayed
        assert "$0.05" in html
        assert "3" in html  # num_turns

    def test_api_task_loads_past_task_from_disk(self, tmp_path: Path) -> None:
        """Test API endpoint loads past task not in memory."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/task/abc12345")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["conversation_id"] == "abc12345"
        assert data["status"] == "completed"
        assert data["session"] is not None
        assert data["session"]["total_cost_usd"] == 0.05

    def test_task_detail_prefers_memory_over_disk(self, tmp_path: Path) -> None:
        """Test that in-memory task takes precedence over disk."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "In-Memory Subject")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Should show in-memory task subject, not disk placeholder
        assert "In-Memory Subject" in html
        assert "IN PROGRESS" in html
        # Past conversation label should NOT appear
        assert "[Past conversation" not in html

    def test_load_task_from_disk_multiple_replies(self, tmp_path: Path) -> None:
        """Test past task with multiple replies shows correct message count."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_1",
                "duration_ms": 5000,
                "total_cost_usd": 0.01,
                "num_turns": 2,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_2",
                "duration_ms": 3000,
                "total_cost_usd": 0.02,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_from_disk("abc12345")

        assert result is not None
        task, session = result
        assert task.message_count == 2
        assert len(session.replies) == 2

    def test_load_task_from_disk_invalid_timestamp(
        self, tmp_path: Path
    ) -> None:
        """Test past task handles invalid timestamp gracefully."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file with invalid timestamp by writing raw JSON
        session_file = conv_dir / "session.json"
        session_file.write_text(
            json.dumps(
                {
                    "conversation_id": "abc12345",
                    "replies": [
                        {
                            "session_id": "sess_123",
                            "timestamp": "not-a-valid-timestamp",
                            "duration_ms": 5000,
                            "total_cost_usd": 0.05,
                            "num_turns": 3,
                            "is_error": False,
                            "usage": {},
                            "request_text": None,
                            "response_text": None,
                            "events": [],
                        }
                    ],
                }
            )
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_from_disk("abc12345")

        assert result is not None
        task, session = result
        # Should fall back to 0.0 for timestamps when parsing fails
        assert task.queued_at == 0.0
        assert task.started_at is None
        assert task.completed_at is None

    def test_load_task_from_disk_real_timestamp_format(
        self, tmp_path: Path
    ) -> None:
        """Test parsing real ISO 8601 timestamp with microseconds and tz."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "5287313b"
        conv_dir.mkdir()

        # Use real timestamp format from production session files
        session_id = "ea8ac106-c5db-4367-bb4e-4461999c2b03"
        session_file = conv_dir / "session.json"
        session_file.write_text(
            json.dumps(
                {
                    "conversation_id": "5287313b",
                    "replies": [
                        {
                            "session_id": session_id,
                            "timestamp": "2026-01-17T10:34:08.085081+00:00",
                            "duration_ms": 150814,
                            "total_cost_usd": 0.8891622,
                            "num_turns": 15,
                            "is_error": False,
                            "usage": {
                                "input_tokens": 3145,
                                "output_tokens": 3779,
                            },
                            "request_text": "Test request",
                            "response_text": "Test response",
                            "events": [],
                        },
                        {
                            "session_id": session_id,
                            "timestamp": "2026-01-17T10:51:54.751870+00:00",
                            "duration_ms": 808867,
                            "total_cost_usd": 7.180404750000002,
                            "num_turns": 80,
                            "is_error": False,
                            "usage": {
                                "input_tokens": 81,
                                "output_tokens": 35015,
                            },
                            "request_text": "Second request",
                            "response_text": "Second response",
                            "events": [],
                        },
                    ],
                }
            )
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_from_disk("5287313b")

        assert result is not None
        task, session = result

        # Should parse timestamp correctly
        assert task.completed_at is not None
        # The timestamp 2026-01-17T10:51:54.751870+00:00 should parse
        assert task.completed_at > 1700000000  # Sanity check it's a real ts
        assert task.queued_at == task.completed_at
        assert task.started_at == task.completed_at

        # Task metadata
        assert task.conversation_id == "5287313b"
        assert task.message_count == 2
        assert task.success is True

        # Session data
        assert len(session.replies) == 2
        # Sum of all replies: 0.8891622 + 7.180404750000002
        assert session.total_cost_usd == pytest.approx(8.069566950000002)

    def test_actions_page_loads_past_task_from_disk(
        self, tmp_path: Path
    ) -> None:
        """Test actions page loads past task not in memory."""
        tracker = TaskTracker()
        # Do NOT add task to tracker - it's a "past" task
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [{"type": "text", "text": "Test"}]
                        },
                    }
                ],
            },
            request_text="Help me with this task",
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "Actions: abc12345" in html
        assert "[Past conversation abc12345]" in html
        # Session data should be displayed
        assert "Reply #1" in html
        # Request text should be rendered on actions page
        assert "Help me with this task" in html
        assert "prompt" in html

    def test_actions_page_prefers_memory_over_disk(
        self, tmp_path: Path
    ) -> None:
        """Test that in-memory task takes precedence over disk for actions."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "In-Memory Subject")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Should show in-memory task subject, not disk placeholder
        assert "In-Memory Subject" in html
        # Past conversation label should NOT appear
        assert "[Past conversation" not in html


class TestLoadTaskWithSession:
    """Tests for the unified _load_task_with_session utility."""

    def test_load_task_with_session_from_memory(self, tmp_path: Path) -> None:
        """Test loading task that exists in memory."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "In-Memory Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_with_session("abc12345")

        assert result is not None
        task, session = result
        assert task.subject == "In-Memory Task"
        assert task.status == TaskStatus.IN_PROGRESS
        assert session is not None
        assert session.conversation_id == "abc12345"

    def test_load_task_with_session_from_disk(self, tmp_path: Path) -> None:
        """Test loading task that only exists on disk."""
        tracker = TaskTracker()
        # Do NOT add task to tracker

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_with_session("abc12345")

        assert result is not None
        task, session = result
        assert task.subject == "[Past conversation abc12345]"
        assert task.status == TaskStatus.COMPLETED
        assert session is not None

    def test_load_task_with_session_not_found(self, tmp_path: Path) -> None:
        """Test loading task that doesn't exist anywhere."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=[tmp_path])

        result = server._load_task_with_session("abc12345")
        assert result is None

    def test_load_task_with_session_memory_no_session_file(
        self, tmp_path: Path
    ) -> None:
        """Test loading in-memory task when session file doesn't exist."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Memory Task")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        result = server._load_task_with_session("abc12345")

        assert result is not None
        task, session = result
        assert task.subject == "Memory Task"
        assert session is None  # No session file on disk


class TestStopEndpoint:
    """Tests for task stop API endpoint."""

    def test_stop_endpoint_success(self) -> None:
        """Test POST /api/task/<id>/stop with successful stop."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.start_task(task_id)

        # Mock stop callback that succeeds
        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.post(f"/api/task/{task_id}/stop")
        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["message"] == "Task stopped"

    def test_stop_endpoint_not_found(self) -> None:
        """Test stop endpoint with non-existent task."""
        tracker = TaskTracker()

        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.post("/api/task/nonexistent/stop")
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_stop_endpoint_not_running(self) -> None:
        """Test stop endpoint with task not in progress."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        # Task is QUEUED, not IN_PROGRESS

        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.post(f"/api/task/{task_id}/stop")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert "not running" in data["error"]

    def test_stop_endpoint_no_callback(self) -> None:
        """Test stop endpoint when no stop callback configured."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.start_task(task_id)

        # No stop callback provided
        server = DashboardServer(tracker, stop_callback=None)
        client = Client(server._wsgi_app)

        response = client.post(f"/api/task/{task_id}/stop")
        assert response.status_code == 503
        data = response.get_json()
        assert "error" in data

    def test_stop_endpoint_callback_fails(self) -> None:
        """Test stop endpoint when callback returns False."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.start_task(task_id)

        # Mock stop callback that fails
        def mock_stop(conv_id: str) -> bool:
            return False

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.post(f"/api/task/{task_id}/stop")
        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False

    def test_stop_endpoint_callback_raises_exception(self) -> None:
        """Test stop endpoint when callback raises exception."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.start_task(task_id)

        # Mock stop callback that raises exception
        def mock_stop(conv_id):
            raise RuntimeError("Stop failed")

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.post(f"/api/task/{task_id}/stop")
        assert response.status_code == 500
        data = response.get_json()
        assert "error" in data

    def test_task_detail_with_stop_button(self) -> None:
        """Test task detail page includes stop button for in-progress tasks."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.start_task(task_id)

        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.get(f"/task/{task_id}")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Check stop button is present
        assert "stopTask()" in html
        assert "Stop Task" in html

    def test_task_detail_without_stop_button(self) -> None:
        """Test task detail page excludes stop button for completed tasks."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.complete_task(task_id, success=True)

        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.get(f"/task/{task_id}")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Check stop button is NOT present
        assert "Stop Task" not in html
