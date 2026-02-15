# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for dashboard request handlers module."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from werkzeug.test import Client

from lib.claude_output.extract import extract_result_summary, extract_session_id
from lib.claude_output.types import Usage
from lib.conversation import (
    CONVERSATION_FILE_NAME,
    ConversationStore,
    ReplySummary,
)
from lib.dashboard.server import DashboardServer
from lib.dashboard.tracker import TaskState, TaskStatus, TaskTracker
from lib.sandbox import EventLog
from tests.dashboard.conftest import parse_events as _parse_events


def _add_reply(
    conv_dir: Path,
    conversation_id: str,
    *raw_events: dict,
    request_text: str | None = None,
    response_text: str | None = None,
) -> None:
    """Parse raw event dicts, write to event log, and add reply summary.

    A convenience helper that mirrors what DashboardHarness.add_events() does,
    but works with an arbitrary conversation directory.
    """
    events = _parse_events(*raw_events)

    # Write events to event log
    event_log = EventLog(conv_dir)
    event_log.start_new_reply()
    for event in events:
        event_log.append_event(event)

    # Build reply summary from events
    session_id = extract_session_id(events) or ""
    summary = extract_result_summary(events)

    if summary is not None:
        reply = ReplySummary(
            session_id=session_id,
            timestamp=datetime.now(tz=UTC).isoformat(),
            duration_ms=summary.duration_ms,
            total_cost_usd=summary.total_cost_usd,
            num_turns=summary.num_turns,
            is_error=summary.is_error,
            usage=summary.usage,
            request_text=request_text,
            response_text=response_text,
        )
    else:
        reply = ReplySummary(
            session_id=session_id,
            timestamp=datetime.now(tz=UTC).isoformat(),
            duration_ms=0,
            total_cost_usd=0.0,
            num_turns=0,
            is_error=False,
            usage=Usage(),
            request_text=request_text,
            response_text=response_text,
        )

    store = ConversationStore(conv_dir)
    store.add_reply(conversation_id, reply)


class TestConversationDataIntegration:
    """Tests for conversation data display in dashboard."""

    def test_init_with_work_dirs(self, tmp_path: Path) -> None:
        """Test server initialization with work_dirs callable."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

        assert server._handlers._work_dirs() == [tmp_path]

    def test_load_conversation_without_work_dirs(self) -> None:
        """Test _load_conversation returns None when work_dirs not set."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)  # No work_dirs

        result = server._load_conversation("abc12345")
        assert result is None

    def test_load_conversation_not_found(self, tmp_path: Path) -> None:
        """Test _load_conversation returns None when conversation missing."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

        result = server._load_conversation("nonexistent")
        assert result is None

    def test_load_conversation_no_file(self, tmp_path: Path) -> None:
        """Test _load_conversation returns None when file doesn't exist."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_conversation("abc12345")
        assert result is None

    def test_load_conversation_success(self, tmp_path: Path) -> None:
        """Test _load_conversation successfully loads conversation data."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.0123,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_conversation("abc12345")

        assert result is not None
        assert result.conversation_id == "abc12345"
        assert len(result.replies) == 1
        assert result.replies[0].session_id == "sess_123"
        assert result.total_cost_usd == 0.0123

    def test_task_detail_shows_conversation_data(self, tmp_path: Path) -> None:
        """Task detail page includes conversation data when available."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_xyz789abcdef1234567890",
                "duration_ms": 12345,
                "total_cost_usd": 0.0456,
                "num_turns": 5,
                "is_error": False,
                "usage": {"input_tokens": 200, "output_tokens": 100},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)

        # Check conversation data is displayed
        assert "Conversation Data" in html
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

    def test_task_detail_no_conversation_data(self) -> None:
        """Task detail page shows placeholder when no data available."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)  # No work_dirs
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "No conversation data available" in html

    def test_api_task_includes_conversation_data(self, tmp_path: Path) -> None:
        """Test /api/conversation/<id> includes conversation data."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.0123,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert "conversation" in data
        assert data["conversation"]["total_cost_usd"] == 0.0123
        assert data["conversation"]["total_turns"] == 3
        assert data["conversation"]["reply_count"] == 1
        assert len(data["conversation"]["replies"]) == 1

    def test_api_task_no_conversation_data(self) -> None:
        """Test /api/conversation/<id> has null when no data available."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)  # No work_dirs
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert "conversation" in data
        assert data["conversation"] is None

    def test_api_tasks_does_not_include_conversation(self) -> None:
        """Excludes conversation data from list endpoint."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversations")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert len(data) == 1
        # Session should not be included in bulk listing
        assert "conversation" not in data[0]

    def test_render_conversation_error_reply(self, tmp_path: Path) -> None:
        """Conversation section shows error styling for error replies."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "error",
                "session_id": "sess_error",
                "duration_ms": 1000,
                "total_cost_usd": 0.001,
                "num_turns": 1,
                "is_error": True,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Check error class is applied
        assert 'class="reply error"' in html

    def test_render_conversation_multiple_replies(self, tmp_path: Path) -> None:
        """Conversation section displays multiple replies correctly."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_1",
                "duration_ms": 5000,
                "total_cost_usd": 0.01,
                "num_turns": 2,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )
        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_2",
                "duration_ms": 8000,
                "total_cost_usd": 0.025,
                "num_turns": 4,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Check both replies are displayed
        assert "Reply #1" in html
        assert "Reply #2" in html

        # Check summary shows totals (6 turns total)
        assert ">6<" in html  # Total turns

    def test_task_to_dict_with_conversation(self, tmp_path: Path) -> None:
        """_task_to_dict includes conversation data when requested."""
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

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 10,
                "is_error": False,
                "usage": {"input_tokens": 500},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._task_to_dict(task, include_conversation=True)

        assert "conversation" in result
        assert result["conversation"]["total_cost_usd"] == 0.05
        assert result["conversation"]["total_turns"] == 10
        assert result["conversation"]["reply_count"] == 1
        assert (
            result["conversation"]["replies"][0]["usage"]["input_tokens"] == 500
        )

    def test_task_to_dict_without_conversation_flag(
        self, tmp_path: Path
    ) -> None:
        """_task_to_dict excludes conversation data when not requested."""
        tracker = TaskTracker()
        task = TaskState(
            conversation_id="abc12345",
            subject="Test",
            status=TaskStatus.COMPLETED,
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._task_to_dict(task, include_conversation=False)

        assert "conversation" not in result

    def test_usage_display_filters_nested_objects(self, tmp_path: Path) -> None:
        """Test usage grid only shows token counts, not nested objects."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
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
                },
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
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

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
            request_text="Please help me with this task",
            response_text="I'll help you with that task.",
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Check request/response sections are displayed
        assert "Request" in html
        assert "Response" in html
        assert "Please help me with this task" in html
        assert "I&#x27;ll help you with that task." in html  # HTML escaped

    def test_task_detail_shows_pending_request_text(
        self, tmp_path: Path
    ) -> None:
        """Task detail page shows pending request text for in-progress tasks.

        When a task is running, the conversation section should display the
        pending_request_text from conversation.json so the user can see
        what prompt triggered the execution.

        Regression test: pending_request_text was only shown on the actions
        page, not on the task detail page's conversation section.
        """
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Set pending request (simulates what gateway does before execution)
        store = ConversationStore(conv_dir)
        store.set_pending_request("abc12345", "Fix the authentication bug")

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Must show the pending request text
        assert "Fix the authentication bug" in html
        # Should show it in the conversation section, not just metadata
        assert "Pending Request" in html

    def test_task_detail_pending_request_with_completed_replies(
        self, tmp_path: Path
    ) -> None:
        """Task detail shows pending request alongside completed replies.

        When a conversation has completed replies and a new request is
        in-progress, both should be visible.
        """
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Add a completed reply first
        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
            request_text="First request",
            response_text="First response",
        )

        # Set pending request for a follow-up
        store = ConversationStore(conv_dir)
        store.set_pending_request("abc12345", "Follow-up request")

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Completed reply should show
        assert "Reply #1" in html
        assert "First request" in html
        # Pending request should also show
        assert "Follow-up request" in html
        assert "Pending Request" in html

    def test_task_detail_pending_request_html_escaped(
        self, tmp_path: Path
    ) -> None:
        """Task detail page escapes pending request text to prevent XSS."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = ConversationStore(conv_dir)
        store.set_pending_request("abc12345", '<script>alert("xss")</script>')

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Must be escaped, not raw
        assert '<script>alert("xss")</script>' not in html
        assert "&lt;script&gt;" in html

    def test_task_detail_no_request_response_text(self, tmp_path: Path) -> None:
        """Test task detail page handles missing request/response text."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        # Request/Response sections should not be present
        assert 'class="text-section"' not in html

    def test_api_task_includes_request_response(self, tmp_path: Path) -> None:
        """Test /api/conversation/<id> includes request/response text."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
            request_text="Test request",
            response_text="Test response",
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345")
        data = json.loads(response.get_data(as_text=True))

        assert (
            data["conversation"]["replies"][0]["request_text"] == "Test request"
        )
        assert (
            data["conversation"]["replies"][0]["response_text"]
            == "Test response"
        )

    def test_api_task_includes_events(self, tmp_path: Path) -> None:
        """Test /api/conversation/<id> includes events from EventLog."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {"type": "system", "subtype": "init", "session_id": "sess_123"},
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345")
        data = json.loads(response.get_data(as_text=True))

        assert "conversation" in data
        assert "replies" in data["conversation"]
        assert "events" in data["conversation"]["replies"][0]
        assert len(data["conversation"]["replies"][0]["events"]) == 2

    def test_task_to_dict_with_preloaded_conversation(
        self, tmp_path: Path
    ) -> None:
        """Test _task_to_dict uses preloaded conversation when provided."""
        tracker = TaskTracker()
        task = TaskState(
            conversation_id="abc12345",
            subject="Test",
            status=TaskStatus.COMPLETED,
        )

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 10,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

        # Load conversation manually
        conversation = server._load_conversation("abc12345")

        # Pass preloaded conversation
        result = server._task_to_dict(
            task, include_conversation=True, conversation=conversation
        )

        assert result["conversation"]["total_cost_usd"] == 0.05
        assert result["conversation"]["total_turns"] == 10


class TestLoadPastTasks:
    """Tests for loading past tasks from disk when not in memory."""

    def test_load_task_from_disk_success(self, tmp_path: Path) -> None:
        """Test loading a past task from disk when not in memory."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_from_disk("abc12345")

        assert result is not None
        task, conversation = result
        assert task.conversation_id == "abc12345"
        assert task.status == TaskStatus.COMPLETED
        assert task.message_count == 1
        assert task.success is True
        assert conversation is not None
        assert conversation.conversation_id == "abc12345"

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
        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

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
        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

        result = server._load_task_from_disk("abc12345")
        assert result is None

    def test_load_task_from_disk_no_conversation_file(
        self, tmp_path: Path
    ) -> None:
        """_load_task_from_disk returns None with no conversation file."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()  # Directory exists but no conversation file

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_from_disk("abc12345")
        assert result is None

    def test_load_task_from_disk_with_error_reply(self, tmp_path: Path) -> None:
        """Test past task with error reply shows success=False."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "error",
                "session_id": "sess_error",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": True,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
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

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "Conversation: abc12345" in html
        assert "[Past conversation abc12345]" in html
        assert "COMPLETED" in html
        # Conversation data should be displayed
        assert "$0.05" in html
        assert "3" in html  # num_turns

    def test_api_task_loads_past_task_from_disk(self, tmp_path: Path) -> None:
        """Test API endpoint loads past task not in memory."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["conversation_id"] == "abc12345"
        assert data["status"] == "completed"
        assert data["conversation"] is not None
        assert data["conversation"]["total_cost_usd"] == 0.05

    def test_task_detail_prefers_memory_over_disk(self, tmp_path: Path) -> None:
        """Test that in-memory task takes precedence over disk."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "In-Memory Subject")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Should show in-memory task subject, not disk placeholder
        assert "In-Memory Subject" in html
        assert "IN PROGRESS" in html
        # Past conversation label should NOT appear
        assert "[Past conversation" not in html

    def test_load_task_from_disk_multiple_replies(self, tmp_path: Path) -> None:
        """Test past task with multiple replies shows correct count."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_1",
                "duration_ms": 5000,
                "total_cost_usd": 0.01,
                "num_turns": 2,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )
        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_2",
                "duration_ms": 3000,
                "total_cost_usd": 0.02,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_from_disk("abc12345")

        assert result is not None
        task, conversation = result
        assert task.message_count == 2
        assert len(conversation.replies) == 2

    def test_load_task_from_disk_invalid_timestamp(
        self, tmp_path: Path
    ) -> None:
        """Test past task handles invalid timestamp gracefully."""
        tracker = TaskTracker()
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create conversation file with invalid timestamp by writing raw JSON
        conversation_file = conv_dir / CONVERSATION_FILE_NAME
        conversation_file.write_text(
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
                        }
                    ],
                }
            )
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_from_disk("abc12345")

        assert result is not None
        task, conversation = result
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

        # Use real timestamp format from production conversation files
        session_id = "ea8ac106-c5db-4367-bb4e-4461999c2b03"
        conversation_file = conv_dir / CONVERSATION_FILE_NAME
        conversation_file.write_text(
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
                        },
                    ],
                }
            )
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_from_disk("5287313b")

        assert result is not None
        task, conversation = result

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

        # Conversation data
        assert len(conversation.replies) == 2
        # Sum of all replies: 0.8891622 + 7.180404750000002
        assert conversation.total_cost_usd == pytest.approx(8.069566950000002)

    def test_actions_page_loads_past_task_from_disk(
        self, tmp_path: Path
    ) -> None:
        """Test actions page loads past task not in memory."""
        tracker = TaskTracker()
        # Do NOT add task to tracker - it's a "past" task
        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": "Test"}],
                },
            },
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {"input_tokens": 100, "output_tokens": 50},
                "result": "",
            },
            request_text="Help me with this task",
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/actions")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "Actions: abc12345" in html
        assert "[Past conversation abc12345]" in html
        # Conversation data should be displayed
        assert "Reply #1" in html
        # Request text should be rendered on actions page
        assert "Help me with this task" in html
        assert "prompt" in html

    def test_actions_page_prefers_memory_over_disk(
        self, tmp_path: Path
    ) -> None:
        """Test that in-memory task takes precedence for actions."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "In-Memory Subject")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/actions")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Should show in-memory task subject, not disk placeholder
        assert "In-Memory Subject" in html
        # Past conversation label should NOT appear
        assert "[Past conversation" not in html


class TestLoadTaskWithConversation:
    """Tests for the unified _load_task_with_conversation utility."""

    def test_load_task_with_conversation_from_memory(
        self, tmp_path: Path
    ) -> None:
        """Test loading task that exists in memory."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "In-Memory Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_with_conversation("abc12345")

        assert result is not None
        task, conversation = result
        assert task.subject == "In-Memory Task"
        assert task.status == TaskStatus.IN_PROGRESS
        assert conversation is not None
        assert conversation.conversation_id == "abc12345"

    def test_load_task_with_conversation_from_disk(
        self, tmp_path: Path
    ) -> None:
        """Test loading task that only exists on disk."""
        tracker = TaskTracker()
        # Do NOT add task to tracker

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        _add_reply(
            conv_dir,
            "abc12345",
            {
                "type": "result",
                "subtype": "success",
                "session_id": "sess_123",
                "duration_ms": 5000,
                "total_cost_usd": 0.05,
                "num_turns": 3,
                "is_error": False,
                "usage": {},
                "result": "",
            },
        )

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_with_conversation("abc12345")

        assert result is not None
        task, conversation = result
        assert task.subject == "[Past conversation abc12345]"
        assert task.status == TaskStatus.COMPLETED
        assert conversation is not None

    def test_load_task_with_conversation_not_found(
        self, tmp_path: Path
    ) -> None:
        """Test loading task that doesn't exist anywhere."""
        tracker = TaskTracker()
        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

        result = server._load_task_with_conversation("abc12345")
        assert result is None

    def test_load_task_with_conversation_memory_no_file(
        self, tmp_path: Path
    ) -> None:
        """Test loading in-memory task when conversation file missing."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Memory Task")

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        result = server._load_task_with_conversation("abc12345")

        assert result is not None
        task, conversation = result
        assert task.subject == "Memory Task"
        assert conversation is None  # No conversation file on disk


class TestStopEndpoint:
    """Tests for task stop API endpoint."""

    def test_stop_endpoint_success(self) -> None:
        """Test POST /api/conversation/<id>/stop with successful stop."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.start_task(task_id)

        # Mock stop callback that succeeds
        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.post(f"/api/conversation/{task_id}/stop")
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

        response = client.post("/api/conversation/nonexistent/stop")
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

        response = client.post(f"/api/conversation/{task_id}/stop")
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

        response = client.post(f"/api/conversation/{task_id}/stop")
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

        response = client.post(f"/api/conversation/{task_id}/stop")
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

        response = client.post(f"/api/conversation/{task_id}/stop")
        assert response.status_code == 500
        data = response.get_json()
        assert "error" in data

    def test_task_detail_with_stop_button(self) -> None:
        """Test task detail page includes stop button for in-progress."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.start_task(task_id)

        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.get(f"/conversation/{task_id}")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Check stop button is present
        assert "stopTask()" in html
        assert 'stopTask()">Stop</button>' in html

    def test_task_detail_without_stop_button(self) -> None:
        """Test task detail page excludes stop button for completed."""
        tracker = TaskTracker()
        task_id = "abc12345"
        tracker.add_task(task_id, "Test Task")
        tracker.complete_task(task_id, success=True)

        def mock_stop(conv_id: str) -> bool:
            return True

        server = DashboardServer(tracker, stop_callback=mock_stop)
        client = Client(server._wsgi_app)

        response = client.get(f"/conversation/{task_id}")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Check stop button is NOT present
        assert "stopTask()" not in html


class TestEventsLogStreamEndpoint:
    """Tests for the per-conversation events SSE stream endpoint."""

    def test_events_log_stream_not_found(self) -> None:
        """Returns 404 when conversation directory doesn't exist."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/nonexist/events/stream")
        assert response.status_code == 404

    def test_events_log_stream_found(self, tmp_path: Path) -> None:
        """Returns SSE response for existing conversation."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/events/stream")
        assert response.status_code == 200
        assert response.content_type == "text/event-stream"

        # Should contain initial HTML event and done event (task completed)
        data = response.get_data(as_text=True)
        assert "event: html\n" in data
        assert "event: done\n" in data

    def test_events_log_stream_connection_limit(self, tmp_path: Path) -> None:
        """Returns 429 when SSE connection limit is reached."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

        # Exhaust all SSE slots
        for _ in range(8):
            server._sse_manager.try_acquire()

        client = Client(server._wsgi_app)
        response = client.get("/api/conversation/abc12345/events/stream")
        assert response.status_code == 429
        assert response.headers.get("Retry-After") == "5"

    def test_events_log_stream_with_offset(self, tmp_path: Path) -> None:
        """Passes offset parameter to the stream."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/conversation/abc12345/events/stream?offset=42"
        )
        assert response.status_code == 200

    def test_events_log_stream_invalid_offset(self, tmp_path: Path) -> None:
        """Handles invalid offset parameter gracefully."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/conversation/abc12345/events/stream?offset=invalid"
        )
        assert response.status_code == 200


class TestNetworkLogStreamEndpoint:
    """Tests for the per-conversation network log SSE stream endpoint."""

    def test_network_log_stream_not_found(self) -> None:
        """Returns 404 when conversation directory doesn't exist."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/nonexist/network/stream")
        assert response.status_code == 404

    def test_network_log_stream_found(self, tmp_path: Path) -> None:
        """Returns SSE response for existing conversation."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/network/stream")
        assert response.status_code == 200
        assert response.content_type == "text/event-stream"

        data = response.get_data(as_text=True)
        assert "event: html\n" in data
        assert "event: done\n" in data

    def test_network_log_stream_connection_limit(self, tmp_path: Path) -> None:
        """Returns 429 when SSE connection limit is reached."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])

        # Exhaust all SSE slots
        for _ in range(8):
            server._sse_manager.try_acquire()

        client = Client(server._wsgi_app)
        response = client.get("/api/conversation/abc12345/network/stream")
        assert response.status_code == 429
        assert response.headers.get("Retry-After") == "5"

    def test_network_log_stream_with_offset(self, tmp_path: Path) -> None:
        """Passes offset parameter to the stream."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/conversation/abc12345/network/stream?offset=42"
        )
        assert response.status_code == 200

    def test_network_log_stream_invalid_offset(self, tmp_path: Path) -> None:
        """Handles invalid offset parameter gracefully."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/conversation/abc12345/network/stream?offset=xyz"
        )
        assert response.status_code == 200


class TestSSELivePages:
    """Tests for SSE integration in HTML pages."""

    def test_task_detail_no_meta_refresh(self) -> None:
        """Task detail page no longer uses meta-refresh."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        assert 'meta http-equiv="refresh"' not in html

    def test_task_detail_has_sse_for_active(self) -> None:
        """Task detail page includes SSE script for active tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        assert "connectTaskSSE" in html
        assert "/api/events/stream" in html

    def test_task_detail_no_sse_for_completed(self) -> None:
        """Task detail page has no SSE script for completed tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.complete_task("abc12345", success=True)

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        assert "connectTaskSSE" not in html

    def test_repo_detail_no_meta_refresh(self) -> None:
        """Repo detail page no longer uses meta-refresh."""
        from lib.dashboard.tracker import (
            RepoState,
            RepoStatus,
        )
        from lib.dashboard.versioned import VersionClock, VersionedStore

        tracker = TaskTracker()
        clock = VersionClock()
        repo_states: tuple[RepoState, ...] = (
            RepoState(
                repo_id="test-repo",
                status=RepoStatus.LIVE,
                git_repo_url="https://github.com/test/repo",
                imap_server="imap.example.com",
                storage_dir="/storage/test",
            ),
        )
        repos_store: VersionedStore[tuple[RepoState, ...]] = VersionedStore(
            repo_states, clock
        )

        server = DashboardServer(tracker, repos_store=repos_store, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get("/repo/test-repo")
        html = response.get_data(as_text=True)

        assert 'meta http-equiv="refresh"' not in html
        assert "connectRepoSSE" in html

    def test_actions_page_has_sse_for_active(self, tmp_path: Path) -> None:
        """Actions page includes SSE script for active tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "connectEventsSSE" in html_text
        assert "/events/stream" in html_text

    def test_actions_page_no_sse_for_completed(self, tmp_path: Path) -> None:
        """Actions page has no SSE script for completed tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "connectEventsSSE" not in html

    def test_network_page_has_sse_for_active(self, tmp_path: Path) -> None:
        """Network page includes SSE script for active tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/network")
        html = response.get_data(as_text=True)

        assert "connectNetworkSSE" in html
        assert "/network/stream" in html

    def test_network_page_sse_offset_matches_log_size(
        self, tmp_path: Path
    ) -> None:
        """Network SSE starts from current log byte offset, not zero.

        Same fix as actions page: SSE must start from the current byte
        offset so it only sends new lines, not duplicate the initial HTML.
        """
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Write some network log content
        log_path = conv_dir / "network-sandbox.log"
        log_content = "allowed GET https://example.com -> 200\n"
        log_path.write_text(log_content)
        file_size = log_path.stat().st_size

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/network")
        html = response.get_data(as_text=True)

        assert f"var currentOffset = {file_size}" in html
        assert "var currentOffset = 0" not in html

    def test_network_page_sse_catchup_does_not_duplicate_lines(
        self, tmp_path: Path
    ) -> None:
        """SSE catch-up from page offset returns no already-rendered lines.

        When the network page loads, log lines are server-rendered in the
        initial HTML. The SSE stream must start from the byte offset at
        render time. Calling tail() at that offset must return zero
        lines, proving the SSE catch-up will not duplicate content.

        Regression test: with offset=0, SSE re-sent ALL log lines as
        raw HTML fragments after the server-rendered content, duplicating
        the entire network log.
        """
        from lib.sandbox import NetworkLog

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Write network log content
        log_path = conv_dir / "network-sandbox.log"
        log_lines = (
            "=== TASK START abc12345 ===\n"
            "allowed GET https://api.example.com/v1/data -> 200\n"
            "BLOCKED POST https://evil.example.com/exfil\n"
        )
        log_path.write_text(log_lines)
        file_size = log_path.stat().st_size

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/network")
        html = response.get_data(as_text=True)

        # Page must contain the server-rendered log lines
        assert "api.example.com" in html
        assert "BLOCKED" in html
        assert "TASK START" in html

        # SSE catch-up from the page offset must return NO lines
        # (all lines are already rendered in the initial HTML)
        network_log = NetworkLog(log_path)
        lines, _ = network_log.tail(file_size)
        assert lines == [], (
            "SSE catch-up from page offset must not return "
            f"already-rendered lines, but got {len(lines)} lines"
        )

        # Verify that offset=0 WOULD return lines (the old bug)
        lines_from_zero, _ = network_log.tail(0)
        assert len(lines_from_zero) > 0, (
            "tail(0) should return lines, confirming offset=0 would "
            "cause duplication"
        )

    def test_network_page_no_sse_for_completed(self, tmp_path: Path) -> None:
        """Network page has no SSE script for completed tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/network")
        html = response.get_data(as_text=True)

        assert "connectNetworkSSE" not in html


class TestEventsLogPollEndpoint:
    """Tests for the per-conversation events log polling endpoint."""

    def test_events_poll_not_found(self) -> None:
        """Returns 404 when conversation directory doesn't exist."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/nonexist/events/poll")
        assert response.status_code == 404

    def test_events_poll_empty_log(self, tmp_path: Path) -> None:
        """Returns empty HTML and offset 0 for empty event log."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/events/poll")
        assert response.status_code == 200
        assert response.content_type == "application/json"

        data = json.loads(response.get_data(as_text=True))
        assert data["offset"] == 0
        assert data["html"] == ""
        assert data["done"] is False

    def test_events_poll_with_data(self, tmp_path: Path) -> None:
        """Returns rendered HTML for new events."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Write raw event JSON directly to the log file
        events_file = conv_dir / "events.jsonl"
        raw = {"type": "assistant", "subtype": "text", "message": "hello"}
        events_file.write_text(json.dumps(raw) + "\n")

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/events/poll")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["offset"] > 0
        assert data["html"] != ""
        assert data["done"] is False

    def test_events_poll_done_for_completed_task(self, tmp_path: Path) -> None:
        """Returns done=True for completed tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/events/poll")
        data = json.loads(response.get_data(as_text=True))
        assert data["done"] is True

    def test_events_poll_etag_304(self, tmp_path: Path) -> None:
        """Returns 304 when ETag matches and no new data."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        # First request to get offset
        response = client.get("/api/conversation/abc12345/events/poll")
        etag = response.headers.get("ETag")
        assert etag is not None

        # Second request with ETag should return 304
        response = client.get(
            "/api/conversation/abc12345/events/poll",
            headers={"If-None-Match": etag},
        )
        assert response.status_code == 304

    def test_events_poll_with_offset(self, tmp_path: Path) -> None:
        """Respects offset parameter to skip already-seen data."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Write raw event JSON directly to the log file
        events_file = conv_dir / "events.jsonl"
        raw = {"type": "assistant", "subtype": "text", "message": "hello"}
        events_file.write_text(json.dumps(raw) + "\n")
        file_size = events_file.stat().st_size

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        # Polling from the end of existing data should return no html
        response = client.get(
            f"/api/conversation/abc12345/events/poll?offset={file_size}"
        )
        data = json.loads(response.get_data(as_text=True))
        assert data["html"] == ""

    def test_events_poll_invalid_offset(self, tmp_path: Path) -> None:
        """Handles invalid offset parameter gracefully."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/conversation/abc12345/events/poll?offset=invalid"
        )
        assert response.status_code == 200

    def test_events_poll_has_etag_header(self, tmp_path: Path) -> None:
        """Response includes ETag header based on offset."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/events/poll")
        assert "ETag" in response.headers
        assert response.headers["ETag"].startswith('"o')


class TestNetworkLogPollEndpoint:
    """Tests for the per-conversation network log polling endpoint."""

    def test_network_poll_not_found(self) -> None:
        """Returns 404 when conversation directory doesn't exist."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/nonexist/network/poll")
        assert response.status_code == 404

    def test_network_poll_empty_log(self, tmp_path: Path) -> None:
        """Returns empty HTML and offset 0 for no network log."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/network/poll")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["offset"] == 0
        assert data["html"] == ""
        assert data["done"] is False

    def test_network_poll_with_data(self, tmp_path: Path) -> None:
        """Returns rendered HTML for new network log lines."""
        from lib.sandbox import NETWORK_LOG_FILENAME

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / NETWORK_LOG_FILENAME
        log_path.write_text("allowed GET https://example.com -> 200\n")

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/network/poll")
        assert response.status_code == 200

        data = json.loads(response.get_data(as_text=True))
        assert data["offset"] > 0
        assert "example.com" in data["html"]
        assert data["done"] is False

    def test_network_poll_done_for_completed_task(self, tmp_path: Path) -> None:
        """Returns done=True for completed tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/api/conversation/abc12345/network/poll")
        data = json.loads(response.get_data(as_text=True))
        assert data["done"] is True

    def test_network_poll_etag_304(self, tmp_path: Path) -> None:
        """Returns 304 when ETag matches and no new data."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        # First request to get ETag
        response = client.get("/api/conversation/abc12345/network/poll")
        etag = response.headers.get("ETag")
        assert etag is not None

        # Second request with matching ETag returns 304
        response = client.get(
            "/api/conversation/abc12345/network/poll",
            headers={"If-None-Match": etag},
        )
        assert response.status_code == 304

    def test_network_poll_with_offset(self, tmp_path: Path) -> None:
        """Respects offset parameter to skip already-seen data."""
        from lib.sandbox import NETWORK_LOG_FILENAME

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / NETWORK_LOG_FILENAME
        log_path.write_text("allowed GET https://example.com -> 200\n")
        file_size = log_path.stat().st_size

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get(
            f"/api/conversation/abc12345/network/poll?offset={file_size}"
        )
        data = json.loads(response.get_data(as_text=True))
        assert data["html"] == ""

    def test_network_poll_invalid_offset(self, tmp_path: Path) -> None:
        """Handles invalid offset parameter gracefully."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get(
            "/api/conversation/abc12345/network/poll?offset=xyz"
        )
        assert response.status_code == 200


class TestPollingFallbackJS:
    """Tests for polling fallback JavaScript in view pages."""

    def test_actions_page_has_polling_fallback(self, tmp_path: Path) -> None:
        """Actions page JS includes polling fallback for active tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "startEventsPolling" in html
        assert "/events/poll" in html

    def test_network_page_has_polling_fallback(self, tmp_path: Path) -> None:
        """Network page JS includes polling fallback for active tasks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/network")
        html = response.get_data(as_text=True)

        assert "startNetworkPolling" in html
        assert "/network/poll" in html

    def test_task_detail_has_polling_fallback(self) -> None:
        """Task detail page JS includes polling fallback."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.start_task("abc12345")

        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345")
        html = response.get_data(as_text=True)

        assert "startTaskPolling" in html
        assert "/api/conversations" in html

    def test_repo_detail_has_polling_fallback(self) -> None:
        """Repo detail page JS includes polling fallback."""
        from lib.dashboard.tracker import RepoState, RepoStatus
        from lib.dashboard.versioned import VersionClock, VersionedStore

        tracker = TaskTracker()
        clock = VersionClock()
        repo_states: tuple[RepoState, ...] = (
            RepoState(
                repo_id="test-repo",
                status=RepoStatus.LIVE,
                git_repo_url="https://github.com/test/repo",
                imap_server="imap.example.com",
                storage_dir="/storage/test",
            ),
        )
        repos_store: VersionedStore[tuple[RepoState, ...]] = VersionedStore(
            repo_states, clock
        )

        server = DashboardServer(tracker, repos_store=repos_store, clock=clock)
        client = Client(server._wsgi_app)

        response = client.get("/repo/test-repo")
        html = response.get_data(as_text=True)

        assert "startRepoPolling" in html
        assert "/api/repos" in html

    def test_completed_actions_page_no_polling(self, tmp_path: Path) -> None:
        """Completed tasks don't include polling fallback JS."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "startEventsPolling" not in html

    def test_completed_network_page_no_polling(self, tmp_path: Path) -> None:
        """Completed tasks don't include polling fallback JS."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Task")
        tracker.complete_task("abc12345", success=True)

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        server = DashboardServer(tracker, work_dirs=lambda: [tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/network")
        html = response.get_data(as_text=True)

        assert "startNetworkPolling" not in html
