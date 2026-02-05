# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for dashboard views module (HTML rendering)."""

from pathlib import Path

from werkzeug.test import Client

from lib.container.session import SessionStore
from lib.dashboard.server import DashboardServer
from lib.dashboard.tracker import TaskTracker


class TestActionsPage:
    """Tests for the actions viewer page."""

    def test_task_actions_endpoint(self, tmp_path: Path) -> None:
        """Test /task/<id>/actions returns actions page."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create session file with events
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
                "events": [
                    {"type": "system", "subtype": "init", "tools": ["Bash"]},
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {"type": "text", "text": "Hello, I'll help."}
                            ]
                        },
                    },
                    {"type": "result", "subtype": "success"},
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"

        html = response.get_data(as_text=True)
        assert "Actions: abc12345" in html
        assert "Test Subject" in html
        assert "Reply #1" in html

    def test_task_actions_not_found(self) -> None:
        """Test /task/<id>/actions returns 404 for nonexistent task."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/task/nonexistent/actions")
        assert response.status_code == 404

    def test_task_actions_no_session(self) -> None:
        """Test actions page shows 'no actions' when session not available."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)  # No work_dirs
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "No actions recorded" in html

    def test_task_actions_shows_events(self, tmp_path: Path) -> None:
        """Test actions page displays different event types."""
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
                "num_turns": 2,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "system",
                        "subtype": "init",
                        "session_id": "sess_123",
                        "model": "claude-opus-4",
                        "tools": ["Bash", "Read", "Write"],
                    },
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Bash",
                                    "input": {"command": "ls -la"},
                                }
                            ]
                        },
                    },
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {"type": "tool_result", "content": "file1.txt"}
                            ]
                        },
                    },
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {"type": "text", "text": "Found 1 file."}
                            ]
                        },
                    },
                    {
                        "type": "result",
                        "subtype": "success",
                        "result": "Found 1 file.",
                        "duration_ms": 5000,
                        "total_cost_usd": 0.05,
                        "num_turns": 2,
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        # Check event content is rendered
        assert "system:" in html  # system event rendered inline
        assert "init" in html
        assert "Bash" in html  # tool name
        assert "ls -la" in html  # tool input
        assert "file1.txt" in html  # tool result
        assert "Found 1 file." in html  # assistant text
        assert "result:" in html  # result event rendered inline

    def test_task_actions_has_toggle_for_raw_json(self, tmp_path: Path) -> None:
        """Test actions page has toggleEvent for raw JSON blocks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [{"type": "system", "subtype": "init"}],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        # toggleEvent JS should exist (used for raw JSON)
        assert "toggleEvent" in html

    def test_task_actions_link_from_detail(self, tmp_path: Path) -> None:
        """Test task detail page has link to actions viewer."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        html = response.get_data(as_text=True)

        # Check link to actions page exists
        assert "/task/abc12345/actions" in html
        assert "View Actions" in html

    def test_render_event_body_tool_use(self, tmp_path: Path) -> None:
        """Test rendering tool_use blocks in assistant events."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Read",
                                    "input": {"file_path": "/test.txt"},
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "Read" in html
        assert "/test.txt" in html

    def test_render_event_body_tool_result_truncation(
        self, tmp_path: Path
    ) -> None:
        """Test large tool results are truncated in display."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create a large tool result (> 20 lines)
        large_content = "\n".join(f"line {i}" for i in range(30))

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "content": large_content,
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "10 more lines" in html

    def test_render_event_body_tool_result_error(self, tmp_path: Path) -> None:
        """Test tool result errors are displayed with error indication."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "content": "Permission denied",
                                    "is_error": True,
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "(error)" in html
        assert "Permission denied" in html

    def test_event_container_has_error_class_for_failed_tool(
        self, tmp_path: Path
    ) -> None:
        """Test event container has error class when tool result has error."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "content": "Command failed",
                                    "is_error": True,
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        # Check event container has error class
        assert 'class="event error"' in html
        # Check meta shows error indicator
        assert "error" in html

    def test_event_container_no_error_class_for_success(
        self, tmp_path: Path
    ) -> None:
        """Test event container has no error class for successful tool."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "content": "Success output",
                                    "is_error": False,
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        # Check event container does NOT have error class
        assert 'class="event error"' not in html
        # Regular event class should be present
        assert 'class="event"' in html

    def test_render_event_body_tool_result_list_content(
        self, tmp_path: Path
    ) -> None:
        """Test tool result with list content (Claude API format) is handled."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "content": [
                                        {"type": "text", "text": "First line"},
                                        {"type": "text", "text": "Second line"},
                                    ],
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        assert "First line" in html
        assert "Second line" in html

    def test_render_event_body_tool_result_list_with_strings(
        self, tmp_path: Path
    ) -> None:
        """Test tool result with list containing plain strings is handled."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "content": [
                                        "Plain string content",
                                        "Another plain string",
                                    ],
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        assert "Plain string content" in html
        assert "Another plain string" in html

    def test_render_event_unknown_type(self, tmp_path: Path) -> None:
        """Test unknown event types show raw JSON."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {"type": "unknown_type", "data": "test_value"},
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        # Raw JSON should be displayed for unknown types
        assert "unknown_type" in html
        assert "test_value" in html

    def test_render_events_empty_list(self, tmp_path: Path) -> None:
        """Test rendering with empty events list."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "No events recorded" in html

    def test_render_assistant_empty_content(self, tmp_path: Path) -> None:
        """Test rendering assistant event with empty content."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {"type": "assistant", "message": {"content": []}},
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "No content" in html

    def test_render_user_empty_content(self, tmp_path: Path) -> None:
        """Test rendering user event with empty content."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {"type": "user", "message": {"content": []}},
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "No content" in html

    def test_render_system_many_tools(self, tmp_path: Path) -> None:
        """Test system event with many tools truncates display."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create more than 20 tools
        many_tools = [f"Tool{i}" for i in range(25)]

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {"type": "system", "subtype": "init", "tools": many_tools},
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        assert "+5 more" in html

    def test_render_result_with_long_result(self, tmp_path: Path) -> None:
        """Test result event truncates long result text."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        long_result = "x" * 600  # > 500 chars

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "result",
                        "subtype": "success",
                        "result": long_result,
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html = response.get_data(as_text=True)

        # Should show truncated result with ...
        assert "..." in html

    def test_bash_tool_shows_command_and_description(
        self, tmp_path: Path
    ) -> None:
        """Test Bash tool shows command in distinct style + description."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Bash",
                                    "input": {
                                        "command": "ls -la",
                                        "description": "List all files",
                                    },
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "Bash" in html_text
        assert "List all files" in html_text
        # Command shown in bash-cmd styled div
        assert "bash-cmd" in html_text
        assert "ls -la" in html_text

    def test_bash_tool_shows_timeout(self, tmp_path: Path) -> None:
        """Test Bash tool displays timeout when present."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Bash",
                                    "input": {
                                        "command": "sleep 60",
                                        "timeout": 120000,
                                    },
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "timeout=120000ms" in html_text
        assert "sleep 60" in html_text

    def test_tool_renderers_various(self, tmp_path: Path) -> None:
        """Test specialized rendering for various tools."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Write",
                                    "input": {
                                        "file_path": "/tmp/out.txt",
                                        "content": "line1\nline2\n",
                                    },
                                },
                                {
                                    "type": "tool_use",
                                    "name": "Edit",
                                    "input": {
                                        "file_path": "/tmp/ed.txt",
                                        "old_string": "old",
                                        "new_string": "new",
                                    },
                                },
                                {
                                    "type": "tool_use",
                                    "name": "Grep",
                                    "input": {
                                        "pattern": "foo",
                                        "path": "/src",
                                    },
                                },
                                {
                                    "type": "tool_use",
                                    "name": "Glob",
                                    "input": {"pattern": "*.py"},
                                },
                                {
                                    "type": "tool_use",
                                    "name": "Task",
                                    "input": {
                                        "description": "search code",
                                    },
                                },
                                {
                                    "type": "tool_use",
                                    "name": "TodoWrite",
                                    "input": {
                                        "todos": [
                                            {
                                                "status": "in_progress",
                                                "content": "Do stuff",
                                            },
                                        ]
                                    },
                                },
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        # Write: shows path and line/char count
        assert "/tmp/out.txt" in html_text
        assert "3 lines" in html_text

        # Edit: shows path and git-style diff
        assert "/tmp/ed.txt" in html_text
        assert "diff-removed" in html_text
        assert "diff-added" in html_text

        # Grep: shows /pattern/
        assert "/foo/" in html_text

        # Glob: shows pattern
        assert "*.py" in html_text

        # Task: shows description
        assert "search code" in html_text

        # TodoWrite: shows items with status
        assert "[in_progress] Do stuff" in html_text

    def test_unknown_tool_shows_json(self, tmp_path: Path) -> None:
        """Test unknown tool renders input as raw JSON."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "CustomTool",
                                    "input": {
                                        "url": "https://example.com",
                                    },
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "CustomTool" in html_text
        # Unknown tools show JSON with keys
        assert "https://example.com" in html_text
        assert "tool-input-json" in html_text

    def test_edit_tool_replace_all(self, tmp_path: Path) -> None:
        """Test Edit tool shows replace_all flag."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Edit",
                                    "input": {
                                        "file_path": "/f.py",
                                        "old_string": "a",
                                        "new_string": "b",
                                        "replace_all": True,
                                    },
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "(replace_all)" in html_text

    def test_edit_tool_truncates_long_diff(
        self,
        tmp_path: Path,
    ) -> None:
        """Test Edit tool truncates long diffs."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # 25 lines exceeds _EDIT_MAX_LINES (20)
        old_text = "\n".join(f"old line {i}" for i in range(25))
        new_text = "\n".join(f"new line {i}" for i in range(25))

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Edit",
                                    "input": {
                                        "file_path": "/f.py",
                                        "old_string": old_text,
                                        "new_string": new_text,
                                    },
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(
            tracker,
            work_dirs=[tmp_path],
        )
        client = Client(server._wsgi_app)

        resp = client.get("/task/abc12345/actions")
        html_text = resp.get_data(as_text=True)

        assert "- old line 0" in html_text
        assert "- old line 19" in html_text
        assert "- old line 20" not in html_text
        assert "(5 more lines)" in html_text
        assert "+ new line 0" in html_text

    def test_read_tool_with_offset_limit(self, tmp_path: Path) -> None:
        """Test Read tool shows offset/limit when present."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Read",
                                    "input": {
                                        "file_path": "/f.py",
                                        "offset": 100,
                                        "limit": 50,
                                    },
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "/f.py" in html_text
        assert "offset=100" in html_text
        assert "limit=50" in html_text

    def test_grep_tool_with_glob_filter(self, tmp_path: Path) -> None:
        """Test Grep tool shows glob filter when present."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "name": "Grep",
                                    "input": {
                                        "pattern": "TODO",
                                        "glob": "*.py",
                                    },
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "/TODO/" in html_text
        assert "glob=*.py" in html_text

    def test_tool_result_empty_content(self, tmp_path: Path) -> None:
        """Test tool result with empty content shows (empty)."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "content": "",
                                    "is_error": False,
                                }
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "(empty)" in html_text

    def test_user_event_with_non_tool_result_content(
        self, tmp_path: Path
    ) -> None:
        """Test user event with non-tool-result content blocks."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "user",
                        "message": {
                            "content": [
                                {"type": "text", "text": "user text"},
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "No content" in html_text

    def test_assistant_event_with_unrecognized_block_types(
        self, tmp_path: Path
    ) -> None:
        """Test assistant event ignores unrecognized block types."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [
                                {"type": "image", "data": "base64stuff"},
                            ]
                        },
                    },
                ],
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/actions")
        html_text = response.get_data(as_text=True)

        assert "No content" in html_text


class TestNetworkLogsPage:
    """Tests for network logs viewer page."""

    def test_network_logs_endpoint(self, tmp_path: Path) -> None:
        """Test /task/<id>/network returns network logs page."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create network log file
        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text(
            "=== TASK START 2026-02-03T12:34:56Z ===\n"
            "allowed GET https://api.github.com/repos -> 200\n"
            "BLOCKED GET https://evil.com/exfiltrate -> 403\n"
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        assert response.status_code == 200
        assert response.content_type == "text/html; charset=utf-8"

        html = response.get_data(as_text=True)
        assert "Network Logs: abc12345" in html
        assert "Test Subject" in html
        assert "TASK START" in html
        assert "api.github.com" in html
        assert "evil.com" in html

    def test_network_logs_not_found(self) -> None:
        """Test /task/<id>/network returns 404 for nonexistent task."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/task/nonexistent/network")
        assert response.status_code == 404

    def test_network_logs_no_session_dir(self) -> None:
        """Test network logs page shows message when session dir not found."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        server = DashboardServer(tracker)  # No work_dirs
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "No network logs available" in html

    def test_network_logs_empty_file(self, tmp_path: Path) -> None:
        """Test network logs page shows message for empty log file."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create empty network log file
        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "Network log is empty" in html

    def test_network_logs_no_log_file(self, tmp_path: Path) -> None:
        """Test network logs page shows message when log file doesn't exist."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()
        # Don't create log file

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "No network logs available" in html

    def test_network_logs_highlights_blocked(self, tmp_path: Path) -> None:
        """Test BLOCKED entries have special styling class."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text(
            "allowed GET https://api.github.com -> 200\n"
            "BLOCKED GET https://evil.com -> 403\n"
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Check that blocked entries have the blocked class
        assert 'class="log-line blocked"' in html
        assert 'class="log-line allowed"' in html

    def test_network_logs_highlights_task_start(self, tmp_path: Path) -> None:
        """Test TASK START lines have blue styling."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("=== TASK START 2026-02-03T12:34:56Z ===\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Check that task start has the task-start class (blue color)
        assert 'class="log-line task-start"' in html

    def test_network_logs_scrolls_to_end(self, tmp_path: Path) -> None:
        """Test network logs page scrolls to end by default."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("allowed GET https://api.github.com -> 200\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Check for scroll-to-end script
        assert "window.scrollTo(0, document.body.scrollHeight)" in html

    def test_network_logs_link_from_detail(self, tmp_path: Path) -> None:
        """Test task detail page has link to network logs viewer."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        store = SessionStore(conv_dir)
        store.add_reply(
            "abc12345",
            {
                "session_id": "sess_123",
                "duration_ms": 1000,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
            },
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345")
        html = response.get_data(as_text=True)

        # Check link to network logs page exists
        assert "/task/abc12345/network" in html
        assert "View Network Logs" in html

    def test_network_logs_escapes_html(self, tmp_path: Path) -> None:
        """Test network logs page escapes HTML in log content."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text(
            "allowed GET https://example.com/<script>alert(1)</script> -> 200\n"
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Check that malicious script tag in log content is escaped
        # Note: page has its own <script> tag for scroll-to-end functionality
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_network_logs_back_link(self, tmp_path: Path) -> None:
        """Test network logs page has back link to task detail."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("allowed GET https://api.github.com -> 200\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Check back link
        assert 'href="/task/abc12345"' in html
        assert "&larr; Back" in html

    def test_network_logs_read_error(self, tmp_path: Path) -> None:
        """Test network logs page handles read errors gracefully."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Create a log file that's a directory to trigger OSError
        log_path = conv_dir / "network-sandbox.log"
        log_path.mkdir()

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        # Should fallback to "no logs available" on read error
        assert "No network logs available" in html

    def test_network_logs_skips_empty_lines(self, tmp_path: Path) -> None:
        """Test network logs page skips empty lines in log content."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text(
            "allowed GET https://api.github.com -> 200\n"
            "\n"
            "allowed GET https://api.example.com -> 200\n"
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Both lines should be present, empty line should be skipped
        assert "api.github.com" in html
        assert "api.example.com" in html
        # Count log-line divs - should be exactly 2
        assert html.count('class="log-line') == 2

    def test_network_logs_unknown_format(self, tmp_path: Path) -> None:
        """Test network logs page handles unknown log format."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("some unknown log format\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Unknown format should be rendered as plain log-line
        assert "some unknown log format" in html
        # Should NOT have allowed/blocked/header classes
        assert 'class="log-line">' in html

    def test_network_logs_highlights_error_responses(
        self, tmp_path: Path
    ) -> None:
        """Test error responses (4xx/5xx) have orange styling."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text(
            "allowed GET https://api.github.com -> 200\n"
            "allowed GET https://api.example.com -> 404\n"
            "allowed POST https://api.example.com/fail -> 500\n"
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # 200 should have allowed class (green)
        assert 'class="log-line allowed"' in html
        # 404 and 500 should have error class (orange)
        assert html.count('class="log-line error"') == 2

    def test_network_logs_bold_error_status_code(self, tmp_path: Path) -> None:
        """Test error status codes are bold in error lines."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("allowed GET https://api.example.com -> 500\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Status code should be wrapped in highlight span
        assert '<span class="highlight">500</span>' in html

    def test_network_logs_bold_blocked(self, tmp_path: Path) -> None:
        """Test BLOCKED text is bold in blocked lines."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("BLOCKED GET https://evil.com -> 403\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # BLOCKED should be wrapped in highlight span
        assert '<span class="highlight">BLOCKED</span>' in html

    def test_network_logs_3xx_not_error(self, tmp_path: Path) -> None:
        """Test 3xx responses are treated as success, not error."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text(
            "allowed GET https://api.example.com -> 301\n"
            "allowed GET https://api.example.com -> 304\n"
        )

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # 3xx responses should have allowed class, not error
        assert html.count('class="log-line allowed"') == 2
        assert 'class="log-line error"' not in html

    def test_network_logs_error_css_styling(self, tmp_path: Path) -> None:
        """Test error class has orange styling in CSS."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("allowed GET https://api.example.com -> 500\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Check that error styling is defined in CSS
        assert ".log-line.error" in html
        # Check highlight styling is defined
        assert ".highlight" in html

    def test_network_logs_allowed_without_status_code(
        self, tmp_path: Path
    ) -> None:
        """Test allowed lines without status code are rendered as allowed."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")

        conv_dir = tmp_path / "abc12345"
        conv_dir.mkdir()

        # Some hypothetical malformed log line without status code
        log_path = conv_dir / "network-sandbox.log"
        log_path.write_text("allowed GET https://api.example.com\n")

        server = DashboardServer(tracker, work_dirs=[tmp_path])
        client = Client(server._wsgi_app)

        response = client.get("/task/abc12345/network")
        html = response.get_data(as_text=True)

        # Line without status code should be rendered as allowed (green)
        assert 'class="log-line allowed"' in html
        # Should NOT be rendered as error
        assert 'class="log-line error"' not in html
