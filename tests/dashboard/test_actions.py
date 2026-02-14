# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the actions viewer page (event rendering)."""

from werkzeug.test import Client

from lib.dashboard.server import DashboardServer
from lib.dashboard.tracker import TaskTracker
from tests.dashboard.conftest import DashboardHarness, result_event


class TestActionsPageEndpoint:
    """Tests for the /conversation/<id>/actions endpoint."""

    def test_returns_200_with_events(self, harness: DashboardHarness) -> None:
        """Test actions page renders with session events."""
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            {
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": "Hello, I'll help."}]
                },
            },
            result_event(duration_ms=5000, total_cost_usd=0.05, num_turns=3),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "Actions: abc12345" in html
        assert "Test Subject" in html
        assert "Reply #1" in html

    def test_not_found(self) -> None:
        """Test actions page returns 404 for nonexistent task."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/nonexistent/actions")
        assert response.status_code == 404

    def test_no_session(self) -> None:
        """Test actions page shows 'no actions' without session data."""
        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test Subject")
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/abc12345/actions")
        html = response.get_data(as_text=True)
        assert "No actions recorded" in html

    def test_toggle_script_present(self, harness: DashboardHarness) -> None:
        """Test actions page includes toggleEvent JavaScript."""
        harness.add_events(result_event())

        html = harness.get_html("/conversation/abc12345/actions")
        assert "toggleEvent" in html

    def test_detail_page_has_actions_link(
        self, harness: DashboardHarness
    ) -> None:
        """Test task detail page links to actions viewer."""
        harness.add_events(result_event())

        html = harness.get_html("/conversation/abc12345")
        assert "/conversation/abc12345/actions" in html
        assert "View Actions" in html


class TestEventRendering:
    """Tests for rendering individual event types."""

    def test_all_event_types_rendered(self, harness: DashboardHarness) -> None:
        """Test system, assistant, user, and result events all render."""
        harness.add_events(
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
                            "id": "tu_1",
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
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": "file1.txt",
                        }
                    ]
                },
            },
            {
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": "Found 1 file."}]
                },
            },
            result_event(
                result="Found 1 file.",
                duration_ms=5000,
                total_cost_usd=0.05,
                num_turns=2,
            ),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "system:" in html
        assert "init" in html
        assert "Bash" in html
        assert "ls -la" in html
        assert "file1.txt" in html
        assert "Found 1 file." in html
        assert "result:" in html

    def test_unknown_event_type(self, harness: DashboardHarness) -> None:
        """Test unknown event types render as collapsible raw JSON."""
        harness.add_events(
            {"type": "ping", "seq": 42},
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "ping" in html
        assert "toggleEvent" in html

    def test_empty_events_list(self, harness: DashboardHarness) -> None:
        """Test rendering with reply but no events in event log."""
        from datetime import UTC, datetime

        from lib.claude_output.types import Usage
        from lib.conversation import ReplySummary

        reply = ReplySummary(
            session_id="",
            timestamp=datetime.now(tz=UTC).isoformat(),
            duration_ms=0,
            total_cost_usd=0.0,
            num_turns=0,
            is_error=False,
            usage=Usage(),
        )
        harness.store.add_reply(harness.CONV_ID, reply)

        html = harness.get_html("/conversation/abc12345/actions")
        assert "No events recorded" in html

    def test_result_event_basic(self, harness: DashboardHarness) -> None:
        """Test result event renders with result type label."""
        harness.add_events(result_event())

        html = harness.get_html("/conversation/abc12345/actions")
        assert "result:" in html

    def test_result_event_truncates_long_text(
        self, harness: DashboardHarness
    ) -> None:
        """Test result event truncates long result text."""
        harness.add_events(result_event(result="x" * 600))

        html = harness.get_html("/conversation/abc12345/actions")
        assert "..." in html

    def test_system_event_many_tools(self, harness: DashboardHarness) -> None:
        """Test system event with many tools truncates display."""
        many_tools = [f"Tool{i}" for i in range(25)]
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": many_tools},
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "+5 more" in html


class TestAssistantEventContent:
    """Tests for assistant event content rendering edge cases."""

    def test_empty_content(self, harness: DashboardHarness) -> None:
        """Test assistant event with empty content blocks."""
        harness.add_events(
            {"type": "assistant", "message": {"content": []}},
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "No content" in html

    def test_unrecognized_block_types(self, harness: DashboardHarness) -> None:
        """Test assistant event ignores unrecognized block types."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [{"type": "image", "data": "base64stuff"}]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "No content" in html

    def test_only_tool_result_blocks(self, harness: DashboardHarness) -> None:
        """Test assistant event with only ToolResultBlock hits fallback."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": "some result",
                            "is_error": False,
                        },
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "No content" in html


class TestUserEventContent:
    """Tests for user event content rendering."""

    def test_empty_content(self, harness: DashboardHarness) -> None:
        """Test user event with empty content blocks."""
        harness.add_events(
            {"type": "user", "message": {"content": []}},
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "No content" in html

    def test_non_tool_result_content(self, harness: DashboardHarness) -> None:
        """Test user event with non-tool-result content blocks."""
        harness.add_events(
            {
                "type": "user",
                "message": {"content": [{"type": "text", "text": "user text"}]},
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "No content" in html


class TestToolRenderers:
    """Tests for specialized tool renderers."""

    def test_bash_command_and_description(
        self, harness: DashboardHarness
    ) -> None:
        """Test Bash tool shows command and description."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Bash",
                            "input": {
                                "command": "ls -la",
                                "description": "List all files",
                            },
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "Bash" in html
        assert "List all files" in html
        assert "bash-cmd" in html
        assert "ls -la" in html

    def test_bash_timeout(self, harness: DashboardHarness) -> None:
        """Test Bash tool displays timeout when present."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Bash",
                            "input": {
                                "command": "sleep 60",
                                "timeout": 120000,
                            },
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "timeout=120000ms" in html
        assert "sleep 60" in html

    def test_read_with_offset_limit(self, harness: DashboardHarness) -> None:
        """Test Read tool shows offset/limit when present."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
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
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "/f.py" in html
        assert "offset=100" in html
        assert "limit=50" in html

    def test_edit_replace_all(self, harness: DashboardHarness) -> None:
        """Test Edit tool shows replace_all flag."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
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
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "(replace_all)" in html

    def test_edit_truncates_long_diff(self, harness: DashboardHarness) -> None:
        """Test Edit tool truncates long diffs."""
        old_text = "\n".join(f"old line {i}" for i in range(25))
        new_text = "\n".join(f"new line {i}" for i in range(25))

        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
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
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "- old line 0" in html
        assert "- old line 19" in html
        assert "- old line 20" not in html
        assert "(5 more lines)" in html
        assert "+ new line 0" in html

    def test_grep_with_glob_filter(self, harness: DashboardHarness) -> None:
        """Test Grep tool shows glob filter when present."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Grep",
                            "input": {"pattern": "TODO", "glob": "*.py"},
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "/TODO/" in html
        assert "glob=*.py" in html

    def test_various_tools(self, harness: DashboardHarness) -> None:
        """Test specialized rendering for various tools."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Write",
                            "input": {
                                "file_path": "/tmp/out.txt",
                                "content": "line1\nline2\n",
                            },
                        },
                        {
                            "type": "tool_use",
                            "id": "tu_2",
                            "name": "Edit",
                            "input": {
                                "file_path": "/tmp/ed.txt",
                                "old_string": "old",
                                "new_string": "new",
                            },
                        },
                        {
                            "type": "tool_use",
                            "id": "tu_3",
                            "name": "Grep",
                            "input": {"pattern": "foo", "path": "/src"},
                        },
                        {
                            "type": "tool_use",
                            "id": "tu_4",
                            "name": "Glob",
                            "input": {"pattern": "*.py"},
                        },
                        {
                            "type": "tool_use",
                            "id": "tu_5",
                            "name": "Task",
                            "input": {"description": "search code"},
                        },
                        {
                            "type": "tool_use",
                            "id": "tu_6",
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
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")

        # Write
        assert "/tmp/out.txt" in html
        assert "3 lines" in html
        # Edit
        assert "/tmp/ed.txt" in html
        assert "diff-removed" in html
        assert "diff-added" in html
        # Grep
        assert "/foo/" in html
        # Glob
        assert "*.py" in html
        # Task
        assert "search code" in html
        # TodoWrite
        assert "[in_progress] Do stuff" in html

    def test_unknown_tool_shows_json(self, harness: DashboardHarness) -> None:
        """Test unknown tool renders input as raw JSON."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "CustomTool",
                            "input": {"url": "https://example.com"},
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "CustomTool" in html
        assert "https://example.com" in html
        assert "tool-input-json" in html

    def test_tool_use_block(self, harness: DashboardHarness) -> None:
        """Test rendering tool_use blocks in assistant events."""
        harness.add_events(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Read",
                            "input": {"file_path": "/test.txt"},
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "Read" in html
        assert "/test.txt" in html


class TestToolResultRendering:
    """Tests for tool result rendering."""

    def test_truncates_large_output(self, harness: DashboardHarness) -> None:
        """Test large tool results are truncated in display."""
        large_content = "\n".join(f"line {i}" for i in range(30))
        harness.add_events(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": large_content,
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "10 more lines" in html

    def test_error_indication(self, harness: DashboardHarness) -> None:
        """Test tool result errors are displayed with error indication."""
        harness.add_events(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": "Permission denied",
                            "is_error": True,
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "(error)" in html
        assert "Permission denied" in html

    def test_error_class_on_container(self, harness: DashboardHarness) -> None:
        """Test event container has error class when tool result has error."""
        harness.add_events(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": "Command failed",
                            "is_error": True,
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert 'class="event error"' in html

    def test_no_error_class_on_success(self, harness: DashboardHarness) -> None:
        """Test event container has no error class for successful tool."""
        harness.add_events(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": "Success output",
                            "is_error": False,
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert 'class="event error"' not in html
        assert 'class="event"' in html

    def test_list_content_text_blocks(self, harness: DashboardHarness) -> None:
        """Test tool result with list content (Claude API format)."""
        harness.add_events(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": [
                                {"type": "text", "text": "First line"},
                                {"type": "text", "text": "Second line"},
                            ],
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "First line" in html
        assert "Second line" in html

    def test_list_content_plain_strings(
        self, harness: DashboardHarness
    ) -> None:
        """Test tool result with list containing plain strings."""
        harness.add_events(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": [
                                "Plain string content",
                                "Another plain string",
                            ],
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "Plain string content" in html
        assert "Another plain string" in html

    def test_empty_content_shows_empty(self, harness: DashboardHarness) -> None:
        """Test tool result with empty content shows (empty)."""
        harness.add_events(
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tu_1",
                            "content": "",
                            "is_error": False,
                        }
                    ]
                },
            },
            result_event(),
        )

        html = harness.get_html("/conversation/abc12345/actions")
        assert "(empty)" in html
