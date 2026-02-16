# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the actions viewer page (event rendering)."""

from werkzeug.test import Client

from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import TaskTracker
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

    def test_in_progress_shows_events_before_reply_completes(
        self, harness: DashboardHarness
    ) -> None:
        """Test actions page shows events for in-progress tasks.

        When a task is running, events are streamed to events.jsonl but
        no reply has been added to conversation.json yet. The actions page
        must still render those events instead of showing "No actions
        recorded".

        Regression test for PR #72 which split context.json into
        conversation.json + events.jsonl.
        """
        # Simulate in-progress execution: events written to event log
        # but NO reply added to conversation store yet
        from tests.dashboard.conftest import parse_events

        events = parse_events(
            {"type": "system", "subtype": "init", "tools": ["Bash", "Read"]},
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
                            "content": "file1.txt\nfile2.txt",
                        }
                    ]
                },
            },
        )

        # Write events to event log (simulating streaming during execution)
        harness.event_log.start_new_reply()
        for event in events:
            harness.event_log.append_event(event)

        # Do NOT call harness.store.add_reply() — reply hasn't completed yet

        html = harness.get_html("/conversation/abc12345/actions")

        # Must NOT show "No actions recorded" — events are streaming
        assert "No actions recorded" not in html

        # Must show the streamed events
        assert "system:" in html
        assert "Bash" in html
        assert "ls -la" in html
        assert "file1.txt" in html

    def test_not_found(self) -> None:
        """Test actions page returns 404 for nonexistent task."""
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)

        response = client.get("/conversation/nonexistent/actions")
        assert response.status_code == 404

    def test_in_progress_shows_request_text(
        self, harness: DashboardHarness
    ) -> None:
        """Test actions page shows user prompt for in-progress tasks.

        When a task is running, the user's prompt should be visible even
        before the reply completes (i.e., before conversation.json has the
        reply with request_text).

        Regression test for prompt visibility after PR #72.
        """
        from tests.dashboard.conftest import parse_events

        # Persist the pending request text (simulates what gateway does
        # before execution starts via conversation_store.set_pending_request)
        harness.store.set_pending_request(
            harness.CONV_ID, "Please fix the login bug"
        )

        events = parse_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            {
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": "Looking into it."}]
                },
            },
        )

        # Write events to event log (simulating streaming during execution)
        harness.event_log.start_new_reply()
        for event in events:
            harness.event_log.append_event(event)

        # Do NOT call harness.store.add_reply() — reply hasn't completed yet

        html = harness.get_html("/conversation/abc12345/actions")

        # Must show the user's prompt even during in-progress execution
        assert "prompt" in html
        assert "Please fix the login bug" in html

    def test_no_events_and_no_replies(self) -> None:
        """Test actions page shows 'no actions' when truly empty.

        When there are no events in the event log and no replies in
        conversation.json, the page should show "No actions recorded".
        """
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

        from airut.claude_output.types import Usage
        from airut.conversation import ReplySummary

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


class TestActionsPageE2E:
    """End-to-end tests for the actions page.

    Tests the full flow from HTTP request through data loading and
    rendering, covering realistic multi-reply conversations and
    lifecycle transitions that have caused regressions.
    """

    def test_complete_single_reply_with_prompt(
        self, harness: DashboardHarness
    ) -> None:
        """Test completed reply shows both prompt and events."""
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            {
                "type": "assistant",
                "message": {"content": [{"type": "text", "text": "Done."}]},
            },
            result_event(),
            request_text="Fix the login page CSS",
        )

        html = harness.get_html("/conversation/abc12345/actions")

        # Structure checks
        assert "Reply #1" in html
        assert "Fix the login page CSS" in html
        assert "ev-request-label" in html
        assert "system:" in html
        assert "Done." in html
        assert "result:" in html
        assert "No actions recorded" not in html

    def test_multi_reply_conversation(self, harness: DashboardHarness) -> None:
        """Test conversation with multiple completed replies.

        Each reply should have its own section with correct numbering,
        prompt, and events.
        """
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            result_event(),
            request_text="First request",
        )
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Read"]},
            {
                "type": "assistant",
                "message": {"content": [{"type": "text", "text": "Updated."}]},
            },
            result_event(),
            request_text="Second request",
        )

        html = harness.get_html("/conversation/abc12345/actions")

        assert "Reply #1" in html
        assert "Reply #2" in html
        assert "First request" in html
        assert "Second request" in html
        assert "Updated." in html

    def test_completed_reply_then_in_progress(
        self, harness: DashboardHarness
    ) -> None:
        """Test page with one completed reply and one in-progress.

        The completed reply should show its prompt from conversation.json.
        The in-progress reply should show its prompt from
        pending_request_text in conversation.json.
        """
        from tests.dashboard.conftest import parse_events

        # First reply: completed
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            result_event(),
            request_text="Initial setup request",
        )

        # Second reply: in-progress (events only, no completed reply)
        harness.store.set_pending_request(harness.CONV_ID, "Follow-up request")

        events = parse_events(
            {"type": "system", "subtype": "init", "tools": ["Read"]},
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tu_1",
                            "name": "Read",
                            "input": {"file_path": "/workspace/main.py"},
                        }
                    ]
                },
            },
        )
        harness.event_log.start_new_reply()
        for event in events:
            harness.event_log.append_event(event)

        html = harness.get_html("/conversation/abc12345/actions")

        # Completed reply
        assert "Reply #1" in html
        assert "Initial setup request" in html
        # In-progress reply
        assert "Reply #2" in html
        assert "in progress" in html
        assert "Follow-up request" in html
        assert "/workspace/main.py" in html

    def test_in_progress_no_events_yet(self, harness: DashboardHarness) -> None:
        """Test page when task just started with no events or replies.

        When pending_request_text is set but no streaming events have
        arrived yet, the page should still show the prompt in an
        in-progress section rather than "No actions recorded".
        """
        harness.store.set_pending_request(harness.CONV_ID, "Some request")

        html = harness.get_html("/conversation/abc12345/actions")
        assert "No actions recorded" not in html
        assert "Some request" in html
        assert "in progress" in html
        assert "Reply #1" in html

    def test_completed_reply_then_pending_no_events(
        self, harness: DashboardHarness
    ) -> None:
        """Test page with completed reply then pending request, no new events.

        When replying to an existing conversation: a completed reply exists,
        set_pending_request is called, start_new_reply writes a delimiter,
        but no events have been written to the event log yet. The pending
        request should still be visible.

        Regression test: pending_request_text was not shown on the actions
        page when replying to an existing conversation because the empty
        event group was skipped by read_all(), making in_progress_groups
        empty, which should fall through to the elif branch — but didn't
        when event_groups had the same length as replies.
        """
        # First reply: completed (writes events to event log)
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            result_event(),
            request_text="Initial request",
        )

        # Second reply starts: pending request set, delimiter written,
        # but NO events appended yet (the exact state when user reports
        # not seeing the prompt)
        harness.store.set_pending_request(
            harness.CONV_ID, "Follow-up pending request"
        )
        harness.event_log.start_new_reply()

        html = harness.get_html("/conversation/abc12345/actions")

        # Completed reply should show
        assert "Reply #1" in html
        assert "Initial request" in html
        # Pending request must be visible even without new events
        assert "Follow-up pending request" in html
        assert "in progress" in html

    def test_html_escaping_in_prompt(self, harness: DashboardHarness) -> None:
        """Test that user prompts are HTML-escaped to prevent XSS."""
        from tests.dashboard.conftest import parse_events

        harness.store.set_pending_request(
            harness.CONV_ID,
            '<script>alert("xss")</script>',
        )

        events = parse_events(
            {"type": "system", "subtype": "init", "tools": []},
        )
        harness.event_log.start_new_reply()
        for event in events:
            harness.event_log.append_event(event)

        html = harness.get_html("/conversation/abc12345/actions")

        # Must be escaped, not raw — check for the specific injected tag
        assert '<script>alert("xss")</script>' not in html
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html

    def test_completed_reply_prompt_from_conversation_json(
        self, harness: DashboardHarness
    ) -> None:
        """Test that completed replies use request_text from their ReplySummary.

        Even if pending_request_text is set (e.g., from a new in-progress
        request), completed replies should use the request_text stored in
        their ReplySummary.
        """
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": []},
            result_event(),
            request_text="Original prompt from conversation.json",
        )

        # Simulate a new request writing pending_request_text
        harness.store.set_pending_request(
            harness.CONV_ID, "New prompt for next request"
        )

        html = harness.get_html("/conversation/abc12345/actions")

        # Completed reply shows its own request_text
        assert "Original prompt from conversation.json" in html

    def test_error_reply_shows_prompt(self, harness: DashboardHarness) -> None:
        """Test that error replies still show the user's prompt."""
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": []},
            result_event(subtype="error", is_error=True),
            request_text="Request that caused an error",
        )

        html = harness.get_html("/conversation/abc12345/actions")

        assert "Request that caused an error" in html
        assert "Reply #1" in html
        assert "reply-section" in html


class TestSSEServerSideRendering:
    """Tests for server-side HTML rendering in SSE streams.

    Verifies that SSE events are rendered server-side as HTML
    fragments rather than raw JSON, ensuring consistent output
    between initial page load and live streaming.
    """

    def test_sse_script_is_minimal(self, harness: DashboardHarness) -> None:
        """Test SSE script has no client-side rendering logic.

        When a task is in-progress, the actions page includes SSE
        JavaScript that inserts pre-rendered HTML fragments from
        the server. It should not contain any event rendering logic.
        """
        # Mark task as in-progress so SSE script is included
        harness.tracker.start_task(harness.CONV_ID)

        html = harness.get_html("/conversation/abc12345/actions")

        # The SSE script should use the 'html' event type
        assert "addEventListener('html'" in html
        # Should NOT contain client-side rendering functions
        assert "renderStreamEvent" not in html
        assert "escapeHtml" not in html
        assert "formatDiffBlock" not in html

    def test_sse_offset_matches_event_log_size(
        self, harness: DashboardHarness
    ) -> None:
        """SSE starts from current event log byte offset, not zero.

        When the page loads, all existing events are server-rendered in
        the initial HTML. The SSE script must start from the current
        event log byte offset so it only receives NEW events, avoiding
        duplicate content that hides the pending request prompt.

        Regression test: SSE started from offset 0, causing all events
        to be appended again as raw HTML fragments after the structured
        timeline (which included the pending request prompt). Auto-scroll
        then moved past the pending request to the duplicated events.
        """
        # Write some events so the event log has a non-zero byte offset
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            result_event(),
            request_text="First request",
        )

        # Start a follow-up reply (task must be in-progress for SSE)
        harness.tracker.start_task(harness.CONV_ID)
        harness.store.set_pending_request(harness.CONV_ID, "Follow-up request")
        harness.event_log.start_new_reply()

        # Get the actual byte offset of the event log
        file_size = harness.event_log.file_path.stat().st_size
        assert file_size > 0

        html = harness.get_html("/conversation/abc12345/actions")

        # SSE script must start from the current offset, not 0
        assert f"var currentOffset = {file_size}" in html
        assert "var currentOffset = 0" not in html

    def test_sse_catchup_does_not_duplicate_events(
        self, harness: DashboardHarness
    ) -> None:
        """SSE catch-up from page offset returns no already-rendered events.

        When the actions page loads, events are server-rendered in the
        initial HTML. The SSE stream must start from the byte offset at
        render time. Calling tail() at that offset must return zero
        events, proving the SSE catch-up will not duplicate content.

        Regression test: with offset=0, SSE re-sent ALL events as raw
        HTML fragments after the structured timeline, duplicating them.
        """
        from airut.sandbox import EventLog

        # Write events to the event log
        harness.add_events(
            {"type": "system", "subtype": "init", "tools": ["Bash"]},
            {
                "type": "assistant",
                "message": {
                    "content": [{"type": "text", "text": "Working on it."}]
                },
            },
            result_event(),
            request_text="Fix the bug",
        )

        # Start a follow-up reply (task in-progress enables SSE)
        harness.tracker.start_task(harness.CONV_ID)
        harness.store.set_pending_request(harness.CONV_ID, "Next request")
        harness.event_log.start_new_reply()

        # Render the page — captures offset in SSE script
        file_size = harness.event_log.file_path.stat().st_size
        html = harness.get_html("/conversation/abc12345/actions")

        # Page must contain the server-rendered events
        assert "Working on it." in html
        assert "Next request" in html

        # SSE catch-up from the page offset must return NO events
        # (all events are already rendered in the initial HTML)
        event_log = EventLog(harness.conv_dir)
        events, _ = event_log.tail(file_size)
        assert events == [], (
            "SSE catch-up from page offset must not return already-rendered "
            f"events, but got {len(events)} events"
        )

        # Verify that offset=0 WOULD return events (the old bug)
        events_from_zero, _ = event_log.tail(0)
        assert len(events_from_zero) > 0, (
            "tail(0) should return events, confirming offset=0 would "
            "cause duplication"
        )
