# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack plan streamer lifecycle.

Tests that TodoWrite events from Claude execution are streamed to
the Slack thread as plan blocks, and that the stream is finalized
after execution completes.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import wait_for_conv_completion
from .environment import IntegrationEnvironment


class TestSlackPlanStreamer:
    """Test plan streamer integration with execution pipeline."""

    def test_todo_events_streamed_to_thread(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """TodoWrite events produce chat_stream.append calls."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_tool_use_event("TodoWrite", {
        "todos": [
            {"content": "Step 1", "status": "in_progress"},
            {"content": "Step 2", "status": "pending"},
        ],
    }),
    generate_tool_use_event("TodoWrite", {
        "todos": [
            {"content": "Step 1", "status": "completed"},
            {"content": "Step 2", "status": "in_progress"},
        ],
    }),
    generate_assistant_event("All steps processed"),
    generate_result_event(session_id, "Done"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_ALICE",
                text=mock_code,
                thread_ts="1700000000.000060",
            )

            # Wait for reply
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "all steps" in m.kwargs.get("text", "").lower()
                        or any(
                            "all steps" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None, "Did not receive reply"

            # Check that plan stream was started and appended to
            stream_msgs = slack_env.slack_server.get_sent_messages(
                method="chat_stream.append"
            )
            # Should have at least one append (may coalesce due to debounce)
            assert len(stream_msgs) >= 1, (
                f"Expected plan stream append, got {len(stream_msgs)}"
            )

            # Check that stream was stopped
            stop_msgs = slack_env.slack_server.get_sent_messages(
                method="chat_stream.stop"
            )
            assert len(stop_msgs) >= 1, (
                "Plan stream was not finalized (no stop call)"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_no_todos_no_stream(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Execution without TodoWrite events does not start a stream."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_BOB", display_name="Bob")

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("No todos here"),
    generate_result_event(session_id, "Done"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_BOB",
                text=mock_code,
                thread_ts="1700000000.000061",
            )

            # Wait for reply
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "no todos" in m.kwargs.get("text", "").lower()
                        or any(
                            "no todos" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None

            # No stream operations should have happened
            stream_msgs = slack_env.slack_server.get_sent_messages(
                method="chat_stream.append"
            )
            assert len(stream_msgs) == 0, (
                f"Expected no stream append, got {len(stream_msgs)}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_todos_cleared_after_completion(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Todos are cleared in tracker after task completes."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user(
            "U_CHARLIE", display_name="Charlie"
        )

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_tool_use_event("TodoWrite", {
        "todos": [
            {"content": "Task A", "status": "completed"},
            {"content": "Task B", "status": "completed"},
        ],
    }),
    generate_assistant_event("Todos done"),
    generate_result_event(session_id, "Complete"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_CHARLIE",
                text=mock_code,
                thread_ts="1700000000.000062",
            )

            # Wait for reply
            slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "todos done" in m.kwargs.get("text", "").lower()
                        or any(
                            "todos done" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )

            # Find conversation and check todos are cleared
            tasks = service.tracker.get_all_tasks()
            assert len(tasks) >= 1
            conv_id = tasks[0].conversation_id
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None
            assert task.succeeded is True
            assert task.todos is None, (
                f"Todos should be None after completion, got {task.todos!r}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
