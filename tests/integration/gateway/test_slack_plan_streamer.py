# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack plan streamer lifecycle.

Tests that TodoWrite events from Claude execution produce plan
messages posted and updated in the Slack thread via chat.postMessage
and chat.update.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import wait_for_conv_completion
from .environment import IntegrationEnvironment


if TYPE_CHECKING:
    from .slack_server import SentSlackMessage


def _block_text_contains(msg: SentSlackMessage, needle: str) -> bool:
    """Check if a message's text or block text contains a substring.

    Handles both plain ``text`` kwargs and nested mrkdwn block
    structures (``{"type": "section", "text": {"type": "mrkdwn",
    "text": "..."}}``) used by the plan streamer.
    """
    needle_lower = needle.lower()
    text = msg.kwargs.get("text", "")
    if isinstance(text, str) and needle_lower in text.lower():
        return True
    for block in msg.kwargs.get("blocks", []):
        if not isinstance(block, dict):
            continue
        block_text = block.get("text", "")
        if isinstance(block_text, dict):
            block_text = block_text.get("text", "")
        if isinstance(block_text, str) and needle_lower in block_text.lower():
            return True
    return False


class TestSlackPlanStreamer:
    """Test plan streamer integration with execution pipeline."""

    def test_todo_events_streamed_to_thread(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """TodoWrite events produce plan messages via chat.update."""
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

            # Wait for final reply
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and _block_text_contains(m, "all steps")
                ),
                timeout=30.0,
            )
            assert reply is not None, "Did not receive reply"

            # Plan streamer posts initial message and may update it.
            # Look for plan-related postMessage calls (contain emoji
            # status indicators from the rendered plan).
            plan_posts = [
                m
                for m in slack_env.slack_server.get_sent_messages(
                    method="chat_postMessage"
                )
                if _block_text_contains(m, "\u26aa")
                or _block_text_contains(m, "\U0001f504")
                or _block_text_contains(m, "\u2705")
            ]
            assert len(plan_posts) >= 1, (
                f"Expected plan post, got {len(plan_posts)}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_no_todos_no_plan_message(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Execution without TodoWrite events does not post plan updates."""
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
                    and _block_text_contains(m, "no todos")
                ),
                timeout=30.0,
            )
            assert reply is not None

            # No plan-related messages should have been posted
            # (plan messages contain emoji status indicators).
            plan_posts = [
                m
                for m in slack_env.slack_server.get_sent_messages(
                    method="chat_postMessage"
                )
                if _block_text_contains(m, "\u26aa")
                or _block_text_contains(m, "\U0001f504")
                or _block_text_contains(m, "\u2705")
            ]
            assert len(plan_posts) == 0, (
                f"Expected no plan messages, got {len(plan_posts)}"
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
                    and _block_text_contains(m, "todos done")
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
