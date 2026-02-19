# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack conversation resumption.

Tests that follow-up messages in the same Slack thread resume the
existing conversation (same conversation ID, session restored).
"""

import json
import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .environment import IntegrationEnvironment


FIRST_MOCK_CODE = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First task done"),
    generate_result_event(session_id, "First complete"),
]
"""

SECOND_MOCK_CODE = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second task done"),
    generate_result_event(session_id, "Second complete"),
]
"""


class TestSlackConversationResume:
    """Test conversation resumption via Slack thread mapping."""

    def test_same_thread_resumes_conversation(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Second message in same thread reuses the conversation ID."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        thread_ts = "1700000000.000010"

        # ---- First message ----
        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_ALICE",
                text=FIRST_MOCK_CODE,
                thread_ts=thread_ts,
            )

            # Wait for first reply
            reply1 = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "first task" in m.kwargs.get("text", "").lower()
                        or any(
                            "first task" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply1 is not None, "Did not receive first reply"

            # Get conversation ID from tracker
            tasks = service.tracker.get_all_tasks()
            assert len(tasks) >= 1
            conv_id = tasks[0].conversation_id
            assert conv_id is not None

            # Verify conversation.json exists with one reply
            conv_file = (
                slack_env.storage_dir
                / "conversations"
                / conv_id
                / "conversation.json"
            )
            assert conv_file.exists()
            with conv_file.open() as f:
                data = json.load(f)
            assert len(data["replies"]) == 1

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

        # ---- Second message in same thread ----
        slack_env.slack_server.clear_sent()

        service2 = slack_env.create_service()
        service_thread2 = threading.Thread(target=service2.start, daemon=True)
        service_thread2.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_ALICE",
                text=SECOND_MOCK_CODE,
                thread_ts=thread_ts,  # Same thread
            )

            reply2 = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "second task" in m.kwargs.get("text", "").lower()
                        or any(
                            "second task" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply2 is not None, "Did not receive second reply"

            # Verify conversation.json now has two replies
            with conv_file.open() as f:
                data = json.load(f)
            assert len(data["replies"]) == 2, (
                f"Expected 2 replies, got {len(data['replies'])}"
            )

        finally:
            service2.stop()
            service_thread2.join(timeout=10.0)
