# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for new Slack conversation flow.

Tests the complete lifecycle of a new Slack conversation:
1. Slack message received
2. Acknowledgment posted to thread
3. Conversation directory created
4. Claude executed
5. Reply posted to thread with results
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import wait_for_conv_completion
from .environment import IntegrationEnvironment


MOCK_CODE = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Task completed successfully"),
    generate_result_event(session_id, "Done"),
]
"""


class TestSlackNewConversation:
    """Test complete new Slack conversation lifecycle."""

    def test_new_message_creates_conversation_and_replies(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Slack message creates conversation, ack posted, reply posted."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            # Inject a user message
            slack_env.slack_server.inject_user_message(
                user_id="U_ALICE",
                text=MOCK_CODE,
                thread_ts="1700000000.000001",
            )

            # Wait for acknowledgment message
            ack = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and "started working" in m.kwargs.get("text", "").lower()
                ),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive Slack acknowledgment"

            # Wait for reply message with Claude's output
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and m is not ack
                    and (
                        "completed" in m.kwargs.get("text", "").lower()
                        or any(
                            "completed" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None, "Did not receive Slack reply"

            # Verify messages were posted to the correct thread
            assert reply.kwargs.get("thread_ts") == "1700000000.000001"
            assert reply.kwargs.get("channel") == "D_TEST_DM"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_conversation_directory_created(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Slack conversation creates workspace directory with git repo."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_BOB", display_name="Bob")

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_BOB",
                text=MOCK_CODE,
                thread_ts="1700000000.000002",
            )

            # Wait for reply (means execution finished)
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "completed" in m.kwargs.get("text", "").lower()
                        or any(
                            "completed" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None

            # Verify a conversation directory was created
            conversations_dir = slack_env.storage_dir / "conversations"
            conv_dirs = [
                d
                for d in conversations_dir.iterdir()
                if d.is_dir() and len(d.name) == 8
            ]
            assert len(conv_dirs) >= 1, "No conversation directory created"

            # Verify it has a workspace with git
            conv_dir = conv_dirs[0]
            workspace = conv_dir / "workspace"
            assert workspace.exists(), "Workspace not created"
            assert (workspace / ".git").exists(), "Not a git repository"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_dashboard_tracks_slack_task(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Dashboard tracker records Slack task lifecycle."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user(
            "U_CHARLIE", display_name="Charlie"
        )

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_CHARLIE",
                text=MOCK_CODE,
                thread_ts="1700000000.000003",
            )

            # Wait for reply
            slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "completed" in m.kwargs.get("text", "").lower()
                        or any(
                            "completed" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )

            # Find the conversation via tracker
            tasks = service.tracker.get_all_tasks()
            assert len(tasks) >= 1, f"Expected task in tracker, got {tasks}"

            # Find our task
            conv_id = tasks[0].conversation_id
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None
            assert task.status.value == "completed"
            assert task.succeeded is True

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
