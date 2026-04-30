# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack error handling.

Tests that execution errors (Claude crashes, timeouts) result in
error messages posted to the Slack thread.
"""

import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import CompletionReason, TaskStatus

from .environment import IntegrationEnvironment


class TestSlackErrorHandling:
    """Test error handling through the Slack channel."""

    def test_execution_crash_posts_error(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Claude crash results in error message posted to thread."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        mock_code = """
events = [
    generate_system_event(session_id),
]
# Simulate crash with no result event
sys.exit(1)
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_ALICE",
                text=mock_code,
                thread_ts="1700000000.000030",
            )

            # Wait for error message
            error_msg = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (m.contains("error") or m.contains("failed"))
                ),
                timeout=30.0,
            )
            assert error_msg is not None, "Did not receive error message"
            assert error_msg.kwargs.get("thread_ts") == "1700000000.000030"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_error_result_posts_error(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Claude returning an error result sends error message."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_BOB", display_name="Bob")

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_result_event(session_id, "Something went wrong", is_error=True),
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
                thread_ts="1700000000.000031",
            )

            # Wait for any response (could be error or regular reply)
            response = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and m.text() != ""
                    and not m.contains("started working")
                ),
                timeout=30.0,
            )
            assert response is not None, "Did not receive any response"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_channel_send_error_tracks_reason(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Channel send failure records CompletionReason.CHANNEL_ERROR."""
        from airut.gateway.channel import ChannelSendError

        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user(
            "U_CHARLIE", display_name="Charlie"
        )

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Channel error Slack test"),
    generate_result_event(session_id, "Done"),
]
"""

        service = slack_env.create_service()

        # Patch the Slack adapter's send_reply to simulate a delivery
        # failure (e.g. Slack API error) after successful execution.
        slack_adapter = service.repo_handlers["test"].adapters["slack"]
        original_send_reply = slack_adapter.send_reply

        def failing_send_reply(*args, **kwargs):
            raise ChannelSendError("Slack API error: channel_not_found")

        slack_adapter.send_reply = failing_send_reply

        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_CHARLIE",
                text=mock_code,
                thread_ts="1700000000.000032",
            )

            # Poll tracker for CHANNEL_ERROR completion
            deadline = time.monotonic() + 30.0
            channel_error_task = None
            while time.monotonic() < deadline:
                for task in service.tracker.get_all_tasks():
                    if (
                        task.status == TaskStatus.COMPLETED
                        and task.completion_reason
                        == CompletionReason.CHANNEL_ERROR
                    ):
                        channel_error_task = task
                        break
                if channel_error_task:
                    break
                time.sleep(0.1)

            assert channel_error_task is not None, (
                "No CHANNEL_ERROR completion reason found. Tasks: "
                + repr(
                    [
                        (t.conversation_id, t.completion_reason)
                        for t in service.tracker.get_all_tasks()
                    ]
                )
            )
            assert channel_error_task.succeeded is False

        finally:
            slack_adapter.send_reply = original_send_reply
            service.stop()
            service_thread.join(timeout=10.0)
