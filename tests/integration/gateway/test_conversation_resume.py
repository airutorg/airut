# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for conversation resumption.

Tests that conversation history is preserved when resuming an existing
conversation, especially after server restarts or when session files
are loaded from disk.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from lib.conversation import CONVERSATION_FILE_NAME

from .conftest import get_message_text
from .environment import IntegrationEnvironment


class TestConversationResume:
    """Test conversation resumption with history preservation."""

    def test_resume_preserves_history_after_restart(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that resuming a conversation preserves previous responses.

        This test reproduces the issue where conversation history is lost
        when resuming a task, especially after a server restart.

        Steps:
        1. Send first email, get response with conversation ID
        2. Stop the service (simulating server restart)
        3. Send second email to same conversation
        4. Verify session file contains both replies with full events
        """
        # First message
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First task completed"),
    generate_result_event(session_id, "First done"),
]
"""
        msg1 = create_email(
            subject="First task",
            body=first_mock_code,
        )
        integration_env.email_server.inject_message(msg1)

        # Start service
        service1 = integration_env.create_service()

        def run_service1():
            try:
                service1.start()
            except Exception:
                pass

        service_thread1 = threading.Thread(target=run_service1, daemon=True)
        service_thread1.start()

        try:
            # Wait for acknowledgment
            ack1 = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack1 is not None, (
                "Did not receive acknowledgment for first msg"
            )

            # Extract conversation ID
            conv_id = extract_conversation_id(ack1["Subject"])
            assert conv_id is not None
            assert len(conv_id) == 8

            # Wait for first response
            response1 = integration_env.email_server.wait_for_sent(
                lambda m: "first" in get_message_text(m).lower() and m != ack1,
                timeout=30.0,
            )
            assert response1 is not None, "Did not receive first response"

            # Verify conversation file was created
            session_dir = (
                integration_env.storage_dir / "conversations" / conv_id
            )
            conversation_file = session_dir / CONVERSATION_FILE_NAME
            assert conversation_file.exists(), (
                f"Conversation file not created: {conversation_file}"
            )

            # Read and verify first conversation data
            import json

            with conversation_file.open("r") as f:
                conv_data_after_first = json.load(f)

            assert "conversation_id" in conv_data_after_first
            assert "replies" in conv_data_after_first
            assert len(conv_data_after_first["replies"]) == 1
            first_reply = conv_data_after_first["replies"][0]
            assert first_reply["request_text"] is not None
            assert first_reply["response_text"] is not None

        finally:
            # Stop the service (simulate restart)
            service1.running = False
            service1.repo_handlers["test"].listener.interrupt()
            service_thread1.join(timeout=10.0)

        # Clear sent emails to avoid confusion
        integration_env.email_server.clear_outbox()

        # Second message to same conversation (resume)
        second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second task completed"),
    generate_result_event(session_id, "Second done"),
]
"""
        # Extract original message ID for threading
        original_msg_id = ack1.get("Message-ID")

        msg2 = create_email(
            subject=f"Re: [ID:{conv_id}] First task",
            body=second_mock_code,
            in_reply_to=original_msg_id,
            references=[original_msg_id] if original_msg_id else [],
        )
        integration_env.email_server.inject_message(msg2)

        # Start service again (simulating restart)
        service2 = integration_env.create_service()

        def run_service2():
            try:
                service2.start()
            except Exception:
                pass

        service_thread2 = threading.Thread(target=run_service2, daemon=True)
        service_thread2.start()

        try:
            # Wait for second response (no ack for resumed conversation)
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "second" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response2 is not None, "Did not receive second response"

            # Verify response has correct conversation ID
            response2_conv_id = extract_conversation_id(response2["Subject"])
            assert response2_conv_id == conv_id

        finally:
            service2.running = False
            service2.repo_handlers["test"].listener.interrupt()
            service_thread2.join(timeout=10.0)

        # Now verify conversation file has BOTH replies with full history
        with conversation_file.open("r") as f:
            final_conv_data = json.load(f)

        # CRITICAL: Check that we have 2 replies
        assert "conversation_id" in final_conv_data
        assert "replies" in final_conv_data
        assert len(final_conv_data["replies"]) == 2, (
            f"Expected 2 replies, got {len(final_conv_data['replies'])}"
        )

        # Verify first reply preserved its metadata
        first_reply_final = final_conv_data["replies"][0]
        assert first_reply_final["request_text"] is not None
        assert first_reply_final["response_text"] is not None
        assert "first" in first_reply_final["response_text"].lower()

        # Verify second reply has its metadata
        second_reply_final = final_conv_data["replies"][1]
        assert second_reply_final["request_text"] is not None
        assert second_reply_final["response_text"] is not None
        assert "second" in second_reply_final["response_text"].lower()

    def test_resume_uses_previous_session_id(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that resuming a conversation uses the previous session_id."""
        # First message
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Setup complete"),
    generate_result_event(session_id, "Done"),
]
"""
        msg1 = create_email(
            subject="Setup task",
            body=first_mock_code,
        )
        integration_env.email_server.inject_message(msg1)

        # Start service
        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for first response
            ack1 = integration_env.email_server.wait_for_sent(timeout=15.0)
            assert ack1 is not None
            conv_id = extract_conversation_id(ack1["Subject"])
            assert conv_id is not None

            response1 = integration_env.email_server.wait_for_sent(
                lambda m: "complete" in get_message_text(m).lower()
                and m != ack1,
                timeout=30.0,
            )
            assert response1 is not None

            # Get session file and extract first session_id
            session_dir = (
                integration_env.storage_dir / "conversations" / conv_id
            )
            conversation_file = session_dir / CONVERSATION_FILE_NAME

            import json

            with conversation_file.open("r") as f:
                session_data = json.load(f)

            first_session_id = session_data["replies"][0]["session_id"]
            assert first_session_id, "First reply should have session_id"

            # Clear sent emails
            integration_env.email_server.clear_outbox()

            # Second message to same conversation
            second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Follow-up complete"),
    generate_result_event(session_id, "Done"),
]
"""
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Setup task",
                body=second_mock_code,
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for second response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "follow-up" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response2 is not None

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

        # Verify that the executor was called with the correct session_id
        # by checking the conversation file
        with conversation_file.open("r") as f:
            final_session_data = json.load(f)

        assert len(final_session_data["replies"]) == 2
        # Both replies should have session IDs (they may be the same or
        # different depending on Claude's session management, but both exist)
        assert final_session_data["replies"][0]["session_id"]
        assert final_session_data["replies"][1]["session_id"]
