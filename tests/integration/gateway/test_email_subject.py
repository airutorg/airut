# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for email subject line in prompts.

Tests that:
1. Subject line is included in the prompt for new conversations
2. Subject line is NOT included for resumed conversations
3. Empty body on resumed conversation is rejected
"""

import json
import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.conversation import CONVERSATION_FILE_NAME

from .conftest import get_message_text
from .environment import IntegrationEnvironment


class TestEmailSubjectInPrompt:
    """Test that email subject is passed to Claude for new conversations."""

    def test_subject_included_in_prompt_for_new_conversation(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Subject line appears in the prompt for the first message."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Task completed"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Refactor the login module",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for response
            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "completed" in get_message_text(m).lower() and m != ack
                ),
                timeout=30.0,
            )
            assert response is not None

            # Read conversation file and verify subject is in request_text
            conversation_dir = (
                integration_env.storage_dir / "conversations" / conv_id
            )
            conversation_file = conversation_dir / CONVERSATION_FILE_NAME
            assert conversation_file.exists()

            with conversation_file.open("r") as f:
                conv_data = json.load(f)

            assert len(conv_data["replies"]) == 1
            request_text = conv_data["replies"][0]["request_text"]
            assert "Subject: Refactor the login module" in request_text

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_subject_excluded_from_prompt_for_resumed_conversation(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Subject line is NOT included when resuming a conversation."""
        # First message to start conversation
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First task done"),
    generate_result_event(session_id, "First done"),
]
"""
        msg1 = create_email(
            subject="Initial task",
            body=first_mock_code,
        )
        integration_env.email_server.inject_message(msg1)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for first response
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            response1 = integration_env.email_server.wait_for_sent(
                lambda m: "first" in get_message_text(m).lower() and m != ack,
                timeout=30.0,
            )
            assert response1 is not None

            # Verify first message HAS subject in request_text
            conversation_dir = (
                integration_env.storage_dir / "conversations" / conv_id
            )
            conversation_file = conversation_dir / CONVERSATION_FILE_NAME

            with conversation_file.open("r") as f:
                conv_data = json.load(f)
            assert (
                "Subject: Initial task"
                in conv_data["replies"][0]["request_text"]
            )

            # Clear outbox
            integration_env.email_server.clear_outbox()

            # Second message (resume) — subject has [ID:...] tag
            second_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Follow-up done"),
    generate_result_event(session_id, "Second done"),
]
"""
            original_msg_id = ack.get("Message-ID")
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Initial task",
                body=second_mock_code,
                in_reply_to=original_msg_id,
                references=[original_msg_id] if original_msg_id else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for second response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "follow-up" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response2 is not None

            # Verify second message does NOT have subject in request_text
            with conversation_file.open("r") as f:
                conv_data = json.load(f)

            assert len(conv_data["replies"]) == 2
            second_request = conv_data["replies"][1]["request_text"]
            assert "Subject:" not in second_request

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_empty_body_rejected_for_resumed_conversation(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Empty body on a resumed conversation is rejected."""
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

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for first response
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            response1 = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "complete" in get_message_text(m).lower() and m != ack
                ),
                timeout=30.0,
            )
            assert response1 is not None

            # Clear outbox
            integration_env.email_server.clear_outbox()

            # Send empty body reply to resumed conversation
            original_msg_id = ack.get("Message-ID")
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Setup task",
                body="",
                in_reply_to=original_msg_id,
                references=[original_msg_id] if original_msg_id else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Should get an "empty message" error response
            error_response = integration_env.email_server.wait_for_sent(
                lambda m: "empty" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert error_response is not None, (
                "Did not receive 'empty message' error for resumed "
                "conversation with empty body"
            )

            # Verify conversation file still has only 1 reply
            # (the empty message was rejected, not processed)
            conversation_dir = (
                integration_env.storage_dir / "conversations" / conv_id
            )
            conversation_file = conversation_dir / CONVERSATION_FILE_NAME
            with conversation_file.open("r") as f:
                conv_data = json.load(f)
            assert len(conv_data["replies"]) == 1

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
