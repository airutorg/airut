# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for new conversation flow.

Tests the complete lifecycle of a new conversation:
1. Email received
2. Acknowledgment sent
3. Conversation directory created
4. Claude executed
5. Response sent with results
"""

import re
import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text
from .environment import IntegrationEnvironment


class TestNewConversationFlow:
    """Test complete new conversation lifecycle."""

    def test_new_conversation_creates_repo_and_replies(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that a new email creates conversation and gets reply."""
        # Create and inject test email
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Task completed"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Please help with task",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        # Start service in background thread
        service = integration_env.create_service()

        def run_service():
            try:
                service.start()
            except Exception:
                pass  # Expected when we stop the service

        service_thread = threading.Thread(target=run_service, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment email
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"

            # Extract conversation ID from acknowledgment
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None, (
                f"No conversation ID in subject: {ack['Subject']}"
            )
            assert len(conv_id) == 8, f"Invalid conversation ID: {conv_id}"

            # Verify conversation directory was created
            conv_path = (
                integration_env.storage_dir
                / "conversations"
                / conv_id
                / "workspace"
            )
            assert conv_path.exists(), (
                f"Conversation directory not created: {conv_path}"
            )
            assert (conv_path / ".git").exists(), "Not a git repository"

            # Wait for response email (with Claude's output)
            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "completed" in get_message_text(m).lower() and m != ack
                ),  # Not the acknowledgment
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            # Verify response has correct conversation ID
            response_conv_id = extract_conversation_id(response["Subject"])
            assert response_conv_id == conv_id, (
                f"Conv ID mismatch: {response_conv_id} != {conv_id}"
            )

        finally:
            # Stop the service
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_conversation_id_format(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that conversation IDs are valid 8-character hex strings."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Test response"),
    generate_result_event(session_id, "Complete"),
]
"""
        msg = create_email(
            subject="Test conversation ID",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for any response
            response = integration_env.email_server.wait_for_sent(timeout=15.0)
            assert response is not None

            # Extract and validate conversation ID
            subject = response["Subject"]
            match = re.search(r"\[ID:([a-f0-9]+)\]", subject, re.IGNORECASE)
            assert match is not None, (
                f"No conversation ID in subject: {subject}"
            )

            conv_id = match.group(1)
            assert len(conv_id) == 8, (
                f"Conversation ID should be 8 chars: {conv_id}"
            )
            assert conv_id.isalnum(), (
                f"Conversation ID should be hex: {conv_id}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_email_threading_headers(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that response emails have correct threading headers."""
        original_msg_id = "<original-123@test.local>"
        msg = create_email(
            subject="Test threading",
            body="Check threading headers",
            message_id=original_msg_id,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for response
            response = integration_env.email_server.wait_for_sent(timeout=15.0)
            assert response is not None

            # Check In-Reply-To header
            in_reply_to = response.get("In-Reply-To")
            assert in_reply_to == original_msg_id, (
                f"In-Reply-To should be {original_msg_id}, got {in_reply_to}"
            )

            # Check References header contains original message ID
            references = response.get("References", "")
            assert original_msg_id in references, (
                f"References should contain {original_msg_id}, got {references}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_dashboard_tracks_task(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that dashboard tracks task through its lifecycle."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Tracking test completed"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Test dashboard tracking",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for task completion
            response = integration_env.email_server.wait_for_sent(
                lambda m: "completed" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            # Get conversation ID
            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            # Wait for task completion
            task = service.tracker.wait_for_completion(conv_id, timeout=5.0)

            assert task is not None, f"Task {conv_id} not found in tracker"
            assert task.status.value == "completed", (
                f"Task status: {task.status}"
            )
            assert task.success is True, "Task should be successful"

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)
