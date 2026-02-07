# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for authorization and security.

Tests that unauthorized senders are rejected:
1. Wrong sender email is rejected
2. No conversation directory created for rejected messages
3. No response sent for rejected messages
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .environment import IntegrationEnvironment


class TestAuthorizationRejection:
    """Test that unauthorized senders are rejected."""

    def test_unauthorized_sender_rejected(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that emails from unauthorized senders are silently rejected."""
        # Create email from unauthorized sender
        msg = create_email(
            subject="Please help me",
            body="This should be rejected",
            sender="hacker@evil.com",  # Not authorized
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for service to process the injected message
            processed = integration_env.email_server.wait_until_inbox_empty(
                timeout=10.0
            )
            assert processed, "Service did not process message in time"

            # Check that no response was sent
            sent = integration_env.email_server.get_sent_messages()
            assert len(sent) == 0, (
                f"Should not respond to unauthorized sender, got {len(sent)}"
            )

            # Check that no conversation directory was created
            # Filter by 8-character conversation ID
            conversations_dir = integration_env.storage_dir / "conversations"
            conversations = [
                d
                for d in conversations_dir.iterdir()
                if d.is_dir()
                and not d.name.startswith(".")
                and len(d.name) == 8
            ]
            assert len(conversations) == 0, (
                f"Should not create conversation for unauthorized sender, "
                f"found: {conversations}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_authorized_sender_accepted(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that emails from authorized sender are processed."""
        # Create email from authorized sender (default in fixture)
        msg = create_email(
            subject="Please help me",
            body="This should be accepted",
            sender="user@test.local",  # Matches authorized_sender in config
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for response
            response = integration_env.email_server.wait_for_sent(timeout=15.0)
            assert response is not None, (
                "Should receive response from authorized sender"
            )

            # Check that conversation directory was created
            # Filter by 8-character conversation ID
            conversations_dir = integration_env.storage_dir / "conversations"
            conversations = [
                d
                for d in conversations_dir.iterdir()
                if d.is_dir()
                and not d.name.startswith(".")
                and len(d.name) == 8
            ]
            assert len(conversations) == 1, (
                f"Should create one conversation, found: {conversations}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_case_insensitive_sender_match(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that sender matching is case-insensitive."""
        # Use different case than configured
        msg = create_email(
            subject="Case test",
            body="Testing case sensitivity",
            sender="USER@TEST.LOCAL",  # Different case
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Should receive response (case-insensitive match)
            response = integration_env.email_server.wait_for_sent(timeout=15.0)
            assert response is not None, (
                "Should accept sender with different case"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_dmarc_fail_rejected(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that emails failing DMARC/SPF are rejected."""
        # Authorized sender but DMARC fails
        msg = create_email(
            subject="DMARC fail test",
            body="This should be rejected due to DMARC",
            sender="user@test.local",  # Correct sender
            authentication_results="test.local; dmarc=fail; spf=fail",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for service to process the injected message
            processed = integration_env.email_server.wait_until_inbox_empty(
                timeout=10.0
            )
            assert processed, "Service did not process message in time"

            # Check that no response was sent
            sent = integration_env.email_server.get_sent_messages()
            assert len(sent) == 0, (
                f"Should not send response when DMARC fails, got {len(sent)}"
            )

            # Check that no conversation directory was created
            # Filter by 8-character conversation ID
            conversations_dir = integration_env.storage_dir / "conversations"
            conversations = [
                d
                for d in conversations_dir.iterdir()
                if d.is_dir()
                and not d.name.startswith(".")
                and len(d.name) == 8
            ]
            assert len(conversations) == 0, (
                f"Should not create conversation when DMARC fails, "
                f"found: {conversations}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_missing_auth_results_rejected(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that emails without Authentication-Results are rejected."""
        # Authorized sender but no auth header
        msg = create_email(
            subject="No auth header test",
            body="This should be rejected due to missing auth",
            sender="user@test.local",  # Correct sender
            authentication_results="",  # Empty = no header
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for service to process the injected message
            processed = integration_env.email_server.wait_until_inbox_empty(
                timeout=10.0
            )
            assert processed, "Service did not process message in time"

            # Check that no response was sent
            sent = integration_env.email_server.get_sent_messages()
            assert len(sent) == 0, (
                f"Should not send response without auth header, got {len(sent)}"
            )

            # Check that no conversation directory was created
            # Filter by 8-character conversation ID
            conversations_dir = integration_env.storage_dir / "conversations"
            conversations = [
                d
                for d in conversations_dir.iterdir()
                if d.is_dir()
                and not d.name.startswith(".")
                and len(d.name) == 8
            ]
            assert len(conversations) == 0, (
                f"Should not create conversation without auth header, "
                f"found: {conversations}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)
