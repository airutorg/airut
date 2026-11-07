# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for authorization and security.

Tests that unauthorized senders are rejected:
1. Wrong sender email is rejected
2. No conversation directory created for rejected messages
3. No response sent for rejected messages
4. Forged DMARC results and From headers naming others are rejected
5. Header fields the DKIM signature does not cover are not acted on
6. Messages not addressed to the channel are rejected
"""

import sys
import threading
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from airut.dashboard.tracker import CompletionReason, TaskStatus
from tests import dkim_signing

from .conftest import get_message_text, wait_for_task
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
            service.stop()
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
            service.stop()
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
            service.stop()
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
            service.stop()
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
            service.stop()
            service_thread.join(timeout=10.0)


#: The header the mail server wrote for a forged DKIM signature whose
#: identity held ``dmarc=pass``, followed by the real DMARC failure.
_FORGED_DKIM_IDENTITY = (
    'test.local; dkim=neutral header.i="a dmarc=pass b@evil.example"'
    " header.s=x; dmarc=fail header.from=test.local"
)


class TestForgedSender:
    """Forged DMARC results and From headers naming others are rejected."""

    @pytest.mark.parametrize(
        ("sender", "authentication_results"),
        [
            pytest.param(
                "user@test.local", _FORGED_DKIM_IDENTITY, id="dmarc-in-value"
            ),
            pytest.param(
                "<user@test.local>, attacker@evil.example",
                "test.local; dmarc=pass header.from=test.local",
                id="several-mailboxes",
            ),
        ],
    )
    def test_rejected(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        sender: str,
        authentication_results: str,
    ) -> None:
        msg = create_email(
            subject="Forged",
            body="This should be rejected",
            sender=sender,
            authentication_results=authentication_results,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            task = wait_for_task(
                service.tracker,
                lambda t: t.status == TaskStatus.COMPLETED,
                timeout=10.0,
            )
            assert task is not None, "Service did not process message in time"
            assert task.completion_reason == CompletionReason.AUTH_FAILED
            assert integration_env.email_server.get_sent_messages() == []
        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    @pytest.mark.parametrize(
        ("dkim_signed", "authentication_results"),
        [
            pytest.param(
                False,
                "test.local; dkim=pass header.d=test.local;"
                " dmarc=pass header.from=test.local",
                id="server-says-pass-but-unsigned",
            ),
            pytest.param(
                True,
                "test.local; dmarc=pass header.from=test.local; spf=pass",
                id="signed-but-server-records-no-dkim",
            ),
        ],
    )
    def test_dkim_required_by_default(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        dkim_signed: bool,
        authentication_results: str,
    ) -> None:
        """By default both the server and Airut must verify DKIM."""
        msg = create_email(
            subject="DKIM",
            body="This should be rejected",
            sender="user@test.local",
            authentication_results=authentication_results,
            dkim_signed=dkim_signed,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            task = wait_for_task(
                service.tracker,
                lambda t: t.status == TaskStatus.COMPLETED,
                timeout=10.0,
            )
            assert task is not None, "Service did not process message in time"
            assert task.completion_reason == CompletionReason.AUTH_FAILED
            assert integration_env.email_server.get_sent_messages() == []
        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_reply_goes_only_to_authenticated_address(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        msg = create_email(
            subject="Display name",
            body="Hello",
            sender="Test User <user@test.local>",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(timeout=15.0)
            assert response is not None
            assert response["To"] == "user@test.local"
            assert response["X-RcptTo"] == "user@test.local"
        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestUnsignedHeaderFields:
    """Header fields the DKIM signature does not cover are not acted on."""

    def test_unsigned_in_reply_to_does_not_resume(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """A follow-up threaded only by an unsigned field starts anew."""
        first = create_email(subject="First task", body="Hello")
        integration_env.email_server.inject_message(first)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            first_id = extract_conversation_id(ack["Subject"])
            assert first_id is not None
            assert integration_env.email_server.wait_for_sent(
                lambda m: (
                    m is not ack
                    and "started working" not in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            integration_env.email_server.clear_outbox()

            follow_up = create_email(
                subject="Unrelated subject",
                body="Hello again",
                in_reply_to=ack["Message-ID"],
                references=[ack["Message-ID"]],
                dkim_headers=("from", "to", "subject", "date", "message-id"),
            )
            integration_env.email_server.inject_message(follow_up)

            ack2 = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack2 is not None, "Follow-up was not started anew"
            second_id = extract_conversation_id(ack2["Subject"])
            assert second_id not in (None, first_id)
        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestChannelRecipient:
    """Messages whose To and Cc do not name the channel are rejected."""

    @pytest.mark.parametrize(
        ("recipient", "dkim_headers"),
        [
            pytest.param(
                "friend@example.org",
                dkim_signing.SIGNED_HEADERS,
                id="to-someone-else",
            ),
            pytest.param(
                "claude@test.local",
                ("from", "subject", "date", "message-id"),
                id="to-not-signed",
            ),
        ],
    )
    def test_rejected(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        recipient: str,
        dkim_headers: tuple[str, ...],
    ) -> None:
        msg = create_email(
            subject="Lunch",
            body="See you at noon",
            recipient=recipient,
            dkim_headers=dkim_headers,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            task = wait_for_task(
                service.tracker,
                lambda t: t.status == TaskStatus.COMPLETED,
                timeout=10.0,
            )
            assert task is not None, "Service did not process message in time"
            assert task.completion_reason == CompletionReason.AUTH_FAILED
            assert task.completion_detail == "not addressed to this channel"
            assert integration_env.email_server.get_sent_messages() == []
        finally:
            service.stop()
            service_thread.join(timeout=10.0)
