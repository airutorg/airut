# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for multiple sender authorization.

Tests that:
1. Multiple exact email addresses can be authorized
2. Domain wildcards work correctly
3. Replies go to the correct sender
4. Tasks from multiple senders can run concurrently
"""

import threading
import time

from .conftest import MOCK_CONTAINER_COMMAND
from .environment import IntegrationEnvironment


class TestMultipleSendersAuthorization:
    """Test authorization with multiple senders and wildcards."""

    def test_multiple_exact_senders_accepted(
        self,
        tmp_path,
        create_email,
    ) -> None:
        """Test that multiple exact email addresses can be authorized."""
        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["alice@test.local", "bob@test.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Create emails from both authorized senders
            msg_alice = create_email(
                subject="Request from Alice",
                body="Alice's request",
                sender="alice@test.local",
            )
            msg_bob = create_email(
                subject="Request from Bob",
                body="Bob's request",
                sender="bob@test.local",
            )
            env.email_server.inject_message(msg_alice)
            env.email_server.inject_message(msg_bob)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            try:
                # Wait for inbox to be processed
                processed = env.email_server.wait_until_inbox_empty(
                    timeout=10.0
                )
                assert processed, "Service did not process messages in time"

                # Wait for responses to both senders
                # Note: wait_for_sent returns any matching message and doesn't
                # track which messages were already returned. We must wait for
                # both recipients to have received responses.
                deadline = time.monotonic() + 30.0
                while time.monotonic() < deadline:
                    messages = env.email_server.get_sent_messages()
                    to_addresses = {
                        msg.get("To", "").lower() for msg in messages
                    }
                    has_alice = any(
                        "alice@test.local" in addr for addr in to_addresses
                    )
                    has_bob = any(
                        "bob@test.local" in addr for addr in to_addresses
                    )
                    if has_alice and has_bob:
                        break
                    time.sleep(0.05)

                # Verify both received responses
                messages = env.email_server.get_sent_messages()
                assert len(messages) >= 2, (
                    f"Should have at least 2 messages, got {len(messages)}"
                )

                to_addresses = {msg.get("To", "").lower() for msg in messages}
                assert any(
                    "alice@test.local" in addr for addr in to_addresses
                ), f"Alice should receive a reply, got: {to_addresses}"
                assert any("bob@test.local" in addr for addr in to_addresses), (
                    f"Bob should receive a reply, got: {to_addresses}"
                )

                # Check that two conversations were created
                conversations_dir = env.storage_dir / "conversations"
                conversations = [
                    d
                    for d in conversations_dir.iterdir()
                    if d.is_dir()
                    and not d.name.startswith(".")
                    and len(d.name) == 8
                ]
                assert len(conversations) == 2, (
                    f"Should create two conversations, found: {conversations}"
                )

            finally:
                service.running = False
                service.repo_handlers["test"].listener.interrupt()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_wildcard_domain_sender_accepted(
        self,
        tmp_path,
        create_email,
    ) -> None:
        """Test that domain wildcard patterns work correctly."""
        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["*@company.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Create email from any user at the authorized domain
            msg = create_email(
                subject="Request from employee",
                body="Employee's request",
                sender="employee@company.local",
            )
            env.email_server.inject_message(msg)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            try:
                # Should receive response (wildcard match)
                response = env.email_server.wait_for_sent(timeout=15.0)
                assert response is not None, (
                    "Should accept sender from wildcard domain"
                )

            finally:
                service.running = False
                service.repo_handlers["test"].listener.interrupt()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_wildcard_domain_sender_rejected(
        self,
        tmp_path,
        create_email,
    ) -> None:
        """Test that senders outside wildcard domain are rejected."""
        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["*@company.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Create email from unauthorized domain
            msg = create_email(
                subject="Request from outsider",
                body="Outsider's request",
                sender="outsider@other.local",
            )
            env.email_server.inject_message(msg)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            try:
                # Wait for service to process
                processed = env.email_server.wait_until_inbox_empty(
                    timeout=10.0
                )
                assert processed, "Service did not process message in time"

                # Should NOT receive response (not authorized)
                sent = env.email_server.get_sent_messages()
                assert len(sent) == 0, (
                    f"Should not respond to unauthorized domain, "
                    f"got {len(sent)}"
                )

            finally:
                service.running = False
                service.repo_handlers["test"].listener.interrupt()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_replies_directed_to_correct_sender(
        self,
        tmp_path,
        create_email,
    ) -> None:
        """Test that replies go to the sender who submitted the task."""
        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["alice@test.local", "bob@test.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Create email from Alice
            msg = create_email(
                subject="Request from Alice",
                body="Alice's request",
                sender="alice@test.local",
            )
            env.email_server.inject_message(msg)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            try:
                # Wait for response
                response = env.email_server.wait_for_sent(timeout=15.0)
                assert response is not None, "Should receive response"

                # Verify reply was sent to Alice (the sender)
                to_addr = response.get("To", "")
                assert "alice@test.local" in to_addr.lower(), (
                    f"Reply should be sent to Alice, got: {to_addr}"
                )

            finally:
                service.running = False
                service.repo_handlers["test"].listener.interrupt()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_concurrent_tasks_from_different_senders(
        self,
        tmp_path,
        create_email,
    ) -> None:
        """Test that tasks from different senders can run concurrently."""
        import time

        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["alice@test.local", "bob@test.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Create emails from both senders
            msg_alice = create_email(
                subject="Alice concurrent task",
                body="Alice's concurrent request",
                sender="alice@test.local",
            )
            msg_bob = create_email(
                subject="Bob concurrent task",
                body="Bob's concurrent request",
                sender="bob@test.local",
            )

            # Inject both messages
            env.email_server.inject_message(msg_alice)
            env.email_server.inject_message(msg_bob)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            try:
                # Wait for inbox to be processed
                processed = env.email_server.wait_until_inbox_empty(
                    timeout=10.0
                )
                assert processed, "Service did not process messages in time"

                # Wait for all responses (ack + reply for each = 4 messages)
                # Give some time for all responses to arrive
                deadline = time.monotonic() + 30.0
                while time.monotonic() < deadline:
                    messages = env.email_server.get_sent_messages()
                    if len(messages) >= 4:
                        break
                    time.sleep(0.05)

                messages = env.email_server.get_sent_messages()
                # Should have at least 2 messages (final replies)
                assert len(messages) >= 2, (
                    f"Should have at least 2 messages, got {len(messages)}"
                )

                # Collect all To addresses
                to_addresses = {msg.get("To", "").lower() for msg in messages}

                # Verify both Alice and Bob received replies
                has_alice = any(
                    "alice@test.local" in addr for addr in to_addresses
                )
                has_bob = any("bob@test.local" in addr for addr in to_addresses)
                assert has_alice, (
                    f"Alice should receive a reply, got: {to_addresses}"
                )
                assert has_bob, (
                    f"Bob should receive a reply, got: {to_addresses}"
                )

                # Verify two separate conversations were created
                conversations_dir = env.storage_dir / "conversations"
                conversations = [
                    d
                    for d in conversations_dir.iterdir()
                    if d.is_dir()
                    and not d.name.startswith(".")
                    and len(d.name) == 8
                ]
                assert len(conversations) == 2, (
                    f"Should have two separate conversations, found: "
                    f"{[c.name for c in conversations]}"
                )

            finally:
                service.running = False
                service.repo_handlers["test"].listener.interrupt()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()
