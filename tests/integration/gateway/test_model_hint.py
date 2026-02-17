# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for model hint via email subaddressing.

Tests:
1. New conversation with model hint uses the requested model
2. Resumed conversation ignores model hint, uses stored model
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from .conftest import get_message_text, wait_for_conv_completion
from .environment import IntegrationEnvironment


class TestModelHint:
    """Test model selection via email subaddressing."""

    def test_new_conversation_uses_model_hint(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Model hint in To address overrides default for new conversations.

        The test repo's default_model is "sonnet". Sending to
        claude+opus@test.local should create a conversation using
        model "opus" instead.

        Validates:
        - Tracker records the hinted model
        - ConversationStore persists the hinted model
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Model hint test"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Model hint test",
            body=mock_code,
            recipient="claude+opus@test.local",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for ack
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for completion
            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=10.0
            )
            assert task is not None
            assert task.model == "opus", (
                f"Expected model 'opus' from hint, got '{task.model}'"
            )

            # Verify model persisted in conversation store
            from airut.conversation import ConversationStore

            conv_dir = integration_env.storage_dir / "conversations" / conv_id
            store = ConversationStore(conv_dir)
            stored_model = store.get_model()
            assert stored_model == "opus", (
                f"Stored model should be 'opus', got '{stored_model}'"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_resumed_conversation_ignores_model_hint(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Model hint on resumed conversation is ignored.

        First message creates conversation with default model ("sonnet").
        Second message sent to claude+opus@test.local should still use
        "sonnet" (the stored model), not "opus".

        Validates:
        - First task uses the default model
        - Second task ignores the hint and uses the stored model
        """
        first_mock = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First response"),
    generate_result_event(session_id, "Done"),
]
"""
        msg1 = create_email(
            subject="Resume model test",
            body=first_mock,
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
                lambda m: "first response" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert response1 is not None

            task1 = wait_for_conv_completion(
                service.tracker, conv_id, timeout=10.0
            )
            assert task1 is not None
            assert task1.model == "sonnet", (
                f"First task should use default 'sonnet', got '{task1.model}'"
            )

            integration_env.email_server.clear_outbox()

            # Second message with model hint — should be ignored
            second_mock = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second response"),
    generate_result_event(session_id, "Done"),
]
"""
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Resume model test",
                body=second_mock,
                recipient="claude+opus@test.local",
                in_reply_to=ack.get("Message-ID"),
                references=[ack.get("Message-ID")]
                if ack.get("Message-ID")
                else [],
            )
            integration_env.email_server.inject_message(msg2)

            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "second response" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert response2 is not None

            # Get the second task
            tasks = service.tracker.get_tasks_for_conversation(conv_id)
            assert len(tasks) >= 2
            newest = tasks[0]
            assert newest.model == "sonnet", (
                f"Resumed task should use stored 'sonnet', got '{newest.model}'"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
