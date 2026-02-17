# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for session recovery on prompt-too-long errors.

Tests the recovery flow in message_processing.py where:
1. First execution returns PROMPT_TOO_LONG (or SESSION_CORRUPTED)
2. System builds a recovery prompt and retries with a fresh session
3. Retry succeeds and sends a normal reply

These outcomes are determined by classify_outcome() in sandbox/_output.py:
- "Prompt is too long" in stdout → Outcome.PROMPT_TOO_LONG
- "API Error: 4" in stdout/stderr → Outcome.SESSION_CORRUPTED

The recovery path only triggers when session_id is not None (i.e., resumed
conversations), so each test starts a conversation, then sends a follow-up
that triggers the error on the first attempt.
"""

import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import CompletionReason, TaskStatus

from .conftest import (
    get_message_text,
    wait_for_conv_completion,
)
from .environment import IntegrationEnvironment


def _poll_tracker(
    tracker,
    predicate,
    timeout: float = 15.0,
    interval: float = 0.1,
):
    """Poll the tracker until predicate(all_tasks) is truthy."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        tasks = tracker.get_all_tasks()
        result = predicate(tasks)
        if result:
            return result
        time.sleep(interval)
    return None


class TestPromptTooLongRecovery:
    """Test recovery when a resumed session returns PROMPT_TOO_LONG."""

    def test_prompt_too_long_retries_with_fresh_session(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Recovery flow on PROMPT_TOO_LONG: fresh session retry succeeds.

        Scenario:
        1. First message creates a conversation (succeeds normally)
        2. Second message to the same conversation triggers PROMPT_TOO_LONG
           on the first execution attempt (mock_claude outputs "Prompt is
           too long" and exits non-zero)
        3. System detects the error, builds a recovery prompt, retries with
           session_id=None
        4. Retry succeeds and sends a normal reply

        Validates:
        - Recovery prompt is constructed and retried
        - Reply email is sent with recovery response
        - Task completes with SUCCESS despite initial failure
        - Conversation state is persisted correctly
        """
        # First message: normal success to establish conversation
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("First response"),
    generate_result_event(session_id, "First done"),
]
"""
        msg1 = create_email(
            subject="Recovery test conversation",
            body=first_mock_code,
            message_id="<recovery-first@test.local>",
        )
        integration_env.email_server.inject_message(msg1)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for ack + response for the first message
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for the first response
            response1 = integration_env.email_server.wait_for_sent(
                lambda m: "first response" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response1 is not None, "Did not receive first response"

            # Wait for the first task to fully complete in the tracker
            first_task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=10.0
            )
            assert first_task is not None
            assert first_task.status == TaskStatus.COMPLETED
            assert first_task.succeeded

            # Clear the outbox so we can detect the second response
            integration_env.email_server.clear_outbox()

            # Second message: triggers PROMPT_TOO_LONG on first attempt.
            #
            # The mock_claude code checks for the session_id env var. When
            # resuming (session_id is set by the executor from conversation
            # state), it outputs "Prompt is too long" and exits 1. The
            # sandbox's classify_outcome detects this and returns
            # Outcome.PROMPT_TOO_LONG.
            #
            # The recovery path retries with session_id=None. On the
            # second execution, mock_claude sees no MOCK_CLAUDE_SESSION_ID
            # (fresh session), so it runs normally.
            second_mock_code = """
# When resuming an existing session, simulate prompt-too-long.
# The recovery path retries with session_id=None.
if os.environ.get("MOCK_CLAUDE_SESSION_ID"):
    # Output the magic string that classify_outcome looks for
    print(json.dumps({
        "type": "result",
        "subtype": "error",
        "is_error": True,
        "result": "Prompt is too long",
    }))
    sys.exit(1)
else:
    # Fresh session (recovery retry) — succeed normally
    events = [
        generate_system_event(session_id),
        generate_assistant_event("Recovered successfully"),
        generate_result_event(session_id, "Recovery done"),
    ]
"""
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Recovery test conversation",
                body=second_mock_code,
                message_id="<recovery-second@test.local>",
                in_reply_to=ack.get("Message-ID"),
                references=[ack.get("Message-ID")]
                if ack.get("Message-ID")
                else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for the recovery response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "recovered" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response2 is not None, (
                "Did not receive recovery response email. "
                "The PROMPT_TOO_LONG recovery path may have failed."
            )

            # Wait for the second task to complete in the tracker
            # (email may arrive before tracker updates)
            completed = _poll_tracker(
                service.tracker,
                lambda tasks: (
                    sum(
                        1
                        for t in tasks
                        if t.conversation_id == conv_id
                        and t.status == TaskStatus.COMPLETED
                    )
                    >= 2
                ),
                timeout=10.0,
            )
            assert completed, (
                "Second task did not complete in tracker. Tasks: "
                + repr(
                    [
                        (t.conversation_id, t.status.value)
                        for t in service.tracker.get_all_tasks()
                    ]
                )
            )

            # Verify the task completed successfully
            tasks = service.tracker.get_tasks_for_conversation(conv_id)
            assert len(tasks) >= 2, (
                f"Expected at least 2 tasks, got {len(tasks)}"
            )
            # The newest task (second message) should succeed
            newest_task = tasks[0]
            assert newest_task.status == TaskStatus.COMPLETED
            assert newest_task.completion_reason == CompletionReason.SUCCESS

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestSessionCorruptedRecovery:
    """Test recovery when a resumed session returns SESSION_CORRUPTED."""

    def test_session_corrupted_retries_with_fresh_session(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Recovery flow on SESSION_CORRUPTED: fresh session retry succeeds.

        Same as prompt-too-long but triggered by "API Error: 4" in output.
        """
        # First message: normal success
        first_mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Setup response"),
    generate_result_event(session_id, "Setup done"),
]
"""
        msg1 = create_email(
            subject="Corrupted session test",
            body=first_mock_code,
            message_id="<corrupted-first@test.local>",
        )
        integration_env.email_server.inject_message(msg1)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for first response to complete
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            response1 = integration_env.email_server.wait_for_sent(
                lambda m: "setup response" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response1 is not None

            first_task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=10.0
            )
            assert first_task is not None
            assert first_task.succeeded

            integration_env.email_server.clear_outbox()

            # Second message: triggers SESSION_CORRUPTED on first attempt
            second_mock_code = """
# Simulate API 4xx error on resume, succeed on fresh session.
if os.environ.get("MOCK_CLAUDE_SESSION_ID"):
    # Output the magic string for session corruption detection
    print("API Error: 400 - Bad Request")
    sys.exit(1)
else:
    events = [
        generate_system_event(session_id),
        generate_assistant_event("Session recovered"),
        generate_result_event(session_id, "Recovery done"),
    ]
"""
            msg2 = create_email(
                subject=f"Re: [ID:{conv_id}] Corrupted session test",
                body=second_mock_code,
                message_id="<corrupted-second@test.local>",
                in_reply_to=ack.get("Message-ID"),
                references=[ack.get("Message-ID")]
                if ack.get("Message-ID")
                else [],
            )
            integration_env.email_server.inject_message(msg2)

            # Wait for the recovery response
            response2 = integration_env.email_server.wait_for_sent(
                lambda m: "session recovered" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response2 is not None, (
                "Did not receive recovery response. "
                "SESSION_CORRUPTED recovery path may have failed."
            )

            # Wait for the second task to complete in the tracker
            completed = _poll_tracker(
                service.tracker,
                lambda tasks: (
                    sum(
                        1
                        for t in tasks
                        if t.conversation_id == conv_id
                        and t.status == TaskStatus.COMPLETED
                    )
                    >= 2
                ),
                timeout=10.0,
            )
            assert completed, "Second task did not complete"

            # Verify the second task completed with SUCCESS
            tasks = service.tracker.get_tasks_for_conversation(conv_id)
            assert len(tasks) >= 2
            newest_task = tasks[0]
            assert newest_task.status == TaskStatus.COMPLETED
            assert newest_task.completion_reason == CompletionReason.SUCCESS

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
