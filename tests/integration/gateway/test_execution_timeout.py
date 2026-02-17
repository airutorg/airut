# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for execution timeout handling.

Tests the timeout code path in message_processing.py where:
1. Sandbox returns Outcome.TIMEOUT
2. Error reply is sent with timeout message
3. Task completes with CompletionReason.TIMEOUT
4. Reply is persisted to conversation state as an error

The real timeout mechanism (subprocess.TimeoutExpired → SIGKILL) cannot
be exercised with mock_podman because the `uv run` wrapper keeps stdout
open even after the child closes fd 1. Instead, we patch Sandbox to
return a mock task whose execute() returns an ExecutionResult with
Outcome.TIMEOUT. This exercises the full message_processing code path
from outcome classification through error reply and state persistence.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.claude_output.types import Usage
from airut.conversation import ConversationStore
from airut.dashboard.tracker import CompletionReason, TaskStatus
from airut.sandbox.event_log import EventLog
from airut.sandbox.types import ExecutionResult, Outcome

from .conftest import (
    get_message_text,
    wait_for_conv_completion,
)
from .environment import IntegrationEnvironment


class _MockTimeoutTask:
    """Mock sandbox task that simulates a timeout on execute().

    Returns an ExecutionResult with Outcome.TIMEOUT and empty response
    text. Mimics what the real sandbox returns when the container is
    killed by TimeoutExpired.
    """

    def __init__(self, event_log: EventLog) -> None:
        self.event_log = event_log

    def execute(
        self,
        prompt,
        *,
        session_id=None,
        model="sonnet",
        on_event=None,
    ):
        return ExecutionResult(
            outcome=Outcome.TIMEOUT,
            session_id=session_id or "mock-timeout",
            response_text="",
            events=[],
            duration_ms=10000,
            total_cost_usd=0.0,
            num_turns=0,
            usage=Usage(),
            stdout="",
            stderr="",
            exit_code=-9,
        )

    def stop(self):
        return False


class TestExecutionTimeout:
    """Test execution timeout handling end-to-end."""

    def test_timeout_sends_error_and_tracks_completion_reason(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Timeout produces error reply with correct tracking.

        Patches the sandbox to return Outcome.TIMEOUT, then verifies:
        1. Error reply email is sent mentioning the timeout
        2. Task completes with CompletionReason.TIMEOUT
        3. Reply is persisted to conversation state as an error
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("This will time out"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Timeout test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()

        # Patch Sandbox.create_task to return a timeout-simulating task
        def create_timeout_task(**kwargs):
            """Create a mock task that returns TIMEOUT on execute."""
            conversation_dir = kwargs.get("execution_context_dir")
            event_log = (
                EventLog(conversation_dir)
                if conversation_dir
                else (EventLog(Path("/tmp")))
            )
            return _MockTimeoutTask(event_log)

        service.sandbox.create_task = create_timeout_task

        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for the timeout error response
            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    m != ack
                    and (
                        "interrupted" in get_message_text(m).lower()
                        or "timeout" in get_message_text(m).lower()
                        or "seconds" in get_message_text(m).lower()
                    )
                ),
                timeout=15.0,
            )
            assert response is not None, (
                "Did not receive timeout error response"
            )

            # Verify error message mentions the timeout
            payload = get_message_text(response)
            assert "interrupted" in payload.lower(), (
                f"Response should mention 'interrupted': {payload[:200]}"
            )

            # Verify task tracked with TIMEOUT completion reason
            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None
            assert task.status == TaskStatus.COMPLETED
            assert task.completion_reason == CompletionReason.TIMEOUT

            # Verify reply was persisted to conversation state
            conversation_dir = (
                integration_env.storage_dir / "conversations" / conv_id
            )
            store = ConversationStore(conversation_dir)
            conv_data = store.load()
            assert conv_data is not None
            assert len(conv_data.replies) >= 1
            last_reply = conv_data.replies[-1]
            assert last_reply.is_error is True

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
