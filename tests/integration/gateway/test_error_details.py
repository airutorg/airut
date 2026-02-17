# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for error response details.

Tests:
1. Error responses include outbox files as attachments
2. Error responses include Claude's error summary output
3. Empty message body produces the correct error email
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.dashboard.tracker import CompletionReason, TaskStatus

from .conftest import get_message_text
from .environment import IntegrationEnvironment


def _get_attachments(msg) -> list[tuple[str, bytes]]:
    """Extract attachments from an email message."""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    payload = part.get_payload(decode=True)
                    if payload:
                        attachments.append((filename, payload))
    return attachments


class TestErrorWithOutboxFiles:
    """Test that error responses include outbox file attachments."""

    def test_failed_execution_attaches_outbox_files(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Outbox files are attached even when execution fails.

        Scenario:
        1. Mock code creates a file in outbox/
        2. Then exits with non-zero (crash)
        3. Error response email should include the outbox file

        Validates message_processing.py:629-633 where outbox_files
        are collected and sent with the error response.
        """
        mock_code = """
# Create file in outbox before crashing
(outbox / 'partial-results.txt').write_text('Partial output before crash')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Working on it..."),
    generate_result_event(session_id, "Crashed", is_error=True),
]
exit_code = 1
"""
        msg = create_email(
            subject="Error with outbox test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for the error response (skip ack)
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            error_response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    m != ack
                    and (
                        "error" in get_message_text(m).lower()
                        or "retry" in get_message_text(m).lower()
                    )
                ),
                timeout=15.0,
            )
            assert error_response is not None, "Did not receive error response"

            # Verify the outbox file is attached
            attachments = _get_attachments(error_response)
            filenames = [name for name, _ in attachments]
            assert "partial-results.txt" in filenames, (
                f"Expected 'partial-results.txt' in attachments, "
                f"got {filenames}"
            )

            # Verify attachment content
            content = next(
                data
                for name, data in attachments
                if name == "partial-results.txt"
            )
            assert b"Partial output before crash" in content

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestErrorSummaryInResponse:
    """Test that error responses include Claude's output summary."""

    def test_error_response_includes_claude_output(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Error email body includes extract_error_summary output.

        When execution fails, message_processing.py:610-614 calls
        extract_error_summary(result.events) and appends the result
        to the error email body under "Claude output:".

        Mock code emits an assistant event with diagnostic text,
        then a result event with is_error=True. The error summary
        should appear in the reply email.
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Analyzing the problem..."),
    generate_result_event(
        session_id,
        "TypeError: cannot unpack non-sequence NoneType",
        is_error=True,
    ),
]
exit_code = 1
"""
        msg = create_email(
            subject="Error summary test",
            body=mock_code,
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

            # Wait for the error response
            error_response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    m != ack
                    and (
                        "error" in get_message_text(m).lower()
                        or "retry" in get_message_text(m).lower()
                    )
                ),
                timeout=15.0,
            )
            assert error_response is not None, "Did not receive error response"

            # Verify error summary is included in response body
            body = get_message_text(error_response)
            assert "Claude output:" in body, (
                f"Expected 'Claude output:' in error email, got: {body[:300]}"
            )
            assert "TypeError" in body, (
                f"Expected error text in email body, got: {body[:300]}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestEmptyBodyResponse:
    """Test the complete empty message body error flow."""

    def test_empty_body_sends_correct_error_email(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Empty message body produces specific error email.

        message_processing.py:294-302 checks for empty body and sends
        "Your message appears to be empty" error without creating a
        conversation.

        Validates:
        - Error email text contains the expected message
        - Task completes with EXECUTION_FAILED
        - No conversation directory is created
        """
        msg = create_email(
            subject="Empty body test",
            body="   ",  # Whitespace-only body
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Should receive an error (not an ack)
            error = integration_env.email_server.wait_for_sent(
                lambda m: "empty" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert error is not None, "Did not receive empty-body error email"

            body = get_message_text(error)
            assert "empty" in body.lower()
            assert "new message" in body.lower(), (
                f"Expected instructions to send a new message, "
                f"got: {body[:200]}"
            )

            # Wait for task completion in tracker (may lag behind
            # the email delivery)
            import time

            deadline = time.monotonic() + 5.0
            empty_tasks = []
            while time.monotonic() < deadline:
                tasks = service.tracker.get_all_tasks()
                empty_tasks = [
                    t
                    for t in tasks
                    if t.status == TaskStatus.COMPLETED
                    and t.completion_reason == CompletionReason.EXECUTION_FAILED
                ]
                if empty_tasks:
                    break
                time.sleep(0.1)
            all_tasks = service.tracker.get_all_tasks()
            summary = [(t.status.value, t.completion_reason) for t in all_tasks]
            assert len(empty_tasks) >= 1, (
                "Expected at least one EXECUTION_FAILED task, "
                f"got tasks: {summary}"
            )

            # No conversation directory should have been created
            conversations_dir = integration_env.storage_dir / "conversations"
            if conversations_dir.exists():
                conv_dirs = [
                    d
                    for d in conversations_dir.iterdir()
                    if d.is_dir() and not d.name.startswith(".")
                ]
                # The empty body path returns conv_id=None, so no
                # conversation directory should be created for it
                # (other tests in the same session may create dirs)
                for d in conv_dirs:
                    # If a conversation dir exists, it shouldn't be from
                    # this empty-body message (verify via tracker)
                    conv_id = d.name
                    conv_tasks = service.tracker.get_tasks_for_conversation(
                        conv_id
                    )
                    for t in conv_tasks:
                        assert (
                            t.completion_reason
                            != CompletionReason.EXECUTION_FAILED
                            or t.display_title != "Empty body test"
                        ), "Empty body should not create conversation dir"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
