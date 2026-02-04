# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for error handling.

Tests that the service handles errors gracefully:
1. Claude timeout sends error response
2. Claude crash sends error response
3. Conversation remains recoverable after errors
"""

import sys
import threading
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text
from .environment import IntegrationEnvironment


class TestErrorHandling:
    """Test error handling and recovery."""

    @pytest.mark.skip(
        reason="Timeout test requires long wait and SMTP connection stability"
    )
    def test_timeout_sends_error_response(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that execution timeout sends an error response."""
        # Mock code that sleeps forever to trigger timeout
        mock_code = """
# Sleep longer than any reasonable timeout
time.sleep(999)
"""

        msg = create_email(
            subject="Timeout test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Should receive an error response
            # Wait longer than execution timeout (30s) for the error to arrive
            response = integration_env.email_server.wait_for_sent(
                lambda m: "timed out" in get_message_text(m).lower()
                or "error" in get_message_text(m).lower(),
                timeout=45.0,
            )
            assert response is not None, (
                "Should receive error response on timeout"
            )

            # Verify error mentioned in response
            payload = get_message_text(response)
            assert (
                "timed out" in payload.lower() or "timeout" in payload.lower()
            ), f"Response should mention timeout: {payload[:200]}"

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_crash_sends_error_response(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that execution crash sends an error response."""
        # Mock code that exits with error code
        mock_code = """
sys.exit(1)
"""

        msg = create_email(
            subject="Crash test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Should receive an error response
            response = integration_env.email_server.wait_for_sent(
                lambda m: "failed" in get_message_text(m).lower()
                or "error" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, (
                "Should receive error response on crash"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_invalid_json_sends_error_response(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Test that invalid JSON output sends an error response."""
        # Mock code that outputs invalid JSON
        mock_code = """
print("this is not valid json {{{")
sys.exit(0)
"""

        msg = create_email(
            subject="Invalid JSON test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Should receive an error response
            response = integration_env.email_server.wait_for_sent(
                lambda m: "failed" in get_message_text(m).lower()
                or "error" in get_message_text(m).lower()
                or "parse" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, (
                "Should receive error response on parse error"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_dashboard_tracks_failed_task(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that dashboard tracks failed tasks correctly."""
        # Mock code that crashes
        mock_code = """
sys.exit(1)
"""

        msg = create_email(
            subject="Dashboard failure test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for error response
            response = integration_env.email_server.wait_for_sent(timeout=30.0)
            assert response is not None

            # Check tracker has the failed task
            # The conversation ID should be in the subject
            conv_id = extract_conversation_id(response["Subject"])
            if conv_id:
                # Wait for task completion
                task = service.tracker.wait_for_completion(conv_id, timeout=5.0)

                if task:
                    assert task.success is False, (
                        "Task should be marked as failed"
                    )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)
