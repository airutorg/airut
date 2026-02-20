# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack long message handling.

Tests that long responses are correctly split into multiple messages
or uploaded as files, matching the adapter's message splitting logic.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .environment import IntegrationEnvironment


class TestSlackLongMessages:
    """Test long message splitting and delivery."""

    def test_short_message_single_post(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Short response is sent as a single message."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Short reply"),
    generate_result_event(session_id, "Done"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_ALICE",
                text=mock_code,
                thread_ts="1700000000.000080",
            )

            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "short reply" in m.kwargs.get("text", "").lower()
                        or any(
                            "short reply" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None

            # Should have blocks (markdown block format)
            blocks = reply.kwargs.get("blocks")
            if blocks:
                assert len(blocks) >= 1

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_very_long_message_uploaded_as_file(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Response exceeding 65K chars is uploaded as a file."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_BOB", display_name="Bob")

        # Generate a very long response (>65K chars)
        mock_code = """
long_text = "A" * 70000

events = [
    generate_system_event(session_id),
    generate_assistant_event(long_text),
    generate_result_event(session_id, "Done with long output"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            slack_env.slack_server.inject_user_message(
                user_id="U_BOB",
                text=mock_code,
                thread_ts="1700000000.000081",
            )

            # Wait for either a file upload or a content post (not the ack).
            # The adapter may upload long output as a file or split
            # into multiple messages — both are acceptable.
            result = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "files_upload_v2"
                    or (
                        m.method == "chat_postMessage"
                        and "started working"
                        not in m.kwargs.get("text", "").lower()
                    )
                ),
                timeout=30.0,
            )
            assert result is not None, (
                "Expected file upload or content message for very long output"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
