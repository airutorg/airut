# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack thread title setting.

Tests that the adapter sets the thread title via
``assistant_threads_setTitle`` after sending a reply.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .environment import IntegrationEnvironment


class TestSlackThreadTitle:
    """Test thread title setting."""

    def test_thread_title_set_after_reply(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Thread title is set from the first message text."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Title test reply"),
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
                thread_ts="1700000000.000050",
            )

            # Wait for reply
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "title test" in m.kwargs.get("text", "").lower()
                        or any(
                            "title test" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None

            # Check that setTitle was called
            title_calls = slack_env.slack_server.get_sent_messages(
                method="assistant_threads_setTitle"
            )
            assert len(title_calls) >= 1, (
                "assistant_threads_setTitle not called"
            )

            title_call = title_calls[0]
            assert title_call.kwargs.get("channel_id") == "D_TEST_DM"
            assert title_call.kwargs.get("thread_ts") == "1700000000.000050"

            # Title should be derived from the message text
            title = title_call.kwargs.get("title", "")
            assert len(title) > 0, "Title should not be empty"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
