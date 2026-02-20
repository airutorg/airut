# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack file attachment handling.

Tests that files attached to Slack messages are downloaded to the
inbox directory and available during Claude execution.

Note: Unlike email attachments which are embedded in the MIME message,
Slack attachments are downloaded via URLs.  The download is mocked by
patching ``urllib.request.urlopen`` in the adapter.
"""

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .environment import IntegrationEnvironment


class TestSlackAttachments:
    """Test Slack file attachment download and processing."""

    def test_single_attachment_downloaded_and_available(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """File attachment is downloaded to inbox and accessible."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        attachment_content = b"name,value\nfoo,123\nbar,456\n"

        # Mock code that reads from inbox
        mock_code = """
input_file = inbox / 'data.csv'
if input_file.exists():
    content = input_file.read_text()
    msg = f"Got file: {len(content)} chars"
else:
    msg = "No file found"

events = [
    generate_system_event(session_id),
    generate_assistant_event(msg),
    generate_result_event(session_id, "File check done"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            # Mock urllib for file download
            mock_response = MagicMock()
            mock_response.read.return_value = attachment_content
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock(return_value=False)

            with patch(
                "airut.gateway.slack.adapter.urllib.request.urlopen",
                return_value=mock_response,
            ):
                slack_env.slack_server.inject_user_message(
                    user_id="U_ALICE",
                    text=mock_code,
                    thread_ts="1700000000.000090",
                    files=[
                        {
                            "name": "data.csv",
                            "url_private_download": (
                                "https://files.slack.com/data.csv"
                            ),
                        }
                    ],
                )

                # Wait for reply
                reply = slack_env.slack_server.wait_for_sent(
                    predicate=lambda m: (
                        m.method == "chat_postMessage"
                        and (
                            "got file" in m.kwargs.get("text", "").lower()
                            or any(
                                "got file" in b.get("text", "").lower()
                                for b in m.kwargs.get("blocks", [])
                                if isinstance(b, dict)
                            )
                        )
                    ),
                    timeout=30.0,
                )
                assert reply is not None, "Did not receive reply about file"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
