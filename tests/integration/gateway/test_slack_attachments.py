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
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .environment import IntegrationEnvironment


def _download_patch(url_to_content: dict[str, bytes]):
    """Patch the adapter's ``urlopen`` to serve canned per-URL content."""

    def fake_urlopen(
        req: urllib.request.Request, *args: object, **kwargs: object
    ) -> MagicMock:
        resp = MagicMock()
        resp.read.return_value = url_to_content[req.full_url]
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    return patch(
        "airut.gateway.slack.adapter.urllib.request.urlopen",
        side_effect=fake_urlopen,
    )


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
                        and m.contains("got file")
                    ),
                    timeout=30.0,
                )
                assert reply is not None, "Did not receive reply about file"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_duplicate_attachment_names_both_saved(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Two attachments sharing a name are both saved to the inbox."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        # Both attachments are named data.csv but carry different content.
        mock_code = """
first = inbox / 'data.csv'
second = inbox / 'data-1.csv'
if first.exists() and second.exists():
    msg = f"Both saved: {first.read_text()} / {second.read_text()}"
else:
    msg = "Files missing"

events = [
    generate_system_event(session_id),
    generate_assistant_event(msg),
    generate_result_event(session_id, "Dup check done"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        slack_env.slack_server.wait_for_ready()

        try:
            url_to_content = {
                "https://files.slack.com/first": b"AAA",
                "https://files.slack.com/second": b"BBB",
            }
            with _download_patch(url_to_content):
                slack_env.slack_server.inject_user_message(
                    user_id="U_ALICE",
                    text=mock_code,
                    thread_ts="1700000000.000091",
                    files=[
                        {
                            "name": "data.csv",
                            "url_private_download": (
                                "https://files.slack.com/first"
                            ),
                        },
                        {
                            "name": "data.csv",
                            "url_private_download": (
                                "https://files.slack.com/second"
                            ),
                        },
                    ],
                )

                reply = slack_env.slack_server.wait_for_sent(
                    predicate=lambda m: (
                        m.method == "chat_postMessage"
                        and m.contains("both saved")
                    ),
                    timeout=30.0,
                )
                assert reply is not None, "Both attachments were not saved"
                # Both distinct contents are present (neither clobbered).
                assert reply.contains("AAA")
                assert reply.contains("BBB")
        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_mid_thread_history_attachment_downloaded(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """A file posted before the agent was invited reaches the inbox."""
        assert slack_env.slack_server is not None
        server = slack_env.slack_server
        server.register_user("U_ALICE", display_name="Alice")

        thread_root = "1699999999.000050"
        # An earlier thread message carried an attachment, before the bot
        # was mentioned into the thread.
        server.thread_history = [
            {
                "ts": thread_root,
                "user": "U_ALICE",
                # Slack tags uploads as file_share; replay must keep them.
                "subtype": "file_share",
                "text": "here is the spec",
                "files": [
                    {
                        "name": "spec.txt",
                        "url_private_download": (
                            "https://files.slack.com/spec.txt"
                        ),
                    }
                ],
            },
        ]

        mock_code = """
f = inbox / 'spec.txt'
msg = f"Got spec: {f.read_text()}" if f.exists() else "No spec found"

events = [
    generate_system_event(session_id),
    generate_assistant_event(msg),
    generate_result_event(session_id, "Spec check done"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        server.wait_for_ready()

        try:
            with _download_patch(
                {"https://files.slack.com/spec.txt": b"SPEC-BODY"}
            ):
                server.inject_channel_message(
                    user_id="U_ALICE",
                    text=mock_code,
                    channel_id="C_TEST",
                    ts="1700000000.000200",
                    thread_ts=thread_root,
                )

                reply = server.wait_for_sent(
                    predicate=lambda m: (
                        m.method == "chat_postMessage"
                        and m.contains("got spec")
                    ),
                    timeout=30.0,
                )
                assert reply is not None, "History attachment was not available"
                assert reply.contains("SPEC-BODY")
        finally:
            service.stop()
            service_thread.join(timeout=10.0)
