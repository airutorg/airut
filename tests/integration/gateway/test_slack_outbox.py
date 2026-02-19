# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack outbox file handling.

Tests that files placed in outbox/ during execution are uploaded
to the Slack thread via files_upload_v2.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .environment import IntegrationEnvironment


class TestSlackOutbox:
    """Test outbox file upload via Slack."""

    def test_single_outbox_file_uploaded(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """File in outbox is uploaded to Slack thread."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_ALICE", display_name="Alice")

        mock_code = """
(outbox / 'report.txt').write_text('Test report content')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created report in outbox"),
    generate_result_event(session_id, "Report ready"),
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
                thread_ts="1700000000.000040",
            )

            # Wait for reply with Claude's output
            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "created report" in m.kwargs.get("text", "").lower()
                        or any(
                            "created report" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None, "Did not receive reply"

            # Wait for file upload (happens after reply in send_reply)
            upload = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: m.method == "files_upload_v2",
                timeout=10.0,
            )
            assert upload is not None, "Expected file upload"
            assert upload.kwargs.get("thread_ts") == "1700000000.000040"

            # Check file content was preserved
            file_content = upload.kwargs.get("_file_content")
            if file_content is not None:
                assert file_content == b"Test report content"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_multiple_outbox_files_uploaded(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """Multiple outbox files are all uploaded to thread."""
        assert slack_env.slack_server is not None
        slack_env.slack_server.register_user("U_BOB", display_name="Bob")

        mock_code = """
(outbox / 'data.csv').write_text('name,value\\nfoo,1\\n')
(outbox / 'summary.txt').write_text('Summary')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created multiple files"),
    generate_result_event(session_id, "Files ready"),
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
                thread_ts="1700000000.000041",
            )

            reply = slack_env.slack_server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage"
                    and (
                        "created multiple" in m.kwargs.get("text", "").lower()
                        or any(
                            "created multiple" in b.get("text", "").lower()
                            for b in m.kwargs.get("blocks", [])
                            if isinstance(b, dict)
                        )
                    )
                ),
                timeout=30.0,
            )
            assert reply is not None

            # Wait for file uploads (happen after reply in send_reply)
            import time

            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                uploads = slack_env.slack_server.get_sent_messages(
                    method="files_upload_v2"
                )
                if len(uploads) >= 2:
                    break
                time.sleep(0.2)

            uploads = slack_env.slack_server.get_sent_messages(
                method="files_upload_v2"
            )
            assert len(uploads) >= 2, (
                f"Expected 2 file uploads, got {len(uploads)}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
