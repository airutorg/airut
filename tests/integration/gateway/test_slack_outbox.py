# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for Slack outbox file handling.

Tests that files placed in outbox/ during execution are uploaded
to the Slack thread via files_upload_v2, and that the outbox is
cleared afterwards so later turns do not re-upload them.
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import wait_for_conv_completion
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
                    and m.contains("created report")
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
                    and m.contains("created multiple")
                ),
                timeout=30.0,
            )
            assert reply is not None

            # Wait for the second file upload (they happen after reply)
            server = slack_env.slack_server
            second_upload = server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "files_upload_v2"
                    and len(server.get_sent_messages(method="files_upload_v2"))
                    >= 2
                ),
                timeout=10.0,
            )
            assert second_upload is not None, (
                "Expected 2 file uploads, got "
                f"{len(server.get_sent_messages(method='files_upload_v2'))}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_outbox_emptied_after_upload(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """The conversation outbox is emptied once files are uploaded."""
        assert slack_env.slack_server is not None
        server = slack_env.slack_server
        server.register_user("U_DAN", display_name="Dan")

        mock_code = """
(outbox / 'notes.txt').write_text('Notes')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Wrote notes"),
    generate_result_event(session_id, "Notes ready"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        server.wait_for_ready()

        try:
            server.inject_user_message(
                user_id="U_DAN",
                text=mock_code,
                thread_ts="1700000000.000042",
            )

            reply = server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage" and m.contains("wrote notes")
                ),
                timeout=30.0,
            )
            assert reply is not None, "Did not receive reply"

            tasks = service.tracker.get_all_tasks()
            assert tasks
            conv_id = tasks[0].conversation_id
            assert conv_id is not None
            completed = wait_for_conv_completion(service.tracker, conv_id)
            assert completed is not None
            assert completed.status.value == "completed"

            outbox = (
                slack_env.storage_dir / "conversations" / conv_id / "outbox"
            )
            remaining = list(outbox.iterdir()) if outbox.exists() else []
            assert remaining == [], (
                f"Outbox should be empty after upload but contains: {remaining}"
            )

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_outbox_file_not_reuploaded_on_next_turn(
        self,
        slack_env: IntegrationEnvironment,
    ) -> None:
        """A file uploaded once is not re-sent with later replies.

        Repro for the channel bug where every follow-up in an engaged
        thread re-uploaded the previous turns' attachments: the outbox
        lives for the whole conversation, so files left behind after
        delivery were collected again on the next turn.
        """
        assert slack_env.slack_server is not None
        server = slack_env.slack_server
        server.register_user("U_ERIN", display_name="Erin")

        thread_root = "1700000000.000050"

        first_code = """
(outbox / 'report.txt').write_text('First turn report')

events = [
    generate_system_event(session_id),
    generate_assistant_event("First turn done"),
    generate_result_event(session_id, "First complete"),
]
"""
        # The follow-up produces no file of its own, so any upload it
        # triggers is a re-send of the first turn's report.
        second_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Second turn done"),
    generate_result_event(session_id, "Second complete"),
]
"""

        service = slack_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        server.wait_for_ready()

        try:
            # ---- First turn: channel mention that produces a file ----
            server.inject_channel_message(
                user_id="U_ERIN",
                text=first_code,
                channel_id="C_TEST",
                ts=thread_root,
            )

            reply1 = server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage" and m.contains("first turn")
                ),
                timeout=30.0,
            )
            assert reply1 is not None, "Did not receive first reply"

            tasks = service.tracker.get_all_tasks()
            assert tasks
            conv_id = tasks[0].conversation_id
            assert conv_id is not None
            turn1 = wait_for_conv_completion(service.tracker, conv_id)
            assert turn1 is not None
            assert turn1.status.value == "completed", (
                "First turn did not finish"
            )

            uploads = server.get_sent_messages(method="files_upload_v2")
            assert [u.kwargs.get("filename") for u in uploads] == ["report.txt"]

            # ---- Second turn: same thread, no new file ----
            server.inject_channel_message(
                user_id="U_ERIN",
                text=second_code,
                channel_id="C_TEST",
                ts="1700000000.000051",
                thread_ts=thread_root,
            )

            reply2 = server.wait_for_sent(
                predicate=lambda m: (
                    m.method == "chat_postMessage" and m.contains("second turn")
                ),
                timeout=30.0,
            )
            assert reply2 is not None, "Did not receive second reply"

            # The reply text is posted before the uploads, so wait for the
            # follow-up task to finish before counting them.
            turn2 = wait_for_conv_completion(service.tracker, conv_id)
            assert turn2 is not None
            assert turn2.status.value == "completed", (
                "Second turn did not finish"
            )

            uploads = server.get_sent_messages(method="files_upload_v2")
            assert [u.kwargs.get("filename") for u in uploads] == [
                "report.txt"
            ], "First turn's attachment was re-uploaded on the follow-up"

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
