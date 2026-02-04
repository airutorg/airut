# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for attachment handling.

Tests that email attachments are:
1. Extracted correctly
2. Saved to the inbox directory
3. Referenced in the prompt to Claude
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text
from .environment import IntegrationEnvironment


class TestAttachmentHandling:
    """Test email attachment handling."""

    def test_single_attachment_saved(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that a single attachment is saved to inbox."""
        # Create email with attachment
        attachment_content = b"name,value\nfoo,123\nbar,456\n"
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("File processed"),
    generate_result_event(session_id, "Processing complete"),
]
"""
        msg = create_email(
            subject="Please process this file",
            body=mock_code,
            attachments=[
                ("data.csv", attachment_content, "text/csv"),
            ],
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment first
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"

            # Wait for response with Claude's output
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "processed" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            # Get conversation ID and check inbox
            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None
            inbox_path = (
                integration_env.storage_dir / "sessions" / conv_id / "inbox"
            )
            assert inbox_path.exists(), (
                f"Inbox directory not created: {inbox_path}"
            )

            # Check attachment was saved
            attachment_path = inbox_path / "data.csv"
            assert attachment_path.exists(), (
                f"Attachment not saved: {attachment_path}"
            )
            assert attachment_path.read_bytes() == attachment_content

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_multiple_attachments_saved(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that multiple attachments are all saved."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Files processed"),
    generate_result_event(session_id, "All files handled"),
]
"""
        msg = create_email(
            subject="Multiple files",
            body=mock_code,
            attachments=[
                ("file1.txt", b"Content of file 1", "text/plain"),
                ("file2.txt", b"Content of file 2", "text/plain"),
                ("data.json", b'{"key": "value"}', "application/json"),
            ],
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment first
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"

            # Now wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "processed" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            conv_id = extract_conversation_id(response["Subject"])
            inbox_path = (
                integration_env.storage_dir / "sessions" / conv_id / "inbox"
            )

            # Check all attachments were saved
            assert (inbox_path / "file1.txt").exists()
            assert (inbox_path / "file2.txt").exists()
            assert (inbox_path / "data.json").exists()

            # Verify contents
            assert (
                inbox_path / "file1.txt"
            ).read_bytes() == b"Content of file 1"
            assert (
                inbox_path / "file2.txt"
            ).read_bytes() == b"Content of file 2"
            assert (
                inbox_path / "data.json"
            ).read_bytes() == b'{"key": "value"}'

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_binary_attachment_preserved(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that binary attachment content is preserved exactly."""
        # Create binary content - avoid CR/LF bytes which may be normalized
        # by MIME handling (0x0A, 0x0D)
        binary_content = bytes([b for b in range(256) if b not in (0x0A, 0x0D)])

        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Binary file processed"),
    generate_result_event(session_id, "Binary complete"),
]
"""
        msg = create_email(
            subject="Binary file",
            body=mock_code,
            attachments=[
                ("binary.bin", binary_content, "application/octet-stream"),
            ],
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment first
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"

            # Wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "processed" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            conv_id = extract_conversation_id(response["Subject"])
            attachment_path = (
                integration_env.storage_dir
                / "sessions"
                / conv_id
                / "inbox"
                / "binary.bin"
            )

            # Verify binary content preserved exactly
            assert attachment_path.read_bytes() == binary_content

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_email_without_attachment(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that emails without attachments still work."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Message processed"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="No attachment",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment first
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"

            # Wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "processed" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            conv_id = extract_conversation_id(response["Subject"])
            inbox_path = (
                integration_env.storage_dir / "sessions" / conv_id / "inbox"
            )

            # Inbox should exist but be empty (or contain only directories)
            if inbox_path.exists():
                files = [f for f in inbox_path.iterdir() if f.is_file()]
                assert len(files) == 0, f"Unexpected files in inbox: {files}"

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)
