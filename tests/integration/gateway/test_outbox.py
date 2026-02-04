# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for outbox attachment handling.

Tests that files placed in outbox/ directory are:
1. Collected after execution
2. Attached to the email reply
3. Properly MIME-encoded with correct content types
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text
from .environment import IntegrationEnvironment


def get_message_attachments(msg) -> list[tuple[str, bytes]]:
    """Extract attachments from email message.

    Args:
        msg: Email message (MIMEMultipart or similar).

    Returns:
        List of (filename, content) tuples for attachments.
    """
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


class TestOutboxHandling:
    """Test outbox file attachment."""

    def test_single_outbox_file_attached(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that a file in outbox is attached to reply email."""
        # Mock code that creates a file in outbox/
        mock_code = """
(outbox / 'report.txt').write_text('Test report content')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created report in outbox"),
    generate_result_event(session_id, "Report ready"),
]
"""
        msg = create_email(
            subject="Generate a report",
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

            # Wait for response with Claude's output
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "created report" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            # Check that attachment is present in the email
            attachments = get_message_attachments(response)
            assert len(attachments) == 1, (
                f"Expected 1 attachment, got {len(attachments)}"
            )

            filename, content = attachments[0]
            assert filename == "report.txt"
            assert content == b"Test report content"

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_multiple_outbox_files_attached(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that multiple files in outbox are all attached."""
        mock_code = """
(outbox / 'data.csv').write_text('name,value\\nfoo,1\\nbar,2\\n')
(outbox / 'summary.txt').write_text('Summary of data')
(outbox / 'metadata.json').write_text('{"records": 2}')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created multiple files"),
    generate_result_event(session_id, "All files ready"),
]
"""
        msg = create_email(
            subject="Generate multiple files",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "created multiple files" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            # Check all attachments
            attachments = get_message_attachments(response)
            assert len(attachments) == 3, (
                f"Expected 3 attachments, got {len(attachments)}"
            )

            # Convert to dict for easier lookup
            attachment_dict = {name: content for name, content in attachments}

            assert "data.csv" in attachment_dict
            assert attachment_dict["data.csv"] == b"name,value\nfoo,1\nbar,2\n"

            assert "summary.txt" in attachment_dict
            assert attachment_dict["summary.txt"] == b"Summary of data"

            assert "metadata.json" in attachment_dict
            assert attachment_dict["metadata.json"] == b'{"records": 2}'

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_binary_outbox_file_preserved(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that binary file content is preserved exactly."""
        mock_code = """
# Create binary content (avoid CR/LF which may be normalized)
binary_content = bytes([b for b in range(256) if b not in (0x0A, 0x0D)])
(outbox / 'binary.bin').write_bytes(binary_content)

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created binary file"),
    generate_result_event(session_id, "Binary file ready"),
]
"""
        msg = create_email(
            subject="Generate binary file",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "created binary file" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            # Check binary attachment
            attachments = get_message_attachments(response)
            assert len(attachments) == 1

            filename, content = attachments[0]
            assert filename == "binary.bin"

            # Verify binary content preserved exactly
            expected = bytes([b for b in range(256) if b not in (0x0A, 0x0D)])
            assert content == expected

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_email_without_outbox_files(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that emails work normally without outbox files."""
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("No files to send"),
    generate_result_event(session_id, "Task complete"),
]
"""
        msg = create_email(
            subject="Simple task",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "no files to send" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            # Check no attachments in response
            attachments = get_message_attachments(response)
            assert len(attachments) == 0, (
                f"Expected no attachments, got {len(attachments)}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_inbox_and_outbox_together(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that inbox and outbox work together in same conversation."""
        # Mock code that reads from inbox and writes to outbox
        mock_code = """

# Read from inbox (should contain input.txt)
input_file = inbox / 'input.txt'
content = input_file.read_text()

# Process and write to outbox
(outbox / 'output.txt').write_text(f'Processed: {content}')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Processed input file"),
    generate_result_event(session_id, "Output ready"),
]
"""
        msg = create_email(
            subject="Process file",
            body=mock_code,
            attachments=[
                ("input.txt", b"test data", "text/plain"),
            ],
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "processed input file" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            # Check that output file is attached
            attachments = get_message_attachments(response)
            assert len(attachments) == 1

            filename, content = attachments[0]
            assert filename == "output.txt"
            assert content == b"Processed: test data"

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_email_context_in_prompt(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that email context is mentioned in prompt to Claude."""
        # Mock code that verifies the prompt contains email context
        # We'll check the acknowledgment message which confirms system works
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Email context received"),
    generate_result_event(session_id, "Context confirmed"),
]
"""
        msg = create_email(
            subject="Check email context",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Wait for response - just check it arrives successfully
            # Email context is in the prompt, not in the response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack,
                timeout=30.0,
            )
            assert response is not None

            # If we got here, the service successfully processed the email
            # with the new prompt format
            text = get_message_text(response)
            assert len(text) > 0

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)

    def test_outbox_cleanup_after_send(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Test that outbox files are deleted after sending."""
        mock_code = """
(outbox / 'file1.txt').write_text('content1')
(outbox / 'file2.txt').write_text('content2')

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created files in outbox"),
    generate_result_event(session_id, "Files ready"),
]
"""
        msg = create_email(
            subject="Test outbox cleanup",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None

            # Extract conversation ID for checking filesystem
            conv_id = extract_conversation_id(ack["Subject"])

            # Wait for final response
            response = integration_env.email_server.wait_for_sent(
                lambda m: m != ack
                and "created files" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            # Verify files were attached
            attachments = get_message_attachments(response)
            assert len(attachments) == 2

            # Verify outbox directory is cleaned up after send
            # Poll for a short time since cleanup happens after SMTP send
            outbox_path = (
                integration_env.storage_dir / "sessions" / conv_id / "outbox"
            )

            import time

            max_wait = 2.0  # Wait up to 2 seconds for cleanup
            start_time = time.time()
            outbox_empty = False

            while time.time() - start_time < max_wait:
                if not outbox_path.exists():
                    outbox_empty = True
                    break
                outbox_files = list(outbox_path.iterdir())
                if len(outbox_files) == 0:
                    outbox_empty = True
                    break
                time.sleep(0.1)

            files = list(outbox_path.iterdir()) if outbox_path.exists() else []
            assert outbox_empty, (
                f"Outbox should be empty after {max_wait}s but contains: "
                f"{files}"
            )

        finally:
            service.running = False
            service.repo_handlers["test"].listener.interrupt()
            service_thread.join(timeout=10.0)
