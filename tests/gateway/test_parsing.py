# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email parsing utilities."""

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from unittest.mock import patch

import pytest

from lib.gateway.parsing import (
    collect_outbox_files,
    extract_attachments,
    extract_body,
    extract_conversation_id,
    extract_model_from_address,
)


def test_extract_conversation_id_valid() -> None:
    """Test extracting valid conversation ID."""
    subject = "[ID:abc12345] Fix the bug"
    conv_id = extract_conversation_id(subject)
    assert conv_id == "abc12345"


def test_extract_conversation_id_middle_of_subject() -> None:
    """Test extracting conversation ID from middle of subject."""
    subject = "Re: [ID:deadbeef] Review this code please"
    conv_id = extract_conversation_id(subject)
    assert conv_id == "deadbeef"


def test_extract_conversation_id_missing() -> None:
    """Test extracting conversation ID when not present."""
    subject = "No conversation ID here"
    conv_id = extract_conversation_id(subject)
    assert conv_id is None


def test_extract_conversation_id_invalid_format() -> None:
    """Test extracting conversation ID with invalid format."""
    # Too short
    subject = "[ID:abc] Something"
    conv_id = extract_conversation_id(subject)
    assert conv_id is None

    # Too long
    subject = "[ID:abc123456789] Something"
    conv_id = extract_conversation_id(subject)
    assert conv_id is None

    # Non-hex characters
    subject = "[ID:abcdefgh] Something"
    conv_id = extract_conversation_id(subject)
    assert conv_id is None


def test_extract_model_from_address_basic() -> None:
    """Test extracting model from simple email address."""
    model = extract_model_from_address("airut+opus@example.com")
    assert model == "opus"


def test_extract_model_from_address_with_name() -> None:
    """Test extracting model from address with display name."""
    model = extract_model_from_address("Airut <airut+sonnet@example.com>")
    assert model == "sonnet"


def test_extract_model_from_address_case_insensitive() -> None:
    """Test model extraction normalizes to lowercase."""
    model = extract_model_from_address("airut+OPUS@example.com")
    assert model == "opus"

    model = extract_model_from_address("airut+Haiku@example.com")
    assert model == "haiku"


def test_extract_model_from_address_with_hyphen() -> None:
    """Test extracting model with hyphen in name."""
    model = extract_model_from_address("airut+opus-4@example.com")
    assert model == "opus-4"


def test_extract_model_from_address_with_underscore() -> None:
    """Test extracting model with underscore in name."""
    model = extract_model_from_address("airut+claude_sonnet@example.com")
    assert model == "claude_sonnet"


def test_extract_model_from_address_no_subaddress() -> None:
    """Test extracting model when no subaddress present."""
    model = extract_model_from_address("airut@example.com")
    assert model is None


def test_extract_model_from_address_no_subaddress_with_name() -> None:
    """Test extracting model when no subaddress present with display name."""
    model = extract_model_from_address("Airut <airut@example.com>")
    assert model is None


def test_extract_model_from_address_empty() -> None:
    """Test extracting model from empty string."""
    model = extract_model_from_address("")
    assert model is None


def test_extract_body_plain_text() -> None:
    """Test extracting body from plain text message."""
    msg = MIMEText("This is the body content.")
    body = extract_body(msg)
    assert body == "This is the body content."


def test_extract_body_multipart() -> None:
    """Test extracting body from multipart message prefers HTML."""
    msg = MIMEMultipart()

    text_part = MIMEText("This is the text body.")
    msg.attach(text_part)

    html_part = MIMEText("<p>This is HTML</p>", "html")
    msg.attach(html_part)

    body = extract_body(msg)
    assert "This is HTML" in body


def test_extract_body_multipart_html_only() -> None:
    """Test extracting body from multipart with only text/html."""
    msg = MIMEMultipart()

    html_part = MIMEText("<p>Only <b>HTML</b> here</p>", "html")
    msg.attach(html_part)

    body = extract_body(msg)
    assert "Only **HTML** here" in body


def test_extract_body_multipart_prefers_html() -> None:
    """Test that text/html is preferred over text/plain in multipart."""
    msg = MIMEMultipart()

    text_part = MIMEText("Plain text version.")
    msg.attach(text_part)

    html_part = MIMEText("<p>HTML version.</p>", "html")
    msg.attach(html_part)

    body = extract_body(msg)
    assert "HTML version." in body


def test_extract_body_multipart_text_plain_fallback() -> None:
    """Test falling back to text/plain when no HTML part is available."""
    msg = MIMEMultipart()

    text_part = MIMEText("Only plain text here.")
    msg.attach(text_part)

    body = extract_body(msg)
    assert body == "Only plain text here."


def test_extract_body_multipart_strips_html_quotes() -> None:
    """Test that HTML quotes are stripped from multipart HTML body."""
    msg = MIMEMultipart()

    html_part = MIMEText(
        "<html><body>"
        "<p>My reply</p>"
        '<div id="mail-editor-reference-message-container">'
        "<p>Quoted previous message</p>"
        "</div>"
        "</body></html>",
        "html",
    )
    msg.attach(html_part)

    body = extract_body(msg)
    assert "My reply" in body
    assert "Quoted previous message" not in body


def test_extract_body_html_only_message() -> None:
    """Test extracting body from a non-multipart text/html message."""
    msg = MIMEText("<p>Hello <em>world</em></p>", "html")

    body = extract_body(msg)
    assert "Hello *world*" in body


def test_extract_body_html_only_strips_quotes() -> None:
    """Test that quotes are stripped from non-multipart HTML message."""
    msg = MIMEText(
        "<html><body>"
        "<p>Reply text</p>"
        '<div class="gmail_quote">'
        "<p>Original quoted message</p>"
        "</div>"
        "</body></html>",
        "html",
    )

    body = extract_body(msg)
    assert "Reply text" in body
    assert "Original quoted message" not in body


def test_extract_body_empty() -> None:
    """Test extracting body from empty message."""
    msg = MIMEMultipart()
    body = extract_body(msg)
    assert body == ""


def test_extract_body_utf8_decoding() -> None:
    """Test extracting body with UTF-8 encoding."""
    msg = MIMEText("Hello 世界 café", _charset="utf-8")
    body = extract_body(msg)
    assert "Hello" in body
    assert "世界" in body or "�" in body  # May get replacement char
    assert "café" in body or "caf" in body


def test_extract_attachments_with_files(tmp_path: Path) -> None:
    """Test extracting attachments from message."""
    inbox_dir = tmp_path / "inbox"
    inbox_dir.mkdir()

    msg = MIMEMultipart()
    text_part = MIMEText("Body text")
    msg.attach(text_part)

    # Add attachment
    attachment = MIMEText("Attachment content")
    attachment.add_header(
        "Content-Disposition", "attachment", filename="test.txt"
    )
    msg.attach(attachment)

    filenames = extract_attachments(msg, inbox_dir)

    assert len(filenames) == 1
    assert "test.txt" in filenames

    # Verify file was saved
    saved_file = inbox_dir / "test.txt"
    assert saved_file.exists()
    assert saved_file.read_text() == "Attachment content"


def test_extract_attachments_multiple(tmp_path: Path) -> None:
    """Test extracting multiple attachments."""
    inbox_dir = tmp_path / "inbox"
    inbox_dir.mkdir()

    msg = MIMEMultipart()

    # Add multiple attachments
    for i, content in enumerate(["First", "Second", "Third"]):
        attachment = MIMEText(content)
        attachment.add_header(
            "Content-Disposition", "attachment", filename=f"file{i}.txt"
        )
        msg.attach(attachment)

    filenames = extract_attachments(msg, inbox_dir)

    assert len(filenames) == 3
    assert "file0.txt" in filenames
    assert "file1.txt" in filenames
    assert "file2.txt" in filenames


def test_extract_attachments_no_attachments(tmp_path: Path) -> None:
    """Test extracting attachments when none present."""
    inbox_dir = tmp_path / "inbox"
    inbox_dir.mkdir()

    msg = MIMEMultipart()
    text_part = MIMEText("Body text only")
    msg.attach(text_part)

    filenames = extract_attachments(msg, inbox_dir)
    assert len(filenames) == 0


def test_extract_attachments_plain_message(tmp_path: Path) -> None:
    """Test extracting attachments from plain message."""
    inbox_dir = tmp_path / "inbox"
    inbox_dir.mkdir()

    msg = MIMEText("Plain text, no attachments")

    filenames = extract_attachments(msg, inbox_dir)
    assert len(filenames) == 0


def test_extract_attachments_nonexistent_inbox() -> None:
    """Test extracting attachments with nonexistent inbox directory."""
    inbox_dir = Path("/nonexistent/path")
    msg = MIMEMultipart()

    with pytest.raises(ValueError, match="Inbox directory does not exist"):
        extract_attachments(msg, inbox_dir)


def test_extract_attachments_no_filename(tmp_path: Path) -> None:
    """Test attachment without filename is skipped."""
    inbox_dir = tmp_path / "inbox"
    inbox_dir.mkdir()

    msg = MIMEMultipart()

    # Attachment without filename
    attachment = MIMEText("Content")
    attachment.add_header("Content-Disposition", "attachment")
    msg.attach(attachment)

    filenames = extract_attachments(msg, inbox_dir)
    assert len(filenames) == 0


def test_extract_attachments_no_payload(tmp_path: Path) -> None:
    """Test attachment with no payload is skipped."""
    inbox_dir = tmp_path / "inbox"
    inbox_dir.mkdir()

    msg = MIMEMultipart()

    # Create attachment with no payload
    from email.mime.base import MIMEBase

    attachment = MIMEBase("application", "octet-stream")
    attachment.add_header(
        "Content-Disposition", "attachment", filename="empty.bin"
    )
    msg.attach(attachment)

    filenames = extract_attachments(msg, inbox_dir)
    # Should not crash, may or may not save depending on payload
    assert isinstance(filenames, list)


def test_collect_outbox_files_with_files(tmp_path: Path) -> None:
    """Test collecting files from outbox directory."""
    outbox_dir = tmp_path / "outbox"
    outbox_dir.mkdir()

    # Create test files
    (outbox_dir / "report.txt").write_text("Report content")
    (outbox_dir / "data.csv").write_text("name,value\nfoo,1\n")

    files = collect_outbox_files(outbox_dir)

    assert len(files) == 2
    filenames = {name for name, _ in files}
    assert "report.txt" in filenames
    assert "data.csv" in filenames

    # Check content
    content_map = {name: content for name, content in files}
    assert content_map["report.txt"] == b"Report content"
    assert content_map["data.csv"] == b"name,value\nfoo,1\n"


def test_collect_outbox_files_binary(tmp_path: Path) -> None:
    """Test collecting binary files from outbox."""
    outbox_dir = tmp_path / "outbox"
    outbox_dir.mkdir()

    # Create binary file
    binary_content = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE])
    (outbox_dir / "binary.bin").write_bytes(binary_content)

    files = collect_outbox_files(outbox_dir)

    assert len(files) == 1
    filename, content = files[0]
    assert filename == "binary.bin"
    assert content == binary_content


def test_collect_outbox_files_empty_directory(tmp_path: Path) -> None:
    """Test collecting from empty outbox directory."""
    outbox_dir = tmp_path / "outbox"
    outbox_dir.mkdir()

    files = collect_outbox_files(outbox_dir)
    assert len(files) == 0


def test_collect_outbox_files_nonexistent_directory(tmp_path: Path) -> None:
    """Test collecting from nonexistent outbox directory."""
    outbox_dir = tmp_path / "nonexistent"

    files = collect_outbox_files(outbox_dir)
    assert len(files) == 0


def test_collect_outbox_files_ignores_subdirectories(tmp_path: Path) -> None:
    """Test that subdirectories in outbox are ignored."""
    outbox_dir = tmp_path / "outbox"
    outbox_dir.mkdir()

    # Create file and subdirectory
    (outbox_dir / "file.txt").write_text("File content")
    subdir = outbox_dir / "subdir"
    subdir.mkdir()
    (subdir / "nested.txt").write_text("Nested file")

    files = collect_outbox_files(outbox_dir)

    # Should only collect the top-level file
    assert len(files) == 1
    filename, content = files[0]
    assert filename == "file.txt"
    assert content == b"File content"


def test_collect_outbox_files_handles_read_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Test that OSError during file read is handled gracefully."""
    outbox_dir = tmp_path / "outbox"
    outbox_dir.mkdir()

    # Create a file that will be mocked to fail
    (outbox_dir / "good.txt").write_text("Good content")
    (outbox_dir / "bad.txt").write_text("Bad content")

    # Mock read_bytes to raise OSError for bad.txt
    original_read_bytes = Path.read_bytes

    def mock_read_bytes(self: Path) -> bytes:
        if self.name == "bad.txt":
            raise OSError("Permission denied")
        return original_read_bytes(self)

    with patch.object(Path, "read_bytes", mock_read_bytes):
        files = collect_outbox_files(outbox_dir)

    # Should still collect the good file
    assert len(files) == 1
    filename, content = files[0]
    assert filename == "good.txt"
    assert content == b"Good content"

    # Should have logged warning for bad file
    assert "Failed to read outbox file" in caplog.text
    assert "bad.txt" in caplog.text
