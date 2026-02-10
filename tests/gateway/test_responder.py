# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email responder (SMTP)."""

import smtplib
from unittest.mock import MagicMock, patch

import pytest

from lib.gateway.responder import EmailResponder, SMTPSendError


def test_responder_init(email_config):
    """Test responder initialization."""
    responder = EmailResponder(email_config)
    assert responder.config == email_config
    assert responder._token_provider is None


def test_responder_init_with_oauth2(microsoft_oauth2_email_config):
    """Test responder initialization with Microsoft OAuth2."""
    responder = EmailResponder(microsoft_oauth2_email_config)
    assert responder._token_provider is not None


def test_send_reply_success(email_config):
    """Test sending reply successfully."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="[ID:abc12345] Re: Test",
            body="This is the reply.",
            in_reply_to="<msg123@example.com>",
            references=["<msg1@example.com>", "<msg123@example.com>"],
        )

        mock_smtp_class.assert_called_once_with(
            email_config.smtp_server, email_config.smtp_port
        )
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with(
            email_config.email_username, email_config.email_password
        )
        mock_server.send_message.assert_called_once()

        # Verify message structure (multipart alternative)
        sent_message = mock_server.send_message.call_args[0][0]
        assert sent_message["From"] == email_config.email_from
        assert sent_message["To"] == "recipient@example.com"
        assert sent_message["Subject"] == "[ID:abc12345] Re: Test"
        assert sent_message["In-Reply-To"] == "<msg123@example.com>"
        assert (
            sent_message["References"]
            == "<msg1@example.com> <msg123@example.com>"
        )
        # Verify multipart structure
        assert sent_message.is_multipart()
        parts = sent_message.get_payload()
        assert len(parts) == 2
        assert parts[0].get_content_type() == "text/plain"
        assert parts[1].get_content_type() == "text/html"


def test_send_reply_without_threading(email_config):
    """Test sending reply without threading headers."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="[ID:abc12345] New conversation",
            body="This is a new conversation.",
        )

        # Verify message doesn't have threading headers
        sent_message = mock_server.send_message.call_args[0][0]
        assert "In-Reply-To" not in sent_message
        assert "References" not in sent_message


def test_send_reply_smtp_exception(email_config):
    """Test sending reply with SMTP exception."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server
        mock_server.send_message.side_effect = smtplib.SMTPException(
            "SMTP error"
        )

        with pytest.raises(SMTPSendError, match="Failed to send email"):
            responder.send_reply(
                to="recipient@example.com",
                subject="Test",
                body="Body",
            )


def test_send_reply_connection_error(email_config):
    """Test sending reply with connection error."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_smtp_class.side_effect = OSError("Connection refused")

        with pytest.raises(SMTPSendError, match="Failed to send email"):
            responder.send_reply(
                to="recipient@example.com",
                subject="Test",
                body="Body",
            )


def test_send_reply_starttls_error(email_config):
    """Test sending reply with STARTTLS error."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server
        mock_server.starttls.side_effect = smtplib.SMTPException(
            "STARTTLS failed"
        )

        with pytest.raises(SMTPSendError, match="Failed to send email"):
            responder.send_reply(
                to="recipient@example.com",
                subject="Test",
                body="Body",
            )


def test_send_reply_auth_error(email_config):
    """Test sending reply with authentication error."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(
            535, "Authentication failed"
        )

        with pytest.raises(SMTPSendError, match="Failed to send email"):
            responder.send_reply(
                to="recipient@example.com",
                subject="Test",
                body="Body",
            )


def test_send_reply_empty_references(email_config):
    """Test sending reply with empty references list."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body="Body",
            in_reply_to="<msg@example.com>",
            references=[],
        )

        sent_message = mock_server.send_message.call_args[0][0]
        assert sent_message["In-Reply-To"] == "<msg@example.com>"
        # Empty references list should still set the header (to empty string)
        assert (
            "References" not in sent_message or sent_message["References"] == ""
        )


def test_send_reply_unicode_content(email_config):
    """Test sending reply with unicode content."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="[ID:abc12345] Test 世界 café",
            body="Hello 世界 café! This is a test.",
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]
        assert (
            "世界" in sent_message["Subject"] or "?" in sent_message["Subject"]
        )


def test_send_reply_with_explicit_html_body(email_config):
    """Test sending reply with explicit HTML body."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        plain_body = "Plain text body"
        html_body = "<p>Custom <strong>HTML</strong> body</p>"

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body=plain_body,
            html_body=html_body,
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]

        # Verify multipart structure with custom HTML
        assert sent_message.is_multipart()
        parts = sent_message.get_payload()
        assert len(parts) == 2

        # Plain text part
        assert parts[0].get_content_type() == "text/plain"
        assert plain_body in parts[0].get_payload()

        # HTML part should use explicit html_body
        assert parts[1].get_content_type() == "text/html"
        assert html_body in parts[1].get_payload()


def test_send_reply_markdown_to_html_conversion(email_config):
    """Test markdown is converted to HTML when no explicit html_body."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        # Body with markdown
        markdown_body = "# Header\n\nThis is **bold** text."

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body=markdown_body,
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]

        # Verify multipart structure
        assert sent_message.is_multipart()
        parts = sent_message.get_payload()

        # HTML part should have converted markdown
        # h1 is rendered as bold underline to keep font size constant
        html_content = parts[1].get_payload()
        assert "<strong><u>Header</u></strong>" in html_content
        assert "<strong>bold</strong>" in html_content


def test_send_reply_with_single_attachment(email_config):
    """Test sending reply with a single attachment."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="[ID:abc12345] Re: Test",
            body="Here is the report.",
            attachments=[("report.txt", b"Report content")],
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]

        # Verify message structure (multipart mixed with nested alternative)
        assert sent_message.is_multipart()
        assert sent_message.get_content_type() == "multipart/mixed"

        parts = sent_message.get_payload()
        assert len(parts) == 2

        # First part should be the alternative (text + HTML)
        assert parts[0].get_content_type() == "multipart/alternative"
        alt_parts = parts[0].get_payload()
        assert len(alt_parts) == 2
        assert alt_parts[0].get_content_type() == "text/plain"
        assert alt_parts[1].get_content_type() == "text/html"

        # Second part should be the attachment
        assert parts[1].get_content_disposition() == "attachment"
        assert parts[1].get_filename() == "report.txt"


def test_send_reply_with_multiple_attachments(email_config):
    """Test sending reply with multiple attachments."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body="Multiple files attached.",
            attachments=[
                ("file1.txt", b"Content 1"),
                ("file2.csv", b"name,value\n"),
                ("file3.json", b'{"key": "value"}'),
            ],
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]

        # Verify message structure
        assert sent_message.is_multipart()
        assert sent_message.get_content_type() == "multipart/mixed"

        parts = sent_message.get_payload()
        assert len(parts) == 4  # 1 alternative + 3 attachments

        # Check attachments
        assert parts[1].get_filename() == "file1.txt"
        assert parts[2].get_filename() == "file2.csv"
        assert parts[3].get_filename() == "file3.json"


def test_send_reply_without_attachments(email_config):
    """Test sending reply without attachments uses alternative structure."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body="No attachments.",
            attachments=None,
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]

        # Without attachments, should use alternative (not mixed)
        assert sent_message.is_multipart()
        assert sent_message.get_content_type() == "multipart/alternative"

        parts = sent_message.get_payload()
        assert len(parts) == 2
        assert parts[0].get_content_type() == "text/plain"
        assert parts[1].get_content_type() == "text/html"


def test_send_reply_with_binary_attachment(email_config):
    """Test sending reply with binary attachment."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        binary_content = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE])

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body="Binary file attached.",
            attachments=[("binary.bin", binary_content)],
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]

        parts = sent_message.get_payload()
        assert len(parts) == 2

        # Check attachment
        attachment = parts[1]
        assert attachment.get_filename() == "binary.bin"
        assert attachment.get_content_type() == "application/octet-stream"


def test_send_reply_with_unknown_extension_attachment(email_config):
    """Test attachment with unknown file extension."""
    responder = EmailResponder(email_config)

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body="File with unknown extension.",
            attachments=[("data.xyz123", b"Unknown format")],
        )

        mock_server.send_message.assert_called_once()
        sent_message = mock_server.send_message.call_args[0][0]

        parts = sent_message.get_payload()
        # Check that unknown extension defaults to octet-stream
        attachment = parts[1]
        assert attachment.get_filename() == "data.xyz123"
        assert attachment.get_content_type() == "application/octet-stream"


def test_send_reply_oauth2_xoauth2(microsoft_oauth2_email_config):
    """Test SMTP authentication with Microsoft OAuth2 uses XOAUTH2."""
    responder = EmailResponder(microsoft_oauth2_email_config)
    assert responder._token_provider is not None

    with (
        patch("smtplib.SMTP") as mock_smtp_class,
        patch.object(
            responder._token_provider,
            "generate_xoauth2_string",
            return_value="user=test@company.com\x01auth=Bearer tok\x01\x01",
        ) as mock_gen,
    ):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        responder.send_reply(
            to="recipient@example.com",
            subject="Test",
            body="OAuth2 reply.",
        )

        # Should use auth() with XOAUTH2, not login()
        mock_server.login.assert_not_called()
        mock_server.auth.assert_called_once()
        call_args = mock_server.auth.call_args
        assert call_args[0][0] == "XOAUTH2"
        # The second arg is a callable; invoke it to verify the auth string
        auth_fn = call_args[0][1]
        assert (
            auth_fn(b"") == "user=test@company.com\x01auth=Bearer tok\x01\x01"
        )
        mock_gen.assert_called_once_with(
            microsoft_oauth2_email_config.email_username
        )
        mock_server.send_message.assert_called_once()


def test_send_reply_oauth2_token_error_raises_smtp_send_error(
    microsoft_oauth2_email_config,
):
    """Test OAuth2 token errors are wrapped in SMTPSendError."""
    from lib.gateway.microsoft_oauth2 import MicrosoftOAuth2TokenError

    responder = EmailResponder(microsoft_oauth2_email_config)
    assert responder._token_provider is not None

    with (
        patch("smtplib.SMTP") as mock_smtp_class,
        patch.object(
            responder._token_provider,
            "generate_xoauth2_string",
            side_effect=MicrosoftOAuth2TokenError("invalid_client: Bad secret"),
        ),
    ):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        with pytest.raises(SMTPSendError, match="Failed to send email"):
            responder.send_reply(
                to="recipient@example.com",
                subject="Test",
                body="OAuth2 reply.",
            )
