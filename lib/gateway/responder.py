# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email responder for SMTP sending.

This module provides the EmailResponder class for sending email replies
via SMTP with proper threading headers.
"""

import logging
import mimetypes
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from lib.gateway.config import RepoServerConfig
from lib.markdown import markdown_to_html


logger = logging.getLogger(__name__)


class SMTPSendError(Exception):
    """Raised when SMTP send operation fails."""


class EmailResponder:
    """SMTP email responder with threading support.

    Attributes:
        config: Email service configuration.
    """

    def __init__(self, config: RepoServerConfig) -> None:
        """Initialize email responder.

        Args:
            config: Email service configuration.
        """
        self.config = config
        logger.debug(
            "Initialized email responder for: %s",
            config.smtp_server,
        )

    def send_reply(
        self,
        to: str,
        subject: str,
        body: str,
        in_reply_to: str | None = None,
        references: list[str] | None = None,
        html_body: str | None = None,
        attachments: list[tuple[str, bytes]] | None = None,
    ) -> None:
        """Send email reply with threading headers.

        Sends a multipart email with both plain text and HTML alternatives.
        If html_body is not provided, the body is converted from markdown
        to HTML automatically.

        Args:
            to: Recipient email address.
            subject: Email subject (should include [ID:...]).
            body: Email body text (plain text or markdown).
            in_reply_to: Message-ID of message being replied to.
            references: List of Message-IDs in thread.
            html_body: Optional pre-rendered HTML body. If not provided,
                body is converted from markdown to HTML.
            attachments: Optional list of (filename, content) tuples to attach.

        Raises:
            SMTPSendError: If sending fails.
        """
        try:
            # Create multipart message with text and HTML alternatives
            # If we have attachments, use "mixed" as the top level
            if attachments:
                msg = MIMEMultipart("mixed")
            else:
                msg = MIMEMultipart("alternative")

            msg["From"] = self.config.email_from
            msg["To"] = to
            msg["Subject"] = subject

            # Threading headers
            if in_reply_to:
                msg["In-Reply-To"] = in_reply_to

            if references:
                msg["References"] = " ".join(references)

            # Create the alternative part (text + HTML) for the body
            if attachments:
                # With attachments, nest alternative inside mixed
                alt_part = MIMEMultipart("alternative")
                alt_part.attach(MIMEText(body, "plain"))
                html_content = (
                    html_body if html_body else markdown_to_html(body)
                )
                alt_part.attach(MIMEText(html_content, "html"))
                msg.attach(alt_part)
            else:
                # Without attachments, attach directly to message
                msg.attach(MIMEText(body, "plain"))
                html_content = (
                    html_body if html_body else markdown_to_html(body)
                )
                msg.attach(MIMEText(html_content, "html"))

            # Attach files if provided
            if attachments:
                for filename, content in attachments:
                    # Guess MIME type based on filename
                    mime_type, _ = mimetypes.guess_type(filename)
                    if mime_type is None:
                        mime_type = "application/octet-stream"

                    # Split into maintype/subtype
                    maintype, subtype = mime_type.split("/", 1)

                    attachment = MIMEApplication(
                        content, _subtype=subtype, name=filename
                    )
                    attachment.add_header(
                        "Content-Disposition", "attachment", filename=filename
                    )
                    msg.attach(attachment)
                    logger.debug(
                        "Attached file: %s (%d bytes, %s)",
                        filename,
                        len(content),
                        mime_type,
                    )

            logger.debug("Sending email to %s: %s", to, subject)

            with smtplib.SMTP(
                self.config.smtp_server, self.config.smtp_port
            ) as server:
                server.ehlo()
                # Only use STARTTLS if the server supports it
                if server.has_extn("STARTTLS"):
                    server.starttls()
                    server.ehlo()  # Re-identify after TLS for AUTH capabilities
                # Only authenticate if required (allows testing without auth)
                if self.config.smtp_require_auth:
                    server.login(
                        self.config.email_username, self.config.email_password
                    )
                server.send_message(msg)

            logger.info("Sent email to %s: %s", to, subject)

        except (smtplib.SMTPException, OSError) as e:
            logger.error("Failed to send email: %s", e)
            raise SMTPSendError(f"Failed to send email: {e}")
