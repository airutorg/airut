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
import re
import secrets
import smtplib
import time
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parseaddr

from lib.gateway.config import RepoServerConfig
from lib.gateway.microsoft_oauth2 import (
    MicrosoftOAuth2TokenError,
    MicrosoftOAuth2TokenProvider,
)
from lib.markdown import markdown_to_html


logger = logging.getLogger(__name__)

# Pattern to extract domain from an email address.
_EMAIL_DOMAIN_RE = re.compile(r"@([\w.-]+)")


def _extract_domain(email_from: str) -> str:
    """Extract domain from an email From address.

    Handles both bare addresses and "Display Name <addr>" format.

    Args:
        email_from: The From address (may include display name).

    Returns:
        Domain portion of the email address, or "localhost" as fallback.
    """
    _, addr = parseaddr(email_from)
    match = _EMAIL_DOMAIN_RE.search(addr)
    return match.group(1) if match else "localhost"


def generate_message_id(conv_id: str, email_from: str) -> str:
    """Generate a structured Message-ID encoding the conversation ID.

    Format: ``<airut.{conv_id}.{timestamp}.{nonce}@{domain}>``

    The conversation ID can be extracted from this Message-ID by other
    Airut instances or the same instance when processing reply headers
    (In-Reply-To / References).

    A 4-character random nonce ensures uniqueness when multiple emails
    are sent for the same conversation within the same second (e.g.,
    acknowledgment followed by an immediate rejection).

    Args:
        conv_id: 8-character hex conversation ID.
        email_from: The From address used for outbound mail (used to
            derive the domain portion of the Message-ID).

    Returns:
        RFC 5322 compliant Message-ID string.
    """
    domain = _extract_domain(email_from)
    timestamp = int(time.time())
    nonce = secrets.token_hex(2)
    return f"<airut.{conv_id}.{timestamp}.{nonce}@{domain}>"


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

        # Create Microsoft OAuth2 token provider if configured
        self._token_provider: MicrosoftOAuth2TokenProvider | None = None
        if config.microsoft_oauth2_tenant_id:
            assert config.microsoft_oauth2_client_id
            assert config.microsoft_oauth2_client_secret
            self._token_provider = MicrosoftOAuth2TokenProvider(
                tenant_id=config.microsoft_oauth2_tenant_id,
                client_id=config.microsoft_oauth2_client_id,
                client_secret=config.microsoft_oauth2_client_secret,
            )

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
        message_id: str | None = None,
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
            message_id: Explicit Message-ID for this outgoing message.
                When set, encodes the conversation ID for header-based
                thread resolution on future replies.

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

            # Set explicit Message-ID if provided
            if message_id:
                msg["Message-ID"] = message_id

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
                    if self._token_provider:
                        # Microsoft OAuth2: XOAUTH2 SASL mechanism
                        auth_string = (
                            self._token_provider.generate_xoauth2_string(
                                self.config.email_username
                            )
                        )

                        def _xoauth2_authobject(
                            _challenge: bytes | None = None,
                        ) -> str:
                            return auth_string

                        server.auth("XOAUTH2", _xoauth2_authobject)
                    else:
                        server.login(
                            self.config.email_username,
                            self.config.email_password,
                        )
                server.send_message(msg)

            logger.info("Sent email to %s: %s", to, subject)

        except (
            smtplib.SMTPException,
            OSError,
            MicrosoftOAuth2TokenError,
        ) as e:
            logger.error("Failed to send email: %s", e)
            raise SMTPSendError(f"Failed to send email: {e}")
