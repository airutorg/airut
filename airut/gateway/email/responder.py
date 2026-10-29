# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email responder for SMTP sending.

This module provides the EmailResponder class for sending email replies
via SMTP with proper threading headers.
"""

import logging
import re
import secrets
import smtplib
import time
from collections.abc import Generator
from contextlib import contextmanager
from email.utils import parseaddr

from airut.gateway.config import EmailChannelConfig
from airut.gateway.email.composer import (
    Attachment,
    Draft,
    fit_attachments,
    is_size_rejection,
    omitted_note,
)
from airut.gateway.email.microsoft_oauth2 import (
    MicrosoftOAuth2TokenError,
    MicrosoftOAuth2TokenProvider,
)
from airut.units import MB


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

    An 8-character random nonce ensures uniqueness when multiple emails
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
    nonce = secrets.token_hex(4)
    return f"<airut.{conv_id}.{timestamp}.{nonce}@{domain}>"


class SMTPSendError(Exception):
    """Raised when SMTP send operation fails."""


class EmailResponder:
    """SMTP email responder with threading support.

    Attributes:
        config: Email channel configuration.
    """

    def __init__(self, config: EmailChannelConfig) -> None:
        """Initialize email responder.

        Args:
            config: Email channel configuration.
        """
        self.config = config

        # Create Microsoft OAuth2 token provider if configured
        self._token_provider: MicrosoftOAuth2TokenProvider | None = None
        if config.microsoft_oauth2:
            self._token_provider = MicrosoftOAuth2TokenProvider(
                tenant_id=config.microsoft_oauth2.tenant_id,
                client_id=config.microsoft_oauth2.client_id,
                client_secret=config.microsoft_oauth2.client_secret,
            )

        logger.debug(
            "Initialized email responder for: %s",
            config.smtp.server,
        )

    def send_reply(
        self,
        to: str,
        subject: str,
        body: str,
        in_reply_to: str | None = None,
        references: list[str] | None = None,
        attachments: list[tuple[str, bytes]] | None = None,
        message_id: str | None = None,
        footer: str = "",
    ) -> None:
        """Send email reply with threading headers.

        Sends a multipart email with both plain text and HTML
        alternatives, the HTML rendered from the markdown body.

        The message is kept under the size limit — the configured
        ``max_message_size_mb`` or the ``SIZE`` the server advertises,
        whichever is lower — by leaving out the largest attachments.  If
        the server still refuses the message as too large, it is sent
        once more without attachments.  Either way the body names the
        files that were left out.

        Args:
            to: Recipient email address.
            subject: Email subject (should include [ID:...]).
            body: Email body text (plain text or markdown).
            in_reply_to: Message-ID of message being replied to.
            references: List of Message-IDs in thread.
            attachments: Optional list of (filename, content) tuples to attach.
            message_id: Explicit Message-ID for this outgoing message.
                When set, encodes the conversation ID for header-based
                thread resolution on future replies.
            footer: Usage summary, set in italics after the body and
                after any note about attachments that were left out.

        Raises:
            SMTPSendError: If sending fails.
        """
        draft = Draft(
            sender=self.config.account.from_address,
            to=to,
            subject=subject,
            body=body,
            footer=footer,
            in_reply_to=in_reply_to,
            references=references,
            message_id=message_id,
        )
        files = [
            Attachment(filename, content)
            for filename, content in attachments or []
        ]
        try:
            logger.debug("Sending email to %s: %s", to, subject)
            self._deliver(draft, files)
            logger.info("Sent email to %s: %s", to, subject)
        except (
            smtplib.SMTPException,
            OSError,
            MicrosoftOAuth2TokenError,
        ) as e:
            logger.error("Failed to send email: %s", e)
            raise SMTPSendError(f"Failed to send email: {e}")

    def _deliver(self, draft: Draft, attachments: list[Attachment]) -> None:
        """Send *draft*, keeping it under the size limit.

        Raises:
            smtplib.SMTPException: If the server refuses the message.
            OSError: On connection failures.
            MicrosoftOAuth2TokenError: If no OAuth2 token is available.
        """
        with self._connect() as server:
            msg, omitted = fit_attachments(
                draft, attachments, self._size_limit(server)
            )
            try:
                server.send_message(msg)
                return
            except smtplib.SMTPException as e:
                if len(omitted) == len(attachments) or not is_size_rejection(e):
                    raise
                # The server's limit is lower than it advertised (or it
                # advertised none).  The text matters more than the
                # files, so it goes out without them.
                logger.warning(
                    "SMTP server rejected message as too large (%s); "
                    "resending without attachments",
                    e,
                )
        # Some servers hang up after refusing a message, so the resend
        # opens a new session.
        note = omitted_note(
            attachments,
            "because the mail server rejected the email as too large",
        )
        with self._connect() as server:
            server.send_message(draft.build([], note))

    def _size_limit(self, server: smtplib.SMTP) -> int:
        """Return the largest message size to send over *server*.

        That is the configured limit, or the ``SIZE`` the server
        advertised in its EHLO response if that is lower.
        """
        limit = self.config.smtp.max_message_size_mb * MB
        try:
            advertised = int(server.esmtp_features.get("size", ""))
        except ValueError:
            return limit
        # RFC 1870: SIZE 0 means the server sets no fixed limit.
        return min(limit, advertised) if advertised > 0 else limit

    @contextmanager
    def _connect(self) -> Generator[smtplib.SMTP]:
        """Open an SMTP session, upgraded to TLS and authenticated."""
        with smtplib.SMTP(
            self.config.smtp.server, self.config.smtp.port
        ) as server:
            server.ehlo()
            # Only use STARTTLS if the server supports it
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo()  # Re-identify after TLS for AUTH capabilities
            # Only authenticate if required (allows testing without auth)
            if self.config.smtp.require_auth:
                self._authenticate(server)
            yield server

    def _authenticate(self, server: smtplib.SMTP) -> None:
        """Log in with OAuth2 (Microsoft 365) or the account password."""
        if self._token_provider:
            # Microsoft OAuth2: XOAUTH2 SASL mechanism
            auth_string = self._token_provider.generate_xoauth2_string(
                self.config.account.username
            )

            def _xoauth2_authobject(
                _challenge: bytes | None = None,
            ) -> str:
                if _challenge is not None:
                    # Server sent an error challenge (334);
                    # respond with empty string to acknowledge
                    # per the XOAUTH2 spec.
                    return ""
                return auth_string

            server.auth("XOAUTH2", _xoauth2_authobject)
        else:
            assert self.config.account.password is not None
            server.login(
                self.config.account.username,
                self.config.account.password,
            )
