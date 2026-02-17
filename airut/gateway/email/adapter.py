# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email channel adapter.

Implements the ChannelAdapter protocol for email, wrapping DMARC
authentication, MIME parsing, and SMTP reply delivery.
"""

from __future__ import annotations

import html as html_module
import logging
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path

from airut.gateway.channel import (
    AuthenticationError,
    ChannelAdapter,
    ParsedMessage,
    RawMessage,
)
from airut.gateway.config import EmailChannelConfig
from airut.gateway.email.channel_listener import EmailChannelListener
from airut.gateway.email.parsing import (
    collect_outbox_files,
    decode_subject,
    extract_attachments,
    extract_body,
    extract_conversation_id,
    extract_conversation_id_from_headers,
    extract_model_from_address,
)
from airut.gateway.email.responder import (
    EmailResponder,
    SMTPSendError,
    generate_message_id,
)
from airut.gateway.email.security import SenderAuthenticator, SenderAuthorizer


logger = logging.getLogger(__name__)


@dataclass
class EmailParsedMessage(ParsedMessage):
    """Email-specific parsed message with threading state.

    Carries the additional fields needed for constructing email replies
    (Message-ID references, decoded subject). The core treats this as
    a plain ParsedMessage; the adapter downcasts when sending replies.
    """

    original_message_id: str | None = None
    """Message-ID of the incoming email for In-Reply-To."""

    original_references: list[str] = field(default_factory=list)
    """References header values for threading."""

    decoded_subject: str = ""
    """Decoded subject line for reply construction."""

    _raw_message: Message | None = field(default=None, repr=False)
    """Raw email message retained for deferred attachment extraction.

    Set by authenticate_and_parse() and consumed by save_attachments().
    Not part of the public ParsedMessage interface."""


class EmailChannelAdapter(ChannelAdapter):
    """ChannelAdapter implementation for email (IMAP/SMTP).

    Wraps SenderAuthenticator, SenderAuthorizer, email parsing functions,
    EmailListener, and EmailResponder behind the ChannelAdapter interface.
    """

    def __init__(
        self,
        config: EmailChannelConfig,
        authenticator: SenderAuthenticator,
        authorizer: SenderAuthorizer,
        responder: EmailResponder,
        listener: EmailChannelListener | None = None,
        *,
        repo_id: str,
    ) -> None:
        self._config = config
        self._repo_id = repo_id
        self._authenticator = authenticator
        self._authorizer = authorizer
        self._responder = responder
        self._listener = listener

    @classmethod
    def from_config(
        cls, config: EmailChannelConfig, *, repo_id: str
    ) -> EmailChannelAdapter:
        """Create an adapter with all email components from config.

        Constructs the authenticator, authorizer, responder, and listener
        internally. This is the primary factory for production use.

        Args:
            config: Email channel configuration.
            repo_id: Repository identifier (used for log messages).

        Returns:
            Fully configured EmailChannelAdapter.
        """
        return cls(
            config=config,
            authenticator=SenderAuthenticator(
                config.trusted_authserv_id,
                allow_internal_auth_fallback=(
                    config.microsoft_internal_auth_fallback
                ),
            ),
            authorizer=SenderAuthorizer(config.authorized_senders),
            responder=EmailResponder(config),
            listener=EmailChannelListener(config, repo_id=repo_id),
            repo_id=repo_id,
        )

    @property
    def listener(self) -> EmailChannelListener:
        """Email channel listener for message lifecycle management.

        Raises:
            RuntimeError: If adapter was created without a listener.
        """
        if self._listener is None:
            raise RuntimeError("EmailChannelAdapter created without a listener")
        return self._listener

    @property
    def responder(self) -> EmailResponder:
        """Expose responder for low-level SMTP access."""
        return self._responder

    def authenticate_and_parse(
        self, raw_message: RawMessage[Message]
    ) -> EmailParsedMessage:
        """Authenticate sender via DMARC and parse the email.

        Args:
            raw_message: RawMessage wrapping an email.message.Message.

        Returns:
            EmailParsedMessage if authenticated and authorized.

        Raises:
            AuthenticationError: If DMARC verification or sender
                authorization fails.
        """
        email_msg = raw_message.content
        sender = email_msg.get("From", "")
        message_id = email_msg.get("Message-ID", "")
        repo_id = self._repo_id

        # Authentication: verify DMARC from trusted server
        authenticated_sender = self._authenticator.authenticate(email_msg)
        if authenticated_sender is None:
            logger.warning(
                "Repo '%s': rejecting unauthenticated message from %s "
                "(Message-ID: %s)",
                repo_id,
                sender,
                message_id,
            )
            raise AuthenticationError(
                sender=sender,
                reason="DMARC verification failed",
            )

        # Authorization: check sender is allowed
        if not self._authorizer.is_authorized(authenticated_sender):
            logger.warning(
                "Repo '%s': rejecting unauthorized message from %s "
                "(Message-ID: %s)",
                repo_id,
                sender,
                message_id,
            )
            raise AuthenticationError(
                sender=sender,
                reason="sender not authorized",
            )

        # Extract conversation ID: headers first, then subject fallback
        subject = decode_subject(email_msg)
        references = email_msg.get("References", "").split()
        in_reply_to = email_msg.get("In-Reply-To")
        conv_id = extract_conversation_id_from_headers(
            references, in_reply_to
        ) or extract_conversation_id(subject)

        # Extract model from To address (e.g., airut+opus@domain.com)
        to_address = email_msg.get("To", "")
        model_hint = extract_model_from_address(to_address)

        # Extract body (HTML quotes stripped)
        clean_body = extract_body(email_msg)

        # Build channel context
        channel_context = (
            "User is interacting with this session via email interface "
            "and will receive your last reply as email. "
            "After the reply, everything not in /workspace, /inbox, "
            "and /storage is reset. "
            "Markdown formatting is supported in your responses. "
            "To send files back to the user, place them in the "
            "/outbox directory root (no subdirectories). "
            "Use /storage to persist files across messages.\n\n"
            "IMPORTANT: AskUserQuestion and plan mode tools "
            "(EnterPlanMode/ExitPlanMode) do not work over email "
            "interface. If you need clarification, include questions in "
            "your response text and the user will reply via email."
        )

        return EmailParsedMessage(
            sender=sender,
            body=clean_body,
            conversation_id=conv_id,
            model_hint=model_hint,
            subject=subject or "(no subject)",
            channel_context=channel_context,
            original_message_id=email_msg.get("Message-ID"),
            original_references=references,
            decoded_subject=subject,
            _raw_message=email_msg,
        )

    def save_attachments(
        self, parsed: ParsedMessage, inbox_dir: Path
    ) -> list[str]:
        """Extract and save email attachments to the inbox directory.

        Called by the core after conversation setup, when the inbox
        directory is available.

        Args:
            parsed: Parsed message (must be an EmailParsedMessage).
            inbox_dir: Path to save attachments to.

        Returns:
            List of saved filenames.
        """
        assert isinstance(parsed, EmailParsedMessage)
        if parsed._raw_message is None:
            return []
        return extract_attachments(parsed._raw_message, inbox_dir)

    def send_acknowledgment(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        model: str,
        dashboard_url: str | None,
    ) -> None:
        """Send email acknowledgment for new conversations."""
        assert isinstance(parsed, EmailParsedMessage)

        subject, references_list = self._build_reply_headers(
            parsed, conversation_id
        )

        if dashboard_url:
            task_url = f"{dashboard_url}/conversation/{conversation_id}"
            body = (
                f"I've started working on this and will reply shortly. "
                f"See progress at {task_url}"
            )
            html_body = (
                f"I've started working on this and will reply shortly. "
                f'See progress at <a href="{task_url}">{task_url}</a>'
            )
        else:
            body = "I've started working on this and will reply shortly."
            html_body = "I've started working on this and will reply shortly."

        outgoing_message_id = generate_message_id(
            conversation_id, self._config.from_address
        )

        try:
            self._responder.send_reply(
                to=parsed.sender,
                subject=subject,
                body=body,
                in_reply_to=parsed.original_message_id,
                references=references_list,
                html_body=html_body,
                message_id=outgoing_message_id,
            )
            logger.info(
                "Sent acknowledgment to %s for conversation %s",
                parsed.sender,
                conversation_id,
            )
        except SMTPSendError as e:
            logger.warning("Failed to send acknowledgment (non-fatal): %s", e)

    def send_reply(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        response_text: str,
        usage_footer: str,
        outbox_files: list[Path],
    ) -> None:
        """Send email reply with response text and attachments."""
        assert isinstance(parsed, EmailParsedMessage)

        subject, references_list = self._build_reply_headers(
            parsed, conversation_id
        )

        # Append usage footer if present
        body = response_text
        if usage_footer:
            body = f"{response_text}\n\n*{usage_footer}*"

        outgoing_message_id = generate_message_id(
            conversation_id, self._config.from_address
        )

        # Collect attachments from outbox directory
        attachments: list[tuple[str, bytes]] | None = None
        outbox_path: Path | None = None
        if outbox_files:
            outbox_path = outbox_files[0].parent
            attachments_data = collect_outbox_files(outbox_path)
            if attachments_data:
                attachments = attachments_data
                logger.info(
                    "Attaching %d files from outbox: %s",
                    len(attachments_data),
                    ", ".join(f[0] for f in attachments_data),
                )

        try:
            self._responder.send_reply(
                to=parsed.sender,
                subject=subject,
                body=body,
                in_reply_to=parsed.original_message_id,
                references=references_list,
                attachments=attachments,
                message_id=outgoing_message_id,
            )

            if outbox_path:
                _clean_outbox(attachments or [], outbox_path)

        except SMTPSendError as e:
            logger.error("Failed to send reply: %s", e)
            # Retry once
            logger.info("Retrying SMTP send...")
            try:
                self._responder.send_reply(
                    to=parsed.sender,
                    subject=subject,
                    body=body,
                    in_reply_to=parsed.original_message_id,
                    references=references_list,
                    attachments=attachments,
                    message_id=outgoing_message_id,
                )

                if outbox_path:
                    _clean_outbox(attachments or [], outbox_path)

            except SMTPSendError as retry_error:
                logger.critical("SMTP retry failed: %s", retry_error)
                raise

    def send_error(
        self,
        parsed: ParsedMessage,
        conversation_id: str | None,
        error_message: str,
    ) -> None:
        """Send error notification email."""
        assert isinstance(parsed, EmailParsedMessage)

        subject = f"Re: {parsed.decoded_subject}"
        message_id = parsed.original_message_id

        try:
            self._responder.send_reply(
                to=parsed.sender,
                subject=subject,
                body=error_message,
                in_reply_to=message_id,
                references=[message_id] if message_id else [],
            )
        except SMTPSendError as e:
            logger.error("Failed to send error reply: %s", e)

    def send_rejection(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        reason: str,
        dashboard_url: str | None,
    ) -> None:
        """Send rejection reply when a message cannot be processed."""
        assert isinstance(parsed, EmailParsedMessage)

        subject, references_list = self._build_reply_headers(
            parsed, conversation_id
        )

        escaped_reason = html_module.escape(reason)

        if dashboard_url:
            task_url = f"{dashboard_url}/conversation/{conversation_id}"
            body = (
                "Your message could not be processed.\n"
                "\n"
                f"Reason: {reason}\n"
                "\n"
                f"Conversation ID: {conversation_id} ({task_url})"
            )
            html_body = (
                "Your message could not be processed."
                "<br><br>"
                f"Reason: {escaped_reason}"
                "<br><br>"
                f'Conversation ID: <a href="{task_url}">'
                f"{conversation_id}</a>"
            )
        else:
            body = (
                "Your message could not be processed.\n"
                "\n"
                f"Reason: {reason}\n"
                "\n"
                f"Conversation ID: {conversation_id}"
            )
            html_body = (
                "Your message could not be processed."
                "<br><br>"
                f"Reason: {escaped_reason}"
                "<br><br>"
                f"Conversation ID: {conversation_id}"
            )

        outgoing_message_id = generate_message_id(
            conversation_id, self._config.from_address
        )

        try:
            self._responder.send_reply(
                to=parsed.sender,
                subject=subject,
                body=body,
                in_reply_to=parsed.original_message_id,
                references=references_list,
                html_body=html_body,
                message_id=outgoing_message_id,
            )
            logger.info(
                "Sent rejection reply to %s for conversation %s",
                parsed.sender,
                conversation_id,
            )
        except SMTPSendError as e:
            logger.warning("Failed to send rejection reply (non-fatal): %s", e)

    def _build_reply_headers(
        self,
        parsed: EmailParsedMessage,
        conversation_id: str,
    ) -> tuple[str, list[str]]:
        """Build subject and references for an email reply.

        Args:
            parsed: Email parsed message with threading state.
            conversation_id: Conversation ID.

        Returns:
            Tuple of (subject, references_list).
        """
        # Strip existing "Re: " prefixes to avoid accumulation
        clean_subject = parsed.decoded_subject
        while clean_subject.lower().startswith("re: "):
            clean_subject = clean_subject[4:]

        # Build subject with conversation ID
        if f"[ID:{conversation_id}]" not in clean_subject:
            subject = f"Re: [ID:{conversation_id}] {clean_subject}"
        else:
            subject = f"Re: {clean_subject}"

        # Build references list
        references = parsed.original_references
        message_id = parsed.original_message_id
        references_list = (
            references + [message_id]
            if references and message_id
            else [message_id]
            if message_id
            else []
        )

        return subject, references_list


def _clean_outbox(
    attachments: list[tuple[str, bytes]], outbox_path: Path
) -> None:
    """Remove files from outbox after successful send."""
    if not attachments or not outbox_path.exists():
        return
    for filepath in outbox_path.iterdir():
        if filepath.is_file():
            try:
                filepath.unlink()
            except OSError as e:
                logger.warning(
                    "Failed to delete outbox file %s: %s",
                    filepath,
                    e,
                )
    logger.info("Cleaned up outbox directory")
