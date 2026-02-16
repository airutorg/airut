# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email reply handling for the gateway service.

This module handles sending various types of email replies:
- Standard replies with Claude output
- Acknowledgment emails for new conversations
- Error replies for processing failures
- Rejection replies for duplicate requests
"""

from __future__ import annotations

import html as html_module
import logging
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING

from airut.conversation import create_conversation_layout
from airut.gateway.parsing import collect_outbox_files, decode_subject
from airut.gateway.responder import SMTPSendError, generate_message_id


if TYPE_CHECKING:
    from airut.gateway.config import GlobalConfig
    from airut.gateway.service.repo_handler import RepoHandler

logger = logging.getLogger(__name__)


def send_reply(
    repo_handler: RepoHandler,
    original_message: Message,
    conv_id: str,
    body: str,
) -> None:
    """Send email reply with threading headers.

    Args:
        repo_handler: Repo handler for SMTP sending.
        original_message: Original email message.
        conv_id: Conversation ID.
        body: Response body text.
    """
    sender = original_message.get("From", "")
    original_subject = decode_subject(original_message)
    message_id = original_message.get("Message-ID")
    references = original_message.get("References", "").split()

    # Strip existing "Re: " prefixes to avoid accumulation
    clean_subject = original_subject
    while clean_subject.lower().startswith("re: "):
        clean_subject = clean_subject[4:]

    # Build subject with conversation ID
    if f"[ID:{conv_id}]" not in clean_subject:
        subject = f"Re: [ID:{conv_id}] {clean_subject}"
    else:
        subject = f"Re: {clean_subject}"

    # Build references list
    references_list = (
        references + [message_id]
        if references and message_id
        else [message_id]
        if message_id
        else []
    )

    # Generate structured Message-ID for thread resolution
    outgoing_message_id = generate_message_id(
        conv_id, repo_handler.config.email_from
    )

    # Collect attachments from outbox directory
    conv_mgr = repo_handler.conversation_manager
    conversation_dir = conv_mgr.get_conversation_dir(conv_id)
    outbox_path = create_conversation_layout(conversation_dir).outbox
    attachments = collect_outbox_files(outbox_path)
    if attachments:
        logger.info(
            "Attaching %d files from outbox: %s",
            len(attachments),
            ", ".join(f[0] for f in attachments),
        )

    try:
        repo_handler.responder.send_reply(
            to=sender,
            subject=subject,
            body=body,
            in_reply_to=message_id,
            references=references_list,
            attachments=attachments if attachments else None,
            message_id=outgoing_message_id,
        )

        _clean_outbox(attachments, outbox_path)

    except SMTPSendError as e:
        logger.error("Failed to send reply: %s", e)
        # Retry once
        logger.info("Retrying SMTP send...")
        try:
            repo_handler.responder.send_reply(
                to=sender,
                subject=subject,
                body=body,
                in_reply_to=message_id,
                references=references_list,
                attachments=attachments if attachments else None,
                message_id=outgoing_message_id,
            )

            _clean_outbox(attachments, outbox_path)

        except SMTPSendError as retry_error:
            logger.critical("SMTP retry failed: %s", retry_error)
            raise


def _clean_outbox(
    attachments: list[tuple[str, bytes]], outbox_path: Path
) -> None:
    """Remove files from outbox after successful send.

    Args:
        attachments: Collected attachment list (checked for non-empty).
        outbox_path: Path to the outbox directory.
    """
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


def send_acknowledgment(
    repo_handler: RepoHandler,
    original_message: Message,
    conv_id: str,
    model: str,
    global_config: GlobalConfig,
) -> None:
    """Send acknowledgment reply when task is picked up.

    Args:
        repo_handler: Repo handler for SMTP sending.
        original_message: Original email message.
        conv_id: Conversation ID.
        model: Claude model name being used (unused, kept for API compat).
        global_config: Global configuration for dashboard URL.
    """
    del model  # Unused - acknowledgment no longer includes model info
    sender = original_message.get("From", "")
    original_subject = decode_subject(original_message)
    message_id = original_message.get("Message-ID")
    references = original_message.get("References", "").split()

    clean_subject = original_subject
    while clean_subject.lower().startswith("re: "):
        clean_subject = clean_subject[4:]

    if f"[ID:{conv_id}]" not in clean_subject:
        subject = f"Re: [ID:{conv_id}] {clean_subject}"
    else:
        subject = f"Re: {clean_subject}"

    references_list = (
        references + [message_id]
        if references and message_id
        else [message_id]
        if message_id
        else []
    )

    dashboard_base_url = global_config.dashboard_base_url
    if dashboard_base_url:
        task_url = f"{dashboard_base_url}/conversation/{conv_id}"
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

    # Generate structured Message-ID for thread resolution
    outgoing_message_id = generate_message_id(
        conv_id, repo_handler.config.email_from
    )

    try:
        repo_handler.responder.send_reply(
            to=sender,
            subject=subject,
            body=body,
            in_reply_to=message_id,
            references=references_list,
            html_body=html_body,
            message_id=outgoing_message_id,
        )
        logger.info(
            "Sent acknowledgment to %s for conversation %s", sender, conv_id
        )
    except SMTPSendError as e:
        logger.warning("Failed to send acknowledgment (non-fatal): %s", e)


def send_error_reply(
    repo_handler: RepoHandler,
    original_message: Message,
    error_message: str,
) -> None:
    """Send error message to user.

    Args:
        repo_handler: Repo handler for SMTP sending.
        original_message: Original email message.
        error_message: Error message to send.
    """
    sender = original_message.get("From", "")
    subject = decode_subject(original_message)
    message_id = original_message.get("Message-ID")

    try:
        repo_handler.responder.send_reply(
            to=sender,
            subject=f"Re: {subject}",
            body=error_message,
            in_reply_to=message_id,
            references=[message_id] if message_id else [],
        )
    except SMTPSendError as e:
        logger.error("Failed to send error reply: %s", e)


def send_rejection_reply(
    repo_handler: RepoHandler,
    original_message: Message,
    conv_id: str,
    reason: str,
    global_config: GlobalConfig,
) -> None:
    """Send rejection reply when a message cannot be processed.

    Args:
        repo_handler: Repo handler for SMTP sending.
        original_message: Original email message.
        conv_id: Conversation ID.
        reason: Human-readable reason for rejection.
        global_config: Global configuration for dashboard URL.
    """
    sender = original_message.get("From", "")
    original_subject = decode_subject(original_message)
    message_id = original_message.get("Message-ID")
    references = original_message.get("References", "").split()

    clean_subject = original_subject
    while clean_subject.lower().startswith("re: "):
        clean_subject = clean_subject[4:]

    if f"[ID:{conv_id}]" not in clean_subject:
        subject = f"Re: [ID:{conv_id}] {clean_subject}"
    else:
        subject = f"Re: {clean_subject}"

    references_list = (
        references + [message_id]
        if references and message_id
        else [message_id]
        if message_id
        else []
    )

    escaped_reason = html_module.escape(reason)

    dashboard_base_url = global_config.dashboard_base_url
    if dashboard_base_url:
        task_url = f"{dashboard_base_url}/conversation/{conv_id}"
        body = (
            "Your message could not be processed.\n"
            "\n"
            f"Reason: {reason}\n"
            "\n"
            f"Conversation ID: {conv_id} ({task_url})"
        )
        html_body = (
            "Your message could not be processed."
            "<br><br>"
            f"Reason: {escaped_reason}"
            "<br><br>"
            f'Conversation ID: <a href="{task_url}">{conv_id}</a>'
        )
    else:
        body = (
            "Your message could not be processed.\n"
            "\n"
            f"Reason: {reason}\n"
            "\n"
            f"Conversation ID: {conv_id}"
        )
        html_body = (
            "Your message could not be processed."
            "<br><br>"
            f"Reason: {escaped_reason}"
            "<br><br>"
            f"Conversation ID: {conv_id}"
        )

    # Generate structured Message-ID for thread resolution
    outgoing_message_id = generate_message_id(
        conv_id, repo_handler.config.email_from
    )

    try:
        repo_handler.responder.send_reply(
            to=sender,
            subject=subject,
            body=body,
            in_reply_to=message_id,
            references=references_list,
            html_body=html_body,
            message_id=outgoing_message_id,
        )
        logger.info(
            "Sent rejection reply to %s for conversation %s",
            sender,
            conv_id,
        )
    except SMTPSendError as e:
        logger.warning("Failed to send rejection reply (non-fatal): %s", e)
