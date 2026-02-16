# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email message parsing utilities.

This module provides utilities for parsing email messages, extracting
conversation IDs and handling attachments.
"""

import logging
import re
from email.header import decode_header
from email.message import Message
from pathlib import Path

from airut.html_to_text import html_to_text


logger = logging.getLogger(__name__)


# Pattern to match [ID:abc12345] in subject lines
CONVERSATION_ID_PATTERN = re.compile(r"\[ID:([0-9a-f]{8})\]")

# Pattern to extract conversation ID from structured Airut Message-IDs.
# Matches: <airut.{8-hex-chars}.{timestamp}.{nonce}@domain>
# The trailing segments (timestamp, nonce) are matched flexibly with
# [\w.]+ to tolerate format changes without breaking thread resolution.
AIRUT_MESSAGE_ID_PATTERN = re.compile(r"<airut\.([0-9a-f]{8})\.[\w.]+@")

# Pattern to extract model name from email address with subaddressing
# Matches: user+opus@domain.com, user+sonnet@domain.com, etc.
MODEL_SUBADDRESS_PATTERN = re.compile(r"\+([a-zA-Z0-9_-]+)@")


class ParseError(Exception):
    """Base exception for parsing errors."""


def decode_subject(message: Message) -> str:
    """Decode the Subject header from an email message.

    Email clients may encode headers using RFC 2047 encoded-words
    (e.g., ``=?big5?B?...?=``).  Python's ``Message.get()`` returns the
    raw encoded form, so this function uses ``email.header.decode_header``
    to produce a proper Unicode string.

    Args:
        message: Parsed email message.

    Returns:
        Decoded subject string, or empty string if not present.
    """
    raw = message.get("Subject", "")
    if not raw:
        return ""

    parts = decode_header(raw)
    decoded_parts: list[str] = []
    for data, charset in parts:
        if isinstance(data, bytes):
            decoded_parts.append(
                data.decode(charset or "utf-8", errors="replace")
            )
        else:
            decoded_parts.append(data)
    return " ".join(decoded_parts)


def extract_conversation_id(subject: str) -> str | None:
    """Extract conversation ID from email subject line.

    Looks for pattern: [ID:abc12345] in subject.

    Args:
        subject: Email subject line.

    Returns:
        8-character hex conversation ID, or None if not found.
    """
    match = CONVERSATION_ID_PATTERN.search(subject)
    if match:
        conversation_id = match.group(1)
        logger.debug("Extracted conversation ID: %s", conversation_id)
        return conversation_id

    logger.debug("No conversation ID found in subject: %s", subject)
    return None


def extract_conversation_id_from_headers(
    references: list[str],
    in_reply_to: str | None = None,
) -> str | None:
    """Extract conversation ID from email threading headers.

    Looks for structured Airut Message-IDs in the References and
    In-Reply-To headers. Airut Message-IDs follow the pattern:
    ``<airut.{conv_id}.{timestamp}@domain>``.

    This is the primary method for conversation identification,
    with subject-line ``[ID:...]`` tags as a fallback.

    Args:
        references: List of Message-IDs from the References header.
        in_reply_to: Message-ID from the In-Reply-To header.

    Returns:
        8-character hex conversation ID, or None if not found.
    """
    # Check In-Reply-To first (most recent/direct reference),
    # then References (newest last per RFC 5322).
    candidates = []
    if in_reply_to:
        candidates.append(in_reply_to)
    candidates.extend(reversed(references))

    for ref in candidates:
        match = AIRUT_MESSAGE_ID_PATTERN.search(ref)
        if match:
            conversation_id = match.group(1)
            logger.debug(
                "Extracted conversation ID from header: %s (from %s)",
                conversation_id,
                ref,
            )
            return conversation_id

    logger.debug("No Airut conversation ID found in threading headers")
    return None


def extract_model_from_address(to_address: str) -> str | None:
    """Extract model name from email To address using subaddressing.

    Looks for pattern: username+modelname@domain in the To address.
    For example, airut+opus@example.com extracts "opus".

    Args:
        to_address: Email To header (may be in "Name <email>" format).

    Returns:
        Model name string (lowercase), or None if not found.
    """
    # Extract email address from "Name <email@example.com>" format
    if "<" in to_address and ">" in to_address:
        email_addr = to_address.split("<")[1].split(">")[0]
    else:
        email_addr = to_address

    match = MODEL_SUBADDRESS_PATTERN.search(email_addr)
    if match:
        model = match.group(1).lower()
        logger.debug("Extracted model from To address: %s", model)
        return model

    logger.debug("No model subaddress found in To: %s", to_address)
    return None


def extract_body(message: Message) -> str:
    """Extract plain text body from email message.

    Prefers text/html when available, stripping quoted replies using
    client-specific HTML markers before converting to plain text. This is
    more reliable than text/plain quote stripping because email clients
    (Outlook, Gmail, etc.) use well-defined HTML structures to wrap quoted
    content. Falls back to text/plain when no HTML part is available.

    Args:
        message: Parsed email message.

    Returns:
        Plain text body (UTF-8 decoded).
    """
    if message.is_multipart():
        # Log all parts for debugging
        parts = []
        for part in message.walk():
            content_type = part.get_content_type()
            parts.append(content_type)

        logger.debug("Multipart message with parts: %s", ", ".join(parts))

        # First pass: prefer text/html for reliable quote stripping
        for part in message.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html_body = payload.decode(charset, errors="replace")  # type: ignore[union-attr]
                    body = html_to_text(html_body, strip_quotes=True)
                    logger.debug(
                        "Extracted body from HTML part (%d chars HTML"
                        " -> %d chars text, charset=%s)",
                        len(html_body),
                        len(body),
                        charset,
                    )
                    return body

        # Second pass: fall back to text/plain
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body = payload.decode(charset, errors="replace")  # type: ignore[union-attr]
                    logger.debug(
                        "Extracted body from multipart message"
                        " (%d chars, charset=%s)",
                        len(body),
                        charset,
                    )
                    return body
    else:
        content_type = message.get_content_type()
        logger.debug("Plain message with content type: %s", content_type)

        payload = message.get_payload(decode=True)
        if payload:
            charset = message.get_content_charset() or "utf-8"
            raw = payload.decode(charset, errors="replace")  # type: ignore[union-attr]
            if content_type == "text/html":
                body = html_to_text(raw, strip_quotes=True)
                logger.debug(
                    "Converted HTML body to text (%d chars HTML"
                    " -> %d chars text, charset=%s)",
                    len(raw),
                    len(body),
                    charset,
                )
                return body
            logger.debug(
                "Extracted body from plain message (%d chars, charset=%s)",
                len(raw),
                charset,
            )
            return raw

    logger.warning("No text body found in message")
    return ""


def extract_attachments(
    message: Message,
    inbox_dir: Path,
) -> list[str]:
    """Extract attachments from email and save to inbox directory.

    Args:
        message: Parsed email message.
        inbox_dir: Directory to save attachments (must exist).

    Returns:
        List of saved filenames.

    Raises:
        ValueError: If inbox_dir doesn't exist.
    """
    if not inbox_dir.exists():
        raise ValueError(f"Inbox directory does not exist: {inbox_dir}")

    filenames = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    filepath = inbox_dir / filename
                    payload = part.get_payload(decode=True)
                    if payload:
                        with open(filepath, "wb") as f:
                            f.write(payload)  # type: ignore[arg-type]
                        filenames.append(filename)
                        logger.debug(
                            "Saved attachment: %s (%d bytes)",
                            filename,
                            len(payload),
                        )

    if filenames:
        logger.info("Extracted %d attachments", len(filenames))
    else:
        logger.debug("No attachments found in message")

    return filenames


def collect_outbox_files(outbox_dir: Path) -> list[tuple[str, bytes]]:
    """Collect files from outbox directory for email attachment.

    Args:
        outbox_dir: Directory to scan for files to attach.

    Returns:
        List of (filename, content) tuples for files to attach.
        Returns empty list if directory doesn't exist or is empty.
    """
    if not outbox_dir.exists():
        logger.debug("Outbox directory does not exist: %s", outbox_dir)
        return []

    attachments = []
    for filepath in outbox_dir.iterdir():
        if filepath.is_file():
            try:
                content = filepath.read_bytes()
                attachments.append((filepath.name, content))
                logger.debug(
                    "Collected outbox file: %s (%d bytes)",
                    filepath.name,
                    len(content),
                )
            except OSError as e:
                logger.warning("Failed to read outbox file %s: %s", filepath, e)

    if attachments:
        logger.info("Collected %d files from outbox", len(attachments))
    else:
        logger.debug("No files found in outbox")

    return attachments
