# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Outgoing email composition.

Builds the MIME message for an outgoing email and keeps it under the
size limit by leaving out attachments that do not fit.  Files left out
are named in the body, so the user learns they exist even though they
did not arrive.
"""

import io
import logging
import mimetypes
import re
import smtplib
from dataclasses import dataclass
from email import encoders
from email.generator import BytesGenerator
from email.message import Message
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import cached_property

from airut.markdown import markdown_to_html
from airut.units import format_size


logger = logging.getLogger(__name__)

#: Room ``attachment_budget`` leaves for headers and the reply text,
#: which goes out twice (plain text and HTML) and may be base64-encoded.
_TEXT_ALLOWANCE = 256 * 1024

#: An RFC 3463 enhanced status code at the start of a reply line.
#: smtplib strips the basic reply code from each line it joins.
_ENHANCED_STATUS_RE = re.compile(
    r"^(\d\.\d{1,3}\.\d{1,3})(?=\s|$)", re.MULTILINE
)

#: Enhanced status codes for a message over a size limit: 5.3.4
#: "message too big for system" and 5.2.3 "message length exceeds
#: administrative limit".
_SIZE_STATUSES = frozenset({"5.3.4", "5.2.3"})


def wire_size(msg: Message) -> int:
    """Return the size of *msg* as ``smtplib`` transmits it.

    Serializes the way ``SMTP.send_message`` does: CRLF line endings,
    and ``From `` at the start of a body line escaped as ``>From ``.
    """
    buffer = io.BytesIO()
    BytesGenerator(buffer).flatten(msg, linesep="\r\n")
    return buffer.getbuffer().nbytes


def _mime_part(filename: str, content: bytes) -> MIMEBase:
    """Encode *content* as a base64 attachment named *filename*.

    The MIME type is guessed from the file name, falling back to
    ``application/octet-stream``.
    """
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None:
        mime_type = "application/octet-stream"
    maintype, subtype = mime_type.split("/", 1)

    part = MIMEBase(maintype, subtype)
    part.set_payload(content)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=filename)
    return part


@dataclass(frozen=True, eq=False)
class Attachment:
    """A file to attach to an outgoing email.

    The file is only encoded once it is actually attached, so one too
    large to send costs nothing beyond reading it.

    Attributes:
        filename: Name shown to the recipient.
        content: File content.
    """

    filename: str
    content: bytes

    @property
    def size(self) -> int:
        """Size of the file itself."""
        return len(self.content)

    @cached_property
    def part(self) -> MIMEBase:
        """The file encoded as a MIME part."""
        return _mime_part(self.filename, self.content)

    @cached_property
    def encoded_size(self) -> int:
        """Size of the encoded part on its own, as sent on the wire.

        Base64 turns every 3 bytes into 4 characters and ends each
        76-character line with CRLF; the headers are measured on an
        empty part with the same name.  In a message, the part also
        takes a boundary line, so this is a lower bound on what it adds.
        """
        headers = wire_size(_mime_part(self.filename, b""))
        encoded = 4 * ((self.size + 2) // 3)
        return headers + encoded + 2 * ((encoded + 75) // 76)


@dataclass(frozen=True)
class Draft:
    """Headers and text of an outgoing email, without attachments.

    Attributes:
        sender: From address.
        to: Recipient address.
        subject: Subject line.
        body: Markdown body.
        footer: Usage summary, set in italics after the body and after
            any note about attachments that were left out.
        in_reply_to: Message-ID of the message being replied to.
        references: Message-IDs in the thread.
        message_id: Explicit Message-ID for this message.
    """

    sender: str
    to: str
    subject: str
    body: str
    footer: str = ""
    in_reply_to: str | None = None
    references: list[str] | None = None
    message_id: str | None = None

    def build(
        self, attachments: list[Attachment], note: str = ""
    ) -> MIMEMultipart:
        """Assemble the MIME message.

        The text goes out as both plain text and HTML alternatives;
        with attachments, that pair is nested inside a ``mixed``
        container next to them.

        Args:
            attachments: Attachments to include.
            note: Text placed between the body and the footer.

        Returns:
            The message, ready to send.
        """
        footer = f"*{self.footer}*" if self.footer else ""
        text = "\n\n".join(t for t in (self.body, note, footer) if t)
        html = markdown_to_html(text)

        msg = MIMEMultipart("mixed" if attachments else "alternative")
        msg["From"] = self.sender
        msg["To"] = self.to
        msg["Subject"] = self.subject
        if self.message_id:
            msg["Message-ID"] = self.message_id
        if self.in_reply_to:
            msg["In-Reply-To"] = self.in_reply_to
        if self.references:
            msg["References"] = " ".join(self.references)

        if attachments:
            alternative = MIMEMultipart("alternative")
            alternative.attach(MIMEText(text, "plain"))
            alternative.attach(MIMEText(html, "html"))
            msg.attach(alternative)
            for attachment in attachments:
                msg.attach(attachment.part)
        else:
            msg.attach(MIMEText(text, "plain"))
            msg.attach(MIMEText(html, "html"))
        return msg


def omitted_note(omitted: list[Attachment], reason: str) -> str:
    """Render the line naming attachments that were left out.

    Args:
        omitted: Attachments left out of the message.
        reason: Why, phrased to follow "Could not attach N file(s)".

    Returns:
        The note.
    """
    names = ", ".join(f"{a.filename} ({format_size(a.size)})" for a in omitted)
    return f"Could not attach {len(omitted)} file(s) {reason}: {names}"


def fit_attachments(
    draft: Draft, attachments: list[Attachment], limit: int
) -> tuple[MIMEMultipart, list[Attachment]]:
    """Build *draft*, leaving out attachments until it fits in *limit*.

    The largest files are left out first, so as many files as possible
    still go through.  Those left out are named in a note above the
    footer.  If the message is still too large with no attachments at
    all, it is returned as is for the server to judge.

    Args:
        draft: The email to build.
        attachments: Attachments to include if they fit.
        limit: Largest acceptable message size in bytes.

    Returns:
        The message and the attachments left out of it, in their
        original order.
    """
    if not attachments:
        return draft.build([]), []

    kept = list(attachments)
    note = ""
    while True:
        text_only = draft.build([], note)
        if not kept:
            msg = text_only
            break
        # The text plus the encoded files is a lower bound on the size,
        # so only a message within it is built and measured in full.
        excess = (
            wire_size(text_only) + sum(a.encoded_size for a in kept) - limit
        )
        if excess <= 0:
            msg = draft.build(kept, note)
            excess = wire_size(msg) - limit
            if excess <= 0:
                break
        _leave_out_largest(kept, excess)
        note = omitted_note(
            [a for a in attachments if a not in kept],
            f"without exceeding the {format_size(limit)} email size limit",
        )

    omitted = [a for a in attachments if a not in kept]
    if omitted:
        logger.warning(
            "Leaving out %d of %d attachment(s) to stay under %d bytes: %s",
            len(omitted),
            len(attachments),
            limit,
            ", ".join(a.filename for a in omitted),
        )
    return msg, omitted


def _leave_out_largest(kept: list[Attachment], excess: int) -> None:
    """Remove the largest attachments from *kept* to cover *excess*."""
    for attachment in sorted(kept, key=lambda a: a.encoded_size, reverse=True):
        kept.remove(attachment)
        excess -= attachment.encoded_size
        if excess <= 0:
            return


def is_size_rejection(error: smtplib.SMTPException) -> bool:
    """Return whether *error* is the server refusing the message's size.

    Judged by the enhanced status code (RFC 3463) when the reply has
    one, since some servers also use 552 for other rejections, such as
    a blocked file type.  Otherwise 552, the RFC 1870 reply for
    exceeding the size limit.
    """
    if not isinstance(error, smtplib.SMTPResponseException):
        return False
    detail = error.smtp_error
    if isinstance(detail, bytes):
        detail = detail.decode(errors="replace")
    status = _ENHANCED_STATUS_RE.search(detail)
    if status:
        return status.group(1) in _SIZE_STATUSES
    return error.smtp_code == 552


def attachment_budget(max_message_size: int) -> int:
    """Return the total file size that fits in a message of this size.

    Base64 turns every 3 bytes into 4 characters and ends each
    76-character line with CRLF, so files grow by about 37% on the wire.
    Room is also left for the headers and the reply text.

    Args:
        max_message_size: Message size limit in bytes.

    Returns:
        Bytes of files that fit alongside a typical reply.
    """
    return (max_message_size - _TEXT_ALLOWANCE) * 3 // 4 * 76 // 78
