# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""An incoming email, as fetched from the mailbox."""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser


#: A carriage return not followed by a line feed.
_BARE_CR_RE = re.compile(rb"\r(?!\n)")


@dataclass(frozen=True)
class IncomingEmail:
    """A fetched email: its bytes as received, and the parsed message.

    DKIM signatures are verified over the bytes: serializing the parsed
    message again would not reproduce them exactly.

    Attributes:
        raw: The message exactly as the mail server returned it.
        message: The message parsed from *raw*.
    """

    raw: bytes
    message: Message

    @classmethod
    def parse(cls, raw: bytes) -> IncomingEmail:
        """Parse *raw* into an ``IncomingEmail``."""
        return cls(raw, BytesParser().parsebytes(raw))

    def has_bare_cr_in_header(self) -> bool:
        """Whether a carriage return without a line feed is in the header.

        Parsers disagree on whether such a carriage return ends a line,
        and so on which header fields the message has.  The header
        section ends at the first CRLF CRLF or LF LF.
        """
        ends = []
        crlf = self.raw.find(b"\r\n\r\n")
        if crlf >= 0:
            ends.append(crlf + 2)
        lf = self.raw.find(b"\n\n")
        if lf >= 0:
            ends.append(lf + 1)
        header = self.raw[: min(ends)] if ends else self.raw
        return _BARE_CR_RE.search(header) is not None
