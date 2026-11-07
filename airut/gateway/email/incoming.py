# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""An incoming email, as fetched from the mailbox."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser


#: A line break: CRLF, or a lone LF.
_LINE_BREAK_RE = re.compile(rb"\r?\n")

#: The start of a header field's first line: a name of printable ASCII
#: other than ``:``, then ``:`` (RFC 5322 §2.2).
_FIELD_RE = re.compile(rb"[\x21-\x39\x3b-\x7e]+:")

#: How much of a refused header-section line is shown.
_SHOWN_LINE_LENGTH = 100

#: Header fields a message may hold at most once: those of RFC 5322
#: §3.6, and MIME's fields saying how the body is read (RFC 2045).
_SINGLE_FIELDS = (
    "Date",
    "From",
    "Sender",
    "Reply-To",
    "To",
    "Cc",
    "Bcc",
    "Message-ID",
    "In-Reply-To",
    "References",
    "Subject",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
)


def _header_lines(raw: bytes) -> Iterator[bytes]:
    """Yield the lines of *raw*'s header section, without line breaks.

    The section ends at the first empty line, or with the message.
    """
    start = 0
    for match in _LINE_BREAK_RE.finditer(raw):
        line = raw[start : match.start()]
        if not line:
            return
        yield line
        start = match.end()
    if start < len(raw):
        yield raw[start:]


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

    def header_section_problem(self) -> str | None:
        """Return why parsers may read the header section differently.

        Every line of the section must be a header field's first line (a
        name of printable ASCII other than ``:``, then ``:``) or, after
        the first line, a continuation of one (starting with a space or a
        tab), and no carriage return may stand without a line feed.
        Parsers treat other lines inconsistently — as the start of the
        body, as lines to skip, or as errors — and disagree on whether a
        bare carriage return ends a line, so they could read different
        header fields, or a different body.

        Nor may a field in ``_SINGLE_FIELDS`` appear more than once:
        parsers disagree on which one counts (the standard library's
        reads the first, while a DKIM signature covers the last).

        Returns:
            What is wrong, or None if the section is unambiguous.
        """
        for index, line in enumerate(_header_lines(self.raw)):
            if b"\r" in line:
                return "a carriage return not followed by a line feed"
            if line[:1] in (b" ", b"\t"):
                if index == 0:
                    return "a continuation line at the start"
            elif not _FIELD_RE.match(line):
                shown = line[:_SHOWN_LINE_LENGTH]
                return f"a line that is not a header field: {shown!r}"
        counts = Counter(name.lower() for name in self.message.keys())
        for name in _SINGLE_FIELDS:
            if counts[name.lower()] > 1:
                return f"more than one {name} field"
        return None

    def signed_headers(self, fields: Sequence[str]) -> Message:
        """Return just the header fields a DKIM signature covers.

        A signature whose ``h=`` tag lists a name *n* times covers the
        last *n* fields of that name (RFC 6376 §5.4.2).

        Args:
            fields: The names the signature's ``h=`` tag lists.

        Returns:
            A message holding those fields, in their order, and no body.
        """
        wanted = Counter(name.lower() for name in fields)
        covered: list[tuple[str, str]] = []
        for name, value in reversed(list(self.message.raw_items())):
            if wanted[name.lower()] > 0:
                wanted[name.lower()] -= 1
                covered.append((name, value))
        return self._header_message(reversed(covered))

    def headers(self) -> Message:
        """Return all the message's header fields, without its body."""
        return self._header_message(self.message.raw_items())

    def _header_message(self, fields: Iterable[tuple[str, str]]) -> Message:
        """Return a message holding *fields*, as received, and no body."""
        headers = Message(policy=self.message.policy)
        for name, value in fields:
            headers[name] = value
        return headers
