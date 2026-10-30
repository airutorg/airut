# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for outgoing email composition and attachment fitting."""

import smtplib
from email.message import Message
from email.parser import BytesParser
from unittest.mock import MagicMock

import pytest

from airut.gateway.email.composer import (
    Attachment,
    Draft,
    attachment_budget,
    fit_attachments,
    is_size_rejection,
    omitted_note,
    wire_size,
)
from airut.units import MB, format_size
from tests.gateway.email.conftest import attachment_names, plain_text


def _draft(
    body: str = "Here is the report.",
    footer: str = "",
    in_reply_to: str | None = None,
    message_id: str | None = None,
) -> Draft:
    return Draft(
        sender="Bot <bot@example.com>",
        to="user@example.com",
        subject="[ID:abc12345] Re: Report",
        body=body,
        footer=footer,
        in_reply_to=in_reply_to,
        message_id=message_id,
    )


def _html(msg: Message) -> str:
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True)
            assert isinstance(payload, bytes)
            return payload.decode()
    raise AssertionError("no text/html body")


def _smtplib_size(msg: Message) -> int:
    """Return the number of bytes ``smtplib`` hands to ``sendmail``."""
    server = smtplib.SMTP(local_hostname="localhost")
    server.ehlo_resp = b""
    sendmail = MagicMock()
    server.sendmail = sendmail
    server.send_message(msg)
    return len(sendmail.call_args[0][2])


class TestAttachment:
    @pytest.mark.parametrize("size", [0, 1, 3, 56, 57, 58, 114, 100_000])
    def test_encoded_size_matches_part(self, size: int) -> None:
        """The size is worked out without encoding, and must be exact."""
        attachment = Attachment("report.pdf", b"\xa5" * size)
        assert attachment.size == size
        assert attachment.encoded_size == wire_size(attachment.part)

    def test_encoded_size_counts_encoded_file_name(self) -> None:
        attachment = Attachment("räport 2026 – final.pdf", b"x" * 1000)
        assert attachment.encoded_size == wire_size(attachment.part)

    def test_guesses_mime_type(self) -> None:
        assert (
            Attachment("photo.png", b"png").part.get_content_type()
            == "image/png"
        )
        assert (
            Attachment("data.xyz123", b"?").part.get_content_type()
            == "application/octet-stream"
        )


class TestWireSize:
    def test_matches_smtplib(self) -> None:
        """Lines starting with "From " cost an escaping ">" on the wire."""
        body = "From the logs:\n\nFrom here on it fails."
        files = [Attachment("log.txt", b"From somewhere\n" * 100)]
        msg = _draft(body=body).build(files)
        assert wire_size(msg) == _smtplib_size(msg)


class TestDraftBuild:
    def test_note_sits_between_body_and_footer(self) -> None:
        msg = _draft(footer="Cost: $1").build([], "Could not attach x")
        assert plain_text(msg) == (
            "Here is the report.\n\nCould not attach x\n\n*Cost: $1*"
        )
        html = _html(msg)
        assert html.index("report") < html.index("Could not attach")
        assert html.index("Could not attach") < html.index("<em>Cost")

    def test_renders_html_from_markdown(self) -> None:
        msg = _draft(body="See <https://example.com/x>").build([])
        assert '<a href="https://example.com/x">' in _html(msg)

    def test_headers(self) -> None:
        msg = _draft(
            in_reply_to="<m1@example.com>",
            message_id="<airut.abc@example.com>",
        ).build([])
        assert msg["From"] == "Bot <bot@example.com>"
        assert msg["To"] == "user@example.com"
        assert msg["In-Reply-To"] == "<m1@example.com>"
        assert msg["Message-ID"] == "<airut.abc@example.com>"
        assert "References" not in msg


class TestOmittedNote:
    def test_names_files_with_sizes(self) -> None:
        note = omitted_note(
            [
                Attachment("big.zip", b"x" * (3 * MB)),
                Attachment("a.txt", b"hi"),
            ],
            "because reasons",
        )
        assert note == (
            "Could not attach 2 file(s) because reasons: "
            "big.zip (3.0MB), a.txt (2B)"
        )


class TestFitAttachments:
    def test_no_attachments(self) -> None:
        msg, omitted = fit_attachments(_draft(), [], limit=1)
        assert omitted == []
        assert msg.get_content_type() == "multipart/alternative"

    def test_everything_fits(self) -> None:
        files = [
            Attachment("a.txt", b"a" * 1000),
            Attachment("b.txt", b"b" * 1000),
        ]
        msg, omitted = fit_attachments(_draft(), files, limit=MB)
        assert omitted == []
        assert attachment_names(msg) == ["a.txt", "b.txt"]
        assert "Could not attach" not in plain_text(msg)

    def test_leaves_out_largest_first(self) -> None:
        """Dropping the largest file keeps as many files as possible."""
        small1 = Attachment("small1.txt", b"a" * 20_000)
        big = Attachment("big.bin", b"b" * 60_000)
        small2 = Attachment("small2.txt", b"c" * 20_000)
        # Room for both small files, but not for the big one.
        limit = wire_size(_draft().build([small1, small2])) + 2_000

        msg, omitted = fit_attachments(
            _draft(footer="Cost: $1"), [small1, big, small2], limit
        )

        assert omitted == [big]
        assert attachment_names(msg) == ["small1.txt", "small2.txt"]
        assert wire_size(msg) <= limit
        assert plain_text(msg) == (
            "Here is the report.\n\n"
            "Could not attach 1 file(s) without exceeding the "
            f"{format_size(limit)} email size limit: big.bin (59KB)\n\n"
            "*Cost: $1*"
        )

    def test_leaves_out_several_until_it_fits(self) -> None:
        files = [
            Attachment(f"f{i}.bin", bytes([i]) * (10_000 + i * 1000))
            for i in range(5)
        ]
        limit = wire_size(_draft().build(files[:2])) + 2_000

        msg, omitted = fit_attachments(_draft(), files, limit)

        assert omitted == files[2:]
        assert attachment_names(msg) == ["f0.bin", "f1.bin"]
        assert wire_size(msg) <= limit
        # Named in their original order.
        assert "f2.bin (12KB), f3.bin (13KB), f4.bin (14KB)" in plain_text(msg)

    def test_files_that_only_just_fit_are_measured_exactly(self) -> None:
        """Within the cheap estimate, the full message decides."""
        files = [
            Attachment("a.bin", b"a" * 30_000),
            Attachment("b.bin", b"b" * 30_000),
        ]
        exact = wire_size(_draft().build(files))

        msg, omitted = fit_attachments(_draft(), files, exact)
        assert omitted == []

        msg, omitted = fit_attachments(_draft(), files, exact - 1)
        assert len(omitted) == 1
        assert wire_size(msg) <= exact - 1

    def test_files_left_out_are_never_encoded(self) -> None:
        huge = Attachment("huge.bin", b"h" * MB)
        small = Attachment("small.txt", b"s" * 100)

        msg, omitted = fit_attachments(_draft(), [huge, small], 100_000)

        assert omitted == [huge]
        assert attachment_names(msg) == ["small.txt"]
        assert "part" not in vars(huge)

    def test_nothing_fits(self) -> None:
        files = [
            Attachment("a.bin", b"a" * 50_000),
            Attachment("b.bin", b"b" * 40_000),
        ]
        limit = 10_000

        msg, omitted = fit_attachments(_draft(), files, limit)

        assert omitted == files
        assert attachment_names(msg) == []
        # No attachments left: the plain alternative structure.
        assert msg.get_content_type() == "multipart/alternative"
        assert "a.bin (49KB), b.bin (39KB)" in plain_text(msg)

    def test_text_alone_over_limit_still_built(self) -> None:
        """The server judges a message that cannot be made to fit."""
        files = [Attachment("a.bin", b"a" * 1000)]
        msg, omitted = fit_attachments(_draft(), files, limit=100)
        assert omitted == files
        assert wire_size(msg) > 100
        assert "Here is the report." in plain_text(msg)

    def test_round_trips_through_parser(self) -> None:
        files = [Attachment("a.txt", b"payload")]
        msg, _ = fit_attachments(_draft(), files, limit=MB)
        parsed = BytesParser().parsebytes(msg.as_bytes())
        parts = [p for p in parsed.walk() if p.get_filename() == "a.txt"]
        assert parts[0].get_payload(decode=True) == b"payload"


class TestIsSizeRejection:
    @pytest.mark.parametrize(
        "error",
        [
            smtplib.SMTPSenderRefused(
                552, b"5.3.4 Message size exceeds fixed limit", "bot@x"
            ),
            # No enhanced status code: 552 is the RFC 1870 size reply.
            smtplib.SMTPDataError(552, b"Too much mail data"),
            smtplib.SMTPDataError(554, b"5.3.4 Message too big for system"),
            smtplib.SMTPDataError(552, b"5.2.3 Your message exceeded limits"),
            smtplib.SMTPDataError(
                552,
                b"5.3.4 Your message exceeded Google's message size limits."
                b"\n5.3.4 Please visit https://support.google.com/mail",
            ),
            smtplib.SMTPDataError(554, "5.3.4 Message too big"),
        ],
    )
    def test_size_errors(self, error: smtplib.SMTPException) -> None:
        assert is_size_rejection(error)

    @pytest.mark.parametrize(
        "error",
        [
            smtplib.SMTPDataError(550, b"5.7.1 Rejected as spam"),
            # Gmail refuses some file types with 552 and a 5.7.0 status.
            smtplib.SMTPDataError(
                552, b"5.7.0 Our system detected an illegal attachment"
            ),
            smtplib.SMTPDataError(
                550, b"5.7.1 Client host [10.5.3.42] blocked"
            ),
            smtplib.SMTPDataError(550, b"Client host [10.5.3.42] blocked"),
            smtplib.SMTPDataError(550, b"5.3.4.1 is not a status code"),
            smtplib.SMTPServerDisconnected("Connection unexpectedly closed"),
            smtplib.SMTPRecipientsRefused({"u@x": (550, b"No such user")}),
        ],
    )
    def test_other_errors(self, error: smtplib.SMTPException) -> None:
        assert not is_size_rejection(error)


class TestAttachmentBudget:
    def test_files_of_budget_size_fit(self) -> None:
        """A reply with files totalling the budget stays under the limit."""
        limit = 2 * MB
        budget = attachment_budget(limit)
        half = budget // 2
        files = [
            Attachment("a.bin", b"\x00" * half),
            Attachment("b.bin", b"\xff" * (budget - half)),
        ]
        draft = _draft(body="Long reply with ünicode. " * 2000)

        msg, omitted = fit_attachments(draft, files, limit)

        assert omitted == []
        assert wire_size(msg) <= limit

    def test_default_limit(self) -> None:
        assert 18 * MB < attachment_budget(25 * MB) < 18.5 * MB
