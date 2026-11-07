# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the fetched-email wrapper."""

import pytest

from airut.gateway.email.incoming import IncomingEmail


def _problem(raw: bytes) -> str | None:
    return IncomingEmail.parse(raw).header_section_problem()


class TestHeaderSectionProblem:
    """Every header-section line must be a field or a continuation of one.

    Parsers treat other lines, and bare carriage returns, inconsistently:
    they could read different header fields, or a different body.
    """

    @pytest.mark.parametrize(
        "line",
        [
            b"From the sender: a note",
            b"From :someone@example.org",
            b"From someone@example.org Sat Nov  7 10:00:00 2026",
            b"no colon here",
            b"Bad Name: value",
            b": no name",
            b"::value",
            b"\xc3\xa4ddress: value",
        ],
    )
    @pytest.mark.parametrize("position", ["first", "middle", "last"])
    def test_line_that_is_not_a_field(self, line: bytes, position: str):
        fields = [b"From: a@example.com", b"Subject: s"]
        index = {"first": 0, "middle": 1, "last": 2}[position]
        fields.insert(index, line)
        raw = b"\r\n".join(fields) + b"\r\n\r\nbody\r\n"
        assert _problem(raw) == f"a line that is not a header field: {line!r}"

    def test_long_line_shown_truncated(self):
        line = b"x" * 500
        problem = _problem(b"From: a@example.com\r\n" + line + b"\r\n\r\n")
        assert problem == f"a line that is not a header field: {line[:100]!r}"

    def test_continuation_line_at_the_start(self):
        raw = b" folded\r\nFrom: a@example.com\r\n\r\nbody\r\n"
        assert _problem(raw) == "a continuation line at the start"

    @pytest.mark.parametrize(
        "raw",
        [
            b"From: a@example.com\r\nX-Note: a\r b\r\n\r\nbody\r\n",
            b"From: a@example.com\r\n\r\r\nbody\r\n",
            b"From: a@example.com\r\n\rbody\r\n",
        ],
        ids=["in-a-field", "line-of-its-own", "starting-a-line"],
    )
    def test_bare_carriage_return(self, raw: bytes):
        assert _problem(raw) == "a carriage return not followed by a line feed"

    @pytest.mark.parametrize(
        "raw",
        [
            b"From: a@example.com\r\nSubject: s\r\n\tfolded\r\n \r\n\r\nb\r\n",
            b"From: a@example.com\nSubject: s\n\n",
            b"From: a@example.com\r\n",
            b"From: a@example.com",
            b"",
        ],
        ids=["folded", "lf", "no-body", "no-line-break", "empty"],
    )
    def test_unambiguous(self, raw: bytes):
        assert _problem(raw) is None

    @pytest.mark.parametrize(
        "separator", [b"\r\n\r\n", b"\n\n", b"\r\n\n", b"\n\r\n"]
    )
    def test_body_not_checked(self, separator: bytes):
        """The section ends at the first empty line, however it ends."""
        raw = b"From: a@example.com" + separator + b"From x\r\nline\ronly\r\n"
        assert _problem(raw) is None

    def test_last_line_without_line_break_checked(self):
        assert _problem(b"From: a@example.com\r\nFrom x") is not None
