# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for strict reading of the From header."""

import base64

import pytest

from airut.gateway.email.from_header import (
    MAX_COMMENT_DEPTH,
    MAX_LENGTH,
    parse_from_mailbox,
)


AUTHORIZED = "authorized@example.com"


class TestBasics:
    def test_bare_email(self):
        assert parse_from_mailbox("user@example.com") == "user@example.com"

    def test_with_display_name(self):
        assert (
            parse_from_mailbox("User <user@example.com>") == "user@example.com"
        )

    def test_quoted_display_name(self):
        assert (
            parse_from_mailbox('"User, Name" <user@example.com>')
            == "user@example.com"
        )

    def test_case_insensitive(self):
        assert parse_from_mailbox("USER@EXAMPLE.COM") == "user@example.com"

    def test_whitespace(self):
        assert parse_from_mailbox("  user@example.com  ") == "user@example.com"

    def test_empty(self):
        assert parse_from_mailbox("") is None

    def test_empty_angle_brackets(self):
        assert parse_from_mailbox("User <>") is None

    def test_multiple_angle_brackets(self):
        assert (
            parse_from_mailbox("Evil <evil@example.net> <good@example.net>")
            is None
        )

    def test_unquoted_address_as_display_name_rejected(self):
        """An unquoted address is not a valid display name."""
        assert parse_from_mailbox("good@example.net <evil@example.net>") is None

    def test_quoted_address_as_display_name(self):
        """A quoted display name may look like an address."""
        assert (
            parse_from_mailbox('"good@example.net" <evil@example.net>')
            == "evil@example.net"
        )

    def test_gt_before_lt(self):
        assert parse_from_mailbox(">user@example.net<") is None

    def test_invalid_email_format(self):
        assert parse_from_mailbox("not an email") is None


class TestSingleMailbox:
    """From must hold exactly one mailbox: replies go to every address."""

    @pytest.mark.parametrize(
        "from_header",
        [
            "<authorized@example.com>, x@",
            "<authorized@example.com>, attacker@evil.example",
            "attacker@evil.example, <authorized@example.com>",
            "Authorized <authorized@example.com>, attacker@evil.example",
            "group: authorized@example.com;",
            "group: authorized@example.com, attacker@evil.example;",
            "undisclosed-recipients:;",
            "authorized",
            "<authorized>",
            "authorized@example.com <attacker@evil.example>",
            '"authorized@example.com"@evil.example',
            "authorized@[192.0.2.1]",
            "Authorized <authorized@example.com",
            "authorized..x@example.com",
            "Doe, John <authorized@example.com>",
            "Authorized [Company] <authorized@example.com>",
            "(c):",
            "(c): authorized@example.com;",
            "=?UTF-8?q?authorized=40example=2Ecom?=",
        ],
    )
    def test_rejected(self, from_header: str):
        assert parse_from_mailbox(from_header) is None

    @pytest.mark.parametrize(
        "from_header",
        [
            "authorized@example.com",
            "Authorized <authorized@example.com>",
            '"Authorized, User" <authorized@example.com>',
            "John Q. Public <authorized@example.com>",
            "Authorized\r\n <authorized@example.com>",
            "=?utf-8?q?P=C3=BCry?= <authorized@example.com>",
        ],
    )
    def test_accepted(self, from_header: str):
        assert parse_from_mailbox(from_header) == AUTHORIZED

    @pytest.mark.parametrize(
        "from_header",
        [
            "authorized@example.com\nBcc: x@example.org",
            "Authorized\r\n<authorized@example.com>",
            "<authorized@example.com\n>",
        ],
    )
    def test_bare_line_break_rejected(self, from_header: str):
        assert parse_from_mailbox(from_header) is None


class TestAddressWrittenPlainly:
    """The address itself holds no comments, whitespace or route."""

    @pytest.mark.parametrize(
        "from_header",
        [
            "authorized(c)@example.com",
            "authorized@(c)example.com",
            "authorized@example.com(c)",
            "Authorized <authorized(c)@example.com>",
            "Authorized <authorized@example.com (c)>",
            "Authorized < authorized@example.com >",
            "Authorized <authorized @ example.com>",
            "<@route.example:authorized@example.com>",
            '"<authorized@example.com>" <@route.example:'
            "authorized@example.com>",
            "authorized@example.com (Authorized)",
            '<"authorized"@example.com>',
            '"authorized"@example.com',
            "Authorized\r\n <authorized@\r\n example.com>",
            "Authorized <authorized@example.com> (see <other@example.org>)",
            "Authorized <authorized@example.com> (work)",
            # A comment holding the address does not make it plain.
            "authorized(c)@example.com (<authorized@example.com>)",
            "authorized@(c)example.com (<authorized@example.com>)",
            "Authorized <authorized(c)@example.com> (<authorized@example.com>)",
            "Authorized <authorized @ example.com> (<authorized@example.com>)",
            "<@r.example:authorized@example.com> (<authorized@example.com>)",
            '<"authorized"@example.com> (<authorized@example.com>)',
            "authorized@example.com (<authorized@example.com>)",
            # Another angle address in the display name could be read as
            # the sender by a parser that takes the first one.
            '"<other@example.org>" <authorized@example.com>',
            "(<other@example.org>) <authorized@example.com>",
            '"a>b" <authorized@example.com>',
            # Encoded words are decoded before the structure is read; a
            # parser that does not decode them sees the specials inside.
            "=?utf-8?q?,attacker@example.com,?= <authorized@example.com>",
            "=?utf-8?q?:attacker@example.com;?= <authorized@example.com>",
            '=?utf-8?q?"?= <authorized@example.com>',
            "=?utf-8?q?(?= <authorized@example.com>",
            "=?utf-8?q?x, ?= <authorized@example.com>",
            ", <authorized@example.com>",
            "Authorized\\ <authorized@example.com>",
            # Decodes to a display name that looks like another address.
            "=?utf-8?q?=3Cattacker=40example=2Ecom=3E?="
            " <authorized@example.com>",
            # Decoded as lenient clients decode them: an encoded word not
            # set apart by spaces, or inside a comment.
            "x=?utf-8?q?=3Cmallory=40example.com=3E?= <authorized@example.com>",
            "Name (=?utf-8?q?=3Cmallory=40example.com=3E?=)"
            " <authorized@example.com>",
            # An "@" only decoding produces.
            "=?utf-8?q?mallory=40example.com?= <authorized@example.com>",
            "mallory=?utf-8?q?=40?=example.com <authorized@example.com>",
            "=?utf-8?b?bWFsbG9yeUBleGFtcGxlLmNvbSw=?= <authorized@example.com>",
            # Decoded parentheses or quotes that free a raw "@".
            "(=?utf-8?q?=29?= mallory@example.com =?utf-8?q?=28=28?=)"
            " <authorized@example.com>",
            "Name (=?utf-8?q?=29_mallory@example.com_=28?=)"
            " <authorized@example.com>",
            '=?utf-8?q?=22?= "mallory@example.com" <authorized@example.com>',
            # Display names that cannot be decoded.
            "=?x-unknown?q?a?= <authorized@example.com>",
            "=?utf-8?b?!!!?= <authorized@example.com>",
            "Name (=?x-unknown?q?a?=) <authorized@example.com>",
            # An encoded word left undecoded in the address itself.
            "a.=?utf-8?b?PA==?=.b@example.com",
            # Characters str.strip() would drop but other parsers keep.
            " \x1cauthorized@example.com",
            "authorized@example.com \x1f",
            "\x0bAuthorized <authorized@example.com>",
        ],
    )
    def test_rejected(self, from_header: str):
        assert parse_from_mailbox(from_header) is None

    @pytest.mark.parametrize(
        "from_header",
        [
            "Authorized (work) <authorized@example.com>",
            '"Authorized (work)" <authorized@example.com>',
            '"Doe, John" <authorized@example.com>',
            '"Authorized \\"Q\\" User" <authorized@example.com>',
            "Authorized via List <authorized@example.com>",
            "'Authorized' via Group <authorized@example.com>",
            "=?utf-8?b?UMOkaXZp?= <authorized@example.com>",
            "=?iso-8859-1?Q?M=FCller=2C_Hans?= <authorized@example.com>",
            "=?utf-8?q?M=C3=BCller_=28IT=29?= <authorized@example.com>",
            "=?UTF-8?Q?'P=C3=A4ivi'_via_Gr=C3=BCppe?= <authorized@example.com>",
            "\"'authorized@example.com' via Group\" <authorized@example.com>",
            '"authorized@example.com" <authorized@example.com>',
            "\tAuthorized <authorized@example.com>\t",
            "AUTHORIZED@EXAMPLE.COM",
            "  Authorized <authorized@example.com>  ",
        ],
    )
    def test_accepted(self, from_header: str):
        assert parse_from_mailbox(from_header) == AUTHORIZED


class TestLength:
    """The standard library's parser is quadratic; long input is refused."""

    def test_at_limit_accepted(self):
        address = f" <{AUTHORIZED}>"
        from_header = "a" * (MAX_LENGTH - len(address)) + address
        assert parse_from_mailbox(from_header) == AUTHORIZED

    def test_over_limit_rejected(self):
        address = f" <{AUTHORIZED}>"
        from_header = "a" * (MAX_LENGTH + 1 - len(address)) + address
        assert parse_from_mailbox(from_header) is None

    def test_limit_applies_unfolded(self):
        """Folding does not count towards the length."""
        address = f"\r\n <{AUTHORIZED}>"
        from_header = "a" * (MAX_LENGTH + 1 - len(address)) + address
        assert parse_from_mailbox(from_header) == AUTHORIZED

    def test_huge_header_rejected(self):
        assert parse_from_mailbox("(a)" * 1_000_000 + AUTHORIZED) is None


class TestCommentDepth:
    """The parser recurses into nested comments; deep nesting is refused."""

    @staticmethod
    def _nested(depth: int) -> str:
        return "Authorized " + "(" * depth + ")" * depth + f" <{AUTHORIZED}>"

    def test_at_limit_accepted(self):
        assert parse_from_mailbox(self._nested(MAX_COMMENT_DEPTH)) == AUTHORIZED

    @pytest.mark.parametrize("depth", [MAX_COMMENT_DEPTH + 1, 300, 480])
    def test_over_limit_rejected(self, depth: int):
        from_header = self._nested(depth)
        assert len(from_header) <= MAX_LENGTH
        assert parse_from_mailbox(from_header) is None

    def test_escaped_close_does_not_end_a_comment(self):
        from_header = "N " + "(\\)" * 242 + ")" * 242 + f" <{AUTHORIZED}>"
        assert len(from_header) <= MAX_LENGTH
        assert parse_from_mailbox(from_header) is None

    def test_every_parenthesis_counts(self):
        """Even quoted or escaped ones: counting more only rejects more."""
        assert parse_from_mailbox('"((((" <authorized@example.com>') is None
        assert (
            parse_from_mailbox(r"A (\(\(\() <authorized@example.com>") is None
        )

    @pytest.mark.parametrize(
        "from_header",
        [
            pytest.param('x@["] ' + "(" * 990, id="quote-in-domain-literal"),
            pytest.param(
                '=?utf-8?q?"?= ' + "(" * 984, id="quote-in-encoded-word"
            ),
            pytest.param(
                '"=?utf-8?q?"?=" ' + "(" * 981, id="encoded-word-in-quotes"
            ),
        ],
    )
    def test_quote_does_not_hide_parentheses(self, from_header: str):
        """A '"' the parser reads as text cannot hide nesting from the count."""
        assert len(from_header) <= MAX_LENGTH
        assert parse_from_mailbox(from_header) is None

    def test_nesting_only_in_decoded_text(self):
        """Decoded nesting hits the parser's recursion limit: a rejection."""
        from_header = (
            "=?utf-8?b?"
            + base64.b64encode(b"(" * 700).decode()
            + "?=x@example.com"
        )
        assert len(from_header) <= MAX_LENGTH
        assert parse_from_mailbox(from_header) is None
