# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the Authentication-Results parser (RFC 8601)."""

import pytest

from airut.gateway.email.authres import (
    AuthResult,
    AuthResults,
    AuthResultsParseError,
)
from airut.gateway.email.authres import (
    parse_authentication_results as parse,
)


class TestStructure:
    def test_authserv_id_and_entries(self):
        parsed = parse(
            "mx.example.com; spf=pass smtp.mailfrom=example.com;"
            " dmarc=pass header.from=example.com"
        )
        assert parsed == AuthResults(
            "mx.example.com",
            (
                AuthResult("spf", "pass", (("smtp.mailfrom", "example.com"),)),
                AuthResult("dmarc", "pass", (("header.from", "example.com"),)),
            ),
        )

    def test_authserv_id_with_version(self):
        parsed = parse("mx.example.com 1; dmarc=pass")
        assert parsed.authserv_id == "mx.example.com"

    def test_quoted_authserv_id(self):
        assert parse('"mx.example.com"; dmarc=pass').authserv_id == (
            "mx.example.com"
        )

    def test_none(self):
        assert parse("mx.example.com; none") == AuthResults(
            "mx.example.com", ()
        )

    def test_none_case_insensitive(self):
        assert parse("mx.example.com; NONE").results == ()

    def test_authserv_id_only(self):
        assert parse("mx.example.com").results == ()

    def test_trailing_and_empty_segments(self):
        parsed = parse("mx.example.com; ; dmarc=pass;")
        assert [r.method for r in parsed.results] == ["dmarc"]

    def test_no_authserv_id(self):
        """Microsoft 365 starts with the first entry."""
        parsed = parse(
            "spf=pass (sender IP is 10.0.0.1) smtp.mailfrom=example.com;"
            " dkim=pass (signature was verified) header.d=example.com;"
            " dmarc=pass action=none header.from=example.com;"
            "compauth=pass reason=100"
        )
        assert parsed.authserv_id is None
        assert [(r.method, r.result) for r in parsed.results] == [
            ("spf", "pass"),
            ("dkim", "pass"),
            ("dmarc", "pass"),
            ("compauth", "pass"),
        ]
        assert parsed.results[2].properties == (
            ("action", "none"),
            ("header.from", "example.com"),
        )
        assert parsed.results[3].values("reason") == ["100"]

    def test_segments_that_are_not_methods(self):
        """Amazon SES writes key=value segments beside its entries."""
        parsed = parse(
            "amazonses.com; spf=pass (spfCheck: ...) client-ip=203.0.113.1;"
            " envelope-from=user@example.com; helo=mail.example.com;"
            " dmarc=pass header.from=example.com;"
        )
        assert [(r.method, r.result) for r in parsed.results] == [
            ("spf", "pass"),
            ("envelope-from", "user@example.com"),
            ("helo", "mail.example.com"),
            ("dmarc", "pass"),
        ]

    def test_method_version_dropped(self):
        assert parse("mx; dkim/1=pass").results[0].method == "dkim"

    def test_case_folded(self):
        result = parse("mx; DMARC=Pass Header.From=Example.COM").results[0]
        assert (result.method, result.result) == ("dmarc", "pass")
        assert result.values("HEADER.FROM") == ["Example.COM"]

    def test_values_in_order(self):
        result = parse("mx; dmarc=pass header.from=a header.from=b").results[0]
        assert result.values("header.from") == ["a", "b"]
        assert result.values("header.d") == []


class TestWhitespaceAndComments:
    def test_folded(self):
        parsed = parse("mx.example.com;\r\n\tdkim=pass\r\n header.d=x.com")
        assert parsed.results[0].values("header.d") == ["x.com"]

    def test_whitespace_around_equals(self):
        result = parse("mx; dmarc = pass header.from =x.com").results[0]
        assert result.result == "pass"
        assert result.values("header.from") == ["x.com"]

    def test_comments_dropped(self):
        result = parse(
            "mx (comment); dmarc=(a)pass (p=reject (nested) dis=none)"
            " header.from=(b)x.com"
        ).results[0]
        assert result == AuthResult(
            "dmarc", "pass", (("header.from", "x.com"),)
        )

    def test_escaped_parenthesis_in_comment(self):
        result = parse(
            r"mx; dmarc=pass (a \) dmarc=fail) header.from=x"
        ).results
        assert len(result) == 1
        assert result[0].values("header.from") == ["x"]

    def test_semicolon_in_comment(self):
        parsed = parse("mx; spf=pass (x; dmarc=pass) smtp.mailfrom=x")
        assert [r.method for r in parsed.results] == ["spf"]

    def test_comment_separates_tokens(self):
        result = parse("mx; dmarc=pass(c)header.from=x").results[0]
        assert result.values("header.from") == ["x"]


class TestValues:
    def test_quoted_value(self):
        result = parse(
            'mx; dkim=neutral header.i="a dmarc=pass b@evil.example" header.s=x'
        ).results[0]
        assert result.values("header.i") == ["a dmarc=pass b@evil.example"]
        assert result.values("header.s") == ["x"]

    def test_quoted_semicolon_is_not_a_separator(self):
        parsed = parse('mx; dkim=pass header.i="; dmarc=pass"')
        assert len(parsed.results) == 1
        assert parsed.results[0].values("header.i") == ["; dmarc=pass"]

    def test_escapes_in_quoted_string(self):
        result = parse(r'mx; dkim=pass header.i="a\"b\\c"').results[0]
        assert result.values("header.i") == ['a"b\\c']

    def test_quoted_local_part_joined_to_domain(self):
        result = parse('mx; spf=pass smtp.mailfrom="a b;c"@x.com').results[0]
        assert result.values("smtp.mailfrom") == ["a b;c@x.com"]

    def test_at_domain(self):
        result = parse("mx; dkim=pass header.i=@x.com").results[0]
        assert result.values("header.i") == ["@x.com"]

    def test_value_keeps_padding(self):
        result = parse("mx; dkim=pass header.b=abc== header.s=x").results[0]
        assert result.values("header.b") == ["abc=="]
        assert result.values("header.s") == ["x"]

    def test_empty_quoted_value(self):
        result = parse('mx; dmarc=pass reason=""').results[0]
        assert result.values("reason") == [""]


class TestMalformed:
    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("", id="empty"),
            pytest.param("; dmarc=pass", id="empty-authserv-id"),
            pytest.param("mx extra junk; dmarc=pass", id="authserv-id-junk"),
            pytest.param("mx v1; dmarc=pass", id="bad-version"),
            pytest.param('mx "1"; dmarc=pass', id="quoted-version"),
            pytest.param("mx dmarc=pass", id="no-semicolon"),
            pytest.param("mx; dmarc=pass (open", id="unterminated-comment"),
            pytest.param("mx; dmarc=pass (a (b)", id="unclosed-nested"),
            pytest.param("mx; dmarc=pass (a\\", id="escape-at-end-of-comment"),
            pytest.param("mx; dmarc=pass )", id="unbalanced-paren"),
            pytest.param(
                'mx; dmarc=pass reason="open', id="unterminated-quote"
            ),
            pytest.param('mx; dmarc=pass reason="a\\', id="escape-at-end"),
            pytest.param("mx; dmarc", id="method-without-result"),
            pytest.param("mx; dmarc pass", id="missing-equals"),
            pytest.param("mx; dmarc=", id="missing-result"),
            pytest.param("mx; dmarc==pass", id="equals-as-result"),
            pytest.param("mx; =pass", id="missing-method"),
            pytest.param('mx; "dmarc"=pass', id="quoted-method"),
            pytest.param("mx; dm@rc=pass", id="invalid-method"),
            pytest.param("mx; header.from=x", id="property-as-method"),
            pytest.param('mx; dmarc="pass"', id="quoted-result"),
            pytest.param('mx; dmarc=pa"ss"', id="partly-quoted-result"),
            pytest.param("mx; dmarc=pass header.from", id="property-no-equals"),
            pytest.param("mx; none; dmarc=pass", id="none-with-entries"),
        ],
    )
    def test_rejected(self, value: str):
        with pytest.raises(AuthResultsParseError):
            parse(value)
