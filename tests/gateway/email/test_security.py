# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email authentication and authorization."""

import logging
from email.message import Message
from email.parser import BytesParser

import pytest

from airut.gateway.email.security import (
    SenderAuthenticator,
    SenderAuthorizer,
)


TRUSTED = "mx.example.com"
AUTHORIZED = "authorized@example.com"

#: A DMARC pass for AUTHORIZED's domain.
DMARC_PASS = "dmarc=pass header.from=example.com"


def _msg(
    from_addr: str = AUTHORIZED,
    auth_results: str | list[str] | None = None,
) -> Message:
    """Build a test email Message."""
    msg = Message()
    msg["From"] = from_addr
    if auth_results is not None:
        if isinstance(auth_results, list):
            for ar in auth_results:
                msg["Authentication-Results"] = ar
        else:
            msg["Authentication-Results"] = auth_results
    return msg


# ---------------------------------------------------------------------------
# SenderAuthenticator tests
# ---------------------------------------------------------------------------


class TestAuthenticate:
    """Test DMARC-based sender authentication."""

    def test_valid_dmarc(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS}; spf=fail")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_dmarc_fail(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=fail; spf=fail")
        assert auth.authenticate(msg) is None

    def test_no_auth_results(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=None)
        assert auth.authenticate(msg) is None

    def test_missing_from_header(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = Message()
        msg["Authentication-Results"] = f"{TRUSTED}; {DMARC_PASS}"
        assert auth.authenticate(msg) is None

    def test_returns_lowercase_email(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="USER@EXAMPLE.COM",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) == "user@example.com"

    def test_display_name_with_angle_brackets(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="User <authorized@example.com>",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_malformed_from_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="Evil <a@x.com> <b@x.com>",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) is None

    def test_empty_angle_brackets(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="User <>",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) is None


class TestSPFAloneInsufficient:
    """SPF pass without DMARC pass must be rejected."""

    def test_spf_pass_only_rejected(self):
        """SPF alone does not validate the From header."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; spf=pass")
        assert auth.authenticate(msg) is None

    def test_spf_pass_dmarc_fail_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=fail; spf=pass")
        assert auth.authenticate(msg) is None

    def test_dmarc_pass_spf_fail_accepted(self):
        """DMARC pass is sufficient even when SPF fails."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS}; spf=fail")
        assert auth.authenticate(msg) == AUTHORIZED


class TestFirstHeaderAuthservId:
    """Only the first (topmost) Authentication-Results header is examined.

    The receiving MTA prepends its header at the top (RFC 8601 §5).
    We stop at the very first header regardless of its authserv-id.
    """

    def test_untrusted_first_header_rejects(self):
        """First header from untrusted server — reject immediately."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"fake.server.com; {DMARC_PASS}")
        assert auth.authenticate(msg) is None

    def test_trusted_first_header_accepted(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS}")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_untrusted_first_then_trusted_second_rejected(self):
        """Untrusted first header — trusted header below is never examined."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                "untrusted.com; dmarc=fail",
                f"{TRUSTED}; {DMARC_PASS}",
            ]
        )
        assert auth.authenticate(msg) is None

    def test_untrusted_first_pass_then_trusted_second_rejected(self):
        """Untrusted first header with dmarc=pass — still rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                f"untrusted.com; {DMARC_PASS}",
                f"{TRUSTED}; {DMARC_PASS}",
            ]
        )
        assert auth.authenticate(msg) is None

    def test_authserv_id_case_insensitive(self):
        """Authserv-id comparison is case-insensitive."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"MX.EXAMPLE.COM; {DMARC_PASS}")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_no_semicolon_in_header(self):
        """Malformed first header without semicolon is rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"mx.example.com {DMARC_PASS}")
        assert auth.authenticate(msg) is None

    def test_trusted_first_fails_second_trusted_passes_rejected(self):
        """First trusted header fails — injected pass below is ignored.

        This is the key security property: an attacker injects a forged
        Authentication-Results header with dmarc=pass.  The real MTA
        prepends its own header (with dmarc=fail) above it.  We must
        reject based on the first header alone.
        """
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                f"{TRUSTED}; dmarc=fail",
                f"{TRUSTED}; {DMARC_PASS}",
            ]
        )
        assert auth.authenticate(msg) is None

    def test_trusted_first_passes_second_trusted_ignored(self):
        """First trusted header passes — lower headers are irrelevant."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                f"{TRUSTED}; {DMARC_PASS}",
                f"{TRUSTED}; dmarc=fail",
            ]
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_trusted_first_spf_only_second_dmarc_pass_rejected(self):
        """First header has only SPF — lower dmarc=pass is never seen."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                f"{TRUSTED}; spf=pass",
                f"{TRUSTED}; {DMARC_PASS}",
            ]
        )
        assert auth.authenticate(msg) is None


class TestAuthservIdMismatchLogging:
    """Authserv-id mismatch logs the header value for debugging."""

    def test_logs_header_on_mismatch(self, caplog: pytest.LogCaptureFixture):
        """Warning includes actual header so misconfigurations are obvious."""
        header = f"wrong.server.com; {DMARC_PASS}; spf=pass"
        msg = _msg(auth_results=header)
        with caplog.at_level(
            logging.WARNING, logger="airut.gateway.email.security"
        ):
            auth = SenderAuthenticator(TRUSTED)
            auth.authenticate(msg)
        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "wrong.server.com" in record.message
        assert TRUSTED in record.message
        assert header in record.message


class TestEmptyAuthservId:
    """Microsoft 365 / EOP omits authserv-id from Authentication-Results.

    When trusted_authserv_id is empty string, the authserv-id check is
    skipped and we rely solely on the first-header-only policy (the
    receiving MTA prepends its header at the top per RFC 8601 §5).
    """

    def test_microsoft_style_dmarc_pass(self):
        """Microsoft header with no authserv-id, dmarc=pass."""
        auth = SenderAuthenticator("")
        msg = _msg(
            auth_results=(
                "spf=pass (sender IP is 10.0.0.1)"
                " smtp.mailfrom=example.com;"
                " dkim=pass header.d=example.com;"
                " dmarc=pass action=none header.from=example.com;"
                "compauth=pass reason=100"
            )
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_microsoft_style_dmarc_fail(self):
        """Microsoft header with no authserv-id, dmarc=fail."""
        auth = SenderAuthenticator("")
        msg = _msg(
            auth_results=(
                "spf=pass (sender IP is 10.0.0.1)"
                " smtp.mailfrom=example.com;"
                " dmarc=fail action=none header.from=example.com"
            )
        )
        assert auth.authenticate(msg) is None

    def test_empty_authserv_id_still_uses_first_header_only(self):
        """Injected second header with dmarc=pass is never examined."""
        auth = SenderAuthenticator("")
        msg = _msg(
            auth_results=[
                (
                    "spf=pass smtp.mailfrom=example.com;"
                    " dmarc=fail header.from=example.com"
                ),
                (
                    "spf=pass smtp.mailfrom=example.com;"
                    " dmarc=pass header.from=example.com"
                ),
            ]
        )
        assert auth.authenticate(msg) is None

    def test_empty_authserv_id_single_entry(self):
        """A header that is a single entry needs no semicolon."""
        auth = SenderAuthenticator("")
        msg = _msg(auth_results=DMARC_PASS)
        assert auth.authenticate(msg) == AUTHORIZED

    def test_empty_authserv_id_missing_header_from(self):
        """Microsoft mode still requires header.from."""
        auth = SenderAuthenticator("")
        msg = _msg(auth_results="dmarc=pass")
        assert auth.authenticate(msg) is None

    def test_empty_authserv_id_no_header(self):
        """No Authentication-Results header is still rejected."""
        auth = SenderAuthenticator("")
        msg = _msg()
        assert auth.authenticate(msg) is None


class TestInternalAuthFallback:
    """Microsoft 365 internal mail has no Authentication-Results.

    Intra-org email in Microsoft 365 has no Authentication-Results
    header.  Instead, EOP stamps X-MS-Exchange-Organization-AuthAs:
    Internal.  When allow_internal_auth_fallback is enabled, this
    header is accepted as authentication proof when (and only when)
    no Authentication-Results header exists at all.
    """

    def _internal_msg(
        self,
        auth_as: str | None = "Internal",
        auth_results: str | list[str] | None = None,
        from_addr: str = AUTHORIZED,
    ) -> Message:
        """Build a message with Microsoft internal headers."""
        msg = _msg(from_addr=from_addr, auth_results=auth_results)
        if auth_as is not None:
            msg["X-MS-Exchange-Organization-AuthAs"] = auth_as
        return msg

    def test_internal_auth_accepted(self):
        """Internal message accepted when fallback enabled."""
        auth = SenderAuthenticator("", allow_internal_auth_fallback=True)
        msg = self._internal_msg()
        assert auth.authenticate(msg) == AUTHORIZED

    def test_fallback_disabled_rejects(self):
        """Internal message rejected when fallback disabled."""
        auth = SenderAuthenticator("", allow_internal_auth_fallback=False)
        msg = self._internal_msg()
        assert auth.authenticate(msg) is None

    def test_fallback_default_disabled(self):
        """Fallback is disabled by default."""
        auth = SenderAuthenticator("")
        msg = self._internal_msg()
        assert auth.authenticate(msg) is None

    def test_auth_results_present_no_fallback(self):
        """Fallback does not apply when Authentication-Results exists."""
        auth = SenderAuthenticator(TRUSTED, allow_internal_auth_fallback=True)
        msg = self._internal_msg(auth_results=f"{TRUSTED}; dmarc=fail")
        assert auth.authenticate(msg) is None

    def test_auth_results_present_dmarc_pass(self):
        """DMARC pass takes precedence over internal fallback."""
        auth = SenderAuthenticator(TRUSTED, allow_internal_auth_fallback=True)
        msg = self._internal_msg(auth_results=f"{TRUSTED}; {DMARC_PASS}")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_auth_as_anonymous_rejected(self):
        """Non-Internal AuthAs value is rejected."""
        auth = SenderAuthenticator("", allow_internal_auth_fallback=True)
        msg = self._internal_msg(auth_as="Anonymous")
        assert auth.authenticate(msg) is None

    def test_no_auth_as_header_rejected(self):
        """Missing AuthAs header is rejected."""
        auth = SenderAuthenticator("", allow_internal_auth_fallback=True)
        msg = self._internal_msg(auth_as=None)
        assert auth.authenticate(msg) is None

    def test_auth_as_case_insensitive(self):
        """AuthAs comparison is case-insensitive."""
        auth = SenderAuthenticator("", allow_internal_auth_fallback=True)
        msg = self._internal_msg(auth_as="INTERNAL")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_still_requires_valid_from(self):
        """Fallback still validates the From header."""
        auth = SenderAuthenticator("", allow_internal_auth_fallback=True)
        msg = self._internal_msg(from_addr="Evil <a@x> <b@x>")
        assert auth.authenticate(msg) is None

    def test_auth_as_raw_8bit(self):
        """An undecodable header is a Header object, not a str."""
        raw = (
            f"From: {AUTHORIZED}\r\n"
            "X-MS-Exchange-Organization-AuthAs: Intern\u00e4l\r\n\r\n"
        ).encode()
        msg = BytesParser().parsebytes(raw)
        auth = SenderAuthenticator("", allow_internal_auth_fallback=True)
        assert auth.authenticate(msg) is None

    def test_auth_as_with_whitespace(self):
        """AuthAs value with leading/trailing whitespace."""
        auth = SenderAuthenticator("", allow_internal_auth_fallback=True)
        msg = self._internal_msg(auth_as="  Internal  ")
        assert auth.authenticate(msg) == AUTHORIZED


class TestSubstringMatchBypass:
    """Partial/substring matches on DMARC results must not pass."""

    def test_dmarc_passthrough_should_not_match(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=passthrough")
        assert auth.authenticate(msg) is None

    def test_prefix_dmarc_should_not_match(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; not{DMARC_PASS}")
        assert auth.authenticate(msg) is None

    def test_dmarc_pass_with_parenthetical(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS} (p=NONE); spf=fail")
        assert auth.authenticate(msg) == AUTHORIZED


class TestDmarcCaseInsensitive:
    """DMARC verification is case-insensitive."""

    def test_uppercase_dmarc_pass(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=f"{TRUSTED}; DMARC=Pass Header.From=EXAMPLE.com"
        )
        assert auth.authenticate(msg) == AUTHORIZED


class TestComplexAuthHeader:
    """Test with realistic complex Authentication-Results headers."""

    def test_complex_header(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=f"""{TRUSTED};
       dkim=pass header.i=@example.com header.s=selector1;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=example.com;
       spf=fail (google.com: domain of test@other.com does not designate)"""
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_only_dkim_pass(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dkim=pass")
        assert auth.authenticate(msg) is None

    def test_empty_header(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results="")
        assert auth.authenticate(msg) is None


class TestHeaderObfuscation:
    """RFC comment injection and folding edge cases."""

    def test_comment_between_tokens_is_whitespace(self):
        """RFC 8601 allows comments between any two tokens."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=(
                f"{TRUSTED}; dmarc=(checking)pass (p=reject)"
                " header.from=(x)example.com"
            )
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_dmarc_pass_inside_comment_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=(
                f"{TRUSTED}; spf=pass (dmarc=pass header.from=example.com)"
                " smtp.mailfrom=example.com; dmarc=fail header.from=example.com"
            )
        )
        assert auth.authenticate(msg) is None

    def test_folded_auth_results_header(self):
        """A folded (multi-line) header parses like an unfolded one."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED};\r\n {DMARC_PASS}")
        assert auth.authenticate(msg) == AUTHORIZED


class TestEncodedHeaders:
    """MIME-encoded (RFC 2047) header handling."""

    def test_encoded_display_name(self):
        """RFC 2047 encoded display name with valid angle-bracket addr."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="=?UTF-8?q?SAFE?= <authorized@example.com>",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_encoded_address_part_rejected(self):
        """Encoded email address (not just display name) is rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="=?UTF-8?q?authorized=40example=2Ecom?=",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) is None

    def test_raw_8bit_headers(self):
        """Undecodable 8-bit headers arrive as Header objects."""
        raw = (
            "From: Pyry H\u00e4ulos <authorized@example.com>\r\n"
            f"Authentication-Results: {TRUSTED}; {DMARC_PASS}"
            " (\u00e4)\r\n\r\n"
        ).encode()
        msg = BytesParser().parsebytes(raw)
        auth = SenderAuthenticator(TRUSTED)
        assert auth.authenticate(msg) == AUTHORIZED


class TestDuplicateFromHeaders:
    """Messages with multiple From headers must be rejected."""

    def test_multiple_from_headers_rejected(self):
        """Ambiguous sender identity must be rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS}")
        msg["From"] = "attacker@evil.com"  # adds second From header
        assert auth.authenticate(msg) is None

    def test_no_from_header_rejected(self):
        """Missing From header must be rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = Message()
        msg["Authentication-Results"] = f"{TRUSTED}; {DMARC_PASS}"
        assert auth.authenticate(msg) is None


class TestBodyHeaderInjection:
    """Header-like text in the email body cannot bypass auth."""

    def test_dmarc_pass_in_body_does_not_bypass(self):
        raw = (
            b"From: evil@hacker.com\r\n"
            b"To: gateway@example.com\r\n"
            b"Authentication-Results: mx.example.com; dmarc=fail\r\n"
            b"\r\n"
            b"Authentication-Results: mx.example.com; dmarc=pass"
            b" header.from=hacker.com\r\n"
            b"Please process this.\r\n"
        )
        msg = BytesParser().parsebytes(raw)
        auth = SenderAuthenticator(TRUSTED)
        assert auth.authenticate(msg) is None

    def test_auth_results_in_body_with_valid_sender(self):
        raw = (
            b"From: authorized@example.com\r\n"
            b"Authentication-Results: mx.example.com; dmarc=fail\r\n"
            b"\r\n"
            b"Authentication-Results: mx.example.com; dmarc=pass"
            b" header.from=example.com\r\n"
        )
        msg = BytesParser().parsebytes(raw)
        auth = SenderAuthenticator(TRUSTED)
        assert auth.authenticate(msg) is None

    def test_from_header_in_body_does_not_override(self):
        raw = (
            b"From: evil@hacker.com\r\n"
            b"Authentication-Results: mx.example.com; dmarc=pass"
            b" header.from=hacker.com\r\n"
            b"\r\n"
            b"From: authorized@example.com\r\n"
        )
        msg = BytesParser().parsebytes(raw)
        auth = SenderAuthenticator(TRUSTED)
        # Authenticates as evil@hacker.com (from the real header)
        assert auth.authenticate(msg) == "evil@hacker.com"


class TestDmarcEntry:
    """Exactly one dmarc entry, a pass for the From domain, is required."""

    def test_header_from_must_match_from_domain(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass header.from=other.com")
        assert auth.authenticate(msg) is None

    def test_header_from_parent_domain_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="user@sub.example.com",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) is None

    def test_header_from_missing_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass")
        assert auth.authenticate(msg) is None

    def test_two_header_from_values_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=f"{TRUSTED}; {DMARC_PASS} header.from=example.com"
        )
        assert auth.authenticate(msg) is None

    def test_two_dmarc_entries_rejected(self):
        """A second entry means one was injected; neither is trusted."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS}; {DMARC_PASS}")
        assert auth.authenticate(msg) is None

    def test_injected_pass_beside_real_fail_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=(
                f"{TRUSTED}; {DMARC_PASS}; dmarc=fail header.from=example.com"
            )
        )
        assert auth.authenticate(msg) is None

    @pytest.mark.parametrize(
        "result", ["fail", "none", "temperror", "permerror", "bestguesspass"]
    )
    def test_other_results_rejected(self, result: str):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=f"{TRUSTED}; dmarc={result} header.from=example.com"
        )
        assert auth.authenticate(msg) is None

    def test_authserv_id_with_version(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED} 1; {DMARC_PASS}")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_malformed_header_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f'{TRUSTED}; {DMARC_PASS} reason="unclosed')
        assert auth.authenticate(msg) is None

    def test_amazon_ses_header(self):
        """SES writes key=value segments that are not methods."""
        auth = SenderAuthenticator("amazonses.com")
        msg = _msg(
            auth_results=(
                "amazonses.com; spf=pass (spfCheck: domain of example.com"
                " designates 203.0.113.1 as permitted sender)"
                " client-ip=203.0.113.1; envelope-from=authorized@example.com;"
                " helo=mail.example.com; dkim=pass header.i=@example.com;"
                f" {DMARC_PASS};"
            )
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_quoted_result_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=f'{TRUSTED}; dmarc="pass" header.from=example.com'
        )
        assert auth.authenticate(msg) is None

    def test_logs_why_dmarc_failed(self, caplog: pytest.LogCaptureFixture):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass header.from=other.com")
        with caplog.at_level(
            logging.WARNING, logger="airut.gateway.email.security"
        ):
            assert auth.authenticate(msg) is None
        assert len(caplog.records) == 1
        message = caplog.records[0].message
        assert "header.from=other.com" in message
        assert "From domain example.com" in message

    def test_non_ascii_lookalike_header_from_rejected(self):
        """The Kelvin sign lowercases to "k" but is not one."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="authorized@example.kom",
            auth_results=f"{TRUSTED}; dmarc=pass header.from=example.\u212aom",
        )
        assert auth.authenticate(msg) is None

    def test_non_ascii_lookalike_authserv_id_rejected(self):
        auth = SenderAuthenticator("mx.example.kom")
        msg = _msg(auth_results=f"mx.example.\u212aom; {DMARC_PASS}")
        assert auth.authenticate(msg) is None

    def test_header_without_authserv_id_rejected(self):
        """A Microsoft-style header does not match a configured id."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=DMARC_PASS)
        assert auth.authenticate(msg) is None


#: The header an MTA wrote for a forged DKIM signature whose ``i=`` tag
#: held ``a dmarc=pass b@evil.example``, followed by the real results.
FORGED_DKIM_IDENTITY = (
    "mx.example.com;\r\n"
    '\tdkim=neutral (body hash did not verify) header.i="a dmarc=pass '
    'b@evil.example" header.s=x header.b=AAAAAAAA;\r\n'
    "\tspf=fail smtp.mailfrom=evil.example;\r\n"
    "\tdmarc=fail header.from=example.com"
)


class TestForgedResultInValues:
    """Sender-controlled values may hold ``dmarc=pass``; it is never read."""

    @pytest.mark.parametrize(
        "auth_results",
        [
            pytest.param(FORGED_DKIM_IDENTITY, id="dkim-identity"),
            pytest.param(
                'mx.example.com; spf=pass smtp.mailfrom="x dmarc=pass"'
                "@evil.example; dmarc=fail header.from=example.com",
                id="quoted-local-part",
            ),
            pytest.param(
                'mx.example.com; dkim=pass header.d=evil.example header.i="'
                '; dmarc=pass header.from=example.com"; '
                "dmarc=fail header.from=example.com",
                id="quoted-semicolon",
            ),
            pytest.param(
                'mx.example.com; dkim-atps=neutral header.from="dmarc=pass";'
                " dmarc=temperror header.from=example.com",
                id="dkim-atps-header-from",
            ),
            pytest.param(
                "mx.example.com; spf=pass (dmarc=pass) smtp.mailfrom=x;"
                " dmarc=fail header.from=example.com",
                id="comment",
            ),
            pytest.param(
                'mx.example.com; dmarc=fail reason="dmarc=pass"'
                " header.from=example.com",
                id="reason",
            ),
            pytest.param(
                'mx.example.com; dmarc=fail policy.dmarc="pass"'
                " header.from=example.com",
                id="property",
            ),
        ],
    )
    def test_rejected(self, auth_results: str):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=auth_results)
        assert auth.authenticate(msg) is None


class TestHostileHeaderSizes:
    """Oversized or deeply nested headers are rejected without parsing."""

    def test_long_from_rejected(self):
        """Valid syntax, but longer than RFC 5322's 998-character line."""
        auth = SenderAuthenticator(TRUSTED)
        from_addr = "a." * 500 + " <authorized@example.com>"
        msg = _msg(from_addr=from_addr, auth_results=f"{TRUSTED}; {DMARC_PASS}")
        assert auth.authenticate(msg) is None

    def test_malformed_authentication_results_log_is_bounded(
        self, caplog: pytest.LogCaptureFixture
    ):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; " + "x" * 16000 + " y")
        with caplog.at_level(
            logging.WARNING, logger="airut.gateway.email.security"
        ):
            assert auth.authenticate(msg) is None
        assert max(len(r.getMessage()) for r in caplog.records) < 1000

    def test_deeply_nested_from_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="(" * 480 + ")" * 480 + f" <{AUTHORIZED}>",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )
        assert auth.authenticate(msg) is None

    def test_long_authentication_results_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        padding = " (" + "x" * 16384 + ")"
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS}{padding}")
        assert auth.authenticate(msg) is None


# ---------------------------------------------------------------------------
# SenderAuthorizer tests
# ---------------------------------------------------------------------------


class TestAuthorizer:
    """Test sender authorization against allowed list."""

    def test_authorized_sender(self):
        authz = SenderAuthorizer([AUTHORIZED])
        assert authz.is_authorized(AUTHORIZED) is True

    def test_unauthorized_sender(self):
        authz = SenderAuthorizer([AUTHORIZED])
        assert authz.is_authorized("evil@hacker.com") is False

    def test_case_insensitive(self):
        authz = SenderAuthorizer(["USER@EXAMPLE.COM"])
        assert authz.is_authorized("user@example.com") is True

    def test_different_domain(self):
        authz = SenderAuthorizer([AUTHORIZED])
        assert authz.is_authorized("authorized@other.com") is False


class TestAuthorizerMultipleSenders:
    """Test authorization with multiple senders."""

    def test_multiple_exact_matches(self):
        authz = SenderAuthorizer(["alice@example.com", "bob@example.com"])
        assert authz.is_authorized("alice@example.com") is True
        assert authz.is_authorized("bob@example.com") is True
        assert authz.is_authorized("carol@example.com") is False

    def test_domain_wildcard(self):
        authz = SenderAuthorizer(["*@company.com"])
        assert authz.is_authorized("alice@company.com") is True
        assert authz.is_authorized("bob@company.com") is True
        assert authz.is_authorized("admin@company.com") is True
        assert authz.is_authorized("alice@other.com") is False

    def test_domain_wildcard_case_insensitive(self):
        """Pattern is case-insensitive, sender is always lowercase from auth."""
        authz = SenderAuthorizer(["*@COMPANY.COM"])
        # SenderAuthenticator always returns lowercase addresses
        assert authz.is_authorized("alice@company.com") is True
        assert authz.is_authorized("bob@company.com") is True

    def test_mixed_exact_and_wildcard(self):
        authz = SenderAuthorizer(
            [
                "external@partner.org",
                "*@company.com",
            ]
        )
        assert authz.is_authorized("alice@company.com") is True
        assert authz.is_authorized("external@partner.org") is True
        assert authz.is_authorized("internal@partner.org") is False

    def test_wildcard_does_not_match_subdomain(self):
        authz = SenderAuthorizer(["*@company.com"])
        # The domain must be exactly company.com
        assert authz.is_authorized("user@sub.company.com") is False

    def test_empty_list_rejects_all(self):
        authz = SenderAuthorizer([])
        assert authz.is_authorized("anyone@anywhere.com") is False

    def test_first_match_wins(self):
        """Authorization succeeds on first pattern match."""
        authz = SenderAuthorizer(["alice@example.com", "*@example.com"])
        # alice@example.com matches the exact pattern first
        assert authz.is_authorized("alice@example.com") is True


# ---------------------------------------------------------------------------
# End-to-end: authentication + authorization combined
# ---------------------------------------------------------------------------


class TestEndToEnd:
    """Test authentication and authorization together."""

    def test_valid_sender_authenticated_and_authorized(self):
        auth = SenderAuthenticator(TRUSTED)
        authz = SenderAuthorizer([AUTHORIZED])
        msg = _msg(auth_results=f"{TRUSTED}; {DMARC_PASS}")

        sender = auth.authenticate(msg)
        assert sender is not None
        assert authz.is_authorized(sender) is True

    def test_authenticated_but_unauthorized(self):
        auth = SenderAuthenticator(TRUSTED)
        authz = SenderAuthorizer([AUTHORIZED])
        msg = _msg(
            from_addr="other@example.com",
            auth_results=f"{TRUSTED}; {DMARC_PASS}",
        )

        sender = auth.authenticate(msg)
        assert sender == "other@example.com"
        assert authz.is_authorized(sender) is False

    def test_unauthenticated_skips_authorization(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"fake.server.com; {DMARC_PASS}")

        sender = auth.authenticate(msg)
        assert sender is None
