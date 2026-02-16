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
    _extract_email,
)


# ---------------------------------------------------------------------------
# _extract_email unit tests
# ---------------------------------------------------------------------------

TRUSTED = "mx.example.com"
AUTHORIZED = "authorized@example.com"


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


class TestExtractEmail:
    """Test strict email address extraction."""

    def test_bare_email(self):
        assert _extract_email("user@example.com") == "user@example.com"

    def test_with_display_name(self):
        assert _extract_email("User <user@example.com>") == "user@example.com"

    def test_quoted_display_name(self):
        assert (
            _extract_email('"User, Name" <user@example.com>')
            == "user@example.com"
        )

    def test_case_insensitive(self):
        assert _extract_email("USER@EXAMPLE.COM") == "user@example.com"

    def test_whitespace(self):
        assert _extract_email("  user@example.com  ") == "user@example.com"

    def test_empty(self):
        assert _extract_email("") is None

    def test_empty_angle_brackets(self):
        assert _extract_email("User <>") is None

    def test_multiple_angle_brackets(self):
        """Multiple angle brackets are rejected (injection attempt)."""
        assert _extract_email("Evil <evil@x.com> <good@x.com>") is None

    def test_display_name_contains_email(self):
        """Display name with email should extract angle bracket content."""
        assert _extract_email("good@x.com <evil@x.com>") == "evil@x.com"

    def test_gt_before_lt(self):
        assert _extract_email(">user@x.com<") is None

    def test_invalid_email_format(self):
        """Address with spaces fails regex validation."""
        assert _extract_email("not an email") is None


# ---------------------------------------------------------------------------
# SenderAuthenticator tests
# ---------------------------------------------------------------------------


class TestAuthenticate:
    """Test DMARC-based sender authentication."""

    def test_valid_dmarc(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass; spf=fail")
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
        msg["Authentication-Results"] = f"{TRUSTED}; dmarc=pass"
        assert auth.authenticate(msg) is None

    def test_returns_lowercase_email(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="USER@EXAMPLE.COM",
            auth_results=f"{TRUSTED}; dmarc=pass",
        )
        assert auth.authenticate(msg) == "user@example.com"

    def test_display_name_with_angle_brackets(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="User <authorized@example.com>",
            auth_results=f"{TRUSTED}; dmarc=pass",
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_malformed_from_rejected(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="Evil <a@x.com> <b@x.com>",
            auth_results=f"{TRUSTED}; dmarc=pass",
        )
        assert auth.authenticate(msg) is None

    def test_empty_angle_brackets(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="User <>",
            auth_results=f"{TRUSTED}; dmarc=pass",
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
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass; spf=fail")
        assert auth.authenticate(msg) == AUTHORIZED


class TestFirstHeaderAuthservId:
    """Only the first (topmost) Authentication-Results header is examined.

    The receiving MTA prepends its header at the top (RFC 8601 §5).
    We stop at the very first header regardless of its authserv-id.
    """

    def test_untrusted_first_header_rejects(self):
        """First header from untrusted server — reject immediately."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results="fake.server.com; dmarc=pass")
        assert auth.authenticate(msg) is None

    def test_trusted_first_header_accepted(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_untrusted_first_then_trusted_second_rejected(self):
        """Untrusted first header — trusted header below is never examined."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                "untrusted.com; dmarc=fail",
                f"{TRUSTED}; dmarc=pass",
            ]
        )
        assert auth.authenticate(msg) is None

    def test_untrusted_first_pass_then_trusted_second_rejected(self):
        """Untrusted first header with dmarc=pass — still rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                "untrusted.com; dmarc=pass",
                f"{TRUSTED}; dmarc=pass",
            ]
        )
        assert auth.authenticate(msg) is None

    def test_authserv_id_case_insensitive(self):
        """Authserv-id comparison is case-insensitive."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results="MX.EXAMPLE.COM; dmarc=pass")
        assert auth.authenticate(msg) == AUTHORIZED

    def test_no_semicolon_in_header(self):
        """Malformed first header without semicolon is rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results="mx.example.com dmarc=pass")
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
                f"{TRUSTED}; dmarc=pass",
            ]
        )
        assert auth.authenticate(msg) is None

    def test_trusted_first_passes_second_trusted_ignored(self):
        """First trusted header passes — lower headers are irrelevant."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            auth_results=[
                f"{TRUSTED}; dmarc=pass",
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
                f"{TRUSTED}; dmarc=pass",
            ]
        )
        assert auth.authenticate(msg) is None


class TestAuthservIdMismatchLogging:
    """Authserv-id mismatch logs the header value for debugging."""

    def test_logs_header_on_mismatch(self, caplog: pytest.LogCaptureFixture):
        """Warning includes actual header so misconfigurations are obvious."""
        auth = SenderAuthenticator(TRUSTED)
        header = "wrong.server.com; dmarc=pass; spf=pass"
        msg = _msg(auth_results=header)
        with caplog.at_level(logging.WARNING, logger="airut.gateway.security"):
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

    def test_empty_authserv_id_no_semicolon(self):
        """Malformed header without semicolon is still rejected."""
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
        msg = self._internal_msg(auth_results=f"{TRUSTED}; dmarc=pass")
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
        msg = _msg(auth_results=f"{TRUSTED}; notdmarc=pass")
        assert auth.authenticate(msg) is None

    def test_dmarc_pass_with_parenthetical(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass (p=NONE); spf=fail")
        assert auth.authenticate(msg) == AUTHORIZED


class TestDmarcCaseInsensitive:
    """DMARC verification is case-insensitive."""

    def test_uppercase_dmarc_pass(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; DMARC=PASS; SPF=FAIL")
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

    def test_dmarc_pass_with_rfc_comment_rejected(self):
        """RFC comments in header values must not bypass strict matching."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=(checking)pass")
        assert auth.authenticate(msg) is None

    def test_folded_auth_results_header(self):
        """Folded (multi-line) headers are unfolded by Python's email lib."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED};\r\n dmarc=pass")
        assert auth.authenticate(msg) == AUTHORIZED


class TestEncodedHeaders:
    """MIME-encoded (RFC 2047) header handling."""

    def test_encoded_display_name(self):
        """RFC 2047 encoded display name with valid angle-bracket addr."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="=?UTF-8?q?SAFE?= <authorized@example.com>",
            auth_results=f"{TRUSTED}; dmarc=pass",
        )
        assert auth.authenticate(msg) == AUTHORIZED

    def test_encoded_address_part_rejected(self):
        """Encoded email address (not just display name) is rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(
            from_addr="=?UTF-8?q?authorized=40example=2Ecom?=",
            auth_results=f"{TRUSTED}; dmarc=pass",
        )
        assert auth.authenticate(msg) is None


class TestDuplicateFromHeaders:
    """Messages with multiple From headers must be rejected."""

    def test_multiple_from_headers_rejected(self):
        """Ambiguous sender identity must be rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass")
        msg["From"] = "attacker@evil.com"  # adds second From header
        assert auth.authenticate(msg) is None

    def test_no_from_header_rejected(self):
        """Missing From header must be rejected."""
        auth = SenderAuthenticator(TRUSTED)
        msg = Message()
        msg["Authentication-Results"] = f"{TRUSTED}; dmarc=pass"
        assert auth.authenticate(msg) is None


class TestBodyHeaderInjection:
    """Header-like text in the email body cannot bypass auth."""

    def test_dmarc_pass_in_body_does_not_bypass(self):
        raw = (
            b"From: evil@hacker.com\r\n"
            b"To: gateway@example.com\r\n"
            b"Authentication-Results: mx.example.com; dmarc=fail\r\n"
            b"\r\n"
            b"Authentication-Results: mx.example.com; dmarc=pass\r\n"
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
            b"Authentication-Results: mx.example.com; dmarc=pass\r\n"
        )
        msg = BytesParser().parsebytes(raw)
        auth = SenderAuthenticator(TRUSTED)
        assert auth.authenticate(msg) is None

    def test_from_header_in_body_does_not_override(self):
        raw = (
            b"From: evil@hacker.com\r\n"
            b"Authentication-Results: mx.example.com; dmarc=pass\r\n"
            b"\r\n"
            b"From: authorized@example.com\r\n"
        )
        msg = BytesParser().parsebytes(raw)
        auth = SenderAuthenticator(TRUSTED)
        # Authenticates as evil@hacker.com (from the real header)
        assert auth.authenticate(msg) == "evil@hacker.com"


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
        # "user@sub.company.com" ends with @company.com? No, it ends with .com
        # Actually @sub.company.com does not end with @company.com
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
        msg = _msg(auth_results=f"{TRUSTED}; dmarc=pass")

        sender = auth.authenticate(msg)
        assert sender is not None
        assert authz.is_authorized(sender) is True

    def test_authenticated_but_unauthorized(self):
        auth = SenderAuthenticator(TRUSTED)
        authz = SenderAuthorizer([AUTHORIZED])
        msg = _msg(
            from_addr="other@example.com",
            auth_results=f"{TRUSTED}; dmarc=pass",
        )

        sender = auth.authenticate(msg)
        assert sender == "other@example.com"
        assert authz.is_authorized(sender) is False

    def test_unauthenticated_skips_authorization(self):
        auth = SenderAuthenticator(TRUSTED)
        msg = _msg(auth_results="fake.server.com; dmarc=pass")

        sender = auth.authenticate(msg)
        assert sender is None
