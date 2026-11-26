# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for Airut's own DKIM verification."""

import base64
from unittest.mock import MagicMock, patch

import dkim
import dns.exception
import pytest

from airut.gateway.email.dkim import (
    MAX_HEADER_FIELDS,
    MAX_KEY_RECORD_BYTES,
    MAX_SIGNATURE_BYTES,
    MAX_SIGNATURES,
    MAX_SIGNED_HEADERS,
    DkimVerifier,
    lookup_txt,
)
from tests import dkim_signing


MESSAGE = (
    b"From: Authorized <authorized@example.com>\r\n"
    b"To: airut@example.org\r\n"
    b"Subject: Hello\r\n"
    b"Date: Sat, 07 Nov 2026 06:00:00 +0000\r\n"
    b"Message-ID: <m1@example.com>\r\n"
    b"\r\n"
    b"Please do the thing.\r\n"
)


class _Lookup:
    """The test key's DNS, counting lookups."""

    def __init__(self) -> None:
        self.names: list[bytes] = []

    def __call__(self, name: bytes, timeout: int = 5) -> bytes | None:
        self.names.append(name)
        return dkim_signing.lookup(name, timeout)


@pytest.fixture
def lookup() -> _Lookup:
    return _Lookup()


def _verify(
    raw: bytes, lookup: _Lookup, sender: str = "authorized@example.com"
) -> bool:
    return DkimVerifier(lookup).verify(raw, sender) is not None


class TestVerifier:
    def test_valid_signature(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        assert _verify(signed, lookup) is True
        assert lookup.names == [b"test._domainkey.example.com."]

    def test_returns_the_fields_the_signature_covers(self, lookup: _Lookup):
        """As ``h=`` lists them: lowercase, in order, repeats kept."""
        signed = dkim_signing.sign(
            MESSAGE, "example.com", headers=("From", "subject", "from")
        )
        fields = DkimVerifier(lookup).verify(signed, "authorized@example.com")
        assert fields == ("from", "subject", "from")

    def test_returns_the_verifying_signatures_fields(self, lookup: _Lookup):
        """Not those of a signature that does not verify."""
        signed = dkim_signing.sign(MESSAGE, "example.com", headers=("from",))
        broken = dkim_signing.sign(
            MESSAGE, "example.com", selector="missing", headers=("from", "to")
        )
        raw = broken[: broken.index(MESSAGE)] + signed
        fields = DkimVerifier(lookup).verify(raw, "authorized@example.com")
        assert fields == ("from",)

    def test_signing_domain_case_insensitive(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "Example.COM")
        assert _verify(signed, lookup) is True

    def test_no_signature(self, lookup: _Lookup):
        assert _verify(MESSAGE, lookup) is False

    def test_signature_by_another_domain_not_tried(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "evil.example")
        assert _verify(signed, lookup) is False
        assert lookup.names == []

    def test_parent_domain_does_not_count(self, lookup: _Lookup):
        signed = dkim_signing.sign(
            MESSAGE.replace(b"@example.com>", b"@sub.example.com>"),
            "example.com",
        )
        assert _verify(signed, lookup, "authorized@sub.example.com") is False

    def test_signed_from_must_be_the_sender(self, lookup: _Lookup):
        """A valid signature over another sender's From does not count."""
        signed = dkim_signing.sign(MESSAGE, "example.com")
        assert _verify(signed, lookup, "other@example.com") is False
        assert lookup.names == []

    def test_two_signed_from_fields_refused(self, lookup: _Lookup):
        message = b"From: other@example.com\r\n" + MESSAGE
        signed = dkim_signing.sign(
            message, "example.com", headers=("from", "from", "subject")
        )
        assert _verify(signed, lookup) is False
        assert lookup.names == []

    def test_signed_from_compared_case_insensitively(self, lookup: _Lookup):
        signed = dkim_signing.sign(
            MESSAGE.replace(b"authorized@", b"Authorized@"), "example.com"
        )
        assert _verify(signed, lookup) is True

    def test_body_changed(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        tampered = signed.replace(b"the thing", b"something else")
        assert _verify(tampered, lookup) is False

    def test_from_changed(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        tampered = signed.replace(b"Authorized <", b"Mallory <")
        assert _verify(tampered, lookup) is False

    def test_body_length_tag_refused(self, lookup: _Lookup):
        """With l=, anyone may append to the signed body."""
        signed = dkim_signing.sign(MESSAGE, "example.com", length=True)
        assert _verify(signed + b"Also this.\r\n", lookup) is False
        assert lookup.names == []

    def test_rsa_sha1_refused(self, lookup: _Lookup):
        signature = dkim.sign(
            MESSAGE,
            b"test",
            b"example.com",
            dkim_signing.private_pem(),
            include_headers=[b"from"],
            signature_algorithm=b"rsa-sha1",
        )
        assert _verify(signature + MESSAGE, lookup) is False
        assert lookup.names == []

    def test_signature_not_covering_from_refused(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        unsigned_from = signed.replace(b"h=from : to", b"h=to", 1)
        assert unsigned_from != signed
        assert _verify(unsigned_from, lookup) is False
        assert lookup.names == []

    def test_too_many_signed_headers_refused(self, lookup: _Lookup):
        headers = ("from",) + tuple(
            f"x-h{i}" for i in range(MAX_SIGNED_HEADERS)
        )
        signed = dkim_signing.sign(MESSAGE, "example.com", headers=headers)
        with patch.object(dkim.DKIM, "verify", autospec=True) as verify:
            assert _verify(signed, lookup) is False
        verify.assert_not_called()

    def test_malformed_signature_skipped(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        assert _verify(b"DKIM-Signature: garbage\r\n" + signed, lookup)

    def test_non_ascii_signing_domain_skipped(self, lookup: _Lookup):
        raw = "DKIM-Signature: v=1; d=exämple.com; s=x\r\n".encode()
        assert _verify(raw + MESSAGE, lookup) is False
        assert lookup.names == []

    def test_later_signature_verifies(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        broken = dkim_signing.sign(MESSAGE, "example.com", selector="missing")
        broken_signature = broken[: len(broken) - len(MESSAGE)]
        assert _verify(broken_signature + signed, lookup) is True
        assert len(lookup.names) == 2

    def test_at_most_max_signatures_tried(self, lookup: _Lookup):
        """Each tries a DNS lookup; an attacker could add any number."""
        signed = dkim_signing.sign(MESSAGE, "example.com")
        broken = dkim_signing.sign(MESSAGE, "example.com", selector="missing")
        broken_signature = broken[: len(broken) - len(MESSAGE)]
        raw = broken_signature * MAX_SIGNATURES + signed
        assert _verify(raw, lookup) is False
        assert len(lookup.names) == MAX_SIGNATURES

    def test_too_many_header_fields(self, lookup: _Lookup):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        padding = b"X-Pad: x\r\n" * MAX_HEADER_FIELDS
        assert _verify(padding + signed, lookup) is False
        assert lookup.names == []

    def test_ed25519_signature(self, lookup: _Lookup):
        signed = dkim_signing.sign_ed25519(MESSAGE, "example.com")
        assert b"a=ed25519-sha256" in signed
        fields = DkimVerifier(lookup).verify(signed, "authorized@example.com")
        assert fields == dkim_signing.SIGNED_HEADERS
        assert lookup.names == [b"ed25519._domainkey.example.com."]

    def test_ed25519_body_changed(self, lookup: _Lookup):
        signed = dkim_signing.sign_ed25519(MESSAGE, "example.com")
        tampered = signed.replace(b"the thing", b"another thing")
        assert _verify(tampered, lookup) is False

    def test_ed25519_and_rsa_signatures(self, lookup: _Lookup):
        """Signers adopting Ed25519 sign with RSA too (RFC 8463)."""
        signed = dkim_signing.sign(MESSAGE, "example.com")
        both = dkim_signing.sign_ed25519(signed, "example.com")
        assert _verify(both, lookup) is True
        assert lookup.names == [b"ed25519._domainkey.example.com."]

    def test_ed25519_and_rsa_falls_back_to_rsa(self, lookup: _Lookup):
        """An Ed25519 signature that fails does not stop the RSA one."""
        signed = dkim_signing.sign(MESSAGE, "example.com")
        both = dkim_signing.sign_ed25519(signed, "example.com", selector="no")
        assert _verify(both, lookup) is True
        assert lookup.names == [
            b"no._domainkey.example.com.",
            b"test._domainkey.example.com.",
        ]

    def test_key_type_must_match_algorithm(
        self, lookup: _Lookup, caplog: pytest.LogCaptureFixture
    ):
        """A valid Ed25519 signature labelled ``rsa-sha256`` is refused.

        dkimpy alone verifies it with whatever key the record holds.
        """
        signed = dkim_signing.sign_mislabelled(
            MESSAGE, "example.com", "ed25519"
        )
        assert b"a=rsa-sha256" in signed
        assert dkim.DKIM(signed).verify(dnsfunc=dkim_signing.lookup)
        assert _verify(signed, lookup) is False
        assert lookup.names == [b"ed25519._domainkey.example.com."]
        assert "holds a 'ed25519' key, not 'rsa'" in caplog.text

    def test_key_type_must_match_ed25519_algorithm(
        self, lookup: _Lookup, caplog: pytest.LogCaptureFixture
    ):
        """A valid RSA signature labelled ``ed25519-sha256`` is refused."""
        signed = dkim_signing.sign_mislabelled(MESSAGE, "example.com", "rsa")
        assert b"a=ed25519-sha256" in signed
        assert dkim.DKIM(signed).verify(dnsfunc=dkim_signing.lookup)
        assert _verify(signed, lookup) is False
        assert lookup.names == [b"test._domainkey.example.com."]
        assert "holds a 'rsa' key, not 'ed25519'" in caplog.text

    def test_rsa_signature_with_key_record_without_k(self):
        """A record without ``k=`` holds an RSA key."""
        signed = dkim_signing.sign(MESSAGE, "example.com")
        record = dkim_signing.public_record().replace(b" k=rsa;", b"")
        assert b"k=" not in record
        verifier = DkimVerifier(lambda name, timeout=5: record)
        assert verifier.verify(signed, "authorized@example.com") is not None

    def test_ed25519_key_of_wrong_length_refused(self):
        signed = dkim_signing.sign_ed25519(MESSAGE, "example.com")
        record = b"v=DKIM1; k=ed25519; p=" + base64.b64encode(b"x" * 16)
        verifier = DkimVerifier(lambda name, timeout=5: record)
        assert verifier.verify(signed, "authorized@example.com") is None

    def test_malformed_key_record_refused(
        self, caplog: pytest.LogCaptureFixture
    ):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        verifier = DkimVerifier(lambda name, timeout=5: b"garbage")
        with caplog.at_level("DEBUG", logger="airut.gateway.email.dkim"):
            assert verifier.verify(signed, "authorized@example.com") is None
        assert "is malformed" in caplog.text

    def test_oversized_signature_refused(self, lookup: _Lookup):
        """A valid signature, but longer than the limit."""
        headers = ("from",) + tuple(f"x-{'a' * 40}-{i}" for i in range(90))
        signed = dkim_signing.sign(MESSAGE, "example.com", headers=headers)
        signature = signed[: len(signed) - len(MESSAGE)]
        assert len(signature) > MAX_SIGNATURE_BYTES
        with patch.object(dkim.DKIM, "verify", autospec=True) as verify:
            assert _verify(signed, lookup) is False
        verify.assert_not_called()

    def test_oversized_key_record_refused(self):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        record = dkim_signing.public_record() + b"; n=" + b"a" * 1024
        assert len(record) > MAX_KEY_RECORD_BYTES
        verifier = DkimVerifier(lambda name, timeout=5: record)
        assert verifier.verify(signed, "authorized@example.com") is None

    def test_key_shorter_than_minimum_refused(self):
        signed = dkim_signing.sign(
            MESSAGE, "example.com", key=dkim_signing.small_key()
        )
        record = dkim_signing.public_record(dkim_signing.small_key())
        verifier = DkimVerifier(lambda name, timeout=5: record)
        assert verifier.verify(signed, "authorized@example.com") is None

    def test_costly_whitespace_in_body_refused(self, lookup: _Lookup):
        body = b"x" + b" " * 20_000 + b"x\r\n"
        signed = dkim_signing.sign(MESSAGE + body, "example.com")
        assert _verify(signed, lookup) is False
        assert lookup.names == []

    def test_ordinary_whitespace_in_body_accepted(self, lookup: _Lookup):
        body = b"    indented line\r\n" * 2000 + b"a   b\t\tc\r\n"
        signed = dkim_signing.sign(MESSAGE + body, "example.com")
        assert _verify(signed, lookup) is True

    def test_any_error_from_verification_is_a_failure(self):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        failing = MagicMock(side_effect=RuntimeError("unexpected"))
        verifier = DkimVerifier(failing)
        assert verifier.verify(signed, "authorized@example.com") is None

    def test_unreadable_message(self, lookup: _Lookup):
        assert _verify(b"garbage", lookup) is False

    def test_unusable_key(self):
        signed = dkim_signing.sign(MESSAGE, "example.com")
        verifier = DkimVerifier(lambda name, timeout=5: b"v=DKIM1; p=!!!!")
        assert verifier.verify(signed, "authorized@example.com") is None


class TestLookupTxt:
    def test_record_joined(self):
        rdata = MagicMock(strings=(b"v=DKIM1; ", b"p=abc"))
        answer = MagicMock(rrset=[rdata])
        with patch("dns.resolver.resolve", return_value=answer) as resolve:
            assert lookup_txt(b"s._domainkey.example.com.") == (
                b"v=DKIM1; p=abc"
            )
        resolve.assert_called_once_with(
            "s._domainkey.example.com.",
            "TXT",
            lifetime=5,
            search=False,
            raise_on_no_answer=False,
        )

    def test_no_record(self):
        with patch("dns.resolver.resolve", return_value=MagicMock(rrset=None)):
            assert lookup_txt(b"s._domainkey.example.com.") is None

    def test_dns_error(self):
        error = dns.exception.Timeout()
        with patch("dns.resolver.resolve", side_effect=error):
            assert lookup_txt(b"s._domainkey.example.com.") is None

    def test_non_ascii_name(self):
        assert lookup_txt("s._domainkey.ä.com.".encode()) is None
