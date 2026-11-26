# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""DKIM checks: the mail server's recorded result, and Airut's own.

DMARC passes when either SPF or DKIM is aligned with the From domain,
and SPF depends only on the connecting IP address, which whoever runs
the network in front of the mail server may control.  Requiring a DKIM
signature by the From domain closes that path: only the domain's key
holder can produce one.

``server_dkim_passes`` reads the result the mail server recorded in its
``Authentication-Results`` header.  ``DkimVerifier`` verifies the
signatures in Airut itself, so a result the server got wrong, or a
header written by an account that submits its own mail, cannot vouch
for a signature that does not verify.

Verification uses the message's bytes as received, and looks up the
signer's public key in DNS through the host's resolver.  Whoever can
answer those lookups can make a forged signature verify, so the
resolver must be one an attacker cannot answer for: see the DNS section
of ``doc/email-setup.md``.

A signature counts only if the From field it covers is the sender
Airut authenticated, read the same way.  The verifier reports which
header fields the signature covers, so that Airut acts on those alone.

Signatures made with ``rsa-sha256`` (by an RSA key of at least
``MIN_KEY_BITS``) or ``ed25519-sha256`` (RFC 8463) count, each only with
a key record of its own key type.

Work is bounded whatever the message: at most ``MAX_SIGNATURES``
signatures by the From domain are tried, and none is verified for a
message with more than ``MAX_HEADER_FIELDS`` header fields or with
runs of spaces and tabs costly to canonicalize; a signature
longer than ``MAX_SIGNATURE_BYTES`` or listing more than
``MAX_SIGNED_HEADERS`` header fields, or a key record longer than
``MAX_KEY_RECORD_BYTES``, is not used.
"""

import functools
import logging
import re
from typing import Protocol

import dkim
import dns.exception
import dns.resolver
from dkim.util import InvalidTagValueList, parse_tag_value

from airut.gateway.email.authres import AuthResult, AuthResults, ascii_lower
from airut.gateway.email.from_header import parse_from_mailbox


logger = logging.getLogger(__name__)

#: Most signatures by the From domain tried on one message.
MAX_SIGNATURES = 3

#: Most header fields one signature may list in ``h=``.
MAX_SIGNED_HEADERS = 100

#: Most header fields a message may have.
MAX_HEADER_FIELDS = 1000

#: Longest DKIM-Signature field used; real ones are well under 2 KiB.
MAX_SIGNATURE_BYTES = 4096

#: Longest key record used; an RSA-4096 key takes about 750 bytes.
MAX_KEY_RECORD_BYTES = 1024

#: Most canonicalization work allowed for runs of spaces and tabs in the
#: message, as the sum of the squares of their lengths: relaxed
#: canonicalization of the body takes time growing with that.
MAX_WHITESPACE_COST = 50_000_000

#: Seconds allowed for one DNS lookup.
DNS_TIMEOUT = 5

#: RSA keys shorter than this are refused (RFC 8301).
MIN_KEY_BITS = 1024

#: Signing algorithms accepted (``rsa-sha1`` is not: RFC 8301), with the
#: key type each needs (RFC 8463).
_KEY_TYPES = {b"rsa-sha256": b"rsa", b"ed25519-sha256": b"ed25519"}

#: A run of two or more spaces and tabs.
_WHITESPACE_RUN_RE = re.compile(rb"[\t ]{2,}")


class TxtLookup(Protocol):
    """Looks up the TXT record at a DNS name (dkimpy's ``dnsfunc``)."""

    def __call__(self, name: bytes, timeout: int = DNS_TIMEOUT) -> bytes | None:
        """Return the record's text, or None if there is none."""
        ...


def lookup_txt(name: bytes, timeout: int = DNS_TIMEOUT) -> bytes | None:
    """Look up the TXT record at *name* with the host's resolver.

    Search domains are not appended.  Any failure is reported as no
    record, which fails the signature.
    """
    try:
        answer = dns.resolver.resolve(
            name.decode("ascii"),
            "TXT",
            lifetime=timeout,
            search=False,
            raise_on_no_answer=False,
        )
    except (dns.exception.DNSException, UnicodeDecodeError):
        return None
    if answer.rrset is None:
        return None
    return b"".join(next(iter(answer.rrset)).strings)


class _DkimpyLogger:
    """The logger handed to dkimpy: its messages go to ours at DEBUG.

    Its errors describe the sender's signature or key, not a fault in
    Airut; the verifier logs the outcome itself.
    """

    def debug(self, msg: object, *args: object) -> None:
        logger.debug(msg, *args)

    info = warning = error = debug


def _signing_domain(entry: AuthResult) -> str | None:
    """Return the domain that made the signature *entry* records.

    That is ``header.d``, or, when the server writes only the identity
    (as Stalwart does for a signature with an ``i=`` tag), the domain
    after the last ``@`` of ``header.i``.  RFC 6376 has verifiers check
    that ``i=`` lies within ``d=``.
    """
    signers = entry.values("header.d")
    if signers:
        return ascii_lower(signers[0]) if len(signers) == 1 else None
    identities = entry.values("header.i")
    if len(identities) == 1 and "@" in identities[0]:
        return ascii_lower(identities[0].rpartition("@")[2])
    return None


def server_dkim_passes(results: AuthResults, domain: str) -> bool:
    """Whether the server recorded a passing DKIM signature by *domain*.

    Only ``dkim`` entries count (not ``dkim-atps``), and only those
    whose signing domain is exactly *domain*.

    Args:
        results: The trusted ``Authentication-Results`` header, parsed.
        domain: Lowercase domain of the From address.
    """
    for entry in results.results:
        if (
            entry.method == "dkim"
            and entry.result == "pass"
            and _signing_domain(entry) == domain
        ):
            return True
    logger.warning(
        "DKIM: the mail server recorded no passing signature by %s", domain
    )
    return False


class _UnsuitableError(Exception):
    """A signature cannot vouch for the From domain."""


def _signature_tags(signature: bytes, domain: str) -> dict[bytes, bytes]:
    """Return the tags of *signature*, if it can vouch for *domain*.

    Raises:
        _UnsuitableError: Saying why it cannot.
    """
    if len(signature) > MAX_SIGNATURE_BYTES:
        raise _UnsuitableError("too long")
    try:
        tags = parse_tag_value(signature)
    except InvalidTagValueList:
        raise _UnsuitableError("malformed") from None
    signer = tags.get(b"d", b"")
    if not signer.isascii() or signer.decode().lower() != domain:
        raise _UnsuitableError("another domain")
    if tags.get(b"a") not in _KEY_TYPES:
        raise _UnsuitableError("algorithm not accepted")
    if b"l" in tags:
        raise _UnsuitableError("covers only part of the body (l=)")
    signed = _signed_fields(tags)
    if "from" not in signed:
        raise _UnsuitableError("does not sign From")
    if len(signed) > MAX_SIGNED_HEADERS:
        raise _UnsuitableError("signs too many header fields")
    return tags


def _signed_fields(tags: dict[bytes, bytes]) -> tuple[str, ...]:
    """Return the field names a signature's ``h=`` tag lists, lowercase."""
    return tuple(
        name.strip().lower().decode("ascii", "replace")
        for name in tags.get(b"h", b"").split(b":")
    )


def _whitespace_cost(raw: bytes) -> int:
    """Return the canonicalization work runs of whitespace in *raw* need."""
    return sum(
        (match.end() - match.start()) ** 2
        for match in _WHITESPACE_RUN_RE.finditer(raw)
    )


def _signed_sender(headers: list[list[bytes]]) -> str | None:
    """Return the address in the single From field of *headers*, or None.

    Parsed as Airut parses the From it authenticates, so the two can be
    compared.
    """
    values = [value for name, value in headers if name.lower() == b"from"]
    if len(values) != 1:
        return None
    text = values[0].decode("utf-8", "surrogateescape").rstrip("\r\n")
    return parse_from_mailbox(text)


class DkimVerifier:
    """Verifies DKIM signatures over a message's bytes."""

    def __init__(self, lookup: TxtLookup = lookup_txt) -> None:
        """Initialize the verifier.

        Args:
            lookup: Looks up the TXT records holding signers' keys.
        """
        self._lookup = lookup

    def _lookup_key(
        self, name: bytes, *, key_type: bytes, timeout: int = DNS_TIMEOUT
    ) -> bytes | None:
        """Look up a key record of *key_type*, refusing one unfit to use.

        A record too long, or holding a key of another type than the
        signature's algorithm needs (RFC 6376 section 6.1.2), is refused:
        dkimpy would use whatever key the record holds.
        """
        record = self._lookup(name, timeout=timeout)
        if record is None:
            return None
        if len(record) > MAX_KEY_RECORD_BYTES:
            logger.warning(
                "DKIM: key record at %.200r is %d bytes (limit %d)",
                name,
                len(record),
                MAX_KEY_RECORD_BYTES,
            )
            return None
        try:
            # A record without k= holds an RSA key (RFC 6376 section 3.6.1).
            found = parse_tag_value(record).get(b"k", b"rsa")
        except InvalidTagValueList:
            logger.debug("DKIM: key record at %.200r is malformed", name)
            return None
        if found != key_type:
            logger.warning(
                "DKIM: key record at %.200r holds a %.20r key, not %r",
                name,
                found.decode("ascii", "replace"),
                key_type.decode(),
            )
            return None
        return record

    def verify(self, raw: bytes, sender: str) -> tuple[str, ...] | None:
        """Verify a DKIM signature on *raw* vouching for *sender*.

        Only signatures whose ``d=`` is exactly the sender's domain count,
        and only if the From field they cover is *sender*.

        Args:
            raw: The message exactly as received.
            sender: The authenticated, lowercase From address.

        Returns:
            The names of the header fields the first of those signatures
            that verifies covers, lowercase, as its ``h=`` tag lists them
            (a name may repeat), or None if none verifies.
        """
        domain = sender.rpartition("@")[2]
        # dkimpy parses the sender's message and the signer's key: any
        # failure there means the signature does not verify.
        try:
            checker = dkim.DKIM(
                raw,
                logger=_DkimpyLogger(),
                minkey=MIN_KEY_BITS,
                timeout=DNS_TIMEOUT,
            )
        except Exception as e:
            logger.warning("DKIM: cannot read message: %.200s", e)
            return None
        if not self._within_bounds(raw, checker):
            return None
        # The same for every signature, and needs no DNS.
        if _signed_sender(checker.headers) != sender:
            logger.warning(
                "DKIM: the message's From is not %s as dkimpy reads it", sender
            )
            return None

        signatures = [
            value
            for name, value in checker.headers
            if name.lower() == b"dkim-signature"
        ]
        tried = 0
        for index, signature in enumerate(signatures):
            try:
                tags = _signature_tags(signature, domain)
            except _UnsuitableError as e:
                logger.debug("DKIM: skipping signature %d: %s", index, e)
                continue
            if tried == MAX_SIGNATURES:
                break
            tried += 1
            key_type = _KEY_TYPES[tags[b"a"]]
            dnsfunc = functools.partial(self._lookup_key, key_type=key_type)
            try:
                verified = checker.verify(idx=index, dnsfunc=dnsfunc)
            except Exception as e:
                logger.debug("DKIM: signature %d failed: %.200s", index, e)
                continue
            if verified:
                logger.debug("DKIM: signature %d by %s verified", index, domain)
                return _signed_fields(tags)
        logger.warning(
            "DKIM: no signature by %s for %s verified (%d of %d tried)",
            domain,
            sender,
            tried,
            len(signatures),
        )
        return None

    @staticmethod
    def _within_bounds(raw: bytes, checker: dkim.DKIM) -> bool:
        """Whether verifying the message *raw* takes bounded work."""
        if len(checker.headers) > MAX_HEADER_FIELDS:
            logger.warning(
                "DKIM: message has %d header fields (limit %d)",
                len(checker.headers),
                MAX_HEADER_FIELDS,
            )
            return False
        if _whitespace_cost(raw) > MAX_WHITESPACE_COST:
            logger.warning(
                "DKIM: message has runs of whitespace too costly to "
                "canonicalize"
            )
            return False
        return True
