# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email sender authentication.

``SenderAuthenticator`` verifies the email actually came from who it
claims, via DMARC on trusted Authentication-Results headers and a DKIM
signature by the From domain.  Whether that sender may use the gateway
is the separate authorization layer (``authorization``).

Security model:
- Only the **first** (topmost) ``Authentication-Results`` header is
  considered.  The receiving MTA prepends its header at the top
  (RFC 8601 §5).  If the first header is not from the configured
  ``trusted_authserv_id``, the message is rejected — lower headers are
  never consulted, even if they have a matching authserv-id.
- When ``trusted_authserv_id`` is empty, the authserv-id check is skipped
  (for Microsoft 365 / EOP which omits it from the header).
- DMARC pass is required (SPF alone is insufficient because SPF does not
  validate the From header, only the envelope sender).  The header is
  parsed per RFC 8601 (``authres``), never searched: values in it come
  from the sender and may contain any text, including ``dmarc=pass``.
  It must hold exactly one ``dmarc`` entry, with result ``pass`` and a
  ``header.from`` equal to the From address's domain.
- When ``allow_internal_auth_fallback`` is enabled and no
  ``Authentication-Results`` header exists, the message is accepted if
  ``X-MS-Exchange-Organization-AuthAs: Internal`` is present.  This
  covers intra-org email in Microsoft 365 where EOP skips external
  authentication entirely.
- The From header is read strictly (``from_header``): it must hold
  exactly one mailbox, written plainly, and is rejected unread when
  overly long or deeply nested.
"""

import logging
from email.message import Message

from airut.gateway.config import DKIM_VERIFICATION_MODES
from airut.gateway.email.authres import (
    AuthResults,
    AuthResultsParseError,
    ascii_lower,
    parse_authentication_results,
)
from airut.gateway.email.dkim import DkimVerifier, server_dkim_passes
from airut.gateway.email.from_header import parse_from_mailbox
from airut.gateway.email.incoming import IncomingEmail


logger = logging.getLogger(__name__)


class SecurityValidationError(Exception):
    """Raised when security validation fails."""


class SenderAuthenticator:
    """Verifies email authenticity via DMARC and DKIM.

    Checks only the **first** (topmost) ``Authentication-Results`` header.
    If it is not from the configured trusted mail server, the message is
    rejected without examining lower headers.  This confirms the From
    header domain is authentic (not spoofed).

    When ``allow_internal_auth_fallback`` is enabled and the message has
    **no** ``Authentication-Results`` header at all, the authenticator
    accepts the message if the ``X-MS-Exchange-Organization-AuthAs``
    header is ``Internal``.  This covers intra-org email in Microsoft 365
    where Exchange Online Protection skips external authentication
    entirely for messages sent within the same tenant.

    After DMARC, a DKIM signature by the From domain must be valid, as
    ``dkim_verification`` says: in the server's recorded results
    (``server``), by Airut's own verification (``airut``), by both
    (``both``), or not required (``none``).  The internal-auth fallback
    involves no DKIM: it trusts Exchange.

    Authentication takes two steps, both of which must pass:
    ``authenticate`` reads the message's headers, including the server's
    recorded results, and needs no network; ``verified_headers`` is
    Airut's own DKIM verification, which looks up keys in DNS, and
    returns the header fields the signature covers: callers act on
    those alone.  Callers check authorization between the two steps,
    so that messages from senders who are not allowed anyway cause no
    lookups.

    A message whose header section parsers may read differently is
    rejected (see ``IncomingEmail.header_section_problem``): they could
    disagree on which header fields the message has, or on its body.

    Attributes:
        trusted_authserv_id: Hostname of the trusted mail server whose
            Authentication-Results headers are accepted.
        dkim_verification: Who must find a DKIM signature by the From
            domain valid (one of ``DKIM_VERIFICATION_MODES``).
        allow_internal_auth_fallback: Accept
            ``X-MS-Exchange-Organization-AuthAs: Internal`` when no
            ``Authentication-Results`` header is present.
    """

    def __init__(
        self,
        trusted_authserv_id: str,
        *,
        dkim_verification: str,
        dkim_verifier: DkimVerifier | None = None,
        allow_internal_auth_fallback: bool = False,
    ) -> None:
        """Initialize authenticator.

        Args:
            trusted_authserv_id: The authserv-id to trust in
                Authentication-Results headers.
            dkim_verification: ``both``, ``server``, ``airut`` or
                ``none``.
            dkim_verifier: Verifies signatures for ``airut`` and
                ``both`` (by default, with the host's resolver).
            allow_internal_auth_fallback: When True, accept messages
                with ``X-MS-Exchange-Organization-AuthAs: Internal``
                as authenticated when no ``Authentication-Results``
                header is present.

        Raises:
            ValueError: If *dkim_verification* is not a known mode.
        """
        if dkim_verification not in DKIM_VERIFICATION_MODES:
            raise ValueError(
                f"Unknown dkim_verification: {dkim_verification!r}"
            )
        self.trusted_authserv_id = trusted_authserv_id
        self.dkim_verification = dkim_verification
        self._dkim_verifier = dkim_verifier or DkimVerifier()
        self.allow_internal_auth_fallback = allow_internal_auth_fallback
        logger.debug(
            "Initialized sender authenticator (authserv-id: %s, "
            "dkim_verification: %s, internal_auth_fallback: %s)",
            trusted_authserv_id,
            dkim_verification,
            allow_internal_auth_fallback,
        )

    @property
    def _server_dkim_required(self) -> bool:
        """Whether the server's recorded DKIM result must pass."""
        return self.dkim_verification in ("server", "both")

    @property
    def _own_dkim_required(self) -> bool:
        """Whether Airut must verify the DKIM signature itself."""
        return self.dkim_verification in ("airut", "both")

    def authenticate(self, email: IncomingEmail) -> str | None:
        """Check the message's headers; return the From address if they pass.

        The first step of authentication, needing no network: rejects a
        header section parsers may read differently, extracts the From
        address using strict parsing, and verifies a DMARC pass for its
        domain in the trusted Authentication-Results header, and — when
        ``dkim_verification`` is ``server`` or ``both`` — the server's
        recorded DKIM pass.  Airut's own DKIM verification is the second
        step, ``verified_headers``: a message is authenticated only when
        both pass.

        When ``allow_internal_auth_fallback`` is enabled and there is no
        ``Authentication-Results`` header at all, the message is accepted
        if ``X-MS-Exchange-Organization-AuthAs: Internal`` is present.

        Args:
            email: The email to authenticate.

        Returns:
            Lowercase email address if the header checks pass, None
            otherwise.
        """
        problem = email.header_section_problem()
        if problem is not None:
            logger.warning(
                "Rejecting message whose header section holds %s", problem
            )
            return None

        message = email.message
        # A second From field is an ambiguous header section (above).
        field = message.get("From")
        if field is None:
            logger.warning("Rejecting message with no From header")
            return None

        # str(): an undecodable 8-bit header is a Header object.
        from_value = str(field)
        sender = parse_from_mailbox(from_value)

        if sender is None:
            logger.warning(
                "Rejecting From header that is not a single valid "
                "mailbox: %.100s",
                from_value,
            )
            return None

        domain = sender.rpartition("@")[2]
        results = self._trusted_results(message)
        if results is None:
            if not self._verify_internal_auth(message):
                return None
        elif not self._verify_dmarc(results, domain):
            return None
        elif self._server_dkim_required and not server_dkim_passes(
            results, domain
        ):
            return None

        logger.debug("Sender authenticated: %s", sender)
        return sender

    def verified_headers(
        self, email: IncomingEmail, sender: str
    ) -> Message | None:
        """Verify, in Airut, a DKIM signature vouching for *sender*.

        The second step of authentication, for a message ``authenticate``
        accepted as from *sender*.  Returns the header fields Airut may
        act on: those the verified signature covers, since the others
        may have been added or changed after signing.  Passes without
        checking, returning every field, when ``dkim_verification`` needs
        no verification by Airut, and for messages accepted through the
        internal-auth fallback (which have no ``Authentication-Results``
        header).  Either way the fields come without the body, which
        callers read from the message itself.

        Args:
            email: The email ``authenticate`` accepted.
            sender: The address it returned.

        Returns:
            The header fields to act on (a message with no body), or None
            if no signature verifies.
        """
        if not self._own_dkim_required:
            return email.headers()
        if self.allow_internal_auth_fallback and not email.message.get_all(
            "Authentication-Results"
        ):
            return email.headers()
        fields = self._dkim_verifier.verify(email.raw, sender)
        if fields is None:
            return None
        headers = email.signed_headers(fields)
        unsigned = {name.lower() for name in email.message.keys()} - {
            name.lower() for name in headers.keys()
        }
        logger.debug(
            "DKIM: acting only on signed header fields; not signed: %s",
            ", ".join(sorted(unsigned)) or "(none)",
        )
        return headers

    def _verify_dmarc(self, results: AuthResults, from_domain: str) -> bool:
        """Verify DMARC pass for *from_domain* in the trusted header.

        Requires exactly one ``dmarc`` entry in the first
        ``Authentication-Results`` header (see ``_trusted_results``),
        with result ``pass`` and a ``header.from`` equal to
        *from_domain*.  A second ``dmarc`` entry means the header is not
        what it seems (one may have been injected through a value the
        server failed to quote), so it is rejected rather than resolved.

        SPF alone is not sufficient because SPF validates the envelope
        sender (Return-Path), not the From header — an attacker can pass
        SPF with their own domain while spoofing the From header.

        Args:
            results: The trusted header, parsed.
            from_domain: Lowercase domain of the From address.

        Returns:
            True if the trusted header records a DMARC pass for
            *from_domain*.
        """
        authserv_id = results.authserv_id or "(not checked)"
        dmarc = [r for r in results.results if r.method == "dmarc"]
        if len(dmarc) != 1:
            logger.warning(
                "DMARC verification failed: %d dmarc entries in first "
                "Authentication-Results header (authserv-id: %.100s)",
                len(dmarc),
                authserv_id,
            )
            return False

        entry = dmarc[0]
        header_from = [ascii_lower(d) for d in entry.values("header.from")]
        if entry.result != "pass" or header_from != [from_domain]:
            logger.warning(
                "DMARC verification failed (authserv-id: %.100s): "
                "dmarc=%.100s header.from=%.200s, From domain %s",
                authserv_id,
                entry.result,
                ",".join(header_from) or "(missing)",
                from_domain,
            )
            return False

        logger.debug(
            "DMARC verification passed (authserv-id: %.100s)", authserv_id
        )
        return True

    def _trusted_results(self, message: Message) -> AuthResults | None:
        """Parse the first ``Authentication-Results`` header, if trusted.

        Only considers the **first** (topmost) ``Authentication-Results``
        header, period.  The receiving MTA prepends its header at the top
        (RFC 8601 §5), so the first header is always from our MTA.  If the
        first header's authserv-id does not match the configured trusted
        server, the message is rejected — we do not search lower headers.

        This prevents an attacker from injecting a forged header (with a
        matching authserv-id and ``dmarc=pass``) below legitimate headers
        from other servers.

        When ``trusted_authserv_id`` is empty, the authserv-id check is
        skipped.  This supports Microsoft 365 / EOP which omits the
        authserv-id from the ``Authentication-Results`` header (an
        RFC 8601 violation).  Security relies on the first-header-only
        policy — the MTA always prepends its header at the top.

        Args:
            message: Email message.

        Returns:
            The parsed header, or None if there is none, it cannot be
            parsed, or it is not from the trusted server.
        """
        all_results = message.get_all("Authentication-Results", [])
        if not all_results:
            logger.warning("No Authentication-Results header found")
            return None

        # Only examine the first (topmost) Authentication-Results header.
        header = str(all_results[0])
        try:
            results = parse_authentication_results(header)
        except AuthResultsParseError as e:
            logger.warning(
                "First Authentication-Results header is malformed "
                "(%.100s): %.500s",
                e,
                header.strip(),
            )
            return None

        # When trusted_authserv_id is empty, skip the authserv-id check.
        # This supports Microsoft 365 / EOP which omits the authserv-id
        # from Authentication-Results headers (non-standard).
        trusted_id = ascii_lower(self.trusted_authserv_id)
        if not trusted_id:
            logger.debug(
                "Skipping authserv-id check (trusted_authserv_id is empty)"
            )
            return results

        authserv_id = ascii_lower(results.authserv_id or "")
        if authserv_id != trusted_id:
            logger.warning(
                "First Authentication-Results header is from untrusted "
                "server %.100s (expected %s): %.500s",
                authserv_id or "(none)",
                trusted_id,
                header.strip(),
            )
            return None
        return results

    def _verify_internal_auth(self, message: Message) -> bool:
        """Fall back to Microsoft internal authentication header.

        When ``allow_internal_auth_fallback`` is enabled and the message
        has **no** ``Authentication-Results`` header, checks for the
        ``X-MS-Exchange-Organization-AuthAs: Internal`` header.

        Microsoft 365 / Exchange Online does not generate
        ``Authentication-Results`` for messages sent within the same
        tenant (intra-org mail).  Instead, it stamps the message with
        ``X-MS-Exchange-Organization-AuthAs: Internal``.

        This fallback only activates when there are **no**
        ``Authentication-Results`` headers at all.  If any such header
        exists (even with a DMARC failure), this fallback does not apply
        — DMARC is the authoritative mechanism.

        Reference:
            https://techcommunity.microsoft.com/blog/exchange/
            demystifying-and-troubleshooting-hybrid-mail-flow-
            when-is-a-message-internal/1420838

        Args:
            message: Email message.

        Returns:
            True if the internal auth fallback is enabled and the
            message is authenticated as internal Microsoft mail.
        """
        if not self.allow_internal_auth_fallback:
            return False

        # Only fall back when there are NO Authentication-Results headers.
        all_results: list[str] = message.get_all("Authentication-Results", [])
        if all_results:
            return False

        header = message.get("X-MS-Exchange-Organization-AuthAs")
        if header is None:
            logger.warning(
                "No Authentication-Results header and no "
                "X-MS-Exchange-Organization-AuthAs header found"
            )
            return False

        # str(): an undecodable 8-bit header is a Header object.
        auth_as = str(header).strip()
        if auth_as.lower() == "internal":
            logger.debug(
                "Sender authenticated via "
                "X-MS-Exchange-Organization-AuthAs: Internal"
            )
            return True

        logger.warning(
            "X-MS-Exchange-Organization-AuthAs is %.100r (expected Internal)",
            auth_as,
        )
        return False
