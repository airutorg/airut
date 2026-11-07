# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email authentication and authorization.

Provides two logically separate layers:

- **Authentication** (``SenderAuthenticator``): Verifies the email actually
  came from who it claims via DMARC validation on trusted
  Authentication-Results headers.
- **Authorization** (``SenderAuthorizer``): Checks whether the authenticated
  sender is allowed to use the gateway.

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

from airut.gateway.email.authres import (
    AuthResults,
    AuthResultsParseError,
    parse_authentication_results,
)
from airut.gateway.email.from_header import parse_from_mailbox


logger = logging.getLogger(__name__)


def _ascii_lower(value: str) -> str:
    """Lowercase *value* if it is ASCII; leave it unchanged otherwise.

    Hostnames are compared case-insensitively, but ``str.lower`` also
    folds some non-ASCII characters onto ASCII ones (the Kelvin sign
    becomes ``k``), so such a value must never match an ASCII one.
    """
    return value.lower() if value.isascii() else value


class SecurityValidationError(Exception):
    """Raised when security validation fails."""


class SenderAuthenticator:
    """Verifies email authenticity via DMARC.

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

    Attributes:
        trusted_authserv_id: Hostname of the trusted mail server whose
            Authentication-Results headers are accepted.
        allow_internal_auth_fallback: Accept
            ``X-MS-Exchange-Organization-AuthAs: Internal`` when no
            ``Authentication-Results`` header is present.
    """

    def __init__(
        self,
        trusted_authserv_id: str,
        *,
        allow_internal_auth_fallback: bool = False,
    ) -> None:
        """Initialize authenticator.

        Args:
            trusted_authserv_id: The authserv-id to trust in
                Authentication-Results headers.
            allow_internal_auth_fallback: When True, accept messages
                with ``X-MS-Exchange-Organization-AuthAs: Internal``
                as authenticated when no ``Authentication-Results``
                header is present.
        """
        self.trusted_authserv_id = trusted_authserv_id
        self.allow_internal_auth_fallback = allow_internal_auth_fallback
        logger.debug(
            "Initialized sender authenticator (authserv-id: %s, "
            "internal_auth_fallback: %s)",
            trusted_authserv_id,
            allow_internal_auth_fallback,
        )

    def authenticate(self, message: Message) -> str | None:
        """Authenticate the sender via DMARC and return the From address.

        Extracts the From address using strict parsing, then verifies
        a DMARC pass for its domain in the trusted Authentication-Results
        header.

        When ``allow_internal_auth_fallback`` is enabled and there is no
        ``Authentication-Results`` header at all, the message is accepted
        if ``X-MS-Exchange-Organization-AuthAs: Internal`` is present.

        Args:
            message: Email message to authenticate.

        Returns:
            Lowercase email address if authentication succeeds, None
            otherwise.
        """
        from_values = [str(v) for v in message.get_all("From", [])]
        if len(from_values) != 1:
            logger.warning(
                "Rejecting message with %d From headers (expected 1)",
                len(from_values),
            )
            return None

        sender = parse_from_mailbox(from_values[0])

        if sender is None:
            logger.warning(
                "Rejecting From header that is not a single valid "
                "mailbox: %.100s",
                from_values[0],
            )
            return None

        domain = sender.rpartition("@")[2]
        if not self._verify_dmarc(message, domain):
            if not self._verify_internal_auth(message):
                return None

        logger.debug("Sender authenticated: %s", sender)
        return sender

    def _verify_dmarc(self, message: Message, from_domain: str) -> bool:
        """Verify DMARC pass for *from_domain* in the trusted header.

        Reads the first ``Authentication-Results`` header (see
        ``_trusted_results``) and requires exactly one ``dmarc`` entry,
        with result ``pass`` and a ``header.from`` equal to
        *from_domain*.  A second ``dmarc`` entry means the header is not
        what it seems (one may have been injected through a value the
        server failed to quote), so it is rejected rather than resolved.

        SPF alone is not sufficient because SPF validates the envelope
        sender (Return-Path), not the From header — an attacker can pass
        SPF with their own domain while spoofing the From header.

        Args:
            message: Email message.
            from_domain: Lowercase domain of the From address.

        Returns:
            True if the trusted header records a DMARC pass for
            *from_domain*.
        """
        results = self._trusted_results(message)
        if results is None:
            return False

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
        header_from = [_ascii_lower(d) for d in entry.values("header.from")]
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
        trusted_id = _ascii_lower(self.trusted_authserv_id)
        if not trusted_id:
            logger.debug(
                "Skipping authserv-id check (trusted_authserv_id is empty)"
            )
            return results

        authserv_id = _ascii_lower(results.authserv_id or "")
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


class SenderAuthorizer:
    """Checks whether an authenticated sender is allowed.

    Supports a list of authorized sender patterns:
    - Exact email addresses: ``user@example.com``
    - Domain wildcards: ``*@example.com`` (matches any user at that domain)

    All comparisons are case-insensitive.

    Attributes:
        patterns: List of lowercase (pattern, is_wildcard) tuples; a
            wildcard's pattern is its domain.
    """

    def __init__(self, authorized_senders: list[str]) -> None:
        """Initialize authorizer.

        Args:
            authorized_senders: List of email patterns allowed to send
                commands.  Supports wildcards like ``*@domain.com``.
        """
        self.patterns: list[tuple[str, bool]] = []
        for pattern in authorized_senders:
            lower = pattern.lower()
            if lower.startswith("*@"):
                # Domain wildcard: store the domain (e.g., "example.com")
                self.patterns.append((lower[2:], True))
            else:
                # Exact match
                self.patterns.append((lower, False))
        logger.debug(
            "Initialized sender authorizer for %d patterns: %s",
            len(self.patterns),
            authorized_senders,
        )

    def is_authorized(self, sender: str) -> bool:
        """Check if sender is authorized.

        Args:
            sender: Lowercase email address (as returned by
                ``SenderAuthenticator.authenticate``).

        Returns:
            True if sender matches any authorized pattern.
        """
        domain = sender.rpartition("@")[2]
        for pattern, is_wildcard in self.patterns:
            if is_wildcard:
                # Domain wildcard: the sender's domain must be exactly it
                if domain == pattern:
                    logger.debug(
                        "Sender %s authorized (pattern: *@%s)", sender, pattern
                    )
                    return True
            else:
                # Exact match
                if sender == pattern:
                    logger.debug("Sender %s authorized (exact match)", sender)
                    return True

        logger.warning("Unauthorized sender: %s", sender)
        return False
