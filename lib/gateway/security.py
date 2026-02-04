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
- Only Authentication-Results headers from the configured
  ``trusted_authserv_id`` are considered (prevents header injection by
  upstream relays or attackers).
- DMARC pass is required (SPF alone is insufficient because SPF does not
  validate the From header, only the envelope sender).
- From header is parsed with strict validation, not the permissive
  ``email.utils.parseaddr``.
"""

import logging
import re
from email.message import Message


logger = logging.getLogger(__name__)

# Match "dmarc=pass" as a whole token — not as a substring of longer values
# like "dmarc=passthrough".  The value must be followed by a word boundary
# (whitespace, semicolon, parenthesis, end-of-string).
_DMARC_PASS_RE = re.compile(r"(?:^|[\s;])dmarc=pass(?=[\s;(]|$)", re.IGNORECASE)

# RFC 5322 addr-spec: simple but strict pattern for email addresses.
# Rejects display names, multiple angle brackets, and other tricks.
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+$")


def _extract_email(from_header: str) -> str | None:
    """Extract email address from a From header value.

    Handles two formats:
    - Bare email: ``user@example.com``
    - Display name with angle brackets: ``Name <user@example.com>``

    Returns None if the header is malformed or contains multiple angle
    bracket pairs (a common injection technique).

    Args:
        from_header: Raw From header value.

    Returns:
        Lowercase email address, or None if parsing fails.
    """
    value = from_header.strip()
    if not value:
        return None

    # If angle brackets present, extract content between the LAST < and >
    if "<" in value or ">" in value:
        # Reject multiple < or > (injection attempt)
        if value.count("<") != 1 or value.count(">") != 1:
            return None
        lt = value.index("<")
        gt = value.index(">")
        if gt <= lt:
            return None
        addr = value[lt + 1 : gt].strip()
    else:
        addr = value.strip()

    if not addr:
        return None

    # Validate the extracted address looks like a real email
    if not _EMAIL_RE.match(addr):
        return None

    return addr.lower()


class SecurityValidationError(Exception):
    """Raised when security validation fails."""


class SenderAuthenticator:
    """Verifies email authenticity via DMARC.

    Checks that the email's Authentication-Results header from a trusted
    mail server reports ``dmarc=pass``.  This confirms the From header
    domain is authentic (not spoofed).

    Attributes:
        trusted_authserv_id: Hostname of the trusted mail server whose
            Authentication-Results headers are accepted.
    """

    def __init__(self, trusted_authserv_id: str) -> None:
        """Initialize authenticator.

        Args:
            trusted_authserv_id: The authserv-id to trust in
                Authentication-Results headers.
        """
        self.trusted_authserv_id = trusted_authserv_id
        logger.debug(
            "Initialized sender authenticator (authserv-id: %s)",
            trusted_authserv_id,
        )

    def authenticate(self, message: Message) -> str | None:
        """Authenticate the sender via DMARC and return the From address.

        Verifies DMARC pass from a trusted Authentication-Results header,
        then extracts and returns the From address using strict parsing.

        Args:
            message: Email message to authenticate.

        Returns:
            Lowercase email address if authentication succeeds, None
            otherwise.
        """
        from_values: list[str] = message.get_all("From", [])  # type: ignore[assignment]
        if len(from_values) != 1:
            logger.warning(
                "Rejecting message with %d From headers (expected 1)",
                len(from_values),
            )
            return None

        sender = _extract_email(from_values[0])

        if sender is None:
            logger.warning(
                "Could not parse From header: %s", from_values[0][:100]
            )
            return None

        if not self._verify_dmarc(message):
            return None

        logger.debug("Sender authenticated: %s", sender)
        return sender

    def _verify_dmarc(self, message: Message) -> bool:
        """Verify DMARC pass in Authentication-Results from trusted server.

        Only considers headers where the authserv-id matches the configured
        trusted server.  SPF alone is not sufficient because SPF validates
        the envelope sender (Return-Path), not the From header — an attacker
        can pass SPF with their own domain while spoofing the From header.

        Args:
            message: Email message.

        Returns:
            True if DMARC passes on a trusted Authentication-Results header.
        """
        all_results: list[str] = message.get_all("Authentication-Results", [])  # type: ignore[assignment]

        if not all_results:
            logger.warning("No Authentication-Results header found")
            return False

        trusted_id = self.trusted_authserv_id.lower()

        for auth_results in all_results:
            # The authserv-id is the first token in the header value,
            # terminated by a semicolon.  RFC 8601 §2.2.
            header_stripped = auth_results.strip()
            semi_idx = header_stripped.find(";")
            if semi_idx < 0:
                continue
            authserv_id = header_stripped[:semi_idx].strip().lower()

            if authserv_id != trusted_id:
                logger.debug(
                    "Skipping Authentication-Results from untrusted server: %s",
                    authserv_id,
                )
                continue

            # Only accept dmarc=pass (not spf=pass alone)
            if _DMARC_PASS_RE.search(auth_results):
                logger.debug(
                    "DMARC verification passed (authserv-id: %s)", authserv_id
                )
                return True

        logger.warning(
            "DMARC verification failed (no trusted header with dmarc=pass)"
        )
        return False


class SenderAuthorizer:
    """Checks whether an authenticated sender is allowed.

    Supports a list of authorized sender patterns:
    - Exact email addresses: ``user@example.com``
    - Domain wildcards: ``*@example.com`` (matches any user at that domain)

    All comparisons are case-insensitive.

    Attributes:
        patterns: List of lowercase (pattern, is_wildcard) tuples.
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
                # Domain wildcard: store domain suffix (e.g., "@example.com")
                self.patterns.append((lower[1:], True))
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
        for pattern, is_wildcard in self.patterns:
            if is_wildcard:
                # Domain wildcard: check if sender ends with @domain
                if sender.endswith(pattern):
                    logger.debug(
                        "Sender %s authorized (pattern: *%s)", sender, pattern
                    )
                    return True
            else:
                # Exact match
                if sender == pattern:
                    logger.debug("Sender %s authorized (exact match)", sender)
                    return True

        logger.warning("Unauthorized sender: %s", sender)
        return False
