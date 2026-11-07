# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email sender authorization.

``SenderAuthorizer`` checks whether a sender, already authenticated by
``security.SenderAuthenticator``, is allowed to use the gateway.
"""

import logging


logger = logging.getLogger(__name__)


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
