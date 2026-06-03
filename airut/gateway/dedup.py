# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Bounded deduplication of recently-seen message keys.

Channel listeners receive the same logical message more than once: Slack
delivers a single channel mention as both an ``app_mention`` and a
``message`` event, and an upstream mail server may deliver the same email
to the IMAP mailbox more than once (each copy a distinct UID sharing the
``Message-ID`` header).  :class:`SeenKeyCache` lets a listener process
each message exactly once by claiming a stable key the first time it is
seen.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Hashable


#: Default number of recently-seen keys retained for deduplication.
DEFAULT_DEDUP_CAPACITY = 256


class SeenKeyCache:
    """Thread-safe, bounded record of recently-seen keys.

    Retains the most recent ``capacity`` keys in insertion order,
    evicting the oldest when full.  Bounded so a long-running listener
    does not accumulate keys without limit; the window only needs to span
    the gap between duplicate deliveries of the same message, which is
    short in practice.
    """

    def __init__(self, capacity: int = DEFAULT_DEDUP_CAPACITY) -> None:
        """Initialize the cache.

        Args:
            capacity: Maximum number of keys to retain.
        """
        self._capacity = capacity
        self._seen: OrderedDict[Hashable, None] = OrderedDict()
        self._lock = threading.Lock()

    def claim(self, key: Hashable) -> bool:
        """Claim *key*, returning whether it was previously unseen.

        Args:
            key: A stable, hashable identifier for the message.

        Returns:
            True the first time *key* is seen and False thereafter, so a
            message delivered more than once is processed exactly once.
        """
        with self._lock:
            if key in self._seen:
                return False
            self._seen[key] = None
            if len(self._seen) > self._capacity:
                self._seen.popitem(last=False)
            return True

    def __len__(self) -> int:
        """Return the number of keys currently retained."""
        with self._lock:
            return len(self._seen)
