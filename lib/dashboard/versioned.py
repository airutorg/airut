# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Thread-safe versioned state containers for the dashboard.

Provides a global version clock and generic versioned store that
ensure atomic reads, monotonic version numbers, and condition-based
notification for SSE endpoints.
"""

import threading
import time
from dataclasses import dataclass


class VersionClock:
    """Global monotonic version counter.

    Every state mutation in the system ticks this clock. SSE endpoints
    wait on it and wake when any state changes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._version: int = 0

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def tick(self) -> int:
        """Increment version and notify all waiters.

        Returns new version.
        """
        with self._condition:
            self._version += 1
            self._condition.notify_all()
            return self._version

    def wait(self, known: int, timeout: float = 30.0) -> int | None:
        """Block until version > known, or timeout.

        Returns new version or None on timeout.

        Handles server restart: if known > current version, the client
        has a version from a previous server lifetime. Return immediately
        so the client resets to current state.
        """
        with self._condition:
            # Restart detection: client has a version from a previous
            # server lifetime. Return current version immediately so
            # the client gets a full state reset.
            if known > self._version:
                return self._version

            deadline = time.monotonic() + timeout
            while self._version <= known:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(timeout=remaining)
            return self._version


@dataclass(frozen=True)
class Versioned[T]:
    """A value paired with its version number."""

    version: int
    value: T


class VersionedStore[T]:
    """Thread-safe versioned state container.

    Values must be immutable (frozen dataclasses, tuples, etc.).
    Each update increments the shared VersionClock.

    Thread safety note: ``get()`` and ``update()`` are individually atomic,
    but read-modify-write sequences (get → transform → update) are NOT.
    If multiple threads may write concurrently, callers must synchronize
    externally. In practice, the gateway uses a single-writer pattern
    where only the boot/main thread mutates stores.
    """

    def __init__(self, initial: T, clock: VersionClock) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self._version: int = 0
        self._value: T = initial

    def get(self) -> Versioned[T]:
        """Atomic read of current value + version."""
        with self._lock:
            return Versioned(self._version, self._value)

    def update(self, new_value: T) -> int:
        """Replace value, tick clock, return new version."""
        with self._lock:
            version = self._clock.tick()
            self._version = version
            self._value = new_value
            return version
