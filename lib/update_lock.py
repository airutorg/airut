# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Advisory file lock for coordinating service updates.

This module provides a file-based locking mechanism using fcntl.flock() to
coordinate between the email service and auto-updater. The lock automatically
releases when the process exits (normally, crashes, or is killed).

Usage:
    # In email service (acquire/release as needed):
    lock = UpdateLock(Path("/path/to/repo/.update.lock"))
    if lock.try_acquire():
        # Lock acquired, do work
        lock.release()

    # In auto-updater (context manager for safety):
    lock = UpdateLock(Path("/path/to/repo/.update.lock"))
    with lock:  # Raises UpdateLockBusyError if lock held
        apply_update()
"""

from __future__ import annotations

import fcntl
import logging
import os
from pathlib import Path
from types import TracebackType


logger = logging.getLogger(__name__)


class UpdateLockBusyError(Exception):
    """Raised when the update lock is held by another process."""


class UpdateLock:
    """Advisory file lock for coordinating service updates.

    Uses fcntl.flock() for OS-level advisory locking. The lock is automatically
    released when:
    - release() is called explicitly
    - The context manager exits
    - The process exits (normal, crash, or SIGKILL)
    - The file descriptor is closed

    Thread safety: This class is NOT thread-safe. Each thread should use its
    own UpdateLock instance if needed.

    Attributes:
        lock_path: Path to the lock file.
    """

    def __init__(self, lock_path: Path) -> None:
        """Initialize the lock.

        Args:
            lock_path: Path to the lock file. Will be created if it doesn't
                exist.
        """
        self.lock_path = lock_path
        self._fd: int | None = None

    def try_acquire(self) -> bool:
        """Try to acquire the lock without blocking.

        Returns:
            True if the lock was acquired, False if it's held by another
            process.

        Raises:
            OSError: If the lock file cannot be created or opened.
        """
        if self._fd is not None:
            # Already holding the lock
            return True

        # Create parent directory if needed
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)

        # Open or create the lock file
        # Use O_CREAT to create if missing, O_RDWR for flock compatibility
        fd = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT,
            0o644,
        )

        try:
            # Try non-blocking exclusive lock
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fd = fd
            logger.debug("Acquired update lock: %s", self.lock_path)
            return True
        except BlockingIOError:
            # Lock is held by another process
            os.close(fd)
            logger.debug("Update lock busy: %s", self.lock_path)
            return False

    def release(self) -> None:
        """Release the lock if held.

        Safe to call even if the lock is not held.
        """
        if self._fd is None:
            return

        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            logger.debug("Released update lock: %s", self.lock_path)
        finally:
            os.close(self._fd)
            self._fd = None

    def is_held(self) -> bool:
        """Check if this instance is currently holding the lock.

        Note: This only checks if THIS instance holds the lock, not whether
        any process holds it. Use try_acquire() to check if the lock is
        available.

        Returns:
            True if this instance holds the lock.
        """
        return self._fd is not None

    def __enter__(self) -> UpdateLock:
        """Context manager entry - acquire lock or raise.

        Returns:
            Self for use in with statement.

        Raises:
            UpdateLockBusyError: If the lock is held by another process.
        """
        if not self.try_acquire():
            raise UpdateLockBusyError(f"Lock is held: {self.lock_path}")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager exit - release lock."""
        self.release()

    def __del__(self) -> None:
        """Destructor - release lock if still held."""
        self.release()
