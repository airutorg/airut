# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/update_lock.py."""

import os
from pathlib import Path

import pytest

from lib.update_lock import UpdateLock, UpdateLockBusyError


class TestUpdateLock:
    """Tests for UpdateLock class."""

    def test_try_acquire_creates_lock_file(self, tmp_path: Path) -> None:
        """Test try_acquire creates lock file if it doesn't exist."""
        lock_path = tmp_path / ".update.lock"
        lock = UpdateLock(lock_path)

        assert not lock_path.exists()
        assert lock.try_acquire()
        assert lock_path.exists()

        lock.release()

    def test_try_acquire_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Test try_acquire creates parent directories if needed."""
        lock_path = tmp_path / "nested" / "dir" / ".update.lock"
        lock = UpdateLock(lock_path)

        assert not lock_path.parent.exists()
        assert lock.try_acquire()
        assert lock_path.exists()

        lock.release()

    def test_try_acquire_returns_true_when_already_held(
        self, tmp_path: Path
    ) -> None:
        """Test try_acquire returns True if already holding lock."""
        lock_path = tmp_path / ".update.lock"
        lock = UpdateLock(lock_path)

        assert lock.try_acquire()
        assert lock.try_acquire()  # Should return True again

        lock.release()

    def test_try_acquire_blocks_second_process(self, tmp_path: Path) -> None:
        """Test try_acquire fails if lock held by another fd."""
        lock_path = tmp_path / ".update.lock"
        lock1 = UpdateLock(lock_path)
        lock2 = UpdateLock(lock_path)

        assert lock1.try_acquire()
        assert not lock2.try_acquire()  # Should fail

        lock1.release()
        assert lock2.try_acquire()  # Now should succeed

        lock2.release()

    def test_release_when_not_held(self, tmp_path: Path) -> None:
        """Test release is safe to call when not holding lock."""
        lock_path = tmp_path / ".update.lock"
        lock = UpdateLock(lock_path)

        # Should not raise
        lock.release()
        lock.release()

    def test_release_allows_another_acquire(self, tmp_path: Path) -> None:
        """Test release allows another lock to acquire."""
        lock_path = tmp_path / ".update.lock"
        lock1 = UpdateLock(lock_path)
        lock2 = UpdateLock(lock_path)

        assert lock1.try_acquire()
        lock1.release()

        assert lock2.try_acquire()
        lock2.release()

    def test_is_held_returns_correct_state(self, tmp_path: Path) -> None:
        """Test is_held returns correct state."""
        lock_path = tmp_path / ".update.lock"
        lock = UpdateLock(lock_path)

        assert not lock.is_held()

        lock.try_acquire()
        assert lock.is_held()

        lock.release()
        assert not lock.is_held()

    def test_context_manager_acquires_releases(self, tmp_path: Path) -> None:
        """Test context manager acquires on enter and releases on exit."""
        lock_path = tmp_path / ".update.lock"
        lock = UpdateLock(lock_path)

        assert not lock.is_held()

        with lock:
            assert lock.is_held()

        assert not lock.is_held()

    def test_context_manager_raises_when_busy(self, tmp_path: Path) -> None:
        """Test context manager raises UpdateLockBusyError when lock held."""
        lock_path = tmp_path / ".update.lock"
        lock1 = UpdateLock(lock_path)
        lock2 = UpdateLock(lock_path)

        with lock1:
            with pytest.raises(UpdateLockBusyError, match="Lock is held"):
                with lock2:
                    pass  # Should not reach here

    def test_context_manager_releases_on_error(self, tmp_path: Path) -> None:
        """Test context manager releases lock even if exception raised."""
        lock_path = tmp_path / ".update.lock"
        lock = UpdateLock(lock_path)

        with pytest.raises(ValueError):
            with lock:
                assert lock.is_held()
                raise ValueError("test error")

        assert not lock.is_held()

    def test_destructor_releases_lock(self, tmp_path: Path) -> None:
        """Test destructor releases lock if still held."""
        lock_path = tmp_path / ".update.lock"
        lock1 = UpdateLock(lock_path)

        lock1.try_acquire()
        fd = lock1._fd  # Save fd for verification

        # Delete the lock object
        del lock1

        # Verify fd is closed (will raise if already closed)
        with pytest.raises(OSError):
            os.fstat(fd)  # type: ignore[arg-type]

        # New lock should be able to acquire
        lock2 = UpdateLock(lock_path)
        assert lock2.try_acquire()
        lock2.release()

    def test_lock_file_deleted_while_held(self, tmp_path: Path) -> None:
        """Test behavior when lock file is deleted while held.

        When the lock file is deleted and a new one created, the new file
        is a different inode, so locks are independent. This is expected
        Unix file locking behavior.
        """
        lock_path = tmp_path / ".update.lock"
        lock1 = UpdateLock(lock_path)
        lock2 = UpdateLock(lock_path)

        assert lock1.try_acquire()
        assert lock_path.exists()

        # Delete the lock file
        lock_path.unlink()
        assert not lock_path.exists()

        # Lock2 creates a new file (different inode) so can acquire
        # This is expected behavior - new file is independent
        assert lock2.try_acquire()

        # Both locks are valid (on different inodes)
        assert lock1.is_held()
        assert lock2.is_held()

        lock1.release()
        lock2.release()

    def test_lock_path_attribute(self, tmp_path: Path) -> None:
        """Test lock_path attribute is accessible."""
        lock_path = tmp_path / ".update.lock"
        lock = UpdateLock(lock_path)

        assert lock.lock_path == lock_path
