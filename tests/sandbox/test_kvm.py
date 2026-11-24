# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/sandbox/kvm.py -- KVM device checks."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock

from airut.sandbox.kvm import (
    KVM_DEVICE,
    kvm_access_warning,
    kvm_unavailable_reason,
)


def _device(mode: int, *, uid: int | None = None) -> MagicMock:
    """Return a fake device path whose ``stat()`` reports *mode* and *uid*."""
    owner = os.getuid() + 1 if uid is None else uid
    result = os.stat_result((mode, 0, 0, 1, owner, 0, 0, 0, 0, 0))
    device = MagicMock(spec=Path)
    device.__str__.return_value = "/dev/kvm"
    device.stat.return_value = result
    return device


def _failing_device(error: OSError) -> MagicMock:
    """Return a fake device path whose ``stat()`` raises *error*."""
    device = MagicMock(spec=Path)
    device.__str__.return_value = "/dev/kvm"
    device.stat.side_effect = error
    return device


class TestKvmUnavailableReason:
    """Tests for kvm_unavailable_reason()."""

    def test_default_device(self) -> None:
        """The default device is the host's /dev/kvm."""
        assert KVM_DEVICE == Path("/dev/kvm")

    def test_missing(self, tmp_path: Path) -> None:
        """A missing device explains how to enable KVM."""
        reason = kvm_unavailable_reason(tmp_path / "kvm")

        assert reason is not None
        assert "does not exist" in reason
        assert "nested virtualization" in reason

    def test_stat_error(self) -> None:
        """Other stat errors are reported."""
        reason = kvm_unavailable_reason(
            _failing_device(PermissionError("denied"))
        )

        assert reason == "cannot stat /dev/kvm: denied"

    def test_not_character_device(self, tmp_path: Path) -> None:
        """A regular file is rejected."""
        path = tmp_path / "kvm"
        path.touch()

        reason = kvm_unavailable_reason(path)

        assert reason == f"{path} is not a character device"

    def test_character_device(self) -> None:
        """A character device is accepted regardless of permissions."""
        assert kvm_unavailable_reason(_device(stat.S_IFCHR | 0o600)) is None


class TestKvmAccessWarning:
    """Tests for kvm_access_warning()."""

    def test_world_accessible(self) -> None:
        """Mode 0666 is accessible from rootless containers."""
        assert kvm_access_warning(_device(stat.S_IFCHR | 0o666)) is None

    def test_group_only(self) -> None:
        """Group-only access warns that kvm group membership is dropped."""
        warning = kvm_access_warning(_device(stat.S_IFCHR | 0o660))

        assert warning is not None
        assert "mode 0660" in warning
        assert "kvm group membership is dropped" in warning

    def test_read_only_for_others(self) -> None:
        """Read access alone is not enough."""
        assert kvm_access_warning(_device(stat.S_IFCHR | 0o664)) is not None

    def test_owned_by_current_user(self) -> None:
        """Owner permission bits apply when the current user owns it."""
        device = _device(stat.S_IFCHR | 0o600, uid=os.getuid())

        assert kvm_access_warning(device) is None

    def test_owned_by_current_user_without_write(self) -> None:
        """An owner without write permission gets a warning."""
        device = _device(stat.S_IFCHR | 0o466, uid=os.getuid())

        assert kvm_access_warning(device) is not None

    def test_stat_error(self) -> None:
        """Stat errors are reported as warnings."""
        warning = kvm_access_warning(_failing_device(OSError("gone")))

        assert warning == "cannot stat /dev/kvm: gone"
