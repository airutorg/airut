# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""KVM device passthrough checks.

A sandbox task can opt into hardware virtualization by passing the host's
``/dev/kvm`` into the container (``podman run --device=/dev/kvm``).  These
helpers inspect the host device so callers can fail fast with a clear
message instead of letting tools inside the container silently fall back
to slow software emulation.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


#: Host path of the KVM device passed into containers.
KVM_DEVICE = Path("/dev/kvm")


def kvm_unavailable_reason(device: Path = KVM_DEVICE) -> str | None:
    """Return why the KVM device cannot be passed through, or None.

    Only checks that the device exists and is a character device.  Use
    ``kvm_access_warning()`` for the (heuristic) permission check.

    Args:
        device: Device path to inspect.

    Returns:
        Human-readable reason, or None when the device is present.
    """
    try:
        st = device.stat()
    except FileNotFoundError:
        return (
            f"{device} does not exist: KVM is not available on this host "
            "(load the kvm_intel or kvm_amd module; on a virtual machine "
            "host, enable nested virtualization in the hypervisor)"
        )
    except OSError as e:
        return f"cannot stat {device}: {e}"
    if not stat.S_ISCHR(st.st_mode):
        return f"{device} is not a character device"
    return None


def kvm_access_warning(device: Path = KVM_DEVICE) -> str | None:
    """Return a warning if a rootless container likely cannot open KVM.

    Rootless podman drops the host user's supplementary groups inside the
    container, so membership in the ``kvm`` group does not grant access.
    The device must be readable and writable by the user running Airut
    through its owner or "other" permission bits.  This is a heuristic,
    hence a warning rather than an error: POSIX ACL entries and group
    bits for the user's primary group also grant access but are not
    inspected, and owner bits do not apply if the image runs as a
    non-root ``USER``.

    Args:
        device: Device path to inspect (must exist).

    Returns:
        Human-readable warning, or None when access looks fine.
    """
    try:
        st = device.stat()
    except OSError as e:
        return f"cannot stat {device}: {e}"
    if st.st_uid == os.getuid():
        needed = stat.S_IRUSR | stat.S_IWUSR
    else:
        needed = stat.S_IROTH | stat.S_IWOTH
    if st.st_mode & needed == needed:
        return None
    mode = stat.S_IMODE(st.st_mode)
    return (
        f"{device} has mode {mode:04o}, which rootless containers "
        "likely cannot open: kvm group membership is dropped inside "
        "the container, so the device must be readable and writable by "
        "all users (mode 0666)"
    )
