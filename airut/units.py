# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Byte sizes."""

#: Bytes in one MB, the unit of size settings in the server config.
MB = 1024 * 1024


def format_size(size: int) -> str:
    """Format a byte count for messages shown to users.

    Units are binary (1KB = 1024 bytes), matching the size settings in
    the server config.

    Args:
        size: Size in bytes.

    Returns:
        The size as ``B``, ``KB`` or ``MB``, e.g. ``"2.5MB"``.
    """
    if size >= MB:
        return f"{size / MB:.1f}MB"
    if size >= 1024:
        return f"{size / 1024:.0f}KB"
    return f"{size}B"
