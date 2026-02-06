# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""System DNS resolver detection.

Reads the host's ``/etc/resolv.conf`` to discover the first configured
nameserver.  Used as a fallback when the operator does not explicitly set
``network.upstream_dns`` in the server config.
"""

from __future__ import annotations

import logging
from pathlib import Path


log = logging.getLogger(__name__)

_RESOLV_CONF = Path("/etc/resolv.conf")


class SystemResolverError(Exception):
    """Raised when the system DNS resolver cannot be determined."""


def get_system_resolver(
    resolv_conf: Path = _RESOLV_CONF,
) -> str:
    """Return the first nameserver from *resolv_conf*.

    Args:
        resolv_conf: Path to the resolv.conf file (default
            ``/etc/resolv.conf``).

    Returns:
        The IP address string of the first ``nameserver`` entry.

    Raises:
        SystemResolverError: If the file cannot be read or contains no
            nameserver entries.
    """
    try:
        text = resolv_conf.read_text()
    except OSError as exc:
        raise SystemResolverError(
            f"Could not read {resolv_conf}: {exc}. "
            "Please set network.upstream_dns in your server config "
            "(config/airut.yaml)."
        ) from exc

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        parts = stripped.split()
        if parts[0] == "nameserver" and len(parts) >= 2:
            nameserver = parts[1]
            log.info(
                "Auto-detected system DNS resolver: %s (from %s)",
                nameserver,
                resolv_conf,
            )
            return nameserver

    raise SystemResolverError(
        f"No nameserver entries found in {resolv_conf}. "
        "Please set network.upstream_dns in your server config "
        "(config/airut.yaml)."
    )
