# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Airut CLI entry point.

Thin wrapper around :func:`lib.gateway.service.main`. This module exists so
that ``[project.scripts]`` can point to ``lib.airut:cli`` without needing to
package the ``scripts/`` directory.  It will grow subcommands (config check,
dependency verification, service install, etc.) in the future.
"""

import sys

from lib.gateway.service import main


def cli() -> None:
    """Entry point for ``uv run airut`` and ``uv tool install``."""
    sys.exit(main())
