#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Airut Email Gateway Service — script entry point.

Delegates to :func:`lib.airut.cli`.  Equivalent to ``uv run airut``.
"""

import sys
from pathlib import Path


# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.airut import cli


if __name__ == "__main__":
    cli()
