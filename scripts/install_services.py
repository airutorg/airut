#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Systemd user service manager — thin CLI entry point.

All logic lives in ``lib/install_services.py``. This script just bootstraps
the import path and calls ``main()``.
"""

import sys
from pathlib import Path


# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.install_services import main


if __name__ == "__main__":
    sys.exit(main())
