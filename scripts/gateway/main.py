#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Airut Email Gateway Service entry point.

See lib/gateway/service/ for the implementation.
"""

import sys
from pathlib import Path


# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from lib.gateway.service import main


if __name__ == "__main__":
    sys.exit(main())
