# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared fixtures for email channel tests.

Re-exports service test helpers needed by test_replies.py.
"""

from tests.gateway.service.conftest import (
    make_message,
    make_service,
    update_global,
)


__all__ = ["make_message", "make_service", "update_global"]
