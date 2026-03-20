# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for root conftest fixtures."""

from __future__ import annotations

import asyncio
import gc
import warnings


class TestCloseLeakedEventLoops:
    """Tests for the _close_leaked_event_loops autouse fixture."""

    def test_stale_event_loop_closed_after_test(self) -> None:
        """Simulate pytest-asyncio's leak: create a loop, set it, leave open.

        The autouse fixture should close this loop after the test
        finishes, preventing ResourceWarning in a later test's GC.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # Deliberately leave it open -- the fixture will close it.
        assert not loop.is_closed()

    def test_no_warning_from_previous_test(self) -> None:
        """Verify GC after the previous test does not emit warnings.

        If _close_leaked_event_loops works correctly, the event loop
        created in the previous test was already closed and GC'd.
        A full GC sweep here must produce zero ResourceWarnings.
        """
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            gc.collect()
            gc.collect()

        resource_warnings = [
            w for w in caught if issubclass(w.category, ResourceWarning)
        ]
        assert resource_warnings == [], [
            str(w.message) for w in resource_warnings
        ]
