# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for root conftest fixtures."""

from __future__ import annotations

import asyncio
import gc
import logging
import warnings
from pathlib import Path

import pytest

from tests.conftest import _is_pytest_handler, preserve_root_logger


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


class TestPreserveRootLogger:
    """Tests for preserve_root_logger (behind the autouse fixture).

    Code under test may configure the root logger (the airut-sandbox
    CLI sets its level and adds a handler).  Leaked into later tests,
    that broke caplog tests relying on the default WARNING level, so
    they passed or failed depending on test order.
    """

    def test_level_restored(self) -> None:
        """A level set inside is reverted on exit."""
        root = logging.getLogger()
        before = root.level

        with preserve_root_logger():
            root.setLevel(logging.ERROR)

        assert root.level == before

    def test_added_handler_removed_and_closed(self, tmp_path: Path) -> None:
        """Handlers added inside are removed and closed on exit."""
        root = logging.getLogger()
        handler = logging.FileHandler(tmp_path / "log")

        with preserve_root_logger():
            root.addHandler(handler)

        assert handler not in root.handlers
        assert handler.stream is None  # closed

    def test_removed_handler_restored(self) -> None:
        """Handlers removed inside are put back on exit."""
        root = logging.getLogger()
        handler = logging.NullHandler()
        root.addHandler(handler)
        try:
            with preserve_root_logger():
                root.removeHandler(handler)

            assert handler in root.handlers
        finally:
            root.removeHandler(handler)

    def test_pytest_handlers_restored(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Pytest's capture handlers removed inside are put back."""
        root = logging.getLogger()
        assert caplog.handler in root.handlers

        with preserve_root_logger():
            root.removeHandler(caplog.handler)

        logging.getLogger("tests.preserve").warning("still captured")
        assert "still captured" in caplog.text

    def test_pytest_handler_added_inside_kept_open(self) -> None:
        """A pytest handler attached inside is neither removed nor closed.

        pytest attaches and detaches its handlers around test phases,
        which a snapshot taken in one phase must not undo.
        """
        root = logging.getLogger()
        handler = next(
            h
            for h in root.handlers
            if _is_pytest_handler(h) and isinstance(h, logging.FileHandler)
        )
        root.removeHandler(handler)
        try:
            with preserve_root_logger():
                root.addHandler(handler)

            assert handler in root.handlers
            assert handler.stream is not None  # FileHandler.close() clears it
        finally:
            if handler not in root.handlers:
                root.addHandler(handler)
