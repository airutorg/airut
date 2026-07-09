# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut._threads."""

from __future__ import annotations

import threading

from airut._threads import join_if_started


def test_join_if_started_none_returns_false() -> None:
    """A None thread is a no-op and reports 'not started'."""
    assert join_if_started(None, timeout=1) is False


def test_join_if_started_unstarted_thread_does_not_raise() -> None:
    """A thread assigned but never started must not raise on join().

    threading.Thread.join() raises RuntimeError('cannot join thread
    before it is started') for an unstarted thread; join_if_started
    swallows that and reports 'not started'.
    """
    thread = threading.Thread(target=lambda: None)  # never started
    assert join_if_started(thread, timeout=1) is False


def test_join_if_started_finished_thread_returns_true() -> None:
    """A started (and finished) thread is joined and reports started."""
    thread = threading.Thread(target=lambda: None)
    thread.start()
    result = join_if_started(thread, timeout=5)
    assert result is True
    assert not thread.is_alive()
