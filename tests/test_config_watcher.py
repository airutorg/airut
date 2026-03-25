# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Unit tests for ConfigFileWatcher."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

from airut.config.watcher import ConfigFileWatcher


def _wait_for(
    predicate: Callable[[], object],
    timeout: float = 5.0,
    interval: float = 0.05,
) -> None:
    """Wait until predicate returns truthy or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise TimeoutError("Condition not met within timeout")


class _FakeEvent:
    """Minimal inotify event for testing."""

    def __init__(self, name: str) -> None:
        self.name = name


def _make_inotify_mock(
    events_fn: Callable[[], list[_FakeEvent]],
) -> tuple[MagicMock, MagicMock]:
    """Create a mock INotify class and instance wired for select-based loop.

    The returned mock_inotify has a real pipe fd for ``fileno()`` so
    that ``select.select()`` works.  The ``events_fn`` is called on
    each ``read()`` to decide what events to return.

    Returns:
        (mock_inotify_cls, mock_inotify) — the class mock and its
        singleton instance.
    """
    # Use a real pipe so select.select() can work on the fd.
    pipe_r, pipe_w = os.pipe()

    mock_inotify = MagicMock()
    mock_inotify.fileno.return_value = pipe_r
    mock_inotify.read.side_effect = lambda **kw: events_fn()

    mock_inotify_cls = MagicMock(return_value=mock_inotify)

    # Signal the pipe so select returns immediately (inotify fd readable).
    # The watch loop will then call inotify.read(timeout=0).
    os.write(pipe_w, b"\x01")

    # Store pipe fds for cleanup.
    mock_inotify._test_pipe_r = pipe_r
    mock_inotify._test_pipe_w = pipe_w

    return mock_inotify_cls, mock_inotify


def _signal_inotify(mock_inotify: MagicMock) -> None:
    """Signal the fake inotify fd so select() returns it as readable."""
    try:
        os.write(mock_inotify._test_pipe_w, b"\x01")
    except OSError:
        pass


def _cleanup_inotify_mock(mock_inotify: MagicMock) -> None:
    """Close pipe fds from _make_inotify_mock."""
    for fd in (mock_inotify._test_pipe_r, mock_inotify._test_pipe_w):
        try:
            os.close(fd)
        except OSError:
            pass


class TestConfigFileWatcher:
    """Tests for ConfigFileWatcher."""

    def test_detects_config_file_event(self, tmp_path: Path) -> None:
        """Fires callback when inotify returns matching event."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        watcher = ConfigFileWatcher(config_file, callback)

        call_count = 0

        def events_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Drain the byte so select blocks on subsequent calls.
                try:
                    os.read(mock_inotify._test_pipe_r, 1024)
                except OSError:
                    pass
                return [_FakeEvent("airut.yaml")]
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher.start()
                try:
                    _wait_for(lambda: callback.call_count >= 1)
                    assert callback.call_count >= 1
                finally:
                    watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_ignores_other_files(self, tmp_path: Path) -> None:
        """Ignores events for files other than the config file."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        watcher = ConfigFileWatcher(config_file, callback)

        call_count = 0

        def events_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                try:
                    os.read(mock_inotify._test_pipe_r, 1024)
                except OSError:
                    pass
                return [_FakeEvent("other.yaml")]
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher.start()
                try:
                    time.sleep(0.5)
                    assert callback.call_count == 0
                finally:
                    watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_sighup_triggers_reload(self, tmp_path: Path) -> None:
        """SIGHUP event triggers callback via reload_requested."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        reload_event = threading.Event()
        watcher = ConfigFileWatcher(
            config_file,
            callback,
            reload_requested=reload_event,
        )

        def events_fn():
            # Drain so select blocks until next signal.
            try:
                os.read(mock_inotify._test_pipe_r, 1024)
            except OSError:
                pass
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher.start()
                try:
                    # Set SIGHUP then wake inotify fd so select unblocks.
                    reload_event.set()
                    _signal_inotify(mock_inotify)
                    _wait_for(lambda: callback.call_count >= 1)
                    assert callback.call_count >= 1
                    assert not reload_event.is_set()
                finally:
                    watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_sighup_skips_inotify_events(self, tmp_path: Path) -> None:
        """SIGHUP + file write together fires only one callback."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        reload_event = threading.Event()
        watcher = ConfigFileWatcher(
            config_file,
            callback,
            reload_requested=reload_event,
        )

        call_count = 0

        def events_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                try:
                    os.read(mock_inotify._test_pipe_r, 1024)
                except OSError:
                    pass
                # Simulate simultaneous SIGHUP + file event
                reload_event.set()
                return [_FakeEvent("airut.yaml")]
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher.start()
                try:
                    _wait_for(lambda: callback.call_count >= 1)
                    time.sleep(0.3)
                    # SIGHUP takes priority, inotify events skipped
                    assert callback.call_count == 1
                finally:
                    watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_callback_exception_does_not_crash_watcher(
        self, tmp_path: Path
    ) -> None:
        """Exception in callback does not stop the watcher."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        invocations = 0

        def failing_then_ok() -> None:
            nonlocal invocations
            invocations += 1
            if invocations == 1:
                raise RuntimeError("Simulated error")

        watcher = ConfigFileWatcher(config_file, failing_then_ok)

        call_num = 0

        def events_fn():
            nonlocal call_num
            call_num += 1
            if call_num <= 2:
                # Drain, then re-signal for the next iteration.
                try:
                    os.read(mock_inotify._test_pipe_r, 1024)
                except OSError:
                    pass
                _signal_inotify(mock_inotify)
                return [_FakeEvent("airut.yaml")]
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher.start()
                try:
                    _wait_for(lambda: invocations >= 2)
                    assert invocations >= 2
                finally:
                    watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_stop_is_idempotent(self, tmp_path: Path) -> None:
        """Calling stop multiple times does not raise."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        def events_fn():
            try:
                os.read(mock_inotify._test_pipe_r, 1024)
            except OSError:
                pass
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher = ConfigFileWatcher(config_file, lambda: None)
                watcher.start()
                watcher.stop()
                watcher.stop()  # Should not raise
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_one_callback_per_batch(self, tmp_path: Path) -> None:
        """Multiple events in one batch produce one callback."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        watcher = ConfigFileWatcher(config_file, callback)

        call_count = 0

        def events_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                try:
                    os.read(mock_inotify._test_pipe_r, 1024)
                except OSError:
                    pass
                # Multiple events in one batch
                return [
                    _FakeEvent("airut.yaml"),
                    _FakeEvent("airut.yaml"),
                    _FakeEvent("airut.yaml"),
                ]
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher.start()
                try:
                    _wait_for(lambda: callback.call_count >= 1)
                    time.sleep(0.3)
                    assert callback.call_count == 1
                finally:
                    watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_watches_parent_directory(self, tmp_path: Path) -> None:
        """Watcher adds inotify watch on the parent directory."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        def events_fn():
            try:
                os.read(mock_inotify._test_pipe_r, 1024)
            except OSError:
                pass
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher = ConfigFileWatcher(config_file, lambda: None)
                watcher.start()
                _wait_for(lambda: watcher.ready.is_set())
                watcher.stop()

                mock_inotify.add_watch.assert_called_once()
                watch_path = mock_inotify.add_watch.call_args[0][0]
                assert watch_path == str(tmp_path)
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_ready_event_set_after_watch_added(self, tmp_path: Path) -> None:
        """Ready event is set once the inotify watch is active."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        def events_fn():
            try:
                os.read(mock_inotify._test_pipe_r, 1024)
            except OSError:
                pass
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher = ConfigFileWatcher(config_file, lambda: None)
                assert not watcher.ready.is_set()
                watcher.start()
                _wait_for(lambda: watcher.ready.is_set())
                assert watcher.ready.is_set()
                watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_select_timeout_retries(self, tmp_path: Path) -> None:
        """Select timeout (no fds readable) loops back to select again."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        call_count = 0

        def events_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                try:
                    os.read(mock_inotify._test_pipe_r, 1024)
                except OSError:
                    pass
                return [_FakeEvent("airut.yaml")]
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        callback = MagicMock()

        # Wrap real select to inject one empty return (simulating timeout).
        import select as select_mod

        original_select = select_mod.select
        timeout_injected = False

        def fake_select(rlist, wlist, xlist, timeout=None):
            nonlocal timeout_injected
            if not timeout_injected:
                timeout_injected = True
                # Simulate a select timeout (no fds readable).
                return ([], [], [])
            return original_select(rlist, wlist, xlist, timeout)

        try:
            with (
                patch("airut.config.watcher.INotify", mock_inotify_cls),
                patch("airut.config.watcher.select.select", fake_select),
            ):
                watcher = ConfigFileWatcher(config_file, callback)
                watcher.start()
                try:
                    _wait_for(lambda: callback.call_count >= 1)
                    assert callback.call_count >= 1
                finally:
                    watcher.stop()
        finally:
            _cleanup_inotify_mock(mock_inotify)

    def test_stop_returns_immediately(self, tmp_path: Path) -> None:
        """Stop completes in well under 1s thanks to wakeup pipe."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        def events_fn():
            try:
                os.read(mock_inotify._test_pipe_r, 1024)
            except OSError:
                pass
            return []

        mock_inotify_cls, mock_inotify = _make_inotify_mock(events_fn)
        try:
            with patch("airut.config.watcher.INotify", mock_inotify_cls):
                watcher = ConfigFileWatcher(config_file, lambda: None)
                watcher.start()
                _wait_for(lambda: watcher.ready.is_set())

                t0 = time.monotonic()
                watcher.stop()
                elapsed = time.monotonic() - t0
                assert elapsed < 0.5, (
                    f"stop() took {elapsed:.2f}s — wakeup pipe not working"
                )
        finally:
            _cleanup_inotify_mock(mock_inotify)
