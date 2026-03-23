# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Unit tests for ConfigFileWatcher."""

from __future__ import annotations

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


class TestConfigFileWatcher:
    """Tests for ConfigFileWatcher."""

    def test_detects_config_file_event(self, tmp_path: Path) -> None:
        """Fires callback when inotify returns matching event."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        watcher = ConfigFileWatcher(config_file, callback)

        call_count = 0

        def mock_read(timeout: int = 0, read_delay: int = 0):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [_FakeEvent("airut.yaml")]
            # Return empty on subsequent calls
            time.sleep(0.1)
            return []

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read = mock_read
            mock_inotify_cls.return_value = mock_inotify

            watcher.start()
            try:
                _wait_for(lambda: callback.call_count >= 1)
                assert callback.call_count >= 1
            finally:
                watcher.stop()

    def test_ignores_other_files(self, tmp_path: Path) -> None:
        """Ignores events for files other than the config file."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        watcher = ConfigFileWatcher(config_file, callback)

        call_count = 0

        def mock_read(timeout: int = 0, read_delay: int = 0):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [_FakeEvent("other.yaml")]
            time.sleep(0.1)
            return []

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read = mock_read
            mock_inotify_cls.return_value = mock_inotify

            watcher.start()
            try:
                time.sleep(0.5)
                assert callback.call_count == 0
            finally:
                watcher.stop()

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

        def mock_read(timeout: int = 0, read_delay: int = 0):
            time.sleep(0.1)
            return []

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read = mock_read
            mock_inotify_cls.return_value = mock_inotify

            watcher.start()
            try:
                reload_event.set()
                _wait_for(lambda: callback.call_count >= 1)
                assert callback.call_count >= 1
                assert not reload_event.is_set()
            finally:
                watcher.stop()

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

        def mock_read(timeout: int = 0, read_delay: int = 0):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Simulate simultaneous SIGHUP + file event
                reload_event.set()
                return [_FakeEvent("airut.yaml")]
            time.sleep(0.1)
            return []

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read = mock_read
            mock_inotify_cls.return_value = mock_inotify

            watcher.start()
            try:
                _wait_for(lambda: callback.call_count >= 1)
                time.sleep(0.3)
                # SIGHUP takes priority, inotify events skipped
                assert callback.call_count == 1
            finally:
                watcher.stop()

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

        def mock_read(timeout: int = 0, read_delay: int = 0):
            nonlocal call_num
            call_num += 1
            if call_num <= 2:
                return [_FakeEvent("airut.yaml")]
            time.sleep(0.1)
            return []

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read = mock_read
            mock_inotify_cls.return_value = mock_inotify

            watcher.start()
            try:
                _wait_for(lambda: invocations >= 2)
                assert invocations >= 2
            finally:
                watcher.stop()

    def test_stop_is_idempotent(self, tmp_path: Path) -> None:
        """Calling stop multiple times does not raise."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read.return_value = []
            mock_inotify_cls.return_value = mock_inotify

            watcher = ConfigFileWatcher(config_file, lambda: None)
            watcher.start()
            watcher.stop()
            watcher.stop()  # Should not raise

    def test_one_callback_per_batch(self, tmp_path: Path) -> None:
        """Multiple events in one batch produce one callback."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        callback = MagicMock()
        watcher = ConfigFileWatcher(config_file, callback)

        call_count = 0

        def mock_read(timeout: int = 0, read_delay: int = 0):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Multiple events in one batch
                return [
                    _FakeEvent("airut.yaml"),
                    _FakeEvent("airut.yaml"),
                    _FakeEvent("airut.yaml"),
                ]
            time.sleep(0.1)
            return []

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read = mock_read
            mock_inotify_cls.return_value = mock_inotify

            watcher.start()
            try:
                _wait_for(lambda: callback.call_count >= 1)
                time.sleep(0.3)
                assert callback.call_count == 1
            finally:
                watcher.stop()

    def test_watches_parent_directory(self, tmp_path: Path) -> None:
        """Watcher adds inotify watch on the parent directory."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read.return_value = []
            mock_inotify_cls.return_value = mock_inotify

            watcher = ConfigFileWatcher(config_file, lambda: None)
            watcher.start()
            time.sleep(0.2)
            watcher.stop()

            mock_inotify.add_watch.assert_called_once()
            watch_path = mock_inotify.add_watch.call_args[0][0]
            assert watch_path == str(tmp_path)

    def test_ready_event_set_after_watch_added(self, tmp_path: Path) -> None:
        """Ready event is set once the inotify watch is active."""
        config_file = tmp_path / "airut.yaml"
        config_file.write_text("model: opus\n")

        with patch("airut.config.watcher.INotify") as mock_inotify_cls:
            mock_inotify = MagicMock()
            mock_inotify.read.return_value = []
            mock_inotify_cls.return_value = mock_inotify

            watcher = ConfigFileWatcher(config_file, lambda: None)
            assert not watcher.ready.is_set()
            watcher.start()
            _wait_for(lambda: watcher.ready.is_set())
            assert watcher.ready.is_set()
            watcher.stop()
