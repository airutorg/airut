# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config file watcher using inotify.

Watches a config file for changes and invokes a callback when the file
is written or atomically replaced.  Uses Linux inotify via
``inotify-simple`` for sub-millisecond detection.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path

from inotify_simple import INotify, flags


logger = logging.getLogger(__name__)


class ConfigFileWatcher:
    """Watch a config file for changes via inotify.

    Watches the config file's **parent directory** for ``CLOSE_WRITE``
    and ``MOVED_TO`` events on the config filename.  Watching the
    directory (not the file) handles editors that use atomic
    write-to-temp-then-rename patterns.

    Args:
        config_path: Path to the config file to watch.
        on_change: Callback invoked when the config file changes.
            Called from the watcher thread.
        reload_requested: Optional threading event for SIGHUP support.
            When set, the watcher treats it as a reload trigger
            (skipping inotify events to avoid double-reload).
    """

    def __init__(
        self,
        config_path: Path,
        on_change: Callable[[], None],
        reload_requested: threading.Event | None = None,
    ) -> None:
        self._config_dir = config_path.parent
        self._config_name = config_path.name
        self._on_change = on_change
        self._reload_requested = reload_requested or threading.Event()
        self._running = False
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start background daemon thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._watch_loop,
            daemon=True,
            name="ConfigFileWatcher",
        )
        self._thread.start()
        logger.info(
            "Config file watcher started: %s",
            self._config_dir / self._config_name,
        )

    def stop(self) -> None:
        """Stop watching. Thread exits within ~1 second."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        logger.info("Config file watcher stopped")

    @property
    def ready(self) -> threading.Event:
        """Event set once the inotify watch is active."""
        return self._ready

    def _watch_loop(self) -> None:
        """Main watch loop running in the daemon thread."""
        inotify = INotify()
        watch_flags = flags.CLOSE_WRITE | flags.MOVED_TO
        inotify.add_watch(str(self._config_dir), watch_flags)
        self._ready.set()

        try:
            while self._running:
                events = inotify.read(timeout=1000, read_delay=100)

                if self._reload_requested.is_set():
                    # SIGHUP was received — clear and invoke callback.
                    # Skip inotify events to avoid double-reload.
                    self._reload_requested.clear()
                    logger.info("Config reload triggered by SIGHUP")
                    self._safe_callback()
                else:
                    for event in events:
                        if event.name == self._config_name:
                            logger.info(
                                "Config file change detected: %s",
                                self._config_name,
                            )
                            self._safe_callback()
                            break  # one callback per event batch
        finally:
            inotify.close()

    def _safe_callback(self) -> None:
        """Invoke the on_change callback with exception protection."""
        try:
            self._on_change()
        except Exception:
            logger.exception("Error in config change callback")
