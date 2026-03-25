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
import os
import select
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
        # Wakeup pipe: write end is signalled on stop() to break
        # out of the select() call immediately.
        self._wakeup_r, self._wakeup_w = os.pipe()

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
        """Stop watching. Thread exits immediately."""
        self._running = False
        # Signal the wakeup pipe so the watch loop breaks out of select().
        try:
            os.write(self._wakeup_w, b"\x00")
        except OSError:
            pass  # Already closed
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self._close_pipe()
        logger.info("Config file watcher stopped")

    def _close_pipe(self) -> None:
        """Close wakeup pipe fds (idempotent)."""
        for fd in (self._wakeup_r, self._wakeup_w):
            try:
                os.close(fd)
            except OSError:
                pass
        # Prevent double-close by setting to -1
        self._wakeup_r = -1
        self._wakeup_w = -1

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

        inotify_fd = inotify.fileno()

        try:
            while self._running:
                # Block until inotify has events or the wakeup pipe is
                # signalled (on stop).  Timeout is a safety net only.
                readable, _, _ = select.select(
                    [inotify_fd, self._wakeup_r], [], [], 5.0
                )
                if self._wakeup_r in readable:
                    # Drain wakeup pipe and exit.
                    os.read(self._wakeup_r, 1)
                    break

                if inotify_fd not in readable:
                    continue

                # Non-blocking read: select guarantees data is ready.
                events = inotify.read(timeout=0, read_delay=100)

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
