# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Network sandbox log reader.

Provides read access to the network sandbox log file created by the
proxy container during task execution.
"""

from __future__ import annotations

import logging
from pathlib import Path


logger = logging.getLogger(__name__)


# Network sandbox log file name (created in network_log_dir)
NETWORK_LOG_FILENAME = "network-sandbox.log"


class NetworkLog:
    """Read access to the network sandbox log.

    The log file is created by the sandbox at proxy start and written
    to by the proxy container (DNS responder + mitmproxy addon).
    It persists after task completion for dashboard viewing.
    """

    def __init__(self, log_path: Path) -> None:
        self._path = log_path

    @property
    def path(self) -> Path:
        """Path to the log file."""
        return self._path

    def exists(self) -> bool:
        """Whether the log file exists."""
        return self._path.exists()

    def read_raw(self) -> str:
        """Read the raw log file contents.

        Returns:
            Raw log text, or empty string if file doesn't exist.
        """
        if not self._path.exists():
            return ""
        return self._path.read_text()

    def tail(self, offset: int = 0) -> tuple[list[str], int]:
        """Read new lines from a byte offset.

        Enables efficient polling: the caller passes the last known
        offset and gets only new lines since then.

        Args:
            offset: Byte offset to start reading from.

        Returns:
            Tuple of (new_lines, new_offset). The new_offset should
            be passed to the next tail() call.
        """
        if not self._path.exists():
            return [], 0

        try:
            with self._path.open("r") as f:
                f.seek(offset)
                new_content = f.read()
                new_offset = f.tell()
        except OSError as e:
            logger.warning("Failed to tail network log %s: %s", self._path, e)
            return [], offset

        if not new_content:
            return [], new_offset

        lines = [line for line in new_content.splitlines() if line]
        return lines, new_offset
