# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Thread-to-conversation mapping persistence for Slack.

Maintains a JSON-backed mapping between Slack threads (identified by
``channel_id:thread_ts``) and Airut conversation IDs.  Loaded into
memory at startup and flushed to disk on each write.
"""

from __future__ import annotations

import json
import logging
import tempfile
import threading
from pathlib import Path


logger = logging.getLogger(__name__)


class SlackThreadStore:
    """File-backed thread-to-conversation mapping.

    Thread-safe via an internal lock.  The backing file is a flat JSON
    object mapping ``"channel_id:thread_ts"`` keys to conversation ID
    values.

    Args:
        state_dir: Directory for persistent state (created if missing).
    """

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "slack_threads.json"
        self._lock = threading.Lock()
        self._data: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        """Load existing mapping from disk."""
        if not self._path.exists():
            return
        try:
            with open(self._path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._data = data
                logger.info(
                    "Loaded %d thread mappings from %s",
                    len(self._data),
                    self._path,
                )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load thread store %s: %s", self._path, e)

    def _save(self) -> None:
        """Persist current mapping to disk atomically."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd, tmp = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
            try:
                with open(fd, "w") as f:
                    json.dump(self._data, f)
                Path(tmp).replace(self._path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        except OSError as e:
            logger.warning("Failed to save thread store %s: %s", self._path, e)

    @staticmethod
    def _key(channel_id: str, thread_ts: str) -> str:
        """Build composite key from channel ID and thread timestamp."""
        return f"{channel_id}:{thread_ts}"

    def get_conversation_id(
        self, channel_id: str, thread_ts: str
    ) -> str | None:
        """Look up Airut conversation ID for a Slack thread.

        Args:
            channel_id: Slack DM channel ID (``D``-prefixed).
            thread_ts: Thread timestamp.

        Returns:
            Conversation ID if mapped, None otherwise.
        """
        with self._lock:
            return self._data.get(self._key(channel_id, thread_ts))

    def register(self, channel_id: str, thread_ts: str, conv_id: str) -> None:
        """Register a new thread-to-conversation mapping and persist.

        Args:
            channel_id: Slack DM channel ID.
            thread_ts: Thread timestamp.
            conv_id: Airut conversation ID.
        """
        with self._lock:
            self._data[self._key(channel_id, thread_ts)] = conv_id
            self._save()
