# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Append-only event log for Claude streaming output.

Stores raw Claude streaming JSON events in a newline-delimited file
(events.jsonl). Each event is written as a single line via append,
making writes O(1) regardless of file size.

Replies are separated by a blank line delimiter so events can be
grouped by reply when reading back.
"""

import json
import logging
from pathlib import Path
from typing import Any

from lib.claude_output import StreamEvent, parse_event_dict


logger = logging.getLogger(__name__)


EVENTS_FILE_NAME = "events.jsonl"

# Blank line separates events from different replies
_REPLY_DELIMITER = ""


class EventLog:
    """Append-only event log for Claude streaming output.

    Events are written one per line in append mode. No read-modify-write
    cycle — each write is O(1). Replies are separated by blank lines.

    Attributes:
        file_path: Path to the events.jsonl file.
    """

    def __init__(self, execution_context_dir: Path) -> None:
        """Initialize event log.

        Args:
            execution_context_dir: Directory where events.jsonl will be
                stored.
        """
        self.file_path = execution_context_dir / EVENTS_FILE_NAME

    def append_event(self, event: StreamEvent) -> None:
        """Append a single event to the log.

        Opens in append mode, writes one line, and closes. This is
        safe for concurrent reads (tail) from the dashboard.

        Args:
            event: Typed streaming event to append.
        """
        with self.file_path.open("a") as f:
            f.write(event.raw.rstrip("\n") + "\n")

    def start_new_reply(self) -> None:
        """Write a delimiter between replies.

        Call this before appending events for a new reply to ensure
        events can be grouped by reply when reading back.
        """
        # Only write delimiter if file exists and is non-empty
        if self.file_path.exists() and self.file_path.stat().st_size > 0:
            with self.file_path.open("a") as f:
                f.write("\n")

    def read_all(self) -> list[list[StreamEvent]]:
        """Read all events, grouped by reply.

        Returns:
            List of reply groups, where each group is a list of events.
            Empty list if file doesn't exist.
        """
        if not self.file_path.exists():
            return []

        try:
            content = self.file_path.read_text()
        except OSError as e:
            logger.warning("Failed to read event log %s: %s", self.file_path, e)
            return []

        if not content.strip():
            return []

        # Split on blank lines to get reply groups
        reply_chunks = content.split("\n\n")
        result: list[list[StreamEvent]] = []

        for chunk in reply_chunks:
            events = _parse_chunk(chunk)
            if events:
                result.append(events)

        return result

    def read_reply(self, index: int) -> list[StreamEvent]:
        """Read events for a specific reply by index.

        Args:
            index: Zero-based reply index.

        Returns:
            List of events for that reply, or empty list if not found.
        """
        all_replies = self.read_all()
        if 0 <= index < len(all_replies):
            return all_replies[index]
        return []

    def tail(self, offset: int = 0) -> tuple[list[StreamEvent], int]:
        """Read new events from a byte offset.

        Enables efficient polling: the caller passes the last known
        offset and gets only new events since then.

        Args:
            offset: Byte offset to start reading from.

        Returns:
            Tuple of (new_events, new_offset). The new_offset should
            be passed to the next tail() call.
        """
        if not self.file_path.exists():
            return [], 0

        try:
            with self.file_path.open("r") as f:
                f.seek(offset)
                new_content = f.read()
                new_offset = f.tell()
        except OSError as e:
            logger.warning("Failed to tail event log %s: %s", self.file_path, e)
            return [], offset

        if not new_content.strip():
            return [], new_offset

        events = _parse_chunk(new_content)
        return events, new_offset


def _parse_chunk(chunk: str) -> list[StreamEvent]:
    """Parse a chunk of newline-delimited JSON into events."""
    events: list[StreamEvent] = []
    for line in chunk.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            raw_obj: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw_obj, dict):
            continue
        event = parse_event_dict(raw_obj)
        if event is not None:
            events.append(event)
    return events
