# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib.sandbox.event_log."""

import json
from pathlib import Path

from lib.claude_output import StreamEvent, parse_event
from lib.sandbox.event_log import EVENTS_FILE_NAME, EventLog


# ── Helpers ──────────────────────────────────────────────────────────


def _make_event(raw_dict: dict) -> StreamEvent:
    """Create a StreamEvent from a raw dict."""
    raw = json.dumps(raw_dict)
    event = parse_event(raw)
    assert event is not None
    return event


def _system_event(session_id: str = "sess-1") -> StreamEvent:
    return _make_event(
        {"type": "system", "subtype": "init", "session_id": session_id}
    )


def _result_event(
    cost: float = 0.05,
    duration_ms: int = 5000,
    num_turns: int = 3,
) -> StreamEvent:
    return _make_event(
        {
            "type": "result",
            "subtype": "success",
            "session_id": "sess-1",
            "duration_ms": duration_ms,
            "total_cost_usd": cost,
            "num_turns": num_turns,
            "is_error": False,
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }
    )


def _assistant_event(text: str = "Hello") -> StreamEvent:
    return _make_event(
        {
            "type": "assistant",
            "message": {
                "content": [{"type": "text", "text": text}],
            },
        }
    )


# ── Basic operations ─────────────────────────────────────────────────


class TestEventLog:
    def test_file_path(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        assert log.file_path == tmp_path / EVENTS_FILE_NAME

    def test_append_event_creates_file(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())
        assert log.file_path.exists()

    def test_append_event_writes_one_line(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())

        content = log.file_path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 1

    def test_append_multiple_events(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())
        log.append_event(_assistant_event())
        log.append_event(_result_event())

        content = log.file_path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 3

    def test_read_all_no_file(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        assert log.read_all() == []

    def test_read_all_empty_file(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.file_path.write_text("")
        assert log.read_all() == []

    def test_read_all_single_reply(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())
        log.append_event(_assistant_event())
        log.append_event(_result_event())

        groups = log.read_all()
        assert len(groups) == 1
        assert len(groups[0]) == 3

    def test_read_all_multiple_replies(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)

        # First reply
        log.append_event(_system_event("sess-1"))
        log.append_event(_result_event())

        # Delimiter
        log.start_new_reply()

        # Second reply
        log.append_event(_system_event("sess-2"))
        log.append_event(_assistant_event("world"))
        log.append_event(_result_event())

        groups = log.read_all()
        assert len(groups) == 2
        assert len(groups[0]) == 2
        assert len(groups[1]) == 3

    def test_read_all_skips_invalid_json(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.file_path.write_text(
            '{"type": "system", "subtype": "init"}\n'
            "not valid json\n"
            '{"type": "result", "subtype": "success"}\n'
        )
        groups = log.read_all()
        assert len(groups) == 1
        assert len(groups[0]) == 2

    def test_read_all_os_error(self, tmp_path: Path) -> None:
        """read_all returns empty list on OSError."""
        log = EventLog(tmp_path)
        # Create file_path as a directory to trigger OSError
        log.file_path.mkdir()
        assert log.read_all() == []

    def test_read_all_skips_non_dict_json(self, tmp_path: Path) -> None:
        """Non-dict JSON lines (e.g., arrays) are skipped."""
        log = EventLog(tmp_path)
        log.file_path.write_text(
            '[1, 2, 3]\n{"type": "system", "subtype": "init"}\n'
        )
        groups = log.read_all()
        assert len(groups) == 1
        assert len(groups[0]) == 1


# ── Reply delimiter ──────────────────────────────────────────────────


class TestReplyDelimiter:
    def test_start_new_reply_no_file(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        # Should not create file or write anything
        log.start_new_reply()
        assert not log.file_path.exists()

    def test_start_new_reply_empty_file(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.file_path.write_text("")
        log.start_new_reply()
        # Empty file: no delimiter needed
        assert log.file_path.read_text() == ""

    def test_start_new_reply_after_events(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())
        log.start_new_reply()

        content = log.file_path.read_text()
        # Should end with a blank line (double newline)
        assert content.endswith("\n\n")

    def test_multiple_delimiters_produce_separate_groups(
        self, tmp_path: Path
    ) -> None:
        log = EventLog(tmp_path)

        log.append_event(_system_event("s1"))
        log.start_new_reply()
        log.append_event(_system_event("s2"))
        log.start_new_reply()
        log.append_event(_system_event("s3"))

        groups = log.read_all()
        assert len(groups) == 3


# ── read_reply ───────────────────────────────────────────────────────


class TestReadReply:
    def test_read_reply_valid_index(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event("s1"))
        log.start_new_reply()
        log.append_event(_system_event("s2"))

        events = log.read_reply(0)
        assert len(events) == 1
        assert events[0].session_id == "s1"

        events = log.read_reply(1)
        assert len(events) == 1
        assert events[0].session_id == "s2"

    def test_read_reply_invalid_index(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        assert log.read_reply(0) == []
        assert log.read_reply(-1) == []
        assert log.read_reply(99) == []

    def test_read_reply_negative_index(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())
        # Negative indices should return empty (we use explicit bounds check)
        assert log.read_reply(-1) == []


# ── tail ─────────────────────────────────────────────────────────────


class TestTail:
    def test_tail_no_file(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        events, offset = log.tail(0)
        assert events == []
        assert offset == 0

    def test_tail_from_start(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())
        log.append_event(_result_event())

        events, offset = log.tail(0)
        assert len(events) == 2
        assert offset > 0

    def test_tail_incremental(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())

        events1, offset1 = log.tail(0)
        assert len(events1) == 1

        log.append_event(_assistant_event())
        log.append_event(_result_event())

        events2, offset2 = log.tail(offset1)
        assert len(events2) == 2
        assert offset2 > offset1

    def test_tail_no_new_data(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event())

        _, offset = log.tail(0)
        events, new_offset = log.tail(offset)
        assert events == []
        assert new_offset == offset

    def test_tail_across_reply_delimiter(self, tmp_path: Path) -> None:
        log = EventLog(tmp_path)
        log.append_event(_system_event("s1"))

        _, offset = log.tail(0)

        log.start_new_reply()
        log.append_event(_system_event("s2"))

        events, _ = log.tail(offset)
        # Should return the event from the second reply
        # (delimiter is empty line, skipped)
        assert len(events) == 1
        assert events[0].session_id == "s2"

    def test_tail_os_error(self, tmp_path: Path) -> None:
        """Tail returns empty list and original offset on OSError."""
        log = EventLog(tmp_path)
        # Create file_path as a directory to trigger OSError
        log.file_path.mkdir()
        events, offset = log.tail(0)
        assert events == []
        assert offset == 0
