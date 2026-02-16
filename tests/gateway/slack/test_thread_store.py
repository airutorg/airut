# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackThreadStore."""

import json
from pathlib import Path

from airut.gateway.slack.thread_store import SlackThreadStore


class TestSlackThreadStore:
    def test_register_and_get(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "1700000000.000001", "conv_abc")

        result = store.get_conversation_id("D123", "1700000000.000001")
        assert result == "conv_abc"

    def test_get_returns_none_for_unknown(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        result = store.get_conversation_id("D123", "1700000000.999999")
        assert result is None

    def test_persistence(self, tmp_path: Path) -> None:
        store1 = SlackThreadStore(tmp_path)
        store1.register("D123", "1700000000.000001", "conv_abc")

        # Create new store from same directory
        store2 = SlackThreadStore(tmp_path)
        result = store2.get_conversation_id("D123", "1700000000.000001")
        assert result == "conv_abc"

    def test_file_contents(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "1700000000.000001", "conv_abc")

        json_path = tmp_path / "slack_threads.json"
        assert json_path.exists()

        with open(json_path) as f:
            data = json.load(f)
        assert data == {"D123:1700000000.000001": "conv_abc"}

    def test_multiple_threads(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "1700000000.000001", "conv_1")
        store.register("D123", "1700000000.000002", "conv_2")
        store.register("D456", "1700000000.000001", "conv_3")

        assert (
            store.get_conversation_id("D123", "1700000000.000001") == "conv_1"
        )
        assert (
            store.get_conversation_id("D123", "1700000000.000002") == "conv_2"
        )
        assert (
            store.get_conversation_id("D456", "1700000000.000001") == "conv_3"
        )

    def test_overwrite_mapping(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "1700000000.000001", "conv_old")
        store.register("D123", "1700000000.000001", "conv_new")

        assert (
            store.get_conversation_id("D123", "1700000000.000001") == "conv_new"
        )

    def test_handles_corrupted_file(self, tmp_path: Path) -> None:
        json_path = tmp_path / "slack_threads.json"
        json_path.write_text("not valid json{{{")

        store = SlackThreadStore(tmp_path)
        assert store.get_conversation_id("D123", "ts") is None

    def test_handles_missing_file(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        assert store.get_conversation_id("D123", "ts") is None

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b" / "c"
        store = SlackThreadStore(nested)
        store.register("D123", "ts", "conv1")

        assert (nested / "slack_threads.json").exists()

    def test_save_failure_logged(self, tmp_path: Path) -> None:
        """OSError during save is logged, not raised."""
        store = SlackThreadStore(tmp_path)
        # Make the file path a directory so writing fails
        json_path = tmp_path / "slack_threads.json"
        json_path.mkdir()

        # Should not raise
        store.register("D123", "ts", "conv1")
        # Data is still in memory
        assert store.get_conversation_id("D123", "ts") == "conv1"
