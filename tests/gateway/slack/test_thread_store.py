# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackThreadStore."""

import json
from pathlib import Path

from airut.gateway.slack.thread_store import SlackThreadStore


class TestSlackThreadStore:
    def test_register_and_lookup(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "1234567890.123456", "conv1")

        result = store.get_conversation_id("D123", "1234567890.123456")
        assert result == "conv1"

    def test_lookup_missing_returns_none(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        result = store.get_conversation_id("D123", "1234567890.123456")
        assert result is None

    def test_persistence(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "1234567890.123456", "conv1")

        # Create new store from same directory
        store2 = SlackThreadStore(tmp_path)
        result = store2.get_conversation_id("D123", "1234567890.123456")
        assert result == "conv1"

    def test_json_file_created(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "ts1", "conv1")

        json_path = tmp_path / "slack_threads.json"
        assert json_path.exists()

        with open(json_path) as f:
            data = json.load(f)
        assert data == {"D123:ts1": "conv1"}

    def test_multiple_threads(self, tmp_path: Path) -> None:
        store = SlackThreadStore(tmp_path)
        store.register("D123", "ts1", "conv1")
        store.register("D123", "ts2", "conv2")
        store.register("D456", "ts1", "conv3")

        assert store.get_conversation_id("D123", "ts1") == "conv1"
        assert store.get_conversation_id("D123", "ts2") == "conv2"
        assert store.get_conversation_id("D456", "ts1") == "conv3"

    def test_corrupted_json_handled(self, tmp_path: Path) -> None:
        json_path = tmp_path / "slack_threads.json"
        json_path.write_text("not valid json{{{")

        store = SlackThreadStore(tmp_path)
        assert store.get_conversation_id("D123", "ts1") is None

    def test_state_dir_created_on_save(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "nested" / "dir"
        store = SlackThreadStore(state_dir)
        store.register("D123", "ts1", "conv1")
        assert (state_dir / "slack_threads.json").exists()

    def test_non_dict_json_ignored(self, tmp_path: Path) -> None:
        json_path = tmp_path / "slack_threads.json"
        json_path.write_text('["not", "a", "dict"]')

        store = SlackThreadStore(tmp_path)
        assert store.get_conversation_id("D123", "ts1") is None

    def test_save_error_handled(self, tmp_path: Path) -> None:
        """Write errors during save are logged but not raised."""
        from unittest.mock import patch

        store = SlackThreadStore(tmp_path)
        # Make the save fail by patching open to raise
        with patch("builtins.open", side_effect=OSError("disk full")):
            store.register("D123", "ts1", "conv1")
        # Data is in memory even though save failed
        assert store.get_conversation_id("D123", "ts1") == "conv1"
