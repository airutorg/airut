# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for Slack thread history helpers.

Replay behavior is exercised end to end through the adapter in
``test_adapter.py``; these cover the standalone helpers.
"""

from airut._json_types import JsonValue
from airut.gateway.slack.thread_history import ThreadReplay, extract_file_urls


class TestThreadReplayPreamble:
    def test_empty_replay_has_no_preamble(self) -> None:
        assert ThreadReplay().preamble == ""
        assert ThreadReplay(catch_up=True).preamble == ""

    def test_invited_intro(self) -> None:
        replay = ThreadReplay(lines=["[Bob]: hi"])
        assert replay.preamble.startswith("The user invited you")
        assert replay.preamble.endswith(".\n[Bob]: hi")

    def test_catch_up_intro(self) -> None:
        replay = ThreadReplay(lines=["[Bob]: hi"], catch_up=True)
        assert replay.preamble.startswith(
            "In this Slack thread you only receive messages that mention you."
        )
        assert replay.preamble.endswith(".\n[Bob]: hi")


class TestExtractFileUrls:
    def test_extracts_download_url(self) -> None:
        files: JsonValue = [
            {
                "name": "a.txt",
                "url_private_download": "https://files.slack.com/a",
            }
        ]
        assert extract_file_urls(files) == [
            ("a.txt", "https://files.slack.com/a")
        ]

    def test_falls_back_to_url_private(self) -> None:
        files: JsonValue = [
            {"name": "a.txt", "url_private": "https://files.slack.com/a"}
        ]
        assert extract_file_urls(files) == [
            ("a.txt", "https://files.slack.com/a")
        ]

    def test_non_list_yields_empty(self) -> None:
        assert extract_file_urls(None) == []

    def test_non_dict_entries_skipped(self) -> None:
        files: JsonValue = [
            "not-a-dict",
            {"name": "a.txt", "url_private": "https://files.slack.com/a"},
        ]
        assert extract_file_urls(files) == [
            ("a.txt", "https://files.slack.com/a")
        ]

    def test_file_without_url_skipped(self) -> None:
        assert extract_file_urls([{"name": "a.txt"}]) == []
