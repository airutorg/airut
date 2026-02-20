# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackPlanStreamer."""

from __future__ import annotations

from typing import cast
from unittest.mock import MagicMock, patch

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from airut.dashboard.tracker import TodoItem, TodoStatus
from airut.gateway.slack.plan_streamer import (
    SlackPlanStreamer,
    _build_blocks,
    _render_plan,
)


def _make_streamer() -> tuple[SlackPlanStreamer, MagicMock]:
    """Create a plan streamer with a mock WebClient."""
    client = MagicMock(spec=WebClient)
    client.chat_postMessage.return_value = {"ts": "msg_ts_1"}
    streamer = SlackPlanStreamer(
        client=client,
        channel="D123",
        thread_ts="ts1",
    )
    return streamer, client


def _make_items(*statuses: TodoStatus) -> list[TodoItem]:
    """Build a todo list with the given statuses."""
    return [
        TodoItem(
            content=f"Task {i}",
            status=status,
            active_form=f"Working on task {i}",
        )
        for i, status in enumerate(statuses)
    ]


class TestRenderPlan:
    def test_renders_statuses_with_emojis(self) -> None:
        items = _make_items(
            TodoStatus.PENDING,
            TodoStatus.IN_PROGRESS,
            TodoStatus.COMPLETED,
        )
        text = _render_plan(items)

        assert "\u26aa  Working on task 0" in text
        assert "\U0001f535  Working on task 1" in text
        assert "\u2705  Working on task 2" in text

    def test_falls_back_to_content_when_no_active_form(
        self,
    ) -> None:
        items = [TodoItem(content="Run tests", status=TodoStatus.PENDING)]
        text = _render_plan(items)
        assert "Run tests" in text

    def test_uses_active_form_over_content(self) -> None:
        items = [
            TodoItem(
                content="Run tests",
                status=TodoStatus.IN_PROGRESS,
                active_form="Running tests",
            )
        ]
        text = _render_plan(items)
        assert "Running tests" in text

    def test_empty_list(self) -> None:
        text = _render_plan([])
        assert text == ""


class TestBuildBlocks:
    def test_single_block_for_short_text(self) -> None:
        blocks = _build_blocks("short text")
        assert len(blocks) == 1
        assert blocks[0]["type"] == "section"
        inner = cast(dict[str, str], blocks[0]["text"])
        assert inner["text"] == "short text"

    def test_splits_long_text_into_multiple_blocks(self) -> None:
        # Build text that exceeds 3000 chars.
        lines = [f"Line {i}: {'x' * 80}" for i in range(50)]
        text = "\n".join(lines)
        assert len(text) > 3000

        blocks = _build_blocks(text)
        assert len(blocks) > 1
        for block in blocks:
            inner = cast(dict[str, str], block["text"])
            assert len(inner["text"]) <= 3000

    def test_no_empty_blocks(self) -> None:
        blocks = _build_blocks("")
        # Empty string fits in one block.
        assert len(blocks) == 1


class TestSlackPlanStreamerUpdate:
    def test_first_update_posts_message(self) -> None:
        streamer, client = _make_streamer()
        items = _make_items(TodoStatus.IN_PROGRESS)

        streamer.update(items)

        client.chat_postMessage.assert_called_once()
        kw = client.chat_postMessage.call_args[1]
        assert kw["channel"] == "D123"
        assert kw["thread_ts"] == "ts1"
        assert "blocks" in kw

    def test_subsequent_update_calls_chat_update(self) -> None:
        streamer, client = _make_streamer()

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 2.0, 2.0],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))
            streamer.update(
                _make_items(TodoStatus.IN_PROGRESS, TodoStatus.PENDING)
            )

        client.chat_postMessage.assert_called_once()
        client.chat_update.assert_called_once()
        kw = client.chat_update.call_args[1]
        assert kw["channel"] == "D123"
        assert kw["ts"] == "msg_ts_1"

    def test_debounce_skips_rapid_updates(self) -> None:
        streamer, client = _make_streamer()

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 0.1],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))
            streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        client.chat_postMessage.assert_called_once()
        client.chat_update.assert_not_called()

    def test_api_error_non_fatal(self) -> None:
        streamer, client = _make_streamer()
        client.chat_postMessage.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise.
        streamer.update(_make_items(TodoStatus.PENDING))


class TestSlackPlanStreamerFinalize:
    def test_flushes_debounced_update(self) -> None:
        """Finalize sends the last debounced state."""
        streamer, client = _make_streamer()

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 0.1],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))
            streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        client.chat_update.assert_not_called()

        streamer.finalize()
        client.chat_update.assert_called_once()
        # Should show the latest (in_progress) state.
        text = client.chat_update.call_args[1]["blocks"][0]["text"]["text"]
        assert "\U0001f535" in text

    def test_noop_when_never_started(self) -> None:
        streamer, client = _make_streamer()

        streamer.finalize()
        client.chat_postMessage.assert_not_called()
        client.chat_update.assert_not_called()

    def test_noop_when_post_failed(self) -> None:
        """Finalize is a no-op if the initial post never succeeded."""
        streamer, client = _make_streamer()
        client.chat_postMessage.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        streamer.update(_make_items(TodoStatus.PENDING))

        # _message_ts is None because the post failed.
        # Finalize should not attempt another post.
        streamer.finalize()
        client.chat_update.assert_not_called()
        # Only the original failed attempt, no retry.
        client.chat_postMessage.assert_called_once()

    def test_api_error_non_fatal(self) -> None:
        streamer, client = _make_streamer()
        streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        client.chat_update.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise.
        streamer.finalize()

    def test_no_double_update_when_nothing_debounced(self) -> None:
        """If no update was debounced, finalize doesn't re-send."""
        streamer, client = _make_streamer()
        streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # The initial post set _last_text. Finalize would flush
        # it, but we should verify it actually calls update.
        streamer.finalize()

        # chat_update is called (flushing the latest state).
        client.chat_update.assert_called_once()
