# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackPlanStreamer."""

from unittest.mock import MagicMock, patch

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.models.messages.chunk import TaskUpdateChunk

from airut.dashboard.tracker import TodoItem, TodoStatus
from airut.gateway.slack.plan_streamer import (
    SlackPlanStreamer,
    _build_task_chunks,
)


def _make_streamer() -> tuple[SlackPlanStreamer, MagicMock]:
    """Create a plan streamer with a mock WebClient."""
    client = MagicMock(spec=WebClient)
    stream_mock = MagicMock()
    client.chat_stream.return_value = stream_mock
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


class TestBuildTaskChunks:
    def test_maps_statuses_correctly(self) -> None:
        items = _make_items(
            TodoStatus.PENDING,
            TodoStatus.IN_PROGRESS,
            TodoStatus.COMPLETED,
        )
        chunks = _build_task_chunks(items)

        assert len(chunks) == 3
        assert all(isinstance(c, TaskUpdateChunk) for c in chunks)

        assert chunks[0].id == "task_0"
        assert chunks[0].title == "Working on task 0"
        assert chunks[0].status == "pending"

        assert chunks[1].id == "task_1"
        assert chunks[1].title == "Working on task 1"
        assert chunks[1].status == "in_progress"

        assert chunks[2].id == "task_2"
        assert chunks[2].title == "Working on task 2"
        assert chunks[2].status == "complete"

    def test_empty_list(self) -> None:
        chunks = _build_task_chunks([])
        assert chunks == []

    def test_falls_back_to_content_when_no_active_form(self) -> None:
        items = [TodoItem(content="Run tests", status=TodoStatus.PENDING)]
        chunks = _build_task_chunks(items)
        assert chunks[0].title == "Run tests"

    def test_uses_active_form_over_content(self) -> None:
        items = [
            TodoItem(
                content="Run tests",
                status=TodoStatus.IN_PROGRESS,
                active_form="Running tests",
            )
        ]
        chunks = _build_task_chunks(items)
        assert chunks[0].title == "Running tests"


class TestSlackPlanStreamerUpdate:
    def test_first_update_starts_stream(self) -> None:
        streamer, client = _make_streamer()
        items = _make_items(TodoStatus.IN_PROGRESS)

        streamer.update(items)

        client.chat_stream.assert_called_once_with(
            channel="D123",
            thread_ts="ts1",
            task_display_mode="plan",
        )
        stream = client.chat_stream.return_value
        stream.append.assert_called_once()
        chunks = stream.append.call_args[1]["chunks"]
        assert len(chunks) == 1

    def test_subsequent_update_appends(self) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        # Patch monotonic for the entire sequence:
        # call 1: update() reads now=0.0 (first update, stream is None)
        # call 2: _last_append_time set to 0.0
        # call 3: update() reads now=1.0 (second update, elapsed=1.0 > 0.5)
        # call 4: _last_append_time set to 1.0
        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 1.0, 1.0],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))
            streamer.update(
                _make_items(TodoStatus.IN_PROGRESS, TodoStatus.PENDING)
            )

        assert stream.append.call_count == 2

    def test_debounce_skips_rapid_updates(self) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        # Patch monotonic for the entire sequence:
        # call 1: first update() reads now=0.0 (stream is None, no debounce)
        # call 2: _last_append_time set to 0.0
        # call 3: second update() reads now=0.1 (elapsed=0.1 < 0.5)
        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 0.1],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))
            assert stream.append.call_count == 1

            streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # Should still be 1 — debounced
        assert stream.append.call_count == 1

    def test_api_error_non_fatal(self) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value
        stream.append.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise
        streamer.update(_make_items(TodoStatus.PENDING))

    def test_start_stream_api_error_non_fatal(self) -> None:
        streamer, client = _make_streamer()
        client.chat_stream.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise (caught by the outer try/except)
        streamer.update(_make_items(TodoStatus.PENDING))


class TestSlackPlanStreamerFinalize:
    def test_stops_active_stream(self) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))
        streamer.finalize()

        stream.stop.assert_called_once()

    def test_noop_when_never_started(self) -> None:
        streamer, client = _make_streamer()

        # Should not raise or make API calls
        streamer.finalize()
        client.chat_stream.assert_not_called()

    def test_api_error_non_fatal(self) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value
        stream.stop.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # Should not raise
        streamer.finalize()
