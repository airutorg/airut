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
    _content_id,
    _is_stream_expired,
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


def _stream_expired_error() -> SlackApiError:
    """Create a SlackApiError for stream expiry."""
    resp = MagicMock(
        status_code=400,
        data={"ok": False, "error": "message_not_in_streaming_state"},
    )
    return SlackApiError(message="expired", response=resp)


class TestContentId:
    def test_deterministic(self) -> None:
        assert _content_id("Run tests") == _content_id("Run tests")

    def test_different_for_different_content(self) -> None:
        assert _content_id("Run tests") != _content_id("Fix lint")

    def test_returns_8_hex_chars(self) -> None:
        result = _content_id("anything")
        assert len(result) == 8
        int(result, 16)  # Must be valid hex


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

        assert chunks[0].id == _content_id("Task 0")
        assert chunks[0].title == "Working on task 0"
        assert chunks[0].status == "pending"

        assert chunks[1].id == _content_id("Task 1")
        assert chunks[1].title == "Working on task 1"
        assert chunks[1].status == "in_progress"

        assert chunks[2].id == _content_id("Task 2")
        assert chunks[2].title == "Working on task 2"
        assert chunks[2].status == "complete"

    def test_ids_stable_across_reordering(self) -> None:
        """IDs stay the same when items are reordered."""
        items_a = [
            TodoItem(content="Run tests", status=TodoStatus.PENDING),
            TodoItem(content="Fix lint", status=TodoStatus.IN_PROGRESS),
        ]
        items_b = list(reversed(items_a))

        chunks_a = _build_task_chunks(items_a)
        chunks_b = _build_task_chunks(items_b)

        # Same content → same ID regardless of position.
        assert chunks_a[0].id == chunks_b[1].id  # "Run tests"
        assert chunks_a[1].id == chunks_b[0].id  # "Fix lint"

    def test_duplicate_content_gets_unique_ids(self) -> None:
        items = [
            TodoItem(content="Deploy", status=TodoStatus.PENDING),
            TodoItem(content="Deploy", status=TodoStatus.PENDING),
        ]
        chunks = _build_task_chunks(items)
        assert chunks[0].id != chunks[1].id

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

    def test_stream_expired_restarts_stream(self) -> None:
        """When Slack expires the stream, a new one is started."""
        streamer, client = _make_streamer()
        old_stream = client.chat_stream.return_value

        # Patch monotonic for the full sequence:
        #   call 1: first update() now=0.0 (stream is None, no debounce)
        #   call 2: _last_append_time = 0.0
        #   call 3: second update() now=1.0 (elapsed=1.0 > 0.5)
        #   call 4: _last_append_time = 1.0 (after successful retry)
        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 1.0, 1.0],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))
            assert client.chat_stream.call_count == 1

            # The second append fails with stream-expired error.
            old_stream.append.side_effect = _stream_expired_error()

            # Provide a fresh stream mock for the retry.
            new_stream = MagicMock()
            client.chat_stream.return_value = new_stream

            streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # chat_stream was called again to create a replacement stream.
        assert client.chat_stream.call_count == 2
        new_stream.append.assert_called_once()

    def test_stream_expired_retry_failure_non_fatal(self) -> None:
        """If the retry after stream expiry also fails, it's non-fatal."""
        streamer, client = _make_streamer()
        old_stream = client.chat_stream.return_value

        # Patch monotonic for the full sequence:
        #   call 1: first update() now=0.0 (stream is None)
        #   call 2: _last_append_time = 0.0
        #   call 3: second update() now=1.0 (elapsed=1.0 > 0.5)
        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 1.0],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))

            old_stream.append.side_effect = _stream_expired_error()
            # Retry also fails.
            client.chat_stream.side_effect = SlackApiError(
                message="error",
                response=MagicMock(status_code=500, data={}),
            )

            # Should not raise.
            streamer.update(_make_items(TodoStatus.IN_PROGRESS))


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

    def test_stream_expired_on_finalize_is_silent(self) -> None:
        """Finalizing an already-expired stream is a no-op."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value
        stream.stop.side_effect = _stream_expired_error()

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # Should not raise or warn — the stream was already stopped.
        streamer.finalize()


class TestIsStreamExpired:
    def test_matches_stream_expired_error(self) -> None:
        assert _is_stream_expired(_stream_expired_error()) is True

    def test_rejects_other_errors(self) -> None:
        err = SlackApiError(
            message="other",
            response=MagicMock(status_code=500, data={"error": "other"}),
        )
        assert _is_stream_expired(err) is False

    def test_handles_missing_data(self) -> None:
        err = SlackApiError(
            message="weird",
            response=MagicMock(spec=[]),
        )
        assert _is_stream_expired(err) is False
