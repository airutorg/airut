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


#: Patch target for threading.Timer used by the keepalive.
_TIMER_PATCH = "airut.gateway.slack.plan_streamer.threading.Timer"


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

    def test_action_summary_on_first_in_progress(self) -> None:
        """Action summary attaches to first in-progress task."""
        items = _make_items(
            TodoStatus.COMPLETED,
            TodoStatus.IN_PROGRESS,
            TodoStatus.PENDING,
        )
        chunks = _build_task_chunks(items, action_summary="Reading main.py")

        assert chunks[0].details is None  # completed
        assert chunks[1].details == "Reading main.py"  # in_progress
        assert chunks[2].details is None  # pending

    def test_action_summary_only_on_first_in_progress(self) -> None:
        """Only the first in-progress task gets the action summary."""
        items = _make_items(
            TodoStatus.IN_PROGRESS,
            TodoStatus.IN_PROGRESS,
        )
        chunks = _build_task_chunks(items, action_summary="Editing file")

        assert chunks[0].details == "Editing file"
        assert chunks[1].details is None

    def test_no_action_summary_no_details(self) -> None:
        """Without action_summary, no details are set."""
        items = _make_items(TodoStatus.IN_PROGRESS)
        chunks = _build_task_chunks(items)

        assert chunks[0].details is None

    def test_action_summary_skipped_when_no_in_progress(self) -> None:
        """If no in-progress task exists, action summary is not attached."""
        items = _make_items(TodoStatus.PENDING, TodoStatus.COMPLETED)
        chunks = _build_task_chunks(items, action_summary="Running tests")

        assert all(c.details is None for c in chunks)


class TestSlackPlanStreamerUpdate:
    @patch(_TIMER_PATCH)
    def test_first_update_starts_stream(self, _timer_cls: MagicMock) -> None:
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

    @patch(_TIMER_PATCH)
    def test_subsequent_update_appends(self, _timer_cls: MagicMock) -> None:
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

    @patch(_TIMER_PATCH)
    def test_debounce_skips_rapid_updates(self, _timer_cls: MagicMock) -> None:
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

    @patch(_TIMER_PATCH)
    def test_api_error_non_fatal(self, _timer_cls: MagicMock) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value
        stream.append.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise
        streamer.update(_make_items(TodoStatus.PENDING))

    @patch(_TIMER_PATCH)
    def test_start_stream_api_error_non_fatal(
        self, _timer_cls: MagicMock
    ) -> None:
        streamer, client = _make_streamer()
        client.chat_stream.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise (caught by the outer try/except)
        streamer.update(_make_items(TodoStatus.PENDING))

    @patch(_TIMER_PATCH)
    def test_stream_expired_restarts_stream(
        self, _timer_cls: MagicMock
    ) -> None:
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

    @patch(_TIMER_PATCH)
    def test_stream_expired_retry_failure_non_fatal(
        self, _timer_cls: MagicMock
    ) -> None:
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


class TestSlackPlanStreamerUpdateAction:
    @patch(_TIMER_PATCH)
    def test_action_starts_stream_in_no_plan_mode(
        self, _timer_cls: MagicMock
    ) -> None:
        """update_action() starts a stream with a synthetic task."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        streamer.update_action("Reading main.py")

        client.chat_stream.assert_called_once()
        stream.append.assert_called_once()
        chunks = stream.append.call_args[1]["chunks"]
        assert len(chunks) == 1
        assert chunks[0].id == "action"
        assert chunks[0].title == "Reading main.py"
        assert chunks[0].status == "in_progress"

    @patch(_TIMER_PATCH)
    def test_action_with_todo_items_uses_details(
        self, _timer_cls: MagicMock
    ) -> None:
        """When todos exist, action is shown as details on in-progress task."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 1.0, 1.0],
        ):
            streamer.update(_make_items(TodoStatus.IN_PROGRESS))
            streamer.update_action("Running pytest")

        assert stream.append.call_count == 2
        # Second call should have details on the in-progress task
        chunks = stream.append.call_args_list[1][1]["chunks"]
        assert chunks[0].details == "Running pytest"

    @patch(_TIMER_PATCH)
    def test_action_debounced(self, _timer_cls: MagicMock) -> None:
        """Rapid update_action() calls are debounced."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 0.1],
        ):
            streamer.update_action("Reading file A")
            streamer.update_action("Reading file B")

        assert stream.append.call_count == 1

    @patch(_TIMER_PATCH)
    def test_debounced_action_updates_last_chunks(
        self, _timer_cls: MagicMock
    ) -> None:
        """Debounced action still updates _last_chunks for keepalive."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 0.1],
        ):
            streamer.update_action("Reading file A")
            streamer.update_action("Reading file B")

        # Keepalive should use latest action.
        streamer._keepalive_tick()
        keepalive_chunks = stream.append.call_args_list[1][1]["chunks"]
        assert keepalive_chunks[0].title == "Reading file B"

    @patch(_TIMER_PATCH)
    def test_update_preserves_action_summary(
        self, _timer_cls: MagicMock
    ) -> None:
        """update() after update_action() preserves the action summary."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 1.0, 1.0],
        ):
            streamer.update_action("Running pytest")
            streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # The update() should include the action summary as details.
        chunks = stream.append.call_args_list[1][1]["chunks"]
        assert chunks[0].details == "Running pytest"

    @patch(_TIMER_PATCH)
    def test_action_api_error_non_fatal(self, _timer_cls: MagicMock) -> None:
        """API error on update_action() doesn't raise."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value
        stream.append.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise.
        streamer.update_action("Reading file")


class TestSlackPlanStreamerFinalize:
    @patch(_TIMER_PATCH)
    def test_stops_active_stream(self, _timer_cls: MagicMock) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))
        streamer.finalize()

        stream.stop.assert_called_once_with()

    @patch(_TIMER_PATCH)
    def test_noop_when_never_started(self, _timer_cls: MagicMock) -> None:
        streamer, client = _make_streamer()

        # Should not raise or make API calls
        streamer.finalize()
        client.chat_stream.assert_not_called()

    @patch(_TIMER_PATCH)
    def test_api_error_non_fatal(self, _timer_cls: MagicMock) -> None:
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value
        stream.stop.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # Should not raise
        streamer.finalize()

    @patch(_TIMER_PATCH)
    def test_stream_expired_on_finalize_is_silent(
        self, _timer_cls: MagicMock
    ) -> None:
        """Finalizing an already-expired stream is a no-op."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value
        stream.stop.side_effect = _stream_expired_error()

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # Should not raise or warn — the stream was already stopped.
        streamer.finalize()

    @patch(_TIMER_PATCH)
    def test_finalize_cancels_keepalive(self, timer_cls: MagicMock) -> None:
        """Finalize cancels the pending keepalive timer."""
        streamer, _client = _make_streamer()
        timer_instance = timer_cls.return_value

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))
        streamer.finalize()

        timer_instance.cancel.assert_called()

    @patch(_TIMER_PATCH)
    def test_finalize_no_plan_mode_marks_complete(
        self, _timer_cls: MagicMock
    ) -> None:
        """In no-plan mode, finalize marks the action task complete."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        streamer.update_action("Running tests")
        streamer.finalize()

        # stop() should be called with final chunks
        stream.stop.assert_called_once()
        final_chunks = stream.stop.call_args[1]["chunks"]
        assert len(final_chunks) == 1
        assert final_chunks[0].id == "action"
        assert final_chunks[0].status == "complete"
        assert final_chunks[0].title == "Running tests"

    @patch(_TIMER_PATCH)
    def test_finalize_plan_mode_no_final_chunks(
        self, _timer_cls: MagicMock
    ) -> None:
        """When todos exist, finalize calls stop() without chunks."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 1.0, 1.0],
        ):
            streamer.update(_make_items(TodoStatus.IN_PROGRESS))
            streamer.update_action("Reading file")

        streamer.finalize()
        stream.stop.assert_called_once_with()


class TestKeepalive:
    @patch(_TIMER_PATCH)
    def test_update_schedules_keepalive(self, timer_cls: MagicMock) -> None:
        """Each successful update() starts a keepalive timer."""
        streamer, _client = _make_streamer()
        timer_instance = timer_cls.return_value

        streamer.update(_make_items(TodoStatus.PENDING))

        timer_cls.assert_called_once()
        # Timer target is _keepalive_tick.
        assert timer_cls.call_args[0][1] == streamer._keepalive_tick
        timer_instance.start.assert_called_once()

    @patch(_TIMER_PATCH)
    def test_keepalive_timer_is_daemon(self, timer_cls: MagicMock) -> None:
        """Keepalive timer should be a daemon thread."""
        streamer, _client = _make_streamer()
        timer_instance = timer_cls.return_value

        streamer.update(_make_items(TodoStatus.PENDING))

        assert timer_instance.daemon is True

    @patch(_TIMER_PATCH)
    def test_keepalive_tick_resends_last_chunks(
        self, timer_cls: MagicMock
    ) -> None:
        """The keepalive tick re-sends the last task state."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))
        assert stream.append.call_count == 1

        # Simulate the timer firing by calling _keepalive_tick directly.
        streamer._keepalive_tick()

        assert stream.append.call_count == 2
        # The second append used the same chunks as the first.
        first_chunks = stream.append.call_args_list[0][1]["chunks"]
        second_chunks = stream.append.call_args_list[1][1]["chunks"]
        assert first_chunks == second_chunks

    @patch(_TIMER_PATCH)
    def test_keepalive_tick_reschedules(self, timer_cls: MagicMock) -> None:
        """After a successful keepalive, a new timer is scheduled."""
        streamer, _client = _make_streamer()

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))
        initial_call_count = timer_cls.call_count

        streamer._keepalive_tick()

        # A new Timer was created for the next keepalive.
        assert timer_cls.call_count == initial_call_count + 1

    @patch(_TIMER_PATCH)
    def test_keepalive_tick_noop_without_stream(
        self, timer_cls: MagicMock
    ) -> None:
        """Keepalive tick does nothing if stream was never started."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        # Never called update(), so _stream is None.
        streamer._keepalive_tick()

        stream.append.assert_not_called()

    @patch(_TIMER_PATCH)
    def test_keepalive_tick_api_error_non_fatal(
        self, timer_cls: MagicMock
    ) -> None:
        """Keepalive append failure doesn't raise."""
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # Make the keepalive append fail.
        stream.append.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        # Should not raise.
        streamer._keepalive_tick()

    @patch(_TIMER_PATCH)
    def test_keepalive_cancelled_on_stream_expiry_recovery(
        self, timer_cls: MagicMock
    ) -> None:
        """When stream expires and restarts, old timer is cancelled."""
        streamer, client = _make_streamer()
        old_stream = client.chat_stream.return_value
        timer_instance = timer_cls.return_value

        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 1.0, 1.0],
        ):
            streamer.update(_make_items(TodoStatus.PENDING))

            old_stream.append.side_effect = _stream_expired_error()
            new_stream = MagicMock()
            client.chat_stream.return_value = new_stream

            streamer.update(_make_items(TodoStatus.IN_PROGRESS))

        # Timer was cancelled during expiry recovery, then rescheduled.
        timer_instance.cancel.assert_called()

    @patch(_TIMER_PATCH)
    def test_debounced_update_refreshes_chunks_for_keepalive(
        self, _timer_cls: MagicMock
    ) -> None:
        """Debounced update() still updates _last_chunks.

        When a rapid update is debounced (no API call), the keepalive
        should re-send the *latest* items, not stale data from the
        previous successful append.
        """
        streamer, client = _make_streamer()
        stream = client.chat_stream.return_value

        initial_items = _make_items(TodoStatus.PENDING)
        updated_items = _make_items(TodoStatus.IN_PROGRESS)

        # call 1: first update() now=0.0 (stream is None, no debounce)
        # call 2: _last_append_time = 0.0
        # call 3: second update() now=0.1 (debounced)
        with patch(
            "airut.gateway.slack.plan_streamer.time.monotonic",
            side_effect=[0.0, 0.0, 0.1],
        ):
            streamer.update(initial_items)
            streamer.update(updated_items)

        # Only one real append happened (the first).
        assert stream.append.call_count == 1

        # Now simulate keepalive firing.
        streamer._keepalive_tick()

        # The keepalive should use the debounced (newer) chunks.
        keepalive_chunks = stream.append.call_args_list[1][1]["chunks"]
        assert keepalive_chunks[0].status == "in_progress"


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
