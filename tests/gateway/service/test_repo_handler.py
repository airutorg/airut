# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for repo_handler module."""

import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.service.repo_handler import RepoHandler

from .conftest import make_message, make_service


class TestSubmitMessage:
    def test_forwards_to_service(self, email_config, tmp_path: Path) -> None:
        """Raw message is forwarded to service.submit_message."""
        svc, handler = make_service(email_config, tmp_path)
        svc.submit_message = MagicMock(return_value=True)
        adapter = handler.adapters["email"]

        msg = make_message()
        assert handler._submit_message(msg, adapter) is True
        svc.submit_message.assert_called_once_with(msg, handler, adapter)

    def test_returns_false_when_pool_not_ready(
        self, email_config, tmp_path: Path
    ) -> None:
        """Returns False when service.submit_message returns False."""
        svc, handler = make_service(email_config, tmp_path)
        svc.submit_message = MagicMock(return_value=False)
        adapter = handler.adapters["email"]

        msg = make_message()
        assert handler._submit_message(msg, adapter) is False


class TestStartListener:
    def test_updates_mirror_and_starts_listener(
        self, email_config, tmp_path: Path
    ) -> None:
        """start_listener updates mirror and starts listeners."""
        svc, handler = make_service(email_config, tmp_path)

        handler.start_listener()

        handler.conversation_manager.mirror.update_mirror.assert_called_once()
        handler.adapters["email"].listener.start.assert_called_once()

    def test_submit_callback_forwards_to_service(
        self, email_config, tmp_path: Path
    ) -> None:
        """The submit callback passed to listener.start forwards messages."""
        svc, handler = make_service(email_config, tmp_path)
        svc.submit_message = MagicMock(return_value=True)

        handler.start_listener()

        # Extract the submit callback passed to listener.start
        adapter = handler.adapters["email"]
        call_args = adapter.listener.start.call_args
        submit_fn = call_args[1]["submit"]

        msg = make_message()
        result = submit_fn(msg)
        assert result is True
        svc.submit_message.assert_called_once_with(msg, handler, adapter)


class TestStartListenerFailure:
    """A repo whose listeners do not all start runs none of them.

    Regression: listeners started before the failing one kept running
    for a repo recorded as failed (or, on reload, alongside the
    rolled-back listeners), receiving messages nobody tracked.
    """

    @staticmethod
    def _adapters(handler, *channel_types: str) -> list[MagicMock]:
        adapters = {ct: MagicMock() for ct in channel_types}
        handler.adapters = adapters
        return list(adapters.values())

    def test_stops_started_and_remaining_listeners(
        self, email_config, tmp_path: Path
    ) -> None:
        """All listeners are stopped and the start error propagates."""
        _, handler = make_service(email_config, tmp_path)
        first, failing, never_started = self._adapters(
            handler, "email", "slack", "other"
        )
        failing.listener.start.side_effect = RuntimeError("auth failed")

        with pytest.raises(RuntimeError, match="auth failed"):
            handler.start_listener()

        never_started.listener.start.assert_not_called()
        for adapter in (first, failing, never_started):
            adapter.listener.stop.assert_called_once()

    def test_mirror_failure_stops_listeners(
        self, email_config, tmp_path: Path
    ) -> None:
        """A failed mirror update also releases the listeners."""
        _, handler = make_service(email_config, tmp_path)
        (adapter,) = self._adapters(handler, "email")
        handler.conversation_manager.mirror.update_mirror.side_effect = (
            RuntimeError("clone failed")
        )

        with pytest.raises(RuntimeError, match="clone failed"):
            handler.start_listener()

        adapter.listener.start.assert_not_called()
        adapter.listener.stop.assert_called_once()

    def test_stop_error_does_not_mask_start_error(
        self, email_config, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A listener that fails to stop is logged; the rest still stop."""
        _, handler = make_service(email_config, tmp_path)
        first, failing, last = self._adapters(
            handler, "email", "slack", "other"
        )
        failing.listener.start.side_effect = RuntimeError("auth failed")
        failing.listener.stop.side_effect = OSError("already closed")

        with pytest.raises(RuntimeError, match="auth failed"):
            handler.start_listener()

        first.listener.stop.assert_called_once()
        last.listener.stop.assert_called_once()
        assert "failed to stop listener (channel=slack)" in caplog.text


class TestStop:
    def test_stops_listener(self, email_config, tmp_path: Path) -> None:
        """stop() delegates to each adapter's listener.stop()."""
        svc, handler = make_service(email_config, tmp_path)

        handler.stop()

        handler.adapters["email"].listener.stop.assert_called_once()

    def test_stops_others_when_one_fails(
        self, email_config, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A listener failing to stop does not leave the others running."""
        _, handler = make_service(email_config, tmp_path)
        failing, other = MagicMock(), MagicMock()
        failing.listener.stop.side_effect = RuntimeError("boom")
        handler.adapters = {"email": failing, "slack": other}

        handler.stop()

        other.listener.stop.assert_called_once()
        assert "failed to stop listener (channel=email)" in caplog.text

    def test_concurrent_stops_do_not_overlap(
        self, email_config, tmp_path: Path
    ) -> None:
        """Two threads stopping the handler stop each listener in turn.

        A failed start stops the listeners itself, possibly while the
        service is stopping them on another thread; listeners do not
        support concurrent stops.
        """
        _, handler = make_service(email_config, tmp_path)
        adapter = handler.adapters["email"]
        second_entered = threading.Event()
        calls = 0
        overlapped = False

        def stop() -> None:
            nonlocal calls, overlapped
            calls += 1
            if calls == 1:
                # Give the other thread the chance to enter stop() too.
                overlapped = second_entered.wait(timeout=0.2)
            else:
                second_entered.set()

        adapter.listener.stop.side_effect = stop
        barrier = threading.Barrier(2)

        def stop_handler() -> None:
            barrier.wait()
            handler.stop()

        threads = [threading.Thread(target=stop_handler) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert calls == 2
        assert not overlapped


class TestInit:
    def test_clone_failure_creates_no_adapters(
        self, email_config, tmp_path: Path
    ) -> None:
        """The repo is cloned before adapters, which a failure would leak."""
        with (
            patch(
                "airut.gateway.service.repo_handler.ConversationManager",
                side_effect=RuntimeError("clone failed"),
            ),
            patch(
                "airut.gateway.service.repo_handler.create_adapters"
            ) as mock_create,
            pytest.raises(RuntimeError, match="clone failed"),
        ):
            RepoHandler(email_config, MagicMock())

        mock_create.assert_not_called()


class TestChannelStatuses:
    def test_returns_listener_status_per_channel(
        self, email_config, tmp_path: Path
    ) -> None:
        """channel_statuses() reports each adapter's listener status."""
        from airut.gateway.channel import ChannelHealth, ChannelStatus

        svc, handler = make_service(email_config, tmp_path)
        degraded = ChannelStatus(health=ChannelHealth.DEGRADED, message="x")
        handler.adapters["email"].listener.status = degraded

        assert handler.channel_statuses() == {"email": degraded}
