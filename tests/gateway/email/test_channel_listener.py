# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for EmailChannelListener."""

from email.message import Message
from email.parser import BytesParser
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.channel import ChannelHealth, RawMessage
from airut.gateway.config import EmailChannelConfig
from airut.gateway.email.channel_listener import EmailChannelListener
from airut.gateway.email.listener import IMAPConnectionError, IMAPIdleError


def _make_config(
    **overrides: Any,  # noqa: ANN401 - unpacked into mixed-type constructor
) -> EmailChannelConfig:
    """Build an EmailChannelConfig with test defaults."""
    defaults: dict[str, Any] = {
        "imap_server": "imap.example.com",
        "imap_port": 993,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "account_username": "test@example.com",
        "account_password": "test_password",
        "account_from_address": "Test <test@example.com>",
        "auth_authorized_senders": ["user@example.com"],
        "auth_trusted_authserv_id": "mx.example.com",
    }
    defaults.update(overrides)
    return EmailChannelConfig(**defaults)


def _make_message(subject: str = "Test") -> Message:
    """Build a simple email Message for testing."""
    raw = (
        f"From: user@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: <msg1@example.com>\r\n"
        f"\r\nHello"
    )
    return BytesParser().parsebytes(raw.encode())


def _make_polling_listener() -> tuple[EmailChannelListener, MagicMock]:
    """Create a listener configured for polling.

    Pre-sets the stop event so that ``_stop_event.wait()`` returns
    immediately (same effect as patching ``time.sleep`` to a no-op).

    Returns:
        Tuple of (listener, mock_email_listener).
    """
    config = _make_config(imap_use_idle=False, imap_poll_interval_seconds=1)
    mock_el = MagicMock()
    cl = EmailChannelListener(config, email_listener=mock_el, repo_id="test")
    cl._running = True
    cl._stop_event.set()
    return cl, mock_el


def _make_idle_listener(
    **overrides: Any,  # noqa: ANN401 - unpacked into mixed-type constructor
) -> tuple[EmailChannelListener, MagicMock]:
    """Create a listener configured for IDLE mode.

    Pre-sets the stop event so that ``_stop_event.wait()`` returns
    immediately during reconnection backoff.

    Returns:
        Tuple of (listener, mock_email_listener).
    """
    config_kwargs: dict[str, Any] = {
        "imap_use_idle": True,
        "imap_idle_reconnect_interval_seconds": 99999,
    }
    config_kwargs.update(overrides)
    config = _make_config(**config_kwargs)
    mock_el = MagicMock()
    cl = EmailChannelListener(config, email_listener=mock_el, repo_id="test")
    cl._running = True
    cl._stop_event.set()
    cl._submit = MagicMock()
    return cl, mock_el


@pytest.fixture
def listener_and_mock():
    """Create an EmailChannelListener with a mocked EmailListener."""
    config = _make_config()
    mock_el = MagicMock()
    cl = EmailChannelListener(config, email_listener=mock_el, repo_id="test")
    return cl, mock_el


class TestStartStop:
    def test_start_connects_and_spawns_thread(
        self, listener_and_mock: tuple[EmailChannelListener, MagicMock]
    ) -> None:
        """start() connects to IMAP and spawns a listener thread."""
        listener, mock_el = listener_and_mock
        submit = MagicMock(return_value=True)

        with patch.object(listener, "_listener_loop"):
            listener.start(submit)

        mock_el.connect.assert_called_once_with(
            max_retries=listener._config.imap_connect_retries,
            stop_event=listener._stop_event,
        )
        assert listener._thread is not None
        assert listener._thread.daemon is True
        assert listener.status.health == ChannelHealth.CONNECTED

        listener.stop()

    def test_stop_joins_thread_and_closes(
        self, listener_and_mock: tuple[EmailChannelListener, MagicMock]
    ) -> None:
        """stop() interrupts, joins thread, and closes connection."""
        listener, mock_el = listener_and_mock
        submit = MagicMock(return_value=True)

        with patch.object(listener, "_listener_loop"):
            listener.start(submit)

        listener.stop()

        mock_el.interrupt.assert_called_once()
        mock_el.close.assert_called_once()
        assert listener._thread is None

    def test_thread_name_includes_repo_and_server(self) -> None:
        """Thread name includes both repo_id and IMAP server."""
        config = _make_config()
        mock_el = MagicMock()
        cl = EmailChannelListener(
            config, email_listener=mock_el, repo_id="my-repo"
        )
        submit = MagicMock(return_value=True)

        with patch.object(cl, "_listener_loop"):
            cl.start(submit)

        assert cl._thread is not None
        name = "EmailListener-my-repo-imap.example.com"
        assert cl._thread.name == name

        cl.stop()

    def test_stop_warns_on_join_timeout(self) -> None:
        """stop() logs warning if thread doesn't terminate."""
        config = _make_config()
        mock_el = MagicMock()
        cl = EmailChannelListener(
            config, email_listener=mock_el, repo_id="test"
        )

        # Create a mock thread that appears alive after join
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        cl._thread = mock_thread
        cl._running = True

        cl.stop()

        mock_thread.join.assert_called_once_with(timeout=10)
        # Thread reference should be cleared even if alive
        assert cl._thread is None

    def test_initial_status_is_starting(
        self, listener_and_mock: tuple[EmailChannelListener, MagicMock]
    ) -> None:
        """Before start(), status is STARTING."""
        listener, _ = listener_and_mock
        assert listener.status.health == ChannelHealth.STARTING

    def test_empty_repo_id_raises(self) -> None:
        """Empty repo_id raises ValueError."""
        config = _make_config()
        with pytest.raises(ValueError, match="repo_id must not be empty"):
            EmailChannelListener(config, repo_id="")


class TestDispatch:
    def test_dispatches_to_polling(self) -> None:
        """Dispatches to polling loop when use_imap_idle=False."""
        config = _make_config(imap_use_idle=False)
        mock_el = MagicMock()
        cl = EmailChannelListener(
            config, email_listener=mock_el, repo_id="test"
        )
        cl._submit = MagicMock()
        cl._running = True

        with patch.object(cl, "_polling_loop") as mock_pl:
            cl._listener_loop()
        mock_pl.assert_called_once()

    def test_dispatches_to_idle(self) -> None:
        """Dispatches to IDLE loop when use_imap_idle=True."""
        config = _make_config(imap_use_idle=True)
        mock_el = MagicMock()
        cl = EmailChannelListener(
            config, email_listener=mock_el, repo_id="test"
        )
        cl._submit = MagicMock()
        cl._running = True

        with patch.object(cl, "_idle_loop") as mock_il:
            cl._listener_loop()
        mock_il.assert_called_once()


class TestPollingLoop:
    def test_processes_messages(self) -> None:
        """Polling loop processes messages and deletes them."""
        cl, mock_el = _make_polling_listener()
        msg = _make_message()
        call_count = 0
        submit = MagicMock(return_value=True)
        cl._submit = submit

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg)]
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._polling_loop()

        mock_el.delete_message.assert_called_once_with("1")
        submit.assert_called_once()
        raw_msg = submit.call_args[0][0]
        assert isinstance(raw_msg, RawMessage)
        assert raw_msg.content is msg
        assert raw_msg.sender == "user@example.com"
        assert raw_msg.display_title == "Test"

    def test_no_reconnect_during_shutdown(self) -> None:
        """Polling loop skips reconnection when _running is False.

        When stop() interrupts the socket during fetch_unread(), the
        resulting IMAPConnectionError should not trigger reconnection
        if the listener is shutting down.  Attempting to reconnect
        during shutdown can create a new SSL socket that nobody
        closes, leaking the socket and triggering
        PytestUnraisableExceptionWarning in CI.
        """
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()

        def fake_fetch():
            # Simulate interrupt: the socket was shut down
            cl._running = False
            raise IMAPConnectionError("socket shutdown")

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._polling_loop()

        # Should NOT have attempted reconnection
        mock_el.disconnect.assert_not_called()
        mock_el.connect.assert_not_called()

    def test_reconnects_on_imap_error(self) -> None:
        """Polling loop reconnects on IMAPConnectionError."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise IMAPConnectionError("lost connection")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._polling_loop()

        mock_el.disconnect.assert_called_once()
        assert mock_el.connect.call_count == 1

    def test_max_reconnect_attempts(self) -> None:
        """Polling loop exits after max reconnect attempts."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        mock_el.fetch_unread.side_effect = IMAPConnectionError("fail")

        cl._polling_loop()

        assert cl.status.health == ChannelHealth.FAILED

    def test_backoff_skips_reconnect_during_shutdown(self) -> None:
        """Backoff sleep interrupted by stop() skips reconnection."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        # Clear the pre-set stop event so the backoff wait actually blocks
        cl._stop_event.clear()

        def fake_fetch():
            raise IMAPConnectionError("lost")

        mock_el.fetch_unread.side_effect = fake_fetch

        # Simulate stop() interrupting the backoff wait: set the event
        # and _running=False before the reconnect attempt.
        original_wait = cl._stop_event.wait

        def interrupt_on_backoff(timeout):
            cl._running = False
            cl._stop_event.set()
            return original_wait(timeout)

        cl._stop_event.wait = interrupt_on_backoff  # type: ignore[assignment]

        cl._polling_loop()

        # Should NOT have attempted reconnection
        mock_el.disconnect.assert_not_called()
        mock_el.connect.assert_not_called()

    def test_reconnect_failure(self) -> None:
        """Polling loop continues after a reconnection failure."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise IMAPConnectionError("fail")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.connect.side_effect = [
            IMAPConnectionError("reconnect fail"),
            None,
        ]

        cl._polling_loop()

    def test_submit_exception_continues(self) -> None:
        """Polling loop continues after a submit exception."""
        cl, mock_el = _make_polling_listener()
        msg1 = _make_message(subject="msg1")
        msg2 = _make_message(subject="msg2")
        call_count = 0
        cl._submit = MagicMock()

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg1), ("2", msg2)]
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.delete_message.side_effect = [
            RuntimeError("fail"),
            None,
        ]

        cl._polling_loop()

    def test_status_degraded_during_reconnect(self) -> None:
        """Status changes to DEGRADED during reconnection."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        statuses: list[ChannelHealth] = []
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise IMAPConnectionError("lost")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        # Capture status when disconnect is called (during reconnect,
        # after status has been set to DEGRADED).
        mock_el.disconnect.side_effect = lambda: statuses.append(
            cl.status.health
        )

        cl._polling_loop()

        assert ChannelHealth.DEGRADED in statuses


class TestIdleLoop:
    def test_processes_and_idles(self) -> None:
        """IDLE loop processes messages then enters IDLE."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", _make_message())]
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._idle_loop()

    def test_idle_wait_notification(self) -> None:
        """IDLE loop processes notification from idle_wait."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.idle_start.return_value = False  # entered IDLE
        mock_el.idle_wait.return_value = True  # got notification

        cl._idle_loop()
        mock_el.idle_start.assert_called()
        mock_el.idle_done.assert_called()

    def test_idle_timeout(self) -> None:
        """IDLE loop handles idle_wait timeout."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.idle_start.return_value = False
        mock_el.idle_wait.return_value = False  # timeout

        cl._idle_loop()

    def test_periodic_reconnect(self) -> None:
        """IDLE loop performs periodic reconnect."""
        cl, mock_el = _make_idle_listener(
            imap_idle_reconnect_interval_seconds=60,
        )

        def fake_fetch():
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        call_count = [0]

        def fake_time():
            call_count[0] += 1
            if call_count[0] == 1:
                return 0.0
            return 100.0

        with patch("time.time", side_effect=fake_time):
            cl._idle_loop()
        mock_el.disconnect.assert_called()

    def test_submit_exception_continues(self) -> None:
        """IDLE loop continues after a submit exception."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", _make_message())]
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.delete_message.side_effect = RuntimeError("fail")

        cl._idle_loop()

    def test_idle_start_has_pending_skips_idle(self) -> None:
        """When idle_start detects pending messages, skip IDLE.

        Reproduces the race condition where a message arrives between
        fetch_unread() and IDLE.  idle_start() detects the unseen
        message and returns True, causing the loop to skip IDLE and
        call fetch_unread() again.
        """
        cl, mock_el = _make_idle_listener()
        fetch_count = 0

        def fake_fetch():
            nonlocal fetch_count
            fetch_count += 1
            if fetch_count == 1:
                return []
            if fetch_count == 2:
                return [("1", _make_message())]
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.idle_start.side_effect = [True, False]
        mock_el.idle_wait.return_value = False

        cl._idle_loop()

        submit = cl._submit
        assert isinstance(submit, MagicMock)
        submit.assert_called_once()
        mock_el.delete_message.assert_called_once_with("1")
        mock_el.idle_wait.assert_called_once()

    def test_idle_error_forces_reconnect(self) -> None:
        """IDLE error forces a reconnect."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.idle_start.side_effect = [
            IMAPIdleError("idle broken"),
            False,
        ]

        cl._idle_loop()

    def test_idle_no_reconnect_during_shutdown(self) -> None:
        """IDLE loop skips reconnection when _running is False.

        Same as test_no_reconnect_during_shutdown but for the IDLE loop.
        """
        cl, mock_el = _make_idle_listener()

        def fake_fetch():
            cl._running = False
            raise IMAPConnectionError("socket shutdown")

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._idle_loop()

        mock_el.disconnect.assert_not_called()
        mock_el.connect.assert_not_called()

    def test_imap_connection_error_reconnects(self) -> None:
        """IDLE loop reconnects on IMAPConnectionError."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise IMAPConnectionError("lost")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._idle_loop()

    def test_imap_max_reconnect_raises(self) -> None:
        """IDLE loop exits after max reconnect attempts."""
        cl, mock_el = _make_idle_listener()
        mock_el.fetch_unread.side_effect = IMAPConnectionError("fail")

        cl._idle_loop()

        assert cl.status.health == ChannelHealth.FAILED

    def test_imap_reconnect_failure(self) -> None:
        """IDLE loop handles reconnection failure gracefully."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise IMAPConnectionError("fail")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.connect.side_effect = [
            IMAPConnectionError("reconnect fail"),
            None,
        ]

        cl._idle_loop()

    def test_shutdown_skips_idle_done(self) -> None:
        """When shutting down during IDLE, skip idle_done()."""
        cl, mock_el = _make_idle_listener()

        mock_el.fetch_unread.return_value = []
        mock_el.idle_start.return_value = False

        def stop_during_wait(timeout):
            cl._running = False
            return False

        mock_el.idle_wait.side_effect = stop_during_wait

        cl._idle_loop()
        mock_el.idle_done.assert_not_called()

    def test_idle_timeout_zero(self) -> None:
        """When time_until_reconnect is 0, skip wait."""
        cl, mock_el = _make_idle_listener(
            imap_idle_reconnect_interval_seconds=60,
        )
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.idle_start.return_value = False

        with patch("time.time", return_value=99999):
            cl._idle_loop()


class TestChannelStatus:
    def test_connected_after_reconnect(self) -> None:
        """Status returns to CONNECTED after successful reconnect."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise IMAPConnectionError("lost")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._idle_loop()

        assert cl.status.health == ChannelHealth.CONNECTED

    def test_failed_has_error_type(self) -> None:
        """FAILED status includes error type."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        mock_el.fetch_unread.side_effect = IMAPConnectionError("fail")

        cl._polling_loop()

        assert cl.status.health == ChannelHealth.FAILED
        assert cl.status.error_type == "IMAPConnectionError"
        assert "failed" in cl.status.message.lower()


class TestFullLifecycle:
    """Tests that exercise start() → loop → stop() without bypassing."""

    def test_polling_start_processes_and_stops(self) -> None:
        """Full polling lifecycle: start(), process message, stop()."""
        config = _make_config(imap_use_idle=False, imap_poll_interval_seconds=1)
        mock_el = MagicMock()
        cl = EmailChannelListener(
            config, email_listener=mock_el, repo_id="test"
        )
        submit = MagicMock(return_value=True)
        msg = _make_message()

        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg)]
            cl._running = False
            cl._stop_event.set()
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl.start(submit)
        assert cl._thread is not None
        cl._thread.join(timeout=5)

        submit.assert_called_once()
        raw_msg = submit.call_args[0][0]
        assert isinstance(raw_msg, RawMessage)
        assert raw_msg.content is msg
        mock_el.delete_message.assert_called_once_with("1")

        cl.stop()

    def test_idle_start_processes_and_stops(self) -> None:
        """Full IDLE lifecycle: start(), process message, stop()."""
        config = _make_config(
            imap_use_idle=True,
            imap_idle_reconnect_interval_seconds=99999,
        )
        mock_el = MagicMock()
        cl = EmailChannelListener(
            config, email_listener=mock_el, repo_id="test"
        )
        submit = MagicMock(return_value=True)
        msg = _make_message()

        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg)]
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl.start(submit)
        assert cl._thread is not None
        cl._thread.join(timeout=5)

        submit.assert_called_once()
        raw_msg = submit.call_args[0][0]
        assert isinstance(raw_msg, RawMessage)
        mock_el.delete_message.assert_called_once_with("1")

        cl.stop()

    def test_start_wires_submit_callback(self) -> None:
        """start() correctly wires the submit callback to the loop."""
        config = _make_config(imap_use_idle=False, imap_poll_interval_seconds=1)
        mock_el = MagicMock()
        cl = EmailChannelListener(
            config, email_listener=mock_el, repo_id="test"
        )
        received_messages: list[RawMessage] = []

        def track_submit(raw: RawMessage) -> bool:
            received_messages.append(raw)
            return True

        msg = _make_message(subject="Tracked")
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg)]
            cl._running = False
            cl._stop_event.set()
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        cl.start(track_submit)
        assert cl._thread is not None
        cl._thread.join(timeout=5)

        assert len(received_messages) == 1
        assert received_messages[0].display_title == "Tracked"
        assert received_messages[0].content is msg

        cl.stop()
