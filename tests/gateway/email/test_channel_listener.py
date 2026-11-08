# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for EmailChannelListener."""

import threading
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.channel import ChannelHealth, ChannelStatus, RawMessage
from airut.gateway.config import (
    EmailAccountConfig,
    EmailAuthConfig,
    EmailChannelConfig,
    ImapConfig,
    SmtpConfig,
)
from airut.gateway.email.channel_listener import (
    EmailChannelListener,
    reconnect_delay,
)
from airut.gateway.email.incoming import IncomingEmail
from airut.gateway.email.listener import IMAPConnectionError, IMAPIdleError


def _make_config(
    **imap_overrides: Any,  # noqa: ANN401
) -> EmailChannelConfig:
    """Build an EmailChannelConfig with test defaults.

    Keyword arguments are forwarded to ``ImapConfig``.
    """
    imap_kwargs: dict[str, Any] = {
        "server": "imap.example.com",
        "port": 993,
    }
    imap_kwargs.update(imap_overrides)
    return EmailChannelConfig(
        account=EmailAccountConfig(
            username="test@example.com",
            password="test_password",
            from_address="Test <test@example.com>",
        ),
        imap=ImapConfig(**imap_kwargs),
        smtp=SmtpConfig(server="smtp.example.com", port=587),
        auth=EmailAuthConfig(
            authorized_senders=["user@example.com"],
            trusted_authserv_id="mx.example.com",
        ),
    )


def _make_message(subject: str = "Test") -> IncomingEmail:
    """Build a simple fetched email for testing."""
    raw = (
        f"From: user@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: <msg1@example.com>\r\n"
        f"\r\nHello"
    )
    return IncomingEmail.parse(raw.encode())


def _make_polling_listener() -> tuple[EmailChannelListener, MagicMock]:
    """Create a listener configured for polling.

    Pre-sets the stop event so that ``_stop_event.wait()`` returns
    immediately (same effect as patching ``time.sleep`` to a no-op).

    Returns:
        Tuple of (listener, mock_email_listener).
    """
    config = _make_config(use_idle=False, poll_interval=1)
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
        "use_idle": True,
        "idle_reconnect_interval": 99999,
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
            max_retries=listener._config.imap.connect_retries,
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

    def test_stop_does_not_join_unstarted_thread(self) -> None:
        """stop() tolerates a thread assigned but never started.

        start() and stop() run on different threads, so stop() can
        observe self._thread in the window before its .start() ran,
        where join() would raise 'cannot join thread before it is
        started'.
        """
        config = _make_config()
        mock_el = MagicMock()
        cl = EmailChannelListener(config, email_listener=mock_el, repo_id="t")

        # Real, never-started thread — a MagicMock would hide the bug.
        cl._thread = threading.Thread(target=lambda: None)

        cl.stop()  # Must not raise.

        mock_el.close.assert_called_once()

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
        config = _make_config(use_idle=False)
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
        config = _make_config(use_idle=True)
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

    def test_raw_8bit_headers_submitted_as_text(self) -> None:
        """Undecodable 8-bit headers are Header objects; text is submitted.

        The gateway slices the sender for the dashboard title, which a
        Header object does not support.
        """
        cl, mock_el = _make_polling_listener()
        msg = IncomingEmail.parse(
            "From: P\u00e4ivi <user@example.com>\r\n"
            "Subject: Hyv\u00e4\r\n\r\nHello".encode()
        )
        submit = MagicMock(return_value=True)
        cl._submit = submit

        def fake_fetch():
            cl._running = False
            return [("1", msg)]

        mock_el.fetch_unread.side_effect = fake_fetch

        cl._polling_loop()

        raw_msg = submit.call_args[0][0]
        assert isinstance(raw_msg.sender, str)
        assert raw_msg.sender.endswith("<user@example.com>")
        assert isinstance(raw_msg.display_title, str)

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

    def test_never_gives_up_reconnecting(self) -> None:
        """Polling loop keeps reconnecting however long the outage lasts.

        Regression: the loop used to stop for good after 5 failed
        attempts, leaving the channel dead until a restart.
        """
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        mock_el.fetch_unread.return_value = []
        failed_attempts = 0

        def fake_connect(
            max_retries: int = 3, stop_event: threading.Event | None = None
        ) -> None:
            nonlocal failed_attempts
            if failed_attempts < 20:
                failed_attempts += 1
                raise IMAPConnectionError("Connection refused")
            cl._running = False

        mock_el.fetch_unread.side_effect = [
            IMAPConnectionError("lost"),
            [],
        ]
        mock_el.connect.side_effect = fake_connect

        cl._polling_loop()

        assert mock_el.connect.call_count == 21
        assert cl.status.health == ChannelHealth.CONNECTED

    def test_backoff_is_exponential_and_capped(self) -> None:
        """Reconnect delays grow 10s, 30s, 90s, 270s, then stay at 300s."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        waits: list[float] = []

        def record_wait(timeout: float) -> bool:
            waits.append(timeout)
            if len(waits) == 7:
                cl._running = False
            return True

        mock_el.fetch_unread.side_effect = IMAPConnectionError("lost")
        mock_el.connect.side_effect = IMAPConnectionError("refused")

        with patch.object(cl._stop_event, "wait", record_wait):
            cl._polling_loop()

        assert waits == [10, 30, 90, 270, 300, 300, 300]

    def test_backoff_continues_when_connection_drops_again(self) -> None:
        """A reconnect that fails again before a fetch keeps backing off.

        Only a successful fetch resets the backoff, so a server that
        accepts the login but fails every fetch is not hammered at the
        shortest delay.
        """
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        waits: list[float] = []

        def record_wait(timeout: float) -> bool:
            waits.append(timeout)
            if len(waits) == 3:
                cl._running = False
            return True

        mock_el.fetch_unread.side_effect = IMAPConnectionError("fetch failed")

        with patch.object(cl._stop_event, "wait", record_wait):
            cl._polling_loop()

        assert waits == [10, 30, 90]

    def test_successful_fetch_resets_backoff(self) -> None:
        """After a successful fetch, the next outage starts at 10s again."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        waits: list[float] = []

        def record_wait(timeout: float) -> bool:
            waits.append(timeout)
            if len(waits) == 4:
                cl._running = False
            return True

        mock_el.fetch_unread.side_effect = [
            IMAPConnectionError("lost"),
            IMAPConnectionError("lost"),
            [],
            IMAPConnectionError("lost"),
        ]

        with patch.object(cl._stop_event, "wait", record_wait):
            cl._polling_loop()

        # 10s and 30s backoff, 1s poll interval, then 10s again.
        assert waits == [10, 30, 1, 10]

    def test_unexpected_error_reconnects(self) -> None:
        """Errors other than IMAPConnectionError reconnect, not exit.

        E.g. an OSError escaping the IMAP library must not kill the
        listener thread and leave the channel silently dead.
        """
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionResetError("reset by peer")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch

        with patch.object(cl._log, "error") as log_error:
            cl._polling_loop()

        mock_el.disconnect.assert_called_once()
        mock_el.connect.assert_called_once()
        # The unexpected error is logged with its traceback.
        exc_info = log_error.call_args.kwargs["exc_info"]
        assert isinstance(exc_info, ConnectionResetError)

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

        with patch.object(cl._stop_event, "wait", interrupt_on_backoff):
            cl._polling_loop()

        # Should NOT have attempted reconnection
        mock_el.disconnect.assert_not_called()
        mock_el.connect.assert_not_called()

    def test_reconnect_failure(self) -> None:
        """Polling loop retries after a reconnection failure."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise IMAPConnectionError("fail")
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.connect.side_effect = [
            RuntimeError("unexpected reconnect error"),
            None,
        ]

        cl._polling_loop()

        assert mock_el.connect.call_count == 2
        assert cl.status.health == ChannelHealth.CONNECTED

    def test_stop_during_reconnect_attempt(self) -> None:
        """A connect aborted by stop() ends the retries."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        mock_el.fetch_unread.side_effect = IMAPConnectionError("lost")

        def aborted_connect(
            max_retries: int = 3, stop_event: threading.Event | None = None
        ) -> None:
            cl._running = False
            raise IMAPConnectionError("Connection aborted: shutting down")

        mock_el.connect.side_effect = aborted_connect

        cl._polling_loop()

        mock_el.connect.assert_called_once()

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

    def test_delete_connection_error_triggers_reconnect(self) -> None:
        """IMAPConnectionError during delete triggers reconnection.

        When the IMAP connection dies between fetch_unread() and
        delete_message(), the connection error must propagate to the
        outer handler for reconnection — not be swallowed by the
        inner per-message exception handler.
        """
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", _make_message())]
            cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        mock_el.delete_message.side_effect = IMAPConnectionError("socket died")

        cl._polling_loop()

        # Must have triggered reconnection, not just logged "submit error"
        mock_el.disconnect.assert_called_once()
        assert mock_el.connect.call_count == 1

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
            idle_reconnect_interval=60,
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

    def test_delete_connection_error_triggers_reconnect(self) -> None:
        """IMAPConnectionError during delete triggers reconnection.

        Same as the polling loop variant: connection errors from
        delete_message() must bubble up for reconnection instead of
        being swallowed by the per-message exception handler.
        """
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
        mock_el.delete_message.side_effect = IMAPConnectionError("socket died")

        cl._idle_loop()

        # Must have triggered reconnection
        mock_el.disconnect.assert_called_once()
        assert mock_el.connect.call_count == 1

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

    def test_never_gives_up_reconnecting(self) -> None:
        """IDLE loop keeps reconnecting however long the outage lasts."""
        cl, mock_el = _make_idle_listener()
        failed_attempts = 0

        def fake_connect(
            max_retries: int = 3, stop_event: threading.Event | None = None
        ) -> None:
            nonlocal failed_attempts
            if failed_attempts < 20:
                failed_attempts += 1
                raise IMAPConnectionError("Connection refused")
            cl._running = False

        mock_el.fetch_unread.side_effect = IMAPConnectionError("lost")
        mock_el.connect.side_effect = fake_connect

        cl._idle_loop()

        assert mock_el.connect.call_count == 21

    def test_unexpected_error_reconnects(self) -> None:
        """An unexpected error in IDLE handling reconnects, not exits."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                cl._running = False
            return []

        mock_el.fetch_unread.side_effect = fake_fetch
        # e.g. sending IDLE on a reset socket raises a bare OSError
        mock_el.idle_start.side_effect = BrokenPipeError("broken pipe")

        cl._idle_loop()

        mock_el.connect.assert_called_once()

    def test_imap_reconnect_failure(self) -> None:
        """IDLE loop retries after a reconnection failure."""
        cl, mock_el = _make_idle_listener()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
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
            idle_reconnect_interval=60,
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

    def test_degraded_reports_latest_error(self) -> None:
        """DEGRADED status names the attempt and the latest error."""
        cl, mock_el = _make_polling_listener()
        cl._submit = MagicMock()
        statuses: list[ChannelStatus] = []

        def record_wait(timeout: float) -> bool:
            statuses.append(cl.status)
            if len(statuses) == 2:
                cl._running = False
            return True

        mock_el.fetch_unread.side_effect = IMAPConnectionError("lost")
        mock_el.connect.side_effect = OSError("[Errno 111] Connection refused")

        with patch.object(cl._stop_event, "wait", record_wait):
            cl._polling_loop()

        first, second = statuses
        assert first.health == ChannelHealth.DEGRADED
        assert first.message == "IMAP reconnecting (attempt 1): lost"
        assert first.error_type == "IMAPConnectionError"
        assert second.health == ChannelHealth.DEGRADED
        assert second.message == (
            "IMAP reconnecting (attempt 2): [Errno 111] Connection refused"
        )
        assert second.error_type == "OSError"

    @pytest.mark.parametrize("use_idle", [False, True])
    def test_failed_when_loop_exits_unexpectedly(self, use_idle: bool) -> None:
        """A loop that ends while running marks the listener FAILED."""
        config = _make_config(use_idle=use_idle)
        cl = EmailChannelListener(
            config, email_listener=MagicMock(), repo_id="test"
        )
        cl._running = True
        loop = "_idle_loop" if use_idle else "_polling_loop"

        with patch.object(cl, loop, side_effect=SystemExit):
            with pytest.raises(SystemExit):
                cl._listener_loop()

        assert cl.status == ChannelStatus(
            health=ChannelHealth.FAILED,
            message="Email listener stopped unexpectedly",
            error_type="SystemExit",
        )

    def test_failed_when_loop_returns_while_running(self) -> None:
        """A loop returning without stop() is FAILED with no error type."""
        cl, _ = _make_polling_listener()

        with patch.object(cl, "_polling_loop", return_value=None):
            cl._listener_loop()

        assert cl.status == ChannelStatus(
            health=ChannelHealth.FAILED,
            message="Email listener stopped unexpectedly",
        )

    def test_not_failed_when_stopped(self) -> None:
        """A loop that ends because of stop() leaves the status alone."""
        cl, _ = _make_polling_listener()
        cl._status = ChannelStatus(health=ChannelHealth.CONNECTED)

        def stop_loop() -> None:
            cl._running = False

        with patch.object(cl, "_polling_loop", side_effect=stop_loop):
            cl._listener_loop()

        assert cl.status.health == ChannelHealth.CONNECTED


class TestReconnectDelay:
    def test_grows_and_caps(self) -> None:
        """Delays triple from 10s and cap at 5 minutes."""
        assert [reconnect_delay(n) for n in range(1, 8)] == [
            10,
            30,
            90,
            270,
            300,
            300,
            300,
        ]

    def test_long_outage_stays_capped(self) -> None:
        """Attempt counts from a days-long outage still give 300s."""
        assert reconnect_delay(100_000) == 300


class TestFullLifecycle:
    """Tests that exercise start() → loop → stop() without bypassing."""

    def test_polling_start_processes_and_stops(self) -> None:
        """Full polling lifecycle: start(), process message, stop()."""
        config = _make_config(use_idle=False, poll_interval=1)
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
            use_idle=True,
            idle_reconnect_interval=99999,
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
        config = _make_config(use_idle=False, poll_interval=1)
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
