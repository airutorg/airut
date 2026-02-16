# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for repo_handler module."""

import sys
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from .conftest import make_message, make_service, update_repo


def _make_slack_config(tmp_path: Path) -> Any:
    """Create a RepoServerConfig with slack channel for testing."""
    from airut.gateway.config import RepoServerConfig
    from airut.gateway.slack.config import SlackChannelConfig

    slack_config = SlackChannelConfig(
        bot_token="xoxb-test-token",
        app_token="xapp-test-token",
        authorized=[{"workspace_members": True}],
    )
    return RepoServerConfig(
        repo_id="test-slack",
        git_repo_url=str(tmp_path / "repo"),
        slack=slack_config,
    )


def _make_slack_handler(tmp_path: Path) -> tuple[Any, Any]:
    """Create a RepoHandler with Slack config, mocking Slack deps."""
    from airut.gateway.config import GlobalConfig, ServerConfig
    from airut.gateway.service import GatewayService

    slack_config = _make_slack_config(tmp_path)

    global_config = GlobalConfig(dashboard_enabled=False)
    server_config = ServerConfig(
        global_config=global_config, repos={"test-slack": slack_config}
    )

    from airut.gateway.slack.adapter import SlackChannelAdapter

    mock_slack_adapter = MagicMock(spec=SlackChannelAdapter)
    with (
        patch(
            "airut.gateway.slack.adapter.SlackChannelAdapter.from_config",
            return_value=mock_slack_adapter,
        ),
        patch("airut.gateway.service.repo_handler.ConversationManager"),
        patch(
            "airut.gateway.service.gateway.capture_version_info",
            return_value=(MagicMock(git_sha="abc1234"), MagicMock()),
        ),
        patch("airut.gateway.service.gateway.TaskTracker"),
        patch("airut.gateway.service.gateway.Sandbox"),
        patch(
            "airut.gateway.service.gateway.get_system_resolver",
            return_value="127.0.0.53",
        ),
    ):
        svc = GatewayService(server_config, repo_root=tmp_path)

    handler = svc.repo_handlers["test-slack"]
    return svc, handler


class TestSubmitMessage:
    def test_forwards_to_service(self, email_config, tmp_path: Path) -> None:
        """Raw message is forwarded to service.submit_message."""
        svc, handler = make_service(email_config, tmp_path)
        svc.submit_message = MagicMock(return_value=True)

        msg = make_message()
        assert handler._submit_message(msg) is True
        svc.submit_message.assert_called_once_with(msg, handler)

    def test_returns_false_when_pool_not_ready(
        self, email_config, tmp_path: Path
    ) -> None:
        """Returns False when service.submit_message returns False."""
        svc, handler = make_service(email_config, tmp_path)
        svc.submit_message = MagicMock(return_value=False)

        msg = make_message()
        assert handler._submit_message(msg) is False


class TestPollLoop:
    def test_dispatches_to_polling(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, use_imap_idle=False)
        with patch.object(handler, "_polling_loop") as mock_pl:
            handler._listener_loop()
        mock_pl.assert_called_once()

    def test_dispatches_to_idle(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, use_imap_idle=True)
        with patch.object(handler, "_idle_loop") as mock_il:
            handler._listener_loop()
        mock_il.assert_called_once()


class TestPollingLoop:
    def test_processes_messages(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        msg = make_message()
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg)]
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch

        with (
            patch.object(handler, "_submit_message"),
            patch("time.sleep"),
        ):
            handler._polling_loop()
        handler.adapter.listener.delete_message.assert_called_once_with("1")

    def test_reconnects_on_imap_error(
        self, email_config, tmp_path: Path
    ) -> None:
        from airut.gateway import IMAPConnectionError

        svc, handler = make_service(email_config, tmp_path)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise IMAPConnectionError("lost connection")
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch

        with patch("time.sleep"):
            handler._polling_loop()
        handler.adapter.listener.disconnect.assert_called_once()
        assert handler.adapter.listener.connect.call_count == 1

    def test_max_reconnect_attempts(self, email_config, tmp_path: Path) -> None:
        from airut.gateway import IMAPConnectionError

        svc, handler = make_service(email_config, tmp_path)
        handler.adapter.listener.fetch_unread.side_effect = IMAPConnectionError(
            "fail"
        )

        with patch("time.sleep"):
            handler._polling_loop()
        # Loop exits after max reconnect attempts
        # (but doesn't set running=False)
        # The critical section logs the error and returns

    def test_reconnect_failure(self, email_config, tmp_path: Path) -> None:
        from airut.gateway import IMAPConnectionError

        svc, handler = make_service(email_config, tmp_path)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise IMAPConnectionError("fail")
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.connect.side_effect = [
            IMAPConnectionError("reconnect fail"),
            None,
        ]

        with patch("time.sleep"):
            handler._polling_loop()

    def test_submit_exception_continues(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        msg1 = make_message(subject="msg1")
        msg2 = make_message(subject="msg2")
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", msg1), ("2", msg2)]
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.delete_message.side_effect = [
            RuntimeError("fail"),
            None,
        ]

        with patch("time.sleep"):
            handler._polling_loop()


class TestIdleLoop:
    def test_processes_and_idles(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", make_message())]
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch

        with patch.object(handler, "_submit_message"):
            handler._idle_loop()

    def test_idle_wait_notification(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.idle_start.return_value = False  # entered IDLE
        handler.adapter.listener.idle_wait.return_value = (
            True  # got notification
        )

        handler._idle_loop()
        handler.adapter.listener.idle_start.assert_called()
        handler.adapter.listener.idle_done.assert_called()

    def test_idle_timeout(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.idle_start.return_value = False  # entered IDLE
        handler.adapter.listener.idle_wait.return_value = False  # timeout

        handler._idle_loop()

    def test_periodic_reconnect(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=60)

        def fake_fetch():
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch

        # Manipulate last_reconnect directly to trigger reconnect check
        # The idle loop initializes last_reconnect = time.time() at start
        # We need the check: time.time() - last_reconnect >= 60 to be True
        call_count = [0]

        def fake_time():
            call_count[0] += 1
            # First call sets last_reconnect, subsequent calls are far ahead
            if call_count[0] == 1:
                return 0.0
            return 100.0

        with patch("time.time", side_effect=fake_time):
            handler._idle_loop()
        handler.adapter.listener.disconnect.assert_called()

    def test_submit_exception_continues(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [("1", make_message())]
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.delete_message.side_effect = RuntimeError(
            "fail"
        )

        with patch.object(handler, "_submit_message"):
            handler._idle_loop()

    def test_idle_start_has_pending_skips_idle(
        self, email_config, tmp_path: Path
    ) -> None:
        """When idle_start detects pending messages, skip IDLE and re-fetch.

        Reproduces the race condition where a message arrives between
        fetch_unread() and IDLE.  idle_start() detects the unseen message
        and returns True, causing the loop to skip IDLE and call
        fetch_unread() again, which picks up the message.
        """
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        fetch_count = 0

        def fake_fetch():
            nonlocal fetch_count
            fetch_count += 1
            if fetch_count == 1:
                # First poll: inbox empty (message hasn't arrived yet)
                return []
            if fetch_count == 2:
                # Second poll: message arrived during idle_start check
                return [("1", make_message())]
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        # First idle_start: detects pending message, returns True
        # Second idle_start: no pending, enters IDLE normally
        handler.adapter.listener.idle_start.side_effect = [True, False]
        handler.adapter.listener.idle_wait.return_value = False

        with patch.object(handler, "_submit_message") as mock_submit:
            handler._idle_loop()

        # Message should have been processed
        mock_submit.assert_called_once()
        handler.adapter.listener.delete_message.assert_called_once_with("1")
        # idle_wait should only be called once (second idle_start entered IDLE)
        handler.adapter.listener.idle_wait.assert_called_once()

    def test_idle_error_forces_reconnect(
        self, email_config, tmp_path: Path
    ) -> None:
        from airut.gateway import IMAPIdleError

        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.idle_start.side_effect = [
            IMAPIdleError("idle broken"),
            False,
        ]

        handler._idle_loop()

    def test_imap_connection_error_reconnects(
        self, email_config, tmp_path: Path
    ) -> None:
        from airut.gateway import IMAPConnectionError

        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise IMAPConnectionError("lost")
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch

        with patch("time.sleep"):
            handler._idle_loop()

    def test_imap_max_reconnect_raises(
        self, email_config, tmp_path: Path
    ) -> None:
        from airut.gateway import IMAPConnectionError

        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        handler.adapter.listener.fetch_unread.side_effect = IMAPConnectionError(
            "fail"
        )

        with patch("time.sleep"):
            handler._idle_loop()
        # Loop exits after max reconnect attempts
        # (but doesn't set running=False)
        # The critical section logs the error and returns

    def test_imap_reconnect_failure(self, email_config, tmp_path: Path) -> None:
        from airut.gateway import IMAPConnectionError

        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise IMAPConnectionError("fail")
            svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.connect.side_effect = [
            IMAPConnectionError("reconnect fail"),
            None,
        ]

        with patch("time.sleep"):
            handler._idle_loop()

    def test_shutdown_skips_idle_done(
        self, email_config, tmp_path: Path
    ) -> None:
        """When shutting down during IDLE, skip idle_done()."""
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=99999)

        handler.adapter.listener.fetch_unread.return_value = []
        handler.adapter.listener.idle_start.return_value = False  # entered IDLE

        def stop_during_wait(timeout):
            svc.running = False
            return False

        handler.adapter.listener.idle_wait.side_effect = stop_during_wait

        handler._idle_loop()
        handler.adapter.listener.idle_done.assert_not_called()

    def test_idle_timeout_zero(self, email_config, tmp_path: Path) -> None:
        """When time_until_reconnect is 0, idle_timeout is 0 -> skip wait."""
        svc, handler = make_service(email_config, tmp_path)
        update_repo(handler, idle_reconnect_interval_seconds=60)
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                svc.running = False
            return []

        handler.adapter.listener.fetch_unread.side_effect = fake_fetch
        handler.adapter.listener.idle_start.return_value = False  # entered IDLE

        # Always return a time far past reconnect interval -> idle_timeout = 0
        with patch("time.time", return_value=99999):
            handler._idle_loop()


class TestSlackPaths:
    """Tests for Slack-specific paths in RepoHandler."""

    def test_create_adapter_slack(self, tmp_path: Path) -> None:
        """_create_adapter creates SlackChannelAdapter for Slack config."""
        svc, handler = _make_slack_handler(tmp_path)
        assert handler._is_slack is True
        assert handler._email_adapter is None

    def test_start_listener_dispatches_to_slack(self, tmp_path: Path) -> None:
        """start_listener calls _start_slack_listener for Slack config."""
        svc, handler = _make_slack_handler(tmp_path)

        mock_modules = {
            "slack_bolt": MagicMock(),
            "slack_bolt.adapter": MagicMock(),
            "slack_bolt.adapter.socket_mode": MagicMock(),
            "slack_bolt.context": MagicMock(),
            "slack_bolt.context.assistant": MagicMock(),
            "slack_bolt.middleware": MagicMock(),
            "slack_bolt.middleware.assistant": MagicMock(),
        }

        captured_callback = None

        def capture_listener(config, submit_callback=None):
            nonlocal captured_callback
            captured_callback = submit_callback
            return MagicMock()

        with (
            patch.dict(sys.modules, mock_modules),
            patch(
                "airut.gateway.slack.listener.SlackListener",
                side_effect=capture_listener,
            ),
            patch.object(handler.conversation_manager.mirror, "update_mirror"),
        ):
            thread = handler.start_listener()

        assert isinstance(thread, threading.Thread)
        assert thread.daemon is True

        # Invoke the captured submit_callback to cover line 174
        assert captured_callback is not None
        svc.submit_message = MagicMock(return_value=True)
        captured_callback({"text": "hello", "user": "U123"})
        svc.submit_message.assert_called_once()

        # Clean up
        svc.running = False
        thread.join(timeout=2)

    def test_slack_keep_alive_exits_on_stop(self, tmp_path: Path) -> None:
        """_slack_keep_alive exits when service.running is False."""
        svc, handler = _make_slack_handler(tmp_path)
        svc.running = False
        # Should return immediately
        handler._slack_keep_alive()

    def test_stop_slack_listener(self, tmp_path: Path) -> None:
        """stop() calls _slack_listener.close() for Slack channel."""
        svc, handler = _make_slack_handler(tmp_path)
        mock_listener = MagicMock()
        handler._slack_listener = mock_listener

        handler.stop()
        mock_listener.close.assert_called_once()

    def test_submit_message_dict(self, tmp_path: Path) -> None:
        """Slack payload (dict) can be submitted."""
        svc, handler = _make_slack_handler(tmp_path)
        svc.submit_message = MagicMock(return_value=True)

        payload = {"text": "hello", "user": "U123"}
        assert handler._submit_message(payload) is True
        svc.submit_message.assert_called_once_with(payload, handler)
