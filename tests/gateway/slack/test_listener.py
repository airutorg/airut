# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackChannelListener."""

from unittest.mock import MagicMock, patch

from slack_bolt import App

from airut.gateway.channel import ChannelHealth, RawMessage
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.listener import SlackChannelListener


def _make_config() -> SlackChannelConfig:
    return SlackChannelConfig(
        bot_token="xoxb-test-token",
        app_token="xapp-test-token",
        authorized=({"workspace_members": True},),
    )


class TestSlackChannelListener:
    def test_initial_status_starting(self) -> None:
        with (
            patch("airut.gateway.slack.listener.App"),
            patch("airut.gateway.slack.listener.SocketModeHandler"),
        ):
            listener = SlackChannelListener(
                _make_config(),
                app=MagicMock(),
                handler=MagicMock(),
            )
        assert listener.status.health == ChannelHealth.STARTING

    def test_start_connects_and_sets_connected(self) -> None:
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )
        submit = MagicMock()

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(submit)

        handler.connect.assert_called_once()
        assert listener.status.health == ChannelHealth.CONNECTED

    def test_stop_closes_handler(self) -> None:
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=MagicMock(), handler=handler
        )
        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        listener.stop()

        handler.close.assert_called_once()
        assert listener.status.health == ChannelHealth.FAILED
        assert listener.status.message == "stopped"

    def test_handlers_registered_on_start(self) -> None:
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        with patch(
            "airut.gateway.slack.listener.Assistant"
        ) as mock_assistant_cls:
            mock_assistant = mock_assistant_cls.return_value
            listener.start(MagicMock())

        # Handlers should be registered on the Assistant instance
        assert mock_assistant.thread_started.called
        assert mock_assistant.user_message.called
        assert mock_assistant.thread_context_changed.called
        # The Assistant instance should be registered with the app
        app.assistant.assert_called_once_with(mock_assistant)

    def test_user_message_handler_calls_submit(self) -> None:
        """Verify user_message handler wraps payload in RawMessage."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        submit = MagicMock(return_value=True)
        with patch(
            "airut.gateway.slack.listener.Assistant"
        ) as mock_assistant_cls:
            mock_assistant = mock_assistant_cls.return_value
            listener.start(submit)

        # Get the registered user_message handler
        user_msg_decorator = mock_assistant.user_message
        payload = {
            "user": "U123",
            "text": "Hello bot",
            "channel": "D456",
            "thread_ts": "1234567890.123456",
        }
        set_status = MagicMock()

        # Extract the function passed to the decorator
        user_msg_call = user_msg_decorator.call_args
        assert user_msg_call is not None
        actual_handler = user_msg_call[0][0]
        actual_handler(payload=payload, set_status=set_status)

        # Verify submit was called with a RawMessage
        submit.assert_called_once()
        raw: RawMessage = submit.call_args[0][0]
        assert raw.sender == "U123"
        assert raw.content == payload
        assert "Hello bot" in raw.display_title

    def test_thread_started_handler(self) -> None:
        """Verify thread_started handler sets status and says greeting."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )
        with patch(
            "airut.gateway.slack.listener.Assistant"
        ) as mock_assistant_cls:
            mock_assistant = mock_assistant_cls.return_value
            listener.start(MagicMock())

        # Extract thread_started handler
        ts_decorator = mock_assistant.thread_started
        ts_call = ts_decorator.call_args
        assert ts_call is not None
        handler_fn = ts_call[0][0]

        set_status = MagicMock()
        say = MagicMock()
        set_suggested_prompts = MagicMock()
        handler_fn(
            set_status=set_status,
            say=say,
            set_suggested_prompts=set_suggested_prompts,
        )

        set_status.assert_called_once_with("is getting ready...")
        say.assert_called_once()

    def test_context_changed_handler(self) -> None:
        """Verify thread_context_changed handler runs without error."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )
        with patch(
            "airut.gateway.slack.listener.Assistant"
        ) as mock_assistant_cls:
            mock_assistant = mock_assistant_cls.return_value
            listener.start(MagicMock())

        # Extract context_changed handler
        cc_decorator = mock_assistant.thread_context_changed
        cc_call = cc_decorator.call_args
        assert cc_call is not None
        handler_fn = cc_call[0][0]

        context = MagicMock()
        handler_fn(context=context)  # Should not raise

    def test_user_message_submit_exception_handled(self) -> None:
        """Submit exceptions in user_message are caught and logged."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        submit = MagicMock(side_effect=RuntimeError("submit failed"))
        with patch(
            "airut.gateway.slack.listener.Assistant"
        ) as mock_assistant_cls:
            mock_assistant = mock_assistant_cls.return_value
            listener.start(submit)

        user_msg_call = mock_assistant.user_message.call_args
        assert user_msg_call is not None
        handler_fn = user_msg_call[0][0]

        payload = {
            "user": "U123",
            "text": "test",
            "channel": "D456",
            "thread_ts": "ts1",
        }
        # Should not raise
        handler_fn(payload=payload, set_status=MagicMock())


class TestDoubleStartGuard:
    def test_double_start_is_noop(self) -> None:
        """Calling start() twice does not register handlers twice."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        submit = MagicMock()
        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(submit)
            listener.start(submit)  # Should be a no-op

        # connect() should only be called once
        handler.connect.assert_called_once()


class TestConnectionHealthListeners:
    def test_ws_close_sets_degraded(self) -> None:
        """WebSocket close callback sets status to DEGRADED."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        assert listener.status.health == ChannelHealth.CONNECTED

        # Simulate WebSocket close
        listener._on_ws_close(1006, "abnormal closure")

        assert listener.status.health == ChannelHealth.DEGRADED
        assert "1006" in (listener.status.message or "")

    def test_ws_error_sets_degraded(self) -> None:
        """WebSocket error callback sets status to DEGRADED."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        listener._on_ws_error(ConnectionError("network down"))

        assert listener.status.health == ChannelHealth.DEGRADED
        assert "network down" in (listener.status.message or "")

    def test_ws_close_then_message_recovers_connected(self) -> None:
        """Status recovers to CONNECTED when a message arrives after close."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        assert listener.status.health == ChannelHealth.CONNECTED

        # WebSocket closes — status goes to DEGRADED
        listener._on_ws_close(1006, "abnormal closure")
        assert listener.status.health == ChannelHealth.DEGRADED

        # SDK auto-reconnects and delivers a message — status should recover
        listener._on_ws_message("hello")
        assert listener.status.health == ChannelHealth.CONNECTED

    def test_ws_error_then_message_recovers_connected(self) -> None:
        """Status recovers to CONNECTED when a message arrives after error."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        listener._on_ws_error(ConnectionError("network down"))
        assert listener.status.health == ChannelHealth.DEGRADED

        listener._on_ws_message("hello")
        assert listener.status.health == ChannelHealth.CONNECTED

    def test_ws_message_noop_when_already_connected(self) -> None:
        """Message callback is a no-op when already CONNECTED."""
        app = MagicMock()
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        original_status = listener.status
        listener._on_ws_message("hello")
        # Status object should be unchanged (no unnecessary re-assignment)
        assert listener.status is original_status

    def test_install_listeners_no_client(self) -> None:
        """Logs warning when handler has no client attribute."""
        handler = MagicMock()
        # Remove client attribute so getattr returns None
        del handler.client
        listener = SlackChannelListener(
            _make_config(),
            app=MagicMock(),
            handler=handler,
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            with patch("airut.gateway.slack.listener.logger") as mock_logger:
                listener.start(MagicMock())

        mock_logger.warning.assert_any_call(
            "Socket Mode handler has no 'client' attribute; "
            "connection health listeners not installed"
        )

    def test_install_listeners_missing_close_listeners(self) -> None:
        """Logs warning when client lacks on_close_listeners."""
        handler = MagicMock()
        del handler.client.on_close_listeners
        listener = SlackChannelListener(
            _make_config(),
            app=MagicMock(),
            handler=handler,
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            with patch("airut.gateway.slack.listener.logger") as mock_logger:
                listener.start(MagicMock())

        mock_logger.warning.assert_any_call(
            "Socket Mode client has no 'on_close_listeners'; "
            "close events will not be tracked"
        )

    def test_install_listeners_missing_error_listeners(self) -> None:
        """Logs warning when client lacks on_error_listeners."""
        handler = MagicMock()
        del handler.client.on_error_listeners
        listener = SlackChannelListener(
            _make_config(),
            app=MagicMock(),
            handler=handler,
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            with patch("airut.gateway.slack.listener.logger") as mock_logger:
                listener.start(MagicMock())

        mock_logger.warning.assert_any_call(
            "Socket Mode client has no 'on_error_listeners'; "
            "error events will not be tracked"
        )

    def test_install_listeners_missing_message_listeners(self) -> None:
        """Logs warning when client lacks on_message_listeners."""
        handler = MagicMock()
        del handler.client.on_message_listeners
        listener = SlackChannelListener(
            _make_config(),
            app=MagicMock(),
            handler=handler,
        )

        with patch("airut.gateway.slack.listener.Assistant"):
            with patch("airut.gateway.slack.listener.logger") as mock_logger:
                listener.start(MagicMock())

        mock_logger.warning.assert_any_call(
            "Socket Mode client has no 'on_message_listeners'; "
            "reconnect recovery will not be tracked"
        )


class TestHandlerRegistrationWithRealApp:
    """Tests using a real Bolt App to verify handler registration works.

    The previous tests use MagicMock for the App, which auto-creates
    attributes and masks bugs where code accesses ``App.assistant`` as
    an attribute (it's a method). These tests use a real ``App`` to
    catch that class of error.
    """

    def test_register_handlers_with_real_app(self) -> None:
        """_register_handlers must work with a real slack_bolt.App.

        Reproduces: AttributeError: 'function' object has no attribute
        'thread_started' — caused by treating ``App.assistant`` (a method)
        as an ``Assistant`` middleware instance.
        """
        app = App(
            token="xoxb-test",
            signing_secret="test-secret",
            token_verification_enabled=False,
        )
        handler = MagicMock()
        listener = SlackChannelListener(
            _make_config(), app=app, handler=handler
        )

        submit = MagicMock()
        # This should NOT raise AttributeError
        listener.start(submit)

        handler.connect.assert_called_once()
        assert listener.status.health == ChannelHealth.CONNECTED
