# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackChannelListener."""

import inspect
from unittest.mock import MagicMock, patch

from slack_bolt import App

from airut._json_types import JsonDict, JsonValue
from airut.gateway.channel import ChannelHealth, RawMessage
from airut.gateway.slack.authorizer import SlackAuthorizer
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.listener import SlackChannelListener
from airut.gateway.slack.thread_store import SlackThreadStore


def _make_config(
    *, allowed_channels: tuple[str, ...] = ()
) -> SlackChannelConfig:
    return SlackChannelConfig(
        bot_token="xoxb-test-token",
        app_token="xapp-test-token",
        authorized=({"workspace_members": True},),
        allowed_channels=allowed_channels,
    )


def _make_listener(
    *,
    config: SlackChannelConfig | None = None,
    app: App | MagicMock | None = None,
    handler: MagicMock | None = None,
    thread_store: MagicMock | None = None,
    authorizer: MagicMock | None = None,
) -> SlackChannelListener:
    if thread_store is None:
        thread_store = MagicMock(spec=SlackThreadStore)
        thread_store.get_conversation_id.return_value = None
    if authorizer is None:
        authorizer = MagicMock(spec=SlackAuthorizer)
        authorizer.get_bot_user_id.return_value = "UBOT"
    return SlackChannelListener(
        config or _make_config(),
        thread_store,
        authorizer,
        app=app if app is not None else MagicMock(),
        handler=handler if handler is not None else MagicMock(),
    )


class TestSlackChannelListener:
    def test_initial_status_starting(self) -> None:
        with (
            patch("airut.gateway.slack.listener.App"),
            patch("airut.gateway.slack.listener.SocketModeHandler"),
        ):
            listener = _make_listener()
        assert listener.status.health == ChannelHealth.STARTING

    def test_start_connects_and_sets_connected(self) -> None:
        app = MagicMock()
        handler = MagicMock()
        listener = _make_listener(app=app, handler=handler)
        submit = MagicMock()

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(submit)

        handler.connect.assert_called_once()
        assert listener.status.health == ChannelHealth.CONNECTED

    def test_stop_closes_handler(self) -> None:
        handler = MagicMock()
        listener = _make_listener(handler=handler)
        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        listener.stop()

        handler.close.assert_called_once()
        assert listener.status.health == ChannelHealth.FAILED
        assert listener.status.message == "stopped"

    def test_handlers_registered_on_start(self) -> None:
        app = MagicMock()
        handler = MagicMock()
        listener = _make_listener(app=app, handler=handler)

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
        listener = _make_listener(app=app, handler=handler)

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
        # Extract the function passed to the decorator
        user_msg_call = user_msg_decorator.call_args
        assert user_msg_call is not None
        actual_handler = user_msg_call[0][0]
        actual_handler(payload=payload)

        # Verify submit was called with a RawMessage
        submit.assert_called_once()
        raw: RawMessage = submit.call_args[0][0]
        assert raw.sender == "U123"
        assert raw.content == payload
        assert "Hello bot" in raw.display_title

    def test_user_message_handler_does_not_set_status(self) -> None:
        """Status is managed during prep, not set per inbound message.

        Setting it per-message would lock the Slack composer for the
        whole run (and for coalesced bursts), blocking follow-ups.
        """
        app = MagicMock()
        handler = MagicMock()
        listener = _make_listener(app=app, handler=handler)

        with patch(
            "airut.gateway.slack.listener.Assistant"
        ) as mock_assistant_cls:
            mock_assistant = mock_assistant_cls.return_value
            listener.start(MagicMock(return_value=True))

        user_msg_call = mock_assistant.user_message.call_args
        assert user_msg_call is not None
        actual_handler = user_msg_call[0][0]
        params = inspect.signature(actual_handler).parameters
        assert "set_status" not in params

    def test_thread_started_handler(self) -> None:
        """Verify thread_started handler sets status and says greeting."""
        app = MagicMock()
        handler = MagicMock()
        listener = _make_listener(app=app, handler=handler)
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
        listener = _make_listener(app=app, handler=handler)
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
        listener = _make_listener(app=app, handler=handler)

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
        handler_fn(payload=payload)


class TestDoubleStartGuard:
    def test_double_start_is_noop(self) -> None:
        """Calling start() twice does not register handlers twice."""
        app = MagicMock()
        handler = MagicMock()
        listener = _make_listener(app=app, handler=handler)

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
        listener = _make_listener(app=app, handler=handler)

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
        listener = _make_listener(app=app, handler=handler)

        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())

        listener._on_ws_error(ConnectionError("network down"))

        assert listener.status.health == ChannelHealth.DEGRADED
        assert "network down" in (listener.status.message or "")

    def test_ws_close_then_message_recovers_connected(self) -> None:
        """Status recovers to CONNECTED when a message arrives after close."""
        app = MagicMock()
        handler = MagicMock()
        listener = _make_listener(app=app, handler=handler)

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
        listener = _make_listener(app=app, handler=handler)

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
        listener = _make_listener(app=app, handler=handler)

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
        listener = _make_listener(handler=handler)

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
        listener = _make_listener(handler=handler)

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
        listener = _make_listener(handler=handler)

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
        listener = _make_listener(handler=handler)

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
        listener = _make_listener(app=app, handler=handler)

        submit = MagicMock()
        # This should NOT raise AttributeError
        listener.start(submit)

        handler.connect.assert_called_once()
        assert listener.status.health == ChannelHealth.CONNECTED


class TestChannelEventRegistration:
    def test_channel_event_handlers_registered(self) -> None:
        app = MagicMock()
        listener = _make_listener(app=app, handler=MagicMock())
        with patch("airut.gateway.slack.listener.Assistant"):
            listener.start(MagicMock())
        registered = [c.args[0] for c in app.event.call_args_list]
        assert "app_mention" in registered
        assert "message" in registered

    def test_start_warns_when_bot_id_unresolved(self) -> None:
        authorizer = MagicMock(spec=SlackAuthorizer)
        authorizer.get_bot_user_id.return_value = None
        listener = _make_listener(
            app=MagicMock(), handler=MagicMock(), authorizer=authorizer
        )
        with patch("airut.gateway.slack.listener.Assistant"):
            with patch("airut.gateway.slack.listener.logger") as mock_logger:
                listener.start(MagicMock())
        assert any(
            "Could not resolve bot user ID" in str(c.args[0])
            for c in mock_logger.warning.call_args_list
        )


class TestAppMentionHandler:
    def _listener(
        self,
        *,
        allowed_channels: tuple[str, ...] = (),
        bot_user_id: str | None = "UBOT",
    ) -> tuple[SlackChannelListener, MagicMock]:
        authorizer = MagicMock(spec=SlackAuthorizer)
        authorizer.get_bot_user_id.return_value = bot_user_id
        thread_store = MagicMock(spec=SlackThreadStore)
        thread_store.get_conversation_id.return_value = None
        listener = _make_listener(
            config=_make_config(allowed_channels=allowed_channels),
            thread_store=thread_store,
            authorizer=authorizer,
        )
        submit = MagicMock(return_value=True)
        listener._submit = submit
        return listener, submit

    def test_app_mention_submits(self) -> None:
        listener, submit = self._listener()
        listener._on_app_mention(
            {
                "type": "app_mention",
                "user": "U1",
                "text": "<@UBOT> help",
                "channel": "C1",
                "ts": "T1",
            }
        )
        submit.assert_called_once()
        raw: RawMessage = submit.call_args[0][0]
        assert raw.sender == "U1"
        assert raw.content["channel"] == "C1"

    def test_app_mention_dedup(self) -> None:
        listener, submit = self._listener()
        event: JsonDict = {
            "user": "U1",
            "text": "x",
            "channel": "C1",
            "ts": "T1",
        }
        listener._on_app_mention(event)
        listener._on_app_mention(event)
        submit.assert_called_once()

    def test_app_mention_allowlist_blocks(self) -> None:
        listener, submit = self._listener(allowed_channels=("C9",))
        listener._on_app_mention(
            {"user": "U1", "text": "x", "channel": "C1", "ts": "T1"}
        )
        submit.assert_not_called()

    def test_app_mention_allowlist_permits(self) -> None:
        listener, submit = self._listener(allowed_channels=("C1",))
        listener._on_app_mention(
            {"user": "U1", "text": "x", "channel": "C1", "ts": "T1"}
        )
        submit.assert_called_once()

    def test_app_mention_bot_id_skipped(self) -> None:
        listener, submit = self._listener()
        listener._on_app_mention(
            {
                "type": "app_mention",
                "user": "U1",
                "bot_id": "B1",
                "text": "<@UBOT> help",
                "channel": "C1",
                "ts": "T1",
            }
        )
        submit.assert_not_called()

    def test_app_mention_subtype_skipped(self) -> None:
        listener, submit = self._listener()
        listener._on_app_mention(
            {
                "type": "app_mention",
                "user": "U1",
                "subtype": "message_changed",
                "text": "<@UBOT> help",
                "channel": "C1",
                "ts": "T1",
            }
        )
        submit.assert_not_called()


class TestChannelMessageHandler:
    def _listener(
        self,
        *,
        allowed_channels: tuple[str, ...] = (),
        sticky_conv: str | None = None,
        bot_user_id: str | None = "UBOT",
    ) -> tuple[SlackChannelListener, MagicMock, MagicMock]:
        authorizer = MagicMock(spec=SlackAuthorizer)
        authorizer.get_bot_user_id.return_value = bot_user_id
        thread_store = MagicMock(spec=SlackThreadStore)
        thread_store.get_conversation_id.return_value = sticky_conv
        listener = _make_listener(
            config=_make_config(allowed_channels=allowed_channels),
            thread_store=thread_store,
            authorizer=authorizer,
        )
        submit = MagicMock(return_value=True)
        listener._submit = submit
        return listener, submit, thread_store

    def _event(self, **overrides: JsonValue) -> JsonDict:
        event: JsonDict = {
            "type": "message",
            "channel_type": "channel",
            "user": "U1",
            "text": "hello",
            "channel": "C1",
            "ts": "T2",
            "thread_ts": "T1",
        }
        event.update(overrides)
        return event

    def test_dm_channel_type_skipped(self) -> None:
        listener, submit, _ = self._listener(sticky_conv="conv1")
        listener._on_channel_message(self._event(channel_type="im"))
        submit.assert_not_called()

    def test_subtype_skipped(self) -> None:
        listener, submit, _ = self._listener(sticky_conv="conv1")
        listener._on_channel_message(self._event(subtype="message_changed"))
        submit.assert_not_called()

    def test_file_share_subtype_submits_when_sticky(self) -> None:
        """A file uploaded to an engaged thread must be processed.

        Slack tags file uploads with ``subtype: "file_share"``; the blanket
        subtype filter would otherwise drop attachments posted after the bot
        joined the thread.
        """
        listener, submit, _ = self._listener(sticky_conv="conv1")
        listener._on_channel_message(
            self._event(
                subtype="file_share",
                text="",
                files=[{"name": "data.csv", "url_private": "u"}],
            )
        )
        submit.assert_called_once()

    def test_file_share_subtype_submits_with_mention(self) -> None:
        """A file uploaded with a bot mention engages a fresh thread."""
        listener, submit, _ = self._listener(sticky_conv=None)
        listener._on_channel_message(
            self._event(
                subtype="file_share",
                text="<@UBOT> look at this",
                files=[{"name": "data.csv", "url_private": "u"}],
            )
        )
        submit.assert_called_once()

    def test_file_share_without_engagement_dropped(self) -> None:
        """A file upload to a non-engaged thread with no mention is ignored."""
        listener, submit, _ = self._listener(sticky_conv=None)
        listener._on_channel_message(
            self._event(
                subtype="file_share",
                text="just sharing",
                files=[{"name": "data.csv", "url_private": "u"}],
            )
        )
        submit.assert_not_called()

    def test_file_share_bot_id_skipped(self) -> None:
        """The bot's own file uploads (bot_id set) never re-trigger."""
        listener, submit, _ = self._listener(sticky_conv="conv1")
        listener._on_channel_message(
            self._event(subtype="file_share", bot_id="B1")
        )
        submit.assert_not_called()

    def test_bot_message_skipped(self) -> None:
        listener, submit, _ = self._listener(sticky_conv="conv1")
        listener._on_channel_message(self._event(bot_id="B1"))
        submit.assert_not_called()

    def test_sticky_thread_submits_without_mention(self) -> None:
        listener, submit, store = self._listener(sticky_conv="conv1")
        listener._on_channel_message(self._event(text="no mention here"))
        submit.assert_called_once()
        store.get_conversation_id.assert_called_with("C1", "T1")

    def test_mention_submits_when_not_sticky(self) -> None:
        listener, submit, _ = self._listener(sticky_conv=None)
        listener._on_channel_message(self._event(text="<@UBOT> hi"))
        submit.assert_called_once()

    def test_no_engagement_dropped(self) -> None:
        listener, submit, _ = self._listener(sticky_conv=None)
        listener._on_channel_message(self._event(text="just chatting"))
        submit.assert_not_called()

    def test_top_level_uses_ts_for_thread_lookup(self) -> None:
        listener, submit, store = self._listener(sticky_conv="conv1")
        event = self._event(text="follow up")
        del event["thread_ts"]
        listener._on_channel_message(event)
        store.get_conversation_id.assert_called_with("C1", "T2")
        submit.assert_called_once()

    def test_dedup_against_app_mention(self) -> None:
        listener, submit, _ = self._listener(sticky_conv=None)
        listener._on_app_mention(
            {"user": "U1", "text": "<@UBOT> hi", "channel": "C1", "ts": "T2"}
        )
        listener._on_channel_message(self._event(text="<@UBOT> hi"))
        submit.assert_called_once()

    def test_pipe_form_mention_matches(self) -> None:
        listener, submit, _ = self._listener(sticky_conv=None)
        listener._on_channel_message(self._event(text="hey <@UBOT|airut> go"))
        submit.assert_called_once()

    def test_allowlist_blocks_channel_message(self) -> None:
        listener, submit, _ = self._listener(
            allowed_channels=("C9",), sticky_conv="conv1"
        )
        listener._on_channel_message(self._event())
        submit.assert_not_called()

    def test_no_bot_id_disables_mention_engagement(self) -> None:
        listener, submit, _ = self._listener(sticky_conv=None, bot_user_id=None)
        listener._on_channel_message(self._event(text="<@UBOT> hi"))
        submit.assert_not_called()

    def test_submit_exception_handled(self) -> None:
        listener, submit, _ = self._listener(sticky_conv="conv1")
        submit.side_effect = RuntimeError("boom")
        # Should not raise.
        listener._on_channel_message(self._event(text="hi"))

    def test_dedup_evicts_oldest_over_capacity(self) -> None:
        from airut.gateway.slack.listener import _DEDUP_CAPACITY

        listener, _, _ = self._listener()
        # Fill the dedup set beyond capacity; the first key is evicted and
        # can be claimed again.
        assert listener._claim_event("C1", "first") is True
        for i in range(_DEDUP_CAPACITY):
            listener._claim_event("C1", f"k{i}")
        assert len(listener._seen_events) == _DEDUP_CAPACITY
        assert listener._claim_event("C1", "first") is True
