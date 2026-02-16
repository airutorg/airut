# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackListener."""

import sys
from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.slack.config import SlackChannelConfig


def _make_config() -> SlackChannelConfig:
    return SlackChannelConfig(
        bot_token="xoxb-test-token",
        app_token="xapp-test-token",
        authorized=[{"workspace_members": True}],
    )


@pytest.fixture
def _mock_slack_bolt() -> Generator[
    tuple[MagicMock, MagicMock, MagicMock, MagicMock]
]:
    """Mock all slack_bolt modules needed by SlackListener.

    Since slack_bolt is imported locally inside __init__, we mock
    the modules in sys.modules before importing.
    """
    mock_app = MagicMock()
    mock_handler = MagicMock()
    mock_assistant = MagicMock()
    mock_context = MagicMock()

    mock_bolt = MagicMock()
    mock_bolt.App = mock_app

    mock_socket_mode = MagicMock()
    mock_socket_mode.SocketModeHandler = mock_handler

    mock_assistant_mod = MagicMock()
    mock_assistant_mod.Assistant = mock_assistant

    mock_context_mod = MagicMock()
    mock_context_mod.AssistantThreadContext = mock_context

    modules = {
        "slack_bolt": mock_bolt,
        "slack_bolt.adapter": MagicMock(),
        "slack_bolt.adapter.socket_mode": mock_socket_mode,
        "slack_bolt.context": MagicMock(),
        "slack_bolt.context.assistant": mock_context_mod,
        "slack_bolt.middleware": MagicMock(),
        "slack_bolt.middleware.assistant": mock_assistant_mod,
    }

    with patch.dict(sys.modules, modules):
        yield mock_app, mock_handler, mock_assistant, mock_context


class TestSlackListener:
    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_init_creates_app_and_handler(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        mock_app, mock_handler, mock_assistant, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        config = _make_config()
        listener = SlackListener(config)

        mock_app.assert_called_once_with(token="xoxb-test-token")
        mock_handler.assert_called_once_with(
            mock_app.return_value, "xapp-test-token"
        )
        assert listener.app is mock_app.return_value

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_connect_starts_handler(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        mock_app, mock_handler, _, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        listener = SlackListener(_make_config())
        listener.connect()

        mock_handler.return_value.connect.assert_called_once()

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_close_disconnects_handler(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        _, mock_handler, _, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        listener = SlackListener(_make_config())
        listener.close()

        mock_handler.return_value.close.assert_called_once()

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_interrupt_calls_close(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        _, mock_handler, _, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        listener = SlackListener(_make_config())
        listener.interrupt()

        mock_handler.return_value.close.assert_called_once()

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_thread_started_handler(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        """Verify thread_started handler calls say()."""
        _, _, mock_assistant_cls, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        mock_assistant = mock_assistant_cls.return_value
        # Make decorator return the function (passthrough)
        mock_assistant.thread_started = MagicMock(side_effect=lambda fn: fn)
        mock_assistant.thread_context_changed = MagicMock(
            side_effect=lambda fn: fn
        )
        mock_assistant.user_message = MagicMock(side_effect=lambda fn: fn)

        SlackListener(_make_config())

        # Get the registered function (called as decorator argument)
        mock_assistant.thread_started.assert_called_once()
        handler_fn = mock_assistant.thread_started.call_args[0][0]

        mock_say = MagicMock()
        handler_fn(say=mock_say, set_suggested_prompts=MagicMock())
        mock_say.assert_called_once()

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_context_changed_handler(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        """Verify thread_context_changed handler runs without error."""
        _, _, mock_assistant_cls, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        mock_assistant = mock_assistant_cls.return_value
        mock_assistant.thread_started = MagicMock(side_effect=lambda fn: fn)
        mock_assistant.thread_context_changed = MagicMock(
            side_effect=lambda fn: fn
        )
        mock_assistant.user_message = MagicMock(side_effect=lambda fn: fn)

        SlackListener(_make_config())

        handler_fn = mock_assistant.thread_context_changed.call_args[0][0]
        handler_fn(context=MagicMock())

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_user_message_with_callback(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        """Verify user_message handler invokes submit_callback."""
        _, _, mock_assistant_cls, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        mock_assistant = mock_assistant_cls.return_value
        mock_assistant.thread_started = MagicMock(side_effect=lambda fn: fn)
        mock_assistant.thread_context_changed = MagicMock(
            side_effect=lambda fn: fn
        )
        mock_assistant.user_message = MagicMock(side_effect=lambda fn: fn)

        callback = MagicMock()
        SlackListener(_make_config(), submit_callback=callback)

        handler_fn = mock_assistant.user_message.call_args[0][0]
        payload = {"text": "hello", "user": "U123"}
        handler_fn(payload=payload, say=MagicMock(), set_status=MagicMock())
        callback.assert_called_once_with(payload)

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_user_message_without_callback(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        """Verify user_message handler logs when no callback is set."""
        _, _, mock_assistant_cls, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        mock_assistant = mock_assistant_cls.return_value
        mock_assistant.thread_started = MagicMock(side_effect=lambda fn: fn)
        mock_assistant.thread_context_changed = MagicMock(
            side_effect=lambda fn: fn
        )
        mock_assistant.user_message = MagicMock(side_effect=lambda fn: fn)

        SlackListener(_make_config(), submit_callback=None)

        handler_fn = mock_assistant.user_message.call_args[0][0]
        # Should not raise
        handler_fn(
            payload={"text": "hello"},
            say=MagicMock(),
            set_status=MagicMock(),
        )

    @pytest.mark.usefixtures("_mock_slack_bolt")
    def test_assistant_middleware_registered(
        self,
        _mock_slack_bolt: tuple[MagicMock, MagicMock, MagicMock, MagicMock],
    ) -> None:
        """Verify the Assistant middleware is added to the App."""
        mock_app, _, mock_assistant_cls, _ = _mock_slack_bolt
        from airut.gateway.slack.listener import SlackListener

        SlackListener(_make_config())
        mock_app.return_value.use.assert_called_once_with(
            mock_assistant_cls.return_value
        )
