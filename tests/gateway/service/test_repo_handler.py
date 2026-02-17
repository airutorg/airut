# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for repo_handler module."""

from pathlib import Path
from unittest.mock import MagicMock

from .conftest import make_message, make_service


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


class TestStartListener:
    def test_updates_mirror_and_starts_listener(
        self, email_config, tmp_path: Path
    ) -> None:
        """start_listener updates git mirror and starts adapter listener."""
        svc, handler = make_service(email_config, tmp_path)

        handler.start_listener()

        handler.conversation_manager.mirror.update_mirror.assert_called_once()
        handler.adapter.listener.start.assert_called_once()

    def test_submit_callback_forwards_to_service(
        self, email_config, tmp_path: Path
    ) -> None:
        """The submit callback passed to listener.start forwards messages."""
        svc, handler = make_service(email_config, tmp_path)
        svc.submit_message = MagicMock(return_value=True)

        handler.start_listener()

        # Extract the submit callback passed to listener.start
        call_args = handler.adapter.listener.start.call_args
        submit_fn = call_args[1]["submit"]

        msg = make_message()
        result = submit_fn(msg)
        assert result is True
        svc.submit_message.assert_called_once_with(msg, handler)


class TestStop:
    def test_stops_listener(self, email_config, tmp_path: Path) -> None:
        """stop() delegates to adapter.listener.stop()."""
        svc, handler = make_service(email_config, tmp_path)

        handler.stop()

        handler.adapter.listener.stop.assert_called_once()
