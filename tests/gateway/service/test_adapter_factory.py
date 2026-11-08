# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for adapter_factory module."""

from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.service.adapter_factory import (
    create_adapters,
    stop_listeners,
)


class TestCreateAdapters:
    def test_creates_email_adapter(self) -> None:
        """create_adapters returns EmailChannelAdapter dict."""
        from airut.gateway.config import (
            EmailAccountConfig,
            EmailAuthConfig,
            EmailChannelConfig,
            ImapConfig,
            RepoServerConfig,
            SmtpConfig,
        )

        email_config = EmailChannelConfig(
            account=EmailAccountConfig(
                username="test@example.com",
                from_address="Bot <bot@example.com>",
                password="pass",
            ),
            imap=ImapConfig(server="imap.example.com", port=993),
            smtp=SmtpConfig(server="smtp.example.com", port=587),
            auth=EmailAuthConfig(
                authorized_senders=["user@example.com"],
                trusted_authserv_id="mx.example.com",
            ),
        )

        config = MagicMock(spec=RepoServerConfig)
        config.channels = {"email": email_config}
        config.repo_id = "test-repo"

        with patch(
            "airut.gateway.email.adapter.EmailChannelAdapter"
        ) as mock_cls:
            mock_cls.from_config.return_value = MagicMock()
            result = create_adapters(config)

        mock_cls.from_config.assert_called_once_with(
            email_config, repo_id="test-repo"
        )
        assert result == {"email": mock_cls.from_config.return_value}

    def test_creates_slack_adapter(self) -> None:
        """create_adapters returns SlackChannelAdapter dict."""
        from airut.gateway.config import RepoServerConfig
        from airut.gateway.slack.config import SlackChannelConfig

        slack_config = SlackChannelConfig(
            bot_token="xoxb-test-factory",
            app_token="xapp-test-factory",
            authorized=({"workspace_members": True},),
        )

        config = MagicMock(spec=RepoServerConfig)
        config.channels = {"slack": slack_config}
        config.repo_id = "test-repo"

        with patch(
            "airut.gateway.slack.adapter.SlackChannelAdapter"
        ) as mock_cls:
            mock_cls.from_config.return_value = MagicMock()
            result = create_adapters(config)

        mock_cls.from_config.assert_called_once_with(
            slack_config, repo_id="test-repo"
        )
        assert result == {"slack": mock_cls.from_config.return_value}

    def test_unknown_channel_config_raises(self) -> None:
        """create_adapters raises ValueError for unknown channel config."""
        from airut.gateway.config import RepoServerConfig

        unknown_config = MagicMock()  # Not an EmailChannelConfig
        unknown_config.__class__.__name__ = "UnknownConfig"

        config = MagicMock(spec=RepoServerConfig)
        config.channels = {"unknown": unknown_config}
        config.repo_id = "test-repo"

        with pytest.raises(ValueError, match="Unknown channel config type"):
            create_adapters(config)


class TestCreateAdaptersFailure:
    def test_stops_already_created_listeners(self) -> None:
        """Adapters created before a failing one have their listeners stopped.

        A listener can hold resources from construction (e.g. the Slack
        SDK's background threads), which would otherwise leak.
        """
        from airut.gateway.config import EmailChannelConfig, RepoServerConfig
        from airut.gateway.slack.config import SlackChannelConfig

        config = MagicMock(spec=RepoServerConfig)
        config.channels = {
            "email": MagicMock(spec=EmailChannelConfig),
            "slack": MagicMock(spec=SlackChannelConfig),
        }
        config.repo_id = "test-repo"
        email_adapter = MagicMock()

        with (
            patch(
                "airut.gateway.email.adapter.EmailChannelAdapter"
            ) as email_cls,
            patch(
                "airut.gateway.slack.adapter.SlackChannelAdapter"
            ) as slack_cls,
        ):
            email_cls.from_config.return_value = email_adapter
            slack_cls.from_config.side_effect = RuntimeError("invalid_auth")
            with pytest.raises(RuntimeError, match="invalid_auth"):
                create_adapters(config)

        email_adapter.listener.stop.assert_called_once()


class TestStopListeners:
    def test_stops_all_and_logs_failures(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Every listener is stopped even when an earlier one fails."""
        failing, other = MagicMock(), MagicMock()
        failing.listener.stop.side_effect = OSError("closed")

        stop_listeners({"email": failing, "slack": other}, "repo")

        other.listener.stop.assert_called_once()
        assert "Repo 'repo': failed to stop listener (channel=email)" in (
            caplog.text
        )
