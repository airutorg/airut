# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for adapter_factory module."""

from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.service.adapter_factory import create_adapter


class TestCreateAdapter:
    def test_creates_email_adapter(self) -> None:
        """create_adapter returns EmailChannelAdapter for email config."""
        from airut.gateway.config import EmailChannelConfig, RepoServerConfig

        email_config = EmailChannelConfig(
            imap_server="imap.example.com",
            imap_port=993,
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="test@example.com",
            password="pass",
            from_address="Bot <bot@example.com>",
            authorized_senders=["user@example.com"],
            trusted_authserv_id="mx.example.com",
        )

        config = MagicMock(spec=RepoServerConfig)
        config.channel = email_config
        config.repo_id = "test-repo"

        with patch(
            "airut.gateway.email.adapter.EmailChannelAdapter"
        ) as mock_cls:
            mock_cls.from_config.return_value = MagicMock()
            result = create_adapter(config)

        mock_cls.from_config.assert_called_once_with(
            email_config, repo_id="test-repo"
        )
        assert result is mock_cls.from_config.return_value

    def test_unknown_channel_config_raises(self) -> None:
        """create_adapter raises ValueError for unknown channel config."""
        from airut.gateway.config import RepoServerConfig

        config = MagicMock(spec=RepoServerConfig)
        config.channel = MagicMock()  # Not an EmailChannelConfig
        config.channel.__class__.__name__ = "UnknownConfig"

        with pytest.raises(ValueError, match="Unknown channel config type"):
            create_adapter(config)
