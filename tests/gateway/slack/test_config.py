# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackChannelConfig."""

import pytest

from airut.gateway.slack.config import SlackChannelConfig


class TestSlackChannelConfig:
    def test_basic_creation(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test-token",
            app_token="xapp-test-token",
            authorized=({"workspace_members": True},),
        )
        assert config.bot_token == "xoxb-test-token"
        assert config.app_token == "xapp-test-token"
        assert config.authorized == ({"workspace_members": True},)

    def test_channel_type(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test",
            app_token="xapp-test",
            authorized=({"workspace_members": True},),
        )
        assert config.channel_type == "slack"

    def test_channel_info(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test",
            app_token="xapp-test",
            authorized=({"workspace_members": True},),
        )
        assert config.channel_info == "Slack (Socket Mode)"

    def test_empty_authorized_raises(self) -> None:
        with pytest.raises(ValueError, match="authorization rule"):
            SlackChannelConfig(
                bot_token="xoxb-test",
                app_token="xapp-test",
                authorized=(),
            )

    def test_frozen(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test",
            app_token="xapp-test",
            authorized=({"workspace_members": True},),
        )
        with pytest.raises(AttributeError):
            config.bot_token = "new"  # type: ignore[misc]

    def test_list_coerced_to_tuple(self) -> None:
        """Passing a list for authorized gets coerced to tuple."""
        config = SlackChannelConfig(
            bot_token="xoxb-test",
            app_token="xapp-test",
            authorized=[{"workspace_members": True}],  # type: ignore[arg-type]
        )
        assert isinstance(config.authorized, tuple)

    def test_secret_filter_registration(self) -> None:
        """Both tokens are registered with SecretFilter."""
        from unittest.mock import patch

        with patch("airut.gateway.slack.config.SecretFilter") as mock_sf:
            SlackChannelConfig(
                bot_token="xoxb-secret-token",
                app_token="xapp-secret-token",
                authorized=({"workspace_members": True},),
            )

        mock_sf.register_secret.assert_any_call("xoxb-secret-token")
        mock_sf.register_secret.assert_any_call("xapp-secret-token")

    def test_multiple_rules(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test",
            app_token="xapp-test",
            authorized=(
                {"user_group": "engineering"},
                {"user_id": "U12345678"},
            ),
        )
        assert len(config.authorized) == 2
