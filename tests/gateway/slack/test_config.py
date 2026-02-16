# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackChannelConfig."""

import pytest

from airut.gateway.slack.config import SlackChannelConfig


class TestSlackChannelConfig:
    def test_valid_workspace_members_rule(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test-token",
            app_token="xapp-test-token",
            authorized=[{"workspace_members": True}],
        )
        assert config.bot_token == "xoxb-test-token"
        assert config.app_token == "xapp-test-token"
        assert len(config.authorized) == 1

    def test_valid_user_group_rule(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test-token",
            app_token="xapp-test-token",
            authorized=[{"user_group": "engineering"}],
        )
        assert config.authorized[0]["user_group"] == "engineering"

    def test_valid_user_id_rule(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test-token",
            app_token="xapp-test-token",
            authorized=[{"user_id": "U12345678"}],
        )
        assert config.authorized[0]["user_id"] == "U12345678"

    def test_multiple_rules(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test-token",
            app_token="xapp-test-token",
            authorized=[
                {"user_group": "engineering"},
                {"user_id": "U11111111"},
                {"user_id": "U22222222"},
            ],
        )
        assert len(config.authorized) == 3

    def test_empty_authorized_raises(self) -> None:
        with pytest.raises(ValueError, match="At least one authorization"):
            SlackChannelConfig(
                bot_token="xoxb-test-token",
                app_token="xapp-test-token",
                authorized=[],
            )

    def test_unknown_rule_key_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown key"):
            SlackChannelConfig(
                bot_token="xoxb-test-token",
                app_token="xapp-test-token",
                authorized=[{"unknown_key": "value"}],
            )

    def test_workspace_members_non_bool_raises(self) -> None:
        with pytest.raises(ValueError, match="must be a bool"):
            SlackChannelConfig(
                bot_token="xoxb-test-token",
                app_token="xapp-test-token",
                authorized=[{"workspace_members": "yes"}],
            )

    def test_user_group_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            SlackChannelConfig(
                bot_token="xoxb-test-token",
                app_token="xapp-test-token",
                authorized=[{"user_group": ""}],
            )

    def test_user_id_non_string_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            SlackChannelConfig(
                bot_token="xoxb-test-token",
                app_token="xapp-test-token",
                authorized=[{"user_id": 123}],  # type: ignore[list-item]
            )

    def test_rule_with_multiple_keys_raises(self) -> None:
        with pytest.raises(ValueError, match="exactly one key"):
            SlackChannelConfig(
                bot_token="xoxb-test-token",
                app_token="xapp-test-token",
                authorized=[{"workspace_members": True, "user_id": "U123"}],
            )

    def test_rule_empty_dict_raises(self) -> None:
        with pytest.raises(ValueError, match="exactly one key"):
            SlackChannelConfig(
                bot_token="xoxb-test-token",
                app_token="xapp-test-token",
                authorized=[{}],
            )

    def test_secrets_registered(self) -> None:
        from airut.logging import SecretFilter

        SecretFilter.clear_secrets()
        SlackChannelConfig(
            bot_token="xoxb-secret-bot-token",
            app_token="xapp-secret-app-token",
            authorized=[{"workspace_members": True}],
        )
        # Verify secrets are registered by checking they would be redacted
        assert SecretFilter._pattern is not None
        assert SecretFilter._pattern.search("xoxb-secret-bot-token")
        assert SecretFilter._pattern.search("xapp-secret-app-token")

    def test_frozen(self) -> None:
        config = SlackChannelConfig(
            bot_token="xoxb-test-token",
            app_token="xapp-test-token",
            authorized=[{"workspace_members": True}],
        )
        with pytest.raises(AttributeError):
            config.bot_token = "new-token"  # type: ignore[misc]
