# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack channel configuration.

Contains all settings specific to the Slack channel: bot token, app-level
token for Socket Mode, and authorization rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from airut.logging import SecretFilter


@dataclass(frozen=True)
class SlackChannelConfig:
    """Slack channel configuration.

    Attributes:
        bot_token: Bot token (xoxb-...) for API calls.
        app_token: App-level token (xapp-...) for Socket Mode.
        authorized: List of authorization rules. Each rule is a dict
            with exactly one key: ``workspace_members`` (bool),
            ``user_group`` (str), or ``user_id`` (str).
    """

    bot_token: str
    app_token: str
    authorized: list[dict[str, str | bool]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate configuration and register secrets.

        Raises:
            ValueError: If configuration is invalid.
        """
        SecretFilter.register_secret(self.bot_token)
        SecretFilter.register_secret(self.app_token)
        if not self.authorized:
            raise ValueError("At least one authorization rule is required")
        _validate_rules(self.authorized)


_VALID_RULE_KEYS = frozenset({"workspace_members", "user_group", "user_id"})


def _validate_rules(rules: list[dict[str, str | bool]]) -> None:
    """Validate authorization rules.

    Each rule must be a dict with exactly one key from the valid set.

    Args:
        rules: List of authorization rule dicts.

    Raises:
        ValueError: If any rule is invalid.
    """
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict) or len(rule) != 1:
            raise ValueError(
                f"Authorization rule {i}: must be a dict with exactly one key"
            )
        key = next(iter(rule))
        if key not in _VALID_RULE_KEYS:
            raise ValueError(
                f"Authorization rule {i}: unknown key '{key}', "
                f"expected one of {sorted(_VALID_RULE_KEYS)}"
            )
        value = rule[key]
        if key == "workspace_members":
            if not isinstance(value, bool):
                raise ValueError(
                    f"Authorization rule {i}: workspace_members must be a bool"
                )
        elif not isinstance(value, str) or not value:
            raise ValueError(
                f"Authorization rule {i}: {key} must be a non-empty string"
            )
