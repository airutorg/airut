# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack channel configuration.

Frozen dataclass implementing the ``ChannelConfig`` protocol for Slack.
Holds bot token, app-level token, and authorization rules.
"""

from __future__ import annotations

from dataclasses import dataclass

from airut.gateway.channel import ChannelConfig
from airut.logging import SecretFilter


@dataclass(frozen=True)
class SlackChannelConfig(ChannelConfig):
    """Slack channel configuration (Socket Mode).

    Contains all settings specific to the Slack channel: bot token for
    API calls, app-level token for Socket Mode WebSocket, and
    authorization rules controlling who may interact with the bot.

    Attributes:
        bot_token: Bot User OAuth Token (``xoxb-...``) from the Slack
            app's OAuth & Permissions page.  Used for all Slack API
            calls (``chat.postMessage``, ``users.info``, etc.).
        app_token: App-Level Token (``xapp-...``) for Socket Mode
            WebSocket connections.
        authorized: Authorization rules evaluated in order.  Each rule
            is a dict with exactly one key: ``workspace_members``
            (bool), ``user_group`` (str handle), or ``user_id``
            (str Slack user ID).  First match grants access.
    """

    bot_token: str
    app_token: str
    authorized: tuple[dict[str, str | bool], ...] = ()

    def __post_init__(self) -> None:
        """Validate configuration and register secrets.

        Raises:
            ValueError: If configuration is invalid.
        """
        SecretFilter.register_secret(self.bot_token)
        SecretFilter.register_secret(self.app_token)
        # Coerce list→tuple for true immutability on a frozen dataclass
        if not isinstance(self.authorized, tuple):
            object.__setattr__(self, "authorized", tuple(self.authorized))
        if not self.authorized:
            raise ValueError("At least one authorization rule is required")

    @property
    def channel_type(self) -> str:
        """Return the channel type identifier."""
        return "slack"

    @property
    def channel_info(self) -> str:
        """Return a short description for dashboard display."""
        return "Slack (Socket Mode)"
