# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Channel adapter factory.

Dispatches on channel config type to create the correct adapter
implementation.  Kept in its own module so that ``repo_handler.py``
stays channel-agnostic at the module level.
"""

from __future__ import annotations

from airut.gateway.channel import ChannelAdapter
from airut.gateway.config import RepoServerConfig


def create_adapters(config: RepoServerConfig) -> dict[str, ChannelAdapter]:
    """Create channel adapters for all configured channels.

    Dispatches on each channel config type to create the correct
    adapter implementation.

    Imports are deferred to keep this module lightweight and to
    avoid pulling in heavy channel dependencies at import time.

    Args:
        config: Per-repo server configuration.

    Returns:
        Mapping of channel type to adapter implementation.
    """
    from airut.gateway.config import EmailChannelConfig
    from airut.gateway.email.adapter import EmailChannelAdapter
    from airut.gateway.slack.adapter import SlackChannelAdapter
    from airut.gateway.slack.config import SlackChannelConfig

    adapters: dict[str, ChannelAdapter] = {}
    for channel_type, channel_config in config.channels.items():
        if isinstance(channel_config, EmailChannelConfig):
            adapters[channel_type] = EmailChannelAdapter.from_config(
                channel_config, repo_id=config.repo_id
            )
        elif isinstance(channel_config, SlackChannelConfig):
            adapters[channel_type] = SlackChannelAdapter.from_config(
                channel_config, repo_id=config.repo_id
            )
        else:
            raise ValueError(
                f"Unknown channel config type: {type(channel_config).__name__}"
            )
    return adapters
