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


def create_adapter(config: RepoServerConfig) -> ChannelAdapter:
    """Create the appropriate channel adapter for a repo config.

    Dispatches on the channel config type to create the correct
    adapter implementation. Currently only email is supported; new
    channel types (Slack, etc.) add ``elif`` branches here.

    Imports are deferred to keep this module lightweight and to
    avoid pulling in heavy channel dependencies at import time.

    Args:
        config: Per-repo server configuration.

    Returns:
        ChannelAdapter implementation for the configured channel.
    """
    from airut.gateway.config import EmailChannelConfig
    from airut.gateway.email.adapter import EmailChannelAdapter

    if isinstance(config.channel, EmailChannelConfig):
        return EmailChannelAdapter.from_config(
            config.channel, repo_id=config.repo_id
        )

    raise ValueError(
        f"Unknown channel config type: {type(config.channel).__name__}"
    )
