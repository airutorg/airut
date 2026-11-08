# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Channel adapter factory.

Dispatches on channel config type to create the correct adapter
implementation, and stops their listeners.  Kept in its own module so
that ``repo_handler.py`` stays channel-agnostic at the module level.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from airut.gateway.channel import ChannelAdapter
from airut.gateway.config import RepoServerConfig


logger = logging.getLogger(__name__)


def create_adapters(config: RepoServerConfig) -> dict[str, ChannelAdapter]:
    """Create channel adapters for all configured channels.

    Dispatches on each channel config type to create the correct
    adapter implementation.

    Imports are deferred to keep this module lightweight and to
    avoid pulling in heavy channel dependencies at import time.

    If creating an adapter fails, the listeners of those already created
    are stopped before the error propagates: a listener can hold
    resources from construction (e.g. the Slack SDK's background
    threads).

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
    try:
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
                    "Unknown channel config type: "
                    f"{type(channel_config).__name__}"
                )
    except Exception:
        stop_listeners(adapters, config.repo_id)
        raise
    return adapters


def stop_listeners(
    adapters: Mapping[str, ChannelAdapter], repo_id: str
) -> None:
    """Stop the listener of every adapter, even if some fail to stop.

    Safe for listeners that were never started or already stopped (see
    ``ChannelListener.stop``).  A listener that fails to stop is logged
    so the others are still stopped and the caller's own error, if any,
    is not masked.

    Args:
        adapters: Adapters keyed by channel type.
        repo_id: Repository identifier for log context.
    """
    for channel_type, adapter in adapters.items():
        try:
            adapter.listener.stop()
        except Exception:
            logger.exception(
                "Repo '%s': failed to stop listener (channel=%s)",
                repo_id,
                channel_type,
            )
        else:
            logger.info(
                "Repo '%s': listener stopped (channel=%s)",
                repo_id,
                channel_type,
            )
