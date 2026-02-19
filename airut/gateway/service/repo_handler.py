# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-repository handler for the gateway service.

This module contains the RepoHandler class that manages:
- Channel adapter lifecycle (listener start/stop)
- Conversation management for a single repository
- Container executor for Claude Code
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from airut.gateway.channel import ChannelAdapter, RawMessage
from airut.gateway.config import RepoServerConfig
from airut.gateway.conversation import ConversationManager
from airut.gateway.service.adapter_factory import create_adapters


if TYPE_CHECKING:
    from airut.gateway.service.gateway import GatewayService

logger = logging.getLogger(__name__)


class RepoHandler:
    """Per-repo components and listener lifecycle.

    Encapsulates all components that are specific to a single repository:
    channel adapters, conversation management, and container execution.

    The channel listeners manage their own threads internally. RepoHandler
    delegates lifecycle to each adapter's listener.

    Attributes:
        config: Per-repo server-side configuration.
        service: Back-reference to the parent service for shared resources.
        adapters: Channel adapters keyed by channel type.
    """

    def __init__(
        self,
        config: RepoServerConfig,
        service: GatewayService,
    ) -> None:
        """Initialize per-repo components.

        Args:
            config: Per-repo server-side configuration.
            service: Parent service for shared resources.
        """
        self.config = config
        self.service = service

        self.adapters: dict[str, ChannelAdapter] = create_adapters(config)
        self.conversation_manager = ConversationManager(
            repo_url=config.git_repo_url,
            storage_dir=config.storage_dir,
        )

        channel_types = ", ".join(self.adapters.keys())
        logger.info(
            "RepoHandler initialized for '%s' (channels=[%s])",
            config.repo_id,
            channel_types,
        )

    def start_listener(self) -> None:
        """Start all channel listeners.

        Updates the git mirror first, then starts each adapter's listener
        with a per-adapter submit callback. Each listener manages its
        own threads.
        """
        logger.info(
            "Repo '%s': updating git mirror from origin...",
            self.config.repo_id,
        )
        self.conversation_manager.mirror.update_mirror()

        for channel_type, adapter in self.adapters.items():
            adapter.listener.start(
                submit=lambda msg, a=adapter: self._submit_message(msg, a)
            )
            logger.info(
                "Repo '%s': listener started (channel=%s)",
                self.config.repo_id,
                channel_type,
            )

    def _submit_message(
        self,
        message: RawMessage[Any],
        adapter: ChannelAdapter,
    ) -> bool:
        """Submit a raw message for authentication and processing.

        Authentication happens in the worker thread, not here.

        Args:
            message: Raw message envelope to process.
            adapter: The originating channel adapter.

        Returns:
            True if message was submitted, False if pool not ready.
        """
        return self.service.submit_message(message, self, adapter)

    def stop(self) -> None:
        """Stop all listeners and close resources."""
        for channel_type, adapter in self.adapters.items():
            adapter.listener.stop()
            logger.info(
                "Repo '%s': listener stopped (channel=%s)",
                self.config.repo_id,
                channel_type,
            )
