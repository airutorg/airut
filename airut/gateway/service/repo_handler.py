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
from airut.gateway.service.adapter_factory import create_adapter


if TYPE_CHECKING:
    from airut.gateway.service.gateway import GatewayService

logger = logging.getLogger(__name__)


class RepoHandler:
    """Per-repo components and listener lifecycle.

    Encapsulates all components that are specific to a single repository:
    channel adapter, conversation management, and container execution.

    The channel listener manages its own threads internally. RepoHandler
    delegates lifecycle to the adapter's listener.

    Attributes:
        config: Per-repo server-side configuration.
        service: Back-reference to the parent service for shared resources.
        adapter: Channel adapter for sending replies.
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

        self.adapter: ChannelAdapter = create_adapter(config)
        self.conversation_manager = ConversationManager(
            repo_url=config.git_repo_url,
            storage_dir=config.storage_dir,
        )

        logger.info(
            "RepoHandler initialized for '%s' (channel=%s)",
            config.repo_id,
            config.channel_type,
        )

    def start_listener(self) -> None:
        """Start the channel listener.

        Updates the git mirror first, then delegates to the channel
        adapter's listener. The listener manages its own threads.
        """
        logger.info(
            "Repo '%s': updating git mirror from origin...",
            self.config.repo_id,
        )
        self.conversation_manager.mirror.update_mirror()

        self.adapter.listener.start(
            submit=lambda msg: self._submit_message(msg)
        )

        logger.info(
            "Repo '%s': listener started (channel=%s)",
            self.config.repo_id,
            self.config.channel_type,
        )

    def _submit_message(self, message: RawMessage[Any]) -> bool:
        """Submit a raw message for authentication and processing.

        Authentication happens in the worker thread, not here.

        Args:
            message: Raw message envelope to process.

        Returns:
            True if message was submitted, False if pool not ready.
        """
        return self.service.submit_message(message, self)

    def stop(self) -> None:
        """Stop listener and close resources."""
        self.adapter.listener.stop()
        logger.info("Repo '%s': listener stopped", self.config.repo_id)
