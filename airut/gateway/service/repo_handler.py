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
import threading
from typing import TYPE_CHECKING, Any

from airut.gateway.channel import ChannelAdapter, ChannelStatus, RawMessage
from airut.gateway.config import RepoServerConfig
from airut.gateway.conversation import ConversationManager
from airut.gateway.service.adapter_factory import (
    create_adapters,
    stop_listeners,
)


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
        # Serializes stop(): a failed start stops the listeners itself,
        # possibly while the service is stopping them on another thread,
        # and listeners do not support concurrent stops.
        self._stop_lock = threading.Lock()

        # Before the adapters: their listeners can hold resources from
        # construction, which a failed clone would otherwise leak.
        self.conversation_manager = ConversationManager(
            repo_url=config.git_repo_url,
            storage_dir=config.storage_dir,
        )
        self.adapters: dict[str, ChannelAdapter] = create_adapters(config)

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

        All or nothing: if any step fails, every listener is stopped
        before the error propagates, so a repo that failed to start
        receives no messages and leaves nothing running.

        Raises:
            Exception: Whatever the mirror update or a listener's
                ``start()`` raised.
        """
        try:
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
        except Exception:
            self.stop()
            raise

    def channel_statuses(self) -> dict[str, ChannelStatus]:
        """Return the current health of each listener, by channel type."""
        return {
            channel_type: adapter.listener.status
            for channel_type, adapter in self.adapters.items()
        }

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
        """Stop all listeners and close resources.

        Every listener is stopped even if one fails to (that failure is
        logged), so none is left running.  Concurrent calls run one after
        the other.
        """
        with self._stop_lock:
            stop_listeners(self.adapters, self.config.repo_id)
