# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-repository handler for the gateway service.

This module contains the RepoHandler class that manages:
- Email listener lifecycle (IMAP connection, polling/IDLE)
- Email responder for sending replies
- Authentication and authorization
- Conversation management for a single repository
- Container executor for Claude Code
"""

from __future__ import annotations

import logging
import threading
import time
from email.message import Message
from typing import TYPE_CHECKING

from lib.container.executor import ClaudeExecutor
from lib.gateway.config import RepoServerConfig
from lib.gateway.conversation import ConversationManager
from lib.gateway.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)
from lib.gateway.responder import EmailResponder
from lib.gateway.security import SenderAuthenticator, SenderAuthorizer


if TYPE_CHECKING:
    from lib.gateway.service.gateway import EmailGatewayService

logger = logging.getLogger(__name__)


class _ReconnectFailedError(Exception):
    """Sentinel raised when IMAP reconnection attempts are exhausted."""


class RepoHandler:
    """Per-repo components and listener thread.

    Encapsulates all components that are specific to a single repository:
    email listener, responder, authentication, authorization, conversation
    management, and container execution.

    The handler runs a listener loop in its own thread and submits messages
    to the shared executor pool for processing.

    Attributes:
        config: Per-repo server-side configuration.
        service: Back-reference to the parent service for shared resources.
    """

    def __init__(
        self,
        config: RepoServerConfig,
        service: EmailGatewayService,
    ) -> None:
        """Initialize per-repo components.

        Args:
            config: Per-repo server-side configuration.
            service: Parent service for shared resources.
        """
        self.config = config
        self.service = service

        self.listener = EmailListener(config)
        self.responder = EmailResponder(config)
        self.authenticator = SenderAuthenticator(config.trusted_authserv_id)
        self.authorizer = SenderAuthorizer(config.authorized_senders)
        self.conversation_manager = ConversationManager(
            repo_url=config.git_repo_url,
            storage_dir=config.storage_dir,
        )
        self.executor = ClaudeExecutor(
            mirror=self.conversation_manager.mirror,
            entrypoint_path=service.repo_root
            / "docker"
            / "airut-entrypoint.sh",
            container_command=service.global_config.container_command,
        )

        self._listener_thread: threading.Thread | None = None

        logger.info("RepoHandler initialized for '%s'", config.repo_id)

    def start_listener(self) -> threading.Thread:
        """Start the listener in a daemon thread.

        Returns:
            The listener thread.
        """
        # Update git mirror on startup (before proxy, which reads config
        # from the mirror)
        logger.info(
            "Repo '%s': updating git mirror from origin...",
            self.config.repo_id,
        )
        self.conversation_manager.mirror.update_mirror()

        # Connect to IMAP
        logger.info(
            "Repo '%s': connecting to IMAP %s:%d",
            self.config.repo_id,
            self.config.imap_server,
            self.config.imap_port,
        )
        self.listener.connect(max_retries=3)

        self._listener_thread = threading.Thread(
            target=self._listener_loop,
            daemon=True,
            name=f"Listener-{self.config.repo_id}",
        )
        self._listener_thread.start()

        logger.info(
            "Repo '%s': listener started (%s mode)",
            self.config.repo_id,
            "IDLE" if self.config.use_imap_idle else "polling",
        )
        return self._listener_thread

    def _listener_loop(self) -> None:
        """Main listener loop, dispatching to IDLE or polling mode."""
        if self.config.use_imap_idle:
            self._idle_loop()
        else:
            self._polling_loop()

    def _reconnect_with_backoff(
        self, reconnect_attempts: int, max_reconnect_attempts: int
    ) -> int:
        """Handle IMAP reconnection with exponential backoff.

        Args:
            reconnect_attempts: Current attempt count (will be incremented).
            max_reconnect_attempts: Max attempts before giving up.

        Returns:
            Updated reconnect_attempts count.

        Raises:
            _ReconnectFailedError: If max attempts reached.
        """
        reconnect_attempts += 1
        repo_id = self.config.repo_id
        logger.error(
            "Repo '%s': IMAP connection error (attempt %d/%d)",
            repo_id,
            reconnect_attempts,
            max_reconnect_attempts,
        )

        if reconnect_attempts >= max_reconnect_attempts:
            logger.critical(
                "Repo '%s': failed to reconnect after %d attempts",
                repo_id,
                max_reconnect_attempts,
            )
            raise _ReconnectFailedError

        backoff = min(10 * (3 ** (reconnect_attempts - 1)), 300)
        logger.info("Repo '%s': reconnecting in %ds...", repo_id, backoff)
        time.sleep(backoff)

        try:
            self.listener.disconnect()
            self.listener.connect(max_retries=3)
            logger.info("Repo '%s': reconnected to IMAP", repo_id)
        except IMAPConnectionError as reconnect_error:
            logger.error(
                "Repo '%s': reconnection failed: %s",
                repo_id,
                reconnect_error,
            )

        return reconnect_attempts

    def _polling_loop(self) -> None:
        """Polling-based message loop."""
        reconnect_attempts = 0
        max_reconnect_attempts = 5
        repo_id = self.config.repo_id

        while self.service.running:
            try:
                messages = self.listener.fetch_unread()

                if messages:
                    logger.info(
                        "Repo '%s': processing %d new messages",
                        repo_id,
                        len(messages),
                    )

                reconnect_attempts = 0

                for msg_id, message in messages:
                    try:
                        self.listener.delete_message(msg_id)
                        self._submit_message(message)
                    except Exception as e:
                        logger.exception(
                            "Repo '%s': failed to submit message: %s",
                            repo_id,
                            e,
                        )

                time.sleep(self.config.poll_interval_seconds)

            except IMAPConnectionError:
                try:
                    reconnect_attempts = self._reconnect_with_backoff(
                        reconnect_attempts, max_reconnect_attempts
                    )
                except _ReconnectFailedError:
                    return

    def _idle_loop(self) -> None:
        """IDLE-based message loop."""
        reconnect_attempts = 0
        max_reconnect_attempts = 5
        last_reconnect = time.time()
        reconnect_interval = self.config.idle_reconnect_interval_seconds
        repo_id = self.config.repo_id

        while self.service.running:
            try:
                if time.time() - last_reconnect >= reconnect_interval:
                    logger.info(
                        "Repo '%s': periodic reconnect after %d seconds",
                        repo_id,
                        reconnect_interval,
                    )
                    self.listener.disconnect()
                    self.listener.connect(max_retries=3)
                    last_reconnect = time.time()

                messages = self.listener.fetch_unread()

                if messages:
                    logger.info(
                        "Repo '%s': processing %d new messages",
                        repo_id,
                        len(messages),
                    )

                reconnect_attempts = 0

                for msg_id, message in messages:
                    try:
                        self.listener.delete_message(msg_id)
                        self._submit_message(message)
                    except Exception as e:
                        logger.exception(
                            "Repo '%s': failed to submit message: %s",
                            repo_id,
                            e,
                        )

                if messages:
                    continue

                try:
                    has_pending = self.listener.idle_start()
                    if has_pending:
                        continue

                    time_until_reconnect = max(
                        0, reconnect_interval - (time.time() - last_reconnect)
                    )
                    idle_timeout = min(time_until_reconnect, 29 * 60)

                    if idle_timeout > 0:
                        got_notification = self.listener.idle_wait(idle_timeout)

                        if got_notification:
                            logger.debug(
                                "Repo '%s': IDLE notification received",
                                repo_id,
                            )

                    if not self.service.running:
                        break

                    self.listener.idle_done()

                except IMAPIdleError as e:
                    logger.warning(
                        "Repo '%s': IDLE error, reconnecting: %s",
                        repo_id,
                        e,
                    )
                    last_reconnect = 0

            except IMAPConnectionError:
                try:
                    reconnect_attempts = self._reconnect_with_backoff(
                        reconnect_attempts, max_reconnect_attempts
                    )
                    last_reconnect = time.time()
                except _ReconnectFailedError:
                    return

    def _submit_message(self, message: Message) -> bool:
        """Submit message to the shared executor pool.

        Args:
            message: Email message to process.

        Returns:
            True if message was submitted, False if rejected.
        """
        return self.service.submit_message(message, self)

    def stop(self) -> None:
        """Stop listener and close resources."""
        self.listener.interrupt()
        self.listener.close()
        logger.info("Repo '%s': listener stopped", self.config.repo_id)
