# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-repository handler for the gateway service.

This module contains the RepoHandler class that manages:
- Channel adapter lifecycle (email/Slack listener, authentication, responder)
- Conversation management for a single repository
- Container executor for Claude Code
"""

from __future__ import annotations

import logging
import threading
import time
from email.message import Message
from typing import TYPE_CHECKING, Any

from airut.gateway.channel import ChannelAdapter
from airut.gateway.config import RepoServerConfig
from airut.gateway.conversation import ConversationManager
from airut.gateway.email.adapter import EmailChannelAdapter
from airut.gateway.email.listener import (
    IMAPConnectionError,
    IMAPIdleError,
)


if TYPE_CHECKING:
    from airut.gateway.service.gateway import GatewayService

logger = logging.getLogger(__name__)


class _ReconnectFailedError(Exception):
    """Sentinel raised when IMAP reconnection attempts are exhausted."""


class RepoHandler:
    """Per-repo components and listener thread.

    Encapsulates all components that are specific to a single repository:
    channel adapter, conversation management, and container execution.

    The handler runs a listener loop in its own thread and submits messages
    to the shared executor pool for processing.

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

        self.adapter: ChannelAdapter = self._create_adapter(config)
        # Keep a typed reference for email-specific listener operations.
        self._email_adapter: EmailChannelAdapter | None = (
            self.adapter if config.email is not None else None
        )
        self.conversation_manager = ConversationManager(
            repo_url=config.git_repo_url,
            storage_dir=config.storage_dir,
        )

        self._listener_thread: threading.Thread | None = None
        self._is_slack = config.slack is not None

        logger.info(
            "RepoHandler initialized for '%s' (channel=%s)",
            config.repo_id,
            config.channel_type,
        )

    @staticmethod
    def _create_adapter(config: RepoServerConfig) -> ChannelAdapter:
        """Create the appropriate channel adapter from config.

        Args:
            config: Per-repo server configuration.

        Returns:
            ChannelAdapter implementation (email or Slack).
        """
        if config.slack is not None:
            from airut.gateway.slack.adapter import SlackChannelAdapter

            return SlackChannelAdapter.from_config(
                config.slack,
                repo_id=config.repo_id,
                storage_dir=config.storage_dir,
            )

        assert config.email is not None
        return EmailChannelAdapter.from_config(
            config.email, repo_id=config.repo_id
        )

    def start_listener(self) -> threading.Thread:
        """Start the listener in a daemon thread.

        For email: connects to IMAP and starts polling/IDLE loop.
        For Slack: connects via Socket Mode (non-blocking).

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

        if self._is_slack:
            return self._start_slack_listener()
        return self._start_email_listener()

    def _start_email_listener(self) -> threading.Thread:
        """Start IMAP email listener."""
        assert self.config.email is not None
        assert self._email_adapter is not None

        logger.info(
            "Repo '%s': connecting to IMAP %s:%d",
            self.config.repo_id,
            self.config.email.imap_server,
            self.config.email.imap_port,
        )
        self._email_adapter.listener.connect(max_retries=3)

        self._listener_thread = threading.Thread(
            target=self._listener_loop,
            daemon=True,
            name=f"Listener-{self.config.repo_id}",
        )
        self._listener_thread.start()

        logger.info(
            "Repo '%s': listener started (%s mode)",
            self.config.repo_id,
            "IDLE" if self.config.email.use_imap_idle else "polling",
        )
        return self._listener_thread

    def _start_slack_listener(self) -> threading.Thread:
        """Start Slack Socket Mode listener."""
        from airut.gateway.slack.adapter import SlackChannelAdapter
        from airut.gateway.slack.listener import SlackListener

        assert isinstance(self.adapter, SlackChannelAdapter)
        assert self.config.slack is not None

        def submit_callback(payload: dict) -> None:
            """Submit Slack event payload for processing."""
            self._submit_message(payload)

        self._slack_listener = SlackListener(
            self.config.slack,
            submit_callback=submit_callback,
        )
        self._slack_listener.connect()

        # Slack listener runs in the SDK's background thread.
        # Create a keep-alive thread for consistency with the email path.
        self._listener_thread = threading.Thread(
            target=self._slack_keep_alive,
            daemon=True,
            name=f"Listener-{self.config.repo_id}",
        )
        self._listener_thread.start()

        logger.info(
            "Repo '%s': Slack listener started (Socket Mode)",
            self.config.repo_id,
        )
        return self._listener_thread

    def _slack_keep_alive(self) -> None:
        """Keep-alive loop for Slack listener thread."""
        while self.service.running:
            time.sleep(1)

    def _listener_loop(self) -> None:
        """Main listener loop, dispatching to IDLE or polling mode.

        Only called for email-channel repos.
        """
        assert self.config.email is not None
        if self.config.email.use_imap_idle:
            self._idle_loop()
        else:
            self._polling_loop()

    def _reconnect_with_backoff(
        self,
        reconnect_attempts: int,
        max_reconnect_attempts: int,
        *,
        error: IMAPConnectionError | None = None,
    ) -> int:
        """Handle IMAP reconnection with exponential backoff.

        Args:
            reconnect_attempts: Current attempt count (will be incremented).
            max_reconnect_attempts: Max attempts before giving up.
            error: The connection error that triggered the reconnect.

        Returns:
            Updated reconnect_attempts count.

        Raises:
            _ReconnectFailedError: If max attempts reached.
        """
        reconnect_attempts += 1
        repo_id = self.config.repo_id
        logger.error(
            "Repo '%s': IMAP connection error (attempt %d/%d): %s",
            repo_id,
            reconnect_attempts,
            max_reconnect_attempts,
            error or "unknown",
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

        assert self._email_adapter is not None
        try:
            self._email_adapter.listener.disconnect()
            self._email_adapter.listener.connect(max_retries=3)
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
        assert self._email_adapter is not None
        assert self.config.email is not None
        reconnect_attempts = 0
        max_reconnect_attempts = 5
        repo_id = self.config.repo_id
        listener = self._email_adapter.listener

        while self.service.running:
            try:
                messages = listener.fetch_unread()

                if messages:
                    logger.info(
                        "Repo '%s': processing %d new messages",
                        repo_id,
                        len(messages),
                    )

                reconnect_attempts = 0

                for msg_id, message in messages:
                    try:
                        listener.delete_message(msg_id)
                        self._submit_message(message)
                    except Exception as e:
                        logger.exception(
                            "Repo '%s': failed to submit message: %s",
                            repo_id,
                            e,
                        )

                time.sleep(self.config.email.poll_interval_seconds)

            except IMAPConnectionError as e:
                try:
                    reconnect_attempts = self._reconnect_with_backoff(
                        reconnect_attempts, max_reconnect_attempts, error=e
                    )
                except _ReconnectFailedError:
                    return

    def _idle_loop(self) -> None:
        """IDLE-based message loop."""
        assert self._email_adapter is not None
        assert self.config.email is not None
        reconnect_attempts = 0
        max_reconnect_attempts = 5
        last_reconnect = time.time()
        reconnect_interval = self.config.email.idle_reconnect_interval_seconds
        repo_id = self.config.repo_id
        listener = self._email_adapter.listener

        while self.service.running:
            try:
                if time.time() - last_reconnect >= reconnect_interval:
                    logger.info(
                        "Repo '%s': periodic reconnect after %d seconds",
                        repo_id,
                        reconnect_interval,
                    )
                    listener.disconnect()
                    listener.connect(max_retries=3)
                    last_reconnect = time.time()

                messages = listener.fetch_unread()

                if messages:
                    logger.info(
                        "Repo '%s': processing %d new messages",
                        repo_id,
                        len(messages),
                    )

                reconnect_attempts = 0

                for msg_id, message in messages:
                    try:
                        listener.delete_message(msg_id)
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
                    has_pending = listener.idle_start()
                    if has_pending:
                        continue

                    time_until_reconnect = max(
                        0,
                        reconnect_interval - (time.time() - last_reconnect),
                    )
                    idle_timeout = min(time_until_reconnect, 29 * 60)

                    if idle_timeout > 0:
                        got_notification = listener.idle_wait(idle_timeout)

                        if got_notification:
                            logger.debug(
                                "Repo '%s': IDLE notification received",
                                repo_id,
                            )

                    if not self.service.running:
                        break

                    listener.idle_done()

                except IMAPIdleError as e:
                    logger.warning(
                        "Repo '%s': IDLE error, reconnecting: %s",
                        repo_id,
                        e,
                    )
                    last_reconnect = 0

            except IMAPConnectionError as e:
                try:
                    reconnect_attempts = self._reconnect_with_backoff(
                        reconnect_attempts, max_reconnect_attempts, error=e
                    )
                    last_reconnect = time.time()
                except _ReconnectFailedError:
                    return

    def _submit_message(self, message: Message | dict[str, Any]) -> bool:
        """Submit a raw message for authentication and processing.

        Authentication happens in the worker thread, not here.

        Args:
            message: Raw email message or Slack event payload dict.

        Returns:
            True if message was submitted, False if pool not ready.
        """
        return self.service.submit_message(message, self)

    def stop(self) -> None:
        """Stop listener and close resources."""
        if self._is_slack:
            if hasattr(self, "_slack_listener"):
                self._slack_listener.close()
        elif self._email_adapter is not None:
            self._email_adapter.listener.interrupt()
            self._email_adapter.listener.close()
        logger.info("Repo '%s': listener stopped", self.config.repo_id)
