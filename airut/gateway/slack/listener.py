# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack Socket Mode listener.

Wraps Bolt App + SocketModeHandler for receiving Slack events
via Agents & AI Apps mode.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from airut.gateway.slack.config import SlackChannelConfig


logger = logging.getLogger(__name__)


class SlackListener:
    """Manages the Bolt App and Socket Mode connection.

    Uses Slack's Agents & AI Apps ``Assistant`` framework for
    thread-based DM interactions.

    Attributes:
        app: The Bolt App instance.
    """

    def __init__(
        self,
        config: SlackChannelConfig,
        submit_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """Initialize the Slack listener.

        Args:
            config: Slack channel configuration.
            submit_callback: Callback to invoke with raw event payload
                when a user message is received. If None, messages are
                logged but not processed (useful for testing).
        """
        from slack_bolt import App
        from slack_bolt.adapter.socket_mode import SocketModeHandler
        from slack_bolt.context.assistant import AssistantThreadContext
        from slack_bolt.middleware.assistant import Assistant

        self._config = config
        self._submit_callback = submit_callback

        self.app = App(token=config.bot_token)
        self._handler = SocketModeHandler(self.app, config.app_token)

        # Register Agents & AI Apps event handlers
        assistant = Assistant()

        @assistant.thread_started
        def handle_thread_started(
            say: Callable[..., Any],
            set_suggested_prompts: Callable[..., Any],
            **kwargs: Any,
        ) -> None:
            say("Hello! Send me a message to get started.")

        @assistant.thread_context_changed
        def handle_context_changed(
            context: AssistantThreadContext,
            **kwargs: Any,
        ) -> None:
            logger.debug("Thread context changed: %s", context)

        @assistant.user_message
        def handle_user_message(
            payload: dict[str, Any],
            say: Callable[..., Any],
            set_status: Callable[..., Any],
            **kwargs: Any,
        ) -> None:
            if self._submit_callback is not None:
                self._submit_callback(payload)
            else:
                logger.debug(
                    "Received Slack message (no callback): %s",
                    payload.get("text", "")[:100],
                )

        self.app.use(assistant)

    def connect(self) -> None:
        """Start Socket Mode (non-blocking).

        Establishes a WebSocket connection in a background thread.
        """
        logger.info("Connecting to Slack via Socket Mode...")
        self._handler.connect()
        logger.info("Slack Socket Mode connected")

    def close(self) -> None:
        """Disconnect Socket Mode."""
        logger.info("Disconnecting Slack Socket Mode...")
        self._handler.close()
        logger.info("Slack Socket Mode disconnected")

    def interrupt(self) -> None:
        """Signal shutdown (for compatibility with RepoHandler.stop)."""
        self.close()
