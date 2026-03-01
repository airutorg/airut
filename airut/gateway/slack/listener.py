# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack channel listener implementing the ChannelListener protocol.

Wraps the Bolt SDK's ``App`` and ``SocketModeHandler`` with Agents &
AI Apps event handling, health tracking, and the ``ChannelListener``
interface.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_bolt.context.assistant.thread_context import (
    AssistantThreadContext,
)
from slack_bolt.middleware.assistant import Assistant

from airut.gateway.channel import (
    ChannelHealth,
    ChannelListener,
    ChannelStatus,
    RawMessage,
)
from airut.gateway.slack.config import SlackChannelConfig


logger = logging.getLogger(__name__)


class SlackChannelListener(ChannelListener):
    """Socket Mode listener implementing the ChannelListener protocol.

    Wraps the Bolt SDK's ``App`` and ``SocketModeHandler`` to receive
    Slack events via WebSocket.  Uses the ``Assistant`` middleware for
    Agents & AI Apps event handling.

    The event handlers wrap incoming messages in ``RawMessage[dict]``
    and call the ``submit`` callback, which feeds into the same worker
    thread pool used by the email channel.

    Args:
        config: Slack channel configuration.
        app: Optional pre-built Bolt ``App`` (for testing).
        handler: Optional pre-built ``SocketModeHandler`` (for testing).
    """

    def __init__(
        self,
        config: SlackChannelConfig,
        app: App | None = None,
        handler: SocketModeHandler | None = None,
    ) -> None:
        self._config = config
        self._app = app or App(token=config.bot_token)
        self._handler = handler or SocketModeHandler(
            self._app, config.app_token
        )
        self._status = ChannelStatus(health=ChannelHealth.STARTING)
        self._submit: Callable[[RawMessage[dict[str, Any]]], bool] | None = None
        self._started = False

    def start(self, submit: Callable[[RawMessage[Any]], bool]) -> None:
        """Connect Socket Mode and start receiving events.

        Registers event handlers, then calls ``handler.connect()``
        which is non-blocking — it starts the WebSocket in a background
        thread and returns immediately.

        Args:
            submit: Callback invoked with each ``RawMessage``.
        """
        if self._started:
            logger.warning("Slack listener already started, ignoring")
            return
        self._submit = submit
        self._register_handlers()
        self._install_connection_listeners()
        self._handler.connect()
        self._started = True
        self._status = ChannelStatus(health=ChannelHealth.CONNECTED)
        logger.info("Slack listener connected (Socket Mode)")

    def stop(self) -> None:
        """Disconnect Socket Mode and release resources."""
        self._handler.close()
        self._status = ChannelStatus(
            health=ChannelHealth.FAILED, message="stopped"
        )
        logger.info("Slack listener stopped")

    @property
    def status(self) -> ChannelStatus:
        """Current health of this listener."""
        return self._status

    def _install_connection_listeners(self) -> None:
        """Install close/error listeners on the Socket Mode client."""
        client = getattr(self._handler, "client", None)
        if client is None:
            logger.warning(
                "Socket Mode handler has no 'client' attribute; "
                "connection health listeners not installed"
            )
            return

        installed = 0

        close_listeners = getattr(client, "on_close_listeners", None)
        if close_listeners is not None:
            close_listeners.append(self._on_ws_close)
            installed += 1
        else:
            logger.warning(
                "Socket Mode client has no 'on_close_listeners'; "
                "close events will not be tracked"
            )

        error_listeners = getattr(client, "on_error_listeners", None)
        if error_listeners is not None:
            error_listeners.append(self._on_ws_error)
            installed += 1
        else:
            logger.warning(
                "Socket Mode client has no 'on_error_listeners'; "
                "error events will not be tracked"
            )

        message_listeners = getattr(client, "on_message_listeners", None)
        if message_listeners is not None:
            message_listeners.append(self._on_ws_message)
            installed += 1
        else:
            logger.warning(
                "Socket Mode client has no 'on_message_listeners'; "
                "reconnect recovery will not be tracked"
            )

        logger.debug("Installed %d connection health listener(s)", installed)

    def _on_ws_close(self, code: int, reason: str | None) -> None:
        """Handle WebSocket close — mark as degraded (auto-reconnect)."""
        self._status = ChannelStatus(
            health=ChannelHealth.DEGRADED,
            message=f"WebSocket closed (code={code})",
        )
        logger.warning(
            "Slack WebSocket closed: code=%d reason=%s", code, reason
        )

    def _on_ws_error(self, error: Exception) -> None:
        """Handle WebSocket error — mark as degraded."""
        self._status = ChannelStatus(
            health=ChannelHealth.DEGRADED,
            message=f"WebSocket error: {error}",
        )
        logger.warning("Slack WebSocket error: %s", error)

    def _on_ws_message(self, message: str) -> None:
        """Handle WebSocket message — recover from degraded state.

        After a close/error, the Bolt SDK auto-reconnects.  The first
        message received on the new connection proves connectivity is
        restored, so we flip back to CONNECTED.
        """
        if self._status.health != ChannelHealth.DEGRADED:
            return
        self._status = ChannelStatus(health=ChannelHealth.CONNECTED)
        logger.info("Slack WebSocket recovered (message received)")

    def _register_handlers(self) -> None:
        """Register Agents & AI Apps event handlers on the Bolt app."""
        assistant = Assistant()
        submit = self._submit
        assert submit is not None

        @assistant.thread_started
        def handle_thread_started(
            set_status: Any,
            say: Any,
            set_suggested_prompts: Any,
        ) -> None:
            """Handle new thread creation in Agents & AI Apps mode."""
            set_status("is getting ready...")
            say("Hello! How can I help you today?")
            logger.debug("Slack: thread_started event handled")

        @assistant.thread_context_changed
        def handle_context_changed(
            context: AssistantThreadContext,
        ) -> None:
            """Handle context change (user switched channels)."""
            logger.debug("Slack: thread_context_changed event: %s", context)

        @assistant.user_message
        def handle_user_message(
            payload: dict[str, Any],
            set_status: Any,
        ) -> None:
            """Handle user message in a thread.

            Wraps the event payload in a ``RawMessage`` and calls the
            submit callback.  Authentication happens in the worker
            thread, not here.
            """
            user_id = payload.get("user", "")
            text = payload.get("text", "")
            channel = payload.get("channel", "")
            thread_ts = payload.get("thread_ts", "")

            # Build display title from first line of message
            display_title = text[:60].split("\n")[0] if text else ""

            set_status("is working on this...")

            raw: RawMessage[dict[str, Any]] = RawMessage(
                sender=user_id,
                content=payload,
                display_title=display_title,
            )

            logger.info(
                "Slack message from %s in %s (thread %s)",
                user_id,
                channel,
                thread_ts,
            )

            try:
                submit(raw)
            except Exception:
                logger.exception(
                    "Failed to submit Slack message from %s", user_id
                )

        # Register the Assistant middleware with the Bolt app
        self._app.assistant(assistant)
