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
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, cast

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_bolt.context.assistant.thread_context import (
    AssistantThreadContext,
)
from slack_bolt.context.say import Say
from slack_bolt.context.set_status import SetStatus
from slack_bolt.context.set_suggested_prompts import SetSuggestedPrompts
from slack_bolt.middleware.assistant import Assistant

from airut._json_types import JsonDict
from airut.gateway.channel import (
    ChannelHealth,
    ChannelListener,
    ChannelStatus,
    RawMessage,
)
from airut.gateway.slack.authorizer import SlackAuthorizer
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.thread_store import SlackThreadStore


logger = logging.getLogger(__name__)

#: Maximum number of recently-seen ``(channel, ts)`` keys retained for
#: deduplicating the ``app_mention`` / ``message`` double-delivery of a
#: single channel mention.
_DEDUP_CAPACITY = 256

#: Message subtypes that still carry genuine user content and must not be
#: filtered out with the system/edit subtypes.  Slack tags a file upload as
#: ``file_share`` (even when it includes a text comment); dropping it would
#: lose attachments posted into an engaged thread.  Shared with the adapter's
#: thread-history replay so the two stay in sync on what counts as content.
CONTENT_SUBTYPES: frozenset[str] = frozenset({"file_share"})


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
        thread_store: Thread-to-conversation mapping, consulted on the
            event-handler thread to decide whether a channel follow-up
            belongs to an engaged thread (the "sticky thread" rule).
        authorizer: Authorizer, used here only to resolve the bot's own
            user ID for the ``@``-mention engagement check.
        app: Optional pre-built Bolt ``App`` (for testing).
        handler: Optional pre-built ``SocketModeHandler`` (for testing).
    """

    def __init__(
        self,
        config: SlackChannelConfig,
        thread_store: SlackThreadStore,
        authorizer: SlackAuthorizer,
        *,
        app: App | None = None,
        handler: SocketModeHandler | None = None,
    ) -> None:
        self._config = config
        self._thread_store = thread_store
        self._authorizer = authorizer
        self._app = app or App(token=config.bot_token)
        self._handler = handler or SocketModeHandler(
            self._app, config.app_token
        )
        self._status = ChannelStatus(health=ChannelHealth.STARTING)
        self._submit: Callable[[RawMessage[JsonDict]], bool] | None = None
        self._started = False
        # Ordered set of recently-seen (channel, ts) keys for dedup.
        self._seen_events: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._dedup_lock = threading.Lock()

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
        # Warm the bot user ID so channel @-mention detection works from
        # the first event.  Resolution is cached on the authorizer.
        if self._authorizer.get_bot_user_id() is None:
            logger.warning(
                "Could not resolve bot user ID; channel @-mention "
                "engagement is disabled until auth.test succeeds"
            )
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
            set_status: SetStatus,
            say: Say,
            set_suggested_prompts: SetSuggestedPrompts,
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
            payload: JsonDict,
        ) -> None:
            """Handle user message in a thread.

            Wraps the event payload in a ``RawMessage`` and calls the
            submit callback.  Authentication happens in the worker
            thread, not here.

            The loading status is intentionally not set here: the
            adapter surfaces it from the lifecycle phases the gateway
            reports (see ``ChannelAdapter.report_phase``), scoped to the
            prep window.  Setting it per-message would lock the Slack
            composer for the whole run and for coalesced bursts,
            preventing follow-ups.
            """
            user_id = cast(str, payload.get("user", ""))
            text = cast(str, payload.get("text", ""))
            channel = cast(str, payload.get("channel", ""))
            thread_ts = cast(str, payload.get("thread_ts", ""))

            # Build display title from first line of message
            display_title = text[:60].split("\n")[0] if text else ""

            raw: RawMessage[JsonDict] = RawMessage(
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

        # Register the Assistant middleware with the Bolt app (DM surface).
        self._app.assistant(assistant)

        # Channel surface: app_mention is the canonical engagement signal;
        # message.channels / message.groups carry follow-ups (and a
        # duplicate copy of each mention, deduplicated below).
        self._app.event("app_mention")(self._on_app_mention)
        self._app.event("message")(self._on_channel_message)

    def _on_app_mention(self, event: JsonDict) -> None:
        """Handle an ``app_mention`` event (channel engagement trigger).

        Subtyped messages and bot-authored mentions are ignored: a bot
        that ``@``-mentions Airut must never trigger a run, otherwise two
        Airut instances sharing a channel could mention each other into an
        unbounded back-and-forth.  A genuine mention is always an
        engagement signal, so the remaining gates are the channel
        allowlist and dedup (the same mention also arrives as a
        ``message.channels`` / ``message.groups`` event).
        """
        if event.get("subtype") or event.get("bot_id"):
            return
        channel = cast(str, event.get("channel", ""))
        ts = cast(str, event.get("ts", ""))
        if not self._channel_allowed(channel):
            return
        if not self._claim_event(channel, ts):
            return
        self._submit_channel_event(event)

    def _on_channel_message(self, event: JsonDict) -> None:
        """Handle a ``message`` event in a public or private channel.

        DMs (``channel_type == "im"``) are handled by the Assistant
        middleware and skipped here.  System/edit subtypes (edits, joins,
        bot posts) and bot-authored messages are ignored, but content
        subtypes such as ``file_share`` are kept so attachments are not
        dropped.  A message is submitted only when it lands in an
        already-engaged thread (the sticky-thread rule) or it
        ``@``-mentions the bot.
        """
        channel_type = cast(str, event.get("channel_type", ""))
        if channel_type not in ("channel", "group"):
            return
        subtype = cast(str, event.get("subtype", ""))
        if subtype and subtype not in CONTENT_SUBTYPES:
            return
        if event.get("bot_id"):
            return

        channel = cast(str, event.get("channel", ""))
        ts = cast(str, event.get("ts", ""))
        text = cast(str, event.get("text", ""))
        # Top-level messages have no thread_ts; their own ts roots a thread.
        thread_ts = cast(str, event.get("thread_ts", "")) or ts

        if not self._channel_allowed(channel):
            return

        engaged = (
            self._thread_store.get_conversation_id(channel, thread_ts)
            is not None
        )
        if not engaged and not self._has_bot_mention(text):
            return

        if not self._claim_event(channel, ts):
            return
        self._submit_channel_event(event)

    def _submit_channel_event(self, event: JsonDict) -> None:
        """Wrap a channel event in a ``RawMessage`` and submit it."""
        assert self._submit is not None
        user_id = cast(str, event.get("user", ""))
        text = cast(str, event.get("text", ""))
        channel = cast(str, event.get("channel", ""))
        display_title = text[:60].split("\n")[0] if text else ""

        raw: RawMessage[JsonDict] = RawMessage(
            sender=user_id,
            content=event,
            display_title=display_title,
        )
        logger.info(
            "Slack channel message from %s in %s (ts %s)",
            user_id,
            channel,
            event.get("ts", ""),
        )
        try:
            self._submit(raw)
        except Exception:
            logger.exception(
                "Failed to submit Slack channel message from %s", user_id
            )

    def _channel_allowed(self, channel: str) -> bool:
        """Return whether *channel* passes the optional channel allowlist."""
        allowed = self._config.allowed_channels
        return not allowed or channel in allowed

    def _has_bot_mention(self, text: str) -> bool:
        """Return whether *text* contains the bot's ``<@BOT_USER_ID>`` token.

        Matches both the bare ``<@U…>`` form and the ``<@U…|label>`` form
        Slack uses when a display name is available.
        """
        bot_id = self._authorizer.get_bot_user_id()
        if not bot_id:
            return False
        return f"<@{bot_id}>" in text or f"<@{bot_id}|" in text

    def _claim_event(self, channel: str, ts: str) -> bool:
        """Claim a ``(channel, ts)`` event for processing, deduplicating.

        Returns True the first time a key is seen and False thereafter,
        so the duplicate ``app_mention`` / ``message`` delivery of one
        mention is processed exactly once.  Retains the most recent
        :data:`_DEDUP_CAPACITY` keys.
        """
        key = (channel, ts)
        with self._dedup_lock:
            if key in self._seen_events:
                return False
            self._seen_events[key] = None
            if len(self._seen_events) > _DEDUP_CAPACITY:
                self._seen_events.popitem(last=False)
            return True
