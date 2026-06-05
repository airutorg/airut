# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email channel listener implementing the ChannelListener protocol.

Wraps the low-level EmailListener (IMAP operations) with polling/IDLE
loops, reconnection logic, and health tracking.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections.abc import Callable
from email.message import Message

from airut.gateway.channel import (
    ChannelHealth,
    ChannelListener,
    ChannelStatus,
    RawMessage,
)
from airut.gateway.config import EmailChannelConfig
from airut.gateway.dedup import SeenKeyCache
from airut.gateway.email.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)


logger = logging.getLogger(__name__)


def _content_fingerprint(message: Message) -> str:
    """Return a stable hash of an email's originator fields and body.

    Combined with the ``Message-ID`` as the dedup key so that a message
    re-delivered to the mailbox is suppressed, while two genuinely
    distinct messages that happen to share a ``Message-ID`` (e.g. a
    sender that reuses one) still hash differently and are processed.

    Only fields set at origination are hashed — the ``From``/``Subject``/
    ``Date`` headers and, for every leaf part, its content type, filename,
    and decoded payload (so body and attachments, including an
    attachment's name, all contribute).  Per-delivery trace headers
    (``Received``, ``Return-Path``, ...) are excluded, so two copies of
    one re-delivered message produce the same fingerprint.
    """
    digest = hashlib.sha256()

    def _feed(value: str | bytes) -> None:
        if isinstance(value, str):
            value = value.encode("utf-8", "replace")
        digest.update(value)
        digest.update(b"\x00")

    for header in ("From", "Subject", "Date"):
        _feed(str(message.get(header, "")))
    for part in message.walk():
        if part.is_multipart():
            continue
        _feed(part.get_content_type())
        _feed(part.get_filename() or "")
        payload = part.get_payload(decode=True)
        _feed(payload if isinstance(payload, bytes) else b"")
    return digest.hexdigest()


class _ReconnectFailedError(Exception):
    """Sentinel raised when IMAP reconnection attempts are exhausted."""


class EmailChannelListener(ChannelListener):
    """ChannelListener implementation for email (IMAP).

    Manages the IMAP polling/IDLE loop in an internal thread, with
    automatic reconnection and health status tracking.
    """

    def __init__(
        self,
        config: EmailChannelConfig,
        email_listener: EmailListener | None = None,
        *,
        repo_id: str,
    ) -> None:
        """Initialize email channel listener.

        Args:
            config: Email channel configuration.
            email_listener: Low-level IMAP listener. If None, one is
                created from the config.
            repo_id: Repository identifier for log context. Must not
                be empty.

        Raises:
            ValueError: If repo_id is empty.
        """
        if not repo_id:
            raise ValueError("repo_id must not be empty")
        self._config = config
        self._repo_id = repo_id
        self._log = logging.LoggerAdapter(logger, {"repo_id": repo_id})
        self._email_listener = email_listener or EmailListener(config)
        self._thread: threading.Thread | None = None
        self._submit: Callable[[RawMessage[Message]], bool] | None = None
        self._running = False
        self._stop_event = threading.Event()
        self._status = ChannelStatus(health=ChannelHealth.STARTING)
        # Recently-seen (Message-ID, content-hash) keys, for deduplicating
        # an email the mail server delivers to the mailbox more than once.
        self._seen_messages: SeenKeyCache = SeenKeyCache()

    def start(self, submit: Callable[[RawMessage[Message]], bool]) -> None:
        """Connect to IMAP and start the listener thread.

        The initial IMAP connection is synchronous (may block with
        retries). After connecting, the polling/IDLE loop runs in a
        background thread.

        Args:
            submit: Callback invoked with each RawMessage.

        Raises:
            IMAPConnectionError: If the initial connection fails.
        """
        self._submit = submit
        self._running = True
        self._stop_event.clear()

        self._log.info(
            "Connecting to IMAP %s:%d",
            self._config.imap.server,
            self._config.imap.port,
        )
        self._email_listener.connect(
            max_retries=self._config.imap.connect_retries,
            stop_event=self._stop_event,
        )
        self._status = ChannelStatus(health=ChannelHealth.CONNECTED)

        thread_name = (
            f"EmailListener-{self._repo_id}-{self._config.imap.server}"
        )
        self._thread = threading.Thread(
            target=self._listener_loop,
            daemon=True,
            name=thread_name,
        )
        self._thread.start()

        mode = "IDLE" if self._config.imap.use_idle else "polling"
        self._log.info(
            "Email listener started (%s mode)",
            mode,
        )

    def stop(self) -> None:
        """Stop the listener and close the IMAP connection."""
        self._running = False
        self._stop_event.set()
        self._email_listener.interrupt()
        if self._thread is not None:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                self._log.warning(
                    "Listener thread did not terminate within 10s"
                )
            self._thread = None
        self._email_listener.close()
        self._log.info("Email listener stopped")

    @property
    def status(self) -> ChannelStatus:
        """Current health of this listener."""
        return self._status

    def _listener_loop(self) -> None:
        """Main listener loop, dispatching to IDLE or polling mode."""
        if self._config.imap.use_idle:
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
        error_msg = str(error) if error else "unknown"
        self._log.error(
            "IMAP connection error (attempt %d/%d): %s",
            reconnect_attempts,
            max_reconnect_attempts,
            error_msg,
        )

        self._status = ChannelStatus(
            health=ChannelHealth.DEGRADED,
            message=(
                f"IMAP reconnecting (attempt {reconnect_attempts}"
                f"/{max_reconnect_attempts})"
            ),
            error_type=type(error).__name__ if error else None,
        )

        if reconnect_attempts >= max_reconnect_attempts:
            self._log.critical(
                "Failed to reconnect after %d attempts",
                max_reconnect_attempts,
            )
            self._status = ChannelStatus(
                health=ChannelHealth.FAILED,
                message=(
                    f"IMAP reconnection failed after "
                    f"{max_reconnect_attempts} attempts"
                ),
                error_type=type(error).__name__ if error else None,
            )
            raise _ReconnectFailedError

        backoff = min(10 * (3 ** (reconnect_attempts - 1)), 300)
        self._log.info("Reconnecting in %ds...", backoff)
        self._stop_event.wait(backoff)

        if not self._running:
            return reconnect_attempts

        try:
            self._email_listener.disconnect()
            self._email_listener.connect(
                max_retries=self._config.imap.connect_retries,
                stop_event=self._stop_event,
            )
            self._log.info("Reconnected to IMAP")
            self._status = ChannelStatus(health=ChannelHealth.CONNECTED)
        except IMAPConnectionError as reconnect_error:
            self._log.error(
                "Reconnection attempt %d/%d failed: %s",
                reconnect_attempts,
                max_reconnect_attempts,
                reconnect_error,
            )

        return reconnect_attempts

    def _claim_message(self, message: Message) -> bool:
        """Claim a message for processing, deduplicating re-deliveries.

        The dedup key is the ``Message-ID`` paired with a content
        fingerprint (see :func:`_content_fingerprint`).  The first time a
        key is seen this returns True; an identical re-delivery returns
        False so it never becomes a second task.  Requiring the content to
        match too means a distinct message that merely reuses a
        ``Message-ID`` is still processed rather than silently dropped.

        Messages without a ``Message-ID`` header carry no stable identity
        and are always processed.

        Args:
            message: The parsed email message.

        Returns:
            Whether the message should be submitted for processing.
        """
        message_id = str(message.get("Message-ID", "")).strip()
        if not message_id:
            return True
        key = (message_id, _content_fingerprint(message))
        if self._seen_messages.claim(key):
            return True
        self._log.info("Skipping duplicate message %s", message_id)
        return False

    def _deliver_messages(self, messages: list[tuple[bytes, Message]]) -> None:
        """Delete and submit each fetched message, skipping duplicates.

        Every message is removed from the mailbox; a message that is an
        exact re-delivery (same ``Message-ID`` and content, see
        :meth:`_claim_message`) is then dropped instead of becoming a
        second task.  Per-message failures are logged and skipped, but
        connection errors propagate so the caller can reconnect.

        Args:
            messages: ``(imap_uid, parsed_message)`` tuples from
                ``fetch_unread()``.

        Raises:
            IMAPConnectionError: If deletion fails on a connection error.
        """
        assert self._submit is not None
        for msg_id, message in messages:
            try:
                self._email_listener.delete_message(msg_id)
                if not self._claim_message(message):
                    continue
                raw = RawMessage(
                    sender=message.get("From", ""),
                    content=message,
                    display_title=message.get("Subject", ""),
                )
                self._submit(raw)
            except IMAPConnectionError:
                raise  # Bubble up for reconnection
            except Exception as e:
                self._log.exception(
                    "Failed to submit message: %s",
                    e,
                )

    def _polling_loop(self) -> None:
        """Polling-based message loop."""
        reconnect_attempts = 0
        max_reconnect_attempts = 5
        el = self._email_listener

        while self._running:
            try:
                messages = el.fetch_unread()

                if messages:
                    self._log.info(
                        "Processing %d new messages",
                        len(messages),
                    )

                reconnect_attempts = 0

                self._deliver_messages(messages)

                self._stop_event.wait(self._config.imap.poll_interval)

            except IMAPConnectionError as e:
                if not self._running:
                    return  # Shutting down; don't attempt reconnection
                try:
                    reconnect_attempts = self._reconnect_with_backoff(
                        reconnect_attempts, max_reconnect_attempts, error=e
                    )
                except _ReconnectFailedError:
                    return

    def _idle_loop(self) -> None:
        """IDLE-based message loop."""
        reconnect_attempts = 0
        max_reconnect_attempts = 5
        last_reconnect = time.time()
        reconnect_interval = self._config.imap.idle_reconnect_interval
        el = self._email_listener

        while self._running:
            try:
                if time.time() - last_reconnect >= reconnect_interval:
                    self._log.info(
                        "Periodic reconnect after %d seconds",
                        reconnect_interval,
                    )
                    el.disconnect()
                    el.connect(
                        max_retries=self._config.imap.connect_retries,
                        stop_event=self._stop_event,
                    )
                    last_reconnect = time.time()
                    reconnect_attempts = 0

                messages = el.fetch_unread()

                if messages:
                    self._log.info(
                        "Processing %d new messages",
                        len(messages),
                    )

                reconnect_attempts = 0

                self._deliver_messages(messages)

                if messages:
                    continue

                try:
                    has_pending = el.idle_start()
                    if has_pending:
                        continue

                    time_until_reconnect = max(
                        0,
                        reconnect_interval - (time.time() - last_reconnect),
                    )
                    idle_timeout = min(time_until_reconnect, 29 * 60)

                    if idle_timeout > 0:
                        got_notification = el.idle_wait(idle_timeout)

                        if got_notification:
                            self._log.debug("IDLE notification received")

                    if not self._running:
                        break

                    el.idle_done()

                except IMAPIdleError as e:
                    self._log.warning(
                        "IDLE error, reconnecting: %s",
                        e,
                    )
                    last_reconnect = 0

            except IMAPConnectionError as e:
                if not self._running:
                    return  # Shutting down; don't attempt reconnection
                try:
                    reconnect_attempts = self._reconnect_with_backoff(
                        reconnect_attempts, max_reconnect_attempts, error=e
                    )
                    last_reconnect = time.time()
                except _ReconnectFailedError:
                    return
