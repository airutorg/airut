# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email channel listener implementing the ChannelListener protocol.

Wraps the low-level EmailListener (IMAP operations) with polling/IDLE
loops, reconnection logic, and health tracking.  A lost connection is
retried indefinitely with capped exponential backoff.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections.abc import Callable

from airut._threads import join_if_started
from airut.gateway.channel import (
    ChannelHealth,
    ChannelListener,
    ChannelStatus,
    RawMessage,
)
from airut.gateway.config import EmailChannelConfig
from airut.gateway.email.incoming import IncomingEmail
from airut.gateway.email.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)


logger = logging.getLogger(__name__)


#: First reconnect delay in seconds; each further attempt triples it.
_RECONNECT_BASE_DELAY = 10

#: Longest reconnect delay in seconds.  Retries continue at this interval
#: for as long as the server stays unreachable.
_RECONNECT_MAX_DELAY = 300


def reconnect_delay(attempt: int) -> int:
    """Seconds to wait before IMAP reconnect *attempt* (1-based).

    10s, 30s, 90s, 270s, then 300s for every later attempt.
    """
    # Bound the exponent so the delay stays cheap to compute however
    # long an outage lasts; the cap is reached from attempt 5 on.
    exponent = min(attempt - 1, 4)
    return min(_RECONNECT_BASE_DELAY * 3**exponent, _RECONNECT_MAX_DELAY)


def _raw_message(email: IncomingEmail) -> RawMessage[IncomingEmail]:
    """Wrap a fetched email for submission to the gateway.

    Header values are converted to text: a header with undecodable 8-bit
    bytes comes back from the email library as a ``Header`` object.
    """
    return RawMessage(
        sender=str(email.message.get("From", "")),
        content=email,
        display_title=str(email.message.get("Subject", "")),
    )


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
        self._submit: Callable[[RawMessage[IncomingEmail]], bool] | None = None
        self._running = False
        self._stop_event = threading.Event()
        self._status = ChannelStatus(health=ChannelHealth.STARTING)

    def start(
        self, submit: Callable[[RawMessage[IncomingEmail]], bool]
    ) -> None:
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
        thread = self._thread
        if thread is not None and join_if_started(thread, timeout=10):
            if thread.is_alive():
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
        """Main listener loop, dispatching to IDLE or polling mode.

        The loops only return once ``stop()`` is called.  Should one end
        any other way, the listener can no longer receive mail, so it is
        marked FAILED rather than left looking connected.
        """
        try:
            if self._config.imap.use_idle:
                self._idle_loop()
            else:
                self._polling_loop()
        finally:
            if self._running:
                self._log.critical("Email listener loop exited unexpectedly")
                error = sys.exc_info()[1]
                self._status = ChannelStatus(
                    health=ChannelHealth.FAILED,
                    message="Email listener stopped unexpectedly",
                    error_type=type(error).__name__ if error else None,
                )

    def _reconnect(self, failures: int, error: Exception) -> int:
        """Reconnect to IMAP, retrying until connected or stopped.

        Never gives up: waits with capped exponential backoff (see
        ``reconnect_delay``) between attempts and reports DEGRADED until
        the connection is back, so an outage of any length recovers
        without a restart.

        Args:
            failures: Consecutive failed attempts so far.  The loops reset
                it only after a successful fetch, so a connection that
                drops again right after reconnecting keeps backing off.
            error: The error that lost the connection.

        Returns:
            Updated count of consecutive failed attempts.
        """
        while self._running:
            failures += 1
            delay = reconnect_delay(failures)
            self._log.error(
                "IMAP connection error, reconnecting in %ds (attempt %d): %s",
                delay,
                failures,
                error,
                # Errors other than IMAPConnectionError are unexpected;
                # log the traceback to make them diagnosable.
                exc_info=(
                    None if isinstance(error, IMAPConnectionError) else error
                ),
            )
            self._status = ChannelStatus(
                health=ChannelHealth.DEGRADED,
                message=f"IMAP reconnecting (attempt {failures}): {error}",
                error_type=type(error).__name__,
            )

            self._stop_event.wait(delay)
            if not self._running:
                break

            try:
                self._email_listener.disconnect()
                self._email_listener.connect(
                    max_retries=self._config.imap.connect_retries,
                    stop_event=self._stop_event,
                )
            except Exception as e:
                error = e
                continue

            self._log.info("Reconnected to IMAP")
            self._status = ChannelStatus(health=ChannelHealth.CONNECTED)
            break

        return failures

    def _process_messages(
        self, messages: list[tuple[bytes, IncomingEmail]]
    ) -> None:
        """Delete each fetched message from the server and submit it.

        Raises:
            IMAPConnectionError: If the connection fails while deleting,
                so the loop reconnects.  Other per-message errors are
                logged and the next message is processed.
        """
        assert self._submit is not None
        if messages:
            self._log.info("Processing %d new messages", len(messages))

        for msg_id, message in messages:
            try:
                self._email_listener.delete_message(msg_id)
                self._submit(_raw_message(message))
            except IMAPConnectionError:
                raise  # Bubble up for reconnection
            except Exception as e:
                self._log.exception("Failed to submit message: %s", e)

    def _polling_loop(self) -> None:
        """Polling-based message loop.

        Any error outside per-message handling, expected or not, is
        treated as a lost connection and retried by ``_reconnect``.
        """
        failures = 0
        el = self._email_listener

        while self._running:
            try:
                messages = el.fetch_unread()
                failures = 0
                self._process_messages(messages)
                self._stop_event.wait(self._config.imap.poll_interval)

            except Exception as e:
                if not self._running:
                    return  # Shutting down; don't attempt reconnection
                failures = self._reconnect(failures, e)

    def _idle_loop(self) -> None:
        """IDLE-based message loop.

        Errors are handled as in ``_polling_loop``.
        """
        failures = 0
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

                messages = el.fetch_unread()
                failures = 0
                self._process_messages(messages)

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

            except Exception as e:
                if not self._running:
                    return  # Shutting down; don't attempt reconnection
                failures = self._reconnect(failures, e)
                last_reconnect = time.time()
