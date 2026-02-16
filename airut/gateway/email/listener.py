# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email listener for IMAP polling and IDLE.

This module provides the EmailListener class for connecting to IMAP servers,
fetching unread messages, and handling connection retry logic. Supports both
polling and IMAP IDLE for push notifications.
"""

import imaplib
import logging
import os
import select
import socket
import time
from email.message import Message
from email.parser import BytesParser

from airut.gateway.config import EmailChannelConfig
from airut.gateway.email.microsoft_oauth2 import (
    MicrosoftOAuth2TokenError,
    MicrosoftOAuth2TokenProvider,
)


logger = logging.getLogger(__name__)


class IMAPIdleError(Exception):
    """Raised when IMAP IDLE operation fails."""


class IMAPConnectionError(Exception):
    """Raised when IMAP connection/operation fails."""


class EmailListener:
    """IMAP email listener with polling and retry logic.

    Attributes:
        config: Email channel configuration.
        connection: Active IMAP connection (None when disconnected).
    """

    def __init__(self, config: EmailChannelConfig) -> None:
        """Initialize email listener.

        Args:
            config: Email channel configuration.
        """
        self.config = config
        self.connection: imaplib.IMAP4_SSL | None = None
        self._idle_tag: str | None = None
        self._interrupted = False

        # Create Microsoft OAuth2 token provider if configured
        self._token_provider: MicrosoftOAuth2TokenProvider | None = None
        if config.microsoft_oauth2_tenant_id:
            assert config.microsoft_oauth2_client_id
            assert config.microsoft_oauth2_client_secret
            self._token_provider = MicrosoftOAuth2TokenProvider(
                tenant_id=config.microsoft_oauth2_tenant_id,
                client_id=config.microsoft_oauth2_client_id,
                client_secret=config.microsoft_oauth2_client_secret,
            )

        # Pipe for interrupting IDLE wait from another thread.
        # Writing to _interrupt_write will wake up select() on _interrupt_read.
        self._interrupt_read: int | None = None
        self._interrupt_write: int | None = None
        self._create_interrupt_pipe()

        logger.debug(
            "Initialized email listener for: %s",
            config.imap_server,
        )

    def _create_interrupt_pipe(self) -> None:
        """Create pipe for interrupt signaling."""
        # Use os.pipe for cross-thread signaling
        self._interrupt_read, self._interrupt_write = os.pipe()
        # Set non-blocking mode
        os.set_blocking(self._interrupt_read, False)
        os.set_blocking(self._interrupt_write, False)

    def connect(self, max_retries: int = 3) -> None:
        """Connect to IMAP server with retry logic.

        Args:
            max_retries: Maximum connection attempts.

        Raises:
            IMAPConnectionError: If connection fails after retries.
        """
        for attempt in range(1, max_retries + 1):
            try:
                logger.debug(
                    "Connecting to IMAP (attempt %d/%d)",
                    attempt,
                    max_retries,
                )

                # Use 10s connection timeout to fail fast on unreachable hosts
                self.connection = imaplib.IMAP4_SSL(
                    self.config.imap_server, self.config.imap_port, timeout=10
                )

                if self._token_provider:
                    # Microsoft OAuth2: XOAUTH2 SASL mechanism
                    auth_string = self._token_provider.generate_xoauth2_string(
                        self.config.username
                    ).encode("utf-8")

                    def _xoauth2_callback(challenge: bytes) -> bytes:
                        # XOAUTH2 protocol: server sends empty challenge
                        # for initial auth.  If auth fails, server sends a
                        # non-empty JSON error as a second challenge —
                        # respond with empty bytes to get the final error.
                        if challenge:
                            return b""
                        return auth_string

                    self.connection.authenticate("XOAUTH2", _xoauth2_callback)
                else:
                    self.connection.login(
                        self.config.username, self.config.password
                    )

                logger.info(
                    "Connected to IMAP server: %s",
                    self.config.imap_server,
                )
                return

            except (
                imaplib.IMAP4.error,
                OSError,
                MicrosoftOAuth2TokenError,
            ) as e:
                logger.warning(
                    "IMAP connection attempt %d/%d failed: %s",
                    attempt,
                    max_retries,
                    e,
                )

                if attempt < max_retries:
                    sleep_time = 2 ** (attempt - 1)
                    logger.debug("Retrying in %ds...", sleep_time)
                    time.sleep(sleep_time)
                else:
                    raise IMAPConnectionError(
                        f"Failed to connect after {max_retries} attempts: {e}"
                    )

    def fetch_unread(self) -> list[tuple[bytes, Message]]:
        """Fetch unread messages from INBOX.

        Returns:
            List of tuples (imap_msg_id, parsed_message).

        Raises:
            IMAPConnectionError: If not connected or fetch fails.
        """
        if not self.connection:
            raise IMAPConnectionError("Not connected to IMAP server")

        try:
            self.connection.select("INBOX")

            # Search for unread messages
            status, message_ids = self.connection.search(None, "UNSEEN")

            if status != "OK":
                raise IMAPConnectionError(f"IMAP search failed: {status}")

            messages = []
            parser = BytesParser()

            for msg_id in message_ids[0].split():
                status, data = self.connection.fetch(msg_id, "(RFC822)")

                # IMAP fetch returns data like [(header, body), b')']
                # We need to validate the response format before parsing
                if status == "OK" and data[0] and isinstance(data[0], tuple):
                    message_bytes = data[0][1]
                    if isinstance(message_bytes, bytes):
                        message = parser.parsebytes(message_bytes)
                        messages.append((msg_id, message))
                    else:
                        logger.warning(
                            "Unexpected message body type for ID %s: %s",
                            msg_id.decode(),
                            type(message_bytes).__name__,
                        )

            if messages:
                logger.info("Fetched %d unread messages", len(messages))
            return messages

        except (imaplib.IMAP4.error, OSError) as e:
            raise IMAPConnectionError(f"Failed to fetch messages: {e}")

    def mark_as_read(self, msg_id: bytes) -> None:
        """Mark a message as read.

        Args:
            msg_id: IMAP message ID from fetch_unread().

        Raises:
            IMAPConnectionError: If not connected or marking fails.
        """
        if not self.connection:
            raise IMAPConnectionError("Not connected to IMAP server")

        try:
            self.connection.select("INBOX")
            status, data = self.connection.store(
                msg_id.decode(), "+FLAGS", "\\Seen"
            )
            if status != "OK":
                logger.warning(
                    "Mark as read returned status %s for message %s",
                    status,
                    msg_id.decode(),
                )
            logger.debug("Marked message %s as read", msg_id.decode())
        except imaplib.IMAP4.error as e:
            raise IMAPConnectionError(f"Failed to mark message as read: {e}")

    def delete_message(self, msg_id: bytes) -> None:
        """Delete a message permanently.

        Args:
            msg_id: IMAP message ID from fetch_unread().

        Raises:
            IMAPConnectionError: If not connected or deletion fails.
        """
        if not self.connection:
            raise IMAPConnectionError("Not connected to IMAP server")

        try:
            self.connection.select("INBOX")
            # Mark for deletion
            status, data = self.connection.store(
                msg_id.decode(), "+FLAGS", "\\Deleted"
            )
            if status != "OK":
                logger.warning(
                    "Mark as deleted returned status %s for message %s",
                    status,
                    msg_id.decode(),
                )
            # Expunge to permanently delete
            self.connection.expunge()
            logger.debug("Deleted message %s", msg_id.decode())
        except imaplib.IMAP4.error as e:
            raise IMAPConnectionError(f"Failed to delete message: {e}")

    def disconnect(self) -> None:
        """Disconnect from IMAP server.

        If the connection was interrupted (socket shutdown), this skips
        the graceful logout since the socket is no longer usable.
        """
        if self.connection:
            try:
                # If we were interrupted, socket is already shutdown.
                # Skip logout and just close the connection.
                if not self._interrupted:
                    self.connection.logout()
                    logger.debug("Disconnected from IMAP server")
                else:
                    logger.debug("Skipping logout (connection was interrupted)")
            except Exception as e:
                # Only log as warning if not already interrupted
                if not self._interrupted:
                    logger.warning("Error during IMAP disconnect: %s", e)
            finally:
                self.connection = None

    def interrupt(self) -> None:
        """Interrupt any blocking IDLE wait or readline.

        Thread-safe. Can be called from signal handlers or other threads
        to wake up a blocking idle_wait() call or any blocking socket read.

        This works by:
        1. Writing to the interrupt pipe to wake up select() in idle_wait()
        2. Calling socket.shutdown() to unblock any readline() calls
        """
        self._interrupted = True

        # Wake up select() in idle_wait()
        if self._interrupt_write is not None:
            try:
                os.write(self._interrupt_write, b"x")
            except OSError:
                # Pipe may already be closed or buffer full, ignore
                pass

        # Shutdown the socket to unblock any readline() calls.
        # This causes readline() to return empty bytes immediately.
        if self.connection:
            try:
                sock = self.connection.socket()
                if sock:
                    sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Socket may already be closed or in error state, ignore
                pass

        logger.debug("Interrupt signal sent")

    def close(self) -> None:
        """Close all resources including interrupt pipe.

        Call this when completely done with the listener (e.g., during
        service shutdown).
        """
        self.disconnect()

        # Close interrupt pipe file descriptors
        if self._interrupt_read is not None:
            try:
                os.close(self._interrupt_read)
            except OSError:
                pass
            self._interrupt_read = None

        if self._interrupt_write is not None:
            try:
                os.close(self._interrupt_write)
            except OSError:
                pass
            self._interrupt_write = None

        logger.debug("Listener closed")

    def idle_start(self) -> bool:
        """Enter IDLE mode on the IMAP connection.

        Must be connected and have INBOX selected before calling this.
        After calling idle_start(), use idle_wait() to wait for notifications.

        Performs a SEARCH UNSEEN check after SELECT but before sending the
        IDLE command.  If unseen messages exist, returns True without entering
        IDLE so the caller can fetch them instead.  This closes the race
        window where a message arrives between fetch_unread() and IDLE.

        Returns:
            True if there are pending unseen messages (IDLE was NOT entered).
            False if IDLE was entered successfully.

        Raises:
            IMAPConnectionError: If not connected to IMAP server.
            IMAPIdleError: If server doesn't support IDLE or command fails.
        """
        if not self.connection:
            raise IMAPConnectionError("Not connected to IMAP server")

        try:
            # Select INBOX first (required for IDLE)
            self.connection.select("INBOX")

            # Check for unseen messages before entering IDLE.  This closes
            # the race between the previous fetch_unread() and IDLE: if a
            # message arrived in between, we detect it here and return
            # without entering IDLE.
            status, message_ids = self.connection.search(None, "UNSEEN")
            if status == "OK" and message_ids[0].strip():
                logger.debug(
                    "Skipping IDLE: %d unseen messages pending",
                    len(message_ids[0].split()),
                )
                return True

            # Send IDLE command and store tag for response matching
            self._idle_tag = self.connection._new_tag().decode()
            self.connection.send(f"{self._idle_tag} IDLE\r\n".encode())

            # Read continuation response (+ idling)
            response = self.connection.readline()
            if not response.startswith(b"+"):
                self._idle_tag = None
                raise IMAPIdleError(f"IDLE not accepted: {response.decode()}")

            logger.debug("Entered IDLE mode with tag %s", self._idle_tag)
            return False

        except imaplib.IMAP4.error as e:
            self._idle_tag = None
            raise IMAPIdleError(f"Failed to enter IDLE mode: {e}")

    def idle_wait(self, timeout: float = 29 * 60) -> bool:
        """Wait for IDLE notification, interrupt, or timeout.

        Args:
            timeout: Maximum seconds to wait (default 29 minutes, within
                RFC 2177 recommended 29-minute limit).

        Returns:
            True if notification received, False if timeout or interrupted.

        Raises:
            IMAPConnectionError: If not connected.
            IMAPIdleError: If an error occurs during wait.
        """
        if not self.connection:
            raise IMAPConnectionError("Not connected to IMAP server")

        # Check if already interrupted
        if self._interrupted:
            logger.debug("IDLE wait skipped - already interrupted")
            return False

        try:
            sock = self.connection.socket()

            # Include interrupt pipe in select to allow waking up
            watch_fds = [sock]
            if self._interrupt_read is not None:
                watch_fds.append(self._interrupt_read)

            readable, _, _ = select.select(watch_fds, [], [], timeout)

            # Check if we were interrupted (pipe fd is readable)
            interrupt_fd = self._interrupt_read
            if interrupt_fd is not None and interrupt_fd in readable:
                # Drain the interrupt pipe
                try:
                    os.read(interrupt_fd, 1024)
                except OSError:
                    pass
                logger.debug("IDLE wait interrupted by shutdown signal")
                return False

            if sock in readable:
                # Read whatever data is available (EXISTS/EXPUNGE notification)
                response_data = self.connection.readline()
                decoded = response_data.decode().strip()
                logger.debug("IDLE notification received: %s", decoded)
                return True

            logger.debug("IDLE timeout after %.0f seconds", timeout)
            return False

        except OSError as e:
            raise IMAPIdleError(f"IDLE wait error: {e}")

    def idle_done(self) -> None:
        """Exit IDLE mode.

        Sends DONE command to terminate IDLE state. Drains any buffered
        untagged responses before reading the tagged completion response.

        Raises:
            IMAPConnectionError: If not connected.
            IMAPIdleError: If an error occurs.
        """
        if not self.connection:
            raise IMAPConnectionError("Not connected to IMAP server")

        try:
            # Send DONE to terminate IDLE
            self.connection.send(b"DONE\r\n")

            # Read responses until we get the tagged response.
            # The server may send untagged notifications (e.g., * 2 EXISTS)
            # before the tagged completion response (e.g., A001 OK IDLE done).
            max_responses = 100  # Safety limit to prevent infinite loop
            tag_bytes = self._idle_tag.encode() if self._idle_tag else b""

            for _ in range(max_responses):
                response = self.connection.readline()
                response_str = response.decode().strip()

                # Untagged responses start with *
                if response.startswith(b"*"):
                    logger.debug("Draining untagged response: %s", response_str)
                    continue

                # Tagged response - check if it matches our IDLE tag
                if tag_bytes and response.startswith(tag_bytes):
                    if b"OK" in response.upper():
                        logger.debug("Exited IDLE mode")
                    else:
                        logger.warning(
                            "IDLE completed with non-OK status: %s",
                            response_str,
                        )
                    break

                # Fallback: response doesn't start with * or our tag
                # Could be an error or unexpected format
                if b"OK" in response.upper():
                    logger.debug("Exited IDLE mode (fallback OK match)")
                    break

                logger.warning("Unexpected IDLE response: %s", response_str)
                break

        except (imaplib.IMAP4.error, OSError) as e:
            raise IMAPIdleError(f"Failed to exit IDLE mode: {e}")
        finally:
            self._idle_tag = None
