# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email listener (IMAP)."""

import imaplib
import os
import socket
from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from lib.gateway.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)


def test_listener_init(email_config):
    """Test listener initialization."""
    listener = EmailListener(email_config)

    assert listener.config == email_config
    assert listener.connection is None
    assert listener._idle_tag is None
    assert listener._interrupted is False
    # Interrupt pipe file descriptors should be valid (non-negative integers)
    assert listener._interrupt_read is not None
    assert listener._interrupt_read >= 0
    assert listener._interrupt_write is not None
    assert listener._interrupt_write >= 0

    # Cleanup
    listener.close()


def test_connect_success(email_config):
    """Test successful IMAP connection."""
    listener = EmailListener(email_config)

    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_conn = MagicMock()
        mock_imap.return_value = mock_conn

        listener.connect()

        mock_imap.assert_called_once_with(
            email_config.imap_server, email_config.imap_port, timeout=10
        )
        mock_conn.login.assert_called_once_with(
            email_config.email_username, email_config.email_password
        )
        assert listener.connection == mock_conn


def test_connect_retry_success(email_config):
    """Test connection succeeds after retry."""
    listener = EmailListener(email_config)

    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_conn = MagicMock()

        # First call fails, second succeeds
        mock_imap.side_effect = [
            imaplib.IMAP4.error("Connection refused"),
            mock_conn,
        ]

        with patch("time.sleep"):  # Skip actual sleep
            listener.connect(max_retries=3)

        assert listener.connection == mock_conn


def test_connect_retry_exhausted(email_config):
    """Test connection fails after max retries."""
    listener = EmailListener(email_config)

    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_imap.side_effect = imaplib.IMAP4.error("Connection refused")

        with patch("time.sleep"):  # Skip actual sleep
            with pytest.raises(
                IMAPConnectionError, match="Failed to connect after 3 attempts"
            ):
                listener.connect(max_retries=3)

    assert listener.connection is None


def test_connect_oserror_retry(email_config):
    """Test connection retries on OSError."""
    listener = EmailListener(email_config)

    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_conn = MagicMock()

        # First call raises OSError, second succeeds
        mock_imap.side_effect = [OSError("Network unreachable"), mock_conn]

        with patch("time.sleep"):
            listener.connect(max_retries=3)

        assert listener.connection == mock_conn


def test_fetch_unread_success(email_config, sample_email_bytes):
    """Test fetching unread messages."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    # Mock IMAP search and fetch responses
    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("OK", [b"1 2 3"])
    mock_conn.fetch.side_effect = [
        ("OK", [(b"1 (RFC822 {123})", sample_email_bytes)]),
        ("OK", [(b"2 (RFC822 {123})", sample_email_bytes)]),
        ("OK", [(b"3 (RFC822 {123})", sample_email_bytes)]),
    ]

    messages = listener.fetch_unread()

    assert len(messages) == 3
    assert all(
        isinstance(msg_id, bytes) and isinstance(msg, Message)
        for msg_id, msg in messages
    )

    mock_conn.select.assert_called_once_with("INBOX")
    mock_conn.search.assert_called_once_with(None, "UNSEEN")


def test_fetch_unread_empty_inbox(email_config):
    """Test fetching with no unread messages."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"0"])
    mock_conn.search.return_value = ("OK", [b""])

    messages = listener.fetch_unread()

    assert len(messages) == 0


def test_fetch_unread_not_connected(email_config):
    """Test fetching without connection."""
    listener = EmailListener(email_config)

    with pytest.raises(
        IMAPConnectionError, match="Not connected to IMAP server"
    ):
        listener.fetch_unread()


def test_fetch_unread_search_fails(email_config):
    """Test fetching when IMAP search fails."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("NO", [])

    with pytest.raises(IMAPConnectionError, match="IMAP search failed"):
        listener.fetch_unread()


def test_fetch_unread_imap_error(email_config):
    """Test fetching when IMAP error occurs."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.side_effect = imaplib.IMAP4.error("IMAP error")

    with pytest.raises(IMAPConnectionError, match="Failed to fetch messages"):
        listener.fetch_unread()


def test_fetch_unread_skip_failed_message(email_config, sample_email_bytes):
    """Test fetching skips messages that fail to fetch."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("OK", [b"1 2"])
    mock_conn.fetch.side_effect = [
        ("OK", [(b"1 (RFC822 {123})", sample_email_bytes)]),
        ("NO", []),  # Second message fails
    ]

    messages = listener.fetch_unread()

    # Should get 1 message (second one failed)
    assert len(messages) == 1


def test_fetch_unread_malformed_response_bytes_not_tuple(
    email_config, sample_email_bytes
):
    """Test fetching handles malformed response where data[0] is bytes."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("OK", [b"1 2"])
    mock_conn.fetch.side_effect = [
        ("OK", [(b"1 (RFC822 {123})", sample_email_bytes)]),
        # Malformed response: data[0] is bytes, not a tuple
        # This can happen with some IMAP servers
        ("OK", [b")"]),
    ]

    messages = listener.fetch_unread()

    # Should get 1 message (second one has malformed response)
    assert len(messages) == 1


def test_fetch_unread_malformed_response_non_bytes_body(email_config, caplog):
    """Test fetching handles malformed response where body is not bytes."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("OK", [b"1"])
    # Response has tuple but body element is int (simulating the crash scenario)
    mock_conn.fetch.return_value = ("OK", [(b"1 (RFC822 {123})", 12345)])

    messages = listener.fetch_unread()

    # Should skip the malformed message
    assert len(messages) == 0
    # Should log warning about unexpected type
    assert "Unexpected message body type for ID 1: int" in caplog.text


def test_disconnect_success(email_config):
    """Test successful disconnect."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    listener.disconnect()

    mock_conn.logout.assert_called_once()
    assert listener.connection is None


def test_disconnect_not_connected(email_config):
    """Test disconnect when not connected."""
    listener = EmailListener(email_config)

    # Should not raise error
    listener.disconnect()
    assert listener.connection is None


def test_disconnect_with_error(email_config):
    """Test disconnect handles logout errors gracefully."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    mock_conn.logout.side_effect = Exception("Logout failed")
    listener.connection = mock_conn

    # Should not raise, just log warning
    listener.disconnect()

    assert listener.connection is None


def test_mark_as_read_success(email_config):
    """Test marking message as read."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.store.return_value = ("OK", [b"1 (FLAGS (\\Seen))"])

    listener.mark_as_read(b"123")

    mock_conn.select.assert_called_once_with("INBOX")
    mock_conn.store.assert_called_once_with("123", "+FLAGS", "\\Seen")


def test_mark_as_read_non_ok_status(email_config):
    """Test marking as read with non-OK status."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.store.return_value = ("NO", [])  # Non-OK status

    # Should not raise error, just log warning
    listener.mark_as_read(b"123")

    mock_conn.select.assert_called_once_with("INBOX")
    mock_conn.store.assert_called_once_with("123", "+FLAGS", "\\Seen")


def test_mark_as_read_not_connected(email_config):
    """Test marking as read when not connected."""
    listener = EmailListener(email_config)

    with pytest.raises(
        IMAPConnectionError, match="Not connected to IMAP server"
    ):
        listener.mark_as_read(b"123")


def test_mark_as_read_imap_error(email_config):
    """Test marking as read with IMAP error."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.store.side_effect = imaplib.IMAP4.error("Store failed")

    with pytest.raises(
        IMAPConnectionError, match="Failed to mark message as read"
    ):
        listener.mark_as_read(b"123")


def test_delete_message_success(email_config):
    """Test deleting message."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.store.return_value = ("OK", [b"1 (FLAGS (\\Deleted))"])
    mock_conn.expunge.return_value = ("OK", [b"1"])

    listener.delete_message(b"123")

    mock_conn.select.assert_called_once_with("INBOX")
    mock_conn.store.assert_called_once_with("123", "+FLAGS", "\\Deleted")
    mock_conn.expunge.assert_called_once()


def test_delete_message_non_ok_status(email_config):
    """Test deleting with non-OK status."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.store.return_value = ("NO", [])  # Non-OK status
    mock_conn.expunge.return_value = ("OK", [])

    # Should not raise error, just log warning
    listener.delete_message(b"123")

    mock_conn.select.assert_called_once_with("INBOX")
    mock_conn.store.assert_called_once_with("123", "+FLAGS", "\\Deleted")
    mock_conn.expunge.assert_called_once()


def test_delete_message_not_connected(email_config):
    """Test deleting when not connected."""
    listener = EmailListener(email_config)

    with pytest.raises(
        IMAPConnectionError, match="Not connected to IMAP server"
    ):
        listener.delete_message(b"123")


def test_delete_message_imap_error(email_config):
    """Test deleting with IMAP error."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.store.side_effect = imaplib.IMAP4.error("Delete failed")

    with pytest.raises(IMAPConnectionError, match="Failed to delete message"):
        listener.delete_message(b"123")


# IDLE tests


def test_idle_start_success(email_config):
    """Test entering IDLE mode."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    # Mock _new_tag to return a tag
    mock_conn._new_tag.return_value = b"A001"
    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("OK", [b""])
    mock_conn.readline.return_value = b"+ idling\r\n"

    result = listener.idle_start()

    assert result is False
    mock_conn.select.assert_called_once_with("INBOX")
    mock_conn.search.assert_called_once_with(None, "UNSEEN")
    mock_conn.send.assert_called_once_with(b"A001 IDLE\r\n")
    assert listener._idle_tag == "A001"


def test_idle_start_not_connected(email_config):
    """Test IDLE start without connection."""
    listener = EmailListener(email_config)

    with pytest.raises(
        IMAPConnectionError, match="Not connected to IMAP server"
    ):
        listener.idle_start()


def test_idle_start_not_accepted(email_config):
    """Test IDLE start when server doesn't accept IDLE."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn._new_tag.return_value = b"A001"
    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("OK", [b""])
    mock_conn.readline.return_value = b"A001 BAD IDLE not supported\r\n"

    with pytest.raises(IMAPIdleError, match="IDLE not accepted"):
        listener.idle_start()

    # Tag should be cleared on failure
    assert listener._idle_tag is None


def test_idle_start_has_pending_messages(email_config):
    """Test IDLE start returns True when unseen messages exist.

    This covers the race condition where a message arrives between
    fetch_unread() and IDLE: idle_start() detects the pending message
    and returns True without entering IDLE.
    """
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.return_value = ("OK", [b"42"])
    mock_conn.search.return_value = ("OK", [b"1 2"])

    result = listener.idle_start()

    assert result is True
    mock_conn.select.assert_called_once_with("INBOX")
    mock_conn.search.assert_called_once_with(None, "UNSEEN")
    # IDLE command should NOT have been sent
    mock_conn.send.assert_not_called()
    assert listener._idle_tag is None


def test_idle_start_imap_error(email_config):
    """Test IDLE start with IMAP error."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_conn.select.side_effect = imaplib.IMAP4.error("Select failed")

    with pytest.raises(IMAPIdleError, match="Failed to enter IDLE mode"):
        listener.idle_start()

    # Tag should be cleared on failure
    assert listener._idle_tag is None


def test_idle_wait_notification_received(email_config):
    """Test IDLE wait receives notification."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock
    mock_conn.readline.return_value = b"* 1 EXISTS\r\n"

    with patch("lib.gateway.listener.select.select") as mock_select:
        # Simulate socket becoming readable
        mock_select.return_value = ([mock_sock], [], [])

        result = listener.idle_wait(timeout=60)

    assert result is True
    # select is now called with both IMAP socket and interrupt pipe fd
    mock_select.assert_called_once_with(
        [mock_sock, listener._interrupt_read], [], [], 60
    )
    listener.close()


def test_idle_wait_timeout(email_config):
    """Test IDLE wait timeout."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock

    with patch("lib.gateway.listener.select.select") as mock_select:
        # Simulate timeout (no readable sockets)
        mock_select.return_value = ([], [], [])

        result = listener.idle_wait(timeout=60)

    assert result is False
    listener.close()


def test_idle_wait_not_connected(email_config):
    """Test IDLE wait without connection."""
    listener = EmailListener(email_config)

    with pytest.raises(
        IMAPConnectionError, match="Not connected to IMAP server"
    ):
        listener.idle_wait()

    listener.close()


def test_idle_wait_oserror(email_config):
    """Test IDLE wait with OS error."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock

    with patch("lib.gateway.listener.select.select") as mock_select:
        mock_select.side_effect = OSError("Socket error")

        with pytest.raises(IMAPIdleError, match="IDLE wait error"):
            listener.idle_wait()

    listener.close()


def test_idle_done_success(email_config):
    """Test exiting IDLE mode."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._idle_tag = "A001"

    mock_conn.readline.return_value = b"A001 OK IDLE terminated\r\n"

    listener.idle_done()

    mock_conn.send.assert_called_once_with(b"DONE\r\n")
    # Tag should be cleared after done
    assert listener._idle_tag is None


def test_idle_done_not_connected(email_config):
    """Test IDLE done without connection."""
    listener = EmailListener(email_config)

    with pytest.raises(
        IMAPConnectionError, match="Not connected to IMAP server"
    ):
        listener.idle_done()


def test_idle_done_unexpected_response(email_config):
    """Test IDLE done with unexpected response (logs warning)."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._idle_tag = "A001"

    # Non-OK response should log warning but not raise
    mock_conn.readline.return_value = b"A001 BAD unexpected\r\n"

    # Should not raise
    listener.idle_done()

    mock_conn.send.assert_called_once_with(b"DONE\r\n")
    # Tag should still be cleared
    assert listener._idle_tag is None


def test_idle_done_imap_error(email_config):
    """Test IDLE done with IMAP error."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._idle_tag = "A001"

    mock_conn.send.side_effect = imaplib.IMAP4.error("Send failed")

    with pytest.raises(IMAPIdleError, match="Failed to exit IDLE mode"):
        listener.idle_done()

    # Tag should still be cleared even on error
    assert listener._idle_tag is None


def test_idle_done_oserror(email_config):
    """Test IDLE done with OS error."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._idle_tag = "A001"

    mock_conn.send.side_effect = OSError("Socket closed")

    with pytest.raises(IMAPIdleError, match="Failed to exit IDLE mode"):
        listener.idle_done()

    # Tag should still be cleared even on error
    assert listener._idle_tag is None


def test_idle_done_drains_buffered_notifications(email_config):
    """Test IDLE done drains buffered untagged responses."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._idle_tag = "A001"

    # Server sends multiple EXISTS notifications before the tagged response
    mock_conn.readline.side_effect = [
        b"* 2 EXISTS\r\n",
        b"* 3 EXISTS\r\n",
        b"A001 OK IDLE terminated\r\n",
    ]

    listener.idle_done()

    mock_conn.send.assert_called_once_with(b"DONE\r\n")
    assert mock_conn.readline.call_count == 3
    assert listener._idle_tag is None


def test_idle_done_fallback_ok_match(email_config):
    """Test IDLE done fallback OK match when tag is not set."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    # No tag set (edge case)
    listener._idle_tag = None

    mock_conn.readline.return_value = b"AAAA OK IDLE terminated\r\n"

    listener.idle_done()

    mock_conn.send.assert_called_once_with(b"DONE\r\n")
    assert listener._idle_tag is None


def test_idle_done_unexpected_non_ok_response(email_config, caplog):
    """Test IDLE done with unexpected non-OK, non-untagged response."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._idle_tag = "A001"

    # Response doesn't match tag and isn't untagged
    mock_conn.readline.return_value = b"ZZZZ NO something went wrong\r\n"

    listener.idle_done()

    mock_conn.send.assert_called_once_with(b"DONE\r\n")
    assert "Unexpected IDLE response" in caplog.text
    assert listener._idle_tag is None


def test_idle_done_non_ok_tagged_response(email_config, caplog):
    """Test IDLE done with non-OK status in tagged response."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._idle_tag = "A001"

    mock_conn.readline.return_value = b"A001 NO IDLE failed\r\n"

    listener.idle_done()

    mock_conn.send.assert_called_once_with(b"DONE\r\n")
    assert "IDLE completed with non-OK status" in caplog.text
    assert listener._idle_tag is None


# Interrupt and close tests


def test_interrupt_sets_flag_and_signals(email_config):
    """Test interrupt sets flag and sends signal to pipe."""
    listener = EmailListener(email_config)

    assert listener._interrupted is False

    listener.interrupt()

    assert listener._interrupted is True
    # Pipe should have received data
    assert listener._interrupt_read is not None
    data = os.read(listener._interrupt_read, 1024)
    assert data == b"x"

    listener.close()


def test_interrupt_multiple_times(email_config):
    """Test interrupt can be called multiple times safely."""
    listener = EmailListener(email_config)

    # Call interrupt multiple times
    listener.interrupt()
    listener.interrupt()
    listener.interrupt()

    assert listener._interrupted is True

    listener.close()


def test_interrupt_with_closed_pipe(email_config):
    """Test interrupt handles closed pipe gracefully."""
    listener = EmailListener(email_config)

    # Close the write end of the pipe
    assert listener._interrupt_write is not None
    os.close(listener._interrupt_write)
    listener._interrupt_write = None

    # Should not raise
    listener.interrupt()

    assert listener._interrupted is True

    listener.close()


def test_close_cleans_up_fds(email_config):
    """Test close cleans up all resources."""
    listener = EmailListener(email_config)

    # Store references to check they're closed
    assert listener._interrupt_read is not None
    assert listener._interrupt_write is not None
    read_fd = listener._interrupt_read
    write_fd = listener._interrupt_write

    listener.close()

    assert listener._interrupt_read is None
    assert listener._interrupt_write is None
    assert listener.connection is None

    # File descriptors should be closed (os.fstat raises on closed fd)
    with pytest.raises(OSError):
        os.fstat(read_fd)
    with pytest.raises(OSError):
        os.fstat(write_fd)


def test_close_with_connection(email_config):
    """Test close disconnects IMAP connection."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    listener.close()

    mock_conn.logout.assert_called_once()
    assert listener.connection is None


def test_close_idempotent(email_config):
    """Test close can be called multiple times safely."""
    listener = EmailListener(email_config)

    listener.close()
    listener.close()  # Should not raise
    listener.close()  # Should not raise

    assert listener._interrupt_read is None
    assert listener._interrupt_write is None


def test_idle_wait_returns_false_when_interrupted(email_config):
    """Test idle_wait returns False immediately when already interrupted."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._interrupted = True

    # Should return False without blocking
    result = listener.idle_wait(timeout=60)

    assert result is False
    # select should not have been called
    listener.close()


def test_idle_wait_interrupted_by_signal(email_config):
    """Test idle_wait returns False when interrupt signal received."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock

    assert listener._interrupt_read is not None
    assert listener._interrupt_write is not None

    with patch("lib.gateway.listener.select.select") as mock_select:
        # Simulate interrupt pipe becoming readable
        mock_select.return_value = ([listener._interrupt_read], [], [])

        # Write to interrupt pipe to simulate interrupt
        os.write(listener._interrupt_write, b"x")

        result = listener.idle_wait(timeout=60)

    assert result is False
    listener.close()


def test_idle_wait_with_both_fds_readable(email_config):
    """Test idle_wait prioritizes interrupt over IMAP notification."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock

    assert listener._interrupt_read is not None
    assert listener._interrupt_write is not None

    with patch("lib.gateway.listener.select.select") as mock_select:
        # Both fds readable - interrupt should take priority
        mock_select.return_value = (
            [listener._interrupt_read, mock_sock],
            [],
            [],
        )

        # Write to interrupt pipe
        os.write(listener._interrupt_write, b"x")

        result = listener.idle_wait(timeout=60)

    # Should return False due to interrupt, not True due to IMAP
    assert result is False
    listener.close()


def test_idle_wait_without_interrupt_pipe(email_config):
    """Test idle_wait works when interrupt pipe is None."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    # Close and clear interrupt pipe
    assert listener._interrupt_read is not None
    assert listener._interrupt_write is not None
    os.close(listener._interrupt_read)
    os.close(listener._interrupt_write)
    listener._interrupt_read = None
    listener._interrupt_write = None

    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock
    mock_conn.readline.return_value = b"* 1 EXISTS\r\n"

    with patch("lib.gateway.listener.select.select") as mock_select:
        mock_select.return_value = ([mock_sock], [], [])

        result = listener.idle_wait(timeout=60)

    assert result is True
    listener.close()


def test_interrupt_oserror_on_write(email_config):
    """Test interrupt handles OSError during write gracefully."""
    listener = EmailListener(email_config)

    # Close the write fd to cause OSError on write
    assert listener._interrupt_write is not None
    write_fd = listener._interrupt_write
    os.close(write_fd)
    # Don't set to None - let it try to write to closed fd

    # Should not raise, just silently fail
    listener.interrupt()

    assert listener._interrupted is True

    # Clean up read fd (write fd already closed)
    assert listener._interrupt_read is not None
    os.close(listener._interrupt_read)
    listener._interrupt_read = None
    listener._interrupt_write = None


def test_close_oserror_on_close_fds(email_config):
    """Test close handles OSError when closing file descriptors."""
    listener = EmailListener(email_config)

    # Close the fds ourselves first to simulate already-closed state
    assert listener._interrupt_read is not None
    assert listener._interrupt_write is not None
    os.close(listener._interrupt_read)
    os.close(listener._interrupt_write)
    # Don't set to None - let close() try to close them again

    # Should not raise, just handle OSError silently
    listener.close()

    assert listener._interrupt_read is None
    assert listener._interrupt_write is None


def test_idle_wait_oserror_draining_interrupt_pipe(email_config):
    """Test idle_wait handles OSError when draining interrupt pipe."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn

    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock

    assert listener._interrupt_read is not None
    assert listener._interrupt_write is not None
    read_fd = listener._interrupt_read

    with patch("lib.gateway.listener.select.select") as mock_select:
        # Simulate interrupt pipe becoming readable
        mock_select.return_value = ([read_fd], [], [])

        # Close the read fd before os.read is called to cause OSError
        # We need to patch os.read since it's called after select
        with patch("lib.gateway.listener.os.read") as mock_read:
            mock_read.side_effect = OSError("fd already closed")

            result = listener.idle_wait(timeout=60)

    # Should return False (interrupted) despite OSError in drain
    assert result is False
    listener.close()


def test_interrupt_shuts_down_socket(email_config):
    """Test interrupt calls socket.shutdown to unblock readline."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    mock_sock = MagicMock()
    mock_conn.socket.return_value = mock_sock
    listener.connection = mock_conn

    listener.interrupt()

    assert listener._interrupted is True
    mock_sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)

    listener.close()


def test_interrupt_handles_socket_shutdown_oserror(email_config):
    """Test interrupt handles OSError during socket shutdown gracefully."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    mock_sock = MagicMock()
    mock_sock.shutdown.side_effect = OSError("Socket already closed")
    mock_conn.socket.return_value = mock_sock
    listener.connection = mock_conn

    # Should not raise
    listener.interrupt()

    assert listener._interrupted is True
    mock_sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)

    listener.close()


def test_interrupt_no_connection(email_config):
    """Test interrupt works without connection."""
    listener = EmailListener(email_config)

    # No connection set
    assert listener.connection is None

    # Should not raise
    listener.interrupt()

    assert listener._interrupted is True

    listener.close()


def test_interrupt_socket_returns_none(email_config):
    """Test interrupt handles socket() returning None."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    mock_conn.socket.return_value = None
    listener.connection = mock_conn

    # Should not raise
    listener.interrupt()

    assert listener._interrupted is True

    listener.close()


def test_disconnect_skips_logout_when_interrupted(email_config):
    """Test disconnect skips logout when already interrupted."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._interrupted = True

    listener.disconnect()

    # logout should NOT be called when interrupted
    mock_conn.logout.assert_not_called()
    assert listener.connection is None


def test_disconnect_calls_logout_when_not_interrupted(email_config):
    """Test disconnect calls logout when not interrupted."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    listener.connection = mock_conn
    listener._interrupted = False

    listener.disconnect()

    # logout SHOULD be called when not interrupted
    mock_conn.logout.assert_called_once()
    assert listener.connection is None


def test_disconnect_logs_warning_only_when_not_interrupted(
    email_config, caplog
):
    """Test disconnect only logs warning for errors when not interrupted."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    mock_conn.logout.side_effect = Exception("Connection lost")
    listener.connection = mock_conn
    listener._interrupted = False

    listener.disconnect()

    assert "Error during IMAP disconnect" in caplog.text
    assert listener.connection is None


def test_disconnect_no_warning_when_interrupted_with_error(
    email_config, caplog
):
    """Test disconnect does not log warning when interrupted, even on error."""
    listener = EmailListener(email_config)

    mock_conn = MagicMock()
    # logout shouldn't be called, but if it were to fail, we should not warn
    mock_conn.logout.side_effect = Exception("Connection lost")
    listener.connection = mock_conn
    listener._interrupted = True

    listener.disconnect()

    # No warning should be logged since we're interrupted
    assert "Error during IMAP disconnect" not in caplog.text
    assert listener.connection is None
