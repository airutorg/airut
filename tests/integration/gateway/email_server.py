# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Test SMTP/IMAP server for integration tests.

Provides an in-process email server with:
- SMTP server (using aiosmtpd) for receiving outgoing mail from the service
- Minimal IMAP server for serving incoming mail to the service

The two servers share a mailbox store, allowing the test to:
1. Inject messages into the IMAP inbox (simulating external sender)
2. Retrieve messages sent via SMTP (verifying service responses)
"""

import asyncio
import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from email.message import EmailMessage

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message as SMTPMessageHandler


logger = logging.getLogger(__name__)


def find_free_port() -> int:
    """Find a free TCP port on localhost.

    Creates a socket, binds to port 0 (asking OS for any free port),
    retrieves the assigned port, then closes the socket.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        return port


@dataclass
class StoredMessage:
    """A message stored in the mailbox."""

    uid: int
    message: EmailMessage
    flags: set[str] = field(default_factory=set)
    deleted: bool = False


class MailboxStore:
    """Thread-safe in-memory mailbox store.

    Supports both SMTP (write) and IMAP (read) operations with proper
    synchronization for concurrent access.
    """

    def __init__(self) -> None:
        self._messages: list[StoredMessage] = []
        self._next_uid: int = 1
        self._lock = threading.Lock()
        self._new_message_event = threading.Event()

    def add_message(self, msg: EmailMessage) -> int:
        """Add a message and return its UID."""
        with self._lock:
            uid = self._next_uid
            self._next_uid += 1
            self._messages.append(StoredMessage(uid=uid, message=msg))
            logger.debug(
                "Added message UID=%d: %s", uid, msg.get("Subject", "")
            )
            self._new_message_event.set()
            return uid

    def get_unseen_uids(self) -> list[int]:
        r"""Get UIDs of all unseen (not \Seen flag) messages."""
        with self._lock:
            return [
                m.uid
                for m in self._messages
                if not m.deleted and "\\Seen" not in m.flags
            ]

    def get_message(self, uid: int) -> EmailMessage | None:
        """Get message by UID."""
        with self._lock:
            for m in self._messages:
                if m.uid == uid and not m.deleted:
                    return m.message
            return None

    def add_flag(self, uid: int, flag: str) -> bool:
        """Add a flag to a message."""
        with self._lock:
            for m in self._messages:
                if m.uid == uid and not m.deleted:
                    m.flags.add(flag)
                    # Mark as deleted if \Deleted flag is set
                    if flag == "\\Deleted":
                        m.deleted = True
                    logger.debug("Added flag %s to UID=%d", flag, uid)
                    return True
            return False

    def mark_deleted(self, uid: int) -> bool:
        """Mark a message for deletion."""
        with self._lock:
            for m in self._messages:
                if m.uid == uid:
                    m.deleted = True
                    logger.debug("Marked UID=%d for deletion", uid)
                    return True
            return False

    def expunge(self) -> list[int]:
        """Remove all messages marked for deletion. Returns removed UIDs."""
        with self._lock:
            removed = [m.uid for m in self._messages if m.deleted]
            self._messages = [m for m in self._messages if not m.deleted]
            if removed:
                logger.debug("Expunged UIDs: %s", removed)
            return removed

    def count(self) -> int:
        """Get count of non-deleted messages."""
        with self._lock:
            return sum(1 for m in self._messages if not m.deleted)

    def wait_for_message(self, timeout: float = 30.0) -> bool:
        """Wait for a new message to arrive."""
        self._new_message_event.clear()
        return self._new_message_event.wait(timeout)

    def get_unseen_seq_nums(self) -> list[int]:
        r"""Get 1-based sequence numbers of unseen messages.

        Sequence numbers are positional indices into the list of
        non-deleted messages.  Unlike UIDs, they shift when earlier
        messages are expunged.
        """
        with self._lock:
            non_deleted = [m for m in self._messages if not m.deleted]
            return [
                i + 1
                for i, m in enumerate(non_deleted)
                if "\\Seen" not in m.flags
            ]

    def get_message_by_seq(self, seq_num: int) -> EmailMessage | None:
        """Get message by 1-based sequence number."""
        with self._lock:
            non_deleted = [m for m in self._messages if not m.deleted]
            if 1 <= seq_num <= len(non_deleted):
                return non_deleted[seq_num - 1].message
            return None

    def add_flag_by_seq(self, seq_num: int, flag: str) -> bool:
        """Add flag to message by 1-based sequence number."""
        with self._lock:
            non_deleted = [m for m in self._messages if not m.deleted]
            if 1 <= seq_num <= len(non_deleted):
                msg = non_deleted[seq_num - 1]
                msg.flags.add(flag)
                if flag == "\\Deleted":
                    msg.deleted = True
                logger.debug(
                    "Added flag %s to seq=%d (UID=%d)",
                    flag,
                    seq_num,
                    msg.uid,
                )
                return True
            return False

    def get_all_messages(self) -> list[EmailMessage]:
        """Get all non-deleted messages."""
        with self._lock:
            return [m.message for m in self._messages if not m.deleted]


class TestSMTPHandler(SMTPMessageHandler):
    """SMTP handler that stores messages in the outbox."""

    def __init__(self, outbox: MailboxStore) -> None:
        super().__init__()
        self.outbox = outbox

    def handle_message(  # type: ignore[override]
        self, message: EmailMessage
    ) -> None:  # ty:ignore[invalid-method-override]
        """Handle incoming SMTP message by storing in outbox."""
        logger.info("SMTP received message: %s", message.get("Subject", ""))
        self.outbox.add_message(message)


class MinimalIMAPHandler:
    """Minimal IMAP4 protocol handler.

    Implements only the commands needed by EmailListener:
    - LOGIN, LOGOUT
    - SELECT
    - SEARCH UNSEEN (sequence numbers) / UID SEARCH UNSEEN (UIDs)
    - FETCH (sequence number) / UID FETCH (UID)
    - STORE (sequence number) / UID STORE (UID)
    - EXPUNGE
    - IDLE, DONE

    Non-UID commands use sequence numbers (1-based positional indices
    into non-deleted messages).  UID-prefixed commands use stable UIDs.
    This distinction matters because sequence numbers shift when
    messages are expunged, while UIDs do not.
    """

    def __init__(
        self,
        inbox: MailboxStore,
        username: str,
        password: str,
        inboxes: dict[str, MailboxStore] | None = None,
    ) -> None:
        self.inbox = inbox
        self.username = username
        self.password = password
        self._inboxes = inboxes
        self.authenticated = False
        self.selected_mailbox: str | None = None
        self._tag_counter = 0
        self._idle_mode = False

    @staticmethod
    def _parse_flag(flag_str: str) -> str:
        r"""Extract flag from STORE flag argument.

        Handles both parenthesized (from imaplib.store) and bare
        (from imaplib.uid) formats:
        - ``(\Seen)`` → ``\Seen``
        - ``\Seen``   → ``\Seen``
        """
        return flag_str.strip().strip("()")

    def handle_command(
        self, tag: str, command: str, args: str
    ) -> list[str | bytes]:
        """Handle an IMAP command and return response lines."""
        command = command.upper()
        logger.debug("IMAP command: %s %s %s", tag, command, args)

        if command == "CAPABILITY":
            return [
                "* CAPABILITY IMAP4rev1 IDLE LOGIN",
                f"{tag} OK CAPABILITY completed",
            ]

        elif command == "LOGIN":
            parts = args.split(None, 1)
            if len(parts) >= 2:
                user = parts[0].strip('"')
                pwd = parts[1].strip('"')
                # Multi-inbox: authenticate any known user
                if (
                    self._inboxes
                    and user in self._inboxes
                    and pwd == self.password
                ):
                    self.inbox = self._inboxes[user]
                    self.authenticated = True
                    return [f"{tag} OK LOGIN completed"]
                elif user == self.username and pwd == self.password:
                    self.authenticated = True
                    return [f"{tag} OK LOGIN completed"]
            return [f"{tag} NO LOGIN failed"]

        elif command == "LOGOUT":
            return [
                "* BYE IMAP4rev1 Server logging out",
                f"{tag} OK LOGOUT completed",
            ]

        elif command == "SELECT":
            if not self.authenticated:
                return [f"{tag} NO Not authenticated"]
            mailbox = args.strip('"')
            self.selected_mailbox = mailbox
            count = self.inbox.count()
            return [
                f"* {count} EXISTS",
                "* 0 RECENT",
                "* FLAGS (\\Seen \\Deleted)",
                f"{tag} OK [READ-WRITE] SELECT completed",
            ]

        elif command == "SEARCH":
            if not self.selected_mailbox:
                return [f"{tag} NO No mailbox selected"]
            if "UNSEEN" in args.upper():
                # Non-UID SEARCH returns sequence numbers
                seq_nums = self.inbox.get_unseen_seq_nums()
                seq_str = " ".join(str(s) for s in seq_nums)
                return [
                    f"* SEARCH {seq_str}",
                    f"{tag} OK SEARCH completed",
                ]
            return [f"{tag} BAD Unsupported SEARCH criteria"]

        elif command == "FETCH":
            if not self.selected_mailbox:
                return [f"{tag} NO No mailbox selected"]
            parts = args.split(None, 1)
            if len(parts) < 2:
                return [f"{tag} BAD Invalid FETCH arguments"]
            seq_num = int(parts[0])
            fetch_items = parts[1]
            # Non-UID FETCH uses sequence numbers
            msg = self.inbox.get_message_by_seq(seq_num)
            if msg is None:
                return [f"{tag} NO Message not found"]

            if "RFC822" in fetch_items.upper():
                msg_bytes = msg.as_bytes()
                return [
                    f"* {seq_num} FETCH (RFC822 "
                    f"{{{len(msg_bytes)}}}\r\n".encode()
                    + msg_bytes
                    + b")\r\n",
                    f"{tag} OK FETCH completed",
                ]
            return [f"{tag} BAD Unsupported FETCH items"]

        elif command == "STORE":
            if not self.selected_mailbox:
                return [f"{tag} NO No mailbox selected"]
            parts = args.split(None, 2)
            if len(parts) < 3:
                return [f"{tag} BAD Invalid STORE arguments"]
            seq_num = int(parts[0])
            flag = self._parse_flag(parts[2])
            # Non-UID STORE uses sequence numbers
            if self.inbox.add_flag_by_seq(seq_num, flag):
                return [f"{tag} OK STORE completed"]
            return [f"{tag} NO Message not found"]

        elif command == "UID":
            # UID-prefixed commands use stable UIDs
            sub_parts = args.split(None, 1)
            if not sub_parts:
                return [f"{tag} BAD Missing UID sub-command"]
            sub_cmd = sub_parts[0].upper()
            sub_args = sub_parts[1] if len(sub_parts) > 1 else ""
            return self._handle_uid_command(tag, sub_cmd, sub_args)

        elif command == "EXPUNGE":
            if not self.selected_mailbox:
                return [f"{tag} NO No mailbox selected"]
            removed = self.inbox.expunge()
            responses: list[str | bytes] = [
                f"* {uid} EXPUNGE" for uid in removed
            ]
            responses.append(f"{tag} OK EXPUNGE completed")
            return responses

        elif command == "IDLE":
            self._idle_mode = True
            return ["+ idling"]

        elif command == "NOOP":
            return [f"{tag} OK NOOP completed"]

        else:
            return [f"{tag} BAD Unknown command {command}"]

    def _handle_uid_command(
        self, tag: str, command: str, args: str
    ) -> list[str | bytes]:
        """Handle UID-prefixed commands using stable UID lookups.

        Per RFC 3501 §6.4.8, a non-existent UID is silently ignored:
        UID FETCH returns OK with no data, UID STORE returns OK
        without performing any operations.
        """
        if command == "SEARCH":
            if not self.selected_mailbox:
                return [f"{tag} NO No mailbox selected"]
            if "UNSEEN" in args.upper():
                uids = self.inbox.get_unseen_uids()
                uid_str = " ".join(str(u) for u in uids)
                return [
                    f"* SEARCH {uid_str}",
                    f"{tag} OK SEARCH completed",
                ]
            return [f"{tag} BAD Unsupported SEARCH criteria"]

        elif command == "FETCH":
            if not self.selected_mailbox:
                return [f"{tag} NO No mailbox selected"]
            parts = args.split(None, 1)
            if len(parts) < 2:
                return [f"{tag} BAD Invalid FETCH arguments"]
            uid = int(parts[0])
            fetch_items = parts[1]
            msg = self.inbox.get_message(uid)
            # Non-existent UID → OK with no data (RFC 3501 §6.4.8)
            if msg is None:
                return [f"{tag} OK FETCH completed"]

            if "RFC822" in fetch_items.upper():
                msg_bytes = msg.as_bytes()
                return [
                    f"* {uid} FETCH (RFC822 {{{len(msg_bytes)}}}\r\n".encode()
                    + msg_bytes
                    + b")\r\n",
                    f"{tag} OK FETCH completed",
                ]
            return [f"{tag} BAD Unsupported FETCH items"]

        elif command == "STORE":
            if not self.selected_mailbox:
                return [f"{tag} NO No mailbox selected"]
            parts = args.split(None, 2)
            if len(parts) < 3:
                return [f"{tag} BAD Invalid STORE arguments"]
            uid = int(parts[0])
            flag = self._parse_flag(parts[2])
            # Non-existent UID → OK, no-op (RFC 3501 §6.4.8)
            self.inbox.add_flag(uid, flag)
            return [f"{tag} OK STORE completed"]

        else:
            return [f"{tag} BAD Unknown UID sub-command"]

    def handle_idle_done(self, tag: str) -> list[str]:
        """Handle DONE command to exit IDLE mode."""
        self._idle_mode = False
        return [f"{tag} OK IDLE terminated"]


_cached_ssl_context: ssl.SSLContext | None = None


def _get_ssl_context() -> ssl.SSLContext:
    """Return a cached self-signed SSL context for testing.

    Generates the certificate once per process and reuses it across
    all IMAP server instances.
    """
    global _cached_ssl_context  # noqa: PLW0603
    if _cached_ssl_context is not None:
        return _cached_ssl_context

    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = f"{tmpdir}/key.pem"
        cert_file = f"{tmpdir}/cert.pem"

        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_file,
                "-out",
                cert_file,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
        )

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)

    _cached_ssl_context = context
    return context


class MinimalIMAPServer:
    """Minimal IMAP4 server using asyncio.

    Handles SSL/TLS connections and routes commands to MinimalIMAPHandler.
    """

    def __init__(
        self,
        inbox: MailboxStore,
        username: str = "test",
        password: str = "test",
        inboxes: dict[str, MailboxStore] | None = None,
    ) -> None:
        self.inbox = inbox
        self.username = username
        self.password = password
        self._inboxes = inboxes
        self._server: asyncio.Server | None = None
        self._port: int | None = None
        self._ssl_context: ssl.SSLContext | None = None
        self._client_tasks: set[asyncio.Task[None]] = set()
        self._client_writers: set[asyncio.StreamWriter] = set()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single IMAP client connection."""
        handler = MinimalIMAPHandler(
            self.inbox, self.username, self.password, inboxes=self._inboxes
        )
        addr = writer.get_extra_info("peername")
        logger.debug("IMAP client connected from %s", addr)
        self._client_writers.add(writer)

        try:
            # Send greeting
            writer.write(b"* OK IMAP4rev1 Test Server Ready\r\n")
            await writer.drain()

            current_tag = ""
            while True:
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=60.0
                    )
                except TimeoutError:
                    break

                if not line:
                    break

                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue

                logger.debug("IMAP recv: %s", line_str)

                # Handle DONE in IDLE mode (no tag)
                if handler._idle_mode and line_str.upper() == "DONE":
                    responses = handler.handle_idle_done(current_tag)
                    for resp in responses:
                        writer.write(f"{resp}\r\n".encode())
                    await writer.drain()
                    continue

                # Parse tag and command
                parts = line_str.split(None, 2)
                if len(parts) < 2:
                    writer.write(b"* BAD Invalid command\r\n")
                    await writer.drain()
                    continue

                tag = parts[0]
                command = parts[1]
                args = parts[2] if len(parts) > 2 else ""

                current_tag = tag
                responses = handler.handle_command(tag, command, args)

                for resp in responses:
                    if isinstance(resp, bytes):
                        writer.write(resp)
                    else:
                        writer.write(f"{resp}\r\n".encode())
                await writer.drain()

                # Handle LOGOUT
                if command.upper() == "LOGOUT":
                    break

                # Handle IDLE - need to watch for new messages
                if command.upper() == "IDLE":
                    # Wait for new message or timeout
                    try:
                        while handler._idle_mode:
                            # Check for DONE command with short timeout
                            try:
                                done_line = await asyncio.wait_for(
                                    reader.readline(), timeout=1.0
                                )
                                if done_line:
                                    done_str = done_line.decode().strip()
                                    if done_str.upper() == "DONE":
                                        responses = handler.handle_idle_done(
                                            current_tag
                                        )
                                        for resp in responses:
                                            writer.write(f"{resp}\r\n".encode())
                                        await writer.drain()
                                        break
                            except TimeoutError:
                                # Could send EXISTS notification here
                                pass
                    except Exception as e:
                        logger.debug("IDLE loop error: %s", e)
                        break

        except (Exception, asyncio.CancelledError) as e:
            logger.debug("IMAP client error/cancelled for %s: %s", addr, e)
        finally:
            self._client_writers.discard(writer)
            try:
                if not writer.is_closing():
                    writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (Exception, asyncio.CancelledError):
                pass
            logger.debug("IMAP client disconnected from %s", addr)

    async def _track_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Wrap _handle_client in a tracked task for clean shutdown."""
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
            task.add_done_callback(self._client_tasks.discard)
        await self._handle_client(reader, writer)

    async def start(self) -> int:
        """Start the IMAP server and return the port number."""
        self._ssl_context = _get_ssl_context()

        # Find a free port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self._port = sock.getsockname()[1]
        sock.close()

        self._server = await asyncio.start_server(
            self._track_client,
            "127.0.0.1",
            self._port,
            ssl=self._ssl_context,
        )

        logger.info("IMAP server started on port %d", self._port)
        return self._port

    async def stop(self) -> None:
        """Stop the IMAP server."""
        if self._server:
            self._server.close()
            # Abort all client transports immediately.  writer.close()
            # initiates an SSL shutdown that hangs when the peer has
            # already raw-closed the socket.  transport.abort() tears
            # down the connection without waiting for the handshake.
            for writer in list(self._client_writers):
                transport = writer.transport
                if transport is not None:
                    transport.abort()
            # Cancel client tasks and wait for cleanup.
            tasks = set(self._client_tasks)
            for task in tasks:
                task.cancel()
            if tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=2.0,
                    )
                except TimeoutError:
                    logger.debug("Timed out waiting for client tasks to cancel")
            self._client_tasks.clear()
            self._client_writers.clear()
            # In Python 3.12+, wait_closed() blocks until all active
            # connections are fully closed — safe now that we closed
            # them above.
            await self._server.wait_closed()
            logger.info("IMAP server stopped")


class TestEmailServer:
    """Combined SMTP/IMAP test server.

    Provides:
    - SMTP server for receiving outgoing mail (service responses)
    - IMAP server for serving incoming mail (to be processed by service)

    The servers share a mailbox model where:
    - inbox: Messages injected by tests, served via IMAP
    - outbox: Messages sent via SMTP, retrieved by tests
    """

    def __init__(self, username: str = "test", password: str = "test") -> None:
        self._inbox = MailboxStore()
        self._outbox = MailboxStore()
        self._username = username
        self._password = password

        # Multi-inbox support: maps username -> MailboxStore
        self._inboxes: dict[str, MailboxStore] = {}

        self._smtp_handler = TestSMTPHandler(self._outbox)
        self._smtp_controller: Controller | None = None
        self._imap_server: MinimalIMAPServer | None = None

        self._smtp_port: int | None = None
        self._imap_port: int | None = None

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    @property
    def smtp_port(self) -> int:
        """Get the SMTP server port."""
        if self._smtp_port is None:
            raise RuntimeError("Server not started")
        return self._smtp_port

    @property
    def imap_port(self) -> int:
        """Get the IMAP server port."""
        if self._imap_port is None:
            raise RuntimeError("Server not started")
        return self._imap_port

    def start(self) -> tuple[int, int]:
        """Start the email servers synchronously.

        Returns:
            Tuple of (smtp_port, imap_port).
        """
        # Find a free port for SMTP first
        # We can't use port=0 with aiosmtpd Controller because its
        # _trigger_server method uses self.port (0) instead of the actual port
        smtp_port = find_free_port()

        # Start SMTP server (aiosmtpd handles its own thread)
        self._smtp_controller = Controller(
            self._smtp_handler,
            hostname="127.0.0.1",
            port=smtp_port,
        )
        self._smtp_controller.start()
        self._smtp_port = smtp_port
        logger.info("SMTP server started on port %d", self._smtp_port)

        # Start IMAP server in a background thread with its own event loop
        self._imap_server = MinimalIMAPServer(
            self._inbox,
            self._username,
            self._password,
            inboxes=self._inboxes,
        )

        started = threading.Event()
        imap_port_holder: list[int] = []

        def run_imap():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            async def start_and_signal():
                assert self._imap_server is not None
                port = await self._imap_server.start()
                imap_port_holder.append(port)
                started.set()
                # Keep running until stopped
                try:
                    while True:
                        await asyncio.sleep(1)
                except asyncio.CancelledError:
                    pass

            try:
                self._loop.run_until_complete(start_and_signal())
            except Exception as e:
                logger.debug("IMAP event loop stopped: %s", e)
            finally:
                # Cancel any remaining tasks to prevent
                # "Task was destroyed but it is pending!" warnings
                pending = asyncio.all_tasks(self._loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self._loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                # Close the loop here (in its owning thread) to avoid
                # a race where stop() calls loop.close() while this
                # thread is still draining tasks.
                self._loop.close()

        self._thread = threading.Thread(target=run_imap, daemon=True)
        self._thread.start()

        # Wait for IMAP server to start
        started.wait(timeout=10.0)
        if imap_port_holder:
            self._imap_port = imap_port_holder[0]
        else:
            raise RuntimeError("IMAP server failed to start")

        logger.info(
            "Test email server started: SMTP=%d, IMAP=%d",
            self._smtp_port,
            self._imap_port,
        )
        return self._smtp_port, self._imap_port

    def stop(self) -> None:
        """Stop the email servers."""
        if self._smtp_controller:
            self._smtp_controller.stop()
            logger.info("SMTP server stopped")

        loop = self._loop
        if loop and self._imap_server:
            # Schedule IMAP server stop
            imap_server = self._imap_server

            async def stop_imap():
                await imap_server.stop()

            future = asyncio.run_coroutine_threadsafe(stop_imap(), loop)
            try:
                future.result(timeout=5.0)
            except Exception as e:
                logger.warning("IMAP server stop failed: %s", e)
                future.cancel()

            # Stop the event loop
            loop.call_soon_threadsafe(loop.stop)

        if self._thread:
            self._thread.join(timeout=5.0)

        logger.info("Test email server stopped")

    def add_inbox(self, username: str) -> None:
        """Register an additional inbox for multi-repo testing.

        Can be called before or after start(). Each inbox is isolated
        and accessible via inject_message_to().

        Args:
            username: IMAP username for this inbox.
        """
        self._inboxes[username] = MailboxStore()

    def inject_message(self, msg: EmailMessage) -> int:
        """Add a message to the default INBOX (simulates external sender).

        Returns:
            The UID assigned to the message.
        """
        return self._inbox.add_message(msg)

    def inject_message_to(self, username: str, msg: EmailMessage) -> int:
        """Add a message to a specific user's inbox.

        Args:
            username: IMAP username whose inbox receives the message.
            msg: Email message to inject.

        Returns:
            The UID assigned to the message.

        Raises:
            KeyError: If username has no registered inbox.
        """
        return self._inboxes[username].add_message(msg)

    def get_sent_messages(self) -> list[EmailMessage]:
        """Get all messages sent via SMTP."""
        return self._outbox.get_all_messages()

    def wait_for_sent(
        self,
        predicate: Callable[[EmailMessage], bool] | None = None,
        timeout: float = 30.0,
    ) -> EmailMessage | None:
        """Wait for a sent message matching the predicate.

        Args:
            predicate: Function to match messages. If None, matches any message.
            timeout: Maximum time to wait in seconds.

        Returns:
            The first matching message, or None if timeout.
        """
        deadline = time.monotonic() + timeout
        while True:
            messages = self.get_sent_messages()
            for msg in messages:
                if predicate is None or predicate(msg):
                    return msg
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            # Block until a new message arrives or timeout
            self._outbox._new_message_event.clear()
            self._outbox._new_message_event.wait(timeout=min(remaining, 0.03))

    def clear_outbox(self) -> None:
        """Clear all sent messages from the outbox."""
        self._outbox._messages.clear()

    def wait_until_inbox_empty(
        self,
        timeout: float = 10.0,
        inbox_name: str | None = None,
    ) -> bool:
        """Wait until the inbox has no unprocessed messages.

        Args:
            timeout: Maximum time to wait in seconds.
            inbox_name: Named inbox to check. If None, checks default inbox.

        Returns:
            True if inbox became empty, False if timeout.
        """
        inbox = self._inboxes[inbox_name] if inbox_name else self._inbox
        deadline = time.monotonic() + timeout
        while True:
            if inbox.count() == 0:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(remaining, 0.05))
