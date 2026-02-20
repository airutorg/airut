# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""In-process fake Slack backend for integration tests.

Provides ``TestSlackServer`` which replaces real Slack infrastructure
with in-memory fakes.  Provides:

- ``FakeWebClient``: records all Slack API calls and returns canned
  responses for ``chat.postMessage``, ``users.info``, etc.
- ``FakeSocketModeHandler``: captures the Bolt ``App`` on
  ``connect()`` and exposes ``inject_user_message()`` to simulate
  incoming Slack events.
- ``TestSlackServer``: orchestrates fakes and exposes assertion
  helpers (``wait_for_sent()``, ``get_sent_messages()``).

Design mirrors ``email_server.py``: inject messages via
``inject_user_message()``, assert on outbound messages via
``wait_for_sent()``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock


logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data types
# ------------------------------------------------------------------


@dataclass
class SentSlackMessage:
    """A recorded outbound Slack API call."""

    method: str
    """API method name (``chat_postMessage``, etc.)."""

    kwargs: dict[str, Any]
    """Keyword arguments passed to the API method."""


@dataclass
class RegisteredUser:
    """Fake Slack user info for authorization testing."""

    user_id: str
    team_id: str = "T_TEST_TEAM"
    is_bot: bool = False
    is_restricted: bool = False
    is_ultra_restricted: bool = False
    deleted: bool = False
    display_name: str = ""


# ------------------------------------------------------------------
# Fake WebClient (duck-typed, not subclassed)
# ------------------------------------------------------------------


class FakeWebClient:
    """WebClient replacement that records API calls in memory.

    Duck-typed to match the subset of ``slack_sdk.WebClient`` used
    by ``SlackChannelAdapter``, ``SlackAuthorizer``, and
    ``SlackPlanStreamer``.  Does *not* subclass ``WebClient`` to
    avoid triggering real HTTP initialization.
    """

    def __init__(
        self,
        server: TestSlackServer,
        token: str = "xoxb-fake-token",
    ) -> None:
        self.token = token
        self._server = server

    # -- chat.postMessage -----------------------------------------------

    def chat_postMessage(self, **kwargs: Any) -> MagicMock:  # noqa: N802
        """Record a chat.postMessage call."""
        self._server._record_sent(
            SentSlackMessage(method="chat_postMessage", kwargs=kwargs)
        )
        resp = MagicMock()
        resp.data = {"ok": True, "ts": str(time.time())}
        return resp

    # -- files_upload_v2 ------------------------------------------------

    def files_upload_v2(self, **kwargs: Any) -> MagicMock:
        """Record a files_upload_v2 call."""
        file_path = kwargs.get("file")
        if file_path and Path(file_path).exists():
            kwargs["_file_content"] = Path(file_path).read_bytes()
        self._server._record_sent(
            SentSlackMessage(method="files_upload_v2", kwargs=kwargs)
        )
        resp = MagicMock()
        resp.data = {"ok": True}
        return resp

    # -- assistant_threads_setTitle -------------------------------------

    def assistant_threads_setTitle(self, **kwargs: Any) -> MagicMock:  # noqa: N802
        """Record a setTitle call."""
        self._server._record_sent(
            SentSlackMessage(
                method="assistant_threads_setTitle",
                kwargs=kwargs,
            )
        )
        resp = MagicMock()
        resp.data = {"ok": True}
        return resp

    # -- users.info -----------------------------------------------------

    def users_info(self, **kwargs: Any) -> dict[str, Any]:
        """Return canned user info from registered users."""
        user_id = kwargs.get("user", "")
        user = self._server.get_registered_user(user_id)
        if user is None:
            from slack_sdk.errors import SlackApiError

            resp = MagicMock()
            resp.status_code = 200
            resp.data = {
                "ok": False,
                "error": "user_not_found",
            }
            raise SlackApiError("user_not_found", resp)
        return {
            "ok": True,
            "user": {
                "id": user.user_id,
                "team_id": user.team_id,
                "is_bot": user.is_bot,
                "is_restricted": user.is_restricted,
                "is_ultra_restricted": user.is_ultra_restricted,
                "deleted": user.deleted,
                "name": user.display_name or user.user_id,
                "profile": {
                    "display_name": user.display_name,
                    "real_name": (user.display_name or user.user_id),
                },
            },
        }

    # -- auth.test ------------------------------------------------------

    def auth_test(self, **kwargs: Any) -> dict[str, Any]:
        """Return workspace team ID."""
        return {
            "ok": True,
            "team_id": self._server.workspace_team_id,
            "user_id": "U_BOT",
        }

    # -- chat.update (for plan streamer) --------------------------------

    def chat_update(self, **kwargs: Any) -> MagicMock:  # noqa: N802
        """Record a chat.update call (used by plan streamer)."""
        self._server._record_sent(
            SentSlackMessage(method="chat_update", kwargs=kwargs)
        )
        resp = MagicMock()
        resp.data = {"ok": True, "ts": kwargs.get("ts", str(time.time()))}
        return resp


# ------------------------------------------------------------------
# Fake SocketModeHandler
# ------------------------------------------------------------------


class FakeSocketModeHandler:
    """SocketModeHandler replacement.

    Exposes a ``client`` attribute with ``on_close_listeners`` and
    ``on_error_listeners`` so the listener can install health
    listeners without errors.
    """

    def __init__(self, app: Any, app_token: str = "") -> None:
        self.app = app
        self.app_token = app_token
        self.client = MagicMock()
        self.client.on_close_listeners = []
        self.client.on_error_listeners = []
        self._connected = False

    def connect(self) -> None:
        """Mark as connected (no real WebSocket)."""
        self._connected = True

    def close(self) -> None:
        """Mark as disconnected."""
        self._connected = False

    @property
    def connected(self) -> bool:
        """Whether the handler is connected."""
        return self._connected


# ------------------------------------------------------------------
# TestSlackServer
# ------------------------------------------------------------------


@dataclass
class _FileServer:
    """Simple file server for attachment downloads."""

    files: dict[str, bytes] = field(default_factory=dict)


class TestSlackServer:
    """In-process fake Slack backend.

    Provides the same inject/wait pattern as ``TestEmailServer``:

    1. Register users with ``register_user()``.
    2. Start via ``start()``.
    3. Inject messages via ``inject_user_message()``.
    4. Wait for replies via ``wait_for_sent()``.
    5. Stop via ``stop()``.
    """

    def __init__(
        self,
        workspace_team_id: str = "T_TEST_TEAM",
    ) -> None:
        self.workspace_team_id = workspace_team_id

        self._users: dict[str, RegisteredUser] = {}
        self._sent: list[SentSlackMessage] = []
        self._lock = threading.Lock()
        self._new_message_event = threading.Event()
        self._file_server = _FileServer()

        self._web_client: FakeWebClient | None = None
        self._handler: FakeSocketModeHandler | None = None

        # Submit callback set by listener.start()
        self._submit_callback: Callable[[Any], bool] | None = None
        self._ready_event = threading.Event()

    def start(self) -> None:
        """Initialize the fake Slack backend."""
        self._web_client = FakeWebClient(
            server=self, token="xoxb-fake-bot-token"
        )
        self._handler = FakeSocketModeHandler(
            app=None, app_token="xapp-fake-app-token"
        )
        logger.info("TestSlackServer started")

    def stop(self) -> None:
        """Tear down the fake Slack backend."""
        if self._handler and self._handler.connected:
            self._handler.close()
        logger.info("TestSlackServer stopped")

    @property
    def web_client(self) -> FakeWebClient:
        """Fake WebClient for injection into adapters."""
        assert self._web_client is not None
        return self._web_client

    @property
    def handler(self) -> FakeSocketModeHandler:
        """Fake SocketModeHandler for injection."""
        assert self._handler is not None
        return self._handler

    # -- User registration ----------------------------------------------

    def register_user(
        self,
        user_id: str,
        display_name: str = "",
        team_id: str | None = None,
        is_bot: bool = False,
        is_restricted: bool = False,
        is_ultra_restricted: bool = False,
        deleted: bool = False,
    ) -> None:
        """Register a fake user for authorization checks."""
        self._users[user_id] = RegisteredUser(
            user_id=user_id,
            team_id=team_id or self.workspace_team_id,
            is_bot=is_bot,
            is_restricted=is_restricted,
            is_ultra_restricted=is_ultra_restricted,
            deleted=deleted,
            display_name=display_name,
        )

    def get_registered_user(self, user_id: str) -> RegisteredUser | None:
        """Look up a registered user by ID."""
        return self._users.get(user_id)

    # -- File hosting for attachments -----------------------------------

    def host_file(self, url: str, content: bytes) -> None:
        """Make file available for download by adapter."""
        self._file_server.files[url] = content

    # -- Message injection ----------------------------------------------

    def set_submit_callback(self, callback: Callable[[Any], bool]) -> None:
        """Set submit callback (called by listener.start)."""
        self._submit_callback = callback
        self._ready_event.set()

    def wait_for_ready(self, timeout: float = 15.0) -> None:
        """Block until the submit callback is registered.

        Call this after starting the service but before injecting
        messages, to avoid the race where ``inject_user_message``
        is called before the listener has started.
        """
        if not self._ready_event.wait(timeout=timeout):
            raise TimeoutError(
                f"Slack listener did not start within {timeout}s"
            )

    def inject_user_message(
        self,
        user_id: str,
        text: str,
        channel_id: str = "D_TEST_DM",
        thread_ts: str | None = None,
        files: list[dict[str, str]] | None = None,
    ) -> None:
        """Simulate a Slack user message event.

        Builds a ``RawMessage`` and calls the ``submit`` callback.
        """
        from airut.gateway.channel import RawMessage

        if thread_ts is None:
            thread_ts = str(time.time())

        payload: dict[str, Any] = {
            "user": user_id,
            "text": text,
            "channel": channel_id,
            "thread_ts": thread_ts,
        }

        if files:
            payload["files"] = files

        display_title = text[:60].split("\n")[0] if text else ""

        raw: RawMessage[dict[str, Any]] = RawMessage(
            sender=user_id,
            content=payload,
            display_title=display_title,
        )

        if self._submit_callback is not None:
            self._submit_callback(raw)
        else:
            raise RuntimeError(
                "No submit callback registered. Call wait_for_ready() first."
            )

    # -- Outbound message recording -------------------------------------

    def _record_sent(self, msg: SentSlackMessage) -> None:
        """Record an outbound API call (thread-safe)."""
        with self._lock:
            self._sent.append(msg)
            self._new_message_event.set()

    def get_sent_messages(
        self,
        method: str | None = None,
    ) -> list[SentSlackMessage]:
        """Return all recorded outbound messages."""
        with self._lock:
            msgs = list(self._sent)
        if method:
            msgs = [m for m in msgs if m.method == method]
        return msgs

    def wait_for_sent(
        self,
        predicate: (Callable[[SentSlackMessage], bool] | None) = None,
        timeout: float = 30.0,
        method: str | None = None,
    ) -> SentSlackMessage | None:
        """Wait for an outbound message matching predicate."""
        deadline = time.monotonic() + timeout
        while True:
            msgs = self.get_sent_messages(method=method)
            for msg in msgs:
                if predicate is None or predicate(msg):
                    return msg

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None

            with self._lock:
                self._new_message_event.clear()
            self._new_message_event.wait(timeout=min(remaining, 1.0))

    def clear_sent(self) -> None:
        """Clear all recorded sent messages."""
        with self._lock:
            self._sent.clear()
            self._new_message_event.clear()
            self._ready_event.clear()

    def get_posted_texts(self) -> list[str]:
        """Convenience: all text from chat.postMessage."""
        msgs = self.get_sent_messages(method="chat_postMessage")
        texts: list[str] = []
        for m in msgs:
            text = m.kwargs.get("text", "")
            if text:
                texts.append(text)
            blocks = m.kwargs.get("blocks", [])
            for block in blocks:
                if isinstance(block, dict) and "text" in block:
                    block_text = block["text"]
                    if isinstance(block_text, dict):
                        texts.append(block_text.get("text", ""))
                    else:
                        texts.append(block_text)
        return texts
