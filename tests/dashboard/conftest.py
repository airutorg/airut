# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared fixtures and helpers for dashboard tests."""

import json
from pathlib import Path
from typing import Any

import pytest
from werkzeug.test import Client

from lib.claude_output import StreamEvent, parse_stream_events
from lib.container.session import SessionStore
from lib.dashboard.server import DashboardServer
from lib.dashboard.tracker import TaskTracker


def parse_events(*raw_events: dict[str, Any]) -> list[StreamEvent]:
    """Parse raw event dicts into typed StreamEvent objects."""
    return parse_stream_events("\n".join(json.dumps(e) for e in raw_events))


# ── Minimal event builders ───────────────────────────────────────────


def result_event(**overrides: Any) -> dict[str, Any]:
    """Build a minimal result event dict, with sane defaults.

    Any key can be overridden via keyword arguments.
    """
    base: dict[str, Any] = {
        "type": "result",
        "subtype": "success",
        "session_id": "sess_123",
        "duration_ms": 1000,
        "total_cost_usd": 0.01,
        "num_turns": 1,
        "is_error": False,
        "usage": {},
    }
    base.update(overrides)
    return base


# ── Dashboard test harness ───────────────────────────────────────────


class DashboardHarness:
    """Encapsulates the common setup for dashboard endpoint tests.

    Creates a tracker, conversation directory, session store, server,
    and werkzeug test client — the boilerplate that every test repeats.

    Usage::

        h = DashboardHarness(tmp_path)
        h.add_events(
            {"type": "system", "subtype": "init"},
            result_event(),
        )
        html = h.get_html("/conversation/abc12345/actions")
        assert "Reply #1" in html
    """

    CONV_ID = "abc12345"
    SUBJECT = "Test Subject"

    def __init__(
        self,
        tmp_path: Path,
        *,
        add_task: bool = True,
        stop_callback: Any = None,
    ) -> None:
        self.tmp_path = tmp_path
        self.tracker = TaskTracker()
        self.conv_dir = tmp_path / self.CONV_ID
        self.conv_dir.mkdir()
        self.store = SessionStore(self.conv_dir)

        if add_task:
            self.tracker.add_task(self.CONV_ID, self.SUBJECT)

        self._server: DashboardServer | None = None
        self._client: Client | None = None
        self._stop_callback = stop_callback

    @property
    def server(self) -> DashboardServer:
        if self._server is None:
            self._server = DashboardServer(
                self.tracker,
                work_dirs=lambda: [self.tmp_path],
                stop_callback=self._stop_callback,
            )
        return self._server

    @property
    def client(self) -> Client:
        if self._client is None:
            self._client = Client(self.server._wsgi_app)
        return self._client

    def add_events(
        self,
        *raw_events: dict[str, Any],
        request_text: str | None = None,
    ) -> None:
        """Parse raw event dicts and add them as a session reply."""
        events = parse_events(*raw_events)
        self.store.add_reply(
            self.CONV_ID,
            events,
            request_text=request_text,
        )

    def write_log(self, content: str) -> Path:
        """Write network log content to the conversation directory."""
        log_path = self.conv_dir / "network-sandbox.log"
        log_path.write_text(content)
        return log_path

    def get_html(self, path: str) -> str:
        """GET a path and return the response body as text."""
        response = self.client.get(path)
        assert response.status_code == 200
        return response.get_data(as_text=True)


@pytest.fixture
def harness(tmp_path: Path) -> DashboardHarness:
    """Pre-built dashboard harness with task and conversation directory."""
    return DashboardHarness(tmp_path)
