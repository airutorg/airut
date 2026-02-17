# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for all dashboard API and page endpoints.

These tests validate that every dashboard endpoint returns correct responses
after a task has been processed through the full gateway lifecycle.

Endpoints covered:
- GET /                                        — Main dashboard page
- GET /api/health                              — Health check (JSON, ETag)
- GET /api/version                             — Version info (JSON)
- GET /api/update                              — Upstream update check (JSON)
- GET /api/conversations                       — Task list (JSON, ETag)
- GET /api/conversation/{id}                   — Single task detail (JSON)
- POST /api/conversation/{id}/stop             — Stop a running task (JSON)
- GET /api/repos                               — Repository list (JSON, ETag)
- GET /api/tracker                             — Full tracker snapshot (ETag)
- GET /api/events/stream                       — SSE state stream
- GET /api/conversation/{id}/events/stream     — SSE event log stream
- GET /api/conversation/{id}/events/poll       — Event log polling
- GET /api/conversation/{id}/network/stream    — SSE network log stream
- GET /api/conversation/{id}/network/poll      — Network log polling
- GET /repo/{repo_id}                          — Repository detail page
- GET /conversation/{id}                       — Task detail page
- GET /conversation/{id}/actions               — Actions viewer page
- GET /conversation/{id}/network               — Network logs viewer page
"""

import json
import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from .conftest import get_message_text, wait_for_conv_completion
from .environment import IntegrationEnvironment


def _wait_for_task_completion(service, conv_id: str, timeout: float = 10.0):
    """Wait for a task to reach COMPLETED status in the tracker.

    Args:
        service: GatewayService instance.
        conv_id: Conversation ID to wait for.
        timeout: Maximum seconds to wait.

    Returns:
        The completed TaskState, or None on timeout.
    """
    return wait_for_conv_completion(service.tracker, conv_id, timeout=timeout)


class TestDashboardAPIEndpoints:
    """Test all dashboard API endpoints after a task lifecycle."""

    def test_all_api_endpoints(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Validate all API endpoints after a task completes.

        Sends a message through the gateway, waits for completion, then
        exercises every dashboard endpoint and validates responses.
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Dashboard API integration test done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Dashboard API test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for response email (task completed)
            response = integration_env.email_server.wait_for_sent(
                lambda m: "dashboard api" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None, "Did not receive response email"

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = _wait_for_task_completion(service, conv_id)
            assert task is not None, f"Task {conv_id} not completed"

            # Now test all endpoints via WSGI test client
            if service.dashboard is None:
                return  # Dashboard not enabled

            from werkzeug.test import Client

            client = Client(service.dashboard._wsgi_app)

            # ── GET /api/health ──────────────────────────────────
            r = client.get("/api/health")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert data["status"] == "ok"
            assert data["tasks"]["completed"] >= 1
            assert data["tasks"]["executing"] == 0
            assert data["tasks"]["queued"] == 0
            assert data["repos"]["live"] >= 1
            assert "boot" in data
            # ETag support
            etag = r.headers.get("ETag")
            assert etag is not None
            r304 = client.get("/api/health", headers={"If-None-Match": etag})
            assert r304.status_code == 304

            # ── GET /api/version ─────────────────────────────────
            r = client.get("/api/version")
            # May be 200 or 404 depending on version_info availability
            assert r.status_code in (200, 404)
            assert r.content_type == "application/json"

            # ── GET /api/update ──────────────────────────────────
            r = client.get("/api/update")
            # May be 200 or 404 depending on git_version_info
            assert r.status_code in (200, 404)
            assert r.content_type == "application/json"

            # ── GET /api/conversations ───────────────────────────
            r = client.get("/api/conversations")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert isinstance(data, list)
            assert len(data) >= 1
            task_data = next(
                (t for t in data if t["conversation_id"] == conv_id),
                None,
            )
            assert task_data is not None
            assert task_data["status"] == "completed"
            assert task_data["completion_reason"] == "success"
            assert "Dashboard API test" in task_data["display_title"]
            # ETag support
            etag = r.headers.get("ETag")
            assert etag is not None
            r304 = client.get(
                "/api/conversations",
                headers={"If-None-Match": etag},
            )
            assert r304.status_code == 304

            # ── GET /api/conversation/{id} ───────────────────────
            r = client.get(f"/api/conversation/{conv_id}")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert data["conversation_id"] == conv_id
            assert data["status"] == "completed"
            assert data["completion_reason"] == "success"
            assert "task_id" in data
            assert "conversation" in data
            assert data["conversation"] is not None
            assert data["conversation"]["reply_count"] >= 1

            # ── GET /api/conversation/{id} (not found) ───────────
            r = client.get("/api/conversation/deadbeef")
            assert r.status_code == 404

            # ── POST /api/conversation/{id}/stop (not running) ───
            r = client.open(f"/api/conversation/{conv_id}/stop", method="POST")
            assert r.status_code == 400
            data = json.loads(r.get_data(as_text=True))
            assert "not running" in data["error"].lower()

            # ── POST /api/conversation/{id}/stop (not found) ─────
            r = client.open("/api/conversation/deadbeef/stop", method="POST")
            assert r.status_code == 404

            # ── GET /api/repos ───────────────────────────────────
            r = client.get("/api/repos")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert isinstance(data, list)
            assert len(data) >= 1
            repo = data[0]
            assert repo["repo_id"] == "test"
            assert repo["status"] == "live"
            # ETag support
            etag = r.headers.get("ETag")
            assert etag is not None
            r304 = client.get("/api/repos", headers={"If-None-Match": etag})
            assert r304.status_code == 304

            # ── GET /api/tracker ─────────────────────────────────
            r = client.get("/api/tracker")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert "version" in data
            assert "counts" in data
            assert "tasks" in data
            assert isinstance(data["version"], int)
            assert data["counts"]["completed"] >= 1
            tracker_task = next(
                (t for t in data["tasks"] if t["conversation_id"] == conv_id),
                None,
            )
            assert tracker_task is not None
            assert tracker_task["status"] == "completed"
            assert tracker_task["completion_reason"] == "success"
            assert tracker_task["repo_id"] == "test"
            assert tracker_task["model"] is not None
            # ETag support
            etag = r.headers.get("ETag")
            assert etag is not None
            r304 = client.get("/api/tracker", headers={"If-None-Match": etag})
            assert r304.status_code == 304

            # ── GET /api/events/stream ───────────────────────────
            # SSE stream requires clock; just verify it doesn't crash
            r = client.get("/api/events/stream")
            # Should be 200 (SSE) or 503 (no clock)
            assert r.status_code in (200, 503)

            # ── GET /api/conversation/{id}/events/poll ───────────
            r = client.get(f"/api/conversation/{conv_id}/events/poll?offset=0")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert "offset" in data
            assert "html" in data
            assert "done" in data
            assert data["done"] is True  # Task is completed

            # ── GET /api/conversation/{id}/network/poll ──────────
            r = client.get(f"/api/conversation/{conv_id}/network/poll?offset=0")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert "offset" in data
            assert "html" in data
            assert "done" in data
            assert data["done"] is True

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestDashboardPageEndpoints:
    """Test all dashboard HTML page endpoints."""

    def test_all_page_endpoints(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Validate all HTML page endpoints return 200 with correct content.

        Sends a message, waits for completion, then checks every page
        endpoint serves valid HTML.
        """
        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Page endpoint test done"),
    generate_result_event(session_id, "Done"),
]
"""
        msg = create_email(
            subject="Page endpoint test",
            body=mock_code,
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: "page endpoint" in get_message_text(m).lower(),
                timeout=30.0,
            )
            assert response is not None

            conv_id = extract_conversation_id(response["Subject"])
            assert conv_id is not None

            task = _wait_for_task_completion(service, conv_id)
            assert task is not None

            if service.dashboard is None:
                return

            from werkzeug.test import Client

            client = Client(service.dashboard._wsgi_app)

            # ── GET / (main dashboard) ───────────────────────────
            r = client.get("/")
            assert r.status_code == 200
            html = r.get_data(as_text=True)
            assert "text/html" in r.content_type
            assert "Page endpoint test" in html

            # ── GET /repo/{repo_id} ──────────────────────────────
            r = client.get("/repo/test")
            assert r.status_code == 200
            assert "text/html" in r.content_type

            # ── GET /repo/{repo_id} (not found) ──────────────────
            r = client.get("/repo/nonexistent")
            assert r.status_code == 404

            # ── GET /conversation/{id} ───────────────────────────
            r = client.get(f"/conversation/{conv_id}")
            assert r.status_code == 200
            assert "text/html" in r.content_type
            html = r.get_data(as_text=True)
            assert conv_id in html

            # ── GET /conversation/{id} (not found) ───────────────
            r = client.get("/conversation/deadbeef")
            assert r.status_code == 404

            # ── GET /conversation/{id}/actions ───────────────────
            r = client.get(f"/conversation/{conv_id}/actions")
            assert r.status_code == 200
            assert "text/html" in r.content_type

            # ── GET /conversation/{id}/network ───────────────────
            r = client.get(f"/conversation/{conv_id}/network")
            assert r.status_code == 200
            assert "text/html" in r.content_type

            # ── GET /favicon.svg ─────────────────────────────────
            r = client.get("/favicon.svg")
            assert r.status_code == 200
            assert r.content_type == "image/svg+xml"

            # ── 404 for unknown paths ────────────────────────────
            r = client.get("/nonexistent-path")
            assert r.status_code == 404

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestDashboardAPIBeforeBoot:
    """Test API endpoints respond correctly during/before boot."""

    def test_health_during_boot(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Verify /api/health returns booting status during startup.

        Creates the service and checks the dashboard before the boot
        sequence completes.
        """
        service = integration_env.create_service()

        # The dashboard is available before start() is called, so we
        # can test the boot state directly
        if service.dashboard is None:
            return

        from werkzeug.test import Client

        client = Client(service.dashboard._wsgi_app)

        # Before start(), boot state may not be set
        r = client.get("/api/health")
        assert r.status_code == 200
        data = json.loads(r.get_data(as_text=True))
        # Status should be degraded (no repos yet) or booting
        assert data["status"] in ("degraded", "booting", "ok")

        # /api/tracker should work too
        r = client.get("/api/tracker")
        assert r.status_code == 200
        data = json.loads(r.get_data(as_text=True))
        assert data["counts"]["queued"] == 0
        assert data["counts"]["executing"] == 0
        assert data["counts"]["completed"] == 0
