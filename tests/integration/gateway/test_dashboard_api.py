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
- GET /api/task/{task_id}                      — Task detail by ID (JSON)
- POST /api/conversation/{id}/stop             — Stop a running task (JSON)
- GET /api/repos                               — Repository list (JSON, ETag)
- GET /api/tracker                             — Full tracker snapshot (ETag)
- GET /api/events/stream                       — SSE state stream
- GET /api/conversation/{id}/events/stream     — SSE event log stream
- GET /api/conversation/{id}/events/poll       — Event log polling
- GET /api/conversation/{id}/network/stream    — SSE network log stream
- GET /api/conversation/{id}/network/poll      — Network log polling
- GET /repo/{repo_id}                          — Repository detail page
- GET /task/{task_id}                          — Task detail page (by ID)
- GET /conversation/{id}                       — Conversation overview page
- GET /conversation/{id}/actions               — Actions viewer page
- GET /conversation/{id}/network               — Network logs viewer page
"""

import json
import sys
import threading
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.config.source import YamlConfigSource
from airut.dashboard.tracker import RepoStatus
from airut.gateway.config import ServerConfig
from airut.gateway.service import GatewayService

from .conftest import get_message_text, wait_for_conv_completion, wait_for_task
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
            # Security headers on every response
            assert r.headers["X-Content-Type-Options"] == "nosniff"
            assert r.headers["X-Frame-Options"] == "DENY"
            assert "default-src 'self'" in r.headers["Content-Security-Policy"]
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
            task_id = data["task_id"]
            assert "conversation" in data
            assert data["conversation"] is not None
            assert data["conversation"]["reply_count"] >= 1
            # New fields from task-centric navigation
            assert data["repo_id"] == "test"
            assert data["reply_index"] == 0  # First task in conversation

            # ── GET /api/conversation/{id} (not found) ───────────
            r = client.get("/api/conversation/deadbeef")
            assert r.status_code == 404

            # ── GET /api/task/{task_id} ───────────────────────────
            r = client.get(f"/api/task/{task_id}")
            assert r.status_code == 200
            assert r.content_type == "application/json"
            data = json.loads(r.get_data(as_text=True))
            assert data["task_id"] == task_id
            assert data["conversation_id"] == conv_id
            assert data["status"] == "completed"
            assert data["reply_index"] == 0
            assert data["repo_id"] == "test"

            # ── GET /api/task/{task_id} (not found) ───────────────
            r = client.get("/api/task/nonexistent-task-id")
            assert r.status_code == 404

            # ── POST /api/conversation/{id}/stop (CSRF rejected) ──
            r = client.open(f"/api/conversation/{conv_id}/stop", method="POST")
            assert r.status_code == 403
            data = json.loads(r.get_data(as_text=True))
            assert "X-Requested-With" in data["error"]

            # ── POST /api/conversation/{id}/stop (not running) ───
            r = client.open(
                f"/api/conversation/{conv_id}/stop",
                method="POST",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            assert r.status_code == 200
            html = r.get_data(as_text=True)
            assert "not running" in html.lower()

            # ── POST /api/conversation/{id}/stop (not found) ─────
            r = client.open(
                "/api/conversation/deadbeef/stop",
                method="POST",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            assert r.status_code == 200

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
            assert tracker_task["reply_index"] == 0
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

            # ── GET /conversation/{id} (overview page) ────────────
            r = client.get(f"/conversation/{conv_id}")
            assert r.status_code == 200
            assert "text/html" in r.content_type
            page_html = r.get_data(as_text=True)
            assert conv_id in page_html

            # ── GET /conversation/{id} (not found) ───────────────
            r = client.get("/conversation/deadbeef")
            assert r.status_code == 404

            # ── GET /task/{task_id} ───────────────────────────────
            r = client.get(f"/task/{task.task_id}")
            assert r.status_code == 200
            assert "text/html" in r.content_type
            task_html = r.get_data(as_text=True)
            assert task.task_id in task_html

            # ── GET /task/{task_id} (not found) ───────────────────
            r = client.get("/task/nonexistent-task-id")
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


def _gate_mock(gate_dir: str) -> str:
    """Return mock code that blocks until a gate file is written."""
    return f"""
events = [
    generate_system_event(session_id),
    generate_assistant_event("Working..."),
    generate_result_event(session_id, "Done"),
]

def sync_between_events(event_num):
    if event_num == 1:
        gate = Path("{gate_dir}")
        gate.mkdir(parents=True, exist_ok=True)
        (gate / "ready").write_text("1")
        while not (gate / "release").exists():
            time.sleep(0.05)
"""


def _wait_for_gate(gate_dir: Path, timeout: float = 15.0) -> None:
    """Wait until the gate mock writes its ready file."""
    ready = gate_dir / "ready"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ready.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"Gate ready file not created within {timeout}s")


def _release_gate(gate_dir: Path) -> None:
    """Signal the gate mock to continue and complete."""
    gate_dir.mkdir(parents=True, exist_ok=True)
    (gate_dir / "release").write_text("1")


def _config_to_yaml(env: IntegrationEnvironment) -> dict:
    """Convert an IntegrationEnvironment to a YAML-serializable dict."""
    from airut.gateway.config import EmailChannelConfig

    gc = env.config.global_config
    result: dict = {
        "container_command": gc.container_command,
        "execution": {
            "max_concurrent": gc.max_concurrent_executions,
            "shutdown_timeout": gc.shutdown_timeout_seconds,
        },
        "dashboard": {
            "enabled": gc.dashboard_enabled,
            "host": gc.dashboard_host,
            "port": gc.dashboard_port,
        },
        "repos": {},
    }
    for repo_id, repo_cfg in env.config.repos.items():
        repo_dict: dict = {
            "repo_url": repo_cfg.git_repo_url,
            "model": repo_cfg.model,
        }
        email_cfg = repo_cfg.channels.get("email")
        if email_cfg is not None:
            assert isinstance(email_cfg, EmailChannelConfig)
            repo_dict["email"] = {
                "account": {
                    "username": email_cfg.account.username,
                    "password": email_cfg.account.password,
                    "from": email_cfg.account.from_address,
                },
                "imap": {
                    "server": email_cfg.imap.server,
                    "port": email_cfg.imap.port,
                    "use_idle": email_cfg.imap.use_idle,
                    "poll_interval": email_cfg.imap.poll_interval,
                },
                "smtp": {
                    "server": email_cfg.smtp.server,
                    "port": email_cfg.smtp.port,
                    "require_auth": email_cfg.smtp.require_auth,
                },
                "auth": {
                    "authorized_senders": list(
                        email_cfg.auth.authorized_senders
                    ),
                    "trusted_authserv_id": email_cfg.auth.trusted_authserv_id,
                },
            }
        result["repos"][repo_id] = repo_dict
    return result


class TestDashboardDuringReload:
    """Dashboard endpoints must remain accessible during pending repo reload.

    Reproduces the bug where network/events log streams returned 404 when
    a repo had RELOAD_PENDING status because _get_work_dirs() only
    included LIVE repos.
    """

    def test_network_poll_during_pending_repo_reload(
        self,
        tmp_path: Path,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Network and events poll endpoints return 200 during RELOAD_PENDING.

        Starts a gate-controlled task, triggers a repo-scope config change
        (which defers reload while task is active), then verifies that
        dashboard endpoints for the active conversation still respond with
        200 instead of 404.
        """
        gate_dir = tmp_path / "gate_dashboard"
        config_path = integration_env.repo_root / "airut.yaml"
        source = YamlConfigSource(config_path)
        yaml_data = _config_to_yaml(integration_env)
        source.save(yaml_data)

        snapshot = ServerConfig.from_source(source)
        service = GatewayService(
            snapshot.value,
            repo_root=integration_env.repo_root,
            egress_network=integration_env.egress_network,
            config_source=source,
            config_snapshot=snapshot,
        )
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for boot
            _wait_for_boot(service)

            # Start gate-controlled task
            msg = create_email(
                subject="Dashboard reload test",
                body=_gate_mock(str(gate_dir)),
            )
            integration_env.email_server.inject_message(msg)

            # Wait for task to reach the gate (executing)
            executing_task = wait_for_task(
                service.tracker,
                lambda t: t.status.value == "executing",
                timeout=15.0,
            )
            assert executing_task is not None
            _wait_for_gate(gate_dir)

            # Get conversation ID from acknowledgment email
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Trigger repo-scope config change while task is active
            gen = service._config_generation
            yaml_data["repos"]["test"]["email"]["auth"][
                "authorized_senders"
            ] = ["user@test.local", "extra@test.local"]
            source.save(yaml_data)

            # Wait for config generation to advance
            _wait_for_config_generation(service, gen)

            # Verify repo is in RELOAD_PENDING state
            repo_states = service._repos_store.get().value
            test_repo = next(r for r in repo_states if r.repo_id == "test")
            assert test_repo.status == RepoStatus.RELOAD_PENDING, (
                f"Expected RELOAD_PENDING, got {test_repo.status}"
            )

            # Now test dashboard endpoints — these should return 200,
            # not 404 as they did before the fix
            assert service.dashboard is not None

            from werkzeug.test import Client

            client = Client(service.dashboard._wsgi_app)

            # Network log poll
            r = client.get(f"/api/conversation/{conv_id}/network/poll?offset=0")
            assert r.status_code == 200, (
                f"network/poll returned {r.status_code} during RELOAD_PENDING"
            )

            # Events log poll
            r = client.get(f"/api/conversation/{conv_id}/events/poll?offset=0")
            assert r.status_code == 200, (
                f"events/poll returned {r.status_code} during RELOAD_PENDING"
            )

            # Conversation detail API
            r = client.get(f"/api/conversation/{conv_id}")
            assert r.status_code == 200, (
                f"conversation API returned {r.status_code} during"
                " RELOAD_PENDING"
            )

            # Release gate and let task complete
            _release_gate(gate_dir)
            wait_for_conv_completion(service.tracker, conv_id, timeout=15.0)

        finally:
            service.stop()
            service_thread.join(timeout=10.0)


def _wait_for_boot(service: "GatewayService", timeout: float = 15.0) -> None:
    """Wait for service boot to reach READY."""
    from airut.dashboard.tracker import BootPhase

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        boot = service._boot_store.get().value
        if boot.phase == BootPhase.READY:
            return
        if boot.phase == BootPhase.FAILED:
            raise RuntimeError(f"Service boot failed: {boot.error_message}")
        time.sleep(0.05)
    raise TimeoutError(f"Service did not boot within {timeout}s")


def _wait_for_config_generation(
    service: "GatewayService",
    generation: int,
    timeout: float = 5.0,
) -> None:
    """Wait until config_generation > generation."""
    with service._reload_condition:
        if not service._reload_condition.wait_for(
            lambda: service._config_generation > generation, timeout
        ):
            raise TimeoutError(
                f"Config reload did not advance within {timeout}s"
            )
