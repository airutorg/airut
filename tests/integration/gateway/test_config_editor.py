# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for config editor API endpoints.

Tests exercise the full config editor flow using a file-backed
GatewayService with live dashboard, verifying:

- GET /config page loads and shows global settings + repos
- PATCH /api/config/field sets scalar values (smoke test)
- POST /api/config/save validates, writes YAML, triggers reload
- POST /api/config/discard resets edit buffer
- Staleness detection after external config changes
- Full edit-save-reload cycle: edit via API, save, observe reload
- EnvVar round-trip through save
- Add repo via editor, save, gateway brings it online and processes task
- Remove repo via editor, save, gateway takes it offline

Fast-path tests (field types, CSRF, diff rendering, add/remove,
dirty count) are covered by unit tests in tests/dashboard/.
"""

import sys
import threading
import time
from pathlib import Path
from typing import Any

import yaml
from werkzeug.test import Client, TestResponse


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.config.source import make_env_loader
from airut.gateway.config import GlobalConfig, ServerConfig
from airut.gateway.service import GatewayService

from .conftest import MOCK_CONTAINER_COMMAND, get_message_text
from .environment import IntegrationEnvironment, create_test_repo
from .test_config_reload import (
    ConfigFile,
    _wait_for_service_ready,
    running_service,
    wait_for_reload,
    wait_for_repo_status,
)


# ------------------------------------------------------------------ #
# Test helpers (config-editor-specific)
# ------------------------------------------------------------------ #


def _make_config_file(
    env: IntegrationEnvironment,
    path: Path,
) -> ConfigFile:
    """Build a YAML config file from an IntegrationEnvironment."""
    return ConfigFile.from_env(env, path)


#: Header dict for CSRF-protected requests.
XHR: dict[str, str] = {"X-Requested-With": "XMLHttpRequest"}


def _patch_field(
    client: Client,
    path: str,
    source: str,
    value: object = None,
) -> TestResponse:
    """Send PATCH /api/config/field as form-encoded data with XHR header."""
    body: dict[str, Any] = {"path": path, "source": source}
    if value is not None:
        body["value"] = value
    return client.patch(
        "/api/config/field",
        data=body,
        headers=XHR,
    )


def _post_form(
    client: Client,
    url: str,
    body: dict[str, Any] | None = None,
) -> TestResponse:
    """Send POST with XHR header and optional form-encoded body."""
    kwargs: dict[str, Any] = {"headers": XHR}
    if body is not None:
        kwargs["data"] = body
    return client.post(url, **kwargs)


def _standard_mock() -> str:
    """Return standard mock code that completes successfully."""
    return """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Task completed"),
    generate_result_event(session_id, "Done"),
]
"""


def _get_client(service: GatewayService) -> Client:
    """Get a werkzeug test client from a service's dashboard."""
    assert service.dashboard is not None
    return Client(service.dashboard._wsgi_app)


def _add_valid_repo(
    client: Client,
    service: GatewayService,
    env: IntegrationEnvironment,
    repo_id: str,
    git_repo_path: Path,
) -> None:
    """Add a repo via the editor API and fill in all required fields.

    Performs POST /api/config/add then patches every field needed for
    a valid config (git URL, email channel, authorized senders, IMAP
    polling).  Does NOT save — caller must POST /api/config/save.
    """
    r = _post_form(
        client,
        "/api/config/add",
        {"path": "repos", "key": repo_id},
    )
    assert r.status_code == 200

    _patch_field(
        client, f"repos.{repo_id}.git.repo_url", "literal", str(git_repo_path)
    )
    _patch_field(
        client, f"repos.{repo_id}.email.imap_server", "literal", "127.0.0.1"
    )
    _patch_field(
        client,
        f"repos.{repo_id}.email.imap_port",
        "literal",
        str(env.imap_port),
    )
    _patch_field(
        client, f"repos.{repo_id}.email.smtp_server", "literal", "127.0.0.1"
    )
    _patch_field(
        client,
        f"repos.{repo_id}.email.smtp_port",
        "literal",
        str(env.smtp_port),
    )
    _patch_field(
        client,
        f"repos.{repo_id}.email.smtp_require_auth",
        "literal",
        "false",
    )
    _patch_field(client, f"repos.{repo_id}.email.username", "literal", repo_id)
    _patch_field(client, f"repos.{repo_id}.email.password", "literal", "test")
    _patch_field(
        client,
        f"repos.{repo_id}.email.from",
        "literal",
        f"{repo_id} <{repo_id}@test.local>",
    )
    _patch_field(
        client,
        f"repos.{repo_id}.email.trusted_authserv_id",
        "literal",
        "test.local",
    )

    # Set fields that require direct buffer manipulation
    dashboard = service.dashboard
    assert dashboard is not None
    buf = dashboard._config_handlers._buffer
    assert buf is not None
    buf.raw["repos"][repo_id]["email"]["authorized_senders"] = [
        "user@test.local"
    ]
    buf.raw["repos"][repo_id]["email"].setdefault("imap", {})
    buf.raw["repos"][repo_id]["email"]["imap"]["use_idle"] = False
    buf.raw["repos"][repo_id]["email"]["imap"]["poll_interval"] = 0.1


# ------------------------------------------------------------------ #
# Tests — only those requiring file-backed service / file watcher
# ------------------------------------------------------------------ #


class TestConfigPageRendering:
    """GET /config renders the global settings page."""

    def test_config_page_loads(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Config page returns 200 and shows global fields and repos."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)

            r = client.get("/config")
            assert r.status_code == 200
            html = r.get_data(as_text=True)
            assert "text/html" in r.content_type

            # Global settings present
            assert "max_concurrent" in html
            assert "shutdown_timeout" in html
            assert "dashboard" in html.lower()

            # Repo summary present
            assert "test" in html

            # Security headers applied
            assert r.headers["X-Content-Type-Options"] == "nosniff"

    def test_config_page_without_file_source(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Config page renders when service has no file-backed source."""
        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()
        try:
            _wait_for_service_ready(service)
            assert service.dashboard is not None, "Dashboard should be enabled"
            client = Client(service.dashboard._wsgi_app)

            r = client.get("/config")
            assert r.status_code == 200
            assert "text/html" in r.content_type
        finally:
            service.stop()
            service_thread.join(timeout=10.0)


class TestFieldPatch:
    """PATCH /api/config/field — smoke test with file-backed service."""

    def test_set_literal_int(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Set a literal integer value and verify buffer holds it."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            r = _patch_field(
                client, "execution.max_concurrent", "literal", "10"
            )
            assert r.status_code == 200
            assert "text/html" in r.content_type

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert buf.raw["execution"]["max_concurrent"] == 10
            assert isinstance(buf.raw["execution"]["max_concurrent"], int)


class TestSave:
    """POST /api/config/save validates and writes YAML."""

    def test_save_writes_yaml(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Save writes the modified config to the YAML file."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _patch_field(client, "execution.max_concurrent", "literal", "5")

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200
            assert r.headers.get("HX-Redirect") == "/config"

            with open(cf.path) as f:
                saved = yaml.load(f, Loader=make_env_loader())
            assert saved["execution"]["max_concurrent"] == 5

    def test_save_triggers_reload(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Save writes YAML which triggers config file watcher reload."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            gen_before = service._config_generation

            _patch_field(client, "execution.shutdown_timeout", "literal", "120")

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200

            wait_for_reload(service, gen_before)
            assert service._config_generation > gen_before
            assert service.config.global_config.shutdown_timeout_seconds == 120

    def test_save_invalid_config(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Save with invalid config returns 422."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            buf._raw["repos"] = {}
            buf._dirty = True

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 422

    def test_save_stale_buffer(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Save with stale buffer returns 409."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _patch_field(client, "execution.max_concurrent", "literal", "99")

            gen = service._config_generation
            cf.set("execution.shutdown_timeout", 999)
            wait_for_reload(service, gen)

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 409
            html = r.get_data(as_text=True)
            assert "changed externally" in html.lower()


class TestDiscard:
    """POST /api/config/discard resets the edit buffer."""

    def test_discard_resets_buffer(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Discard clears the edit buffer and redirects."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            dashboard = service.dashboard
            assert dashboard is not None
            assert dashboard._config_handlers._buffer is not None

            _patch_field(client, "execution.max_concurrent", "literal", "99")
            assert dashboard._config_handlers._buffer.dirty

            r = _post_form(client, "/api/config/discard")
            assert r.status_code == 200
            assert r.headers.get("HX-Redirect") == "/config"
            assert dashboard._config_handlers._buffer is None


class TestFullEditSaveReloadCycle:
    """End-to-end: edit multiple fields, save, verify on-disk and reload."""

    def test_multi_field_edit_save_reload(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Edit multiple fields, save, verify YAML and config reload."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            gen_before = service._config_generation

            _patch_field(client, "execution.max_concurrent", "literal", "8")
            _patch_field(client, "execution.shutdown_timeout", "literal", "300")
            _patch_field(client, "dashboard.host", "literal", "0.0.0.0")

            r = client.get("/api/config/diff")
            assert r.status_code == 200
            html = r.get_data(as_text=True)
            assert "3 change" in html

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200

            with open(cf.path) as f:
                saved = yaml.load(f, Loader=make_env_loader())
            assert saved["execution"]["max_concurrent"] == 8
            assert saved["execution"]["shutdown_timeout"] == 300
            assert saved["dashboard"]["host"] == "0.0.0.0"

            wait_for_reload(service, gen_before)

            gc = service.config.global_config
            assert gc.max_concurrent_executions == 8
            assert gc.shutdown_timeout_seconds == 300
            assert gc.dashboard_host == "0.0.0.0"

    def test_edit_save_and_re_edit(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """After save, a new edit session starts from the saved config."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)

            client.get("/config")
            _patch_field(client, "execution.max_concurrent", "literal", "4")
            gen_before = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200

            dashboard = service.dashboard
            assert dashboard is not None
            # Buffer is kept (marked clean) after save, not discarded.
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert not buf.dirty

            wait_for_reload(service, gen_before)
            assert service.config.global_config.max_concurrent_executions == 4

            r = client.get("/config")
            assert r.status_code == 200
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert buf.get_value("execution.max_concurrent") == 4


class TestStalenessDetection:
    """Edit buffer detects external config changes."""

    def test_external_change_makes_buffer_stale(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Config change via file makes the edit buffer stale."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert not buf.is_stale(service._config_generation)

            gen = service._config_generation
            cf.set("execution.max_concurrent", 99)
            wait_for_reload(service, gen)

            assert buf.is_stale(service._config_generation)


class TestSaveReloadBugs:
    """Reproduce save/reload race conditions (Bug #3).

    After saving, loading the config page should show saved values.
    Re-editing and re-saving should not produce a false stale error.
    """

    def test_save_immediate_page_load_shows_new_values(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """After save, immediate page load must show saved values.

        Simulates browser following HX-Redirect before the file
        watcher has reloaded the config.
        """
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _patch_field(client, "execution.max_concurrent", "literal", "4")

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200

            # Immediately load page — do NOT wait for file watcher.
            r = client.get("/config")
            assert r.status_code == 200

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert buf.get_value("execution.max_concurrent") == 4, (
                "Buffer shows old value after save"
            )

    def test_save_reload_resave_no_stale_error(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """After save + reload, editing and re-saving must not get 409."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _patch_field(client, "execution.max_concurrent", "literal", "4")

            gen_before = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200

            client.get("/config")
            wait_for_reload(service, gen_before)

            _patch_field(client, "execution.shutdown_timeout", "literal", "120")

            r = _post_form(client, "/api/config/save")
            assert r.status_code != 409, (
                "Got stale error on second save — buffer not refreshed "
                "after own save triggered reload"
            )

    def test_double_edit_save_full_cycle(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Two complete edit-save cycles must both succeed."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)

            # First cycle: edit max_concurrent
            client.get("/config")
            _patch_field(client, "execution.max_concurrent", "literal", "4")
            gen1 = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200
            wait_for_reload(service, gen1)

            # Second cycle: edit shutdown_timeout
            client.get("/config")

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert buf.get_value("execution.max_concurrent") == 4

            _patch_field(client, "execution.shutdown_timeout", "literal", "120")
            gen2 = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200, (
                f"Second save failed with {r.status_code}: "
                f"{r.get_data(as_text=True)[:200]}"
            )
            wait_for_reload(service, gen2)

            # Verify both values persisted
            gc = service.config.global_config
            assert gc.max_concurrent_executions == 4
            assert gc.shutdown_timeout_seconds == 120

    def test_clean_stale_buffer_refreshes(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """A stale but clean buffer should auto-refresh on page load."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert not buf.dirty

            # External change
            gen = service._config_generation
            cf.set("execution.max_concurrent", 88)
            wait_for_reload(service, gen)

            # Load page — buffer is stale but clean, should auto-refresh
            client.get("/config")
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert buf.get_value("execution.max_concurrent") == 88, (
                "Clean stale buffer was not refreshed on page load"
            )


class TestEditorRobustness:
    """Additional robustness tests for edge cases."""

    def test_discard_after_edits_reverts_to_live_config(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Discard then /config should show live config values."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            original = buf.get_value("execution.max_concurrent")

            # Edit
            _patch_field(client, "execution.max_concurrent", "literal", "99")
            assert buf.get_value("execution.max_concurrent") == 99

            # Discard
            _post_form(client, "/api/config/discard")

            # Load page
            client.get("/config")
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert buf.get_value("execution.max_concurrent") == original

    def test_save_then_discard_shows_saved_state(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """After save + reload + discard + page load, shows saved values."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _patch_field(client, "execution.max_concurrent", "literal", "7")

            gen_before = service._config_generation
            _post_form(client, "/api/config/save")
            wait_for_reload(service, gen_before)

            # Discard (no-op since buffer was cleared by save)
            _post_form(client, "/api/config/discard")

            # Load page
            client.get("/config")

            dashboard = service.dashboard
            assert dashboard is not None
            buf = dashboard._config_handlers._buffer
            assert buf is not None
            assert buf.get_value("execution.max_concurrent") == 7


class TestEnvVarRoundTrip:
    """EnvVar (!env) and VarRef (!var) survive edit-save cycles."""

    def test_env_var_preserved_through_save(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Setting a field to !env and saving preserves the tag."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _patch_field(client, "dashboard.host", "env", "DASHBOARD_HOST")

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200

            with open(cf.path) as f:
                content = f.read()
            assert "!env" in content
            assert "DASHBOARD_HOST" in content

            with open(cf.path) as f:
                loaded = yaml.load(f, Loader=make_env_loader())
            from airut.yaml_env import EnvVar

            assert isinstance(loaded["dashboard"]["host"], EnvVar)
            assert loaded["dashboard"]["host"].var_name == "DASHBOARD_HOST"


class TestEditorAddRepoLifecycle:
    """Add repo via config editor → save → gateway brings it online."""

    def test_add_repo_save_brings_repo_online(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """Adding a repo through the editor and saving makes it live.

        Full flow: add repo via POST /api/config/add, edit fields via
        PATCH /api/config/field, save via POST /api/config/save, wait
        for config reload, verify repo is live and can process a task.
        """
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        # Pre-register inbox for the new repo
        integration_env.email_server.add_inbox("project-b")

        # Create a second git repo for the new config entry
        repo_b_path = create_test_repo(
            integration_env.repo_root / "master_repo_b"
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)

            # Verify initial state: only 'test' repo is live
            assert "test" in service.repo_handlers
            assert "project-b" not in service.repo_handlers

            # --- Config editor flow: add repo ---
            client.get("/config")
            _add_valid_repo(
                client, service, integration_env, "project-b", repo_b_path
            )

            # --- Save ---
            gen_before = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200, (
                f"Save failed: {r.get_data(as_text=True)[:300]}"
            )

            # Wait for config reload
            wait_for_reload(service, gen_before)

            # Verify new repo is live
            wait_for_repo_status(service, "project-b", "live")
            assert "project-b" in service.repo_handlers

            # --- Send a message to the new repo and verify processing ---
            mock_body = _standard_mock()
            msg = create_email(subject="Project B task", body=mock_body)
            integration_env.email_server.inject_message_to("project-b", msg)

            ack = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "project b task" in m.get("Subject", "").lower()
                    and "started working" in get_message_text(m).lower()
                ),
                timeout=15.0,
            )
            assert ack is not None, (
                "New repo did not process the message — "
                "repo was not brought online after save"
            )

    def test_add_repo_skeleton_save_rejects_incomplete(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Saving with skeleton placeholder values fails validation (422).

        The repo skeleton uses empty placeholders.  Saving without
        filling in required fields (e.g. authorized_senders) must
        reject the save to prevent a broken config.
        """
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            r = _post_form(
                client,
                "/api/config/add",
                {"path": "repos", "key": "project-b"},
            )
            assert r.status_code == 200

            # Only set git URL, leave rest as skeleton placeholders
            repo_b_path = create_test_repo(
                integration_env.repo_root / "master_repo_b"
            )
            _patch_field(
                client,
                "repos.project-b.git.repo_url",
                "literal",
                str(repo_b_path),
            )

            r = _post_form(client, "/api/config/save")
            assert r.status_code == 422, (
                "Save should fail with incomplete skeleton values"
            )

    def test_add_repo_appears_in_config_after_save(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """After add+save with valid fields, repo appears in config."""
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        integration_env.email_server.add_inbox("project-b")

        repo_b_path = create_test_repo(
            integration_env.repo_root / "master_repo_b"
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            assert "project-b" not in service.config.repos

            _add_valid_repo(
                client, service, integration_env, "project-b", repo_b_path
            )

            gen_before = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200, (
                f"Save failed: {r.get_data(as_text=True)[:300]}"
            )
            wait_for_reload(service, gen_before)

            assert "project-b" in service.config.repos
            assert "project-b" in service.repo_handlers

    def test_add_repo_fails_if_listener_start_fails(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Repo shows as FAILED when listener startup fails on reload.

        If the IMAP connection fails during _add_repo, the repo ends
        up in service.config but NOT in repo_handlers.  It should
        still appear in the repos store with FAILED status so the
        dashboard shows the error.
        """
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        # Deliberately do NOT register inbox — IMAP LOGIN will fail
        repo_b_path = create_test_repo(
            integration_env.repo_root / "master_repo_b"
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _add_valid_repo(
                client, service, integration_env, "project-b", repo_b_path
            )

            gen_before = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200
            wait_for_reload(service, gen_before)

            # Config has the repo, but handlers does not (IMAP failed)
            assert "project-b" in service.config.repos
            assert "project-b" not in service.repo_handlers

            # Repo should still appear in repos store with FAILED status
            wait_for_repo_status(service, "project-b", "failed")

    def test_add_repo_reconciled_on_subsequent_reload(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Failed add is retried when a subsequent config change reloads.

        If _add_repo fails on the initial reload, the reconciliation
        in _on_config_changed retries the add when the next reload
        sees the repo in config but not in handlers.
        """
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        repo_b_path = create_test_repo(
            integration_env.repo_root / "master_repo_b"
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            # First save: IMAP will fail (no inbox registered)
            _add_valid_repo(
                client, service, integration_env, "project-b", repo_b_path
            )

            gen_before = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200
            wait_for_reload(service, gen_before)

            assert "project-b" in service.config.repos
            assert "project-b" not in service.repo_handlers

            # Now register the inbox so IMAP login will succeed
            integration_env.email_server.add_inbox("project-b")

            # Re-sync cf._data from disk — the editor save wrote
            # project-b directly to the YAML, bypassing our ConfigFile.
            cf.reload()

            # Trigger a config reload (touch an unrelated field)
            gen_before = service._config_generation
            cf.set("execution.shutdown_timeout", 42)
            wait_for_reload(service, gen_before)

            # Reconciliation should have retried _add_repo
            wait_for_repo_status(service, "project-b", "live", timeout=5.0)
            assert "project-b" in service.repo_handlers

    def test_add_repo_no_auto_retry_without_config_change(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """Failed _add_repo is not retried without a config change.

        After _add_repo fails, the repo remains missing from handlers.
        Without a subsequent config file change, the watcher never
        triggers and the repo is stuck.  This demonstrates that the
        add-repo-via-editor flow has no self-healing path.
        """
        cf = _make_config_file(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        repo_b_path = create_test_repo(
            integration_env.repo_root / "master_repo_b"
        )

        with running_service(cf, integration_env) as service:
            client = _get_client(service)
            client.get("/config")

            _add_valid_repo(
                client, service, integration_env, "project-b", repo_b_path
            )

            gen_before = service._config_generation
            r = _post_form(client, "/api/config/save")
            assert r.status_code == 200
            wait_for_reload(service, gen_before)

            # Repo failed to add (no IMAP inbox registered)
            assert "project-b" in service.config.repos
            assert "project-b" not in service.repo_handlers

            # Register inbox — but no config change triggers retry
            integration_env.email_server.add_inbox("project-b")

            # Wait a bit — no reload should fire
            time.sleep(0.5)
            assert "project-b" not in service.repo_handlers, (
                "Repo appeared in handlers without a config change"
            )


class TestEditorRemoveRepoLifecycle:
    """Remove repo via config editor → save → gateway takes it offline."""

    def test_remove_repo_save_takes_repo_offline(
        self,
        tmp_path: Path,
    ) -> None:
        """Removing a repo through the editor and saving drops it.

        Starts with two repos, removes one via the editor API, saves,
        and verifies the removed repo is no longer in repo_handlers.
        """
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["alpha", "beta"],
            container_command=MOCK_CONTAINER_COMMAND,
        )
        try:
            # Multi-repo env has dashboard disabled; we need it enabled
            env.config = ServerConfig(
                global_config=GlobalConfig(
                    max_concurrent_executions=2,
                    shutdown_timeout_seconds=5,
                    dashboard_enabled=True,
                    dashboard_host="127.0.0.1",
                    dashboard_port=0,
                    container_command=MOCK_CONTAINER_COMMAND,
                ),
                repos=env.config.repos,
            )

            cf = ConfigFile.from_env(env, tmp_path / "airut.yaml")

            with running_service(cf, env) as service:
                # Both repos should be live
                wait_for_repo_status(service, "alpha", "live")
                wait_for_repo_status(service, "beta", "live")
                assert "alpha" in service.repo_handlers
                assert "beta" in service.repo_handlers

                client = _get_client(service)
                client.get("/config")

                # Remove beta via the editor
                r = _post_form(
                    client,
                    "/api/config/remove",
                    {"path": "repos", "key": "beta"},
                )
                assert r.status_code == 200

                # Save
                gen_before = service._config_generation
                r = _post_form(client, "/api/config/save")
                assert r.status_code == 200
                wait_for_reload(service, gen_before)

                # Beta should be gone
                assert "beta" not in service.repo_handlers
                assert "beta" not in service.config.repos
                # Alpha should still be live
                assert "alpha" in service.repo_handlers
        finally:
            env.cleanup()
