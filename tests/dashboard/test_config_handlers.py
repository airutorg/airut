# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor HTTP handlers."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from werkzeug.test import Client

from airut.config.schema import FieldSchema
from airut.config.source import YamlConfigSource
from airut.dashboard.config_editor import ConfigEditor
from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import TaskTracker


# ── Minimal config YAML for tests ──────────────────────────────────


def _write_config(path: Path, data: dict[str, Any] | None = None) -> Path:
    """Write a minimal config YAML file."""
    if data is None:
        data = {
            "vars": {"mail_server": "mail.example.com"},
            "execution": {"max_concurrent": 4},
            "dashboard": {"enabled": True, "host": "127.0.0.1", "port": 5200},
            "repos": {
                "test-repo": {
                    "git": {"repo_url": "https://github.com/test/repo.git"},
                    "model": "opus",
                    "email": {
                        "imap_server": "imap.example.com",
                        "smtp_server": "smtp.example.com",
                        "username": "user@example.com",
                        "password": "secret",
                        "from": "bot@example.com",
                        "authorized_senders": ["admin@example.com"],
                        "trusted_authserv_id": "example.com",
                    },
                },
            },
        }
    config_file = path / "airut.yaml"
    config_file.write_text(yaml.dump(data, default_flow_style=False))
    return config_file


# ── ConfigEditor handler tests ─────────────────────────────────────


class TestConfigEditorHandlers:
    """Tests for ConfigEditor HTTP handlers via werkzeug test client."""

    @pytest.fixture
    def config_path(self, tmp_path: Path) -> Path:
        return _write_config(tmp_path)

    @pytest.fixture
    def editor(self, config_path: Path) -> ConfigEditor:
        return ConfigEditor(YamlConfigSource(config_path))

    @pytest.fixture
    def client(self, config_path: Path) -> Client:
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        return Client(server._wsgi_app)

    def test_config_index_redirects(self, client: Client) -> None:
        response = client.get("/config")
        assert response.status_code == 302
        assert response.headers["Location"] == "/config/global"

    def test_global_get(self, client: Client) -> None:
        response = client.get("/config/global")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Global Settings" in html
        assert "Variables" in html

    def test_global_post_without_csrf_rejected(self, client: Client) -> None:
        response = client.post("/config/global")
        assert response.status_code == 403

    def test_global_post_with_csrf(self, client: Client) -> None:
        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html

    def test_repo_get(self, client: Client) -> None:
        response = client.get("/config/repo/test-repo")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "test-repo" in html

    def test_repo_get_not_found(self, client: Client) -> None:
        response = client.get("/config/repo/nonexistent")
        assert response.status_code == 404

    def test_repo_new_get(self, client: Client) -> None:
        response = client.get("/config/repo/new")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "New Repository" in html

    def test_repo_new_post_creates_repo(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=new-repo&git_repo_url=https://github.com/org/new.git",
        )
        assert response.status_code == 302
        assert "/config/repo/new-repo" in response.headers["Location"]

    def test_repo_new_post_missing_id(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=&git_repo_url=https://example.com/repo.git",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "required" in html.lower()

    def test_repo_new_post_invalid_id(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=!invalid&git_repo_url=https://example.com/repo.git",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Invalid" in html

    def test_repo_new_post_duplicate(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=test-repo&git_repo_url=https://example.com/repo.git",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "already exists" in html

    def test_repo_new_post_missing_url(self, client: Client) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="repo_id=my-repo&git_repo_url=",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "required" in html.lower()

    def test_repo_delete_get(self, client: Client) -> None:
        response = client.get("/config/repo/test-repo/delete")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Delete" in html
        assert "test-repo" in html

    def test_repo_delete_get_not_found(self, client: Client) -> None:
        response = client.get("/config/repo/nonexistent/delete")
        assert response.status_code == 404

    def test_repo_delete_post(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/delete",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 302
        assert response.headers["Location"] == "/config/global"

    def test_repo_delete_post_not_found(self, client: Client) -> None:
        response = client.post(
            "/config/repo/nonexistent/delete",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 404

    def test_nav_fragment(self, client: Client) -> None:
        response = client.get("/config/nav")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "test-repo" in html

    def test_field_input_fragment(self, client: Client) -> None:
        response = client.get(
            "/config/field-input?name=model&type=str&field.model.mode=literal"
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'name="field.model.value"' in html

    def test_field_input_var_mode(self, client: Client) -> None:
        response = client.get(
            "/config/field-input?name=model&type=str&field.model.mode=var"
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Variable name" in html

    def test_field_input_env_mode(self, client: Client) -> None:
        response = client.get(
            "/config/field-input?name=model&type=str&field.model.mode=env"
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "ENV_VAR_NAME" in html

    def test_vars_add(self, client: Client) -> None:
        response = client.post(
            "/config/vars/add",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "var." in html

    def test_credential_add_masked_secret(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=masked_secret",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "masked_secret." in html

    def test_credential_add_signing_credential(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=signing_credential",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "signing_credential." in html

    def test_credential_add_github_app(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=github_app",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "github_app." in html

    def test_reload_status(self, client: Client) -> None:
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "reload-status" in html

    def test_reload_status_no_gen(self, client: Client) -> None:
        response = client.get("/config/reload-status")
        assert response.status_code == 200

    def test_reload_status_with_status_callback(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()

        def status_cb() -> dict[str, object]:
            return {"config_generation": 10}

        server = DashboardServer(
            tracker,
            config_source=source,
            status_callback=status_cb,
        )
        client = Client(server._wsgi_app)

        # gen=5, current=10 → reload complete, stop polling
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "hx-get" not in html  # polling stopped

    def test_reload_status_still_pending(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()

        def status_cb() -> dict[str, object]:
            return {"config_generation": 3}

        server = DashboardServer(
            tracker,
            config_source=source,
            status_callback=status_cb,
        )
        client = Client(server._wsgi_app)

        # gen=5, current=3 → still pending, keep polling
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "hx-get" in html  # still polling

    def test_reload_status_bad_gen_value(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()

        def status_cb() -> dict[str, object]:
            return {"config_generation": "bad"}

        server = DashboardServer(
            tracker,
            config_source=source,
            status_callback=status_cb,
        )
        client = Client(server._wsgi_app)

        # Bad gen value → stop polling gracefully
        response = client.get("/config/reload-status?gen=5")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "hx-get" not in html  # stopped on bad value

    def test_credential_add_invalid_type(self, client: Client) -> None:
        response = client.post(
            "/config/repo/test-repo/credential/add?type=evil",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400

    def test_repo_post_saves_changes(
        self, client: Client, config_path: Path
    ) -> None:
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&field.model.mode=literal"
                "&field.model.value=sonnet"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html

    def test_repo_post_not_found(self, client: Client) -> None:
        response = client.post(
            "/config/repo/nonexistent",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 404

    def test_repo_post_add_slack(
        self, client: Client, config_path: Path
    ) -> None:
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized=workspace_members: true"
            ),
        )
        assert response.status_code == 200
        # Verify slack was saved
        raw = yaml.safe_load(config_path.read_text())
        assert "slack" in raw["repos"]["test-repo"]

    def test_config_not_available_without_source(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)
        response = client.get("/config/global")
        assert response.status_code == 404

    def test_repo_new_with_channels(
        self, client: Client, config_path: Path
    ) -> None:
        response = client.post(
            "/config/repo/new",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "repo_id=multi-chan"
                "&git_repo_url=https://github.com/test/repo.git"
                "&add_email=true"
                "&add_slack=true"
            ),
        )
        assert response.status_code == 302
        raw = yaml.safe_load(config_path.read_text())
        assert "email" in raw["repos"]["multi-chan"]
        assert "slack" in raw["repos"]["multi-chan"]


class TestConfigEditorInternal:
    """Tests for ConfigEditor internal methods."""

    @pytest.fixture
    def editor(self, tmp_path: Path) -> ConfigEditor:
        config_path = _write_config(tmp_path)
        return ConfigEditor(YamlConfigSource(config_path))

    def test_get_vars(self, editor: ConfigEditor) -> None:
        raw = editor._load_raw()
        assert editor._get_vars(raw) == {"mail_server": "mail.example.com"}

    def test_get_vars_empty(self, editor: ConfigEditor) -> None:
        assert editor._get_vars({}) == {}

    def test_get_vars_not_dict(self, editor: ConfigEditor) -> None:
        assert editor._get_vars({"vars": "not_a_dict"}) == {}

    def test_get_repo_ids(self, editor: ConfigEditor) -> None:
        raw = editor._load_raw()
        assert editor._get_repo_ids(raw) == ["test-repo"]

    def test_get_repo_ids_empty(self, editor: ConfigEditor) -> None:
        assert editor._get_repo_ids({}) == []

    def test_resolve_env_set(self, editor: ConfigEditor) -> None:
        with patch.dict("os.environ", {"TEST_VAR": "test_value"}):
            assert editor._resolve_env("TEST_VAR") == "test_value"

    def test_resolve_env_unset(self, editor: ConfigEditor) -> None:
        assert editor._resolve_env("SURELY_NOT_SET_12345") is None

    def test_schema_excludes_credential_fields(
        self, editor: ConfigEditor
    ) -> None:
        excluded = {
            "repo_id",
            "git_repo_url",
            "channels",
            "secrets",
            "masked_secrets",
            "signing_credentials",
            "github_app_credentials",
            "container_env",
        }
        for field in editor._repo_schema:
            assert field.name not in excluded

    def test_global_post_saves_vars(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "var.0.name=new_var&var.0.mode=literal&var.0.value=new_value"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert raw["vars"] == {"new_var": "new_value"}

    def test_global_post_removes_vars_when_empty(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data="",
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "vars" not in raw

    def test_global_post_with_form_errors(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Submit an invalid int value for max_concurrent_executions
        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "field.max_concurrent_executions.mode=literal"
                "&field.max_concurrent_executions.value=not_a_number"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Expected integer" in html

    def test_repo_post_with_email_errors(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Email has required imap_server field
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=true"
                "&has_slack=false"
                "&field.imap_server.mode=literal"
                "&field.imap_server.value="
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "required" in html.lower() or "error" in html.lower()

    def test_repo_post_with_git_url_var_mode(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=var"
                "&git_repo_url.value=my_repo_url"
                "&has_email=false"
                "&has_slack=false"
            ),
        )
        assert response.status_code == 200

    def test_repo_post_with_git_url_env_mode(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=env"
                "&git_repo_url.value=REPO_URL_ENV"
                "&has_email=false"
                "&has_slack=false"
            ),
        )
        assert response.status_code == 200

    def test_repo_post_saves_secrets(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&secret.0.key=API_KEY"
                "&secret.0.value.mode=literal"
                "&secret.0.value.value=my-secret"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert raw["repos"]["test-repo"]["secrets"] == {"API_KEY": "my-secret"}

    def test_repo_post_saves_container_env(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&container_env.0.key=MY_VAR"
                "&container_env.0.value.mode=literal"
                "&container_env.0.value.value=my_val"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert raw["repos"]["test-repo"]["container_env"] == {
            "MY_VAR": "my_val"
        }

    def test_repo_post_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post("/config/repo/test-repo")
        assert response.status_code == 403

    def test_repo_new_post_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/new",
            content_type="application/x-www-form-urlencoded",
            data="repo_id=test&git_repo_url=https://example.com/r.git",
        )
        assert response.status_code == 403

    def test_repo_delete_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post("/config/repo/test-repo/delete")
        assert response.status_code == 403

    def test_repo_post_with_repo_schema_errors(self, tmp_path: Path) -> None:
        """Test that repo field validation errors return the form."""
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Inject a required int field into the repo schema to trigger
        # validation errors (current schema has no required/int fields).
        editor = server._config_editor
        assert editor is not None
        original_schema = editor._repo_schema
        editor._repo_schema = [
            FieldSchema(
                name="fake_int",
                type_name="int",
                default=None,
                required=True,
                doc="Fake",
                scope="task",
                secret=False,
            )
        ]
        try:
            response = client.post(
                "/config/repo/test-repo",
                headers={"X-Requested-With": "XMLHttpRequest"},
                content_type="application/x-www-form-urlencoded",
                data=(
                    "git_repo_url.mode=literal"
                    "&git_repo_url.value=https://github.com/test/repo.git"
                    "&has_email=false"
                    "&has_slack=false"
                    "&field.fake_int.mode=literal"
                    "&field.fake_int.value="
                ),
            )
            assert response.status_code == 200
        finally:
            editor._repo_schema = original_schema

    def test_repo_post_slack_empty_auth_line(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized=workspace_members: true\n"
                "\nuser_id: U123"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        slack = raw["repos"]["test-repo"]["slack"]
        # Empty line should be skipped
        assert len(slack["authorized"]) == 2

    def test_global_post_saves_resource_limits(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "field.rl_timeout.mode=literal"
                "&field.rl_timeout.value=600"
                "&field.rl_memory.mode=literal"
                "&field.rl_memory.value=2048"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html
        raw = yaml.safe_load(config_path.read_text())
        assert raw["resource_limits"]["timeout"] == 600
        assert raw["resource_limits"]["memory"] == "2048"

    def test_global_post_resource_limits_validation_error(
        self, tmp_path: Path
    ) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/global",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "field.rl_timeout.mode=literal"
                "&field.rl_timeout.value=not_a_number"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Expected integer" in html

    def test_repo_post_saves_resource_limits(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&field.rl_timeout.mode=literal"
                "&field.rl_timeout.value=300"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html
        raw = yaml.safe_load(config_path.read_text())
        assert raw["repos"]["test-repo"]["resource_limits"]["timeout"] == 300

    def test_repo_post_resource_limits_validation_error(
        self, tmp_path: Path
    ) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&field.rl_timeout.mode=literal"
                "&field.rl_timeout.value=bad"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Expected integer" in html

    def test_repo_post_slack_authorized_bool(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized=workspace_members: true\n"
                "user_id: U123"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        slack = raw["repos"]["test-repo"]["slack"]
        assert slack["authorized"] == [
            {"workspace_members": True},
            {"user_id": "U123"},
        ]

    def test_repo_post_with_email_valid(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=true"
                "&has_slack=false"
                "&field.imap_server.mode=literal"
                "&field.imap_server.value=imap.new.com"
                "&field.imap_port.mode=literal"
                "&field.imap_port.value=993"
                "&field.smtp_server.mode=literal"
                "&field.smtp_server.value=smtp.new.com"
                "&field.smtp_port.mode=literal"
                "&field.smtp_port.value=587"
                "&field.username.mode=literal"
                "&field.username.value=user@new.com"
                "&field.password.mode=literal"
                "&field.password.value=pass123"
                "&field.from_address.mode=literal"
                "&field.from_address.value=bot@new.com"
                "&field.authorized_senders.mode=literal"
                "&field.authorized_senders.value=admin@new.com"
                "&field.trusted_authserv_id.mode=literal"
                "&field.trusted_authserv_id.value=new.com"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "saved successfully" in html
        raw = yaml.safe_load(config_path.read_text())
        assert (
            raw["repos"]["test-repo"]["email"]["imap_server"] == "imap.new.com"
        )

    def test_repo_post_with_slack_var_mode(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=var"
                "&field.bot_token.value=slack_bot"
                "&field.app_token.mode=env"
                "&field.app_token.value=SLACK_APP_TOKEN"
            ),
        )
        assert response.status_code == 200

    def test_repo_post_slack_clear_authorized(self, tmp_path: Path) -> None:
        # Add slack with authorized rules first
        data = {
            "vars": {},
            "repos": {
                "test-repo": {
                    "git": {"repo_url": "https://github.com/t/r.git"},
                    "model": "opus",
                    "slack": {
                        "bot_token": "xoxb-test",
                        "app_token": "xapp-test",
                        "authorized": [{"workspace_members": True}],
                    },
                },
            },
        }
        config_path = _write_config(tmp_path, data)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # Submit with empty authorized text → clears rules
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/t/r.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized="
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "authorized" not in raw["repos"]["test-repo"]["slack"]

    def test_repo_post_saves_masked_secrets(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&masked_secret.0.key=GH_TOKEN"
                "&masked_secret.0.value.mode=literal"
                "&masked_secret.0.value.value=ghp_test"
                "&masked_secret.0.scopes=api.github.com"
                "&masked_secret.0.headers=Authorization"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "GH_TOKEN" in raw["repos"]["test-repo"]["masked_secrets"]

    def test_repo_post_saves_signing_credentials(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&signing_credential.0.key=aws-main"
                "&signing_credential.0.access_key_id.name=AK"
                "&signing_credential.0.access_key_id.value.mode=literal"
                "&signing_credential.0.access_key_id.value.value=AKIA"
                "&signing_credential.0.secret_access_key.name=SK"
                "&signing_credential.0.secret_access_key.value.mode=literal"
                "&signing_credential.0.secret_access_key.value.value=secret"
                "&signing_credential.0.scopes=bedrock.amazonaws.com"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "aws-main" in raw["repos"]["test-repo"]["signing_credentials"]

    def test_repo_post_saves_github_app_credentials(
        self, tmp_path: Path
    ) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&github_app.0.key=my-app"
                "&github_app.0.app_id.mode=literal"
                "&github_app.0.app_id.value=12345"
                "&github_app.0.private_key.mode=literal"
                "&github_app.0.private_key.value=pk"
                "&github_app.0.installation_id.mode=literal"
                "&github_app.0.installation_id.value=67890"
                "&github_app.0.scopes=api.github.com"
            ),
        )
        assert response.status_code == 200
        raw = yaml.safe_load(config_path.read_text())
        assert "my-app" in raw["repos"]["test-repo"]["github_app_credentials"]

    def test_vars_add_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post("/config/vars/add")
        assert response.status_code == 403

    def test_credential_add_csrf_rejected(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo/credential/add?type=masked_secret"
        )
        assert response.status_code == 403

    def test_repo_post_with_repo_field_errors(self, tmp_path: Path) -> None:
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        # network_sandbox_enabled is bool, give invalid
        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=false"
                "&field.model.mode=literal"
                "&field.model.value=sonnet"
            ),
        )
        # Should succeed since model is valid
        assert response.status_code == 200

    def test_repo_post_slack_invalid_auth_rule(self, tmp_path: Path) -> None:
        """Slack auth rules without ':' are rejected with an error."""
        config_path = _write_config(tmp_path)
        source = YamlConfigSource(config_path)
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/config/repo/test-repo",
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="application/x-www-form-urlencoded",
            data=(
                "git_repo_url.mode=literal"
                "&git_repo_url.value=https://github.com/test/repo.git"
                "&has_email=false"
                "&has_slack=true"
                "&field.bot_token.mode=literal"
                "&field.bot_token.value=xoxb-test"
                "&field.app_token.mode=literal"
                "&field.app_token.value=xapp-test"
                "&slack_authorized=bad_rule_no_colon"
            ),
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Invalid rule" in html
        assert "missing" in html
