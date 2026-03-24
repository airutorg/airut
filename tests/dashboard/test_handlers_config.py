# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor HTTP handlers."""

import json
from pathlib import Path
from typing import Any

from werkzeug.test import Client

from airut.config.snapshot import ConfigSnapshot
from airut.config.source import ConfigSource, YamlConfigSource
from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import TaskTracker
from airut.gateway.config import (
    EmailChannelConfig,
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)


def _make_config_snapshot() -> ConfigSnapshot[ServerConfig]:
    """Create a minimal ServerConfig snapshot for testing."""
    email = EmailChannelConfig(
        imap_server="mail.example.com",
        imap_port=993,
        smtp_server="smtp.example.com",
        smtp_port=587,
        username="user@example.com",
        password="secret",
        from_address="user@example.com",
        authorized_senders=["admin@example.com"],
        trusted_authserv_id="example.com",
    )
    repo = RepoServerConfig(
        repo_id="test-repo",
        git_repo_url="https://github.com/test/repo",
        channels={"email": email},
    )
    config = ServerConfig(
        global_config=GlobalConfig(),
        repos={"test-repo": repo},
    )
    raw: dict[str, Any] = {
        "config_version": 2,
        "repos": {
            "test-repo": {
                "git": {"repo_url": "https://github.com/test/repo"},
                "email": {
                    "imap_server": "mail.example.com",
                    "imap_port": 993,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "user@example.com",
                    "password": "secret",
                    "from": "user@example.com",
                    "authorized_senders": ["admin@example.com"],
                    "trusted_authserv_id": "example.com",
                },
            }
        },
    }
    return ConfigSnapshot(
        config, frozenset({"global_config", "repos"}), raw=raw
    )


def _make_server(
    *,
    generation: int = 0,
    config_source: ConfigSource | None = None,
) -> DashboardServer:
    """Create a DashboardServer with config editor enabled."""
    tracker = TaskTracker()
    snapshot = _make_config_snapshot()

    return DashboardServer(
        tracker=tracker,
        config_callback=lambda: snapshot,
        config_generation_callback=lambda: generation,
        config_source_callback=lambda: config_source,
        config_vars_callback=lambda: {},
    )


class TestConfigPageRoute:
    """Tests for GET /config."""

    def test_config_page_loads(self) -> None:
        """GET /config returns 200 with a form."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.get("/config")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "<form" in html
        assert "config-form" in html

    def test_config_page_has_generation(self) -> None:
        """Config page includes the generation as a hidden field."""
        server = _make_server(generation=42)
        client = Client(server._wsgi_app)
        response = client.get("/config")
        html = response.get_data(as_text=True)
        assert 'value="42"' in html

    def test_config_page_shows_global_fields(self) -> None:
        """Config page shows global config field docs."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.get("/config")
        html = response.get_data(as_text=True)
        assert "Maximum parallel Claude containers" in html

    def test_config_page_shows_repo_section(self) -> None:
        """Config page shows repository section."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.get("/config")
        html = response.get_data(as_text=True)
        assert "test-repo" in html

    def test_config_page_without_callbacks(self) -> None:
        """GET /config returns 404 when no config callbacks set."""
        tracker = TaskTracker()
        server = DashboardServer(tracker=tracker)
        client = Client(server._wsgi_app)
        response = client.get("/config")
        assert response.status_code == 404


class TestConfigSaveRoute:
    """Tests for POST /api/config."""

    def test_save_requires_csrf_header(self) -> None:
        """POST /api/config without X-Requested-With returns 403."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post("/api/config", data={"_generation": "0"})
        assert response.status_code == 403

    def test_save_stale_generation(self) -> None:
        """POST with old generation returns 409."""
        server = _make_server(generation=5)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config",
            data={"_generation": "3"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 409
        html = response.get_data(as_text=True)
        assert "changed externally" in html

    def test_save_validation_failure(self) -> None:
        """POST with invalid config returns 422."""
        server = _make_server(generation=0)
        client = Client(server._wsgi_app)
        # Submit empty config (no repos) which should fail validation
        response = client.post(
            "/api/config",
            data={"_generation": "0"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 422
        html = response.get_data(as_text=True)
        assert "Validation failed" in html

    def test_save_no_config_source(self) -> None:
        """POST with no config source returns 500."""
        server = _make_server(generation=0, config_source=None)
        client = Client(server._wsgi_app)
        # We need valid config data that passes validation.
        # Use a minimal valid config.
        response = client.post(
            "/api/config",
            data={
                "_generation": "0",
                "config_version._source": "literal",
                "config_version._value": "2",
                "repos.test-repo.git.repo_url._source": "literal",
                "repos.test-repo.git.repo_url._value": "https://github.com/test/repo",
                "repos.test-repo.email.imap_server._source": "literal",
                "repos.test-repo.email.imap_server._value": "mail.example.com",
                "repos.test-repo.email.imap_port._source": "literal",
                "repos.test-repo.email.imap_port._value": "993",
                "repos.test-repo.email.smtp_server._source": "literal",
                "repos.test-repo.email.smtp_server._value": "smtp.example.com",
                "repos.test-repo.email.smtp_port._source": "literal",
                "repos.test-repo.email.smtp_port._value": "587",
                "repos.test-repo.email.username._source": "literal",
                "repos.test-repo.email.username._value": "user@example.com",
                "repos.test-repo.email.password._source": "literal",
                "repos.test-repo.email.password._value": "secret",
                "repos.test-repo.email.from._source": "literal",
                "repos.test-repo.email.from._value": "user@example.com",
                "repos.test-repo.email.authorized_senders.0._source": "literal",
                "repos.test-repo.email.authorized_senders"
                ".0._value": "admin@example.com",
                "repos.test-repo.email.trusted_authserv_id._source": "literal",
                "repos.test-repo.email"
                ".trusted_authserv_id._value": "example.com",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 500
        html = response.get_data(as_text=True)
        assert "not available" in html

    def test_save_success(self, tmp_path: Path) -> None:
        """POST with valid config and source returns 200."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text("")
        source = YamlConfigSource(config_path)

        server = _make_server(generation=0, config_source=source)
        client = Client(server._wsgi_app)

        response = client.post(
            "/api/config",
            data={
                "_generation": "0",
                "config_version._source": "literal",
                "config_version._value": "2",
                "repos.test-repo.git.repo_url._source": "literal",
                "repos.test-repo.git.repo_url._value": "https://github.com/test/repo",
                "repos.test-repo.email.imap_server._source": "literal",
                "repos.test-repo.email.imap_server._value": "mail.example.com",
                "repos.test-repo.email.imap_port._source": "literal",
                "repos.test-repo.email.imap_port._value": "993",
                "repos.test-repo.email.smtp_server._source": "literal",
                "repos.test-repo.email.smtp_server._value": "smtp.example.com",
                "repos.test-repo.email.smtp_port._source": "literal",
                "repos.test-repo.email.smtp_port._value": "587",
                "repos.test-repo.email.username._source": "literal",
                "repos.test-repo.email.username._value": "user@example.com",
                "repos.test-repo.email.password._source": "literal",
                "repos.test-repo.email.password._value": "secret",
                "repos.test-repo.email.from._source": "literal",
                "repos.test-repo.email.from._value": "user@example.com",
                "repos.test-repo.email.authorized_senders.0._source": "literal",
                "repos.test-repo.email.authorized_senders"
                ".0._value": "admin@example.com",
                "repos.test-repo.email.trusted_authserv_id._source": "literal",
                "repos.test-repo.email"
                ".trusted_authserv_id._value": "example.com",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Saved" in html
        # Verify the file was written
        assert config_path.exists()
        content = config_path.read_text()
        assert "mail.example.com" in content


class TestConfigAddFragmentRoute:
    """Tests for POST /api/config/add."""

    def test_add_list_item(self) -> None:
        """POST add list_item returns HTML fragment."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={
                "type": "list_item",
                "path": "repos.test-repo.email.authorized_senders",
                "index": "1",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "cfg-list-item" in html

    def test_add_dict_entry(self) -> None:
        """POST add dict_entry returns HTML fragment."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={
                "type": "dict_entry",
                "path": "repos.test-repo.secrets",
                "index": "0",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "cfg-dict-entry" in html

    def test_add_requires_csrf(self) -> None:
        """POST add without X-Requested-With returns 403."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={"type": "list_item", "path": "foo", "index": "0"},
        )
        assert response.status_code == 403

    def test_add_unknown_type(self) -> None:
        """POST add with unknown type returns 400."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={"type": "unknown", "path": "foo", "index": "0"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400

    def test_add_invalid_index(self) -> None:
        """POST add with non-numeric index defaults to 0."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={"type": "list_item", "path": "foo", "index": "abc"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "foo.0" in html


class TestAtomicSave:
    """Tests for atomic YamlConfigSource.save()."""

    def test_save_uses_temp_rename(self, tmp_path: Path) -> None:
        """Save creates file atomically via temp+rename."""
        config_path = tmp_path / "test.yaml"
        source = YamlConfigSource(config_path)
        source.save({"foo": "bar"})

        assert config_path.exists()
        content = config_path.read_text()
        assert "foo" in content
        assert "bar" in content
        # Temp file should not remain
        assert not (tmp_path / "test.yaml.tmp").exists()


class TestDashboardConfigLink:
    """Tests for the Configure button in the dashboard."""

    def test_dashboard_has_config_link_when_enabled(self) -> None:
        """Dashboard shows Configure link when editor is enabled."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.get("/")
        assert response.status_code == 200

    def test_dashboard_no_config_link_when_disabled(self) -> None:
        """Dashboard without config editor doesn't show Configure."""
        tracker = TaskTracker()
        server = DashboardServer(tracker=tracker)
        client = Client(server._wsgi_app)
        response = client.get("/")
        html = response.get_data(as_text=True)
        assert "/config" not in html or "Configure" not in html


class TestConfigPageNotLoaded:
    """Test config page when snapshot is not available."""

    def test_config_page_snapshot_none(self) -> None:
        """GET /config returns 200 with error when snapshot is None."""
        tracker = TaskTracker()
        server = DashboardServer(
            tracker=tracker,
            config_callback=lambda: None,
            config_generation_callback=lambda: 0,
            config_source_callback=lambda: None,
            config_vars_callback=lambda: {},
        )
        client = Client(server._wsgi_app)
        response = client.get("/config")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "not loaded" in html


class TestConfigSaveEdgeCases:
    """Edge cases for POST /api/config."""

    def test_save_bad_generation(self) -> None:
        """POST with non-numeric generation returns 409."""
        server = _make_server(generation=0)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config",
            data={"_generation": "not_a_number"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 409

    def test_save_write_failure(self, tmp_path: Path) -> None:
        """POST returns 500 when source.save() raises."""
        from unittest.mock import MagicMock

        source = MagicMock()
        source.save.side_effect = OSError("disk full")

        server = _make_server(generation=0, config_source=source)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config",
            data={
                "_generation": "0",
                "config_version._source": "literal",
                "config_version._value": "2",
                "repos.test-repo.git.repo_url._source": "literal",
                "repos.test-repo.git.repo_url._value": (
                    "https://github.com/test/repo"
                ),
                "repos.test-repo.email.imap_server._source": "literal",
                "repos.test-repo.email.imap_server._value": (
                    "mail.example.com"
                ),
                "repos.test-repo.email.imap_port._source": "literal",
                "repos.test-repo.email.imap_port._value": "993",
                "repos.test-repo.email.smtp_server._source": "literal",
                "repos.test-repo.email.smtp_server._value": (
                    "smtp.example.com"
                ),
                "repos.test-repo.email.smtp_port._source": "literal",
                "repos.test-repo.email.smtp_port._value": "587",
                "repos.test-repo.email.username._source": "literal",
                "repos.test-repo.email.username._value": ("user@example.com"),
                "repos.test-repo.email.password._source": "literal",
                "repos.test-repo.email.password._value": "secret",
                "repos.test-repo.email.from._source": "literal",
                "repos.test-repo.email.from._value": ("user@example.com"),
                "repos.test-repo.email.authorized_senders.0._source": "literal",
                "repos.test-repo.email.authorized_senders.0._value": (
                    "admin@example.com"
                ),
                "repos.test-repo.email.trusted_authserv_id._source": "literal",
                "repos.test-repo.email"
                ".trusted_authserv_id._value": "example.com",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 500
        html = response.get_data(as_text=True)
        assert "Save failed" in html


class TestConfigAddFragmentTypes:
    """Tests for all add-fragment types."""

    def test_add_collection_entry(self) -> None:
        """POST add collection_entry returns HTML fragment."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={
                "type": "collection_entry",
                "path": "repos.test-repo.secrets",
                "index": "0",
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "cfg-collection-entry" in html

    def test_add_tagged_union_item(self) -> None:
        """POST add tagged_union_item returns HTML fragment."""
        server = _make_server()
        client = Client(server._wsgi_app)
        rules = json.dumps([["workspace_members", "bool", "All members"]])
        response = client.post(
            "/api/config/add",
            data={
                "type": "tagged_union_item",
                "path": "repos.test-repo.slack.authorized",
                "index": "0",
                "rules": rules,
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "cfg-union-item" in html

    def test_add_tagged_union_bad_json(self) -> None:
        """POST tagged_union_item with bad JSON still works."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={
                "type": "tagged_union_item",
                "path": "foo",
                "index": "0",
                "rules": "not_json",
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        assert response.status_code == 200

    def test_add_with_bad_json_body(self) -> None:
        """POST /api/config/add with bad JSON body returns 400."""
        server = _make_server()
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data="not json at all",
            content_type="application/json",
            headers={
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        # With bad JSON, data is {}, type is "", which is unknown
        assert response.status_code == 400


class TestConfigDisabledRoutes:
    """Tests for config routes when editor is disabled."""

    def test_save_disabled(self) -> None:
        """POST /api/config returns 404 when disabled."""
        tracker = TaskTracker()
        server = DashboardServer(tracker=tracker)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config",
            data={"_generation": "0"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 404

    def test_add_disabled(self) -> None:
        """POST /api/config/add returns 404 when disabled."""
        tracker = TaskTracker()
        server = DashboardServer(tracker=tracker)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/add",
            data={
                "type": "list_item",
                "path": "foo",
                "index": "0",
            },
            headers={
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        assert response.status_code == 404
