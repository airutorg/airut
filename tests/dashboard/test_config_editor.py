# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor dashboard endpoints."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml
from werkzeug.test import Client

from airut.config.snapshot import ConfigSnapshot
from airut.config.source import YamlConfigSource, make_tag_dumper
from airut.dashboard.config_handlers import (
    field_change_to_dict,
    json_safe,
    preview_to_dict,
)
from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import TaskTracker
from airut.gateway.config import ServerConfig
from airut.yaml_env import EnvVar, VarRef


def _make_config_file(
    tmp_path: Path,
    *,
    model: str = "opus",
    max_concurrent: int = 3,
) -> Path:
    """Create a minimal valid config YAML file."""
    config = {
        "config_version": 2,
        "execution": {"max_concurrent": max_concurrent},
        "repos": {
            "test-repo": {
                "git": {"repo_url": "https://github.com/test/repo"},
                "email": {
                    "imap_server": "imap.example.com",
                    "imap_port": 993,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "bot@example.com",
                    "password": "secret",
                    "from": "bot@example.com",
                    "authorized_senders": ["admin@example.com"],
                    "trusted_authserv_id": "example.com",
                },
                "model": model,
            }
        },
    }
    config_path = tmp_path / "airut.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f, Dumper=make_tag_dumper(), default_flow_style=False)
    return config_path


def _make_server_with_config(
    tmp_path: Path,
    *,
    model: str = "opus",
    max_concurrent: int = 3,
    generation: int = 1,
) -> tuple[DashboardServer, Path]:
    """Create a DashboardServer with config_callback configured."""
    config_path = _make_config_file(
        tmp_path, model=model, max_concurrent=max_concurrent
    )
    source = YamlConfigSource(config_path)
    snapshot = ServerConfig.from_source(source)

    def config_callback() -> (
        tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
    ):
        return (snapshot, source, generation)

    tracker = TaskTracker()
    server = DashboardServer(
        tracker,
        config_callback=config_callback,
        status_callback=lambda: {
            "config_generation": generation,
            "server_reload_pending": False,
            "last_reload_error": None,
        },
    )
    return server, config_path


class TestConfigEditorPage:
    def test_renders_page(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.get("/config")
        assert response.status_code == 200
        assert b"Config Editor" in response.data

    def test_unavailable_without_callback(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)
        response = client.get("/config")
        assert response.status_code == 200
        assert b"not available" in response.data

    def test_unavailable_when_callback_returns_none(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_callback=lambda: None)
        client = Client(server._wsgi_app)
        response = client.get("/config")
        assert response.status_code == 200
        assert b"not available" in response.data


class TestApiConfigSchema:
    def test_returns_schema(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.get("/api/config/schema")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "global" in data
        assert "repo" in data
        assert "email_channel" in data

    def test_schema_has_yaml_paths(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.get("/api/config/schema")
        data = json.loads(response.data)
        for field in data["global"]:
            assert "yaml_path" in field

    def test_cache_header(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.get("/api/config/schema")
        assert "Cache-Control" in response.headers


class TestApiConfigLoad:
    def test_returns_config(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path, generation=5)
        client = Client(server._wsgi_app)
        response = client.get("/api/config")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["config_generation"] == 5
        assert "config" in data
        assert "repos" in data["config"]

    def test_unavailable_without_callback(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)
        response = client.get("/api/config")
        assert response.status_code == 503

    def test_unavailable_when_callback_returns_none(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_callback=lambda: None)
        client = Client(server._wsgi_app)
        response = client.get("/api/config")
        assert response.status_code == 503

    def test_unavailable_when_raw_is_none(self, tmp_path: Path) -> None:
        """GET /api/config returns 503 when snapshot.raw is None."""
        config_path = _make_config_file(tmp_path)
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.from_source(source)
        # Force raw to None (omit raw= parameter)
        snapshot = ConfigSnapshot(snapshot.value, frozenset())

        def config_cb() -> (
            tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
        ):
            return (snapshot, source, 1)

        tracker = TaskTracker()
        server = DashboardServer(tracker, config_callback=config_cb)
        client = Client(server._wsgi_app)
        response = client.get("/api/config")
        assert response.status_code == 503

    def test_returns_tag_markers(self, tmp_path: Path) -> None:
        """Verify EnvVar/VarRef are encoded as __tag__ markers."""
        config_path = tmp_path / "airut.yaml"
        config_content = {
            "config_version": 2,
            "vars": {
                "mail_pw": EnvVar("MAIL_PASSWORD"),
            },
            "execution": {"max_concurrent": 3},
            "repos": {
                "test-repo": {
                    "git": {"repo_url": "https://github.com/test/repo"},
                    "email": {
                        "imap_server": "imap.example.com",
                        "imap_port": 993,
                        "smtp_server": "smtp.example.com",
                        "smtp_port": 587,
                        "username": "bot@example.com",
                        "password": VarRef("mail_pw"),
                        "from": "bot@example.com",
                        "authorized_senders": ["admin@example.com"],
                        "trusted_authserv_id": "example.com",
                    },
                }
            },
        }
        with open(config_path, "w") as f:
            yaml.dump(
                config_content,
                f,
                Dumper=make_tag_dumper(),
                default_flow_style=False,
            )

        source = YamlConfigSource(config_path)
        with patch.dict("os.environ", {"MAIL_PASSWORD": "secret123"}):
            snapshot = ServerConfig.from_source(source)

        def config_cb() -> (
            tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
        ):
            return (snapshot, source, 1)

        tracker = TaskTracker()
        server = DashboardServer(tracker, config_callback=config_cb)
        client = Client(server._wsgi_app)
        response = client.get("/api/config")
        data = json.loads(response.data)
        # Check that vars section has __tag__ markers
        vars_section = data["config"].get("vars", {})
        assert vars_section["mail_pw"]["__tag__"] == "env"
        # Check that password has __tag__ var marker
        password = data["config"]["repos"]["test-repo"]["email"]["password"]
        assert password["__tag__"] == "var"


class TestApiConfigPreview:
    def test_valid_preview(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        # Load current config
        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        # Change model
        config["repos"]["test-repo"]["model"] = "sonnet"

        response = client.post(
            "/api/config/preview",
            data=json.dumps({"config": config}),
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["valid"] is True
        assert result["diff"] is not None

    def test_invalid_config_preview(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        # Load then break config
        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]
        del config["repos"]["test-repo"]["git"]

        response = client.post(
            "/api/config/preview",
            data=json.dumps({"config": config}),
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        result = json.loads(response.data)
        assert result["valid"] is False
        assert result["error"] is not None

    def test_requires_csrf_header(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/preview",
            data="{}",
            content_type="application/json",
        )
        assert response.status_code == 403

    def test_unavailable_without_callback(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/preview",
            data="{}",
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 503

    def test_unavailable_when_callback_returns_none(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_callback=lambda: None)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/preview",
            data="{}",
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 503

    def test_invalid_json(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/preview",
            data="not json",
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400

    def test_no_changes(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        response = client.post(
            "/api/config/preview",
            data=json.dumps({"config": config}),
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        result = json.loads(response.data)
        assert result["valid"] is True
        assert result["warnings"] == []


class TestApiConfigSave:
    def test_requires_csrf_header(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/save",
            data="{}",
            content_type="application/json",
        )
        assert response.status_code == 403

    def test_unavailable_without_callback(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/save",
            data="{}",
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 503

    def test_unavailable_when_callback_returns_none(self) -> None:
        tracker = TaskTracker()
        server = DashboardServer(tracker, config_callback=lambda: None)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/save",
            data="{}",
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 503

    def test_invalid_json(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)
        response = client.post(
            "/api/config/save",
            data="not json",
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400

    def test_missing_config_generation(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        response = client.post(
            "/api/config/save",
            data=json.dumps({"config": config}),
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400
        result = json.loads(response.data)
        assert "config_generation" in result["error"]

    def test_missing_config_key(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        response = client.post(
            "/api/config/save",
            data=json.dumps({"config_generation": 1}),
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400
        result = json.loads(response.data)
        assert "config" in result["error"]

    def test_stale_generation(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path, generation=5)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        response = client.post(
            "/api/config/save",
            data=json.dumps(
                {
                    "config_generation": 3,  # stale
                    "config": config,
                }
            ),
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 409

    def test_invalid_config_rejected(self, tmp_path: Path) -> None:
        server, _ = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]
        del config["repos"]["test-repo"]["git"]

        response = client.post(
            "/api/config/save",
            data=json.dumps(
                {
                    "config_generation": 1,
                    "config": config,
                }
            ),
            content_type="application/json",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400

    def test_successful_save(self, tmp_path: Path) -> None:
        server, config_path = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        # Modify model
        config["repos"]["test-repo"]["model"] = "sonnet"

        with patch("airut.dashboard.config_handlers.time") as mock_time:
            mock_time.sleep = MagicMock()
            response = client.post(
                "/api/config/save",
                data=json.dumps(
                    {
                        "config_generation": 1,
                        "config": config,
                    }
                ),
                content_type="application/json",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["saved"] is True

        # Verify file was written
        saved = yaml.safe_load(config_path.read_text())
        assert saved["repos"]["test-repo"]["model"] == "sonnet"

    def test_reload_detected_with_status_callback(self, tmp_path: Path) -> None:
        """Save detects generation change and reports 'applied'."""
        config_path = _make_config_file(tmp_path)
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.from_source(source)

        call_count = 0

        def config_cb() -> (
            tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
        ):
            nonlocal call_count
            call_count += 1
            # First call (during save validation): generation=1
            # Polling calls: return generation=2 to signal reload
            gen = 1 if call_count <= 2 else 2
            return (snapshot, source, gen)

        tracker = TaskTracker()
        server = DashboardServer(
            tracker,
            config_callback=config_cb,
            status_callback=lambda: {
                "last_reload_error": None,
                "server_reload_pending": False,
            },
        )
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        with patch("airut.dashboard.config_handlers.time") as mock_time:
            mock_time.sleep = MagicMock()
            response = client.post(
                "/api/config/save",
                data=json.dumps({"config_generation": 1, "config": config}),
                content_type="application/json",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        result = json.loads(response.data)
        assert result["saved"] is True
        assert result["reload_status"] == "applied"
        assert result["config_generation"] == 2

    def test_reload_error_detected(self, tmp_path: Path) -> None:
        """Save detects reload error from status callback."""
        config_path = _make_config_file(tmp_path)
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.from_source(source)

        call_count = 0

        def config_cb() -> (
            tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
        ):
            nonlocal call_count
            call_count += 1
            gen = 1 if call_count <= 2 else 2
            return (snapshot, source, gen)

        tracker = TaskTracker()
        server = DashboardServer(
            tracker,
            config_callback=config_cb,
            status_callback=lambda: {
                "last_reload_error": "validation failed",
                "server_reload_pending": False,
            },
        )
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        with patch("airut.dashboard.config_handlers.time") as mock_time:
            mock_time.sleep = MagicMock()
            response = client.post(
                "/api/config/save",
                data=json.dumps({"config_generation": 1, "config": config}),
                content_type="application/json",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        result = json.loads(response.data)
        assert result["reload_status"] == "reload_error"

    def test_reload_server_pending_warning(self, tmp_path: Path) -> None:
        """Save includes warning when server-scope changes are pending."""
        config_path = _make_config_file(tmp_path)
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.from_source(source)

        call_count = 0

        def config_cb() -> (
            tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
        ):
            nonlocal call_count
            call_count += 1
            gen = 1 if call_count <= 2 else 2
            return (snapshot, source, gen)

        tracker = TaskTracker()
        server = DashboardServer(
            tracker,
            config_callback=config_cb,
            status_callback=lambda: {
                "last_reload_error": None,
                "server_reload_pending": True,
            },
        )
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        with patch("airut.dashboard.config_handlers.time") as mock_time:
            mock_time.sleep = MagicMock()
            response = client.post(
                "/api/config/save",
                data=json.dumps({"config_generation": 1, "config": config}),
                content_type="application/json",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        result = json.loads(response.data)
        assert result["reload_status"] == "applied"
        assert any("server-scope" in w for w in result["warnings"])

    def test_reload_without_status_callback(self, tmp_path: Path) -> None:
        """Save works when no status_callback is set."""
        config_path = _make_config_file(tmp_path)
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.from_source(source)

        call_count = 0

        def config_cb() -> (
            tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
        ):
            nonlocal call_count
            call_count += 1
            gen = 1 if call_count <= 2 else 2
            return (snapshot, source, gen)

        tracker = TaskTracker()
        # No status_callback
        server = DashboardServer(tracker, config_callback=config_cb)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        with patch("airut.dashboard.config_handlers.time") as mock_time:
            mock_time.sleep = MagicMock()
            response = client.post(
                "/api/config/save",
                data=json.dumps({"config_generation": 1, "config": config}),
                content_type="application/json",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        result = json.loads(response.data)
        assert result["reload_status"] == "applied"
        assert result["config_generation"] == 2

    def test_callback_none_during_polling(self, tmp_path: Path) -> None:
        """Save handles callback returning None during poll."""
        config_path = _make_config_file(tmp_path)
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.from_source(source)

        call_count = 0

        def config_cb() -> (
            tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
        ):
            nonlocal call_count
            call_count += 1
            # Return valid for initial calls, None during polling
            if call_count <= 2:
                return (snapshot, source, 1)
            return None

        tracker = TaskTracker()
        server = DashboardServer(tracker, config_callback=config_cb)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        with patch("airut.dashboard.config_handlers.time") as mock_time:
            mock_time.sleep = MagicMock()
            response = client.post(
                "/api/config/save",
                data=json.dumps({"config_generation": 1, "config": config}),
                content_type="application/json",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        result = json.loads(response.data)
        assert result["saved"] is True
        assert result["reload_status"] == "pending"

    def test_creates_backup(self, tmp_path: Path) -> None:
        server, config_path = _make_server_with_config(tmp_path)
        client = Client(server._wsgi_app)

        response = client.get("/api/config")
        data = json.loads(response.data)
        config = data["config"]

        with patch("airut.dashboard.config_handlers.time") as mock_time:
            mock_time.sleep = MagicMock()
            response = client.post(
                "/api/config/save",
                data=json.dumps(
                    {
                        "config_generation": 1,
                        "config": config,
                    }
                ),
                content_type="application/json",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

        assert response.status_code == 200
        backups = list(tmp_path.glob("*.bak"))
        assert len(backups) == 1


class TestJsonSafeHelper:
    def test_primitives(self) -> None:
        assert json_safe("hello") == "hello"
        assert json_safe(42) == 42
        assert json_safe(3.14) == 3.14
        assert json_safe(True) is True
        assert json_safe(None) is None

    def test_dict(self) -> None:
        assert json_safe({"a": 1}) == {"a": 1}

    def test_list(self) -> None:
        assert json_safe([1, "two"]) == [1, "two"]

    def test_tuple(self) -> None:
        assert json_safe((1, 2)) == [1, 2]

    def test_frozenset(self) -> None:
        result = json_safe(frozenset(["b", "a"]))
        assert result == ["a", "b"]

    def test_dataclass(self) -> None:
        from dataclasses import dataclass

        @dataclass
        class Dummy:
            x: int = 1

        result = json_safe(Dummy())
        assert result == {"x": 1}

    def test_other_types(self) -> None:
        result = json_safe(object())
        assert isinstance(result, str)


class TestFieldChangeToDict:
    def test_basic(self) -> None:
        from airut.config.editor import FieldChange

        fc = FieldChange(
            field="model", doc="Model", old="opus", new="sonnet", repo="test"
        )
        d = field_change_to_dict(fc)
        assert d["field"] == "model"
        assert d["old"] == "opus"
        assert d["new"] == "sonnet"
        assert d["repo"] == "test"


class TestPreviewToDict:
    def test_valid(self) -> None:
        from airut.config.editor import FieldChange, PreviewResult

        result = PreviewResult(
            valid=True,
            error=None,
            diff={
                "server": [
                    FieldChange("f1", "doc1", 1, 2, None),
                ],
                "repo": [],
                "task": [],
            },
            warnings=["warn1"],
        )
        d = preview_to_dict(result)
        assert d["valid"] is True
        assert d["error"] is None
        diff = d["diff"]
        assert isinstance(diff, dict)
        assert len(diff["server"]) == 1
        assert d["warnings"] == ["warn1"]

    def test_invalid(self) -> None:
        from airut.config.editor import PreviewResult

        result = PreviewResult(valid=False, error="bad", diff=None, warnings=[])
        d = preview_to_dict(result)
        assert d["valid"] is False
        assert d["diff"] is None
