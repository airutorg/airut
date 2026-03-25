# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor HTTP handlers."""

import copy
from pathlib import Path
from typing import Any

import pytest
from werkzeug.test import Client

from airut.config.snapshot import ConfigSnapshot
from airut.config.source import YamlConfigSource
from airut.dashboard.server import DashboardServer
from airut.dashboard.tracker import TaskTracker
from airut.yaml_env import EnvVar
from tests.conftest import make_sample_raw as _make_sample_raw


def _make_snapshot(raw: dict[str, Any] | None = None) -> ConfigSnapshot:
    """Create a ConfigSnapshot from raw dict."""
    from airut.config.editor import InMemoryConfigSource
    from airut.gateway.config import ServerConfig

    if raw is None:
        raw = _make_sample_raw()
    return ServerConfig.from_source(InMemoryConfigSource(copy.deepcopy(raw)))


XHR: dict[str, str] = {"X-Requested-With": "XMLHttpRequest"}


class ConfigEditorHarness:
    """Test harness for config editor endpoints."""

    def __init__(
        self,
        tmp_path: Path,
        raw: dict[str, Any] | None = None,
    ) -> None:
        self.tmp_path = tmp_path
        self.raw = raw or _make_sample_raw()
        self._snapshot = _make_snapshot(self.raw)
        self._generation = 0
        self._config_path = tmp_path / "airut.yaml"
        self._config_source = YamlConfigSource(self._config_path)

        self.tracker = TaskTracker()
        self.server = DashboardServer(
            self.tracker,
            get_config_snapshot=lambda: self._snapshot,
            get_config_generation=lambda: self._generation,
            get_config_source=lambda: self._config_source,
        )
        self.client = Client(self.server._wsgi_app)

    @classmethod
    def no_snapshot(cls, tmp_path: Path) -> "ConfigEditorHarness":
        """Create a harness with no config snapshot (no file source)."""
        h = cls.__new__(cls)
        h.tmp_path = tmp_path
        h.tracker = TaskTracker()
        h.server = DashboardServer(
            h.tracker,
            get_config_snapshot=lambda: None,
            get_config_generation=lambda: 0,
            get_config_source=lambda: None,
        )
        h.client = Client(h.server._wsgi_app)
        return h

    def bump_generation(self) -> None:
        self._generation += 1


@pytest.fixture
def harness(tmp_path: Path) -> ConfigEditorHarness:
    return ConfigEditorHarness(tmp_path)


class TestHelperFunctions:
    """Tests for module-level helper functions in handlers_config."""

    def test_value_source_env(self) -> None:
        from airut.config.editor import value_source as _value_source

        src, val = _value_source(EnvVar("MY_VAR"))
        assert src == "env"
        assert val == "MY_VAR"

    def test_value_source_var(self) -> None:
        from airut.config.editor import value_source as _value_source
        from airut.yaml_env import VarRef

        src, val = _value_source(VarRef("my_ref"))
        assert src == "var"
        assert val == "my_ref"

    def test_value_source_missing(self) -> None:
        from airut.config.editor import MISSING
        from airut.config.editor import value_source as _value_source

        src, val = _value_source(MISSING)
        assert src == "unset"
        assert val is None

    def test_value_source_literal(self) -> None:
        from airut.config.editor import value_source as _value_source

        src, val = _value_source(42)
        assert src == "literal"
        assert val == 42

    def test_coerce_value_none(self) -> None:
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value(None, "str") is None

    def test_coerce_value_int(self) -> None:
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value("42", "int") == 42

    def test_coerce_value_float(self) -> None:
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value("3.14", "float") == 3.14

    def test_coerce_value_bool_str(self) -> None:
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value("true", "bool") is True
        assert _coerce_value("false", "bool") is False

    def test_coerce_value_bool_int(self) -> None:
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value(1, "bool") is True
        assert _coerce_value(0, "bool") is False

    def test_coerce_value_str(self) -> None:
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value(42, "str") == "42"

    def test_coerce_value_bool_to_int(self) -> None:
        """Boolean must coerce to int, not crash."""
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value(True, "int") == 1
        assert _coerce_value(False, "int") == 0

    def test_coerce_value_bool_to_float(self) -> None:
        """Boolean must coerce to float, not crash."""
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value(True, "float") == 1.0
        assert _coerce_value(False, "float") == 0.0

    def test_coerce_value_invalid_string_to_int(self) -> None:
        """Non-numeric string for int type must raise ValueError."""
        from airut.dashboard.handlers_config import _coerce_value

        with pytest.raises(ValueError):
            _coerce_value("not_a_number", "int")

    def test_coerce_value_invalid_string_to_float(self) -> None:
        """Non-numeric string for float type must raise ValueError."""
        from airut.dashboard.handlers_config import _coerce_value

        with pytest.raises(ValueError):
            _coerce_value("not_a_number", "float")

    def test_find_field_schema_not_found(self) -> None:
        from airut.dashboard.handlers_config import _find_field_schema

        assert _find_field_schema([], "nonexistent") is None

    def test_find_field_schema_nested(self) -> None:
        from airut.config.editor import EditorFieldSchema
        from airut.dashboard.handlers_config import _find_field_schema

        inner = EditorFieldSchema(
            name="timeout",
            path="limits.timeout",
            type_tag="scalar",
            python_type="int",
            default=60,
            required=False,
            doc="Timeout",
            scope="task",
            secret=False,
        )
        outer = EditorFieldSchema(
            name="limits",
            path="limits",
            type_tag="nested",
            python_type="Limits",
            default=None,
            required=False,
            doc="Limits",
            scope="server",
            secret=False,
            nested_fields=[inner],
        )
        found = _find_field_schema([outer], "limits.timeout")
        assert found is not None
        assert found.name == "timeout"

    def test_format_value_none(self) -> None:
        from airut.config.editor import format_raw_value as _format_value

        assert _format_value(None) == "(not set)"

    def test_format_value_bool(self) -> None:
        from airut.config.editor import format_raw_value as _format_value

        assert _format_value(True) == "true"
        assert _format_value(False) == "false"

    def test_format_value_str(self) -> None:
        from airut.config.editor import format_raw_value as _format_value

        assert _format_value(42) == "42"

    def test_format_value_missing(self) -> None:
        from airut.config.editor import MISSING
        from airut.config.editor import format_raw_value as _format_value

        assert _format_value(MISSING) == "(not set)"

    def test_format_value_env_var(self) -> None:
        from airut.config.editor import format_raw_value as _format_value

        assert _format_value(EnvVar("HOST")) == "!env HOST"

    def test_format_value_var_ref(self) -> None:
        from airut.config.editor import format_raw_value as _format_value
        from airut.yaml_env import VarRef

        assert _format_value(VarRef("my_var")) == "!var my_var"

    def test_raw_values_equal_type_mismatch(self) -> None:
        from airut.config.editor import raw_values_equal as _raw_values_equal

        assert not _raw_values_equal(EnvVar("X"), "X")

    def test_raw_values_equal_env_var(self) -> None:
        from airut.config.editor import raw_values_equal as _raw_values_equal

        assert _raw_values_equal(EnvVar("X"), EnvVar("X"))
        assert not _raw_values_equal(EnvVar("X"), EnvVar("Y"))

    def test_raw_values_equal_var_ref(self) -> None:
        from airut.config.editor import raw_values_equal as _raw_values_equal
        from airut.yaml_env import VarRef

        assert _raw_values_equal(VarRef("a"), VarRef("a"))
        assert not _raw_values_equal(VarRef("a"), VarRef("b"))

    def test_get_raw_value_none_raw(self) -> None:
        from airut.config.editor import MISSING
        from airut.config.editor import get_raw_value as _get_raw_value

        assert _get_raw_value(None, "foo.bar") is MISSING


class TestConfigPageLoads:
    def test_config_page_returns_200(
        self, harness: ConfigEditorHarness
    ) -> None:
        response = harness.client.get("/config")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Configuration" in html

    def test_config_page_shows_fields(
        self, harness: ConfigEditorHarness
    ) -> None:
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert "Execution" in html
        assert "Dashboard" in html
        assert "Container" in html

    def test_config_page_shows_field_paths(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Field labels display full YAML paths, not bare field names."""
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert "dashboard.port" in html
        assert "execution.max_concurrent" in html

    def test_config_page_shows_default_button(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Source selector uses 'Default' label instead of 'Not set'."""
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert "Default" in html
        assert "Not set" not in html

    def test_config_page_shows_repos(
        self, harness: ConfigEditorHarness
    ) -> None:
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert "test-repo" in html

    def test_config_page_creates_buffer(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        assert harness.server._config_handlers._buffer is not None

    def test_save_buttons_disabled_initially(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Save/discard buttons are disabled when there are no changes."""
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert 'id="review-save-btn"' in html
        assert "disabled" in html

    def test_config_page_navbar_not_duplicated(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Config page must render the navbar exactly once."""
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert html.count('class="navbar"') == 1

    def test_config_page_no_snapshot(self, tmp_path: Path) -> None:
        """No snapshot -> error message."""
        h = ConfigEditorHarness.no_snapshot(tmp_path)
        response = h.client.get("/config")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "No config available" in html


class TestFieldPatch:
    def test_patch_field_literal(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")

        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.port",
                "source": "literal",
                "value": "5201",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["dashboard"]["port"] == 5201

    def test_patch_field_env(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.host",
                "source": "env",
                "value": "DASH_HOST",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert isinstance(buf.raw["dashboard"]["host"], EnvVar)

    def test_patch_field_unset(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={"path": "dashboard.base_url", "source": "unset"},
            headers=XHR,
        )
        assert response.status_code == 200

    def test_patch_unset_renders_disabled_input(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Unset (Default) state renders a disabled input with default value."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={"path": "dashboard.port", "source": "unset"},
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "disabled" in html
        assert "<input" in html
        assert "Default" in html

    def test_patch_unset_bool_renders_disabled_select(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Unset bool field renders a disabled select with lowercase default."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={"path": "dashboard.enabled", "source": "unset"},
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "disabled" in html
        assert "<select" in html
        # Option text must use lowercase "true" (not Python's "True")
        assert "<option>true</option>" in html

    def test_patch_succeeds_on_stale(
        self, harness: ConfigEditorHarness
    ) -> None:
        """PATCH should work even when buffer is stale."""
        harness.client.get("/config")
        harness.bump_generation()

        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.port",
                "source": "literal",
                "value": "9999",
            },
            headers=XHR,
        )
        assert response.status_code == 200

    def test_patch_field_string_coerced_to_int(
        self, harness: ConfigEditorHarness
    ) -> None:
        """String value "10" for int field must be coerced to int 10."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "10",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["execution"]["max_concurrent"] == 10
        assert isinstance(buf.raw["execution"]["max_concurrent"], int)

    def test_patch_field_invalid_value_returns_422(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Non-numeric string for int field returns 422, not 500."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "not_a_number",
            },
            headers=XHR,
        )
        assert response.status_code == 422

    def test_patch_literal_without_value_returns_400(
        self, harness: ConfigEditorHarness
    ) -> None:
        """PATCH with source=literal but no value key returns 400."""
        harness.client.get("/config")
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        old_val = buf.raw["execution"]["max_concurrent"]

        response = harness.client.patch(
            "/api/config/field",
            data={"path": "execution.max_concurrent", "source": "literal"},
            headers=XHR,
        )
        assert response.status_code == 400
        # Buffer should NOT have been mutated
        assert buf.raw["execution"]["max_concurrent"] == old_val

    def test_patch_field_string_value(
        self, harness: ConfigEditorHarness
    ) -> None:
        """String value for a string field (memory limit like '8g')."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "value": "8g",
                "path": "resource_limits.memory",
                "source": "literal",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.get_value("resource_limits.memory") == "8g"

    def test_patch_bool_true(self, harness: ConfigEditorHarness) -> None:
        """Boolean dropdown sends value='true' → stored as True."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.enabled",
                "source": "literal",
                "value": "true",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["dashboard"]["enabled"] is True

    def test_patch_bool_false(self, harness: ConfigEditorHarness) -> None:
        """Boolean dropdown sends value='false' → stored as False."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.enabled",
                "source": "literal",
                "value": "false",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["dashboard"]["enabled"] is False

    def test_patch_bool_renders_select(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Boolean field response includes <select> dropdown, not checkbox."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.enabled",
                "source": "literal",
                "value": "true",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "<select" in html
        assert "checkbox" not in html.lower()

    def test_csrf_required(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.port",
                "source": "literal",
                "value": "5201",
            },
        )
        assert response.status_code == 403


class TestAddRemove:
    def test_add_list_item(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.email.authorized_senders"},
            headers=XHR,
        )
        assert response.status_code == 200

    def test_remove_item(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.email.authorized_senders",
                "index": "0",
            },
            headers=XHR,
        )
        assert response.status_code == 200


class TestDiff:
    def test_diff_shows_changes(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        # Make a change
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )

        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        # Must show the field name, old value, and new value
        assert "max_concurrent" in html
        assert "3" in html  # old value
        assert "5" in html  # new value

    def test_diff_no_changes(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "No changes" in html

    def test_diff_with_no_global_changes(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Diff with only non-global changes shows no changes."""
        harness.client.get("/config")
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        # Mutate repos (not global fields) — diff only covers global schema
        buf._raw["repos"] = {}
        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "No changes" in html


class TestSave:
    def test_save_redirects_on_success(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Save success returns HX-Redirect to refresh the page."""
        harness.client.get("/config")

        response = harness.client.post(
            "/api/config/save",
            headers=XHR,
        )
        assert response.status_code == 200
        assert response.headers.get("HX-Redirect") == "/config"

        # Buffer should be marked clean (not discarded — keeps saved values
        # for the redirect page load before file watcher reloads).
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert not buf.dirty

        # File should exist
        assert harness.tmp_path.joinpath("airut.yaml").exists()

    def test_save_invalid_config(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")

        # Remove all repos to make config invalid
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        buf._raw["repos"] = {}

        response = harness.client.post(
            "/api/config/save",
            headers=XHR,
        )
        assert response.status_code == 422

    def test_save_stale_config(self, harness: ConfigEditorHarness) -> None:
        """Dirty stale buffer returns 409 on save."""
        harness.client.get("/config")

        # Make the buffer dirty before bumping generation.
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "99",
            },
            headers=XHR,
        )
        harness.bump_generation()

        response = harness.client.post(
            "/api/config/save",
            headers=XHR,
        )
        assert response.status_code == 409

    def test_save_csrf_required(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post("/api/config/save")
        assert response.status_code == 403


class TestHandlerErrorPaths:
    def test_field_patch_no_buffer(self, tmp_path: Path) -> None:
        """PATCH field when no snapshot -> 400."""
        h = ConfigEditorHarness.no_snapshot(tmp_path)
        response = h.client.patch(
            "/api/config/field",
            data={"path": "dashboard.port", "source": "literal", "value": "1"},
            headers=XHR,
        )
        assert response.status_code == 400

    def test_field_patch_missing_body(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            headers=XHR,
        )
        assert response.status_code == 400

    def test_field_patch_unknown_path(
        self, harness: ConfigEditorHarness
    ) -> None:
        """PATCH on a path not in schema returns plain 200."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.git.repo_url",
                "source": "literal",
                "value": "x",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert response.get_data(as_text=True) == "OK"

    def test_add_no_buffer(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness.no_snapshot(tmp_path)
        response = h.client.post(
            "/api/config/add",
            data={"path": "items"},
            headers=XHR,
        )
        assert response.status_code == 400

    def test_add_missing_body(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            headers=XHR,
        )
        assert response.status_code == 400

    def test_add_csrf_required(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "items"},
        )
        assert response.status_code == 403

    def test_remove_no_buffer(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness.no_snapshot(tmp_path)
        response = h.client.post(
            "/api/config/remove",
            data={"path": "items", "index": "0"},
            headers=XHR,
        )
        assert response.status_code == 400

    def test_remove_missing_body(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            headers=XHR,
        )
        assert response.status_code == 400

    def test_remove_invalid_index(self, harness: ConfigEditorHarness) -> None:
        """Non-numeric index in remove returns 400, not 500."""
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.email.authorized_senders",
                "index": "abc",
            },
            headers=XHR,
        )
        assert response.status_code == 400

    def test_remove_csrf_required(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            data={"path": "items"},
        )
        assert response.status_code == 403

    def test_diff_no_buffer(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness.no_snapshot(tmp_path)
        response = h.client.get("/api/config/diff")
        assert response.status_code == 400

    def test_diff_no_snapshot(self, harness: ConfigEditorHarness) -> None:
        """Diff when snapshot becomes None after buffer creation."""
        harness.client.get("/config")
        # Replace snapshot with None
        harness.server._config_handlers._get_snapshot = lambda: None
        response = harness.client.get("/api/config/diff")
        assert response.status_code == 400

    def test_save_no_buffer(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness.no_snapshot(tmp_path)
        response = h.client.post(
            "/api/config/save",
            headers=XHR,
        )
        assert response.status_code == 400

    def test_save_no_config_source(self, harness: ConfigEditorHarness) -> None:
        """Save when config source is None -> 400."""
        harness.client.get("/config")
        harness.server._config_handlers._get_config_source = lambda: None
        response = harness.client.post(
            "/api/config/save",
            headers=XHR,
        )
        assert response.status_code == 400
        html = response.get_data(as_text=True)
        assert "No config source" in html

    def test_save_write_failure(self, harness: ConfigEditorHarness) -> None:
        """Save when source.save() raises -> 500."""
        harness.client.get("/config")

        class FailingSource:
            def save(self, data: object) -> None:
                raise OSError("disk full")

        harness.server._config_handlers._get_config_source = lambda: (
            FailingSource()
        )
        response = harness.client.post(
            "/api/config/save",
            headers=XHR,
        )
        assert response.status_code == 500
        html = response.get_data(as_text=True)
        assert "disk full" in html


class TestRepoSummariesDirect:
    def test_no_buffer_returns_empty(
        self, harness: ConfigEditorHarness
    ) -> None:
        """_get_repo_summaries returns [] when buffer is None."""
        assert harness.server._config_handlers._buffer is None
        result = harness.server._config_handlers._get_repo_summaries()
        assert result == []


class TestTemplateValueSource:
    """Ensure template value_source handles VarRef."""

    def test_config_page_with_var_ref(self, tmp_path: Path) -> None:
        from airut.yaml_env import VarRef

        raw = _make_sample_raw()
        raw["vars"] = {"host_var": "10.0.0.1"}
        raw["dashboard"]["host"] = VarRef("host_var")
        h = ConfigEditorHarness(tmp_path, raw=raw)
        response = h.client.get("/config")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "host_var" in html


class TestRepoSummaries:
    def test_repo_with_slack_channel(self, tmp_path: Path) -> None:
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["slack"] = {
            "bot_token": "xoxb-test",
            "app_token": "xapp-test",
            "authorized": [{"workspace_members": True}],
        }
        h = ConfigEditorHarness(tmp_path, raw=raw)
        h.client.get("/config")
        html_response = h.client.get("/config")
        html = html_response.get_data(as_text=True)
        assert "test-repo" in html


class TestDiscard:
    def test_discard_resets_buffer(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        assert harness.server._config_handlers._buffer is not None

        response = harness.client.post(
            "/api/config/discard",
            headers=XHR,
        )
        assert response.status_code == 200
        assert harness.server._config_handlers._buffer is None

    def test_discard_csrf_required(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post("/api/config/discard")
        assert response.status_code == 403


class TestSaveReloadBugs:
    """Reproduce save/reload race conditions (Bug #3).

    After saving config changes, loading the config page should show the
    saved values, not the old ones.  Re-editing and re-saving should not
    produce a false "stale" error.
    """

    def test_page_after_save_shows_saved_values(
        self, harness: ConfigEditorHarness
    ) -> None:
        """After save, /config must show saved values, not stale snapshot."""
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )

        r = harness.client.post("/api/config/save", headers=XHR)
        assert r.status_code == 200

        # Simulate browser following HX-Redirect — snapshot not yet updated
        # (file watcher hasn't reloaded).
        harness.client.get("/config")

        buf = harness.server._config_handlers._buffer
        assert buf is not None
        # Before the fix, the buffer was recreated from the unchanged
        # snapshot and showed the old value (3) instead of the saved value.
        assert buf.get_value("execution.max_concurrent") == 5

    def test_edit_after_save_and_reload_not_stale(
        self, harness: ConfigEditorHarness
    ) -> None:
        """After save + file reload, re-editing must not trigger stale error."""
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )
        harness.client.post("/api/config/save", headers=XHR)

        # Simulate browser redirect (buffer recreated from old snapshot)
        harness.client.get("/config")

        # Simulate file watcher reload: update snapshot + bump generation
        import yaml

        from airut.config.source import make_env_loader

        with open(harness._config_path) as f:
            saved_raw = yaml.load(f, Loader=make_env_loader())
        harness._snapshot = _make_snapshot(saved_raw)
        harness.bump_generation()

        # Buffer (gen=0) is now stale vs current gen=1.
        # Edit another field — this makes the buffer dirty AND stale.
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.shutdown_timeout",
                "source": "literal",
                "value": "120",
            },
            headers=XHR,
        )

        r = harness.client.post("/api/config/save", headers=XHR)
        assert r.status_code != 409, "Got stale error on re-save after own save"

    def test_clean_stale_buffer_refreshes_on_page_load(
        self, harness: ConfigEditorHarness
    ) -> None:
        """A stale but clean buffer should auto-refresh on page load."""
        harness.client.get("/config")

        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.get_value("execution.max_concurrent") == 3

        # External change: update snapshot + bump generation
        raw = _make_sample_raw()
        raw["execution"]["max_concurrent"] = 99
        harness._snapshot = _make_snapshot(raw)
        harness.bump_generation()

        # Load page — buffer is stale but clean, should auto-refresh
        harness.client.get("/config")

        buf = harness.server._config_handlers._buffer
        assert buf is not None
        # Before the fix, _ensure_buffer returned the existing stale
        # buffer without checking staleness.
        assert buf.get_value("execution.max_concurrent") == 99


class TestDiffGranularity:
    """Reproduce diff granularity bug (Bug #2).

    Diff should show per-field changes (e.g. ``execution.max_concurrent``),
    not one coarse ``global_config`` entry grouping all global settings.
    """

    def test_diff_shows_individual_field_not_global_config(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Diff field name should be specific, not 'global_config'."""
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "10",
            },
            headers=XHR,
        )

        r = harness.client.get("/api/config/diff")
        assert r.status_code == 200
        html = r.get_data(as_text=True)

        # Before the fix, diff_by_scope operated at ServerConfig level,
        # showing "global_config" instead of the specific field.
        assert ">global_config<" not in html, (
            "Diff shows 'global_config' instead of per-field names"
        )

    def test_diff_multiple_fields_counted_separately(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Each changed field should be its own diff entry."""
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "10",
            },
            headers=XHR,
        )
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.shutdown_timeout",
                "source": "literal",
                "value": "120",
            },
            headers=XHR,
        )

        r = harness.client.get("/api/config/diff")
        assert r.status_code == 200
        html = r.get_data(as_text=True)

        # Before the fix, both fields were grouped under one
        # "global_config" entry showing only 1 change.
        assert "2 change" in html, (
            f"Expected '2 changes' but diff shows 1: {html[:500]}"
        )


class TestDirtyCount:
    """Bug D.3: dirty count must reflect actual changes vs live config.

    The server must return an ``X-Dirty-Count`` header with the number of
    leaf fields that actually differ from the live snapshot.  Editing a
    value then reverting it must produce count 0, not 2.
    """

    def test_patch_returns_dirty_count_header(
        self, harness: ConfigEditorHarness
    ) -> None:
        """PATCH response includes X-Dirty-Count header."""
        harness.client.get("/config")

        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert "X-Dirty-Count" in response.headers
        assert response.headers["X-Dirty-Count"] == "1"

    def test_revert_edit_gives_zero_dirty_count(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Editing a field then reverting produces dirty count 0."""
        harness.client.get("/config")

        # Original value is 3
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )
        # Revert back to 3
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "3",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert response.headers["X-Dirty-Count"] == "0"

    def test_two_edits_one_revert_gives_one(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Edit 2 fields, revert 1 → dirty count is 1."""
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.shutdown_timeout",
                "source": "literal",
                "value": "120",
            },
            headers=XHR,
        )
        # Revert max_concurrent back to original (3)
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "3",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert response.headers["X-Dirty-Count"] == "1"

    def test_unset_then_restore_gives_zero(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Unset a field then set it back to its original value → count 0."""
        harness.client.get("/config")

        # Unset shutdown_timeout (originally 60)
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.shutdown_timeout",
                "source": "unset",
            },
            headers=XHR,
        )
        # Set it back to 60
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.shutdown_timeout",
                "source": "literal",
                "value": "60",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert response.headers["X-Dirty-Count"] == "0"

    def test_add_returns_dirty_count_header(
        self, harness: ConfigEditorHarness
    ) -> None:
        """POST /api/config/add also returns X-Dirty-Count header."""
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.email.authorized_senders"},
            headers=XHR,
        )
        assert response.status_code == 200
        assert "X-Dirty-Count" in response.headers

    def test_remove_returns_dirty_count_header(
        self, harness: ConfigEditorHarness
    ) -> None:
        """POST /api/config/remove also returns X-Dirty-Count header."""
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.email.authorized_senders",
                "index": "0",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert "X-Dirty-Count" in response.headers

    def test_dirty_count_zero_when_no_buffer(
        self, harness: ConfigEditorHarness
    ) -> None:
        """_compute_dirty_count returns 0 with no buffer."""
        handlers = harness.server._config_handlers
        assert handlers._compute_dirty_count() == 0

    def test_dirty_count_zero_when_no_snapshot(
        self, harness: ConfigEditorHarness
    ) -> None:
        """_compute_dirty_count returns 0 when snapshot is None."""
        harness.client.get("/config")
        handlers = harness.server._config_handlers
        handlers._get_snapshot = lambda: None
        assert handlers._compute_dirty_count() == 0
