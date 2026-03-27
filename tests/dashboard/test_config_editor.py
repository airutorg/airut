# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for config editor HTTP handlers."""

import copy
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from airut.config.editor_schema import EditorFieldSchema

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

    def test_coerce_value_empty_string_to_int(self) -> None:
        """Empty string for int type returns 0 (mode-switch default)."""
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value("", "int") == 0
        assert _coerce_value("  ", "int") == 0

    def test_coerce_value_empty_string_to_float(self) -> None:
        """Empty string for float type returns 0.0 (mode-switch default)."""
        from airut.dashboard.handlers_config import _coerce_value

        assert _coerce_value("", "float") == 0.0
        assert _coerce_value("  ", "float") == 0.0

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
        assert "Network" in html

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

    def test_patch_env_to_literal_int_field(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Switching from !env to Literal on an int field must not 422.

        Regression: the Literal button's hx-vals embedded the env var
        name (e.g. "PORT_VAR") as the literal value.  For int fields,
        _coerce_value("PORT_VAR", "int") raised ValueError → 422.
        The template should send the field default (or empty string)
        instead of the variable name.
        """
        harness.client.get("/config")

        # Step 1: set an int field to !env
        r1 = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.port",
                "source": "env",
                "value": "PORT_VAR",
            },
            headers=XHR,
        )
        assert r1.status_code == 200

        # Step 2: the Literal button rendered from step 1 must NOT
        # include "PORT_VAR" as the literal value.  Parse the HTML
        # to verify the hx-vals on the Literal button.
        html = r1.get_data(as_text=True)
        # Find the Literal button's hx-vals
        m = re.search(
            r"""hx-vals='(\{[^']*"source"\s*:\s*"literal"[^']*})'""", html
        )
        assert m, "Literal button not found in response HTML"
        vals = json.loads(m.group(1))
        # dashboard.port has default 5200 — template should fall through
        # to f.default instead of using the env var name.
        assert vals["value"] == "5200"

    def test_patch_var_to_literal_int_field(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Switching from !var to Literal on an int field must not 422.

        Same regression as !env: the Literal button would embed the
        var ref name as the literal value.
        """
        from airut.yaml_env import VarRef

        harness.client.get("/config")

        # Set an int field to !var directly in the buffer
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        buf.set_field("dashboard.port", "var", "my_port_ref")
        assert isinstance(buf.raw["dashboard"]["port"], VarRef)

        # Re-render the field to get the HTML with !var active
        r1 = harness.client.patch(
            "/api/config/field",
            data={
                "path": "dashboard.port",
                "source": "var",
                "value": "my_port_ref",
            },
            headers=XHR,
        )
        assert r1.status_code == 200

        html = r1.get_data(as_text=True)
        m = re.search(
            r"""hx-vals='(\{[^']*"source"\s*:\s*"literal"[^']*})'""", html
        )
        assert m, "Literal button not found in response HTML"
        vals = json.loads(m.group(1))
        assert vals["value"] == "5200"

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

    def test_diff_detects_removed_repo(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Diff detects removed repos."""
        harness.client.get("/config")
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        buf._raw["repos"] = {}
        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "test-repo" in html
        assert "(removed)" in html


class TestSave:
    def test_save_redirects_on_success(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Save success returns HX-Redirect to refresh the page."""
        harness.client.get("/config")

        response = harness.client.post(
            "/api/config/save",
            headers={**XHR, "Referer": "http://localhost/config"},
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

    def test_save_persists_config_version(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Saved YAML contains config_version set to latest."""
        import yaml

        from airut.config.migration import CURRENT_CONFIG_VERSION
        from airut.config.source import make_env_loader

        harness.client.get("/config")
        harness.client.post(
            "/api/config/save",
            headers={**XHR, "Referer": "http://localhost/config"},
        )

        with open(harness.tmp_path / "airut.yaml") as f:
            saved = yaml.load(f, Loader=make_env_loader())

        assert saved["config_version"] == CURRENT_CONFIG_VERSION

    def test_save_from_repo_page_redirects_to_repo(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Save from a repo page redirects back to the repo page."""
        harness.client.get("/config")

        response = harness.client.post(
            "/api/config/save",
            headers={
                **XHR,
                "Referer": "http://localhost/config/repos/test-repo",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("HX-Redirect") == "/config/repos/test-repo"

    def test_save_invalid_config(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")

        # Remove required git.repo_url to make config invalid
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        del buf._raw["repos"]["test-repo"]["git"]["repo_url"]

        response = harness.client.post(
            "/api/config/save",
            headers=XHR,
        )
        assert response.status_code == 422

    def test_diff_shows_validation_error(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Bug: diff dialog should surface validation errors.

        The frontend should be signaled to disable the Confirm Save button.
        """
        harness.client.get("/config")

        # Remove required git.repo_url to make config invalid
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        del buf._raw["repos"]["test-repo"]["git"]["repo_url"]
        buf.mark_dirty()

        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        # Must show a validation error in the diff result
        assert "error" in html.lower() or "invalid" in html.lower()
        # Must include a signal for the frontend to disable save button
        assert "diff-has-errors" in html

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
        """PATCH on a path not in any schema returns plain 200."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "totally.nonexistent.path",
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

    def test_diff_snapshot_raw_none(self, harness: ConfigEditorHarness) -> None:
        """Diff when snapshot.raw is None returns 400."""
        harness.client.get("/config")
        snap = harness._snapshot
        snap._raw = None
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


class TestCommonRepoIdsDirect:
    def test_no_buffer_returns_empty(
        self, harness: ConfigEditorHarness
    ) -> None:
        assert harness.server._config_handlers._buffer is None
        result = harness.server._config_handlers._get_common_repo_ids()
        assert result == set()

    def test_no_snapshot_returns_empty(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        harness.server._config_handlers._get_snapshot = lambda: None
        result = harness.server._config_handlers._get_common_repo_ids()
        assert result == set()


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

    def test_var_ref_on_numeric_field_renders_text_input(
        self, tmp_path: Path
    ) -> None:
        """!var on int/float fields must render type=text, not type=number.

        HTML5 number inputs silently reject non-numeric values, so a var
        name like 'default_resource_timeout' would appear as an empty
        field.  Regression test for resource_limits vars not rendering.
        """
        from airut.yaml_env import VarRef

        raw = _make_sample_raw()
        raw["vars"] = {
            "default_resource_timeout": 7200,
            "default_resource_cpus": 2.0,
        }
        raw["repos"]["test-repo"]["resource_limits"] = {
            "timeout": VarRef("default_resource_timeout"),
            "cpus": VarRef("default_resource_cpus"),
        }
        h = ConfigEditorHarness(tmp_path, raw=raw)
        response = h.client.get("/config/repos/test-repo")
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        # The var names must appear as input values, not be silently dropped
        assert "default_resource_timeout" in html
        assert "default_resource_cpus" in html

        # Inputs for var-sourced numeric fields must be type="text"
        # (type="number" would hide the string var name)
        timeout_field_id = "field-repos-test-repo-resource_limits-timeout"
        assert timeout_field_id in html

        # Extract the field div and check its input type
        start = html.index(f'id="{timeout_field_id}"')
        # Find the input within this field's div
        field_html = html[start : start + 2000]
        # The active input (not the disabled default one) must be type="text"
        assert 'type="text"' in field_html
        assert 'type="number"' not in field_html

    def test_var_ref_on_numeric_field_roundtrips_on_save(
        self, tmp_path: Path
    ) -> None:
        """Changing a var-sourced numeric field must preserve the var name.

        When the user submits the form for a !var field on a numeric type,
        the var name must be preserved — not reset to empty string.
        """
        from airut.yaml_env import VarRef

        raw = _make_sample_raw()
        raw["vars"] = {"default_resource_timeout": 7200}
        raw["repos"]["test-repo"]["resource_limits"] = {
            "timeout": VarRef("default_resource_timeout"),
        }
        h = ConfigEditorHarness(tmp_path, raw=raw)
        h.client.get("/config/repos/test-repo")

        # Re-submit the field with source=var — simulates user clicking save
        response = h.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.resource_limits.timeout",
                "source": "var",
                "value": "default_resource_timeout",
            },
            headers=XHR,
        )
        assert response.status_code == 200

        buf = h.server._config_handlers._buffer
        assert buf is not None
        val = buf.get_value("repos.test-repo.resource_limits.timeout")
        assert isinstance(val, VarRef)
        assert val.var_name == "default_resource_timeout"

    def test_env_ref_on_numeric_field_renders_text_input(
        self, tmp_path: Path
    ) -> None:
        """!env on int/float fields must also render type=text.

        Same bug as !var: HTML5 number inputs reject non-numeric strings,
        so an env var name would appear empty.
        """
        from airut.yaml_env import EnvVar

        raw = _make_sample_raw()
        raw["dashboard"]["port"] = EnvVar("DASHBOARD_PORT")
        h = ConfigEditorHarness(tmp_path, raw=raw)
        response = h.client.get("/config")
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        field_id = "field-dashboard-port"
        assert field_id in html
        start = html.index(f'id="{field_id}"')
        field_html = html[start : start + 2000]
        assert "DASHBOARD_PORT" in field_html
        assert 'type="text"' in field_html
        assert 'type="number"' not in field_html


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


class TestRepoPageExcludesRepoId:
    """Bug: repo_id is an internal property and must not appear in the UI."""

    def test_repo_page_does_not_show_repo_id_field(
        self, harness: ConfigEditorHarness
    ) -> None:
        """The per-repo page must not display repos.X.repo_id as a field."""
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "repos.test-repo.repo_id" not in html

    def test_repo_schema_excludes_repo_id(
        self, harness: ConfigEditorHarness
    ) -> None:
        """_get_repo_schema must not include the repo_id field."""
        harness.client.get("/config")
        schema = harness.server._config_handlers._get_repo_schema("test-repo")
        names = {s.name for s in schema}
        assert "repo_id" not in names


class TestEnvVarDirtyCount:
    """Bug: configs with EnvVar values produce false dirty counts.

    When the edit buffer deep-copies the raw config, EnvVar instances
    are duplicated.  Without __eq__, dict comparisons fail and every
    field containing EnvVar appears dirty even with no actual changes.
    """

    def test_no_false_dirty_with_envvar_secrets(self, tmp_path: Path) -> None:
        """Dirty count must be 0 when no changes made, even with EnvVar."""
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["secrets"] = {
            "API_KEY": EnvVar("MY_API_KEY"),
        }
        h = ConfigEditorHarness(tmp_path, raw=raw)
        h.client.get("/config")
        count = h.server._config_handlers._compute_dirty_count()
        assert count == 0

    def test_no_false_diff_with_envvar_secrets(self, tmp_path: Path) -> None:
        """Diff must show 'No changes' when raw dicts contain EnvVar values."""
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["secrets"] = {
            "API_KEY": EnvVar("MY_API_KEY"),
        }
        h = ConfigEditorHarness(tmp_path, raw=raw)
        h.client.get("/config")
        response = h.client.get("/api/config/diff")
        html = response.get_data(as_text=True)
        assert "No changes" in html

    def test_envvar_field_reverts_to_zero_dirty(self, tmp_path: Path) -> None:
        """Revert gives dirty count 0 even with EnvVar config."""
        raw = _make_sample_raw()
        raw["repos"]["test-repo"]["secrets"] = {
            "KEY": EnvVar("SECRET"),
        }
        h = ConfigEditorHarness(tmp_path, raw=raw)
        h.client.get("/config")

        # Change max_concurrent (original value is 3)
        h.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )
        # Revert max_concurrent
        response = h.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "3",
            },
            headers=XHR,
        )
        assert response.headers["X-Dirty-Count"] == "0"


class TestRepoFieldPersistence:
    """Bug: repo field edits vanish on page reload.

    Changing a repo field (e.g. model from Default to Literal) and then
    navigating back to the repo page must show the edited value.
    """

    def test_repo_field_change_persists_on_reload(
        self, harness: ConfigEditorHarness
    ) -> None:
        """PATCH a repo field, then GET the repo page — change visible."""
        harness.client.get("/config")

        # Change model from default to literal "sonnet"
        r = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "sonnet",
            },
            headers=XHR,
        )
        assert r.status_code == 200

        # Navigate to repo page — the change must be visible
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "sonnet" in html

    def test_repo_field_change_persists_after_global_page(
        self, harness: ConfigEditorHarness
    ) -> None:
        """PATCH repo field, visit /config, return to repo page."""
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "haiku",
            },
            headers=XHR,
        )

        # Visit global page, then return to repo page
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "haiku" in html

    def test_default_to_literal_persists(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Switch from Default to Literal with same default value."""
        harness.client.get("/config")

        # model default is "opus"; switch to literal "opus"
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "opus",
            },
            headers=XHR,
        )

        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        # The Literal button should be active, not Default
        # Check that the field shows literal source active
        assert 'class="active"' in html or "active" in html
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.get_value("repos.test-repo.model") == "opus"


class TestUnsetAfterSaveReload:
    """Bug: unset after save+reload shows dirty count 0.

    Sequence:
    1. model NOT set in YAML
    2. Set model to literal "opus" → dirty=1
    3. Save → YAML now has model: opus
    4. Config reloads (gen bumps, snapshot has model: opus)
    5. Page reload (buffer recreated from new snapshot)
    6. Click "Default" to unset model → SHOULD be dirty=1
    7. BUG: dirty count is 0
    """

    def test_unset_after_save_and_reload_shows_dirty(
        self, harness: ConfigEditorHarness
    ) -> None:
        """After saving model=opus, unsetting it must show dirty=1."""
        # model is NOT set in raw (make_sample_raw doesn't include it)
        harness.client.get("/config")

        # Set model to literal "opus"
        r = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "opus",
            },
            headers=XHR,
        )
        assert r.status_code == 200
        assert r.headers["X-Dirty-Count"] == "1"

        # Save
        r = harness.client.post(
            "/api/config/save",
            headers={
                **XHR,
                "Referer": "http://localhost/config/repos/test-repo",
            },
        )
        assert r.status_code == 200

        # Simulate config reload: load saved YAML, create snapshot, bump gen
        import yaml

        from airut.config.source import make_env_loader

        with open(harness._config_path) as f:
            saved_raw = yaml.load(f, Loader=make_env_loader())
        harness._snapshot = _make_snapshot(saved_raw)
        harness.bump_generation()

        # Page reload (follows HX-Redirect)
        harness.client.get("/config/repos/test-repo")

        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.get_value("repos.test-repo.model") == "opus"

        # Click "Default" to unset model
        r = harness.client.patch(
            "/api/config/field",
            data={"path": "repos.test-repo.model", "source": "unset"},
            headers=XHR,
        )
        assert r.status_code == 200

        # Dirty count must be 1: buffer has MISSING, live has "opus"
        assert r.headers["X-Dirty-Count"] == "1", (
            f"Expected dirty count 1 but got {r.headers['X-Dirty-Count']}"
        )

    def test_unset_after_save_gen_bump_before_page_load(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Gen bumps before page load — buffer replaced, then unset."""
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "opus",
            },
            headers=XHR,
        )

        harness.client.post(
            "/api/config/save",
            headers={
                **XHR,
                "Referer": "http://localhost/config/repos/test-repo",
            },
        )

        # File watcher fires BEFORE page load
        import yaml

        from airut.config.source import make_env_loader

        with open(harness._config_path) as f:
            saved_raw = yaml.load(f, Loader=make_env_loader())
        harness._snapshot = _make_snapshot(saved_raw)
        harness.bump_generation()

        harness.client.get("/config/repos/test-repo")

        r = harness.client.patch(
            "/api/config/field",
            data={"path": "repos.test-repo.model", "source": "unset"},
            headers=XHR,
        )
        assert r.headers["X-Dirty-Count"] == "1"

    def test_unset_after_save_gen_bump_after_page_load(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Gen bumps after page load but before PATCH.

        Buffer replaced during PATCH, then unset applied to fresh buffer.
        """
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "opus",
            },
            headers=XHR,
        )

        harness.client.post(
            "/api/config/save",
            headers={
                **XHR,
                "Referer": "http://localhost/config/repos/test-repo",
            },
        )

        # Page load BEFORE file watcher
        harness.client.get("/config/repos/test-repo")

        # File watcher fires AFTER page load but BEFORE PATCH
        import yaml

        from airut.config.source import make_env_loader

        with open(harness._config_path) as f:
            saved_raw = yaml.load(f, Loader=make_env_loader())
        harness._snapshot = _make_snapshot(saved_raw)
        harness.bump_generation()

        r = harness.client.patch(
            "/api/config/field",
            data={"path": "repos.test-repo.model", "source": "unset"},
            headers=XHR,
        )
        assert r.headers["X-Dirty-Count"] == "1"

    def test_unset_after_save_default_value_reload(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Reload with default-value-only change updates snapshot/gen.

        Before the fix, ``_on_config_changed()`` early-returned without
        updating snapshot/generation when the parsed config was identical
        (e.g. explicitly setting model to "opus" which is the default).
        The fix ensures snapshot and generation always update, so the
        editor sees the raw-dict change.
        """
        harness.client.get("/config")

        harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "opus",
            },
            headers=XHR,
        )

        harness.client.post(
            "/api/config/save",
            headers={
                **XHR,
                "Referer": "http://localhost/config/repos/test-repo",
            },
        )

        # File watcher fires — with the fix, snapshot/gen are updated
        # even though the parsed config is semantically identical.
        import yaml

        from airut.config.source import make_env_loader

        with open(harness._config_path) as f:
            saved_raw = yaml.load(f, Loader=make_env_loader())
        harness._snapshot = _make_snapshot(saved_raw)
        harness.bump_generation()

        harness.client.get("/config/repos/test-repo")

        r = harness.client.patch(
            "/api/config/field",
            data={"path": "repos.test-repo.model", "source": "unset"},
            headers=XHR,
        )
        assert r.headers["X-Dirty-Count"] == "1", (
            f"Expected dirty count 1 but got {r.headers['X-Dirty-Count']}"
        )


class TestRepoPage:
    """Tests for the per-repo settings page (Phase 2)."""

    def test_repo_page_returns_200(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "test-repo" in html

    def test_repo_page_shows_fields(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Git" in html
        assert "Model" in html
        assert "Network" in html
        assert "Container" in html
        assert "Resource Limits" in html

    def test_repo_page_shows_field_paths(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Field labels display full YAML paths including repo prefix."""
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "repos.test-repo.git.repo_url" in html
        assert "repos.test-repo.model" in html
        assert "repos.test-repo.claude_version" in html
        assert "repos.test-repo.container.path" in html

    def test_repo_page_not_found(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.get("/config/repos/nonexistent")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "not found" in html

    def test_repo_page_no_snapshot(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness.no_snapshot(tmp_path)
        response = h.client.get("/config/repos/test-repo")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "No config available" in html

    def test_repo_page_breadcrumbs(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert 'href="/config"' in html
        assert "Configuration" in html

    def test_repo_page_save_bar(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert 'id="review-save-btn"' in html
        assert 'id="discard-btn"' in html

    def test_repo_page_remove_button(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Remove" in html
        assert "remove-repo-btn" in html

    def test_repo_page_shows_credentials_section(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Credentials section is shown on repo page."""
        harness.client.get("/config")
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Credentials" in html
        assert "future update" not in html


class TestRepoFieldPatch:
    """Tests for patching per-repo fields."""

    def test_patch_repo_field_literal(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "sonnet",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["repos"]["test-repo"]["model"] == "sonnet"

    def test_patch_repo_field_returns_html(
        self, harness: ConfigEditorHarness
    ) -> None:
        """PATCH on a repo field returns HTML fragment (not plain OK)."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "sonnet",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "cfg-field" in html

    def test_patch_repo_field_env(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.git.repo_url",
                "source": "env",
                "value": "GIT_URL",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert isinstance(
            buf.raw["repos"]["test-repo"]["git"]["repo_url"], EnvVar
        )

    def test_patch_repo_bool_field(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.network.sandbox_enabled",
                "source": "literal",
                "value": "false",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert (
            buf.raw["repos"]["test-repo"]["network"]["sandbox_enabled"] is False
        )


class TestAddRemoveRepo:
    """Tests for add/remove repo operations."""

    def test_add_repo(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-project"},
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert "new-project" in buf.raw["repos"]
        assert buf.dirty

    def test_add_repo_creates_skeleton(
        self, harness: ConfigEditorHarness
    ) -> None:
        """New repo gets a minimal skeleton with git and email stubs."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-project"},
            headers=XHR,
        )
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        repo = buf.raw["repos"]["new-project"]
        assert "git" in repo
        assert "repo_url" in repo["git"]
        assert "email" in repo
        # Sensitive fields use empty literal placeholders
        assert repo["email"]["password"] == ""

    def test_add_repo_does_not_overwrite_existing(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        original_url = buf.raw["repos"]["test-repo"]["git"]["repo_url"]

        harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "test-repo"},
            headers=XHR,
        )
        assert buf.raw["repos"]["test-repo"]["git"]["repo_url"] == original_url

    def test_add_repo_dirty_count(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-project"},
            headers=XHR,
        )
        dirty = response.headers.get("X-Dirty-Count")
        assert dirty is not None
        assert int(dirty) > 0

    def test_remove_repo(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            data={"path": "repos", "key": "test-repo"},
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert "test-repo" not in buf.raw["repos"]

    def test_remove_repo_dirty_count(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            data={"path": "repos", "key": "test-repo"},
            headers=XHR,
        )
        dirty = response.headers.get("X-Dirty-Count")
        assert dirty is not None
        assert int(dirty) > 0


class TestRepoDiff:
    """Tests for diff including repo changes."""

    def test_diff_detects_repo_field_change(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "sonnet",
            },
            headers=XHR,
        )
        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "repos.test-repo.model" in html

    def test_diff_added_repo_shows_subfields(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Bug: adding a repo should show each subfield in the diff.

        Previously showed only a single 'repos.new-project' entry.
        """
        harness.client.get("/config")
        harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-project"},
            headers=XHR,
        )
        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        # Repo subfields like git.repo_url must appear individually
        assert "repos.new-project.git.repo_url" in html
        # Email channel subfields too
        assert "repos.new-project.email.imap_server" in html

    def test_diff_removed_repo_shows_subfields(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Removing a repo should show each subfield in the diff."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/remove",
            data={"path": "repos", "key": "test-repo"},
            headers=XHR,
        )
        response = harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        # Must show individual subfields, not just "repos.test-repo"
        assert "repos.test-repo.git.repo_url" in html
        assert "repos.test-repo.email.imap_server" in html

    def test_dirty_count_added_repo_counts_subfields(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Adding a repo should count all subfields, not just 1."""
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-project"},
            headers=XHR,
        )
        dirty = int(response.headers.get("X-Dirty-Count", "0"))
        # A new repo has many subfields (git.repo_url + email fields)
        # so the dirty count must be greater than 1.
        assert dirty > 1


class TestRepoDirtyCount:
    """Tests for dirty count including repo changes."""

    def test_repo_field_change_increments_dirty(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "sonnet",
            },
            headers=XHR,
        )
        dirty = response.headers.get("X-Dirty-Count")
        assert dirty is not None
        assert int(dirty) >= 1

    def test_global_plus_repo_change_counts_both(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Dirty count covers both global and per-repo fields."""
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
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.model",
                "source": "literal",
                "value": "sonnet",
            },
            headers=XHR,
        )
        dirty = int(response.headers.get("X-Dirty-Count", "0"))
        assert dirty >= 2


class TestInitialDirtyCount:
    """Page load should reflect server-side dirty state.

    After mutations (e.g. adding/removing a repo), navigating to a
    config page should render the save button enabled and the dirty
    count visible — without requiring an additional AJAX mutation.
    """

    _SAVE_BTN_DISABLED = 'class="cfg-btn primary" disabled'
    _DISCARD_BTN_DISABLED = 'class="cfg-btn danger" disabled'

    def test_repo_page_shows_dirty_after_add(
        self, harness: ConfigEditorHarness
    ) -> None:
        """After adding a repo, its edit page shows dirty."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-project"},
            headers=XHR,
        )
        # Simulate JS redirect — full page load
        response = harness.client.get("/config/repos/new-project")
        html = response.get_data(as_text=True)
        # Both buttons must be enabled
        assert self._SAVE_BTN_DISABLED not in html
        assert self._DISCARD_BTN_DISABLED not in html
        # Dirty count span visible with text
        assert re.search(r'id="dirty-count"[^>]*\bhidden\b', html) is None
        assert "unsaved change" in html

    def test_config_page_shows_dirty_after_add(
        self, harness: ConfigEditorHarness
    ) -> None:
        """After adding a repo, config list shows dirty."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-project"},
            headers=XHR,
        )
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert self._SAVE_BTN_DISABLED not in html
        assert "unsaved change" in html

    def test_config_page_shows_dirty_after_remove(
        self, harness: ConfigEditorHarness
    ) -> None:
        """After removing a repo, config list shows dirty."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/remove",
            data={"path": "repos", "key": "test-repo"},
            headers=XHR,
        )
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert self._SAVE_BTN_DISABLED not in html
        assert "unsaved change" in html

    def test_config_page_buttons_disabled_when_clean(
        self, harness: ConfigEditorHarness
    ) -> None:
        """When buffer is clean, buttons are disabled."""
        response = harness.client.get("/config")
        html = response.get_data(as_text=True)
        assert self._SAVE_BTN_DISABLED in html
        assert self._DISCARD_BTN_DISABLED in html
        assert re.search(r'id="dirty-count"[^>]*\bhidden\b', html)


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

    def test_discard_from_repo_page_redirects_to_repo(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Discard from a repo page redirects back to the repo page."""
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/discard",
            headers={
                **XHR,
                "Referer": "http://localhost/config/repos/test-repo",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("HX-Redirect") == "/config/repos/test-repo"

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

    def test_dirty_count_zero_after_save_before_watcher(
        self, harness: ConfigEditorHarness
    ) -> None:
        """After save, dirty count must be 0 even if file watcher is slow.

        Reproduces the bug where saving showed "N unsaved changes" on the
        redirected page because _compute_dirty_count compared buffer vs
        stale snapshot instead of checking buffer.dirty.
        """
        harness.client.get("/config")

        # Edit a field
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "execution.max_concurrent",
                "source": "literal",
                "value": "5",
            },
            headers=XHR,
        )

        # Save — writes file, marks buffer clean
        r = harness.client.post("/api/config/save", headers=XHR)
        assert r.status_code == 200

        # Simulate browser following HX-Redirect.  The file watcher has NOT
        # reloaded the snapshot yet, so snapshot.raw still has old value.
        handlers = harness.server._config_handlers
        count = handlers._compute_dirty_count()
        assert count == 0, f"Expected 0 unsaved changes after save, got {count}"


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
        # Buffer must be dirty to reach the snapshot check.
        assert handlers._buffer is not None
        handlers._buffer.mark_dirty()
        handlers._get_snapshot = lambda: None
        assert handlers._compute_dirty_count() == 0


# ── Phase 3: Channels ──────────────────────────────────────────────


def _make_sample_raw_with_slack() -> dict[str, Any]:
    """Create a sample raw config with both email and Slack channels."""
    raw = _make_sample_raw()
    raw["repos"]["test-repo"]["slack"] = {
        "bot_token": "xoxb-test-token",
        "app_token": "xapp-test-token",
        "authorized": [{"workspace_members": True}],
    }
    return raw


@pytest.fixture
def slack_harness(tmp_path: Path) -> ConfigEditorHarness:
    return ConfigEditorHarness(tmp_path, raw=_make_sample_raw_with_slack())


class TestRepoPageChannels:
    def test_repo_page_shows_email_channel(
        self, harness: ConfigEditorHarness
    ) -> None:
        response = harness.client.get("/config/repos/test-repo")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Email Channel" in html
        assert "imap_server" in html
        assert "authorized_senders" in html

    def test_repo_page_shows_add_slack_button(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Email-only repo shows add-slack button but not add-email."""
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Add Slack Channel" in html
        assert "Add Email Channel" not in html

    def test_repo_page_shows_both_channels(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        response = slack_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Email Channel" in html
        assert "Slack Channel" in html
        assert "Add Email Channel" not in html
        assert "Add Slack Channel" not in html

    def test_repo_page_shows_slack_authorized_rules(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        response = slack_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "authorized" in html
        assert "workspace_members" in html

    def test_repo_page_no_channels_placeholder_gone(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Phase 3 placeholder text is replaced."""
        response = harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Channel editing will be available" not in html


class TestAddChannel:
    def test_add_email_channel(self, harness: ConfigEditorHarness) -> None:
        """Adding email to a repo that only has email should be no-op."""
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.email"},
            headers=XHR,
        )
        assert response.status_code == 200
        # Already has email — should not change
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert "email" in buf.raw["repos"]["test-repo"]

    def test_add_slack_channel(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.slack"},
            headers=XHR,
        )
        assert response.status_code == 200
        assert "HX-Redirect" in response.headers
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        slack = buf.raw["repos"]["test-repo"]["slack"]
        assert "bot_token" in slack
        assert "app_token" in slack
        assert "authorized" in slack

    def test_add_email_to_slack_only_repo(self, tmp_path: Path) -> None:
        """Adding email to a Slack-only repo creates email skeleton."""
        raw = _make_sample_raw_with_slack()
        del raw["repos"]["test-repo"]["email"]
        h = ConfigEditorHarness(tmp_path, raw=raw)
        h.client.get("/config")
        response = h.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.email"},
            headers=XHR,
        )
        assert response.status_code == 200
        buf = h.server._config_handlers._buffer
        assert buf is not None
        email = buf.raw["repos"]["test-repo"]["email"]
        assert "imap_server" in email

    def test_add_channel_nonexistent_repo(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos.nonexistent.slack"},
            headers=XHR,
        )
        assert response.status_code == 400


class TestRemoveChannel:
    def test_remove_email_channel(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/remove",
            data={"path": "repos.test-repo.email"},
            headers=XHR,
        )
        assert response.status_code == 200
        assert "HX-Redirect" in response.headers
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert "email" not in buf.raw["repos"]["test-repo"]

    def test_remove_slack_channel(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        slack_harness.client.get("/config")
        response = slack_harness.client.post(
            "/api/config/remove",
            data={"path": "repos.test-repo.slack"},
            headers=XHR,
        )
        assert response.status_code == 200
        buf = slack_harness.server._config_handlers._buffer
        assert buf is not None
        assert "slack" not in buf.raw["repos"]["test-repo"]


class TestListStrWidget:
    def test_add_list_item_returns_widget(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.email.authorized_senders"},
            headers=XHR,
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "cfg-list-field" in html
        assert "X-Dirty-Count" in response.headers

    def test_remove_list_item_returns_widget(
        self, harness: ConfigEditorHarness
    ) -> None:
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
        html = response.get_data(as_text=True)
        assert "cfg-list-field" in html

    def test_edit_list_item(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.email.authorized_senders",
                "source": "literal",
                "value": "new@example.com",
                "index": "0",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        senders = buf.raw["repos"]["test-repo"]["email"]["authorized_senders"]
        assert senders[0] == "new@example.com"

    def test_edit_list_item_returns_widget(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.email.authorized_senders",
                "source": "literal",
                "value": "new@example.com",
                "index": "0",
            },
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "cfg-list-field" in html


class TestTaggedUnionListWidget:
    def test_add_tagged_union_rule(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        slack_harness.client.get("/config")
        response = slack_harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.slack.authorized"},
            headers=XHR,
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "cfg-tagged-union-field" in html
        buf = slack_harness.server._config_handlers._buffer
        assert buf is not None
        rules = buf.raw["repos"]["test-repo"]["slack"]["authorized"]
        assert len(rules) == 2  # Original + appended
        assert rules[1] == {"workspace_members": True}

    def test_add_tagged_union_rule_creates_list(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        """Adding a tagged union item creates the list if missing."""
        slack_harness.client.get("/config")
        buf = slack_harness.server._config_handlers._buffer
        assert buf is not None
        # Remove the authorized list entirely
        del buf.raw["repos"]["test-repo"]["slack"]["authorized"]
        response = slack_harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.slack.authorized"},
            headers=XHR,
        )
        assert response.status_code == 200
        rules = buf.raw["repos"]["test-repo"]["slack"]["authorized"]
        assert rules == [{"workspace_members": True}]

    def test_remove_tagged_union_rule(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        slack_harness.client.get("/config")
        response = slack_harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.slack.authorized",
                "index": "0",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = slack_harness.server._config_handlers._buffer
        assert buf is not None
        rules = buf.raw["repos"]["test-repo"]["slack"]["authorized"]
        assert len(rules) == 0

    def test_edit_tagged_union_rule(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        slack_harness.client.get("/config")
        response = slack_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.slack.authorized",
                "source": "literal",
                "index": "0",
                "rule_type": "user_id",
                "rule_value": "U12345",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = slack_harness.server._config_handlers._buffer
        assert buf is not None
        rule = buf.raw["repos"]["test-repo"]["slack"]["authorized"][0]
        assert rule == {"user_id": "U12345"}

    def test_edit_tagged_union_workspace_members(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        """workspace_members rule type stores True, not the rule_value."""
        slack_harness.client.get("/config")
        # First change to user_id
        slack_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.slack.authorized",
                "source": "literal",
                "index": "0",
                "rule_type": "user_id",
                "rule_value": "U999",
            },
            headers=XHR,
        )
        # Now change back to workspace_members
        response = slack_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.slack.authorized",
                "source": "literal",
                "index": "0",
                "rule_type": "workspace_members",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = slack_harness.server._config_handlers._buffer
        assert buf is not None
        rule = buf.raw["repos"]["test-repo"]["slack"]["authorized"][0]
        assert rule == {"workspace_members": True}


class TestChannelDirtyCount:
    def test_dirty_count_includes_channel_changes(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Changing an email field should increase dirty count."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.email.imap_server",
                "source": "literal",
                "value": "new-imap.example.com",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        dirty = int(response.headers.get("X-Dirty-Count", "0"))
        assert dirty >= 1

    def test_dirty_count_channel_added(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Adding a Slack channel increases dirty count."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.slack"},
            headers=XHR,
        )
        count = harness.server._config_handlers._compute_dirty_count()
        assert count >= 1

    def test_dirty_count_channel_removed(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Removing the email channel increases dirty count."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/remove",
            data={"path": "repos.test-repo.email"},
            headers=XHR,
        )
        count = harness.server._config_handlers._compute_dirty_count()
        assert count >= 1


class TestChannelDiff:
    def test_diff_shows_channel_field_change(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Diff includes email field changes."""
        harness.client.get("/config")
        harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.email.imap_server",
                "source": "literal",
                "value": "new-imap.example.com",
            },
            headers=XHR,
        )
        response = harness.client.get("/api/config/diff")
        html = response.get_data(as_text=True)
        assert "imap_server" in html
        assert "new-imap.example.com" in html

    def test_diff_shows_channel_added(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Diff shows added Slack channel."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/add",
            data={"path": "repos.test-repo.slack"},
            headers=XHR,
        )
        response = harness.client.get("/api/config/diff")
        html = response.get_data(as_text=True)
        assert "slack" in html
        assert "(added)" in html

    def test_diff_shows_channel_removed(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Diff shows removed email channel."""
        harness.client.get("/config")
        harness.client.post(
            "/api/config/remove",
            data={"path": "repos.test-repo.email"},
            headers=XHR,
        )
        response = harness.client.get("/api/config/diff")
        html = response.get_data(as_text=True)
        assert "email" in html
        assert "(removed)" in html


class TestChannelFieldPatch:
    def test_patch_email_scalar_field(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.email.imap_server",
                "source": "literal",
                "value": "mail.test.com",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["repos"]["test-repo"]["email"]["imap_server"] == (
            "mail.test.com"
        )

    def test_patch_slack_scalar_field(
        self, slack_harness: ConfigEditorHarness
    ) -> None:
        slack_harness.client.get("/config")
        response = slack_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.slack.bot_token",
                "source": "env",
                "value": "MY_BOT_TOKEN",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = slack_harness.server._config_handlers._buffer
        assert buf is not None
        from airut.yaml_env import EnvVar

        assert isinstance(
            buf.raw["repos"]["test-repo"]["slack"]["bot_token"], EnvVar
        )

    def test_patch_list_invalid_index(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.email.authorized_senders",
                "source": "literal",
                "value": "test",
                "index": "abc",
            },
            headers=XHR,
        )
        assert response.status_code == 400

    def test_patch_index_on_non_list_field(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Index param on a scalar field returns 400."""
        harness.client.get("/config")
        response = harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.email.imap_server",
                "source": "literal",
                "value": "test",
                "index": "0",
            },
            headers=XHR,
        )
        assert response.status_code == 400


class TestRemoveNonChannel:
    """Ensure remove on non-channel paths works normally."""

    def test_remove_non_channel_path_with_index(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Remove on a list path (not channel root) works normally."""
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
        assert "HX-Redirect" not in response.headers

    def test_remove_non_channel_path_no_key_no_index(
        self, harness: ConfigEditorHarness
    ) -> None:
        """Remove with path-only (no key/index) on a non-channel path."""
        harness.client.get("/config")
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        # Set a sub-block to remove
        buf.raw.setdefault("repos", {}).setdefault("test-repo", {})["model"] = (
            "opus"
        )
        response = harness.client.post(
            "/api/config/remove",
            data={"path": "repos.test-repo.model"},
            headers=XHR,
        )
        assert response.status_code == 200
        assert "HX-Redirect" not in response.headers


class TestParseChannelPath:
    def test_email_path(self) -> None:
        from airut.dashboard.handlers_config import ConfigEditorHandlers

        result = ConfigEditorHandlers._parse_channel_path("repos.my-repo.email")
        assert result == ("my-repo", "email")

    def test_slack_path(self) -> None:
        from airut.dashboard.handlers_config import ConfigEditorHandlers

        result = ConfigEditorHandlers._parse_channel_path("repos.my-repo.slack")
        assert result == ("my-repo", "slack")

    def test_non_channel_path(self) -> None:
        from airut.dashboard.handlers_config import ConfigEditorHandlers

        assert (
            ConfigEditorHandlers._parse_channel_path("repos.my-repo.model")
            is None
        )
        assert (
            ConfigEditorHandlers._parse_channel_path("dashboard.port") is None
        )

    def test_deep_path_not_channel(self) -> None:
        from airut.dashboard.handlers_config import ConfigEditorHandlers

        assert (
            ConfigEditorHandlers._parse_channel_path(
                "repos.my-repo.email.imap_server"
            )
            is None
        )


# ---------------------------------------------------------------------------
# Phase 4: Credentials + Dict Fields
# ---------------------------------------------------------------------------


def _make_sample_raw_with_credentials() -> dict[str, Any]:
    """Create a sample raw config with credential data."""
    raw = _make_sample_raw()
    raw["repos"]["test-repo"]["secrets"] = {
        "TOKEN_A": "value_a",
        "TOKEN_B": "value_b",
    }
    raw["repos"]["test-repo"]["masked_secrets"] = {
        "GITHUB_TOKEN": {
            "value": "ghp_test123",
            "scopes": ["api.github.com"],
            "headers": ["Authorization"],
            "allow_foreign_credentials": False,
        },
    }
    raw["repos"]["test-repo"]["signing_credentials"] = {
        "AWS_CREDS": {
            "type": "aws-sigv4",
            "access_key_id": {
                "name": "AWS_ACCESS_KEY_ID",
                "value": "AKIATEST1234",
            },
            "secret_access_key": {
                "name": "AWS_SECRET_ACCESS_KEY",
                "value": "wJalrXUtnFEMI",
            },
            "scopes": ["*.amazonaws.com"],
        },
    }
    raw["repos"]["test-repo"]["github_app_credentials"] = {
        "MY_APP": {
            "app_id": "123456",
            "private_key": "test-key-data",
            "installation_id": "789012",
            "scopes": ["api.github.com"],
        },
    }
    return raw


@pytest.fixture
def cred_harness(tmp_path: Path) -> ConfigEditorHarness:
    return ConfigEditorHarness(
        tmp_path, raw=_make_sample_raw_with_credentials()
    )


class TestDictStrStrWidget:
    """Tests for dict[str, str] widget (secrets)."""

    def test_repo_page_shows_secrets(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Plain Secrets" in html
        assert "TOKEN_A" in html
        assert "TOKEN_B" in html
        # container_env field was removed (use secrets instead)
        assert "Container Environment" not in html

    def test_patch_dict_entry(self, cred_harness: ConfigEditorHarness) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
                "source": "literal",
                "value": "new_value",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        assert (
            buf.raw["repos"]["test-repo"]["secrets"]["TOKEN_A"] == "new_value"
        )

    def test_patch_dict_entry_env(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
                "source": "env",
                "value": "SECRET_VAR",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        assert isinstance(
            buf.raw["repos"]["test-repo"]["secrets"]["TOKEN_A"], EnvVar
        )

    def test_patch_dict_entry_unset(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
                "source": "unset",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        assert "TOKEN_A" not in buf.raw["repos"]["test-repo"]["secrets"]

    def test_patch_dict_entry_returns_widget(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
                "source": "literal",
                "value": "new",
            },
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "cfg-dict-field" in html
        assert "X-Dirty-Count" in response.headers

    def test_add_dict_entry(self, cred_harness: ConfigEditorHarness) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.secrets",
                "key": "NEW_TOKEN",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        assert "NEW_TOKEN" in buf.raw["repos"]["test-repo"]["secrets"]
        assert buf.raw["repos"]["test-repo"]["secrets"]["NEW_TOKEN"] == ""

    def test_add_dict_entry_returns_widget(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.secrets",
                "key": "NEW_TOKEN",
            },
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "cfg-dict-field" in html
        assert "X-Dirty-Count" in response.headers

    def test_remove_dict_entry(self, cred_harness: ConfigEditorHarness) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        assert "TOKEN_A" not in buf.raw["repos"]["test-repo"]["secrets"]

    def test_remove_dict_entry_returns_widget(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
            },
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "cfg-dict-field" in html

    def test_patch_dict_unknown_path_returns_ok(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """PATCH with key on unknown path returns plain OK."""
        cred_harness.client.get("/config")
        response = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.nonexistent",
                "key": "K",
                "source": "literal",
                "value": "v",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert "X-Dirty-Count" in response.headers

    def test_add_dict_entry_creates_dict(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Add to a path that doesn't exist yet creates the dict."""
        cred_harness.client.get("/config")
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        # Remove secrets entirely
        del buf.raw["repos"]["test-repo"]["secrets"]
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.secrets",
                "key": "FRESH",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        assert buf.raw["repos"]["test-repo"]["secrets"]["FRESH"] == ""

    def test_add_dict_entry_empty_key_rejected(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Adding a dict entry with empty key returns 400."""
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.secrets",
                "key": "",
            },
            headers=XHR,
        )
        assert response.status_code == 400

    def test_add_dict_entry_whitespace_key_rejected(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Adding a dict entry with whitespace-only key returns 400."""
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.secrets",
                "key": "   ",
            },
            headers=XHR,
        )
        assert response.status_code == 400

    def test_dict_dirty_count(self, cred_harness: ConfigEditorHarness) -> None:
        """Adding a dict entry shows in dirty count."""
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.secrets",
                "key": "EXTRA",
            },
            headers=XHR,
        )
        count = int(response.headers["X-Dirty-Count"])
        assert count >= 1


class TestKeyedCollectionWidget:
    """Tests for keyed collection widget (masked_secrets, etc.)."""

    def test_repo_page_shows_masked_secrets(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Masked Secrets" in html
        assert "GITHUB_TOKEN" in html

    def test_repo_page_shows_signing_credentials(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "Signing Credentials" in html
        assert "AWS_CREDS" in html

    def test_repo_page_shows_github_app_credentials(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "GitHub App Credentials" in html
        assert "MY_APP" in html

    def test_keyed_collection_shows_item_fields(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        # Masked secret sub-fields should be visible
        assert "allow_foreign_credentials" in html

    def test_patch_keyed_collection_item_field(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.masked_secrets.GITHUB_TOKEN.value",
                "source": "literal",
                "value": "ghp_new_token",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        ms = buf.raw["repos"]["test-repo"]["masked_secrets"]["GITHUB_TOKEN"]
        assert ms["value"] == "ghp_new_token"

    def test_patch_keyed_collection_item_env(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.masked_secrets.GITHUB_TOKEN.value",
                "source": "env",
                "value": "GH_TOKEN_VAR",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        ms = buf.raw["repos"]["test-repo"]["masked_secrets"]["GITHUB_TOKEN"]
        assert isinstance(ms["value"], EnvVar)

    def test_add_keyed_collection_item(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.masked_secrets",
                "key": "OTHER_TOKEN",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        ms = buf.raw["repos"]["test-repo"]["masked_secrets"]
        assert "OTHER_TOKEN" in ms

    def test_add_keyed_collection_empty_key_rejected(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Adding a keyed collection entry with empty key returns 400."""
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.masked_secrets",
                "key": "",
            },
            headers=XHR,
        )
        assert response.status_code == 400

    def test_add_keyed_collection_whitespace_key_rejected(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Whitespace-only key is rejected for keyed collection."""
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.masked_secrets",
                "key": "  ",
            },
            headers=XHR,
        )
        assert response.status_code == 400

    def test_add_keyed_collection_returns_widget(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.masked_secrets",
                "key": "OTHER_TOKEN",
            },
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "cfg-keyed-collection" in html
        assert "X-Dirty-Count" in response.headers

    def test_remove_keyed_collection_item(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.masked_secrets",
                "key": "GITHUB_TOKEN",
            },
            headers=XHR,
        )
        assert response.status_code == 200
        buf = cred_harness.server._config_handlers._buffer
        assert buf is not None
        assert "GITHUB_TOKEN" not in buf.raw["repos"]["test-repo"].get(
            "masked_secrets", {}
        )

    def test_remove_keyed_collection_returns_widget(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/remove",
            data={
                "path": "repos.test-repo.masked_secrets",
                "key": "GITHUB_TOKEN",
            },
            headers=XHR,
        )
        html = response.get_data(as_text=True)
        assert "cfg-keyed-collection" in html

    def test_keyed_collection_dirty_count(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Adding a keyed collection entry shows in dirty count."""
        cred_harness.client.get("/config")
        response = cred_harness.client.post(
            "/api/config/add",
            data={
                "path": "repos.test-repo.masked_secrets",
                "key": "EXTRA",
            },
            headers=XHR,
        )
        count = int(response.headers["X-Dirty-Count"])
        assert count >= 1


class TestFindFieldSchemaKeyedCollection:
    """Tests for _find_field_schema with keyed collection item paths."""

    def test_find_keyed_collection_item_field(self) -> None:
        from airut.config.editor import EditorFieldSchema
        from airut.dashboard.handlers_config import _find_field_schema

        inner = EditorFieldSchema(
            name="value",
            path="value",
            type_tag="scalar",
            python_type="str",
            default="",
            required=False,
            doc="Value",
            scope="repo",
            secret=True,
        )
        coll = EditorFieldSchema(
            name="masked_secrets",
            path="repos.test.masked_secrets",
            type_tag="keyed_collection",
            python_type="dict",
            default=None,
            required=False,
            doc="Masked secrets",
            scope="repo",
            secret=True,
            item_class_name="MaskedSecret",
            item_fields=[inner],
        )
        found = _find_field_schema(
            [coll], "repos.test.masked_secrets.TOKEN.value"
        )
        assert found is not None
        assert found.name == "value"
        assert found.path == "repos.test.masked_secrets.TOKEN.value"

    def test_keyed_collection_no_match(self) -> None:
        from airut.config.editor import EditorFieldSchema
        from airut.dashboard.handlers_config import _find_field_schema

        inner = EditorFieldSchema(
            name="value",
            path="value",
            type_tag="scalar",
            python_type="str",
            default="",
            required=False,
            doc="Value",
            scope="repo",
            secret=True,
        )
        coll = EditorFieldSchema(
            name="masked_secrets",
            path="repos.test.masked_secrets",
            type_tag="keyed_collection",
            python_type="dict",
            default=None,
            required=False,
            doc="Masked secrets",
            scope="repo",
            secret=True,
            item_class_name="MaskedSecret",
            item_fields=[inner],
        )
        found = _find_field_schema(
            [coll], "repos.test.masked_secrets.TOKEN.nonexistent"
        )
        assert found is None


class TestFormatRawValueCollections:
    """Tests for format_raw_value with dict and list values."""

    def test_format_dict(self) -> None:
        from airut.config.editor import format_raw_value

        assert format_raw_value({"a": "1", "b": "2"}) == "(2 entries)"

    def test_format_empty_dict(self) -> None:
        from airut.config.editor import format_raw_value

        assert format_raw_value({}) == "(empty)"

    def test_format_list(self) -> None:
        from airut.config.editor import format_raw_value

        assert format_raw_value(["a", "b"]) == "(2 items)"

    def test_format_empty_list(self) -> None:
        from airut.config.editor import format_raw_value

        assert format_raw_value([]) == "(empty list)"


class TestPrefixedField:
    """Tests for the prefixed_field Jinja2 helper."""

    @staticmethod
    def _get_pf() -> Callable[..., "EditorFieldSchema"]:
        from airut.dashboard.templating import create_jinja_env

        env = create_jinja_env()
        return env.globals["prefixed_field"]  # type: ignore[return-value]

    def test_prefixed_field_rejects_non_schema(self) -> None:
        pf = self._get_pf()
        with pytest.raises(TypeError, match="Expected EditorFieldSchema"):
            pf("not a schema", "prefix")

    def test_prefixed_field_basic(self) -> None:
        from airut.config.editor import EditorFieldSchema

        pf = self._get_pf()

        f = EditorFieldSchema(
            name="value",
            path="value",
            type_tag="scalar",
            python_type="str",
            default="",
            required=False,
            doc="Value",
            scope="repo",
            secret=True,
        )
        result = pf(f, "repos.test.masked_secrets.TOKEN")
        assert isinstance(result, EditorFieldSchema)
        assert result.path == ("repos.test.masked_secrets.TOKEN.value")
        assert result.name == "value"

    def test_prefixed_field_nested(self) -> None:
        from airut.config.editor import EditorFieldSchema

        pf = self._get_pf()

        inner = EditorFieldSchema(
            name="name",
            path="access_key_id.name",
            type_tag="scalar",
            python_type="str",
            default="",
            required=False,
            doc="Name",
            scope="repo",
            secret=False,
        )
        outer = EditorFieldSchema(
            name="access_key_id",
            path="access_key_id",
            type_tag="nested",
            python_type="SigningCredentialField",
            default=None,
            required=True,
            doc="Access key",
            scope="repo",
            secret=True,
            nested_fields=[inner],
        )
        result = pf(outer, "repos.test.signing_credentials.AWS")
        assert isinstance(result, EditorFieldSchema)
        pfx = "repos.test.signing_credentials.AWS"
        assert result.path == f"{pfx}.access_key_id"
        assert result.nested_fields is not None
        assert result.nested_fields[0].path == f"{pfx}.access_key_id.name"

    def test_prefixed_field_item_fields(self) -> None:
        from airut.config.editor import EditorFieldSchema

        pf = self._get_pf()

        item_field = EditorFieldSchema(
            name="value",
            path="value",
            type_tag="scalar",
            python_type="str",
            default="",
            required=False,
            doc="Value",
            scope="repo",
            secret=True,
        )
        collection = EditorFieldSchema(
            name="inner_coll",
            path="inner_coll",
            type_tag="keyed_collection",
            python_type="dict",
            default=None,
            required=False,
            doc="Inner collection",
            scope="repo",
            secret=False,
            item_fields=[item_field],
            item_class_name="SomeType",
        )
        result = pf(collection, "repos.test.outer.KEY")
        assert isinstance(result, EditorFieldSchema)
        assert result.path == "repos.test.outer.KEY.inner_coll"
        assert result.item_fields is not None
        assert result.item_fields[0].path == "repos.test.outer.KEY.value"


class TestCredentialDiff:
    """Tests for diff with credential data."""

    def test_diff_shows_per_key_credential_changes(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        cred_harness.client.get("/config")
        # Modify a secret
        cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
                "source": "literal",
                "value": "changed_value",
            },
            headers=XHR,
        )
        response = cred_harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        # Per-key diff: should show the specific key, not "(N entries)"
        assert "secrets.TOKEN_A" in html
        assert "(1 entries)" not in html

    def test_diff_shows_per_subfield_masked_secret_changes(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Masked secret diff shows per-sub-field changes, not '(N entries)'."""
        cred_harness.client.get("/config")
        # Modify the value sub-field of a masked secret
        cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.masked_secrets.GITHUB_TOKEN.value",
                "source": "literal",
                "value": "ghp_changed",
            },
            headers=XHR,
        )
        response = cred_harness.client.get("/api/config/diff")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        # Should show the sub-field path, not "(N entries)"
        assert "masked_secrets.GITHUB_TOKEN.value" in html
        assert "entries)" not in html

    def test_credential_repo_page_no_placeholder(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Phase 4 placeholder banner should be gone."""
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert "will be available in a future update" not in html

    def test_keyed_collection_cards_collapsed_by_default(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert '<details class="cfg-collection-card" open>' not in html
        assert '<details class="cfg-collection-card">' in html

    def test_no_scope_labels_in_field_widgets(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        assert 'class="cfg-scope cfg-repo"' not in html

    def test_humanized_type_names_in_ui(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        response = cred_harness.client.get("/config/repos/test-repo")
        html = response.get_data(as_text=True)
        # Should show "Masked Secret", not "MaskedSecret"
        assert "Masked Secret" in html
        assert "MaskedSecret" not in html


class TestDiffDictField:
    """Tests for diff_dict_field and count_dict_field_changes."""

    def test_diff_dict_field_added_key(self) -> None:
        from airut.config.editor import (
            MISSING,
            EditorFieldSchema,
            diff_dict_field,
        )

        fs = EditorFieldSchema(
            name="secrets",
            path="repos.test.secrets",
            type_tag="dict_str_str",
            python_type="dict",
            default=None,
            required=False,
            doc="Secrets",
            scope="repo",
            secret=True,
        )
        changes = diff_dict_field(fs, {"KEY": "val"}, MISSING)
        assert len(changes) == 1
        assert changes[0]["field"] == "repos.test.secrets.KEY"
        assert changes[0]["old"] == "(not set)"
        assert changes[0]["new"] == "val"

    def test_diff_dict_field_removed_key(self) -> None:
        from airut.config.editor import EditorFieldSchema, diff_dict_field

        fs = EditorFieldSchema(
            name="secrets",
            path="repos.test.secrets",
            type_tag="dict_str_str",
            python_type="dict",
            default=None,
            required=False,
            doc="Secrets",
            scope="repo",
            secret=True,
        )
        changes = diff_dict_field(fs, {}, {"KEY": "val"})
        assert len(changes) == 1
        assert changes[0]["new"] == "(not set)"

    def test_diff_dict_field_changed_value(self) -> None:
        from airut.config.editor import EditorFieldSchema, diff_dict_field

        fs = EditorFieldSchema(
            name="secrets",
            path="repos.test.secrets",
            type_tag="dict_str_str",
            python_type="dict",
            default=None,
            required=False,
            doc="Secrets",
            scope="repo",
            secret=True,
        )
        changes = diff_dict_field(fs, {"K": "new_val"}, {"K": "old_val"})
        assert len(changes) == 1
        assert changes[0]["old"] == "old_val"
        assert changes[0]["new"] == "new_val"

    def test_diff_dict_field_no_changes(self) -> None:
        from airut.config.editor import EditorFieldSchema, diff_dict_field

        fs = EditorFieldSchema(
            name="secrets",
            path="repos.test.secrets",
            type_tag="dict_str_str",
            python_type="dict",
            default=None,
            required=False,
            doc="Secrets",
            scope="repo",
            secret=True,
        )
        changes = diff_dict_field(fs, {"K": "v"}, {"K": "v"})
        assert changes == []

    def test_diff_keyed_collection_added_key(self) -> None:
        """Keyed collection diff expands sub-fields, not '(N entries)'."""
        from airut.config.editor import (
            MISSING,
            EditorFieldSchema,
            diff_dict_field,
        )

        item_fields = [
            EditorFieldSchema(
                name="value",
                path="value",
                type_tag="scalar",
                python_type="str",
                default=MISSING,
                required=True,
                doc="Secret value",
                scope="repo",
                secret=True,
            ),
            EditorFieldSchema(
                name="scopes",
                path="scopes",
                type_tag="list_str",
                python_type="list[str]",
                default=[],
                required=False,
                doc="Host patterns",
                scope="repo",
                secret=False,
            ),
        ]
        fs = EditorFieldSchema(
            name="masked_secrets",
            path="repos.test.masked_secrets",
            type_tag="keyed_collection",
            python_type="dict",
            default=None,
            required=False,
            doc="Masked secrets",
            scope="repo",
            secret=False,
            item_fields=item_fields,
        )
        changes = diff_dict_field(
            fs,
            {"TOKEN": {"value": "ghp_abc", "scopes": ["github.com"]}},
            MISSING,
        )
        fields = {c["field"] for c in changes}
        assert "repos.test.masked_secrets.TOKEN.value" in fields
        assert "repos.test.masked_secrets.TOKEN.scopes" in fields
        # Should NOT contain the opaque summary
        assert all("entries" not in c["new"] for c in changes)

    def test_diff_keyed_collection_removed_key(self) -> None:
        """Removing a keyed collection entry shows per-sub-field removal."""
        from airut.config.editor import (
            MISSING,
            EditorFieldSchema,
            diff_dict_field,
        )

        item_fields = [
            EditorFieldSchema(
                name="value",
                path="value",
                type_tag="scalar",
                python_type="str",
                default=MISSING,
                required=True,
                doc="Secret value",
                scope="repo",
                secret=True,
            ),
        ]
        fs = EditorFieldSchema(
            name="masked_secrets",
            path="repos.test.masked_secrets",
            type_tag="keyed_collection",
            python_type="dict",
            default=None,
            required=False,
            doc="Masked secrets",
            scope="repo",
            secret=False,
            item_fields=item_fields,
        )
        changes = diff_dict_field(
            fs,
            {},
            {"TOKEN": {"value": "ghp_old"}},
        )
        assert len(changes) == 1
        assert changes[0]["field"] == "repos.test.masked_secrets.TOKEN.value"
        assert changes[0]["old"] == "ghp_old"
        assert changes[0]["new"] == "(not set)"

    def test_diff_keyed_collection_changed_subfield(self) -> None:
        """Changed sub-field shows only that field."""
        from airut.config.editor import (
            MISSING,
            EditorFieldSchema,
            diff_dict_field,
        )

        item_fields = [
            EditorFieldSchema(
                name="value",
                path="value",
                type_tag="scalar",
                python_type="str",
                default=MISSING,
                required=True,
                doc="Secret value",
                scope="repo",
                secret=True,
            ),
            EditorFieldSchema(
                name="scopes",
                path="scopes",
                type_tag="list_str",
                python_type="list[str]",
                default=[],
                required=False,
                doc="Host patterns",
                scope="repo",
                secret=False,
            ),
        ]
        fs = EditorFieldSchema(
            name="masked_secrets",
            path="repos.test.masked_secrets",
            type_tag="keyed_collection",
            python_type="dict",
            default=None,
            required=False,
            doc="Masked secrets",
            scope="repo",
            secret=False,
            item_fields=item_fields,
        )
        changes = diff_dict_field(
            fs,
            {"TOKEN": {"value": "ghp_new", "scopes": ["github.com"]}},
            {"TOKEN": {"value": "ghp_old", "scopes": ["github.com"]}},
        )
        # Only value changed, scopes unchanged
        assert len(changes) == 1
        assert changes[0]["field"] == "repos.test.masked_secrets.TOKEN.value"
        assert changes[0]["old"] == "ghp_old"
        assert changes[0]["new"] == "ghp_new"

    def test_diff_keyed_collection_no_changes(self) -> None:
        """Identical keyed collection entries produce no diff rows."""
        from airut.config.editor import (
            EditorFieldSchema,
            diff_dict_field,
        )

        item_fields = [
            EditorFieldSchema(
                name="value",
                path="value",
                type_tag="scalar",
                python_type="str",
                default=None,
                required=True,
                doc="Value",
                scope="repo",
                secret=True,
            ),
        ]
        fs = EditorFieldSchema(
            name="masked_secrets",
            path="repos.test.masked_secrets",
            type_tag="keyed_collection",
            python_type="dict",
            default=None,
            required=False,
            doc="Masked secrets",
            scope="repo",
            secret=False,
            item_fields=item_fields,
        )
        changes = diff_dict_field(
            fs,
            {"TOKEN": {"value": "same"}},
            {"TOKEN": {"value": "same"}},
        )
        assert changes == []

    def test_count_dict_field_changes(self) -> None:
        from airut.config.editor import count_dict_field_changes

        assert count_dict_field_changes({"A": "1", "B": "2"}, {"A": "1"}) == 1
        assert count_dict_field_changes({}, {"A": "1"}) == 1
        assert count_dict_field_changes({"A": "1"}, {"A": "1"}) == 0

    def test_dirty_count_per_key(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Dirty count should count per key, not per dict."""
        cred_harness.client.get("/config")
        # Change one secret key
        resp = cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
                "source": "literal",
                "value": "changed",
            },
            headers=XHR,
        )
        dirty = int(resp.headers["X-Dirty-Count"])
        assert dirty == 1  # One key changed, not "1 dict field"

    def test_diff_added_repo_with_dict_fields(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Diff for a newly added repo expands dict fields per-key."""
        cred_harness.client.get("/config")
        # Add a new repo
        cred_harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-repo"},
            headers=XHR,
        )
        # Add a secret to it via API
        cred_harness.client.post(
            "/api/config/add",
            data={"path": "repos.new-repo.secrets", "key": "S1"},
            headers=XHR,
        )
        cred_harness.client.patch(
            "/api/config/field",
            data={
                "path": "repos.new-repo.secrets",
                "key": "S1",
                "source": "literal",
                "value": "v1",
            },
            headers=XHR,
        )
        response = cred_harness.client.get("/api/config/diff")
        html = response.get_data(as_text=True)
        # Per-key: should show secrets.S1, not "(1 entries)"
        assert "secrets.S1" in html

    def test_diff_removed_repo_with_dict_fields(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Diff for removed repo expands dict fields per-key."""
        cred_harness.client.get("/config")
        # Remove the test-repo (which has secrets)
        cred_harness.client.post(
            "/api/config/remove",
            data={"path": "repos", "key": "test-repo"},
            headers=XHR,
        )
        response = cred_harness.client.get("/api/config/diff")
        html = response.get_data(as_text=True)
        # Per-key: should show individual secret keys
        assert "secrets.TOKEN_A" in html

    def test_dirty_count_added_repo_dict_fields(
        self, cred_harness: ConfigEditorHarness
    ) -> None:
        """Dirty count for added repo counts dict keys."""
        cred_harness.client.get("/config")
        cred_harness.client.post(
            "/api/config/add",
            data={"path": "repos", "key": "new-repo"},
            headers=XHR,
        )
        # Add two secret keys via API
        cred_harness.client.post(
            "/api/config/add",
            data={"path": "repos.new-repo.secrets", "key": "A"},
            headers=XHR,
        )
        resp = cred_harness.client.post(
            "/api/config/add",
            data={"path": "repos.new-repo.secrets", "key": "B"},
            headers=XHR,
        )
        dirty = int(resp.headers["X-Dirty-Count"])
        # Should count each dict key individually
        assert dirty >= 2


class TestHumanizeTypeFilter:
    """Tests for humanize_type Jinja2 filter."""

    @staticmethod
    def _get_filter() -> Callable[..., str]:
        from airut.dashboard.templating import create_jinja_env

        env = create_jinja_env()
        return env.filters["humanize_type"]  # type: ignore[return-value]

    def test_basic_camel_case(self) -> None:
        assert self._get_filter()("MaskedSecret") == "Masked Secret"

    def test_github_app_credential(self) -> None:
        fn = self._get_filter()
        assert fn("GitHubAppCredential") == "GitHub App Credential"

    def test_signing_credential(self) -> None:
        assert self._get_filter()("SigningCredential") == "Signing Credential"

    def test_single_word(self) -> None:
        assert self._get_filter()("Entry") == "Entry"

    def test_fallback_camel_case(self) -> None:
        assert self._get_filter()("SomeOtherType") == "Some Other Type"


# ---------------------------------------------------------------------------
# Phase 5: Variables
# ---------------------------------------------------------------------------


def _make_raw_with_vars() -> dict[str, Any]:
    """Create a sample raw config with a vars: section and !var references."""
    from airut.yaml_env import VarRef

    raw = _make_sample_raw()
    raw["vars"] = {
        "mail_server": "imap.shared.com",
        "smtp_host": EnvVar("SMTP_HOST"),
    }
    # Replace literal imap_server with a !var reference
    raw["repos"]["test-repo"]["email"]["imap_server"] = VarRef("mail_server")
    return raw


class TestFindVarReferences:
    """Tests for find_var_references utility."""

    def test_no_vars(self) -> None:
        from airut.config.editor import find_var_references

        raw = _make_sample_raw()
        refs = find_var_references(raw)
        assert refs == {}

    def test_finds_var_refs(self) -> None:
        from airut.config.editor import find_var_references

        raw = _make_raw_with_vars()
        refs = find_var_references(raw)
        assert "mail_server" in refs
        assert any("imap_server" in p for p in refs["mail_server"])
        # smtp_host is only used as a var *value* (!env), not referenced
        assert "smtp_host" not in refs

    def test_excludes_vars_section_itself(self) -> None:
        from airut.config.editor import find_var_references
        from airut.yaml_env import VarRef

        raw = _make_sample_raw()
        raw["vars"] = {"a": "hello"}
        # Place a VarRef in repos section only
        raw["repos"]["test-repo"]["email"]["imap_server"] = VarRef("a")
        refs = find_var_references(raw)
        assert "a" in refs
        # Only one reference (in repos), not from vars section
        assert len(refs["a"]) == 1

    def test_finds_refs_in_lists(self) -> None:
        from airut.config.editor import find_var_references
        from airut.yaml_env import VarRef

        raw = {"vars": {"x": "val"}, "items": [VarRef("x"), "plain"]}
        refs = find_var_references(raw)
        assert "x" in refs
        assert "items[0]" in refs["x"]

    def test_finds_top_level_var_ref(self) -> None:
        from airut.config.editor import find_var_references
        from airut.yaml_env import VarRef

        raw = {"vars": {"x": "val"}, "top": VarRef("x")}
        refs = find_var_references(raw)
        assert "x" in refs
        assert "top" in refs["x"]


class TestRenameVarReferences:
    """Tests for rename_var_references utility."""

    def test_renames_refs(self) -> None:
        from airut.config.editor import rename_var_references
        from airut.yaml_env import VarRef

        raw = _make_raw_with_vars()
        count = rename_var_references(raw, "mail_server", "imap_host")
        assert count == 1
        # Reference updated
        val = raw["repos"]["test-repo"]["email"]["imap_server"]
        assert isinstance(val, VarRef)
        assert val.var_name == "imap_host"

    def test_rename_no_match(self) -> None:
        from airut.config.editor import rename_var_references

        raw = _make_sample_raw()
        count = rename_var_references(raw, "nonexistent", "new_name")
        assert count == 0

    def test_rename_in_list(self) -> None:
        from airut.config.editor import rename_var_references
        from airut.yaml_env import VarRef

        raw = {"vars": {"x": "v"}, "data": [VarRef("x")]}
        count = rename_var_references(raw, "x", "y")
        assert count == 1
        assert raw["data"][0].var_name == "y"

    def test_rename_in_nested_list(self) -> None:
        from airut.config.editor import rename_var_references
        from airut.yaml_env import VarRef

        raw = {"vars": {"x": "v"}, "data": [{"inner": VarRef("x")}]}
        count = rename_var_references(raw, "x", "y")
        assert count == 1
        assert raw["data"][0]["inner"].var_name == "y"

    def test_rename_skips_vars_section(self) -> None:
        from airut.config.editor import rename_var_references
        from airut.yaml_env import VarRef

        raw = {"vars": {"old": "val"}, "other": VarRef("old")}
        rename_var_references(raw, "old", "new")
        # vars section is NOT modified by rename_var_references
        assert "old" in raw["vars"]


class TestVarsPageLoad:
    """Tests for vars section rendering on config page."""

    def test_config_page_shows_vars_section(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        resp = h.client.get("/config")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Variables" in html
        assert "mail_server" in html
        assert "smtp_host" in html

    def test_config_page_shows_ref_count(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        resp = h.client.get("/config")
        html = resp.get_data(as_text=True)
        # mail_server is referenced once
        assert "1 ref" in html
        # smtp_host is unused
        assert "unused" in html

    def test_config_page_no_vars(self, harness: ConfigEditorHarness) -> None:
        """Config page renders without errors when no vars: section exists."""
        resp = harness.client.get("/config")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Variables" in html
        assert "No variables defined" in html


class TestVarsAdd:
    """Tests for adding variables."""

    def test_add_variable(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        resp = harness.client.post(
            "/api/config/add",
            data={"path": "vars", "key": "new_var"},
            headers=XHR,
        )
        assert resp.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["vars"]["new_var"] == ""

    def test_add_variable_no_duplicate(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        h.client.post(
            "/api/config/add",
            data={"path": "vars", "key": "mail_server"},
            headers=XHR,
        )
        buf = h.server._config_handlers._buffer
        assert buf is not None
        # Value should be unchanged
        assert buf.raw["vars"]["mail_server"] == "imap.shared.com"

    def test_add_variable_redirects(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        resp = harness.client.post(
            "/api/config/add",
            data={"path": "vars", "key": "my_var"},
            headers=XHR,
        )
        assert resp.headers.get("HX-Redirect") == "/config"


class TestVarsRemove:
    """Tests for removing variables."""

    def test_remove_variable(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.post(
            "/api/config/remove",
            data={"path": "vars", "key": "mail_server"},
            headers=XHR,
        )
        assert resp.status_code == 200
        buf = h.server._config_handlers._buffer
        assert buf is not None
        assert "mail_server" not in buf.raw["vars"]

    def test_remove_variable_redirects(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.post(
            "/api/config/remove",
            data={"path": "vars", "key": "smtp_host"},
            headers=XHR,
        )
        assert resp.headers.get("HX-Redirect") == "/config"


class TestVarsRename:
    """Tests for renaming variables (updates all !var references)."""

    def test_rename_variable(self, tmp_path: Path) -> None:
        from airut.yaml_env import VarRef

        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.post(
            "/api/config/add",
            data={
                "path": "vars",
                "key": "imap_host",
                "rename_from": "mail_server",
            },
            headers=XHR,
        )
        assert resp.status_code == 200
        buf = h.server._config_handlers._buffer
        assert buf is not None
        # Old key removed, new key has old value
        assert "mail_server" not in buf.raw["vars"]
        assert buf.raw["vars"]["imap_host"] == "imap.shared.com"
        # !var references updated
        ref = buf.raw["repos"]["test-repo"]["email"]["imap_server"]
        assert isinstance(ref, VarRef)
        assert ref.var_name == "imap_host"

    def test_rename_nonexistent_variable_noop(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        resp = harness.client.post(
            "/api/config/add",
            data={
                "path": "vars",
                "key": "new_name",
                "rename_from": "nonexistent",
            },
            headers=XHR,
        )
        assert resp.status_code == 200
        buf = harness.server._config_handlers._buffer
        assert buf is not None
        # No vars section created for nonexistent rename
        assert "new_name" not in buf.raw.get("vars", {})


class TestVarsFieldPatch:
    """Tests for editing variable values."""

    def test_set_var_literal(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "literal",
                "value": "imap.new.com",
            },
            headers=XHR,
        )
        assert resp.status_code == 200
        buf = h.server._config_handlers._buffer
        assert buf is not None
        assert buf.raw["vars"]["mail_server"] == "imap.new.com"

    def test_set_var_env(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "env",
                "value": "IMAP_HOST",
            },
            headers=XHR,
        )
        assert resp.status_code == 200
        buf = h.server._config_handlers._buffer
        assert buf is not None
        val = buf.raw["vars"]["mail_server"]
        assert isinstance(val, EnvVar)
        assert val.var_name == "IMAP_HOST"

    def test_set_var_var_rejected(self, tmp_path: Path) -> None:
        """!var source is rejected for vars values (no var-to-var)."""
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "var",
                "value": "other_var",
            },
            headers=XHR,
        )
        assert resp.status_code == 400

    def test_patch_returns_vars_html_fragment(self, tmp_path: Path) -> None:
        """PATCH on a vars field returns the vars section HTML fragment."""
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "literal",
                "value": "new.host.com",
            },
            headers=XHR,
        )
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "vars-section" in html
        assert "new.host.com" in html


class TestVarsDirtyCount:
    """Tests for vars changes in dirty count."""

    def test_add_var_increments_dirty_count(
        self, harness: ConfigEditorHarness
    ) -> None:
        harness.client.get("/config")
        resp = harness.client.post(
            "/api/config/add",
            data={"path": "vars", "key": "new_var"},
            headers=XHR,
        )
        assert resp.headers["X-Dirty-Count"] == "1"

    def test_remove_var_increments_dirty_count(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.post(
            "/api/config/remove",
            data={"path": "vars", "key": "mail_server"},
            headers=XHR,
        )
        assert int(resp.headers["X-Dirty-Count"]) >= 1

    def test_edit_var_value_increments_dirty_count(
        self, tmp_path: Path
    ) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        resp = h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "literal",
                "value": "changed.host.com",
            },
            headers=XHR,
        )
        assert int(resp.headers["X-Dirty-Count"]) >= 1

    def test_revert_var_gives_zero_dirty_count(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        # Change then revert
        h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "literal",
                "value": "changed.com",
            },
            headers=XHR,
        )
        resp = h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "literal",
                "value": "imap.shared.com",
            },
            headers=XHR,
        )
        assert resp.headers["X-Dirty-Count"] == "0"


class TestVarsDiff:
    """Tests for vars changes in diff output."""

    def test_diff_shows_added_var(self, harness: ConfigEditorHarness) -> None:
        harness.client.get("/config")
        harness.client.post(
            "/api/config/add",
            data={"path": "vars", "key": "new_var"},
            headers=XHR,
        )
        resp = harness.client.get("/api/config/diff")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "vars.new_var" in html

    def test_diff_shows_changed_var(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        h.client.patch(
            "/api/config/field",
            data={
                "path": "vars.mail_server",
                "source": "literal",
                "value": "changed.host.com",
            },
            headers=XHR,
        )
        resp = h.client.get("/api/config/diff")
        html = resp.get_data(as_text=True)
        assert "vars.mail_server" in html
        assert "changed.host.com" in html

    def test_diff_shows_removed_var(self, tmp_path: Path) -> None:
        h = ConfigEditorHarness(tmp_path, raw=_make_raw_with_vars())
        h.client.get("/config")
        h.client.post(
            "/api/config/remove",
            data={"path": "vars", "key": "mail_server"},
            headers=XHR,
        )
        resp = h.client.get("/api/config/diff")
        html = resp.get_data(as_text=True)
        assert "vars.mail_server" in html
        assert "(not set)" in html
