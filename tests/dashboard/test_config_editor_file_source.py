# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the config editor's ``!file`` value source."""

from pathlib import Path

from airut.yaml_env import FileRef
from tests.dashboard.test_config_editor import (
    XHR,
    ConfigEditorHarness,
    _make_sample_raw_with_credentials,
)


def _patch(
    harness: ConfigEditorHarness, data: dict[str, str]
) -> tuple[int, str]:
    response = harness.client.patch("/api/config/field", data=data, headers=XHR)
    return response.status_code, response.get_data(as_text=True)


class TestScalarField:
    def test_file_tab_offered(self, tmp_path: Path) -> None:
        harness = ConfigEditorHarness(tmp_path)
        html = harness.client.get("/config").get_data(as_text=True)
        assert '"path":"dashboard.base_url","source":"file","value":""' in html
        # Bool fields have no file source.
        assert '"path":"dashboard.enabled","source":"file"' not in html

    def test_set_file_source(self, tmp_path: Path) -> None:
        harness = ConfigEditorHarness(tmp_path)
        harness.client.get("/config")

        status, html = _patch(
            harness,
            {
                "path": "dashboard.base_url",
                "source": "file",
                "value": "/run/secrets/url",
            },
        )

        assert status == 200
        buffer = harness.server._config_handlers._buffer
        assert buffer is not None
        assert buffer.raw["dashboard"]["base_url"] == FileRef(
            "/run/secrets/url"
        )
        assert 'data-source="file"' in html
        assert 'value="/run/secrets/url"' in html
        assert 'placeholder="/run/secrets/NAME"' in html

    def test_diff_shows_file_reference(self, tmp_path: Path) -> None:
        harness = ConfigEditorHarness(tmp_path)
        harness.client.get("/config")
        _patch(
            harness,
            {
                "path": "dashboard.base_url",
                "source": "file",
                "value": "/run/secrets/url",
            },
        )
        html = harness.client.get("/api/config/diff", headers=XHR).get_data(
            as_text=True
        )
        assert "!file /run/secrets/url" in html


class TestDictEntry:
    def test_set_file_source(self, tmp_path: Path) -> None:
        harness = ConfigEditorHarness(
            tmp_path, raw=_make_sample_raw_with_credentials()
        )
        harness.client.get("/config")

        status, html = _patch(
            harness,
            {
                "path": "repos.test-repo.secrets",
                "key": "TOKEN_A",
                "source": "file",
                "value": "/run/secrets/token-a",
            },
        )

        assert status == 200
        buffer = harness.server._config_handlers._buffer
        assert buffer is not None
        secrets = buffer.raw["repos"]["test-repo"]["secrets"]
        assert secrets["TOKEN_A"] == FileRef("/run/secrets/token-a")
        assert 'placeholder="/run/secrets/NAME"' in html


class TestVars:
    def test_set_file_source(self, tmp_path: Path) -> None:
        raw = _make_sample_raw_with_credentials()
        raw["vars"] = {"shared": "literal"}
        harness = ConfigEditorHarness(tmp_path, raw=raw)
        harness.client.get("/config")

        status, html = _patch(
            harness,
            {
                "path": "vars.shared",
                "source": "file",
                "value": "/run/secrets/shared",
            },
        )

        assert status == 200
        buffer = harness.server._config_handlers._buffer
        assert buffer is not None
        assert buffer.raw["vars"]["shared"] == FileRef("/run/secrets/shared")
        # The input edits the file path, not an env var name.
        assert '"path":"vars.shared","source":"file"}' in html
        assert 'placeholder="/run/secrets/NAME"' in html
