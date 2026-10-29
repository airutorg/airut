# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the config editor's read-only (viewer) mode."""

from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from airut.config.source import YamlConfigSource
from tests.conftest import make_sample_raw
from tests.dashboard.test_config_editor import (
    XHR,
    ConfigEditorHarness,
    _make_sample_raw_with_credentials,
    _make_sample_raw_with_slack,
)


_CONTROLS = frozenset({"button", "input", "select", "textarea", "form"})
_MUTATING_HX = ("hx-post", "hx-patch", "hx-put", "hx-delete")


class _ControlFinder(HTMLParser):
    """Collect interactive elements outside any disabled fieldset."""

    _VOID = frozenset({"input", "br", "hr", "img", "link", "meta"})

    def __init__(self) -> None:
        super().__init__()
        # Open elements: (tag, is a disabled fieldset).
        self._stack: list[tuple[str, bool]] = []
        self.outside: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        names = {name for name, _ in attrs}
        inside = any(disabled for _, disabled in self._stack)
        if not inside and (
            tag in _CONTROLS or names.intersection(_MUTATING_HX)
        ):
            self.outside.append(self.get_starttag_text() or tag)
        if tag not in self._VOID:
            self._stack.append((tag, tag == "fieldset" and "disabled" in names))

    def handle_endtag(self, tag: str) -> None:
        # Pop up to the matching start tag, so implicitly closed
        # elements (e.g. <p> without </p>) cannot strand an entry.
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                return


@pytest.fixture
def read_only(tmp_path: Path) -> ConfigEditorHarness:
    """Harness whose config source is forced read-only."""
    return ConfigEditorHarness(tmp_path, read_only=True)


class TestPages:
    def test_global_page_is_a_viewer(
        self, read_only: ConfigEditorHarness
    ) -> None:
        html = read_only.client.get("/config").get_data(as_text=True)

        assert 'id="read-only-banner"' in html
        assert "the gateway runs with --read-only-config" in html
        assert '<fieldset class="cfg-fieldset" disabled>' in html
        # Values are still shown.
        assert "dashboard.port" in html
        # Nothing to save, discard or add.
        assert 'id="review-save-btn"' not in html
        assert 'id="discard-btn"' not in html
        assert 'id="diff-modal"' not in html
        assert 'class="cfg-add-repo"' not in html
        assert ">View</a>" in html

    def test_repo_page_is_a_viewer(
        self, read_only: ConfigEditorHarness
    ) -> None:
        html = read_only.client.get("/config/repos/test-repo").get_data(
            as_text=True
        )

        assert 'id="read-only-banner"' in html
        assert '<fieldset class="cfg-fieldset" disabled>' in html
        assert "imap.server" in html
        assert 'id="review-save-btn"' not in html
        assert 'id="remove-repo-btn"' not in html
        assert "Danger Zone" not in html

    @pytest.mark.parametrize(
        "make_raw",
        [
            make_sample_raw,
            _make_sample_raw_with_slack,
            _make_sample_raw_with_credentials,
        ],
    )
    def test_no_control_outside_disabled_fieldset(
        self, tmp_path: Path, make_raw: Callable[[], dict[str, Any]]
    ) -> None:
        """Every control on a viewer page is disabled by the fieldset."""
        raw = make_raw()
        raw["vars"] = {"shared_host": "10.0.0.1"}
        harness = ConfigEditorHarness(tmp_path, raw=raw, read_only=True)
        for url in ("/config", "/config/repos/test-repo"):
            finder = _ControlFinder()
            finder.feed(harness.client.get(url).get_data(as_text=True))
            assert finder.outside == [], url

    def test_writable_pages_are_editors(self, tmp_path: Path) -> None:
        harness = ConfigEditorHarness(tmp_path)
        for url in ("/config", "/config/repos/test-repo"):
            html = harness.client.get(url).get_data(as_text=True)
            assert 'id="read-only-banner"' not in html
            assert '<fieldset class="cfg-fieldset">' in html
            assert 'id="review-save-btn"' in html

    def test_symlinked_config_is_read_only(self, tmp_path: Path) -> None:
        """A config linked from elsewhere (e.g. Nix) is read-only."""
        harness = ConfigEditorHarness(tmp_path)
        target = tmp_path / "managed.yaml"
        target.write_text("{}\n")
        harness._config_path.symlink_to(target)

        html = harness.client.get("/config").get_data(as_text=True)

        assert f"{harness._config_path} is a symlink" in html
        assert 'id="review-save-btn"' not in html

    def test_unsaved_edits_dropped_when_config_turns_read_only(
        self, tmp_path: Path
    ) -> None:
        """The viewer shows the live config, not edits it cannot save.

        E.g. home-manager replaces the file with a symlink while the
        editor holds unsaved edits.
        """
        harness = ConfigEditorHarness(tmp_path)
        harness.client.get("/config")
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

        harness._config_source = YamlConfigSource(
            harness._config_path, read_only=True
        )
        html = harness.client.get("/config").get_data(as_text=True)

        assert 'id="read-only-banner"' in html
        assert 'value="9999"' not in html
        buffer = harness.server._config_handlers._buffer
        assert buffer is not None
        assert not buffer.dirty


class TestMutationsRejected:
    """Every mutation endpoint returns 403 and changes nothing."""

    @pytest.mark.parametrize(
        ("url", "data"),
        [
            (
                "/api/config/field",
                {"path": "dashboard.port", "source": "literal", "value": "1"},
            ),
            ("/api/config/add", {"path": "repos", "key": "new-repo"}),
            ("/api/config/remove", {"path": "repos", "key": "test-repo"}),
            ("/api/config/save", {}),
            ("/api/config/discard", {}),
        ],
    )
    def test_rejected(
        self,
        read_only: ConfigEditorHarness,
        url: str,
        data: dict[str, str],
    ) -> None:
        read_only.client.get("/config")
        handlers = read_only.server._config_handlers
        buffer = handlers._buffer
        assert buffer is not None
        before = repr(buffer.raw)

        method = (
            read_only.client.patch
            if url.endswith("/field")
            else read_only.client.post
        )
        response = method(url, data=data, headers=XHR)

        assert response.status_code == 403
        # A page opened while writable reloads into the viewer.
        assert response.headers["HX-Refresh"] == "true"
        assert "Config is read-only" in response.get_data(as_text=True)
        assert handlers._buffer is buffer
        assert repr(buffer.raw) == before
        assert not buffer.dirty
        assert not read_only._config_path.exists()

    def test_reason_is_escaped(self, tmp_path: Path) -> None:
        """The reason (a file path) is HTML-escaped in the response."""
        config_dir = tmp_path / "<b>"
        config_dir.mkdir()
        target = tmp_path / "managed.yaml"
        target.write_text("{}\n")
        harness = ConfigEditorHarness(config_dir)
        harness._config_path.symlink_to(target)
        harness.client.get("/config")

        response = harness.client.post("/api/config/save", headers=XHR)

        assert response.status_code == 403
        assert "&lt;b&gt;" in response.get_data(as_text=True)
