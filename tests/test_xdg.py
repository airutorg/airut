# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the XDG base directory helpers."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove XDG variables so each test starts from a known state."""
    for var in ("XDG_CONFIG_HOME", "XDG_STATE_HOME"):
        monkeypatch.delenv(var, raising=False)


class TestUserConfigPath:
    """Tests for user_config_path."""

    def test_default_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without XDG_CONFIG_HOME, falls back to ~/.config/<appname>."""
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_config_path

        assert user_config_path("myapp") == Path("/home/tester/.config/myapp")

    def test_xdg_config_home_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Respects XDG_CONFIG_HOME when set."""
        monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/config")
        from airut.xdg import user_config_path

        assert user_config_path("myapp") == Path("/custom/config/myapp")

    def test_xdg_config_home_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty XDG_CONFIG_HOME falls back to ~/.config."""
        monkeypatch.setenv("XDG_CONFIG_HOME", "")
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_config_path

        assert user_config_path("myapp") == Path("/home/tester/.config/myapp")

    def test_xdg_config_home_whitespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whitespace-only XDG_CONFIG_HOME falls back to ~/.config."""
        monkeypatch.setenv("XDG_CONFIG_HOME", "   ")
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_config_path

        assert user_config_path("myapp") == Path("/home/tester/.config/myapp")

    def test_returns_path_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Return type is pathlib.Path."""
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_config_path

        result = user_config_path("myapp")
        assert isinstance(result, Path)


class TestUserStatePath:
    """Tests for user_state_path."""

    def test_default_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without XDG_STATE_HOME, falls back to ~/.local/state/<appname>."""
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_state_path

        assert user_state_path("myapp") == Path(
            "/home/tester/.local/state/myapp"
        )

    def test_xdg_state_home_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Respects XDG_STATE_HOME when set."""
        monkeypatch.setenv("XDG_STATE_HOME", "/custom/state")
        from airut.xdg import user_state_path

        assert user_state_path("myapp") == Path("/custom/state/myapp")

    def test_xdg_state_home_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty XDG_STATE_HOME falls back to ~/.local/state."""
        monkeypatch.setenv("XDG_STATE_HOME", "")
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_state_path

        assert user_state_path("myapp") == Path(
            "/home/tester/.local/state/myapp"
        )

    def test_xdg_state_home_whitespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whitespace-only XDG_STATE_HOME falls back to ~/.local/state."""
        monkeypatch.setenv("XDG_STATE_HOME", "   ")
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_state_path

        assert user_state_path("myapp") == Path(
            "/home/tester/.local/state/myapp"
        )

    def test_returns_path_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Return type is pathlib.Path."""
        monkeypatch.setenv("HOME", "/home/tester")
        from airut.xdg import user_state_path

        result = user_state_path("myapp")
        assert isinstance(result, Path)
