# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email gateway dotenv loader."""

from pathlib import Path
from unittest.mock import MagicMock, call, patch

from airut.gateway.dotenv_loader import load_dotenv_once, reset_dotenv_state


class TestLoadDotenvOnce:
    """Tests for load_dotenv_once."""

    def setup_method(self) -> None:
        """Reset state before each test."""
        reset_dotenv_state()

    def _config_path(self, tmp_path: Path, *, with_env: bool) -> Path:
        """Return a config path in its own directory, optionally with .env."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        if with_env:
            (config_dir / ".env").touch()
        return config_dir / "airut.yaml"

    def test_idempotent(self, tmp_path: Path) -> None:
        """Second call is a no-op."""
        config_path = self._config_path(tmp_path, with_env=True)
        mock_ld = MagicMock()
        with (
            patch("airut.gateway.dotenv_loader.load_dotenv", mock_ld),
            patch(
                "airut.gateway.dotenv_loader.Path.cwd",
                return_value=tmp_path / "cwd",
            ),
        ):
            load_dotenv_once(config_path)
            load_dotenv_once(config_path)
        assert mock_ld.call_count == 1

    def test_loads_env_next_to_config(self, tmp_path: Path) -> None:
        """Loads the .env in the config file's directory."""
        config_path = self._config_path(tmp_path, with_env=True)
        mock_ld = MagicMock()
        with (
            patch("airut.gateway.dotenv_loader.load_dotenv", mock_ld),
            patch(
                "airut.gateway.dotenv_loader.Path.cwd",
                return_value=tmp_path / "cwd",
            ),
        ):
            load_dotenv_once(config_path)
        mock_ld.assert_called_once_with(config_path.parent / ".env")

    def test_loads_cwd_env(self, tmp_path: Path) -> None:
        """Loads from CWD when no .env is next to the config."""
        config_path = self._config_path(tmp_path, with_env=False)
        cwd_env = tmp_path / "cwd" / ".env"
        cwd_env.parent.mkdir()
        cwd_env.touch()
        mock_ld = MagicMock()
        with (
            patch("airut.gateway.dotenv_loader.load_dotenv", mock_ld),
            patch(
                "airut.gateway.dotenv_loader.Path.cwd",
                return_value=cwd_env.parent,
            ),
        ):
            load_dotenv_once(config_path)
        mock_ld.assert_called_once_with(cwd_env)

    def test_loads_both(self, tmp_path: Path) -> None:
        """Loads the config directory's .env first, then CWD's."""
        config_path = self._config_path(tmp_path, with_env=True)
        cwd_env = tmp_path / "cwd" / ".env"
        cwd_env.parent.mkdir()
        cwd_env.touch()
        mock_ld = MagicMock()
        with (
            patch("airut.gateway.dotenv_loader.load_dotenv", mock_ld),
            patch(
                "airut.gateway.dotenv_loader.Path.cwd",
                return_value=cwd_env.parent,
            ),
        ):
            load_dotenv_once(config_path)
        assert mock_ld.call_args_list == [
            call(config_path.parent / ".env"),
            call(cwd_env),
        ]

    def test_no_env_files(self, tmp_path: Path) -> None:
        """No-op when neither .env file exists."""
        config_path = self._config_path(tmp_path, with_env=False)
        mock_ld = MagicMock()
        with (
            patch("airut.gateway.dotenv_loader.load_dotenv", mock_ld),
            patch(
                "airut.gateway.dotenv_loader.Path.cwd",
                return_value=tmp_path / "also_nonexistent",
            ),
        ):
            load_dotenv_once(config_path)
        mock_ld.assert_not_called()

    def test_reset_allows_reload(self, tmp_path: Path) -> None:
        """reset_dotenv_state allows re-loading."""
        config_path = self._config_path(tmp_path, with_env=True)
        mock_ld = MagicMock()
        with (
            patch("airut.gateway.dotenv_loader.load_dotenv", mock_ld),
            patch(
                "airut.gateway.dotenv_loader.Path.cwd",
                return_value=tmp_path / "cwd",
            ),
        ):
            load_dotenv_once(config_path)
            assert mock_ld.call_count == 1
            reset_dotenv_state()
            load_dotenv_once(config_path)
            assert mock_ld.call_count == 2
