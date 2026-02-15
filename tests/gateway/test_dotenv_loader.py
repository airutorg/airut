# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email gateway dotenv loader."""

from pathlib import Path
from unittest.mock import MagicMock, call, patch

from lib.gateway.dotenv_loader import load_dotenv_once, reset_dotenv_state


class TestLoadDotenvOnce:
    """Tests for load_dotenv_once."""

    def setup_method(self) -> None:
        """Reset state before each test."""
        reset_dotenv_state()

    def test_idempotent(self, tmp_path: Path) -> None:
        """Second call is a no-op."""
        mock_ld = MagicMock()
        xdg_env = tmp_path / ".env"
        xdg_env.touch()
        with (
            patch("dotenv.load_dotenv", mock_ld),
            patch(
                "lib.gateway.config.get_dotenv_path",
                return_value=xdg_env,
            ),
        ):
            load_dotenv_once()
            load_dotenv_once()
        assert mock_ld.call_count == 1

    def test_loads_xdg_env(self, tmp_path: Path) -> None:
        """Loads from XDG config directory when file exists."""
        xdg_env = tmp_path / "config" / ".env"
        xdg_env.parent.mkdir()
        xdg_env.touch()
        mock_ld = MagicMock()
        with (
            patch("dotenv.load_dotenv", mock_ld),
            patch(
                "lib.gateway.config.get_dotenv_path",
                return_value=xdg_env,
            ),
            patch("lib.gateway.dotenv_loader.Path") as mock_path_cls,
        ):
            # CWD .env does not exist
            mock_cwd_env = MagicMock()
            mock_cwd_env.exists.return_value = False
            mock_path_cls.cwd.return_value.__truediv__ = (
                lambda self, x: mock_cwd_env
            )
            load_dotenv_once()
        mock_ld.assert_called_once_with(xdg_env)

    def test_loads_cwd_env(self, tmp_path: Path) -> None:
        """Loads from CWD when XDG .env doesn't exist."""
        xdg_env = tmp_path / "config" / ".env"
        cwd_env = tmp_path / "cwd" / ".env"
        cwd_env.parent.mkdir(parents=True)
        cwd_env.touch()
        mock_ld = MagicMock()
        with (
            patch("dotenv.load_dotenv", mock_ld),
            patch(
                "lib.gateway.config.get_dotenv_path",
                return_value=xdg_env,
            ),
            patch(
                "lib.gateway.dotenv_loader.Path.cwd",
                return_value=cwd_env.parent,
            ),
        ):
            load_dotenv_once()
        mock_ld.assert_called_once_with(cwd_env)

    def test_loads_both(self, tmp_path: Path) -> None:
        """Loads XDG first, then CWD when both exist."""
        xdg_env = tmp_path / "config" / ".env"
        xdg_env.parent.mkdir()
        xdg_env.touch()
        cwd_env = tmp_path / "cwd" / ".env"
        cwd_env.parent.mkdir()
        cwd_env.touch()
        mock_ld = MagicMock()
        with (
            patch("dotenv.load_dotenv", mock_ld),
            patch(
                "lib.gateway.config.get_dotenv_path",
                return_value=xdg_env,
            ),
            patch(
                "lib.gateway.dotenv_loader.Path.cwd",
                return_value=cwd_env.parent,
            ),
        ):
            load_dotenv_once()
        assert mock_ld.call_args_list == [
            call(xdg_env),
            call(cwd_env),
        ]

    def test_no_env_files(self, tmp_path: Path) -> None:
        """No-op when neither .env file exists."""
        mock_ld = MagicMock()
        xdg_env = tmp_path / "nonexistent" / ".env"
        with (
            patch("dotenv.load_dotenv", mock_ld),
            patch(
                "lib.gateway.config.get_dotenv_path",
                return_value=xdg_env,
            ),
            patch(
                "lib.gateway.dotenv_loader.Path.cwd",
                return_value=tmp_path / "also_nonexistent",
            ),
        ):
            load_dotenv_once()
        mock_ld.assert_not_called()

    def test_reset_allows_reload(self, tmp_path: Path) -> None:
        """reset_dotenv_state allows re-loading."""
        mock_ld = MagicMock()
        xdg_env = tmp_path / ".env"
        xdg_env.touch()
        with (
            patch("dotenv.load_dotenv", mock_ld),
            patch(
                "lib.gateway.config.get_dotenv_path",
                return_value=xdg_env,
            ),
        ):
            load_dotenv_once()
            assert mock_ld.call_count == 1
            reset_dotenv_state()
            load_dotenv_once()
            assert mock_ld.call_count == 2
