# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email gateway dotenv loader."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from lib.gateway.dotenv_loader import load_dotenv_once, reset_dotenv_state


class TestLoadDotenvOnce:
    """Tests for load_dotenv_once."""

    def setup_method(self) -> None:
        """Reset state before each test."""
        reset_dotenv_state()

    def test_idempotent(self) -> None:
        """Second call is a no-op."""
        mock_ld = MagicMock()
        with patch("dotenv.load_dotenv", mock_ld):
            load_dotenv_once()
            load_dotenv_once()
        assert mock_ld.call_count == 1

    def test_explicit_path(self, tmp_path: Path) -> None:
        """Loads from explicit path when provided and exists."""
        env_file = tmp_path / ".env"
        env_file.touch()
        mock_ld = MagicMock()
        with patch("dotenv.load_dotenv", mock_ld):
            load_dotenv_once(env_file)
        mock_ld.assert_called_once_with(env_file)

    def test_explicit_path_missing_falls_back(self, tmp_path: Path) -> None:
        """Falls back to default search when explicit path doesn't exist."""
        mock_ld = MagicMock()
        with patch("dotenv.load_dotenv", mock_ld):
            load_dotenv_once(tmp_path / "nonexistent.env")
        # Should call load_dotenv() (no args) as fallback
        mock_ld.assert_called_once()

    def test_reset_allows_reload(self) -> None:
        """reset_dotenv_state allows re-loading."""
        mock_ld = MagicMock()
        with patch("dotenv.load_dotenv", mock_ld):
            load_dotenv_once()
            assert mock_ld.call_count == 1
            reset_dotenv_state()
            load_dotenv_once()
            assert mock_ld.call_count == 2
