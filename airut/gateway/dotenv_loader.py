# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Standalone dotenv loader for email gateway.

This module provides idempotent .env file loading without depending on
lib/config.py, making the email gateway suitable for independent deployment.

The loader reads environment variables from two locations (in order):

1. ``~/.config/airut/.env`` (XDG config directory) — primary location
2. ``.env`` in the current working directory — allows per-invocation
   overrides when running ``airut`` interactively

Variables set by the first file are **not** overwritten by the second
(``python-dotenv`` respects existing env vars by default).
"""

import logging
from pathlib import Path


logger = logging.getLogger(__name__)

_dotenv_loaded = False


def load_dotenv_once() -> None:
    """Load .env files once, if not already loaded.

    This function is idempotent — calling it multiple times has no effect
    after the first successful load.

    Loads from ``~/.config/airut/.env`` (XDG) first, then from the
    current working directory's ``.env``.  Variables defined in the XDG
    file take precedence because ``python-dotenv`` does not overwrite
    existing environment variables by default.
    """
    global _dotenv_loaded
    if _dotenv_loaded:
        return

    try:
        from dotenv import load_dotenv

        from airut.gateway.config import get_dotenv_path

        # 1. XDG config directory (.env next to airut.yaml)
        xdg_env = get_dotenv_path()
        if xdg_env.exists():
            load_dotenv(xdg_env)
            logger.debug("Loaded .env from %s", xdg_env)

        # 2. Current working directory (override / development use)
        cwd_env = Path.cwd() / ".env"
        if cwd_env.exists():
            load_dotenv(cwd_env)
            logger.debug("Loaded .env from %s", cwd_env)

        _dotenv_loaded = True
    except ImportError:  # pragma: no cover
        logger.debug("dotenv not available, using env vars only")
        _dotenv_loaded = True


def reset_dotenv_state() -> None:
    """Reset the dotenv loaded state. For testing only."""
    global _dotenv_loaded
    _dotenv_loaded = False
