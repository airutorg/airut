# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Standalone dotenv loader for email gateway.

This module provides idempotent .env file loading without depending on
lib/config.py, making the email gateway suitable for independent deployment.
"""

import logging
from pathlib import Path


logger = logging.getLogger(__name__)

_dotenv_loaded = False


def load_dotenv_once(env_path: Path | None = None) -> None:
    """Load .env file once, if not already loaded.

    This function is idempotent - calling it multiple times has no effect
    after the first successful load.

    Args:
        env_path: Explicit path to .env file. If None, searches the
            directory two levels above this file (repo root), then
            falls back to current directory.
    """
    global _dotenv_loaded
    if _dotenv_loaded:
        return

    try:
        from dotenv import load_dotenv

        if env_path and env_path.exists():
            load_dotenv(env_path)
            logger.debug("Loaded .env from %s", env_path)
        else:
            # Try repo root (two levels up from lib/gateway/)
            repo_env = Path(__file__).parent.parent.parent / ".env"
            if repo_env.exists():  # pragma: no cover - .env is gitignored
                load_dotenv(repo_env)
                logger.debug("Loaded .env from %s", repo_env)
            else:
                load_dotenv()
                logger.debug("Loaded .env from current directory")
        _dotenv_loaded = True
    except ImportError:  # pragma: no cover
        logger.debug("dotenv not available, using env vars only")
        _dotenv_loaded = True


def reset_dotenv_state() -> None:
    """Reset the dotenv loaded state. For testing only."""
    global _dotenv_loaded
    _dotenv_loaded = False
