# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Standalone dotenv loader for email gateway.

This module provides idempotent .env file loading without depending on
lib/config.py, making the email gateway suitable for independent deployment.

The loader reads environment variables from two locations (in order):

1. ``.env`` next to the server config file (typically
   ``~/.config/airut/.env``) — primary location
2. ``.env`` in the current working directory — allows per-invocation
   overrides when running ``airut`` interactively

Variables set by the first file are **not** overwritten by the second
(``load_dotenv`` does not overwrite existing env vars by default).
"""

import logging
from pathlib import Path

from airut.dotenv import load_dotenv


logger = logging.getLogger(__name__)

_dotenv_loaded = False


def load_dotenv_once(config_path: Path) -> None:
    """Load .env files once, if not already loaded.

    This function is idempotent — calling it multiple times has no effect
    after the first successful load.

    Loads the ``.env`` next to *config_path* first, then the current
    working directory's ``.env``.  Variables defined in the first file
    take precedence because ``load_dotenv`` does not overwrite existing
    environment variables by default.

    Args:
        config_path: Path to the server config file.
    """
    global _dotenv_loaded
    if _dotenv_loaded:
        return

    from airut.gateway.config import get_dotenv_path

    # 1. Next to the config file
    config_env = get_dotenv_path(config_path)
    if config_env.exists():
        load_dotenv(config_env)
        logger.debug("Loaded .env from %s", config_env)

    # 2. Current working directory (override / development use)
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        load_dotenv(cwd_env)
        logger.debug("Loaded .env from %s", cwd_env)

    _dotenv_loaded = True


def reset_dotenv_state() -> None:
    """Reset the dotenv loaded state.

    Called before config reload to allow ``.env`` files to be re-read.
    Also used in tests to reset global state between test cases.
    """
    global _dotenv_loaded
    _dotenv_loaded = False
