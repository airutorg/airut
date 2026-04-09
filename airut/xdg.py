# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""XDG Base Directory helpers.

Minimal subset of the `XDG Base Directory Specification
<https://specifications.freedesktop.org/basedir/latest/>`_ used by this
project.  Replaces the ``platformdirs`` dependency.
"""

import os
from pathlib import Path


def user_config_path(appname: str) -> Path:
    """Return the user config directory for *appname*.

    ``$XDG_CONFIG_HOME/<appname>`` when the variable is set and
    non-empty, otherwise ``~/.config/<appname>``.
    """
    base = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / appname


def user_state_path(appname: str) -> Path:
    """Return the user state directory for *appname*.

    ``$XDG_STATE_HOME/<appname>`` when the variable is set and
    non-empty, otherwise ``~/.local/state/<appname>``.
    """
    base = os.environ.get("XDG_STATE_HOME", "").strip()
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / appname
