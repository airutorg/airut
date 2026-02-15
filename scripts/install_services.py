#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Migration stub for the legacy auto-updater.

Existing deployments have an ``airut-updater.service`` whose ``ExecStart``
invokes this script.  When the updater fetches new code and finds this
version of the script, it means the installation should migrate from the
old git-clone model to ``uv tool install``.

**Migration steps performed by this script:**

1. Uninstall *all* old systemd services (including the updater itself).
2. Run ``uv tool install airut`` from the GitHub repo.
3. Run ``airut install-service`` to create new-style unit files.
4. Exit — the new updater timer will handle future updates.

After migration, this script is never called again because the new
``airut-updater.service`` invokes ``airut update`` instead.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

#: GitHub URL used for ``uv tool install`` during migration.
_GITHUB_INSTALL_URL = "git+https://github.com/airutorg/airut.git"


def _get_uv_path() -> str:
    """Locate the uv binary."""
    found = shutil.which("uv")
    if found:
        return str(Path(found).resolve())
    return str(Path.home() / ".local" / "bin" / "uv")


def _get_airut_path() -> str:
    """Locate the airut binary (post-install)."""
    found = shutil.which("airut")
    if found:
        return str(Path(found).resolve())
    return str(Path.home() / ".local" / "bin" / "airut")


def _uninstall_old_services() -> None:
    """Stop and remove all legacy systemd user services."""
    service_names = [
        "airut-updater.timer",
        "airut-updater.service",
        "airut.service",
    ]
    systemd_dir = Path.home() / ".config" / "systemd" / "user"

    for name in service_names:
        unit_path = systemd_dir / name
        if not unit_path.exists() and not unit_path.is_symlink():
            continue

        logger.info("Removing legacy service: %s", name)
        for action in ("stop", "disable"):
            try:
                subprocess.run(
                    ["systemctl", "--user", action, name],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError:
                pass  # Service may not be running/enabled

        unit_path.unlink(missing_ok=True)

    # Reload after removing all units
    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        pass


def main() -> int:
    """Migrate from git-clone deployment to uv tool install.

    Returns:
        Exit code.
    """
    logger.info("Migrating to uv tool install")

    # 1. Uninstall all old services
    logger.info("Step 1/3: Uninstalling legacy services")
    _uninstall_old_services()

    # 2. Install via uv tool install
    logger.info("Step 2/3: Installing airut via uv tool install")
    uv_path = _get_uv_path()
    try:
        subprocess.run(
            [
                uv_path,
                "tool",
                "install",
                "--force",
                "airut",
                "--from",
                _GITHUB_INSTALL_URL,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error("uv tool install failed: %s", e.stderr.strip())
        return 1

    # 3. Install new-style services
    logger.info("Step 3/3: Installing new services via airut install-service")
    airut_path = _get_airut_path()
    try:
        subprocess.run(
            [airut_path, "install-service"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error("airut install-service failed: %s", e.stderr.strip())
        return 1

    logger.info("Migration complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
