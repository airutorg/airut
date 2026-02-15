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

1. Run ``uv tool install airut`` from the GitHub repo.
2. Run ``airut install-service`` to create the new-style gateway unit.
3. Stop and remove the legacy updater services (timer + service) **last**,
   since this script is running inside the updater service itself.

After migration, neither this script nor the updater service are used again.
The user should update manually with ``uv tool upgrade airut``.
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

#: Legacy updater services to remove as the final step.
_UPDATER_SERVICES = [
    "airut-updater.timer",
    "airut-updater.service",
]


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


def _uninstall_legacy_gateway() -> None:
    """Stop and remove the legacy airut.service (old git-clone style)."""
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    unit_path = systemd_dir / "airut.service"

    if not unit_path.exists() and not unit_path.is_symlink():
        return

    logger.info("Removing legacy gateway service: airut.service")
    for action in ("stop", "disable"):
        try:
            subprocess.run(
                ["systemctl", "--user", action, "airut.service"],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError:
            pass

    unit_path.unlink(missing_ok=True)

    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        pass


def _remove_updater_services() -> None:
    """Stop and remove the legacy updater timer and service.

    This is done **last** because this script is invoked by the updater
    service itself.  Stopping the timer first prevents re-triggering,
    then the service unit is removed.  The current process will finish
    normally even though its unit file has been deleted.
    """
    systemd_dir = Path.home() / ".config" / "systemd" / "user"

    for name in _UPDATER_SERVICES:
        unit_path = systemd_dir / name
        if not unit_path.exists() and not unit_path.is_symlink():
            continue

        logger.info("Removing legacy updater: %s", name)
        for action in ("stop", "disable"):
            try:
                subprocess.run(
                    ["systemctl", "--user", action, name],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError:
                pass

        unit_path.unlink(missing_ok=True)

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

    # 1. Remove legacy gateway service (old-style unit)
    logger.info("Step 1/4: Removing legacy gateway service")
    _uninstall_legacy_gateway()

    # 2. Install via uv tool install
    logger.info("Step 2/4: Installing airut via uv tool install")
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

    # 3. Install new-style gateway service
    logger.info("Step 3/4: Installing new gateway service")
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

    # 4. Remove updater services LAST — we are running inside the
    #    updater service, so this must be the final step.
    logger.info("Step 4/4: Removing legacy updater services")
    _remove_updater_services()

    logger.info("Migration complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
