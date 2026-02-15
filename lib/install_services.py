# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Systemd user service management and auto-update logic.

This module contains the core logic for installing, uninstalling, and
auto-updating Airut's systemd user services.  Airut is installed via
``uv tool install`` and updated via ``uv tool upgrade``.

The CLI entry point is ``airut install-service`` / ``airut uninstall-service``
/ ``airut update`` (see ``lib/airut.py``).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from lib.gateway.config import get_runtime_dir
from lib.update_lock import UpdateLock


logger = logging.getLogger(__name__)

# Default auto-updater polling interval in minutes.
DEFAULT_UPDATE_INTERVAL = 30

# Service names
SERVICES = [
    "airut.service",
]

UPDATE_SERVICES = [
    "airut-updater.service",
    "airut-updater.timer",
]

ALL_SERVICES = SERVICES + UPDATE_SERVICES

# Order for stopping services
SERVICE_STOP_ORDER = [
    "airut-updater.timer",
    "airut-updater.service",
    "airut.service",
]

# Order for starting services
SERVICE_START_ORDER = [
    "airut.service",
    "airut-updater.timer",
]


def get_update_lock_path() -> Path:
    """Return the path to the update advisory lock file.

    Uses ``$XDG_RUNTIME_DIR/airut/update.lock`` via ``platformdirs``.

    Returns:
        Path to the lock file.
    """
    return get_runtime_dir() / "update.lock"


def get_systemd_user_dir() -> Path:
    """Get the systemd user service directory.

    Returns:
        Path to ~/.config/systemd/user
    """
    return Path.home() / ".config" / "systemd" / "user"


def get_uv_path() -> str:
    """Get the path to the uv executable.

    Uses shutil.which to find uv on PATH, falling back to ~/.local/bin/uv
    since systemd services don't load .bashrc.

    Returns:
        Absolute path to uv executable.
    """
    found = shutil.which("uv")
    if found:
        return str(Path(found).resolve())
    return str(Path.home() / ".local" / "bin" / "uv")


def get_airut_path() -> str:
    """Get the path to the airut executable.

    Uses shutil.which to find airut on PATH, falling back to
    ``~/.local/bin/airut`` (the default ``uv tool install`` location).

    Returns:
        Absolute path to airut executable.
    """
    found = shutil.which("airut")
    if found:
        return str(Path(found).resolve())
    return str(Path.home() / ".local" / "bin" / "airut")


def check_linger() -> None:
    """Check that loginctl linger is enabled for the current user.

    Linger is required for user services to run without an active login session.

    Raises:
        RuntimeError: If linger is not enabled.
    """
    username = os.environ.get("USER") or os.getlogin()
    linger_file = Path(f"/var/lib/systemd/linger/{username}")
    if not linger_file.exists():
        raise RuntimeError(
            f"Linger is not enabled for user '{username}'. "
            f"Enable it with: sudo loginctl enable-linger {username}"
        )
    logger.debug("Linger is enabled for user '%s'", username)


def interval_to_oncalendar(minutes: int) -> str:
    """Convert a polling interval in minutes to a systemd OnCalendar expression.

    Args:
        minutes: Polling interval in minutes. Must be positive.

    Returns:
        A systemd OnCalendar value.
    """
    if minutes <= 0:
        raise ValueError(f"Interval must be positive, got {minutes}")

    if minutes <= 60:
        return f"*:0/{minutes}"

    hours = minutes // 60
    remaining = minutes % 60
    if remaining == 0:
        return f"*-*-* 0/{hours}:00:00"

    # For non-round hours, fall back to minute-level
    return f"*:0/{minutes}"


def generate_unit(
    service_name: str,
    airut_path: str,
    *,
    interval: int | None = None,
) -> str:
    """Generate a systemd unit file content.

    Args:
        service_name: Name of the service (e.g. 'airut.service').
        airut_path: Absolute path to the airut executable.
        interval: Polling interval in minutes for the updater timer.
            If None, uses DEFAULT_UPDATE_INTERVAL.

    Returns:
        Unit file content as a string.

    Raises:
        ValueError: If service_name is unknown.
    """
    if service_name == "airut.service":
        return (
            "[Unit]\n"
            "Description=Airut Email Gateway\n"
            "After=network.target\n"
            "\n"
            "[Service]\n"
            f"ExecStart={airut_path} run-gateway --resilient\n"
            "Restart=always\n"
            "RestartSec=10\n"
            "StandardOutput=journal\n"
            "StandardError=journal\n"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )

    if service_name == "airut-updater.service":
        return (
            "[Unit]\n"
            "Description=Airut Service Auto-Updater\n"
            "After=network.target\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={airut_path} update\n"
            "StandardOutput=journal\n"
            "StandardError=journal\n"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )

    if service_name == "airut-updater.timer":
        effective_interval = interval or DEFAULT_UPDATE_INTERVAL
        oncalendar = interval_to_oncalendar(effective_interval)
        return (
            "[Unit]\n"
            "Description=Airut Auto-Updater Timer\n"
            "Requires=airut-updater.service\n"
            "\n"
            "[Timer]\n"
            f"OnCalendar={oncalendar}\n"
            "OnBootSec=1min\n"
            "Persistent=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
        )

    raise ValueError(f"Unknown service: {service_name}")


def systemctl_user(action: str, service: str | None = None) -> None:
    """Run systemctl --user command.

    Args:
        action: Action to perform (daemon-reload, enable, start, stop, disable).
        service: Service name (optional for daemon-reload).

    Raises:
        RuntimeError: If systemctl command fails.
    """
    cmd = ["systemctl", "--user", action]
    if service:
        cmd.append(service)

    logger.debug("Running: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"systemctl {action} failed: {e.stderr.strip()}"
        ) from e


def uninstall_service(service_name: str, unit_path: Path) -> None:
    """Uninstall a single service.

    Args:
        service_name: Name of the service file.
        unit_path: Path to the unit file in systemd user directory.
    """
    if not unit_path.exists() and not unit_path.is_symlink():
        logger.debug("Service %s not installed, skipping", service_name)
        return

    logger.info("Uninstalling service: %s", service_name)

    # Stop and disable service
    try:
        systemctl_user("stop", service_name)
        logger.debug("Stopped %s", service_name)
    except RuntimeError as e:
        # Service might not be running
        logger.debug("Could not stop %s: %s", service_name, e)

    try:
        systemctl_user("disable", service_name)
        logger.debug("Disabled %s", service_name)
    except RuntimeError as e:
        # Service might not be enabled
        logger.debug("Could not disable %s: %s", service_name, e)

    # Remove unit file (may already be gone if systemctl disable removed it)
    unit_path.unlink(missing_ok=True)
    logger.debug("Removed unit file: %s", unit_path)


def install_service(
    service_name: str, unit_content: str, systemd_dir: Path
) -> None:
    """Install a single service by writing generated unit content.

    Args:
        service_name: Name of the service file.
        unit_content: Generated unit file content.
        systemd_dir: Path to systemd user directory.
    """
    unit_path = systemd_dir / service_name

    # If service is already installed, uninstall it first
    if unit_path.exists() or unit_path.is_symlink():
        logger.info("Service %s already installed, reinstalling", service_name)
        uninstall_service(service_name, unit_path)

    # Write generated unit file
    logger.info("Installing service: %s", service_name)
    unit_path.write_text(unit_content)
    logger.debug("Wrote unit file: %s", unit_path)


def enable_and_start_service(service_name: str) -> None:
    """Enable and start a service.

    Args:
        service_name: Name of the service to enable and start.
    """
    # Enable service
    try:
        systemctl_user("enable", service_name)
        logger.debug("Enabled %s", service_name)
    except RuntimeError as e:
        logger.warning("Could not enable %s: %s", service_name, e)

    # Start service (both .service and .timer)
    try:
        systemctl_user("start", service_name)
        if service_name.endswith(".timer"):
            logger.debug("Started timer %s", service_name)
        else:
            logger.debug("Started %s", service_name)
    except RuntimeError as e:
        logger.warning("Could not start %s: %s", service_name, e)


def install_services(
    *,
    with_updater: bool = True,
    interval: int | None = None,
) -> None:
    """Install all services.

    Services are started in order: email-gateway -> updater.

    Args:
        with_updater: If True, also install auto-updater services.
        interval: Polling interval override in minutes for the updater timer.
    """
    check_linger()

    systemd_dir = get_systemd_user_dir()
    systemd_dir.mkdir(parents=True, exist_ok=True)

    airut_path = get_airut_path()

    # Determine which services to install
    services_to_install = list(SERVICES)
    if with_updater:
        services_to_install.extend(UPDATE_SERVICES)

    # Generate and install all unit files
    for service_name in services_to_install:
        unit_content = generate_unit(
            service_name,
            airut_path,
            interval=interval,
        )
        install_service(service_name, unit_content, systemd_dir)

    # Reload systemd
    logger.info("Reloading systemd user daemon")
    systemctl_user("daemon-reload")

    # Enable and start services in specific order to minimize downtime
    for service_name in SERVICE_START_ORDER:
        if not with_updater and service_name in UPDATE_SERVICES:
            continue
        enable_and_start_service(service_name)

    logger.info("All services installed successfully")


def uninstall_services(with_updater: bool = True) -> None:
    """Uninstall all services.

    Services are stopped in order: updater -> email-gateway.

    Args:
        with_updater: If True, also uninstall auto-updater services.
    """
    systemd_dir = get_systemd_user_dir()

    for service_name in SERVICE_STOP_ORDER:
        if not with_updater and service_name in UPDATE_SERVICES:
            continue
        unit_path = systemd_dir / service_name
        uninstall_service(service_name, unit_path)

    # Reload systemd
    logger.info("Reloading systemd user daemon")
    systemctl_user("daemon-reload")

    logger.info("All services uninstalled successfully")


def apply_update() -> bool:
    """Run ``uv tool upgrade airut`` with update-lock coordination.

    Acquires the update lock before proceeding.  If the email service is
    busy (lock held), the update is skipped and will be retried on the next
    timer trigger.

    Returns:
        True if update was applied, False if skipped due to busy service.

    Raises:
        RuntimeError: If the upgrade command fails.
    """
    lock = UpdateLock(get_update_lock_path())
    if not lock.try_acquire():
        logger.info("Email service is busy, skipping update")
        return False

    # Lock acquired — will be released when this process exits
    logger.info("Running uv tool upgrade")

    uv_path = get_uv_path()
    try:
        subprocess.run(
            [uv_path, "tool", "upgrade", "airut"],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("Upgrade completed successfully")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"uv tool upgrade failed: {e.stderr.strip()}") from e

    return True
