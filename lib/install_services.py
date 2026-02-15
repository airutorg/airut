# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Systemd user service management.

This module contains the core logic for installing and uninstalling Airut's
systemd user services.  Airut is installed via ``uv tool install`` and can
be updated with ``airut update``.

The CLI entry point is ``airut install-service`` / ``airut uninstall-service``
(see ``lib/airut.py``).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path


logger = logging.getLogger(__name__)

# Service names
SERVICES = [
    "airut.service",
]


def get_systemd_user_dir() -> Path:
    """Get the systemd user service directory.

    Returns:
        Path to ~/.config/systemd/user
    """
    return Path.home() / ".config" / "systemd" / "user"


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


def _get_username() -> str:
    """Return the current username from environment or OS.

    Tries ``$USER`` first, then falls back to ``os.getlogin()``.

    Raises:
        RuntimeError: If neither ``$USER`` nor ``os.getlogin()`` is
            available (e.g. headless systemd environments without a TTY).
    """
    name = os.environ.get("USER")
    if name:
        return name
    try:
        return os.getlogin()
    except OSError:
        raise RuntimeError(
            "Cannot determine username: $USER is not set and "
            "os.getlogin() failed.  Set the USER environment variable "
            "and retry."
        ) from None


def check_linger() -> None:
    """Check that loginctl linger is enabled for the current user.

    Linger is required for user services to run without an active login session.

    Raises:
        RuntimeError: If linger is not enabled or username cannot be
            determined.
    """
    username = _get_username()
    linger_file = Path(f"/var/lib/systemd/linger/{username}")
    if not linger_file.exists():
        raise RuntimeError(
            f"Linger is not enabled for user '{username}'. "
            f"Enable it with: sudo loginctl enable-linger {username}"
        )
    logger.debug("Linger is enabled for user '%s'", username)


def generate_unit(service_name: str, airut_path: str) -> str:
    """Generate a systemd unit file content.

    Args:
        service_name: Name of the service (e.g. 'airut.service').
        airut_path: Absolute path to the airut executable.

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


def install_services() -> None:
    """Install all services.

    Installs the email gateway systemd user service.
    """
    check_linger()

    systemd_dir = get_systemd_user_dir()
    systemd_dir.mkdir(parents=True, exist_ok=True)

    airut_path = get_airut_path()

    # Generate and install all unit files
    for service_name in SERVICES:
        unit_content = generate_unit(service_name, airut_path)
        install_service(service_name, unit_content, systemd_dir)

    # Reload systemd
    logger.info("Reloading systemd user daemon")
    systemctl_user("daemon-reload")

    # Enable and start services
    for service_name in SERVICES:
        enable_and_start_service(service_name)

    logger.info("All services installed successfully")


def uninstall_services() -> None:
    """Uninstall all services."""
    systemd_dir = get_systemd_user_dir()

    for service_name in SERVICES:
        unit_path = systemd_dir / service_name
        uninstall_service(service_name, unit_path)

    # Reload systemd
    logger.info("Reloading systemd user daemon")
    systemctl_user("daemon-reload")

    logger.info("All services uninstalled successfully")
