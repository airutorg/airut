#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Systemd user service manager with automatic updates.

Installs, manages, and auto-updates systemd user services for Airut.
Unit files are generated at install time with correct paths to uv and scripts.

Usage:
    # Install services (initial setup or reinstall)
    python scripts/install_services.py

    # Check for updates and apply if available
    python scripts/install_services.py --update

    # Uninstall all services
    python scripts/install_services.py --uninstall

Exit codes:
    0 - Success
    1 - Configuration error
    2 - Git operation failed
    3 - Systemd operation failed
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path


# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.update_lock import UpdateLock


logger = logging.getLogger(__name__)

# Service names (no longer mapped to files -- units are generated)
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


def configure_logging(debug: bool = False) -> None:
    """Configure logging.

    Args:
        debug: If True, enable DEBUG level logging.
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_repo_root() -> Path:
    """Get the repository root directory.

    Returns:
        Path to repository root.

    Raises:
        RuntimeError: If not in a git repository.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Not in a git repository: {e}") from e


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


def generate_unit(service_name: str, repo_root: Path, uv_path: str) -> str:
    """Generate a systemd unit file content.

    Args:
        service_name: Name of the service (e.g. 'airut-gateway.service').
        repo_root: Absolute path to the repository root.
        uv_path: Absolute path to the uv executable.

    Returns:
        Unit file content as a string.

    Raises:
        ValueError: If service_name is unknown.
    """
    wd = str(repo_root)

    if service_name == "airut.service":
        return (
            "[Unit]\n"
            "Description=Airut Email Gateway\n"
            "After=network.target\n"
            "\n"
            "[Service]\n"
            f"WorkingDirectory={wd}\n"
            f"ExecStart={uv_path} run scripts/gateway/main.py\n"
            f"EnvironmentFile={wd}/.env\n"
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
            f"WorkingDirectory={wd}\n"
            f"ExecStart={uv_path} run scripts/install_services.py --update\n"
            "StandardOutput=journal\n"
            "StandardError=journal\n"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )

    if service_name == "airut-updater.timer":
        return (
            "[Unit]\n"
            "Description=Airut Auto-Updater Timer\n"
            "Requires=airut-updater.service\n"
            "\n"
            "[Timer]\n"
            "OnCalendar=*:0/5\n"
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


def install_services(repo_root: Path, with_updater: bool = True) -> None:
    """Install all services.

    Services are started in order: email-gateway -> updater.

    Args:
        repo_root: Path to repository root.
        with_updater: If True, also install auto-updater services.
    """
    check_linger()

    systemd_dir = get_systemd_user_dir()
    systemd_dir.mkdir(parents=True, exist_ok=True)

    uv_path = get_uv_path()

    # Determine which services to install
    services_to_install = list(SERVICES)
    if with_updater:
        services_to_install.extend(UPDATE_SERVICES)

    # Generate and install all unit files
    for service_name in services_to_install:
        unit_content = generate_unit(service_name, repo_root, uv_path)
        install_service(service_name, unit_content, systemd_dir)

    # Reload systemd
    logger.info("Reloading systemd user daemon")
    systemctl_user("daemon-reload")

    # Enable and start services in specific order to minimize fava downtime
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


def check_for_updates(repo_root: Path) -> bool:
    """Check if repository updates are available.

    Args:
        repo_root: Path to repository root.

    Returns:
        True if updates are available, False otherwise.

    Raises:
        RuntimeError: If git operations fail.
    """
    logger.info("Checking for updates")

    # Fetch latest from origin
    try:
        subprocess.run(
            ["git", "fetch", "origin"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git fetch failed: {e.stderr.strip()}") from e

    # Compare local HEAD with origin/main
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        local_rev = result.stdout.strip()

        result = subprocess.run(
            ["git", "rev-parse", "origin/main"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        remote_rev = result.stdout.strip()

        if local_rev != remote_rev:
            logger.info(
                "Updates available: %s -> %s", local_rev[:8], remote_rev[:8]
            )
            return True
        else:
            logger.info("No updates available")
            return False

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git rev-parse failed: {e.stderr.strip()}") from e


def apply_update(repo_root: Path) -> bool:
    """Apply repository update and reinstall services.

    Acquires the update lock before proceeding. If the email service is busy,
    the update is skipped and will be retried on the next timer trigger.

    Args:
        repo_root: Path to repository root.

    Returns:
        True if update was applied, False if skipped due to busy service.

    Raises:
        RuntimeError: If update fails.
    """
    # Try to acquire update lock (email service may be busy)
    lock = UpdateLock(repo_root / ".update.lock")
    if not lock.try_acquire():
        logger.info("Email service is busy, skipping update")
        return False

    # Lock acquired - will be released when process exits (including os.execv)
    logger.info("Applying update")

    # Uninstall services (but not the updater itself)
    uninstall_services(with_updater=False)

    # Checkout main and reset to origin/main
    try:
        subprocess.run(
            ["git", "checkout", "main"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "reset", "--hard", "origin/main"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("Repository updated to origin/main")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"git checkout/reset failed: {e.stderr.strip()}"
        ) from e

    # Sync dependencies before re-executing
    logger.info("Syncing dependencies")
    uv_path = get_uv_path()
    try:
        subprocess.run(
            [uv_path, "sync"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("Dependencies synced")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"uv sync failed: {e.stderr.strip()}") from e

    # Execute the new version of this script, skipping updater reinstall
    # since the updater is the process calling this
    logger.info("Executing updated installer")
    script_path = repo_root / "scripts" / "install_services.py"
    args = [sys.executable, str(script_path), "--skip-updater"]
    os.execv(sys.executable, args)
    return True  # Unreachable - os.execv replaces process


def main() -> int:
    """Main entry point.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description="Manage systemd user services for Airut",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Check for updates and apply if available",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall all services",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--skip-updater",
        action="store_true",
        help="Skip installing updater services (used during self-update)",
    )
    args = parser.parse_args()

    configure_logging(debug=args.debug)

    try:
        repo_root = get_repo_root()
        logger.debug("Repository root: %s", repo_root)

        if args.uninstall:
            uninstall_services()
            return 0

        if args.update:
            if check_for_updates(repo_root):
                if apply_update(repo_root):
                    # Should not reach here (os.execv replaces process)
                    return 0
                else:
                    # Email service busy, skipped update
                    return 0
            else:
                # No updates, exit quietly
                return 0

        # Default: install services
        install_services(repo_root, with_updater=not args.skip_updater)
        return 0

    except RuntimeError as e:
        logger.error("%s", e)
        return 1
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
