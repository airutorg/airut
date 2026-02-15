# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Airut CLI — multi-command entry point.

Provides ``airut <command>`` with subcommands for running the gateway,
initializing configuration, checking system readiness, managing systemd
services, and updating the installation.  Running ``airut`` with no arguments
prints version and usage information.

Subcommands:

* ``init``              — create a stub server config file
* ``check``             — verify config and system dependencies
* ``update``            — update airut to the latest version
* ``install-service``   — install systemd user services
* ``uninstall-service`` — uninstall systemd user services
* ``run-gateway``       — start the email gateway service
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from lib.version import GitVersionInfo

from lib.gateway.config import (
    ConfigError,
    ServerConfig,
    get_config_path,
    get_dotenv_path,
)


logger = logging.getLogger(__name__)

# Known subcommand names.
_SUBCOMMANDS = frozenset(
    {
        "run-gateway",
        "init",
        "check",
        "update",
        "install-service",
        "uninstall-service",
    }
)

# Minimum required versions for system dependencies.
# Podman 4.x introduced the netavark backend with --route and --disable-dns
# flags required for the network sandbox.
_MIN_VERSIONS: dict[str, tuple[int, ...]] = {
    "git": (2, 25),
    "podman": (4, 0),
}

_USAGE = """\
usage: airut <command> [args]

commands:
  init              Create a stub server config file
  check             Verify config and system dependencies
  update            Update airut to the latest version
  install-service   Install systemd user services
  uninstall-service Uninstall systemd user services
  run-gateway       Start the email gateway service

Run 'airut <command> --help' for command-specific help.\
"""


def _parse_version(output: str) -> tuple[int, ...]:
    """Extract a numeric version tuple from command output.

    Looks for the first token that starts with a digit and parses it as a
    dotted version string.  For example::

        git version 2.43.0  -> (2, 43, 0)
        podman version 5.3.1 -> (5, 3, 1)

    Args:
        output: Raw stdout from ``<tool> --version`` or ``<tool> version``.

    Returns:
        Numeric version tuple.

    Raises:
        ValueError: If no version number is found.
    """
    for token in output.split():
        if token and token[0].isdigit():
            parts: list[int] = []
            for segment in token.split("."):
                # Strip non-numeric suffixes (e.g. "1.2.3-rc1")
                digits = ""
                for ch in segment:
                    if ch.isdigit():
                        digits += ch
                    else:
                        break
                if digits:
                    parts.append(int(digits))
            if parts:
                return tuple(parts)
    raise ValueError(f"Cannot parse version from: {output!r}")


def _fmt_version(v: tuple[int, ...]) -> str:
    """Format a version tuple as a dotted string."""
    return ".".join(str(p) for p in v)


# ── Terminal colors ─────────────────────────────────────────────────


def _use_color() -> bool:
    """Determine whether to use ANSI color codes in output.

    Returns True when stdout is a TTY and the ``NO_COLOR`` environment
    variable is not set.  ``TERM=dumb`` also disables color.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


class _Style:
    """ANSI escape helpers.  All methods return plain text when color is off."""

    def __init__(self, color: bool) -> None:
        self._on = color

    def _wrap(self, code: str, text: str) -> str:
        if not self._on:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


# ── Dependency checking ─────────────────────────────────────────────


def _check_dependency(
    name: str,
    version_cmd: list[str],
    min_version: tuple[int, ...] | None = None,
) -> tuple[bool, str]:
    """Check a single dependency is installed and meets version requirements.

    Args:
        name: Human-readable dependency name.
        version_cmd: Command to run to get version output.
        min_version: Minimum required version tuple, or None to skip
            version check.

    Returns:
        ``(ok, detail)`` — *ok* is True when the check passes, *detail*
        is a human-readable status string (no leading indent).
    """
    path = shutil.which(name)
    if path is None:
        return False, f"{name}: not found"

    try:
        result = subprocess.run(
            version_cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        raw = result.stdout.strip() or result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, f"{name}: found at {path} but failed to get version"

    try:
        version = _parse_version(raw)
    except ValueError:
        return False, f"{name}: cannot parse version from: {raw}"

    if min_version and version < min_version:
        got = _fmt_version(version)
        want = _fmt_version(min_version)
        return False, f"{name}: {got} (need >= {want})"

    version_str = _fmt_version(version)
    if min_version:
        return True, f"{name}: {version_str} (>= {_fmt_version(min_version)})"
    return True, f"{name}: {version_str}"


# ── init subcommand ─────────────────────────────────────────────────


_DOCS_BASE = "https://github.com/airutorg/airut/blob/main"


def cmd_init(argv: list[str]) -> int:
    """Create a stub server configuration file.

    Creates ``~/.config/airut/airut.yaml`` with a minimal commented
    template if the file does not already exist.  When a new file is
    created, prints links to the deployment and repo-onboarding guides
    to help the user complete configuration.

    Args:
        argv: Extra arguments (currently unused).

    Returns:
        Exit code (always 0).
    """
    config_path = get_config_path()

    if config_path.exists():
        print(f"Config already exists: {config_path}")
        return 0

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(_STUB_CONFIG)
    print(f"Created stub config: {config_path}")
    print()
    print("Next steps — complete your configuration:")
    print(f"  Deployment guide:      {_DOCS_BASE}/doc/deployment.md")
    print(f"  Repo onboarding guide: {_DOCS_BASE}/doc/repo-onboarding.md")
    return 0


# ── Service status helpers ──────────────────────────────────────────


def _is_service_installed() -> bool:
    """Return True if the airut systemd user unit file exists."""
    from lib.install_services import get_systemd_user_dir

    unit_path = get_systemd_user_dir() / "airut.service"
    return unit_path.exists()


def _is_service_running() -> bool:
    """Return True if airut.service is active (running)."""
    try:
        result = subprocess.run(
            ["systemctl", "--user", "is-active", "airut.service"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "active"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _dashboard_url(config: ServerConfig) -> str:
    """Return the public dashboard URL from config.

    Uses ``dashboard_base_url`` if set, otherwise falls back to the
    bound address and port.  Suitable for display purposes and links.
    """
    gc = config.global_config
    if gc.dashboard_base_url:
        return gc.dashboard_base_url
    return _local_dashboard_url(config)


def _local_dashboard_url(config: ServerConfig) -> str:
    """Return the local dashboard URL from the bound address and port.

    Always uses ``dashboard_host`` and ``dashboard_port``, ignoring
    ``dashboard_base_url``.  Use this for internal requests that must
    bypass any authenticating reverse proxy.
    """
    gc = config.global_config
    return f"http://{gc.dashboard_host}:{gc.dashboard_port}"


def _fetch_running_version(
    base_url: str,
) -> dict[str, str] | None:
    """Fetch version info from the running dashboard server.

    Args:
        base_url: Dashboard base URL (e.g. ``http://127.0.0.1:5200``).

    Returns:
        Parsed JSON dict with ``version``, ``sha_short``, ``sha_full``
        keys, or None if the request fails.
    """
    url = f"{base_url.rstrip('/')}/version"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data: dict[str, str] = json.loads(resp.read().decode())
            return data
    except (
        urllib.error.URLError,
        OSError,
        json.JSONDecodeError,
        ValueError,
    ):
        return None


def _fetch_health(
    base_url: str,
) -> dict[str, Any] | None:
    """Fetch health status from the running dashboard server.

    Args:
        base_url: Dashboard base URL (e.g. ``http://127.0.0.1:5200``).

    Returns:
        Parsed JSON dict with ``status``, ``tasks``, ``repos`` keys,
        or None if the request fails.
    """
    url = f"{base_url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data: dict[str, Any] = json.loads(resp.read().decode())
            return data
    except (
        urllib.error.URLError,
        OSError,
        json.JSONDecodeError,
        ValueError,
    ):
        return None


#: Suggested command to restart the systemd user service.
_RESTART_CMD = "systemctl --user restart airut"


def _running_is_newer(
    running: dict[str, str],
    installed: GitVersionInfo,
) -> bool:
    """Return True if the running server version is newer than installed.

    Compares via PEP 440 version strings when available, ignoring
    unparseable or missing versions.

    Args:
        running: Version dict from the ``/version`` endpoint (has
            ``version``, ``sha_short``, ``sha_full`` keys).
        installed: Locally installed version info.

    Returns:
        True if the running version is strictly newer.
    """
    from lib.version import _is_older

    rv = running.get("version", "").lstrip("v")
    iv = installed.version.lstrip("v")
    if rv and iv:
        return _is_older(iv, rv)
    return False


# ── check subcommand ────────────────────────────────────────────────


def cmd_check(argv: list[str]) -> int:
    """Run readiness checks and print installation status.

    Displays version information, configuration status, system
    dependencies, and service health.  Dependency and configuration
    failures affect the exit code; service status is informational only.

    Args:
        argv: Extra arguments (currently unused).

    Returns:
        0 if all checks pass, 1 if any check fails.
    """
    s = _Style(_use_color())
    all_ok = True

    # ── Version ─────────────────────────────────────────────────
    from lib.version import check_upstream_version, get_git_version_info

    vi = get_git_version_info()
    version_label = vi.version or vi.sha_short
    print(s.bold(f"Airut {version_label}"))

    upstream = check_upstream_version(vi)
    if upstream and upstream.update_available:
        if upstream.source == "pypi":
            print(
                f"  {s.yellow('Update available:')} "
                f"{upstream.current} → {upstream.latest}"
            )
            print(f"  Run {s.cyan('airut update')} to update.")
        else:
            short_current = upstream.current[:7]
            short_latest = upstream.latest[:7]
            print(
                f"  {s.yellow('Update available:')} "
                f"{short_current} → {short_latest}"
            )
            print(f"  Run {s.cyan('airut update')} to update.")
    print()

    # ── Configuration ───────────────────────────────────────────
    print(s.bold("Configuration"))
    config_path = get_config_path()
    print(f"  Config file: {s.dim(str(config_path))}")

    config: ServerConfig | None = None
    if not config_path.exists():
        print(f"  Status:      {s.red('not found')}")
        print(f"  Run {s.cyan('airut init')} to create a stub config.")
        all_ok = False
    else:
        try:
            config = ServerConfig.from_yaml(config_path)
            repo_ids = ", ".join(sorted(config.repos))
            print(
                f"  Status:      {s.green('ok')} — "
                f"{len(config.repos)} repo(s) ({repo_ids})"
            )
        except (ConfigError, ValueError, Exception) as e:
            print(f"  Status:      {s.red('error')} — {e}")
            all_ok = False

    dotenv_path = get_dotenv_path()
    if dotenv_path.exists():
        print(f"  Env file:    {s.dim(str(dotenv_path))}")

    print()

    # ── System dependencies ─────────────────────────────────────
    print(s.bold("Dependencies"))
    for name, version_cmd, min_ver in [
        ("git", ["git", "--version"], _MIN_VERSIONS["git"]),
        ("podman", ["podman", "--version"], _MIN_VERSIONS["podman"]),
    ]:
        ok, detail = _check_dependency(name, version_cmd, min_ver)
        if ok:
            print(f"  {s.green('✓')} {detail}")
        else:
            print(f"  {s.red('✗')} {detail}")
            all_ok = False
    print()

    # ── Service status (informational) ──────────────────────────
    print(s.bold("Service"))
    if _is_service_installed():
        if _is_service_running():
            label = s.green("running")
            if config:
                url = _dashboard_url(config)
                label += f"  {s.dim(url)}"
            print(f"  airut.service: {label}")

            # Check running version against local version
            if config:
                local_url = _local_dashboard_url(config)
                rv = _fetch_running_version(local_url)
                if rv:
                    running_sha = rv.get("sha_short", "")
                    if running_sha and running_sha != vi.sha_short:
                        rl = rv.get("version") or running_sha
                        print(
                            f"  {s.yellow('Version mismatch:')} "
                            f"running {rl}, "
                            f"installed {version_label}"
                        )
                        # If the running server has a newer version
                        # than what is installed, the binary just
                        # needs a restart — no upgrade required.
                        if _running_is_newer(rv, vi):
                            print(f"  Run {s.cyan(_RESTART_CMD)} to apply.")
                        else:
                            print(
                                "  Run "
                                f"{s.cyan('airut update')}"
                                " to apply the update."
                            )
        else:
            print(f"  airut.service: {s.yellow('stopped')}")
    else:
        print(f"  airut.service: {s.yellow('not installed')}")
        print(f"  Run {s.cyan('airut install-service')} to install.")
    print()

    # ── Summary ─────────────────────────────────────────────────
    if all_ok:
        print(s.green("All checks passed."))
    else:
        print(s.red("Some checks failed."))

    return 0 if all_ok else 1


# ── update subcommand ───────────────────────────────────────────────


def _get_active_task_counts() -> tuple[int, int] | None:
    """Query the running gateway for active task counts.

    Loads the server config to determine the local dashboard address,
    then fetches ``/health`` to get task counts.

    Returns:
        ``(in_progress, queued)`` tuple, or None if the service is not
        reachable or not configured.
    """
    config_path = get_config_path()
    if not config_path.exists():
        return None

    try:
        config = ServerConfig.from_yaml(config_path)
    except (ConfigError, ValueError, Exception):
        return None

    local_url = _local_dashboard_url(config)
    health = _fetch_health(local_url)
    if health is None:
        return None

    tasks = health.get("tasks")
    if not isinstance(tasks, dict):
        return None

    in_progress = tasks.get("in_progress")
    queued = tasks.get("queued")
    if not isinstance(in_progress, int) or not isinstance(queued, int):
        return None

    return in_progress, queued


_WAIT_POLL_SECONDS = 10


def cmd_update(argv: list[str]) -> int:
    """Update airut to the latest version.

    Runs ``uv tool upgrade airut``.  If the upgrade is a no-op (already
    up to date), returns immediately without touching the service.

    When the binary was actually updated and the systemd service is
    installed, stops and uninstalls the service, then reinstalls it
    using the new binary.

    Refuses to proceed when the running gateway has queued or in-progress
    tasks.  Use ``--force`` to override, or ``--wait`` to poll until the
    gateway is idle.

    Args:
        argv: Extra arguments (``--force``, ``--wait``).

    Returns:
        Exit code (0 on success, 1 on error).
    """
    s = _Style(_use_color())
    force = "--force" in argv
    wait = "--wait" in argv
    service_was_installed = _is_service_installed()

    # ── Pre-flight: check for tasks in flight ──────────────────
    if service_was_installed and _is_service_running() and not force:
        counts = _get_active_task_counts()
        if counts is not None:
            in_progress, queued = counts
            active = in_progress + queued

            if active > 0 and wait:
                print(
                    f"  {s.yellow('Tasks in flight:')} "
                    f"{in_progress} running, {queued} queued."
                )
                print(f"  {s.dim('Waiting for tasks to complete...')}")

                while active > 0:
                    time.sleep(_WAIT_POLL_SECONDS)
                    counts = _get_active_task_counts()
                    if counts is None:
                        # Service went away — safe to proceed.
                        break
                    in_progress, queued = counts
                    active = in_progress + queued
                    if active > 0:
                        print(
                            f"  {
                                s.dim(
                                    f'  Still waiting: '
                                    f'{in_progress} running, '
                                    f'{queued} queued...'
                                )
                            }"
                        )

                print(f"  {s.green('All tasks completed.')}")

            elif active > 0:
                print(
                    f"  {s.red('Cannot update:')} "
                    f"{in_progress} running, {queued} queued task(s)."
                )
                print(
                    f"  Use {s.cyan('airut update --wait')} to wait, "
                    f"or {s.cyan('airut update --force')} to update anyway."
                )
                return 1

    # ── Run uv tool upgrade ───────────────────────────────────
    print(f"  {s.dim('Upgrading airut...')}")
    try:
        result = subprocess.run(
            ["uv", "tool", "upgrade", "airut"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        print(f"  {s.red('Error:')} uv not found on PATH.")
        return 1
    except subprocess.TimeoutExpired:
        print(f"  {s.red('Error:')} uv tool upgrade timed out.")
        return 1

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        print(f"  {s.red('Error:')} uv tool upgrade failed.")
        if detail:
            print(f"  {detail}")
        return 1

    upgrade_output = result.stdout.strip() or result.stderr.strip()
    if upgrade_output:
        print(f"  {upgrade_output}")

    # Detect no-op upgrades to avoid unnecessary service restart.
    # uv outputs "Nothing to upgrade" when the installed version is current.
    nothing_changed = "nothing to upgrade" in (upgrade_output or "").lower()

    if nothing_changed:
        print(f"  {s.green('Already up to date.')}")
        return 0

    # ── Restart service with the updated binary ───────────────
    if service_was_installed:
        print(f"  {s.dim('Stopping and uninstalling service...')}")
        from lib.install_services import uninstall_services

        try:
            uninstall_services()
        except RuntimeError as e:
            print(f"  {s.red('Error uninstalling service:')} {e}")
            return 1

        print(f"  {s.dim('Reinstalling service...')}")
        from lib.install_services import get_airut_path

        airut_path = get_airut_path()
        try:
            result = subprocess.run(
                [airut_path, "install-service"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"  {s.red('Error reinstalling service:')} {e}")
            return 1

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            print(f"  {s.red('Error reinstalling service.')}")
            if detail:
                print(f"  {detail}")
            return 1

    print(f"  {s.green('Update complete.')}")
    return 0


# ── run-gateway subcommand ──────────────────────────────────────────


def cmd_run_gateway(argv: list[str]) -> int:
    """Start the email gateway service.

    Args:
        argv: Arguments forwarded to the gateway (e.g. --resilient --debug).
    """
    from lib.gateway.service import main as gateway_main

    return gateway_main(argv)


# ── install-service subcommand ──────────────────────────────────────


def cmd_install_service(argv: list[str]) -> int:
    """Install systemd user services for Airut.

    Installs ``airut.service`` (email gateway).

    Args:
        argv: Extra arguments (currently unused).

    Returns:
        Exit code (0 on success, 1 on error).
    """
    from lib.install_services import install_services

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        install_services()
        return 0
    except RuntimeError as e:
        logger.error("%s", e)
        return 1


# ── uninstall-service subcommand ────────────────────────────────────


def cmd_uninstall_service(argv: list[str]) -> int:
    """Uninstall systemd user services for Airut.

    Args:
        argv: Extra arguments (currently unused).

    Returns:
        Exit code (0 on success, 1 on error).
    """
    from lib.install_services import uninstall_services

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        uninstall_services()
        return 0
    except RuntimeError as e:
        logger.error("%s", e)
        return 1


# ── CLI plumbing ────────────────────────────────────────────────────


_DISPATCH: dict[str, str] = {
    "run-gateway": "cmd_run_gateway",
    "init": "cmd_init",
    "check": "cmd_check",
    "update": "cmd_update",
    "install-service": "cmd_install_service",
    "uninstall-service": "cmd_uninstall_service",
}

_SUBCOMMAND_HELP: dict[str, str] = {
    "init": (
        "usage: airut init\n\n"
        "Create a stub server config at ~/.config/airut/airut.yaml.\n"
        "Does nothing if the config already exists."
    ),
    "check": (
        "usage: airut check\n\n"
        "Verify config, system dependencies, and service status.\n"
        "Exit code 0 if all checks pass, 1 otherwise."
    ),
    "update": (
        "usage: airut update [--wait] [--force]\n\n"
        "Update airut to the latest version via uv tool upgrade.\n"
        "If already up to date, exits without restarting the service.\n\n"
        "options:\n"
        "  --wait   Wait for running tasks to complete before updating\n"
        "  --force  Update even if tasks are in flight"
    ),
    "install-service": (
        "usage: airut install-service\n\n"
        "Install and start the airut systemd user service."
    ),
    "uninstall-service": (
        "usage: airut uninstall-service\n\n"
        "Stop and remove the airut systemd user service."
    ),
    "run-gateway": (
        "usage: airut run-gateway [--resilient] [--debug]\n\n"
        "Start the email gateway service (normally managed by systemd)."
    ),
}


def _print_info() -> None:
    """Print version information and available commands."""
    from lib.version import get_git_version_info

    s = _Style(_use_color())
    vi = get_git_version_info()
    version_label = vi.version or vi.sha_short
    print(s.bold(f"Airut {version_label}"))
    print()
    print(_USAGE)


def cli() -> None:
    """Entry point for ``airut`` (via ``uv tool install`` or ``uv run``).

    When no arguments are given, prints version and usage information.
    Requires an explicit subcommand for all operations.
    """
    argv = sys.argv[1:]

    if not argv or argv[0] == "--help":
        _print_info()
        sys.exit(0)

    if argv[0] not in _SUBCOMMANDS:
        print(f"airut: unknown command '{argv[0]}'", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        sys.exit(2)

    command = argv[0]
    rest = argv[1:]

    if "--help" in rest and command in _SUBCOMMAND_HELP:
        print(_SUBCOMMAND_HELP[command])
        sys.exit(0)

    # Look up handler by name so tests can mock individual commands.
    import lib.airut as _self

    handler = getattr(_self, _DISPATCH[command])
    sys.exit(handler(rest))


#: Stub configuration template written by ``airut init``.
_STUB_CONFIG = """\
# Airut Server Configuration
#
# For all available options, see the documented example:
# https://github.com/airutorg/airut/blob/main/config/airut.example.yaml

# execution:
#   max_concurrent: 3
#   shutdown_timeout: 60

# dashboard:
#   enabled: true
#   host: 127.0.0.1
#   port: 5200

# container_command: podman

repos:
  my-project:
    email:
      imap_server: mail.example.com
      smtp_server: mail.example.com
      username: airut@example.com
      password: changeme
      from: "Airut <airut@example.com>"
    authorized_senders:
      - you@example.com
    trusted_authserv_id: mail.example.com
    git:
      repo_url: https://github.com/you/my-project.git
    secrets:
      ANTHROPIC_API_KEY: changeme
"""
