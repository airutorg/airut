# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Airut CLI — multi-command entry point.

Provides ``airut <command>`` with subcommands for running the gateway,
initializing configuration, checking system readiness, and managing systemd
services.

Subcommands:

* ``run-gateway``       — start the email gateway service (default)
* ``init``              — create a stub server config file
* ``check``             — verify config and system dependencies
* ``install-service``   — install systemd user services
* ``uninstall-service`` — uninstall systemd user services
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

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
  run-gateway       Start the email gateway service (default)
  init              Create a stub server config file
  check             Verify config and system dependencies
  install-service   Install systemd user services
  uninstall-service Uninstall systemd user services

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


def cmd_init(argv: list[str]) -> int:
    """Create a stub server configuration file.

    Creates ``~/.config/airut/airut.yaml`` with a minimal commented
    template if the file does not already exist.

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
    """Return the dashboard URL from config.

    Uses ``dashboard_base_url`` if set, otherwise falls back to the
    bound address and port.
    """
    gc = config.global_config
    if gc.dashboard_base_url:
        return gc.dashboard_base_url
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
    from lib.git_version import check_upstream_version, get_git_version_info

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
            print(f"  Run {s.cyan('uv tool upgrade airut')} to update.")
        else:
            short_current = upstream.current[:7]
            short_latest = upstream.latest[:7]
            print(
                f"  {s.yellow('Update available:')} "
                f"{short_current} → {short_latest}"
            )
            print(f"  Run {s.cyan('uv tool upgrade airut')} to update.")
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
                url = _dashboard_url(config)
                rv = _fetch_running_version(url)
                if rv:
                    running_sha = rv.get("sha_short", "")
                    if running_sha and running_sha != vi.sha_short:
                        rl = rv.get("version") or running_sha
                        print(
                            f"  {s.yellow('Version mismatch:')} "
                            f"running {rl}, "
                            f"installed {version_label}"
                        )
                        print(
                            "  Run "
                            f"{s.cyan('systemctl --user restart airut')}"
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
    "install-service": "cmd_install_service",
    "uninstall-service": "cmd_uninstall_service",
}


def cli() -> None:
    """Entry point for ``airut`` (via ``uv tool install`` or ``uv run``).

    When no subcommand is given (or the first argument is a flag),
    all arguments are forwarded to ``run-gateway``, preserving backward
    compatibility with ``airut --resilient``.
    """
    argv = sys.argv[1:]

    if argv and argv[0] == "--help":
        print(_USAGE)
        sys.exit(0)

    # If first arg is a known subcommand, split it off.  Otherwise treat
    # everything as gateway args (backward compat).
    if argv and argv[0] in _SUBCOMMANDS:
        command = argv[0]
        rest = argv[1:]
    else:
        command = "run-gateway"
        rest = argv

    # Look up handler by name so tests can mock individual commands.
    import lib.airut as _self

    handler = getattr(_self, _DISPATCH[command])
    sys.exit(handler(rest))


#: Stub configuration template written by ``airut init``.
_STUB_CONFIG = """\
# Airut Server Configuration
#
# See config/airut.example.yaml for a fully documented example.

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
