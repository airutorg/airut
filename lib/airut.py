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

import logging
import shutil
import subprocess
import sys

from lib.gateway.config import ConfigError, ServerConfig, get_config_path


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


# ── Dependency checking ─────────────────────────────────────────────


def _check_dependency(
    name: str,
    version_cmd: list[str],
    min_version: tuple[int, ...] | None = None,
) -> bool:
    """Check a single dependency is installed and meets version requirements.

    Args:
        name: Human-readable dependency name.
        version_cmd: Command to run to get version output.
        min_version: Minimum required version tuple, or None to skip
            version check.

    Returns:
        True if the dependency is available (and meets version if specified).
    """
    path = shutil.which(name)
    if path is None:
        logger.error("  %s: NOT FOUND", name)
        return False

    try:
        result = subprocess.run(
            version_cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        raw = result.stdout.strip() or result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.error("  %s: found at %s but failed to get version", name, path)
        return False

    try:
        version = _parse_version(raw)
    except ValueError:
        logger.error(
            "  %s: found at %s but cannot parse version from: %s",
            name,
            path,
            raw,
        )
        return False

    if min_version and version < min_version:
        logger.error(
            "  %s: %s (need >= %s)",
            name,
            _fmt_version(version),
            _fmt_version(min_version),
        )
        return False

    version_str = _fmt_version(version)
    if min_version:
        logger.info(
            "  %s: %s (>= %s)",
            name,
            version_str,
            _fmt_version(min_version),
        )
    else:
        logger.info("  %s: %s", name, version_str)
    return True


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


# ── check subcommand ────────────────────────────────────────────────


def cmd_check(argv: list[str]) -> int:
    """Run readiness checks.

    Verifies that the server configuration can be parsed and that required
    system dependencies are installed and meet minimum version requirements.

    Args:
        argv: Extra arguments (currently unused).

    Returns:
        0 if all checks pass, 1 if any check fails.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    all_ok = True

    # ── Configuration ───────────────────────────────────────────
    logger.info("Checking configuration...")
    config_path = get_config_path()

    if not config_path.exists():
        logger.error(
            "  Config file not found: %s\n"
            "  Run 'airut init' to create a stub config.",
            config_path,
        )
        all_ok = False
    else:
        try:
            config = ServerConfig.from_yaml(config_path)
            repo_ids = ", ".join(sorted(config.repos))
            logger.info(
                "  Config OK: %d repo(s) configured (%s)",
                len(config.repos),
                repo_ids,
            )
        except (ConfigError, ValueError, Exception) as e:
            logger.error("  Configuration error: %s", e)
            all_ok = False

    # ── System dependencies ─────────────────────────────────────
    logger.info("Checking system dependencies...")

    if not _check_dependency(
        "git",
        ["git", "--version"],
        _MIN_VERSIONS["git"],
    ):
        all_ok = False

    if not _check_dependency(
        "podman",
        ["podman", "--version"],
        _MIN_VERSIONS["podman"],
    ):
        all_ok = False

    if all_ok:
        logger.info("All checks passed.")
    else:
        logger.error("Some checks failed.")

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
