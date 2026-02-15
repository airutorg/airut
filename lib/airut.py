# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Airut CLI — multi-command entry point.

Provides ``uv run airut <command>`` with subcommands for running the gateway,
checking system readiness, and managing services.  When no subcommand is given,
``run-gateway`` is the default, preserving existing behavior (including bare
flags like ``uv run airut --resilient``).

Subcommands:

* ``run-gateway`` — start the email gateway service (default)
* ``check``       — verify system dependencies and readiness
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys


logger = logging.getLogger(__name__)

# Known subcommand names.
_SUBCOMMANDS = frozenset({"run-gateway", "check"})

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
  check             Verify system dependencies and readiness

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


# ── check subcommand ────────────────────────────────────────────────


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


def cmd_check(argv: list[str]) -> int:
    """Run readiness checks.

    Verifies that required system dependencies are installed and meet
    minimum version requirements.

    Args:
        argv: Extra arguments (currently unused).

    Returns:
        0 if all checks pass, 1 if any check fails.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    logger.info("Checking system dependencies...")
    all_ok = True

    # git — version requirement from _MIN_VERSIONS
    if not _check_dependency(
        "git",
        ["git", "--version"],
        _MIN_VERSIONS["git"],
    ):
        all_ok = False

    # podman — need 4.x+ for netavark backend (--route, --disable-dns)
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


# ── CLI plumbing ────────────────────────────────────────────────────


_DISPATCH = {
    "run-gateway": cmd_run_gateway,
    "check": cmd_check,
}


def cli() -> None:
    """Entry point for ``uv run airut`` and ``uv tool install``.

    When no subcommand is given (or the first argument is a flag),
    all arguments are forwarded to ``run-gateway``, preserving backward
    compatibility with ``uv run airut --resilient``.
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

    handler = _DISPATCH[command]
    sys.exit(handler(rest))
