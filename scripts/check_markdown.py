#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Wrapper for mdformat that fails on code block formatting errors.

mdformat with mdformat-ruff prints warnings when Python code blocks fail to
format but exits with code 0. This is by design - mdformat intentionally
swallows exceptions from code formatters to avoid crashing on invalid code
(see mdformat/renderer/_context.py:171-184).

There is no native --strict or --fail-on-warnings option in mdformat. This
wrapper runs mdformat and checks output for formatting failures, then exits
with code 1 if any are found.

Usage:
    uv run scripts/check_markdown.py [--fix] [paths...]

Args:
    --fix: Run mdformat without --check to fix issues (default: check only)
    paths: Paths to check (default: current directory)
"""

import subprocess
import sys


def main() -> int:
    """Run mdformat and fail if code block formatting errors occur."""
    # Parse arguments
    fix_mode = "--fix" in sys.argv
    args = [arg for arg in sys.argv[1:] if arg != "--fix"]

    # Build mdformat command
    cmd = ["uv", "run", "mdformat"]
    if not fix_mode:
        cmd.append("--check")
    cmd.extend(args if args else ["."])

    # Run mdformat, capturing both stdout and stderr
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    # Print all output
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    # Check for formatting errors in output
    # mdformat-ruff prints these patterns when code blocks fail to format:
    # - "error: Failed to parse"
    # - "Warning: Failed formatting content of a python code block"
    # - "Failed formatting content of a python code block" (without Warning:)
    output = result.stdout + result.stderr
    has_format_errors = (
        "Failed formatting content of a python code block" in output
        or "error: Failed to parse" in output
    )

    # Exit with error if mdformat failed OR if code blocks failed to format
    if result.returncode != 0:
        return result.returncode
    if has_format_errors:
        print(
            "\nERROR: Code block formatting failures detected",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
