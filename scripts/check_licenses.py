#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Check licenses of runtime dependencies only.

Resolves the full transitive closure of [project] dependencies (excluding
[dependency-groups]) via `uv tree --no-dev`, then runs pip-licenses against
only those packages. This ensures the license audit covers exactly what ships
in a production install.

Usage:
    uv run scripts/check_licenses.py
"""

import re
import subprocess
import sys


def resolve_runtime_packages() -> list[str]:
    """Resolve runtime package names from uv dependency tree.

    Returns:
        Sorted list of package names (excluding the root project).
    """
    result = subprocess.run(
        ["uv", "tree", "--no-dev", "--depth", "100"],
        capture_output=True,
        text=True,
        check=True,
    )

    # Parse package names from tree output lines like:
    #   ├── msal v1.34.0
    #   │   └── cryptography v46.0.5 (extra: crypto) (*)
    # The root project line (no tree prefix) is excluded.
    packages: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.search(r"[├└─│ ]+\s+(\S+)\s+v", line)
        if match:
            # Strip extras notation like "pyjwt[crypto]" -> "pyjwt"
            name = re.sub(r"\[.*\]", "", match.group(1))
            packages.add(name)

    return sorted(packages)


def main() -> int:
    """Resolve runtime deps and check their licenses."""
    packages = resolve_runtime_packages()

    if not packages:
        print("ERROR: No runtime packages resolved", file=sys.stderr)
        return 1

    result = subprocess.run(
        ["uv", "run", "pip-licenses", "--packages", *packages],
        text=True,
    )
    return result.returncode


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
