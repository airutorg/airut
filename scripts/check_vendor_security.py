#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Check vendored dependencies for known security vulnerabilities.

Reads the VERSION file from the vendored htmx directory, queries the GitHub
Advisory Database for known vulnerabilities, and checks for newer versions.

Fails CI if the vendored version has a known security advisory, or if any
check (advisory lookup, latest version lookup) cannot be completed.

Usage:
    uv run python scripts/check_vendor_security.py
"""

import json
import sys
from typing import cast
from urllib.error import URLError
from urllib.request import Request, urlopen

from scripts.update_vendor import PACKAGES as _PACKAGES
from scripts.update_vendor import VERSION_FILE, parse_version_file


# GitHub API for global security advisories (no auth required).
# Uses the ``affects`` parameter to filter by ecosystem and package name.
_ADVISORIES_URL = (
    "https://api.github.com/advisories"
    "?affects={ecosystem}:{package}&per_page=100"
)

_GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def _github_get(url: str) -> object:
    """Make a GET request to the GitHub API.

    Args:
        url: The URL to fetch.

    Returns:
        Parsed JSON response.

    Raises:
        URLError: If the request fails.
    """
    request = Request(url, headers=_GITHUB_HEADERS)
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def check_advisories(
    npm_package: str, vendored_version: str
) -> list[dict[str, str]]:
    """Check if a vendored version has known security advisories.

    Args:
        npm_package: The npm package name (e.g., "htmx.org").
        vendored_version: The vendored version string.

    Returns:
        List of advisory dicts with 'ghsa_id', 'severity', and 'summary'.
    """
    url = _ADVISORIES_URL.format(ecosystem="npm", package=npm_package)
    advisories = _github_get(url)
    if not isinstance(advisories, list):
        msg = f"Unexpected advisory API response for {npm_package}"
        raise ValueError(msg)

    affected: list[dict[str, str]] = []
    for item in advisories:
        if not isinstance(item, dict):
            continue
        advisory = cast(dict[str, object], item)
        vulns = advisory.get("vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln_obj in vulns:
            if not isinstance(vuln_obj, dict):
                continue
            vuln = cast(dict[str, object], vuln_obj)
            pkg = vuln.get("package")
            if not isinstance(pkg, dict):
                continue
            pkg_info = cast(dict[str, object], pkg)
            if pkg_info.get("name") != npm_package:
                continue
            if pkg_info.get("ecosystem") != "npm":
                continue
            vr = vuln.get("vulnerable_version_range", "")
            if not isinstance(vr, str):
                continue
            if _version_in_range(vendored_version, vr):
                ghsa_id = advisory.get("ghsa_id", "unknown")
                severity = advisory.get("severity", "unknown")
                summary = advisory.get("summary", "")
                html_url = advisory.get("html_url", "")
                affected.append(
                    {
                        "ghsa_id": str(ghsa_id),
                        "severity": str(severity),
                        "summary": str(summary),
                        "html_url": str(html_url),
                    }
                )
    return affected


def _version_in_range(version: str, range_spec: str) -> bool:
    """Check if a version falls within a vulnerability range.

    Supports simple range formats used by GitHub advisories:
    - ">= 1.0, < 2.0" — affected if version >= 1.0 AND < 2.0
    - "< 2.0.5" — affected if version < 2.0.5
    - ">= 1.0" — affected if version >= 1.0

    Args:
        version: The version to check (e.g., "2.0.8").
        range_spec: The vulnerability range (e.g., ">= 2.0.0, < 2.0.9").

    Returns:
        True if the version is within the vulnerable range.
    """
    if not range_spec:
        return False

    ver_tuple = _parse_version(version)
    if ver_tuple is None:
        return False

    # Split on comma for compound ranges (all conditions must match)
    conditions = [c.strip() for c in range_spec.split(",")]
    for condition in conditions:
        if not condition:
            continue
        if not _check_condition(ver_tuple, condition):
            return False
    return True


def _parse_version(version: str) -> tuple[int, ...] | None:
    """Parse a version string into a tuple of integers.

    Args:
        version: Version string like "2.0.8".

    Returns:
        Tuple of integers, or None if parsing fails.
    """
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return None


def _check_condition(ver: tuple[int, ...], condition: str) -> bool:
    """Check a single version condition.

    Args:
        ver: Parsed version tuple.
        condition: A condition like ">= 2.0.0" or "< 2.0.9".

    Returns:
        True if the condition is satisfied (version IS in the range).
    """
    for op in (">=", "<=", "!=", ">", "<", "="):
        if condition.startswith(op):
            target_str = condition[len(op) :].strip()
            target = _parse_version(target_str)
            if target is None:
                return False
            if op == ">=":
                return ver >= target
            if op == "<=":
                return ver <= target
            if op == ">":
                return ver > target
            if op == "<":
                return ver < target
            if op == "=":
                return ver == target
            if op == "!=":
                return ver != target
    return False


def get_latest_version(npm_package: str) -> str | None:
    """Get the latest version of an npm package from the npm registry.

    Args:
        npm_package: The npm package name (e.g., "htmx.org").

    Returns:
        Version string, or None on failure.
    """
    url = f"https://registry.npmjs.org/{npm_package}/latest"
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            data = json.loads(response.read())
    except URLError:
        return None
    if not isinstance(data, dict):
        return None
    pkg = cast(dict[str, object], data)
    version = pkg.get("version")
    if not isinstance(version, str):
        return None
    return version


def main() -> int:
    """Run vendor security checks.

    Returns:
        0 if no vulnerabilities found, 1 if vulnerabilities exist.
    """
    if not VERSION_FILE.exists():
        print(f"ERROR: {VERSION_FILE} not found")
        return 1

    versions = parse_version_file(VERSION_FILE)
    if not versions:
        print(f"ERROR: No versions found in {VERSION_FILE}")
        return 1

    has_vulnerability = False
    warnings: list[str] = []

    for name, info in _PACKAGES.items():
        version = versions.get(name)
        if version is None:
            print(f"WARNING: {name} not found in {VERSION_FILE}")
            continue

        # Check for security advisories — must succeed or CI fails
        try:
            advisories = check_advisories(info["npm_package"], version)
        except (URLError, ValueError) as e:
            print(f"ERROR: Could not check advisories for {name}: {e}")
            return 1

        if advisories:
            has_vulnerability = True
            for adv in advisories:
                print(
                    f"VULNERABLE: {name} {version} — "
                    f"{adv['ghsa_id']} ({adv['severity']}): "
                    f"{adv['summary']}"
                )
                if adv["html_url"]:
                    print(f"  Details: {adv['html_url']}")

        # Check for newer versions — must succeed or CI fails
        latest = get_latest_version(info["npm_package"])
        if latest is None:
            print(f"ERROR: Could not check latest version for {name}")
            return 1
        elif latest != version:
            latest_tuple = _parse_version(latest)
            current_tuple = _parse_version(version)
            if (
                latest_tuple is not None
                and current_tuple is not None
                and latest_tuple > current_tuple
            ):
                warnings.append(
                    f"UPDATE: {name} {version} → {latest} available"
                )

    # Print warnings (non-fatal)
    for warning in warnings:
        print(warning)

    if has_vulnerability:
        print("\nVendored dependencies have known vulnerabilities!")
        print("Run: uv run python scripts/update_vendor.py")
        return 1

    if not warnings:
        print("All vendored dependencies are up to date and secure.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
