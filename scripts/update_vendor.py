#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Update vendored htmx dependencies to their latest versions.

Downloads the latest htmx and htmx-ext-sse releases from unpkg and
updates the vendored files and VERSION tracker.

Usage:
    uv run python scripts/update_vendor.py
    uv run python scripts/update_vendor.py --check  # dry-run
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


_UNPKG_URL = "https://unpkg.com/{package}@{version}/{path}"

_GITHUB_RELEASES_URL = (
    "https://api.github.com/repos/{owner}/{repo}/releases/latest"
)

_GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

VENDOR_DIR = Path("airut/dashboard/static/vendor")
VERSION_FILE = VENDOR_DIR / "VERSION"

# Package definitions: maps logical name to download info.
# Also imported by check_vendor_security.py.
PACKAGES = {
    "htmx": {
        "npm_package": "htmx.org",
        "github_owner": "bigskysoftware",
        "github_repo": "htmx",
        "file": "htmx.min.js",
        "unpkg_path": "dist/htmx.min.js",
    },
    "htmx-ext-sse": {
        "npm_package": "htmx-ext-sse",
        "github_owner": "bigskysoftware",
        "github_repo": "htmx-ext-sse",
        "file": "sse.min.js",
        "unpkg_path": "dist/sse.min.js",
    },
}


def get_latest_version(owner: str, repo: str) -> str:
    """Get the latest release version from GitHub.

    Args:
        owner: Repository owner.
        repo: Repository name.

    Returns:
        Version string (without 'v' prefix).

    Raises:
        URLError: If the request fails.
        ValueError: If the response is invalid.
    """
    url = _GITHUB_RELEASES_URL.format(owner=owner, repo=repo)
    request = Request(url, headers=_GITHUB_HEADERS)
    with urlopen(request, timeout=30) as response:
        data = json.loads(response.read())
    if not isinstance(data, dict):
        msg = f"Unexpected response from {url}"
        raise ValueError(msg)
    tag = data.get("tag_name", "")
    return tag.lstrip("v")


def download_file(url: str) -> bytes:
    """Download a file and return its content.

    Args:
        url: URL to download.

    Returns:
        File content as bytes.

    Raises:
        URLError: If the download fails.
    """
    request = Request(url)
    with urlopen(request, timeout=60) as response:
        return response.read()


def parse_version_file(path: Path) -> dict[str, str]:
    """Parse the VERSION file into a dict of package -> version.

    Args:
        path: Path to the VERSION file.

    Returns:
        Dict mapping package name to version string.
    """
    versions: dict[str, str] = {}
    if not path.exists():
        return versions
    content = path.read_text()
    for line in content.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2:
            versions[parts[0]] = parts[1]
    return versions


def write_version_file(path: Path, versions: dict[str, str]) -> None:
    """Write the VERSION file.

    Args:
        path: Path to the VERSION file.
        versions: Dict mapping package name to version string.
    """
    lines = [f"{name} {version}\n" for name, version in versions.items()]
    path.write_text("".join(lines))


def update_package(
    name: str,
    info: dict[str, str],
    current_versions: dict[str, str],
    check_only: bool,
) -> tuple[str, str, bool]:
    """Update a single vendored package.

    Args:
        name: Logical package name (e.g., "htmx").
        info: Package info dict with npm_package, github_owner, etc.
        current_versions: Current version dict (mutable, updated in place).
        check_only: If True, don't download files.

    Returns:
        Tuple of (current_version, latest_version, was_updated).
    """
    current = current_versions.get(name, "unknown")

    latest = get_latest_version(info["github_owner"], info["github_repo"])

    if not latest:
        print(f"  Could not determine latest version for {name}")
        return current, "", False

    if current == latest:
        print(f"  {name}: {current} (up to date)")
        return current, latest, False

    print(f"  {name}: {current} → {latest}")

    if check_only:
        return current, latest, False

    # Download the file
    url = _UNPKG_URL.format(
        package=info["npm_package"],
        version=latest,
        path=info["unpkg_path"],
    )
    print(f"    Downloading {url}")
    content = download_file(url)

    dest = VENDOR_DIR / info["file"]
    dest.write_bytes(content)
    print(f"    Wrote {dest} ({len(content)} bytes)")

    current_versions[name] = latest
    return current, latest, True


def main() -> int:
    """Update vendored dependencies.

    Returns:
        0 on success, 1 on error.
    """
    parser = argparse.ArgumentParser(
        description="Update vendored htmx dependencies"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check for updates without downloading",
    )
    args = parser.parse_args()

    if not VENDOR_DIR.exists():
        print(f"ERROR: {VENDOR_DIR} not found")
        return 1

    current_versions = parse_version_file(VERSION_FILE)
    any_updated = False

    for name, info in PACKAGES.items():
        try:
            _, _, updated = update_package(
                name, info, current_versions, args.check
            )
            if updated:
                any_updated = True
        except (URLError, ValueError) as e:
            print(f"  ERROR updating {name}: {e}")
            return 1

    if any_updated:
        write_version_file(VERSION_FILE, current_versions)
        print(f"\nUpdated {VERSION_FILE}")
        print("Review changes and commit.")
    elif not args.check:
        print("\nAll vendored dependencies are up to date.")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
