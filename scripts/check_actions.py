#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Check GitHub Actions version pinning.

Scans workflow files and action.yml for action references.  For SHA-pinned
actions, resolves the current floating tag and reports if the pin is outdated.
For tag/branch-pinned actions (except excluded patterns), reports them as
unpinned.

Usage:
    uv run python scripts/check_actions.py          # Check (report only)
    uv run python scripts/check_actions.py --fix    # Update SHAs in-place
    uv run python scripts/check_actions.py --verbose  # Show up-to-date too
    uv run python scripts/check_actions.py --repo /path/to/sandbox-action
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen


# Actions that are intentionally unpinned (e.g., first-party actions pinned
# to a branch).  Format: "owner/repo".
EXCLUDED_ACTIONS: set[str] = {
    "airutorg/sandbox-action",
}

# Files to scan for action references.
SCAN_GLOBS: list[tuple[str, str]] = [
    (".github/workflows", "*.yml"),
    (".", "action.yml"),
]

_GITHUB_HEADERS: dict[str, str] = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def _get_github_headers() -> dict[str, str]:
    """Build GitHub API headers, including auth token if available."""
    headers = dict(_GITHUB_HEADERS)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# Matches a SHA-pinned action: `uses: owner/repo@<sha> # v1.2.3`
# Also handles subpaths like `actions/cache/restore@<sha> # v4.3.0`
# and branch-style comments like `# release/v1`.
_PINNED_RE = re.compile(
    r"uses:\s+"
    r"(?P<action>[a-zA-Z0-9_./-]+)"
    r"@(?P<sha>[a-fA-F0-9]{40})"
    r"\s+#\s+(?P<version>[a-zA-Z/]*v[\d.]+)"
)

# Matches an unpinned action: `uses: owner/repo@v4` or `@release/v1`
# Excludes self-references (`./`) and SHA-pinned refs.
_UNPINNED_RE = re.compile(
    r"uses:\s+"
    r"(?P<action>[a-zA-Z0-9_./-]+)"
    r"@(?P<ref>[^\s#]+)"
)


def _repo_from_action(action: str) -> str:
    """Extract owner/repo from an action string.

    ``actions/cache/restore`` → ``actions/cache``.
    ``actions/checkout`` → ``actions/checkout``.
    """
    parts = action.split("/")
    return "/".join(parts[:2])


def _github_get(url: str) -> object:
    """Make a GET request to the GitHub API."""
    request = Request(url, headers=_get_github_headers())
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def resolve_tag_sha(repo: str, tag: str) -> str | None:
    """Resolve a floating tag or branch to a commit SHA.

    Tries the ref as a tag first, then as a branch.  Dereferences annotated
    tags to the underlying commit.

    Returns:
        Commit SHA, or None if the ref cannot be resolved.
    """
    # Try as a tag first
    for ref_prefix in ("tags", "heads"):
        try:
            data = _github_get(
                f"https://api.github.com/repos/{repo}/git/ref/{ref_prefix}/{tag}"
            )
        except HTTPError:
            continue
        if not isinstance(data, dict):
            continue
        d = cast(dict[str, object], data)
        obj = d.get("object", {})
        if not isinstance(obj, dict):
            continue
        obj_d = cast(dict[str, object], obj)
        sha = obj_d.get("sha")
        obj_type = obj_d.get("type")
        if not isinstance(sha, str):
            continue
        # Dereference annotated tags
        if obj_type == "tag":
            try:
                tag_data = _github_get(
                    f"https://api.github.com/repos/{repo}/git/tags/{sha}"
                )
            except HTTPError:
                return sha
            if isinstance(tag_data, dict):
                td = cast(dict[str, object], tag_data)
                inner = td.get("object", {})
                if isinstance(inner, dict):
                    inner_d = cast(dict[str, object], inner)
                    commit_sha = inner_d.get("sha")
                    if isinstance(commit_sha, str):
                        return commit_sha
        return sha
    return None


def _major_ref(version: str) -> str:
    """Derive the floating major-version ref from a version string.

    ``v4.3.1`` → ``v4``, ``v1.14.0`` → ``v1``,
    ``release/v1`` → ``release/v1``.
    """
    # Branch-style refs like "release/v1" are already major refs
    if "/" in version:
        return version
    match = re.match(r"(v\d+)", version)
    return match.group(1) if match else version


def latest_version_tag(repo: str, major: str) -> str | None:
    """Find the latest semver tag for a major version.

    Queries the repo's tags and returns the highest ``vMAJOR.x.y`` tag.
    Falls back to the major version itself if no patch tags exist.

    Returns:
        Version string like ``v4.3.1``, or None on failure.
    """
    try:
        tags = _github_get(
            f"https://api.github.com/repos/{repo}/tags?per_page=100"
        )
    except HTTPError:
        return None
    if not isinstance(tags, list):
        return None
    pattern = re.compile(re.escape(major) + r"\.\d+(\.\d+)*$")
    matches: list[tuple[tuple[int, ...], str]] = []
    for tag_obj in tags:
        if not isinstance(tag_obj, dict):
            continue
        tag_d = cast(dict[str, object], tag_obj)
        name = tag_d.get("name")
        if not isinstance(name, str):
            continue
        if pattern.match(name):
            parts = name.lstrip("v").split(".")
            nums = tuple(int(p) for p in parts)
            matches.append((nums, name))
    if not matches:
        return major
    matches.sort()
    return matches[-1][1]


def _resolve_unpinned_ref(repo: str, ref: str) -> tuple[str, str] | None:
    """Resolve an unpinned ref (tag or branch) to (sha, version_label).

    Returns:
        Tuple of (commit_sha, version_label) or None on failure.
    """
    sha = resolve_tag_sha(repo, ref)
    if sha is None:
        return None
    major = _major_ref(ref)
    version = latest_version_tag(repo, major)
    return sha, version or ref


def scan_workflow_files(root: Path | None = None) -> list[Path]:
    """Find all workflow and action files to scan.

    Args:
        root: Repository root to scan. Defaults to current directory.
    """
    base = root or Path(".")
    files: list[Path] = []
    for directory, pattern in SCAN_GLOBS:
        dir_path = base / directory
        if dir_path.is_dir():
            files.extend(sorted(dir_path.glob(pattern)))
    return files


def check_actions(
    *,
    fix: bool = False,
    verbose: bool = False,
    root: Path | None = None,
) -> int:
    """Check and optionally fix action pinning.

    Args:
        fix: Update SHAs in-place.
        verbose: Show up-to-date actions.
        root: Repository root to scan. Defaults to current directory.

    Returns:
        0 if all actions are up to date, 1 if any are outdated or unpinned.
    """
    files = scan_workflow_files(root)
    if not files:
        print("No workflow files found.")
        return 0

    outdated: list[str] = []
    unpinned: list[str] = []
    up_to_date: list[str] = []
    errors: list[str] = []

    for path in files:
        content = path.read_text()
        new_content = content

        for match in _PINNED_RE.finditer(content):
            action = match.group("action")
            repo = _repo_from_action(action)
            pinned_sha = match.group("sha")
            version = match.group("version")

            if repo in EXCLUDED_ACTIONS:
                continue

            major = _major_ref(version)
            current_sha = resolve_tag_sha(repo, major)
            if current_sha is None:
                # Try release/vN branch pattern
                current_sha = resolve_tag_sha(repo, f"release/{major}")

            if current_sha is None:
                errors.append(f"  {path}: {action} — cannot resolve {major}")
                continue

            if current_sha == pinned_sha:
                up_to_date.append(f"  {path}: {action}@{version}")
            else:
                new_version = latest_version_tag(repo, major) or major
                outdated.append(
                    f"  {path}: {action} {version} → {new_version}"
                    f" ({pinned_sha[:12]} → {current_sha[:12]})"
                )
                if fix:
                    old = f"{action}@{pinned_sha} # {version}"
                    new = f"{action}@{current_sha} # {new_version}"
                    new_content = new_content.replace(old, new)

        # Check for unpinned actions (not SHA-pinned, not excluded,
        # not self-ref)
        for match in _UNPINNED_RE.finditer(content):
            action = match.group("action")
            ref = match.group("ref")

            # Skip self-references
            if action.startswith("./") or action == ".":
                continue

            repo = _repo_from_action(action)
            if repo in EXCLUDED_ACTIONS:
                continue

            # Skip if this is actually a SHA (already handled by _PINNED_RE)
            if re.fullmatch(r"[a-fA-F0-9]{40}", ref):
                continue

            resolved = _resolve_unpinned_ref(repo, ref)
            if resolved is None:
                errors.append(f"  {path}: {action}@{ref} — cannot resolve")
                continue

            sha, version_label = resolved
            unpinned.append(
                f"  {path}: {action}@{ref} → @{sha[:12]} # {version_label}"
            )

            if fix:
                old = f"{action}@{ref}"
                new = f"{action}@{sha} # {version_label}"
                # Only replace the exact match to avoid replacing substrings
                new_content = new_content.replace(old, new)

        if fix and new_content != content:
            path.write_text(new_content)

    # Report results
    if errors:
        print("Errors:")
        for msg in errors:
            print(msg)
        print()

    if unpinned:
        label = "Fixed (pinned)" if fix else "Unpinned"
        print(f"{label}:")
        for msg in unpinned:
            print(msg)
        print()

    if outdated:
        label = "Fixed (updated)" if fix else "Outdated"
        print(f"{label}:")
        for msg in outdated:
            print(msg)
        print()

    if verbose and up_to_date:
        print("Up to date:")
        for msg in up_to_date:
            print(msg)
        print()

    total_issues = len(outdated) + len(unpinned) + len(errors)
    if total_issues == 0:
        if not verbose:
            count = len(up_to_date)
            print(f"All {count} pinned action(s) up to date.")
        return 0

    if fix:
        print(f"Fixed {len(outdated) + len(unpinned)} action(s).")
    return 0 if fix and not errors else 1


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Check GitHub Actions version pinning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help=(
            "Update pinned SHAs in workflow files"
            " (review diff before committing)"
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show up-to-date actions too",
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=None,
        help="Repository root to scan (default: current directory)",
    )
    args = parser.parse_args()
    return check_actions(fix=args.fix, verbose=args.verbose, root=args.repo)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
