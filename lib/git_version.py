# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Git version information utility.

This module provides a common utility for reading git repository status,
used by both the Fava server and email service dashboards to capture
version info at launch time.
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class GitVersionInfo:
    """Git version information captured at service startup.

    Attributes:
        sha_short: Short git commit SHA (7-8 characters).
        sha_full: Full 40-character git commit SHA.
        worktree_clean: True if working tree has no uncommitted changes.
        full_status: Full git status output (HEAD info + worktree status).
    """

    sha_short: str
    sha_full: str
    worktree_clean: bool
    full_status: str


def get_git_version_info(repo_path: Path | None = None) -> GitVersionInfo:
    """Read git repository version information.

    Captures the current HEAD commit SHA (short and full), worktree clean
    status, and full status output suitable for displaying in a /.version
    endpoint.

    Args:
        repo_path: Path to git repository root. If None, uses parent of
            this file.

    Returns:
        GitVersionInfo with all version details.
    """
    if repo_path is None:
        repo_path = Path(__file__).parent.parent

    # Get short SHA
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        sha_short = result.stdout.strip()
    except subprocess.CalledProcessError:
        sha_short = "unknown"

    # Get full SHA
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        sha_full = result.stdout.strip()
    except subprocess.CalledProcessError:
        sha_full = "unknown"

    # Check if worktree is clean
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        worktree_clean = len(result.stdout.strip()) == 0
    except subprocess.CalledProcessError:
        worktree_clean = False

    # Get HEAD commit info (git show HEAD --no-patch)
    try:
        result = subprocess.run(
            ["git", "show", "HEAD", "--no-patch"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        head_info = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else str(e)
        head_info = f"Error: {error_msg}"

    # Get full status
    try:
        result = subprocess.run(
            ["git", "status"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        status_info = result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else str(e)
        status_info = f"Error: {error_msg}"

    full_status = (
        f"=== HEAD COMMIT ===\n{head_info}\n\n"
        f"=== WORKING TREE STATUS ===\n{status_info}"
    )

    return GitVersionInfo(
        sha_short=sha_short,
        sha_full=sha_full,
        worktree_clean=worktree_clean,
        full_status=full_status,
    )
