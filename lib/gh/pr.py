# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""PR information utilities."""

import json
import logging
import subprocess
from dataclasses import dataclass
from enum import Enum


logger = logging.getLogger(__name__)


class PRState(Enum):
    """State of a PR."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    MERGED = "MERGED"


@dataclass
class PRInfo:
    """Information about a PR."""

    number: int
    title: str
    state: PRState
    head_ref: str
    base_ref: str
    url: str
    is_draft: bool
    mergeable: str  # MERGEABLE, CONFLICTING, UNKNOWN
    behind_by: int  # Number of commits behind base

    @property
    def has_conflicts(self) -> bool:
        """Check if PR has merge conflicts."""
        return self.mergeable == "CONFLICTING"

    @property
    def is_behind(self) -> bool:
        """Check if PR is behind base branch."""
        return self.behind_by > 0


def get_current_pr() -> PRInfo | None:
    """Get PR associated with current branch.

    Returns:
        PRInfo if a PR exists, None otherwise.

    Raises:
        RuntimeError: If gh command fails unexpectedly.
    """
    try:
        result = subprocess.run(
            [
                "gh",
                "pr",
                "view",
                "--json",
                "number,title,state,headRefName,baseRefName,url,isDraft,"
                "mergeable,commits",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            # No PR exists for current branch
            if "no pull requests found" in result.stderr.lower():
                return None
            raise RuntimeError(f"gh pr view failed: {result.stderr}")

        data = json.loads(result.stdout)

        # Calculate commits behind base
        behind_by = _get_commits_behind(data["baseRefName"])

        return PRInfo(
            number=data["number"],
            title=data["title"],
            state=PRState(data["state"]),
            head_ref=data["headRefName"],
            base_ref=data["baseRefName"],
            url=data["url"],
            is_draft=data.get("isDraft", False),
            mergeable=data.get("mergeable", "UNKNOWN"),
            behind_by=behind_by,
        )

    except subprocess.TimeoutExpired as err:
        raise RuntimeError("gh command timed out") from err
    except json.JSONDecodeError as err:
        raise RuntimeError(f"Failed to parse gh output: {err}") from err


def get_pr_info(pr_number: int) -> PRInfo:
    """Get information about a specific PR.

    Args:
        pr_number: The PR number to look up.

    Returns:
        PRInfo for the specified PR.

    Raises:
        RuntimeError: If gh command fails.
    """
    try:
        result = subprocess.run(
            [
                "gh",
                "pr",
                "view",
                str(pr_number),
                "--json",
                "number,title,state,headRefName,baseRefName,url,isDraft,"
                "mergeable,commits",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            raise RuntimeError(f"gh pr view failed: {result.stderr}")

        data = json.loads(result.stdout)

        # Calculate commits behind base
        behind_by = _get_commits_behind(data["baseRefName"])

        return PRInfo(
            number=data["number"],
            title=data["title"],
            state=PRState(data["state"]),
            head_ref=data["headRefName"],
            base_ref=data["baseRefName"],
            url=data["url"],
            is_draft=data.get("isDraft", False),
            mergeable=data.get("mergeable", "UNKNOWN"),
            behind_by=behind_by,
        )

    except subprocess.TimeoutExpired as err:
        raise RuntimeError("gh command timed out") from err
    except json.JSONDecodeError as err:
        raise RuntimeError(f"Failed to parse gh output: {err}") from err


def _get_commits_behind(base_ref: str) -> int:
    """Get number of commits current branch is behind base.

    Args:
        base_ref: The base branch name (e.g., "main").

    Returns:
        Number of commits behind, 0 if up to date or error.
    """
    try:
        # Fetch to ensure we have latest refs
        subprocess.run(
            ["git", "fetch", "origin", base_ref],
            capture_output=True,
            timeout=30,
        )

        result = subprocess.run(
            [
                "git",
                "rev-list",
                "--count",
                f"HEAD..origin/{base_ref}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            return int(result.stdout.strip())
        return 0

    except (subprocess.TimeoutExpired, ValueError):
        return 0
