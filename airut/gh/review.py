# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Code review status and comments utilities."""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


logger = logging.getLogger(__name__)


class ReviewState(Enum):
    """State of a review."""

    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    COMMENTED = "COMMENTED"
    DISMISSED = "DISMISSED"
    PENDING = "PENDING"


@dataclass
class ReviewComment:
    """A review comment on a PR."""

    author: str
    body: str
    path: str | None  # File path for inline comments
    line: int | None  # Line number for inline comments
    created_at: datetime
    in_reply_to: int | None = None  # Parent comment ID for replies
    is_resolved: bool = False


@dataclass
class ReviewStatus:
    """Aggregate review status for a PR."""

    pr_number: int
    # Dict mapping author username to their review state
    reviews: dict[str, ReviewState] = field(default_factory=dict)
    comments: list[ReviewComment] = field(default_factory=list)
    pending_review_threads: int = 0  # Unresolved review threads
    error: str | None = None

    @property
    def is_approved(self) -> bool:
        """Check if PR is approved (has approval, no changes requested)."""
        if not self.reviews:
            return False
        has_approval = any(
            state == ReviewState.APPROVED for state in self.reviews.values()
        )
        has_changes = any(
            state == ReviewState.CHANGES_REQUESTED
            for state in self.reviews.values()
        )
        return has_approval and not has_changes

    @property
    def needs_changes(self) -> bool:
        """Check if any reviewer has requested changes."""
        return any(
            state == ReviewState.CHANGES_REQUESTED
            for state in self.reviews.values()
        )

    @property
    def has_comments(self) -> bool:
        """Check if there are any review comments."""
        return len(self.comments) > 0


def get_review_status(pr_number: int | None = None) -> ReviewStatus:
    """Get review status and comments for a PR.

    Args:
        pr_number: PR number to check. If None, uses current branch's PR.

    Returns:
        ReviewStatus with review states and comments.

    Raises:
        RuntimeError: If gh command fails or no PR found.
    """
    from airut.gh.pr import get_current_pr

    # Get PR number
    if pr_number is None:
        pr_info = get_current_pr()
        if pr_info is None:
            raise RuntimeError("No PR found for current branch")
        pr_number = pr_info.number

    status = ReviewStatus(pr_number=pr_number)

    # Fetch reviews and comments
    try:
        status.reviews = _fetch_reviews(pr_number)
        status.comments = _fetch_comments(pr_number)
        status.pending_review_threads = _count_unresolved_threads(pr_number)
    except RuntimeError as e:
        status.error = str(e)

    return status


def _fetch_reviews(pr_number: int) -> dict[str, ReviewState]:
    """Fetch review states for a PR.

    Args:
        pr_number: PR number.

    Returns:
        Dict mapping reviewer username to their latest review state.
    """
    try:
        result = subprocess.run(
            [
                "gh",
                "pr",
                "view",
                str(pr_number),
                "--json",
                "reviews",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            raise RuntimeError(f"gh pr view failed: {result.stderr}")

        data = json.loads(result.stdout)
        reviews: dict[str, ReviewState] = {}

        # Process reviews in order to get latest state per reviewer
        for review in data.get("reviews", []):
            author = review.get("author", {}).get("login", "unknown")
            state_str = review.get("state", "").upper()

            try:
                state = ReviewState(state_str)
            except ValueError:
                state = ReviewState.PENDING

            # Later reviews override earlier ones
            reviews[author] = state

        return reviews

    except subprocess.TimeoutExpired as err:
        raise RuntimeError("gh command timed out") from err
    except json.JSONDecodeError as err:
        raise RuntimeError(f"Failed to parse gh output: {err}") from err


def _fetch_comments(pr_number: int) -> list[ReviewComment]:
    """Fetch review comments for a PR.

    Args:
        pr_number: PR number.

    Returns:
        List of ReviewComment.
    """
    comments: list[ReviewComment] = []

    try:
        # Fetch review comments (inline comments on code)
        result = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{{owner}}/{{repo}}/pulls/{pr_number}/comments",
                "--jq",
                ".[] | {author: .user.login, body: .body, path: .path, "
                "line: .line, created_at: .created_at, "
                "in_reply_to: .in_reply_to_id}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    created_str = data.get("created_at", "")
                    created_at = datetime.fromisoformat(
                        created_str.replace("Z", "+00:00")
                    )
                    comments.append(
                        ReviewComment(
                            author=data.get("author", "unknown"),
                            body=data.get("body", ""),
                            path=data.get("path"),
                            line=data.get("line"),
                            created_at=created_at,
                            in_reply_to=data.get("in_reply_to"),
                        )
                    )
                except (json.JSONDecodeError, ValueError):
                    continue

        # Also fetch issue comments (general PR comments, not inline)
        result = subprocess.run(
            [
                "gh",
                "pr",
                "view",
                str(pr_number),
                "--json",
                "comments",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            data = json.loads(result.stdout)
            for comment in data.get("comments", []):
                author_data = comment.get("author", {})
                if author_data is None:
                    author = "unknown"
                else:
                    author = author_data.get("login", "unknown")

                # Skip comments from github-actions bot (CI workflow outputs)
                if author == "github-actions":
                    continue

                created_str = comment.get("createdAt", "")
                if created_str:
                    created_at = datetime.fromisoformat(
                        created_str.replace("Z", "+00:00")
                    )
                else:
                    created_at = datetime.now()

                comments.append(
                    ReviewComment(
                        author=author,
                        body=comment.get("body", ""),
                        path=None,  # Issue comments are not inline
                        line=None,
                        created_at=created_at,
                    )
                )

        # Sort by creation time
        comments.sort(key=lambda c: c.created_at)

        return comments

    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def _count_unresolved_threads(pr_number: int) -> int:
    """Count unresolved review threads.

    Args:
        pr_number: PR number.

    Returns:
        Number of unresolved review threads.
    """
    try:
        # Use GraphQL to get review thread resolution status
        query = """
        query($owner: String!, $repo: String!, $pr: Int!) {
          repository(owner: $owner, name: $repo) {
            pullRequest(number: $pr) {
              reviewThreads(first: 100) {
                nodes {
                  isResolved
                }
              }
            }
          }
        }
        """

        # Get owner/repo from git remote
        result = subprocess.run(
            ["gh", "repo", "view", "--json", "owner,name"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return 0

        repo_data = json.loads(result.stdout)
        owner = repo_data.get("owner", {}).get("login", "")
        repo = repo_data.get("name", "")

        if not owner or not repo:
            return 0

        # Run GraphQL query
        result = subprocess.run(
            [
                "gh",
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-f",
                f"owner={owner}",
                "-f",
                f"repo={repo}",
                "-F",
                f"pr={pr_number}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return 0

        data = json.loads(result.stdout)
        threads = (
            data.get("data", {})
            .get("repository", {})
            .get("pullRequest", {})
            .get("reviewThreads", {})
            .get("nodes", [])
        )

        return sum(1 for t in threads if not t.get("isResolved", True))

    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return 0
