# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""CI status checking utilities."""

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum


logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Status of a CI check."""

    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    WAITING = "WAITING"
    PENDING = "PENDING"
    REQUESTED = "REQUESTED"


class CheckConclusion(Enum):
    """Conclusion of a completed CI check."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"
    TIMED_OUT = "TIMED_OUT"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    STALE = "STALE"
    NEUTRAL = "NEUTRAL"
    STARTUP_FAILURE = "STARTUP_FAILURE"
    NONE = ""  # For checks still in progress


@dataclass
class CICheckResult:
    """Result of a single CI check."""

    name: str
    status: CheckStatus
    conclusion: CheckConclusion
    workflow: str
    url: str | None = None


@dataclass
class CIStatus:
    """Aggregate CI status for a PR."""

    pr_number: int
    checks: list[CICheckResult] = field(default_factory=list)
    has_conflicts: bool = False
    behind_by: int = 0
    error: str | None = None

    @property
    def is_pending(self) -> bool:
        """Check if any CI check is still pending/running."""
        pending_statuses = {
            CheckStatus.QUEUED,
            CheckStatus.IN_PROGRESS,
            CheckStatus.WAITING,
            CheckStatus.PENDING,
            CheckStatus.REQUESTED,
        }
        return any(c.status in pending_statuses for c in self.checks)

    @property
    def is_success(self) -> bool:
        """Check if all CI checks passed."""
        if not self.checks:
            return False
        success_conclusions = {
            CheckConclusion.SUCCESS,
            CheckConclusion.SKIPPED,
            CheckConclusion.NEUTRAL,
        }
        return (
            all(
                c.conclusion in success_conclusions
                for c in self.checks
                if c.status == CheckStatus.COMPLETED
            )
            and not self.is_pending
        )

    @property
    def is_failure(self) -> bool:
        """Check if any CI check failed."""
        failure_conclusions = {
            CheckConclusion.FAILURE,
            CheckConclusion.CANCELLED,
            CheckConclusion.TIMED_OUT,
            CheckConclusion.STARTUP_FAILURE,
        }
        return any(c.conclusion in failure_conclusions for c in self.checks)

    @property
    def failed_checks(self) -> list[CICheckResult]:
        """Get list of failed checks."""
        failure_conclusions = {
            CheckConclusion.FAILURE,
            CheckConclusion.CANCELLED,
            CheckConclusion.TIMED_OUT,
            CheckConclusion.STARTUP_FAILURE,
        }
        return [c for c in self.checks if c.conclusion in failure_conclusions]

    @property
    def ci_blocked(self) -> bool:
        """Check if CI is blocked (won't run due to conflicts)."""
        return self.has_conflicts


def check_ci_status(
    pr_number: int | None = None,
    wait: bool = False,
    poll_interval: int = 30,
    timeout: int = 600,
) -> CIStatus:
    """Check CI status for a PR.

    Args:
        pr_number: PR number to check. If None, uses current branch's PR.
        wait: If True, wait for CI to complete.
        poll_interval: Seconds between status checks when waiting.
        timeout: Maximum seconds to wait for CI completion.

    Returns:
        CIStatus with check results and metadata.

    Raises:
        RuntimeError: If gh command fails or no PR found.
    """
    from lib.gh.pr import get_current_pr, get_pr_info

    # Get PR info
    if pr_number is None:
        pr_info = get_current_pr()
        if pr_info is None:
            raise RuntimeError("No PR found for current branch")
        pr_number = pr_info.number
    else:
        pr_info = get_pr_info(pr_number)

    # Build initial status with PR metadata
    status = CIStatus(
        pr_number=pr_number,
        has_conflicts=pr_info.has_conflicts,
        behind_by=pr_info.behind_by,
    )

    # Check for blocking conditions
    if pr_info.has_conflicts:
        base = pr_info.base_ref
        status.error = (
            "PR has merge conflicts - CI will not run until resolved. "
            f"Rebase on {base}: "
            f"`git fetch origin {base} && "
            f"git rebase origin/{base} && git push --force-with-lease`"
        )
        # Still fetch checks to show status
        status.checks = _fetch_checks(pr_number)
        return status

    # Fetch checks with retry logic for initialization race condition
    start_time = time.time()
    retry_delay = 2.0  # Start with 2s, will exponentially backoff
    max_retry_delay = 16.0  # Cap at 16s
    max_retry_time = 30.0  # Stop retrying for empty checks after 30s

    while True:
        status.checks = _fetch_checks(pr_number)

        # If we're not waiting, return immediately regardless of check status
        if not wait:
            break

        # If we have checks, proceed to normal wait loop
        if status.checks:
            # If checks are complete, we're done
            if not status.is_pending:
                break

            # Otherwise continue waiting
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                status.error = f"Timed out after {timeout}s waiting for CI"
                break

            # Use print (not logger) so it appears in order with final output
            elapsed_int = int(elapsed)
            print(f"Waiting for CI... ({elapsed_int}s elapsed)")
            time.sleep(poll_interval)
        else:
            # Empty checks - GitHub may not have initialized yet
            # Retry with exponential backoff for up to max_retry_time
            elapsed = time.time() - start_time
            if elapsed < max_retry_time:
                print(
                    f"No checks found yet, "
                    f"retrying in {retry_delay:.0f}s "
                    f"(GitHub may still be initializing)..."
                )
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_retry_delay)
            else:
                # After max_retry_time with no checks, give up
                break

    return status


def _parse_check_state(state: str) -> tuple[CheckStatus, CheckConclusion]:
    """Parse gh check state into status and conclusion.

    The gh CLI reports a single 'state' field that combines both.

    Args:
        state: The state string from gh CLI (e.g., 'SUCCESS', 'IN_PROGRESS').

    Returns:
        Tuple of (CheckStatus, CheckConclusion).
    """
    # Terminal states - check is complete
    completed = CheckStatus.COMPLETED
    terminal_states = {
        "SUCCESS": (completed, CheckConclusion.SUCCESS),
        "FAILURE": (completed, CheckConclusion.FAILURE),
        "CANCELLED": (completed, CheckConclusion.CANCELLED),
        "SKIPPED": (completed, CheckConclusion.SKIPPED),
        "TIMED_OUT": (completed, CheckConclusion.TIMED_OUT),
        "NEUTRAL": (completed, CheckConclusion.NEUTRAL),
        "STALE": (completed, CheckConclusion.STALE),
        "STARTUP_FAILURE": (completed, CheckConclusion.STARTUP_FAILURE),
        "ACTION_REQUIRED": (completed, CheckConclusion.ACTION_REQUIRED),
    }

    if state in terminal_states:
        return terminal_states[state]

    # In-progress states
    in_progress_states = {
        "IN_PROGRESS": CheckStatus.IN_PROGRESS,
        "QUEUED": CheckStatus.QUEUED,
        "WAITING": CheckStatus.WAITING,
        "PENDING": CheckStatus.PENDING,
        "REQUESTED": CheckStatus.REQUESTED,
    }

    if state in in_progress_states:
        return (in_progress_states[state], CheckConclusion.NONE)

    # Unknown state - assume pending
    return (CheckStatus.PENDING, CheckConclusion.NONE)


def _fetch_checks(pr_number: int) -> list[CICheckResult]:
    """Fetch CI checks for a PR.

    Args:
        pr_number: PR number to fetch checks for.

    Returns:
        List of CICheckResult.
    """
    try:
        result = subprocess.run(
            [
                "gh",
                "pr",
                "checks",
                str(pr_number),
                "--json",
                "name,state,workflow,link",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            # No checks yet is not an error
            if "no checks" in result.stderr.lower():
                return []
            logger.warning("gh pr checks failed: %s", result.stderr)
            return []

        data = json.loads(result.stdout)
        checks = []

        for check in data:
            # Parse state - gh CLI uses state for both status and conclusion
            # Values: IN_PROGRESS, QUEUED, SUCCESS, FAILURE, etc.
            state_str = check.get("state", "").upper()

            # Map state to status and conclusion
            status, conclusion = _parse_check_state(state_str)

            checks.append(
                CICheckResult(
                    name=check.get("name", "unknown"),
                    status=status,
                    conclusion=conclusion,
                    workflow=check.get("workflow", ""),
                    url=check.get("link"),
                )
            )

        return checks

    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        logger.warning("Failed to fetch checks: %s", e)
        return []


def get_check_failure_logs(pr_number: int, check_name: str) -> str | None:
    """Get logs for a failed CI check.

    Args:
        pr_number: PR number.
        check_name: Name of the check to get logs for.

    Returns:
        Log output as string, or None if not available.
    """
    try:
        # First get the run ID for this check
        result = subprocess.run(
            [
                "gh",
                "pr",
                "checks",
                str(pr_number),
                "--json",
                "name,workflow,link",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)

        # Find the check
        check = None
        for c in data:
            if c.get("name") == check_name:
                check = c
                break

        if not check or not check.get("link"):
            return None

        # Extract run ID from URL
        # URL format: https://github.com/owner/repo/actions/runs/12345/job/67890
        details_url = check["link"]
        parts = details_url.split("/")

        # Find "runs" in path and get the run ID
        run_id = None
        for i, part in enumerate(parts):
            if part == "runs" and i + 1 < len(parts):
                run_id = parts[i + 1]
                break

        if not run_id:
            return None

        # Fetch the logs
        result = subprocess.run(
            [
                "gh",
                "run",
                "view",
                run_id,
                "--log-failed",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0:
            return result.stdout

        return None

    except (subprocess.TimeoutExpired, json.JSONDecodeError, IndexError):
        return None
