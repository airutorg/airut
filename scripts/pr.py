#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""PR workflow helper for CI status and code review.

This script provides unified commands for common PR workflows:
- Checking CI status with conflict detection and failure logs
- Fetching code review status and comments

Usage:
    uv run python scripts/pr.py ci [--wait] [--pr PR_NUMBER]
    uv run python scripts/pr.py review [--pr PR_NUMBER]

Exit codes:
    0 - Success (CI passed / review approved)
    1 - CI failed or review needs changes
    2 - CI blocked (conflicts) or error
"""

import argparse
import logging
import sys
from pathlib import Path


# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from airut.gh import (  # noqa: E402
    CheckConclusion,
    CheckStatus,
    CIStatus,
    ReviewState,
    ReviewStatus,
    check_ci_status,
    get_check_failure_logs,
    get_review_status,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def format_ci_status(status: CIStatus, verbose: bool = False) -> str:
    """Format CI status for display.

    Args:
        status: CIStatus to format.
        verbose: Include detailed check information.

    Returns:
        Formatted status string.
    """
    lines: list[str] = []

    lines.append(f"PR #{status.pr_number} CI Status")
    lines.append("=" * 50)

    # Show blocking conditions first
    if status.has_conflicts:
        lines.append("")
        lines.append("BLOCKED: PR has merge conflicts")
        lines.append("CI will not run until conflicts are resolved.")
        lines.append("")
        lines.append("To fix:")
        lines.append("  git fetch origin main")
        lines.append("  git rebase origin/main")
        lines.append("  git push --force-with-lease")
        lines.append("")

    if status.behind_by > 0:
        lines.append(f"Branch is {status.behind_by} commit(s) behind base")

    # Show error if any
    if status.error:
        lines.append("")
        lines.append(f"Error: {status.error}")

    # Show overall status
    lines.append("")
    if status.is_success:
        lines.append("Status: ✓ All checks passed")
    elif status.is_failure:
        lines.append("Status: ✗ Some checks failed")
    elif status.is_pending:
        lines.append("Status: ⋯ Checks in progress")
    elif status.ci_blocked:
        lines.append("Status: ⊘ CI blocked")
    elif not status.checks:
        lines.append("Status: No checks found")
    else:
        lines.append("Status: Unknown")

    # List checks
    if status.checks:
        lines.append("")
        lines.append("Checks:")

        for check in status.checks:
            # Format status indicator
            if check.status == CheckStatus.COMPLETED:
                if check.conclusion == CheckConclusion.SUCCESS:
                    indicator = "✓"
                elif check.conclusion == CheckConclusion.SKIPPED:
                    indicator = "○"
                elif check.conclusion in {
                    CheckConclusion.FAILURE,
                    CheckConclusion.CANCELLED,
                    CheckConclusion.TIMED_OUT,
                }:
                    indicator = "✗"
                else:
                    indicator = "?"
            else:
                indicator = "⋯"

            line = f"  {indicator} {check.name}"
            if check.workflow and verbose:
                line += f" ({check.workflow})"

            lines.append(line)

    return "\n".join(lines)


def format_review_status(status: ReviewStatus, verbose: bool = False) -> str:
    """Format review status for display.

    Args:
        status: ReviewStatus to format.
        verbose: Include full comment bodies.

    Returns:
        Formatted status string.
    """
    lines: list[str] = []

    lines.append(f"PR #{status.pr_number} Review Status")
    lines.append("=" * 50)

    # Show error if any
    if status.error:
        lines.append("")
        lines.append(f"Error: {status.error}")

    # Show overall status
    lines.append("")
    if status.is_approved:
        lines.append("Status: ✓ Approved")
    elif status.needs_changes:
        lines.append("Status: ✗ Changes requested")
    elif status.reviews:
        lines.append("Status: Pending review")
    else:
        lines.append("Status: No reviews yet")

    # Show reviews by reviewer
    if status.reviews:
        lines.append("")
        lines.append("Reviews:")
        for author, state in sorted(status.reviews.items()):
            if state == ReviewState.APPROVED:
                indicator = "✓"
            elif state == ReviewState.CHANGES_REQUESTED:
                indicator = "✗"
            elif state == ReviewState.COMMENTED:
                indicator = "💬"
            elif state == ReviewState.DISMISSED:
                indicator = "○"
            else:
                indicator = "?"

            lines.append(f"  {indicator} {author}: {state.value}")

    # Show unresolved threads
    if status.pending_review_threads > 0:
        lines.append("")
        threads = status.pending_review_threads
        lines.append(f"Unresolved review threads: {threads}")

    # Show comments
    if status.comments:
        lines.append("")
        lines.append(f"Comments ({len(status.comments)}):")

        for comment in status.comments:
            lines.append("")
            # Header
            location = ""
            if comment.path:
                location = f" on {comment.path}"
                if comment.line:
                    location += f":{comment.line}"

            date_str = comment.created_at.strftime("%Y-%m-%d %H:%M")
            lines.append(f"  [{date_str}] {comment.author}{location}:")

            # Body (truncate if not verbose)
            body = comment.body.strip()
            if verbose:
                for line in body.split("\n"):
                    lines.append(f"    {line}")
            else:
                # Show first line or first 100 chars
                first_line = body.split("\n")[0]
                if len(first_line) > 100:
                    first_line = first_line[:97] + "..."
                lines.append(f"    {first_line}")
                if "\n" in body or len(body) > 100:
                    lines.append("    ...")

    return "\n".join(lines)


def cmd_ci(args: argparse.Namespace) -> int:
    """Handle ci command.

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code.
    """
    from airut.gh.pr import get_current_pr, get_pr_info

    try:
        status = check_ci_status(
            pr_number=args.pr,
            wait=args.wait,
            timeout=args.timeout,
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # Print status
    print(format_ci_status(status, verbose=args.verbose))

    # Print PR URL
    try:
        pr_info = get_pr_info(status.pr_number) if args.pr else get_current_pr()
        if pr_info:
            print()
            print(f"PR URL: {pr_info.url}")
    except RuntimeError:
        pass  # Don't fail if we can't get PR URL

    # If failed and verbose, fetch and print failure logs
    if status.is_failure and args.verbose:
        for check in status.failed_checks:
            print("")
            print(f"Logs for {check.name}:")
            print("-" * 50)
            logs = get_check_failure_logs(status.pr_number, check.name)
            if logs:
                # Truncate beginning if too long (errors are usually at the end)
                if len(logs) > 5000:
                    logs = "(truncated) ...\n" + logs[-5000:]
                print(logs)
            else:
                print("  (logs not available)")

    # Suggest running local CI if checks failed
    if status.is_failure:
        print("")
        print("To debug locally: uv run scripts/ci.py")

    # Determine exit code
    if status.ci_blocked:
        return 2
    elif status.is_failure:
        return 1
    elif status.is_success:
        return 0
    elif status.is_pending:
        return 1  # Still pending, not success
    else:
        return 2  # Unknown state


def cmd_review(args: argparse.Namespace) -> int:
    """Handle review command.

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code.
    """
    from airut.gh.pr import get_current_pr, get_pr_info

    try:
        status = get_review_status(pr_number=args.pr)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # Print status
    print(format_review_status(status, verbose=args.verbose))

    # Print PR URL
    try:
        pr_info = get_pr_info(status.pr_number) if args.pr else get_current_pr()
        if pr_info:
            print()
            print(f"PR URL: {pr_info.url}")
    except RuntimeError:
        pass  # Don't fail if we can't get PR URL

    # Determine exit code
    if status.error:
        return 2
    elif status.is_approved:
        return 0
    elif status.needs_changes:
        return 1
    else:
        return 0  # No reviews or just comments is not an error


def main() -> int:
    """Main entry point.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description="PR workflow helper for CI and code review"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ci subcommand
    ci_parser = subparsers.add_parser(
        "ci",
        help="Check CI status",
        description="Check CI status with conflict detection and failure logs",
    )
    ci_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    ci_parser.add_argument(
        "--pr",
        type=int,
        help="PR number (default: current branch's PR)",
    )
    ci_parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for CI to complete",
    )
    ci_parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Max seconds to wait for CI (default: 600)",
    )

    # review subcommand
    review_parser = subparsers.add_parser(
        "review",
        help="Check review status",
        description="Check code review status and fetch comments",
    )
    review_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    review_parser.add_argument(
        "--pr",
        type=int,
        help="PR number (default: current branch's PR)",
    )

    args = parser.parse_args()

    if args.command == "ci":
        return cmd_ci(args)
    elif args.command == "review":
        return cmd_review(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
