#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Local CI runner that executes the same checks as GitHub Actions workflows.

Provides a single command to validate changes before pushing, with minimal
output on success and focused diagnostics on failure.

Usage:
    uv run scripts/ci.py           # Run all checks
    uv run scripts/ci.py --fix     # Auto-fix formatting issues first
    uv run scripts/ci.py --workflow code   # Run specific workflow only
    uv run scripts/ci.py --verbose # Show output even on success
    uv run scripts/ci.py --step-timeout 600  # Use 10-minute timeout per step
    uv run scripts/ci.py --step-timeout 0    # Disable timeout
"""

import argparse
import logging
import subprocess
import sys
from dataclasses import dataclass


# Default timeout per CI step (5 minutes)
# Can be overridden with --step-timeout flag
DEFAULT_STEP_TIMEOUT_SECONDS = 300


logger = logging.getLogger(__name__)

# ANSI color codes
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"
BOLD = "\033[1m"


@dataclass
class Step:
    """A CI step to execute."""

    name: str
    command: str
    workflow: str
    fix_command: str | None = None


# Steps derived from .github/workflows/*.yml
# See spec/local-ci-runner.md for mapping details
#
# Workflow step name mapping (for drift detection):
# code.yml: Lint, Format check, Type check, Markdown format check,
#           Test coverage, Worktree clean check
# security.yml: License check, Vulnerability scan
# e2e.yml: E2E email gateway tests
STEPS: list[Step] = [
    # code.yml steps
    Step(
        name="Lint",
        command="uv run ruff check .",
        workflow="code",
        fix_command="uv run ruff check . --fix",
    ),
    Step(
        name="Format check",
        command="uv run ruff format --check .",
        workflow="code",
        fix_command="uv run ruff format .",
    ),
    Step(
        name="Type check",
        command="uv run ty check .",
        workflow="code",
    ),
    Step(
        name="Markdown format check",
        command="uv run python scripts/check_markdown.py",
        workflow="code",
        fix_command="uv run python scripts/check_markdown.py --fix",
    ),
    Step(
        name="Test coverage",
        command=(
            "uv run pytest -n auto --cov=lib --cov=docker --cov-fail-under=100"
        ),
        workflow="code",
    ),
    # Worktree clean check
    Step(
        name="Worktree clean check",
        command="git status --porcelain",
        workflow="code",
    ),
    # security.yml steps
    Step(
        name="License check",
        command="uv run pip-licenses",
        workflow="security",
    ),
    Step(
        name="Vulnerability scan",
        command="uv run uv-secure uv.lock",
        workflow="security",
    ),
    # e2e.yml steps
    Step(
        name="E2E email gateway tests",
        command=(
            "uv run pytest tests/integration/ -n auto -v "
            "-W error::pytest.PytestUnraisableExceptionWarning "
            "-W error::RuntimeWarning "
            "--allow-hosts=127.0.0.1,localhost"
        ),
        workflow="e2e",
    ),
]

# Number of output lines to show on failure
FAILURE_OUTPUT_LINES = 50


def use_color() -> bool:
    """Check if stdout supports color output."""
    return sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    """Apply ANSI color if stdout is a TTY."""
    if use_color():
        return f"{color}{text}{RESET}"
    return text


def run_step(
    step: Step, fix_mode: bool, verbose: bool, step_timeout: int
) -> tuple[bool, str]:
    """Run a single CI step.

    Args:
        step: The step to run
        fix_mode: If True and step has fix_command, run that instead
        verbose: If True, always return full output
        step_timeout: Timeout in seconds for the step (0 = no timeout)

    Returns:
        Tuple of (success, output_to_display)
    """
    # Determine which command to run
    if fix_mode and step.fix_command:
        command = step.fix_command
    else:
        command = step.command

    # Run the command with timeout (if enabled)
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=step_timeout if step_timeout > 0 else None,
        )
    except subprocess.TimeoutExpired:
        error_msg = (
            f"Step timed out after {step_timeout} seconds.\n\n"
            "NOTIFY USER: This may indicate a hanging test or "
            "insufficient timeout.\n"
            "Possible actions:\n"
            "  1. Retry the CI run to check if this was a transient "
            "error\n"
            "  2. Investigate which test or check is hanging\n"
            "  3. Run with higher timeout: "
            f"ci.py --step-timeout {step_timeout * 2}\n"
            "  4. Disable timeout entirely: ci.py --step-timeout 0"
        )
        return False, error_msg

    output = result.stdout + result.stderr

    # Special handling for worktree clean check
    if step.name == "Worktree clean check":
        if result.stdout.strip():
            # There are uncommitted changes
            return False, f"Uncommitted changes:\n{result.stdout}"
        return True, ""

    if result.returncode == 0:
        return True, output if verbose else ""

    # On failure, return last N lines
    lines = output.strip().split("\n")
    if len(lines) > FAILURE_OUTPUT_LINES:
        truncated = lines[-FAILURE_OUTPUT_LINES:]
        return False, "\n".join(truncated)
    return False, output


def run_ci(
    workflows: list[str] | None = None,
    fix_mode: bool = False,
    verbose: bool = False,
    step_timeout: int = DEFAULT_STEP_TIMEOUT_SECONDS,
) -> int:
    """Run CI checks.

    Args:
        workflows: List of workflows to run, or None for all
        fix_mode: If True, run fix commands where available
        verbose: If True, show output even on success
        step_timeout: Timeout in seconds per step (0 = no timeout)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Filter steps by workflow if specified
    steps_to_run = STEPS
    if workflows:
        steps_to_run = [s for s in STEPS if s.workflow in workflows]

    if not steps_to_run:
        print(colorize("No steps to run for specified workflow(s)", YELLOW))
        return 2

    failed_steps: list[tuple[Step, str]] = []
    passed_count = 0

    for step in steps_to_run:
        success, output = run_step(step, fix_mode, verbose, step_timeout)

        if success:
            print(colorize(f"✓ {step.name}", GREEN))
            passed_count += 1
            if verbose and output:
                print(output)
        else:
            print(colorize(f"✗ {step.name}", RED))
            failed_steps.append((step, output))

    # Print failure details
    for step, output in failed_steps:
        print()
        print(colorize(f"{step.name} failed:", RED + BOLD))
        cmd = (
            step.fix_command if fix_mode and step.fix_command else step.command
        )
        print(f"Command: {cmd}")
        print("─" * 60)
        if output:
            print(output)
        print("─" * 60)

    # Print summary
    total = len(steps_to_run)
    failed = len(failed_steps)
    print()
    if failed == 0:
        print(colorize(f"All {total} checks passed", GREEN + BOLD))
        return 0
    else:
        print(
            colorize(f"Summary: {failed} of {total} checks failed", RED + BOLD)
        )
        return 1


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run CI checks locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--workflow",
        choices=["code", "security", "e2e"],
        action="append",
        dest="workflows",
        help="Run only steps from specified workflow (can be repeated)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Run fix commands for auto-fixable steps",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show output even on success",
    )
    parser.add_argument(
        "--step-timeout",
        type=int,
        default=DEFAULT_STEP_TIMEOUT_SECONDS,
        help=(
            "Timeout in seconds per CI step "
            f"(default: {DEFAULT_STEP_TIMEOUT_SECONDS}, "
            "0 = no timeout)"
        ),
    )

    args = parser.parse_args()

    return run_ci(
        workflows=args.workflows,
        fix_mode=args.fix,
        verbose=args.verbose,
        step_timeout=args.step_timeout,
    )


if __name__ == "__main__":
    sys.exit(main())
