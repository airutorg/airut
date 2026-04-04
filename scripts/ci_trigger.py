#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""CI trigger script for periodic tasks.

Runs ci.py --fix and, on failure, outputs a prompt for Claude to fix
the CI issues and create a PR. Designed for use as a periodic task
script trigger.

Exit behavior (script trigger mode):
    Exit 0, empty stdout  → CI passed, no action needed.
    Exit 0, non-empty stdout → CI failed, stdout is the prompt for Claude.
"""

import subprocess
import sys
from pathlib import Path


# Branch name used for CI fix PRs.
CI_FIX_BRANCH = "fix/ci"


def run_ci() -> tuple[int, str]:
    """Run ci.py --fix and return (exit_code, combined_output)."""
    ci_script = Path(__file__).parent / "ci.py"
    result = subprocess.run(
        [sys.executable, str(ci_script), "--fix", "--timeout", "0"],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout + result.stderr


def build_prompt(ci_output: str) -> str:
    """Build the Claude prompt for a CI failure."""
    return f"""\
CI is failing on main. Fix the failures and create a PR.

Before starting work, check if there is already an open PR from the \
branch "{CI_FIX_BRANCH}" that fixes CI:
  git fetch origin
  gh pr list --head {CI_FIX_BRANCH} --state open --json number,url

If a PR exists:
  1. Check out the existing branch and rebase on main.
  2. Fix any remaining CI failures on that branch.
  3. Push the updated branch.
  4. Reply with the PR URL and ask for it to be reviewed and merged.

If no PR exists:
  1. Create a new branch named "{CI_FIX_BRANCH}" from main.
  2. Fix the CI failures.
  3. Create a PR from the branch.

CI output follows below.

{ci_output}"""


def main() -> int:
    """Run CI and output prompt on failure."""
    exit_code, ci_output = run_ci()

    if exit_code == 0:
        # CI passed — produce no output so the scheduler skips Claude.
        return 0

    # CI failed — print prompt to stdout for the scheduler to pick up.
    print(build_prompt(ci_output))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
