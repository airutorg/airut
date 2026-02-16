# PR Workflow Tool

CLI tool that wraps GitHub CLI (`gh`) commands to provide reliable PR workflow
automation for AI agents and developers.

## Problem Statement

AI coding agents frequently struggle with GitHub PR workflows:

1. **CI won't run with merge conflicts**: Agents push changes, CI shows
   "pending" forever, and agents don't realize the PR has conflicts blocking CI
2. **Missing failure context**: When CI fails, agents need to fetch logs to
   understand what went wrong, but the gh CLI incantations are complex
3. **Review comment discovery**: Agents miss review feedback because fetching
   comments requires multiple API calls and parsing
4. **Polling without awareness**: Agents poll CI status without understanding
   branch state (behind base, conflicts, etc.)

This tool provides a unified interface that surfaces blocking conditions upfront
and fetches relevant context automatically.

## Overview

Two subcommands cover the primary PR workflow needs:

| Command  | Purpose                                             |
| -------- | --------------------------------------------------- |
| `ci`     | Check CI status with conflict detection and waiting |
| `review` | Fetch review status, approval state, and comments   |

Both commands default to the current branch's PR when `--pr` is not specified.

## CI Status Command

```bash
# Basic status check
uv run scripts/pr.py ci

# Wait for CI to complete (with timeout)
uv run scripts/pr.py ci --wait --timeout 300

# Check specific PR with verbose output
uv run scripts/pr.py ci --pr 123 -v
```

### Features

- **Conflict detection**: Warns when PR has merge conflicts and CI won't run
- **Behind-base tracking**: Shows how many commits behind the base branch
- **Wait mode**: Polls until CI completes or timeout
- **Failure logs**: With `-v`, fetches and displays logs from failed checks

### Output Example

```
PR #214 CI Status
==================================================
Branch is 2 commit(s) behind base

Status: ✓ All checks passed

Checks:
  ✓ code-quality
  ✓ security-scan
```

### Blocked State Example

```
PR #215 CI Status
==================================================

BLOCKED: PR has merge conflicts
CI will not run until conflicts are resolved.

To fix:
  git fetch origin main
  git rebase origin/main
  git push --force-with-lease

Status: ⊘ CI blocked
```

## Review Command

```bash
# Basic review status
uv run scripts/pr.py review

# Check specific PR with full comment bodies
uv run scripts/pr.py review --pr 123 -v
```

### Features

- **Approval tracking**: Shows approval state per reviewer
- **Unresolved threads**: Counts unresolved review threads via GraphQL
- **Comment fetching**: Retrieves both inline and issue comments
- **Chronological ordering**: Comments sorted by creation time

### Output Example

```
PR #214 Review Status
==================================================

Status: ✓ Approved

Reviews:
  ✓ reviewer1: APPROVED

Unresolved review threads: 0

Comments (2):

  [2026-01-16 10:52] github-actions:
    <!-- books-diff -->
    ...

  [2026-01-16 11:30] reviewer1 on airut/gh/ci.py:42:
    Consider adding a docstring here
```

## Exit Codes

| Code | CI Command Meaning           | Review Command Meaning |
| ---- | ---------------------------- | ---------------------- |
| 0    | All checks passed            | Approved or no reviews |
| 1    | Checks failed or pending     | Changes requested      |
| 2    | Blocked (conflicts) or error | Error                  |

Exit code semantics enable scripting:

```bash
# Wait for CI, fail script if not passing
uv run scripts/pr.py ci --wait || exit 1

# Check review, proceed only if approved
uv run scripts/pr.py review && echo "Ready to merge"
```

## Architecture

### Module Structure

```
airut/gh/
├── __init__.py     # Public API exports
├── pr.py           # PR information (conflicts, behind-by)
├── ci.py           # CI status checking and log fetching
└── review.py       # Review status and comment fetching

scripts/
└── pr.py           # CLI entry point
```

### Data Flow

```
gh pr view (JSON)  ──┐
                     ├──> PRInfo ──> CIStatus
gh pr checks (JSON) ─┘

gh pr view (JSON)  ──┐
gh api /reviews    ──┼──> ReviewStatus
gh api /comments   ──┤
GraphQL (threads)  ──┘
```

### Key Types

| Type            | Module      | Purpose                            |
| --------------- | ----------- | ---------------------------------- |
| `PRInfo`        | `pr.py`     | PR metadata, conflict state        |
| `CIStatus`      | `ci.py`     | Check results, blocking conditions |
| `CICheckResult` | `ci.py`     | Individual check status/conclusion |
| `ReviewStatus`  | `review.py` | Reviews, comments, thread count    |
| `ReviewComment` | `review.py` | Single comment with location       |

## Design Decisions

### Why Wrap gh CLI Instead of Using API Directly?

- **Authentication**: `gh` handles auth via `gh auth login`
- **Rate limiting**: `gh` manages rate limits and retries
- **Consistency**: Same auth/config as manual gh usage
- **Simplicity**: No OAuth token management in codebase

### Why Detect Conflicts Explicitly?

The gh CLI doesn't clearly indicate when CI is blocked by conflicts. PRs show
"pending" checks indefinitely, confusing agents. This tool checks `mergeable`
state and surfaces the blocking condition with actionable fix instructions.

### Why Include Wait Mode?

Agents often need to wait for CI before proceeding. Built-in wait mode with
timeout is more reliable than shell loops with `gh pr checks --watch`.

### Why Fetch Logs on Failure?

Understanding CI failures requires log inspection. Verbose mode automatically
fetches logs from failed checks, eliminating a separate manual step.

## CLI Reference

### ci

```
usage: pr.py ci [-h] [-v] [--pr PR] [--wait] [--timeout TIMEOUT]

Check CI status with conflict detection and failure logs

options:
  -h, --help         show this help message and exit
  -v, --verbose      Enable verbose output (workflows, failure logs)
  --pr PR            PR number (default: current branch's PR)
  --wait             Wait for CI to complete
  --timeout TIMEOUT  Max seconds to wait for CI (default: 600)
```

### review

```
usage: pr.py review [-h] [-v] [--pr PR]

Check code review status and fetch comments

options:
  -h, --help     show this help message and exit
  -v, --verbose  Enable verbose output (full comments)
  --pr PR        PR number (default: current branch's PR)
```
