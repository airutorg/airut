# Agentic Operation

This document describes how the Airut repository achieves autonomous email-to-PR
workflows. While Airut provides the infrastructure (email handling, sandboxing,
conversation management), **agentic operation requires proper configuration of
the target repository** — including a well-crafted `CLAUDE.md`, workflow
tooling, and GitHub branch protection.

This repository serves as a reference implementation. For a simpler starting
point, the [airut.org website](https://github.com/airutorg/website) demonstrates
a minimal Airut-managed project. When onboarding new repositories to Airut,
these practices should be adapted and applied to achieve similar autonomous
operation.

## Key Principles

Successful agentic operation relies on:

1. **Clear instructions** — `CLAUDE.md` tells the agent exactly what to do
2. **Reliable tooling** — Scripts that reduce errors and provide structured
   feedback
3. **Human oversight** — Branch protection ensures all changes go through review
4. **Sandboxed execution** — Container and network isolation limit blast radius

## What Airut Provides

Airut handles the infrastructure that enables agentic operation:

- **Email conversation management** — Incoming email triggers agent execution,
  replies are sent automatically, conversation threading via `[ID:xyz123]` in
  subject
- **Container isolation** — Each conversation runs in a dedicated Podman
  container with controlled mounts (workspace, Claude session, inbox/outbox).
  Claude Code runs with `--dangerously-skip-permissions` since interactive
  approval isn't possible over email — the container sandbox provides the safety
  boundary instead
- **Network sandbox** — All HTTP(S) traffic routed through a proxy that enforces
  an allowlist, preventing data exfiltration
- **Credential injection** — Secrets passed via environment variables, never
  mounted from host
- **Session persistence** — Claude Code sessions resume across email replies
  with full context

See [security.md](security.md) for the full security model.

## What the Repository Must Provide

Airut provides the platform, but the target repository must be configured for
autonomous operation:

- **`CLAUDE.md`** — Operating instructions that guide the agent through the
  development workflow (see below)
- **Workflow tooling** — Scripts that wrap common operations (CI, PR management)
  to reduce errors
- **Branch protection** — GitHub settings that require PR approval before merge,
  creating a human-in-the-loop checkpoint
- **Dedicated agent account** — A GitHub account with limited permissions for
  the agent to push branches and create PRs
- **`.airut/` configuration** — Container Dockerfile, network allowlist, and
  repo settings

Without these, Airut will execute Claude Code, but the agent won't reliably
produce mergeable PRs.

## Security Model and Human Oversight

The security model (detailed in [security.md](security.md)) relies on the
default branch being protected:

- **Agents cannot push to main** — All changes go through PRs
- **Agents cannot bypass review** — Branch protection requires human approval
- **Agents cannot modify their own sandbox** — Network allowlist and container
  config are read from the default branch, not the agent's workspace

This creates a permission boundary: agents can propose changes (including to
their own Dockerfile or network allowlist), but those changes only take effect
after human review and merge.

The agent's GitHub account should have:

- Write access to create branches and PRs
- No admin privileges (cannot bypass branch protection)
- Token scoped to repository operations

This provides a clear audit trail (commits attributed to the agent account)
while ensuring humans remain in control.

**Note:** Running without branch protection ("YOLO mode") defeats the security
model — the agent can push to main and modify its own sandbox configuration.

## CLAUDE.md Design

The `CLAUDE.md` file is the most critical component for agentic operation. It
provides operating instructions that guide Claude through the development
workflow.

### Philosophy

A well-designed `CLAUDE.md` achieves autonomous operation by:

1. **Mandating PR creation** — The agent is instructed to always create PRs
   after completing work (unless explicitly told not to, or user input is
   needed). This eliminates manual intervention for routine tasks.

2. **Providing clear workflow** — Step-by-step commands for the standard
   development cycle (branch, commit, push, PR, wait for CI) reduce errors and
   ambiguity.

3. **Documenting the codebase** — Project structure, conventions, and
   architecture notes help the agent understand context quickly, cutting
   exploration time and reducing misunderstandings.

4. **Setting engineering standards** — Rules like "write failing test first for
   bug fixes" and "no legacy shims when refactoring" establish quality
   expectations.

### Key Sections

The Airut repository's `CLAUDE.md` contains several critical sections that drive
autonomous behavior. These can be adapted for other repositories.

#### PR Creation Mandate

This is the core instruction that enables email-to-PR workflows:

```markdown
## CRITICAL: Always Create PRs

**After completing work that modifies files, create a PR immediately.** Only
skip if: (1) you need user input to finish the task, or (2) user explicitly asks
not to create a PR.

**The task is NOT complete until the PR is created and GitHub CI passes.** This
is the final step of every task, not an optional follow-up. After local CI
passes:

\`\`\`bash
git push -u origin HEAD && gh pr create --fill
uv run scripts/pr.py ci --wait -v  # Wait for GitHub CI to pass
\`\`\`

**When task is complete, include the PR URL in your response to the user.** Use
`gh pr view --web` to get the URL, or extract it from the `gh pr create` output.
```

#### Git and PR Workflow

Clear, step-by-step workflow instructions:

```markdown
## Git and PR Workflow

**Before starting work:** Create a feature branch from latest main:

\`\`\`bash
git fetch origin && git checkout -b feature/descriptive-name origin/main
\`\`\`

**Standard workflow:**

1. Make changes, run `uv run scripts/ci.py --fix` (local CI), commit
2. Push and create PR: `git push -u origin HEAD && gh pr create --fill`
3. **Wait for GitHub CI:** `uv run scripts/pr.py ci --wait -v`
4. Address review: `uv run scripts/pr.py review -v`, fix issues, push
5. Merge (repo uses fast-forward only): `gh pr merge --squash --delete-branch`
6. Return to main: `git checkout main && git pull`

**IMPORTANT: Do not stop after step 2.** The task is complete only when the PR
is created AND GitHub CI passes (step 3).
```

#### Spec Adherence

Prevents the agent from making unauthorized architectural decisions:

```markdown
## CRITICAL: Specs and User Intent Take Priority

**When you encounter issues that require deviating from spec or user-supplied
design, stop and ask for guidance.** Do not prioritize "making tests pass" or
"getting CI green" over adhering to the spec or the user's intent.
```

#### Other Important Sections

- **Project structure** — Helps the agent navigate the codebase
- **Engineering process** — Test-first bug fixes, no legacy shims
- **CI requirements** — Mandatory checks, no workarounds
- **Autonomous learning** — Self-updating heuristics section for institutional
  knowledge

## Workflow Tooling

While not strictly necessary (the agent could use raw `git` and `gh` commands),
custom tooling significantly improves agent performance by providing structured
output and handling edge cases.

### ci.py — Local CI Runner

Runs the same checks as GitHub Actions locally:

```bash
uv run scripts/ci.py --fix    # Fix formatting, then run all checks
```

Features:

- Auto-fixes formatting issues (ruff, mdformat)
- Runs lint, type check, tests with coverage
- Checks for clean worktree (no uncommitted changes)
- Authorship validation (prevents AI metadata in commits)
- Minimal output on success, detailed diagnostics on failure

### pr.py — PR Workflow Tool

Wraps `gh` CLI for reliable PR operations:

```bash
uv run scripts/pr.py ci --wait -v    # Wait for CI, show failure logs
uv run scripts/pr.py review -v       # Fetch review comments
```

Features:

- **Conflict detection**: Warns when CI won't run due to merge conflicts
- **Behind-base tracking**: Shows commits behind main
- **Wait mode**: Polls until CI completes or timeout
- **Failure logs**: Automatically fetches logs from failed checks
- **Review comments**: Fetches inline and issue comments

Why wrap `gh`:

- Agents struggle with raw `gh` output parsing
- Conflicts cause "pending" CI that never completes
- Log fetching requires multiple API calls

These tools reduce friction and let the agent focus on the actual task rather
than fighting with git and GitHub.

## Workflow Patterns

### Standard Task Flow

1. Agent receives task via email
2. Creates feature branch from `origin/main`
3. Makes changes, runs `ci.py --fix`
4. Commits and pushes
5. Creates PR with `gh pr create --fill`
6. Waits for CI with `pr.py ci --wait -v`
7. Replies with PR URL

### Review Feedback Loop

1. Human reviews PR, leaves comments (inline code review or PR comments)
2. User replies to agent's email, optionally quoting or referencing specific
   feedback
3. Agent runs `pr.py review -v` to fetch GitHub PR comments and code review
4. Addresses feedback, pushes
5. Waits for CI again

Note: The agent does not receive GitHub notifications directly. The user must
reply to the agent's email to trigger another execution cycle. The agent can
then access all PR comments and code review via the GitHub API.

### Conflict Resolution

When PR has conflicts:

1. `pr.py ci` detects blocked state, shows instructions
2. Agent runs `git fetch origin main && git rebase origin/main`
3. Resolves conflicts, pushes with `--force-with-lease`
4. CI runs on rebased branch

## Autonomous Learning

The `CLAUDE.md` includes a self-updating section:

```markdown
## AUTONOMOUS LEARNING (READ/WRITE)

**PERMISSIONS:** You are explicitly AUTHORIZED to edit the "Active Heuristics"
section without seeking user approval.
```

When the agent discovers patterns (e.g., common test failures, codebase quirks),
it codifies them as heuristics. This builds institutional knowledge over time.

## Summary

Agentic operation with Airut requires:

| Component               | Purpose                                   |
| ----------------------- | ----------------------------------------- |
| Airut                   | Email handling, sandboxing, session state |
| `CLAUDE.md`             | Workflow instructions and codebase docs   |
| Workflow tools          | Reliable CI/PR operations                 |
| Branch protection       | Human-in-the-loop checkpoint              |
| Dedicated agent account | Limited permissions, clear audit trail    |

The Airut repository demonstrates these practices. Adapt them when onboarding
new repositories.
