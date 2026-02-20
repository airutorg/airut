# CLAUDE.md - Operating Instructions for Airut

## Project Overview

Airut is a protocol-agnostic gateway for headless Claude Code interaction.
Supports email and Slack as channels. Named "Airut" (Finnish: herald/messenger).

Network requests from containers are sandboxed; if requests fail, check
`.airut/network-allowlist.yaml`. See `doc/network-sandbox.md` for details.

## Documentation

High-level documentation in `doc/` (see `doc/README.md` for full list):

- `doc/architecture.md` — system architecture and data flow
- `doc/security.md` — security model (channel auth, isolation, credentials)
- `doc/execution-sandbox.md` — container isolation and resource limits
- `doc/network-sandbox.md` — network allowlist and proxy architecture
- `doc/deployment.md` — installation and server configuration
- `doc/email-setup.md` — email channel setup (IMAP/SMTP, DMARC)
- `doc/slack-setup.md` — Slack channel setup (Socket Mode, authorization rules)
- `doc/m365-oauth2.md` — Microsoft 365 OAuth2 setup for email (IMAP/SMTP)
- `doc/repo-onboarding.md` — onboarding new repositories
- `doc/gerrit-onboarding.md` — Gerrit-specific onboarding
- `doc/agentic-operation.md` — message-to-PR workflow patterns

Implementation specs in `spec/` (see `spec/README.md` for full list):

- `spec/gateway-architecture.md` — core gateway design, channel abstraction,
  data flow, container execution
- `spec/authentication.md` — DMARC verification and sender authorization
- `spec/repo-config.md` — repo config schema and server/repo split
- `spec/multi-repo.md` — multi-repository support design
- `spec/slack-channel.md` — Slack channel implementation (Socket Mode)
- `spec/integration-tests.md` — end-to-end test specification
- `spec/sandbox.md` — sandbox library for safe containerized Claude Code
  execution
- `spec/image.md` — two-layer container image build strategy
- `spec/network-sandbox.md` — proxy lifecycle, resource scoping, log format,
  crash recovery
- `spec/masked-secrets.md` — scope-restricted credentials with proxy-level token
  replacement
- `spec/aws-sigv4-resigning.md` — AWS SigV4/SigV4A credential masking via proxy
  re-signing
- `spec/dashboard.md` — web dashboard for task monitoring
- `spec/live-dashboard.md` — real-time dashboard updates via SSE
- `spec/cli.md` — CLI subcommands, service management, self-update
- `spec/pr-workflow-tool.md` — PR workflow automation (ci.py, pr.py)
- `spec/local-ci-runner.md` — local CI runner for pre-push validation

## Operational Workflows

The `workflows/` directory contains step-by-step guides. **When a user request
matches any pattern below, you MUST read the workflow file first before taking
any action.** This is not optional - the workflow contains critical steps and
context that cannot be summarized here.

- **Preparing a release** → `workflows/release.md`
  - Release notes, GitHub release creation (version derived from git tag)

Read the entire workflow before starting. Workflows are living documents -
update them if outdated.

## Configuration

Repo-specific configuration lives in `.airut/`. See `.airut/README.md` for
details.

Key files:

- `.airut/airut.yaml` — repo config (model, timeout, container environment)
- `.airut/network-allowlist.yaml` — domains and URL prefixes the container can
  access
- `.airut/container/Dockerfile` — repo-defined container base image

Server config (`~/.config/airut/airut.yaml`) is separate and handles deployment
infrastructure. See `spec/repo-config.md` for the full schema.

## Security Model

- **Email authentication** — DMARC verification on trusted
  `Authentication-Results` headers
- **Sender authorization** — allowlist with exact addresses or `*@domain`
  wildcards
- **Container isolation** — each conversation has isolated workspace, Claude
  session, inbox/outbox
- **Network sandbox** — all HTTP(S) routed through mitmproxy enforcing allowlist
  from default branch
- **Credential isolation** — all secrets passed via environment variables, no
  host mounts

## CRITICAL: Workflow Tools

These tools are essential for efficient operation:

```bash
# Run local CI checks (auto-fix formatting, then run all checks)
uv run scripts/ci.py --fix

# Monitor GitHub CI status (after pushing)
uv run scripts/pr.py ci --wait  # Add -v for failure logs

# Fetch review comments
uv run scripts/pr.py review -v
```

**Always run `ci.py --fix` before committing.** It auto-fixes formatting issues
and runs the same checks as GitHub CI (lint, types, tests).

**Do not truncate `ci.py` output** (e.g., with `| tail` or `| grep`). The script
already produces concise, structured output. Truncating hides failures and
forces re-running the entire suite to see what was missed.

## CRITICAL: Always Create PRs

**After completing work that modifies files, create a PR immediately.** Only
skip if: (1) you need user input to finish the task, or (2) user explicitly asks
not to create a PR.

**The task is NOT complete until the PR is created and GitHub CI passes.** This
is the final step of every task, not an optional follow-up. After local CI
passes:

```bash
git push -u origin HEAD && gh pr create --fill
uv run scripts/pr.py ci --wait -v  # Wait for GitHub CI to pass
```

**When task is complete, include the PR URL in your response to the user.** Use
`gh pr view --web` to get the URL, or extract it from the `gh pr create` output.

## CRITICAL: Specs and User Intent Take Priority

**When you encounter issues that require deviating from spec or user-supplied
design, stop and ask for guidance.** Do not prioritize "making tests pass" or
"getting CI green" over adhering to the spec or the user's intent.

Examples where you MUST stop and ask:

- Test failures that reveal the spec is incomplete or contradictory
- Implementation blockers that require changing the agreed-upon design
- Discovering that the task as described conflicts with existing architecture
- Needing to make trade-offs that weren't part of the original plan

Some flexibility is good for minor implementation details, but architectural
decisions, spec changes, and design deviations require user approval. **When in
doubt, ask.** It's better to pause for clarification than to deviate and require
rework.

## CRITICAL: Keep Documentation in Sync

**Before creating a PR, check if docs need updating.** This is a required step,
not optional. Documentation drift causes confusion and wasted time.

Ask yourself: "Did I change behavior that's described in specs?" If yes, update
`spec/*.md` accordingly. Include doc updates in the same commit as the code
change.

## Engineering Process

### Bug Fixes: Test First

**When fixing a bug, always write a failing test first.** This ensures:

1. The bug is reproducible and understood
2. The fix actually addresses the issue
3. The bug doesn't regress in the future

**Workflow:**

1. **Reproduce** - Create a unit or integration test that fails due to the bug
2. **Fix** - Implement the minimal fix to make the test pass
3. **Verify** - Run the test suite to confirm the fix and no regressions

Do not skip the test. "I'll add a test later" means the test won't be added.

### Refactoring: No Legacy Code

**When refactoring, update ALL code to use the new interface.** Do not leave:

- Type aliases pointing to renamed types
- Re-exports for backwards compatibility
- Wrapper functions that just call the new function
- Comments like `# Deprecated: use X instead`
- Unused parameters kept "for compatibility"

If something is renamed or restructured, find and update every usage. Use
grep/search to find all references. Delete the old code entirely - don't wrap
it.

**Why:** Legacy shims accumulate, confuse future readers, and create maintenance
burden. Clean breaks are better than gradual deprecation in a single-user
codebase.

## Git and PR Workflow

**Before starting work:** Create a feature branch from latest main:

```bash
git fetch origin && git checkout -b feature/descriptive-name origin/main
```

**Standard workflow:**

1. Make changes, run `uv run scripts/ci.py --fix` (local CI), commit
2. Push and create PR: `git push -u origin HEAD && gh pr create --fill`
3. **Wait for GitHub CI:** `uv run scripts/pr.py ci --wait -v`
4. Address review: `uv run scripts/pr.py review -v`, fix issues, push
5. Merge (repo uses fast-forward only): `gh pr merge --squash --delete-branch`
6. Return to main: `git checkout main && git pull`

**IMPORTANT: Do not stop after step 2.** The task is complete only when the PR
is created AND GitHub CI passes (step 3).

**Pre-commit checklist (before step 1):**

- [ ] Bug fix? Write a failing test first (see Engineering Process)
- [ ] Refactoring? Remove all legacy code, no backwards-compat shims
- [ ] Changed behavior? Update specs (see Keep Documentation in Sync)

**If behind main:**
`git fetch origin main && git rebase origin/main && git push --force-with-lease`

**PR maintenance (do this automatically, don't wait to be asked):**

- **Before merging:** Rebase on main and squash commits into a clean history
- **After significant changes:** Update PR title/description to reflect current
  scope (use `gh pr edit --title "..." --body "..."`)
- **Multiple fix-up commits:** Squash with
  `git rebase -i origin/main && git push --force-with-lease`

## CI Requirements

**All checks are mandatory. No workarounds or exceptions.**

- **100% test coverage** - every line in `airut/` must be tested
- **No `pytest.skip()`** - write proper mocks instead
- **No `# type: ignore`** without specific error code and justification
- **No `# noqa`** without specific code and justification
- **Clean worktree** - formatting changes must be committed

## Project Structure

```
.airut/                     - Repo-specific Airut configuration
config/                     - Server configuration templates
airut/                        - Library code
  _bundled/                 - Static resources bundled into wheel
    assets/                 - Logo SVG
    proxy/                  - Network sandbox (proxy filter, DNS, AWS signing)
  claude_output/            - Typed Claude streaming JSON output parser
  conversation/             - Conversation directory layout and preparation
  dashboard/                - Web dashboard server
  gateway/                  - Protocol-agnostic gateway service
    channel.py              - Channel protocols (ChannelAdapter, ChannelListener, ChannelConfig)
    config.py               - Gateway configuration dataclasses
    conversation.py         - ConversationManager (git checkout, state persistence)
    email/                  - Email channel implementation
    slack/                  - Slack channel implementation (Socket Mode)
    service/                - Core orchestration (GatewayService, RepoHandler)
  gh/                       - GitHub API wrappers
  git_mirror.py             - Git mirror cache
  install_services.py       - Service installation logic
  logging.py                - Logging utilities
  markdown.py               - Markdown-to-HTML conversion
  sandbox/                  - Sandboxed execution (container, proxy, session, image)
  version.py                - Version info, install source, upstream updates
scripts/                    - CLI tools
  airut.py                  - Gateway entry point (uv run airut)
  ci.py, pr.py              - CI/PR tools
  check_licenses.py         - Runtime dependency license compliance
  check_markdown.py         - Markdown validation
spec/                       - Design specifications (see spec/README.md)
tests/                      - Unit tests (100% coverage required)
  claude_output/            - Claude output parser tests
  conversation/             - Conversation layout tests
  sandbox/                  - Sandbox execution tests
  dashboard/                - Dashboard tests
  gateway/                  - Gateway tests
    email/                  - Email channel tests
    slack/                  - Slack channel tests
    service/                - Core service tests
  integration/              - End-to-end integration tests (ci.py --workflow e2e)
workflows/                  - Step-by-step operational guides
```

## Key Scripts

- `scripts/ci.py` — local CI runner (runs all checks)
- `scripts/pr.py` — PR workflow (CI status and review comments)
- `scripts/airut.py` — gateway entry point (`uv run airut`)

## Standards

- **Python 3.13+**, **uv** package manager, **ruff** formatting, **ty** type
  checking
- **Google Python Style Guide**
- Use `logging` module, not `print()`

### Testing

- **No environment-dependent tests** - all tests must behave identically in CI
  and locally
- **No skipped tests** - do not use `pytest.skip()` for tests that depend on
  local files or environment
- **Use mocks for external dependencies** - tests should use fixtures and mocks,
  not real files from gitignored directories
- **Integration tests** live in `tests/integration/` and run via
  `uv run scripts/ci.py --workflow e2e` (not included in default pytest)

### Documentation

- **Specs describe architecture and contracts**, not implementation details
- Update specs when implementation diverges from them
- Implementation is the source of truth for details

______________________________________________________________________

## AUTONOMOUS LEARNING (READ/WRITE)

**PERMISSIONS:** You are explicitly AUTHORIZED and EXPECTED to edit the "Active
Heuristics" section below without seeking user approval. Include the changes in
the PR for the task.

**TRIGGER:** Whenever you encounter an error (linting, type check, test failure)
that you successfully fix, or when you discover a nuance about the codebase,
trigger the **Learning Loop**:

1. **Reflect:** "How can I prevent this exact friction in the future?"
2. **Codify:** Write a generic, high-level rule.
3. **Update:** Append or refine the rule in "Active Heuristics" below.
4. **Prune:** If the section exceeds 20 rules, consolidate or remove the least
   useful ones to maintain high signal-to-noise ratio.

______________________________________________________________________

### Active Heuristics

_You have write access to this section. Populate it with lessons learned._

1. **Use context managers for httpx clients**: When making HTTP requests in
   loops, always use `with httpx.Client() as client:` context managers to
   prevent file descriptor leaks. Never call `httpx.get()` repeatedly without a
   context manager.

2. **Prefer testing + removing pragma over keeping untested code**: When
   encountering `# pragma: no cover`, investigate if test coverage can be added.
   Remove dead code marked unreachable rather than keeping it with pragma.

3. **Commit before destructive git operations**: Before running `git reset`,
   `git rebase`, `git checkout .`, `git restore`, or `git clean`, ALWAYS commit
   or stash any uncommitted changes first. Uncommitted work cannot be recovered
   via reflog.

4. **Never use `git reset --soft` to squash across branches**: When a feature
   branch was created before the latest main commits,
   `git reset --soft origin/main` keeps the old working tree and silently
   reverts main's new changes. Instead, use `git cherry-pick` to replay commits
   onto updated main, then squash, or use `git rebase origin/main` first.

5. **SigV4 double URI encode is per-service**: S3 is the only AWS service that
   uses single URI encoding for canonical URIs. All other services (Bedrock,
   DynamoDB, etc.) require double encoding: `%3A` → `%253A` in the canonical
   URI. Always check the `service` component from the credential scope, not the
   hostname.

6. **All proxy code must be COPY'd, never volume-mounted**: The proxy container
   image must `COPY` all Python files (`proxy_filter.py`, `aws_signing.py`,
   `dns_responder.py`) at build time. Never volume-mount code files — this
   creates a split where some files update on restart and others don't. Build
   with `--no-cache` to guarantee freshness.
