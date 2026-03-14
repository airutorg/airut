# Sandboxed CI Migration

Migration plan for running this repository's GitHub Actions CI inside the Airut
sandbox. This locks down the CI escape vector documented in `doc/security.md`
and `spec/sandbox-cli.md`.

## Goal

Run all agent-steerable CI checks inside `airut-sandbox` with:

- Network isolation (allowlist-enforced proxy)
- Container isolation (`--cap-drop=ALL`, `no-new-privileges`)
- Trusted config from the default branch (agent cannot tamper)

After migration, the agent's code runs exclusively inside the sandbox during CI,
closing the "modify code that workflows execute" escape path.

## Current State

Three separate workflow files run CI checks:

| Workflow          | File              | What it runs                                           |
| ----------------- | ----------------- | ------------------------------------------------------ |
| Code Quality      | `code.yml`        | ruff lint, ruff format, ty check, markdown, pytest     |
| Security          | `security.yml`    | license check, vuln scan, proxy vuln scan, drift check |
| Integration Tests | `integration.yml` | pytest integration suite                               |

All three:

- Trigger on `push` to main and `pull_request` to main
- Check out the PR commit (`${{ github.event.pull_request.head.sha }}`)
- Install Python 3.13 via `setup-uv` + `uv sync`
- Execute repo code directly on the runner (unsandboxed)

A fourth workflow (`publish.yml`) handles PyPI publishing on release events and
is out of scope for this migration.

Locally, `scripts/ci.py` already runs the same checks as all three workflows. It
is the intended single source of truth for CI checks, with drift detection tests
verifying that workflow step names match `ci.py` steps.

## Migration Stages

The migration proceeds in four stages. Each stage is a separate PR (except Stage
D which is a manual configuration change). Each stage is independently testable
and reversible.

### Stage A: Consolidate Workflows

**PR scope**: Workflow files, `ci.py` adjustments, test cleanup.

**Goal**: Replace three workflow files with one that calls `ci.py`. This makes
`ci.py` the sole source of truth -- local and GitHub CI run identical checks.

#### Changes

1. **Create `.github/workflows/ci.yml`**:

   ```yaml
   name: CI

   on:
     push:
       branches: [main]
     pull_request:
       branches: [main]

   jobs:
     ci:
       runs-on: ubuntu-latest
       timeout-minutes: 10
       steps:
         - uses: actions/checkout@v4
           with:
             ref: ${{ github.event.pull_request.head.sha || github.sha }}
         - uses: astral-sh/setup-uv@v4
         - run: uv python install 3.13
         - run: uv sync
         - name: CI checks
           run: uv run scripts/ci.py --verbose --timeout 0
   ```

   All checks (code, security, integration) run in a single job. The
   `--timeout 0` disables `ci.py`'s overall timeout (GitHub Actions provides its
   own `timeout-minutes`). `--verbose` shows full output in CI logs.

2. **Delete** `code.yml`, `security.yml`, `integration.yml`.

3. **Remove drift detection tests** from the test suite. With `ci.py` as the
   sole CI entry point, there are no workflow step names to drift against.
   `ci.py` _is_ the source of truth, not a mirror of it.

4. **Update `spec/local-ci-runner.md`** to reflect that `ci.py` is now the
   workflow entry point, not a local replica of separate workflows.

#### What doesn't change

- Checkout model (still checks out PR commit)
- No sandbox involvement
- No security model change
- `publish.yml` unchanged

#### Validation

- Push PR, verify single CI job runs all checks
- Verify local `uv run scripts/ci.py` produces identical results
- Verify `uv run scripts/ci.py --workflow code` still works for selective runs

### Stage B: Wrap with `airut-sandbox`

**PR scope**: `sandbox.yaml`, wrapper script, workflow modification.

**Goal**: Run `ci.py` inside the sandbox. Still checks out the PR commit on the
host (same trust model as Stage A). The purpose is validating that sandbox
infrastructure works in CI, not security lockdown.

#### Changes

1. **Create `.airut/sandbox.yaml`**:

   ```yaml
   # Sandbox configuration for CI.
   #
   # Used by airut-sandbox to run CI checks inside a container with
   # network isolation and container isolation.

   env:
     CI: "true"
     PYTHONDONTWRITEBYTECODE: "1"

   network_sandbox: true
   ```

   No `masked_secrets` or `pass_env` -- `ci.py` does not require GitHub access
   or any other credentials. All linters run locally, tests mock all external
   calls (`pytest-socket` blocks real network), and `uv-secure` queries
   vulnerability databases over HTTP through the proxy (PyPI hosts are on the
   allowlist).

   No `resource_limits` -- GitHub Actions enforces its own job-level resource
   limits (`timeout-minutes` in the workflow, runner memory/CPU). Adding
   container-level limits would duplicate these and risk false failures.

   Uses the existing `.airut/network-allowlist.yaml` (shared with the gateway)
   and `.airut/container/Dockerfile` (shared with the gateway).

2. **Create `scripts/sandbox-ci.sh`** (wrapper script):

   ```bash
   #!/usr/bin/env bash
   # Wrapper script for running CI inside the Airut sandbox.
   # Runs inside the container with /workspace mounted from the host.
   #
   # Usage: sandbox-ci.sh <commit-sha>
   #
   # The host checks out the default branch. This script fetches and
   # checks out the PR commit inside the container, then runs ci.py.

   set -euo pipefail

   COMMIT_SHA="${1:?Usage: sandbox-ci.sh <commit-sha>}"

   # Fetch and check out the PR commit
   git fetch origin "$COMMIT_SHA"
   git checkout "$COMMIT_SHA"

   # Install dependencies and run CI
   uv sync
   uv run scripts/ci.py --verbose --timeout 0
   ```

3. **Modify `.github/workflows/ci.yml`**:

   ```yaml
   name: CI

   on:
     push:
       branches: [main]
     pull_request:
       branches: [main]

   jobs:
     ci:
       runs-on: ubuntu-latest
       timeout-minutes: 15
       steps:
         - uses: actions/checkout@v4
           with:
             ref: ${{ github.event.pull_request.head.sha || github.sha }}
         - uses: astral-sh/setup-uv@v4
         - run: uv python install 3.13
         - run: uv sync
         - name: CI checks
           run: >-
             uv run airut-sandbox run --verbose --
             scripts/sandbox-ci.sh "$COMMIT_SHA"
           env:
             COMMIT_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
   ```

   The SHA is passed via an `env:` variable rather than inline `${{ }}`
   interpolation in the `run:` script to prevent expression injection (see
   `spec/sandbox-cli.md` residual attack surface table). No secrets are passed
   -- `ci.py` does not require GitHub access or any other credentials.

   The workflow still checks out the PR commit on the host. `airut-sandbox` and
   `.airut/` config come from the PR branch (not yet trusted -- that is Stage
   C). The `timeout-minutes` is increased to account for container image build
   overhead on first run.

#### Security posture

Partial. The sandbox contains execution (network isolation, container
isolation), but since the host has the PR checkout, a malicious PR could tamper
with `airut-sandbox` itself or `.airut/` config. The `workflow` PAT scope
restriction (Stage D) remains the primary security control at this point.

#### Validation

- Push PR, verify CI runs inside sandbox (look for sandbox startup/shutdown
  logs)
- Verify network isolation works (blocked requests visible in CI output)
- Verify `ci.py` checks all pass inside the container

### Stage C: Default-Branch Checkout

**PR scope**: Workflow checkout change, wrapper script update.

**Goal**: Implement the full default-branch trust model from
`spec/sandbox-cli.md`. After this stage, `airut-sandbox`, `.airut/sandbox.yaml`,
`.airut/network-allowlist.yaml`, and `.airut/container/Dockerfile` all come from
the trusted default branch. Only agent-steered code (the PR diff) runs inside
the sandbox.

#### Changes

1. **Modify `.github/workflows/ci.yml` checkout**:

   ```yaml
   - uses: actions/checkout@v4
     with:
       ref: ${{ github.event.repository.default_branch }}
       fetch-depth: 0
   ```

   This always checks out the repository's default branch (main). Two controls
   work together to ensure trusted config:

   - **Branch filter** (`pull_request: branches: [main]`): The workflow only
     triggers on PRs targeting main. A PR targeting a non-protected branch does
     not trigger CI at all.
   - **`repository.default_branch`**: Even within the triggered workflow, the
     checkout explicitly uses the repository's default branch rather than
     `pull_request.base.ref`. This is defense-in-depth -- `base.ref` reflects
     the PR's target branch, which the agent controls. If the branch filter were
     ever loosened, `repository.default_branch` still ensures trusted config.

   Using `base.ref` alone would be vulnerable: if the branch filter were changed
   to `branches: ['**']` or removed, the agent could create a PR targeting a
   non-protected branch containing malicious `.airut/` config.

   `fetch-depth: 0` ensures full history is available for the wrapper script to
   fetch the PR commit inside the container.

2. **The wrapper script (`scripts/sandbox-ci.sh`)** already handles fetching and
   checking out the PR commit inside the container. No changes needed -- the
   script was designed for this from Stage B.

3. **Update `spec/sandbox-cli.md`**: Replace the "CI Integration Patterns
   (Future Work)" section with a reference to this spec and the actual workflow
   implementation.

4. **Update `doc/security.md`**: Update the "GitHub Actions Workflow Escape"
   section to document that CI now runs inside the sandbox with default-branch
   checkout, closing escape path 2. Update the attack surface table.

#### Security posture

The default-branch trust model is now active:

- `airut-sandbox` comes from main (agent cannot tamper with sandbox code)
- `.airut/sandbox.yaml` comes from main (agent cannot modify credential config)
- `.airut/network-allowlist.yaml` comes from main (agent cannot widen network
  access)
- `.airut/container/Dockerfile` comes from main (agent cannot modify container
  image)
- Only the PR code runs inside the sandbox (intended behavior)

Escape path 2 ("modify code that workflows execute") is now closed by the
sandbox. Escape path 1 ("modify workflow files directly") is still open if the
PAT has the `workflow` scope -- Stage D closes this.

#### Validation

- Push PR, verify workflow checks out main on host (not PR commit)
- Verify `airut-sandbox` and `.airut/` come from main
- Verify PR code is fetched and tested inside the container
- Verify a PR that modifies `.airut/sandbox.yaml` does _not_ affect the running
  sandbox config (the host has main's version)

### Stage D: Remove `workflow` PAT Scope

**Scope**: Manual configuration change (no code PR).

**Goal**: Close escape path 1 (direct workflow file modification by the agent).

#### Steps

1. Audit the `GH_TOKEN` PAT used by the agent:

   - **Classic PAT**: Ensure the `workflow` scope checkbox is unchecked. Grant
     only `repo` scope.
   - **Fine-grained PAT**: Grant `Contents: Read and write` for push access. Do
     **not** grant `Workflows: Read and write`.

2. Test that the agent can still:

   - Push branches
   - Create PRs
   - Run `gh` CLI commands (pr create, pr view, etc.)

3. Test that the agent **cannot**:

   - Push commits that modify `.github/workflows/` (GitHub rejects the push)

#### Security posture

Fully locked down:

- **Path 1** (modify workflow files): Blocked by PAT scope restriction. GitHub
  rejects pushes that include changes to `.github/workflows/`.
- **Path 2** (modify code that workflows execute): Blocked by sandbox +
  default-branch checkout. Agent-steered code runs inside the container with
  network isolation and container isolation.

## Dependency Chain

```
Stage A ─── Stage B ─── Stage C ─── Stage D
(consolidate) (sandbox)   (trust)     (PAT)
```

Each stage depends on the previous one being merged and validated. Stage D
depends on Stage C because removing the `workflow` scope without the
default-branch checkout would leave path 2 open (the existing mitigation of
`workflow_dispatch` triggers is no longer in place after Stage A consolidates
workflows with `pull_request` triggers).

## Push-to-Main Behavior

On `push` to main (after PR merge), the workflow runs with `github.sha` pointing
to the merge commit on main. The checkout ref resolves to main itself. The
wrapper script checks out the same SHA that is already on the host. This is a
no-op checkout but is harmless -- the script runs `ci.py` on the merged code,
which is the intended behavior for post-merge validation.

## What This Does Not Cover

- **Fork PRs**: Fork PR security is a GitHub Actions concern
  (`pull_request_target` vs `pull_request` trigger selection). Fork PRs do not
  have access to repository secrets by default.
- **`publish.yml`**: Release publishing triggers on `release: [published]`
  events. The agent cannot create releases or tags (these require permissions
  the agent's PAT does not have), so a human must create the release through the
  GitHub UI. This provides human review before the workflow executes. The
  workflow itself runs only fixed actions (`uv build` + PyPI trusted publisher),
  not arbitrary agent-steerable code.
- **Self-hosted runners**: This migration targets `ubuntu-latest`. Self-hosted
  runner setup (podman, cgroup v2 delegation) is a deployment concern.
- **Non-GitHub CI**: This spec is GitHub Actions-specific. The security model
  section of `spec/sandbox-cli.md` covers platform-agnostic considerations.
