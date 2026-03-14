# Sandbox Action

GitHub Action (`airutorg/sandbox-action`) that runs CI commands inside a
sandboxed container with network restrictions and credential isolation. Designed
for repositories where PRs may come from untrusted sources, such as a coding
agent.

Standard GitHub Actions runners give workflow steps full outbound network access
and expose repository secrets as environment variables. A malicious PR that
modifies test scripts or build steps can exfiltrate secrets. Sandbox Action
prevents this by restricting network access to an allowlist, masking credentials
with surrogate values that the proxy swaps only on matching outbound requests,
and isolating execution in a hardened container.

## Motivation

The `airut-sandbox` CLI (documented in `spec/sandbox-cli.md`) provides the
container isolation, network allowlisting, and credential masking. But
integrating it into a GitHub Actions workflow requires several boilerplate steps
with security-critical details (checkout ref, SHA passthrough via env vars,
fetch-depth). A single `uses:` step eliminates this duplication and ensures the
security invariants are maintained by the action itself.

## Consumer Interface

### Minimal Usage

```yaml
# .github/workflows/ci.yml
name: CI
on:
  pull_request:
    branches: [main]  # MUST target only protected branches

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # This must be the ONLY step -- nothing after it
      - uses: airutorg/sandbox-action@v0
        with:
          command: 'uv sync && uv run pytest'
          pr_sha: ${{ github.event.pull_request.head.sha }}
```

### Full Options

```yaml
- uses: airutorg/sandbox-action@v0
  with:
    command: 'uv sync && uv run scripts/ci.py --verbose --timeout 0'
    pr_sha: ${{ github.event.pull_request.head.sha || github.sha }}
    merge: 'true'               # optional: merge PR into base (default)
    airut_version: '0.15.0'     # optional: override installed version
    sandbox_args: '--verbose'   # optional: extra airut-sandbox flags
  env:
    GH_TOKEN: ${{ secrets.GH_TOKEN }}  # available for masked_secrets in sandbox.yaml
```

### Inputs

| Input           | Required | Default        | Description                                                               |
| --------------- | -------- | -------------- | ------------------------------------------------------------------------- |
| `command`       | Yes      |                | CI command to run inside the sandbox (after PR checkout)                  |
| `pr_sha`        | Yes      |                | PR commit SHA to check out and test                                       |
| `merge`         | No       | `true`         | Merge PR into base branch before running (like GitHub's default behavior) |
| `airut_version` | No       | from `VERSION` | Airut version to install. PyPI version or `main` for GitHub HEAD.         |
| `sandbox_args`  | No       | `--verbose`    | Additional arguments passed to `airut-sandbox run`.                       |

When `merge` is `true` (the default), the container starts on the base branch
and runs `git merge --no-edit <sha>` to create a temporary merge commit. This
matches GitHub Actions' default `pull_request` checkout behavior and tests the
code as it would exist after merging. Set to `false` to check out the PR commit
directly instead.

### Consumer Prerequisites

The consuming repository must have:

- `.airut/container/Dockerfile` -- container image definition (Python, uv,
  tools)
- `.airut/sandbox.yaml` (optional) -- env vars, masked secrets, resource limits
- `.airut/network-allowlist.yaml` (optional) -- only needed if
  `network_sandbox: true` in sandbox.yaml

**Important**: The network allowlist does **not** need to include the
repository's own GitHub URL. The action fetches the PR SHA on the host before
entering the sandbox, so git operations inside the container work from local
`.git` objects without network access.

## Security Model

The base branch is trusted. Sandbox configuration (Dockerfile, network
allowlist, masked secret definitions, resource limits) is loaded from the base
branch checkout on the host. The PR is untrusted -- it runs inside the sandbox
where network access is restricted and credentials are masked.

### Required External Controls

The action cannot enforce these -- the repository operator must configure them:

1. **Workflow files must be immutable to the PR author.** The push token must
   lack the `workflow` scope, or a repository ruleset must block changes to
   `.github/workflows/`. Without this, the PR author can push a workflow that
   bypasses the sandbox entirely.

2. **The base branch must be protected, and the workflow must only trigger on
   PRs targeting protected branches.** The action checks out
   `github.event.pull_request.base.ref` and loads `.airut/` configuration from
   it. If the workflow triggers on PRs to unprotected branches, the PR author
   can push malicious `.airut/` config to the base branch before the workflow
   runs.

### Tainted Workspace

**After sandbox execution, the workspace is tainted and must not be used.**

The sandbox mounts the workspace read-write. The sandboxed code (which is
untrusted -- it comes from the PR) has full write access to the workspace,
including the `.git/` directory. A malicious PR could:

- Install git hooks (`.git/hooks/pre-commit`, `.git/hooks/post-checkout`, etc.)
  that execute arbitrary code when any git command runs.
- Modify `.git/config` to alias git commands or add credential helpers.
- Replace binaries or scripts in the workspace.
- Plant files that a subsequent step might source or execute.

**The sandbox action must be the final step of the job.** No workflow steps
should run after it -- not git operations, not artifact uploads from the
workspace, not cleanup scripts. Any post-sandbox step that touches the workspace
or runs git commands risks executing attacker-controlled code outside the
sandbox.

If post-sandbox operations are needed (e.g., uploading test artifacts), they
must run in a separate job that does not share the tainted workspace, or use
outputs/artifacts produced by the sandbox step itself through a safe channel.

### Fail-Secure

If any step fails (uv not installable, airut-sandbox build error, container
runtime missing, fetch fails), the workflow step exits non-zero. No fallback to
unsandboxed execution.

## Action Implementation

### Repository Structure

```
airutorg/sandbox-action/
├── action.yml    # Composite action definition
├── VERSION       # Airut version to install (e.g., "main" or "0.15.0")
├── README.md     # Consumer documentation
└── LICENSE
```

### `action.yml`

```yaml
name: 'Airut Sandbox'
description: >-
  Run CI commands inside a sandboxed container with network restrictions
  and credential isolation. Loads sandbox configuration from the trusted
  base branch; PR code runs only inside the container.

inputs:
  command:
    description: 'CI command to run inside the sandbox (after PR checkout)'
    required: true
  pr_sha:
    description: 'PR commit SHA to check out and test'
    required: true
  merge:
    description: >-
      Merge PR into base branch before running (like GitHub default).
      Set to "false" to check out the PR commit directly.
    required: false
    default: 'true'
  airut_version:
    description: >-
      Airut version to install. PyPI version (e.g., "0.15.0") or "main"
      for latest from GitHub. Empty = use version bundled with action.
    required: false
    default: ''
  sandbox_args:
    description: 'Additional arguments for airut-sandbox run'
    required: false
    default: '--verbose'

runs:
  using: "composite"
  steps:
    # --- Host-side setup (trusted) ---

    - name: Install uv
      uses: astral-sh/setup-uv@v4

    - name: Install Python
      shell: bash
      run: uv python install 3.13

    - name: Install airut-sandbox
      shell: bash
      env:
        INPUT_VERSION: ${{ inputs.airut_version }}
        ACTION_PATH: ${{ github.action_path }}
      run: |
        VERSION="$INPUT_VERSION"
        if [ -z "$VERSION" ]; then
          VERSION=$(cat "$ACTION_PATH/VERSION")
        fi
        if [ "$VERSION" = "main" ]; then
          uv tool install \
            "airut @ git+https://github.com/airutorg/airut@main"
        else
          uv tool install "airut==$VERSION"
        fi

    # --- Base-branch checkout (trusted config) ---
    # Uses base.ref for PRs, ref_name for push events.
    # Security: the workflow MUST trigger only on PRs targeting protected
    # branches. See README for required security controls.

    - name: Checkout trusted base branch
      uses: actions/checkout@v4
      with:
        ref: ${{ github.event.pull_request.base.ref || github.ref_name }}
        fetch-depth: 0

    # --- Fetch PR SHA on host ---
    # Objects are stored in .git/ which is mounted into the container.
    # This avoids needing GitHub credentials inside the sandbox.

    - name: Fetch PR commit
      shell: bash
      env:
        TARGET_SHA: ${{ inputs.pr_sha }}
      run: git fetch origin "$TARGET_SHA"

    # --- Run sandboxed command ---

    - name: Run sandboxed command
      shell: bash
      env:
        SANDBOX_PR_SHA: ${{ inputs.pr_sha }}
        SANDBOX_COMMAND: ${{ inputs.command }}
        SANDBOX_ARGS: ${{ inputs.sandbox_args }}
        SANDBOX_MERGE: ${{ inputs.merge }}
      run: |
        if [ "$SANDBOX_MERGE" = "true" ]; then
          GIT_CMD='git merge --no-edit "$1"'
        else
          GIT_CMD='git checkout "$1"'
        fi
        # shellcheck disable=SC2086
        airut-sandbox run $SANDBOX_ARGS -- \
          bash -c "$GIT_CMD"' && eval "$2"' \
          _ "$SANDBOX_PR_SHA" "$SANDBOX_COMMAND"
```

**Step ordering rationale:**

1. Install uv and Python first (needed to install airut-sandbox).
2. Install airut-sandbox before checkout -- if installation fails, no point
   checking out the repo.
3. Checkout the base branch -- establishes the trusted `.airut/` config.
4. Fetch the PR SHA on the host -- stores the PR commit objects in `.git/`.
5. Run sandboxed command -- shell expands env vars to literal arguments. The
   merge/checkout and command run inline via `bash -c`, avoiding any file
   written to the workspace.

**Base branch checkout**: The action checks out
`github.event.pull_request.base.ref` for pull request events, or
`github.ref_name` for push events. For PRs, this is the branch the PR targets.
Security relies on the workflow triggering only on PRs to protected branches
(see Required External Controls).

**Inline command pattern**: The sandbox runs
`bash -c 'git merge --no-edit "$1" && eval "$2"' _ <sha> <command>` (or
`git checkout` when merge is false). The `_` is the `$0` placeholder for
`bash -c`. The SHA and command are passed as positional arguments `$1` and `$2`,
safely quoted. This avoids writing an entrypoint script to the workspace, which
would pollute it and break worktree-clean checks.

**Merge mode**: When `merge` is `true` (default), the container starts on the
base branch and merges the PR commit. This matches GitHub Actions' default
`pull_request` behavior where the checkout ref is a temporary merge commit. When
`false`, the container checks out the PR commit directly.

### `VERSION` File

Contains a single line: either a PyPI version string or `main`.

- On the `main` branch: `main` (always install from GitHub HEAD).
- On release tags: the matching version (e.g., `0.15.0`).

## Versioning

Action versions mirror airut releases:

| Action ref | VERSION file contents | airut-sandbox source   | Use case                         |
| ---------- | --------------------- | ---------------------- | -------------------------------- |
| `@main`    | `main`                | `git+.../airut@main`   | Development, airut repo's own CI |
| `@v0`      | latest 0.x.y          | PyPI `airut==<latest>` | Stable, auto-updates with minor  |
| `@v0.15.0` | `0.15.0`              | PyPI `airut==0.15.0`   | Pinned to exact version          |

### Release Process

When a new airut version is released (e.g., `v0.16.0`):

1. In the `sandbox-action` repo, update the `VERSION` file to `0.16.0`.
2. Update `action.yml` if the new airut version requires changes.
3. Commit, tag `v0.16.0`, and move the `v0` tag:
   ```bash
   git add VERSION
   git commit -m "Release v0.16.0"
   git tag v0.16.0
   git tag -f v0
   git push origin main v0.16.0
   git push -f origin v0
   ```

The `v0` tag always points to the latest `v0.x.y` release. Consumers using `@v0`
automatically pick up minor and patch releases.

## Migration: Airut Repo

After the action is published, the airut repo's CI workflow simplifies to:

```yaml
steps:
  - uses: airutorg/sandbox-action@main
    with:
      command: 'uv sync && uv run scripts/ci.py --verbose --timeout 0'
      pr_sha: ${{ github.event.pull_request.head.sha || github.sha }}
```

The airut repo uses `@main` (not `@v0`) because:

- `airut-sandbox` is part of the airut repo itself. The `@main` reference
  installs from the airut GitHub repo's main branch, which is the same trusted
  code that the current workflow runs via `uv sync`.
- This avoids a circular dependency: the action installing airut from PyPI would
  mean CI depends on a published release, but releases depend on CI passing.

## Execution Flow

```
GitHub Actions Runner (ubuntu-latest)
  |
  +-- Install uv, Python 3.13
  +-- Install airut-sandbox (from PyPI or GitHub, based on VERSION)
  |
  +-- actions/checkout (base branch, fetch-depth: 0)
  |     -> .airut/sandbox.yaml, .airut/container/Dockerfile,
  |        .airut/network-allowlist.yaml all from trusted branch
  |
  +-- git fetch origin <PR SHA>
  |     -> PR commit objects stored in .git/ (host-side)
  |
  +-- airut-sandbox run --verbose -- bash -c 'git merge ... && eval ...'
       |
       +-- Load .airut/ config (trusted, from base branch)
       +-- Build/reuse container image (Dockerfile from base branch)
       +-- Start sandbox (container + network proxy + credential masking)
       |
       +-- Inside container:
       |    +-- git merge <SHA> (or git checkout, based on merge input)
       |    +-- eval <command> (e.g., "uv sync && uv run pytest")
       |
       +-- Exit with command's exit code
       |
  (workspace is now tainted -- no further steps allowed)
```

## Runner Requirements

- **Container runtime**: podman (default) or docker. GitHub-hosted
  `ubuntu-latest` runners include podman. Self-hosted runners must have podman
  or docker installed.
- **Disk space**: Space for the container image build. The base image
  (`.airut/container/Dockerfile`) and dependencies determine the size.
- **Network**: The host needs internet access for `actions/checkout`,
  `uv tool install`, and image builds. The container's network access is
  controlled by the network sandbox.

## Initialization

The `airutorg/sandbox-action` repository contains the action files. To
bootstrap:

1. Create the files listed in Repository Structure above.
2. Set `VERSION` to `main` on the main branch.
3. No CI workflow is needed in the action repo itself -- the action is tested by
   its consumers (including the airut repo).
4. Once the airut repo's CI is migrated to use `sandbox-action@main` and CI
   passes, the action is validated.
5. After the next airut release to PyPI, create the first versioned tag (e.g.,
   `v0.15.0`) with `VERSION` set to `0.15.0`, and create the `v0` tag pointing
   to the same commit.

## Design Decisions

### Host-Side SHA Fetch

The action fetches the PR SHA on the host (`git fetch origin $SHA`) rather than
inside the container:

- **No GitHub credentials in sandbox**: The container does not need a GH_TOKEN
  for git fetch. Credentials are only needed if the CI command itself makes
  GitHub API calls (via masked secrets in sandbox.yaml).
- **Private repo support**: The host runner has implicit repo access via
  `actions/checkout`'s GITHUB_TOKEN. No network allowlist entry needed.

### Inline Command (No Entrypoint File)

The sandbox command is passed inline via `bash -c` rather than a separate
entrypoint script. This avoids writing any files to the workspace before sandbox
execution, which would break worktree-clean checks and require cleanup (which
cannot safely run post-sandbox due to workspace tainting).

### `eval` for Command Execution

The inline command uses `eval "$2"` to execute the command string. This supports
multi-line commands naturally:

```yaml
command: |
  uv sync
  uv run pytest
  uv run ruff check
```

`eval` is safe because the command value comes from the workflow YAML, which is
protected by the workflow file restriction. The sandbox provides containment
regardless -- even if the command were malicious, it runs inside the sandbox.

### Base Branch Checkout

The action uses `github.event.pull_request.base.ref` (not
`github.event.repository.default_branch`) for the checkout ref. This supports
repositories with multiple protected branches (e.g., `main` and `release/*`).
Security relies on the workflow trigger being restricted to protected branches
and workflow files being immutable (see Required External Controls).

For `push` events (no PR context), the fallback `github.ref_name` resolves to
the branch being pushed to.
