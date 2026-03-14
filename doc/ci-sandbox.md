# CI Sandbox

When an AI agent creates a pull request, CI workflows run code from that PR on
GitHub Actions runners. The agent controls the PR code, which means test suites,
build scripts, and linters all run agent-steerable code -- on runners with
outbound internet access and access to repository secrets. This is a sandbox
escape: the agent's code runs unsandboxed outside Airut's container.

The `airut-sandbox` CLI and `airutorg/sandbox-action` GitHub Action close this
gap by running CI commands inside the same container isolation, network
allowlisting, and credential masking that the Airut gateway uses.

## The Problem

GitHub Actions workflows triggered by `pull_request` events execute code from
the PR branch. For same-repository PRs (not forks), GitHub grants full access to
repository secrets and `GITHUB_TOKEN` write permissions. A compromised agent
can:

1. **Modify workflow files directly** -- push a workflow that runs arbitrary
   code. Requires the `workflow` PAT scope.
2. **Modify code that workflows execute** -- alter test files, build scripts, or
   application code that existing workflows run. Requires only
   `Contents: Read and write` (which the agent needs for normal git operations).

Path 1 can be closed by omitting the `workflow` scope from the agent's PAT (or
using a repository ruleset -- see
[Protecting Workflow Files](#protecting-workflow-files)). But path 2 is the
harder problem: the agent can modify any repository code, and most CI workflows
execute repository code (`uv run pytest`, `npm test`, build scripts).

Without sandboxing, the only way to close both paths is to use
`workflow_dispatch` triggers (manual-only), which sacrifices auto-triggered CI.

See [security.md](security.md#github-actions-workflow-escape) for the full
threat analysis.

## Solution: Sandbox Action

`airutorg/sandbox-action` runs CI commands inside the Airut sandbox. The
workflow triggers automatically on PRs, but the agent-steerable code runs inside
a container with network restrictions and credential masking -- not directly on
the runner.

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

**What happens:**

1. The action installs `airut-sandbox` on the runner (from PyPI)
2. Checks out the **base branch** (e.g., `main`) -- this provides trusted
   `.airut/` configuration
3. Fetches the PR commit objects on the host (so git credentials are not needed
   inside the sandbox)
4. Runs the command inside `airut-sandbox`: the PR code is checked out inside
   the container, where network access is restricted to the allowlist and
   credentials are masked

Even if the agent injects malicious code into test suites or build scripts, the
sandbox prevents exfiltration. The container never sees real credential values
-- only surrogates that the proxy replaces on matching outbound requests.

## Security Requirements

The sandbox action provides containment, but **the repository must be configured
correctly for the security model to hold**. This configuration is delicate --
each requirement addresses a specific attack vector, and missing any one of them
can undermine the protection.

### 1. Protecting Workflow Files

The PR author must not be able to modify `.github/workflows/`. Two options:

**Option A: Omit the `workflow` scope from the agent's PAT**

GitHub enforces this at the git push level -- any push that includes changes to
`.github/workflows/` is rejected.

- **Fine-grained PAT**: Grant `Contents: Read and write` but do **not** grant
  `Workflows: Read and write`.
- **Classic PAT**: Grant `repo` scope, ensure `workflow` is **unchecked**.
  Existing classic PATs may have `workflow` enabled by default -- audit at
  GitHub → Settings → Developer settings → Personal access tokens.

**Option B: Repository rulesets**

GitHub repository rulesets can restrict changes to specific file paths. Create a
ruleset that blocks pushes modifying `.github/workflows/**` for all users except
repository administrators (or a specific bypass list).

To configure:

1. Go to Settings → Rules → Rulesets → New ruleset
2. Set enforcement status to **Active**
3. Under "Target branches", add `main` and any other protected branches
4. Under "Bypass list", add only trusted administrators
5. Under "Rules", enable **Restrict file paths** and add the pattern
   `.github/workflows/**`

**Important:** Rulesets apply to the target branch. A push to a feature branch
that modifies `.github/workflows/` is not blocked by the ruleset itself -- the
restriction takes effect when the PR targets a protected branch. The PAT scope
restriction (Option A) is more comprehensive because it blocks the push
regardless of target branch. **Both options can be combined** for defense in
depth.

### 2. Branch Protection

The base branch must be protected, and the workflow must only trigger on PRs
targeting protected branches:

```yaml
on:
  pull_request:
    branches: [main]  # Only PRs targeting main
```

**Why:** The sandbox action checks out `github.event.pull_request.base.ref` and
loads `.airut/` configuration from it. If the workflow triggers on PRs to
unprotected branches, the PR author could push malicious `.airut/` config to the
base branch before the workflow runs.

Configure branch protection for `main`:

1. Settings → Branches → Add rule
2. Branch name pattern: `main`
3. Enable: Require a pull request before merging, require approvals
4. Enable: Require status checks to pass

### 3. Sandbox Configuration Files

The repository needs `.airut/` configuration on the default branch:

- **`.airut/container/Dockerfile`** (required) -- container image with the tools
  your CI needs (Python, Node, etc.)
- **`.airut/sandbox.yaml`** (optional) -- environment variables, masked secrets,
  resource limits
- **`.airut/network-allowlist.yaml`** (optional) -- network allowlist if
  `network_sandbox: true`

These files are read from the base branch checkout, not the PR. The agent cannot
tamper with them.

### 4. Terminal Step

**The sandbox action must be the last step of the job.** After sandbox
execution, the workspace is tainted -- the untrusted PR code had write access to
the workspace including `.git/`. A malicious PR could install git hooks, modify
binaries, or plant files. No workflow steps should run after the sandbox step.

If you need post-sandbox operations (e.g., uploading test artifacts), run them
in a separate job that does not share the tainted workspace.

## Configuration

### Sandbox Config (`.airut/sandbox.yaml`)

This file controls what the container receives. It lives on the default branch
and is reviewed by humans before taking effect.

```yaml
# .airut/sandbox.yaml

# Environment variables (non-sensitive only)
env:
  CI: "true"
  PYTHONDONTWRITEBYTECODE: "1"

# Network sandbox (enabled by default)
network_sandbox: true

# Masked secrets — container gets surrogates, proxy swaps for real values
# only on matching hosts. Prevents credential exfiltration.
masked_secrets:
  GH_TOKEN:
    value: !env GH_TOKEN
    scopes: ["api.github.com", "*.githubusercontent.com"]
    headers: ["Authorization"]

# Resource limits
resource_limits:
  memory: "4g"
  cpus: 2
  timeout: 600
```

Pass secrets from GitHub Actions via `env:` on the action step:

```yaml
- uses: airutorg/sandbox-action@v0
  with:
    command: 'uv sync && uv run pytest'
    pr_sha: ${{ github.event.pull_request.head.sha }}
  env:
    GH_TOKEN: ${{ secrets.GH_TOKEN }}
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The `!env` tags in `sandbox.yaml` resolve from the runner's environment
variables (set by the workflow `env:` block). If a referenced variable is
missing, `airut-sandbox` exits with code 125 (fail-closed).

### Network Allowlist

If `network_sandbox: true` (the default), the container's outbound HTTP(S)
traffic is restricted to `.airut/network-allowlist.yaml`. The same allowlist
format is used by the gateway.

The allowlist does **not** need to include the repository's own GitHub URL --
the action fetches the PR SHA on the host before entering the sandbox, so git
operations inside the container work from local `.git` objects.

See [network-sandbox.md](network-sandbox.md) for the allowlist format and
examples.

### Credential Handling

Credentials should use the most restrictive mechanism available:

| Mechanism               | When to use                             | Protection                                 |
| ----------------------- | --------------------------------------- | ------------------------------------------ |
| **Signing credentials** | AWS services (SigV4/SigV4A)             | Strongest: real keys never enter container |
| **Masked secrets**      | All other API tokens, passwords         | Strong: container sees only surrogates     |
| **`pass_env`**          | Non-sensitive values (CI flags, locale) | None: real value visible inside container  |

**Masked secrets should be the default for all credentials.** Even if the
network sandbox prevents most exfiltration, masked secrets ensure that a
container escape or sandbox misconfiguration cannot expose real credentials.

## Action Inputs

| Input           | Required | Default        | Description                                                               |
| --------------- | -------- | -------------- | ------------------------------------------------------------------------- |
| `command`       | Yes      |                | CI command to run inside the sandbox (after PR checkout)                  |
| `pr_sha`        | Yes      |                | PR commit SHA to check out and test                                       |
| `merge`         | No       | `true`         | Merge PR into base branch before running (like GitHub's default behavior) |
| `airut_version` | No       | from `VERSION` | Airut version to install (`0.15.0` for PyPI, `main` for GitHub HEAD)      |
| `sandbox_args`  | No       | `--verbose`    | Additional arguments passed to `airut-sandbox run`                        |

When `merge` is `true` (default), the container starts on the base branch and
runs `git merge --no-edit <sha>` to create a temporary merge commit. This
matches GitHub Actions' default `pull_request` checkout behavior.

## Full Workflow Example

```yaml
name: CI
on:
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: airutorg/sandbox-action@v0
        with:
          command: |
            uv sync
            uv run scripts/ci.py --verbose --timeout 0
          pr_sha: ${{ github.event.pull_request.head.sha || github.sha }}
          sandbox_args: '--verbose'
        env:
          GH_TOKEN: ${{ secrets.GH_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Using `airut-sandbox` Directly

The sandbox action wraps `airut-sandbox` for convenience. You can also use the
CLI directly in any CI system (GitHub Actions, GitLab CI, Buildkite, etc.):

```bash
# Install
uv tool install airut

# Run a command inside the sandbox
airut-sandbox run --verbose -- uv run pytest
```

The CLI reads `.airut/` from the current working directory. In CI, ensure the
working directory contains the **default branch** checkout (trusted config), and
only the PR code runs inside the container.

### CLI Options

```
airut-sandbox run [OPTIONS] -- COMMAND [ARGS...]

Options:
  --config PATH          Sandbox config (default: .airut/sandbox.yaml)
  --dockerfile PATH      Path to Dockerfile (default: .airut/container/Dockerfile)
  --allowlist PATH       Network allowlist override
  --timeout SECONDS      Container timeout (overrides config)
  --mount SRC:DST[:ro]   Additional mount (repeatable)
  --network-log FILE     Append network activity log to FILE
  --log FILE             Write sandbox log to FILE instead of stderr
  --verbose              Enable informational logging
  --debug                Enable debug logging (implies --verbose)
```

The CLI exits with the sandboxed command's exit code (0 for success, non-zero
for failure). Infrastructure errors exit with 125, timeouts with 124.

### Non-GitHub CI Systems

`airut-sandbox` is CI-agnostic, but the workflow-level security guarantees
depend on the CI platform. On non-GitHub platforms, verify:

- **Workflow file protection**: Use branch protection, CODEOWNERS, or path-based
  protections to prevent the agent from modifying CI config files
- **Default-branch checkout**: Ensure the host workspace contains only
  default-branch files before `airut-sandbox` runs
- **Secrets availability**: Audit which secrets are exposed to agent-triggered
  pipelines and use masked secrets for all credentials

## Security Summary

The following table shows which workflow types are safe to auto-trigger:

| Workflow type                                         | Auto-trigger safe? | Why                                           |
| ----------------------------------------------------- | ------------------ | --------------------------------------------- |
| Runs no agent-steerable code                          | Yes                | Agent can't influence execution               |
| Runs agent-steerable code, **no sandbox**             | No                 | Must use `workflow_dispatch` (manual trigger) |
| Runs agent-steerable code, **inside `airut-sandbox`** | Yes                | Agent-steered code contained by sandbox       |

### Checklist

Before relying on the sandbox for CI security, verify:

- [ ] Agent PAT lacks `workflow` scope **or** repository ruleset blocks
  `.github/workflows/**` changes (or both)
- [ ] Workflow triggers only on PRs to protected branches
  (`pull_request: branches: [main]`)
- [ ] Base branch (`main`) has branch protection enabled (require PR, require
  approvals)
- [ ] `.airut/container/Dockerfile` exists on the default branch
- [ ] Sandbox action is the **last step** of the job (nothing runs after it)
- [ ] Credentials passed as masked secrets in `.airut/sandbox.yaml`, not as
  plain environment variables

### Residual Risks

| Risk                                          | Mitigation                                                   |
| --------------------------------------------- | ------------------------------------------------------------ |
| Sandbox escape via container vulnerability    | Same as gateway: `--cap-drop=ALL`, `no-new-privileges`       |
| Misconfigured workflow checks out PR branch   | Follow this guide; use sandbox-action which handles checkout |
| Expression injection in workflow `run:`       | Pass values via `env:`, not inline `${{ }}` interpolation    |
| Tainted workspace after sandbox               | Make sandbox step terminal; no post-sandbox steps            |
| Agent modifies `airut-sandbox` implementation | Installed from PyPI/trusted source, not from PR branch       |

## Fail-Secure Behavior

If `airut-sandbox` cannot run for any reason (not installed, container runtime
unavailable, config error), the workflow step fails and agent-steerable code
does not execute unsandboxed. **Never** structure a workflow where
agent-steerable code runs as a fallback when sandboxing fails.

## Further Reading

- [security.md](security.md) -- Full security model and threat analysis
- [execution-sandbox.md](execution-sandbox.md) -- Container isolation details
- [network-sandbox.md](network-sandbox.md) -- Network allowlist and credential
  masking
- [spec/sandbox-cli.md](../spec/sandbox-cli.md) -- Full CLI specification
- [spec/sandbox-action.md](../spec/sandbox-action.md) -- Full action
  specification
