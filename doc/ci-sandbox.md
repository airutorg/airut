# CI Sandbox

When an AI agent creates a pull request, CI workflows run code from that PR on
GitHub Actions runners. The agent controls the PR code, which means test suites,
build scripts, and linters all run agent-steerable code -- on runners with
outbound internet access and access to repository secrets. This is a sandbox
escape: the agent's code runs unsandboxed outside Airut's container.

The `airut-sandbox` CLI and
[`airutorg/sandbox-action`](https://github.com/airutorg/sandbox-action) GitHub
Action close this gap by running CI commands inside the same container
isolation, network allowlisting, and credential masking that the Airut gateway
uses.

> **For usage documentation** (action inputs, workflow examples, image caching,
> debugging), see the
> [sandbox-action README](https://github.com/airutorg/sandbox-action#readme).
> This document focuses on the security model, threat analysis, and repository
> configuration requirements.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [The Problem](#the-problem)
- [Solution: Sandbox Action](#solution-sandbox-action)
- [Trust Model](#trust-model)
- [Security Requirements](#security-requirements)
  - [1. Protecting Workflow Files](#1-protecting-workflow-files)
  - [2. Branch Protection](#2-branch-protection)
  - [3. Sandbox Configuration Files](#3-sandbox-configuration-files)
  - [4. Terminal Step](#4-terminal-step)
- [Configuration](#configuration)
  - [Credential Handling](#credential-handling)
- [Using `airut-sandbox` Directly](#using-airut-sandbox-directly)
  - [CLI Options](#cli-options)
  - [Non-GitHub CI Systems](#non-github-ci-systems)
- [Security Summary](#security-summary)
  - [Checklist](#checklist)
  - [Residual Risks](#residual-risks)
- [Image Caching Security](#image-caching-security)
- [Fail-Secure Behavior](#fail-secure-behavior)
- [Further Reading](#further-reading)

<!-- mdformat-toc end -->

## The Problem

GitHub Actions workflows triggered by `pull_request` events execute code from
the PR branch. For same-repository PRs (not forks), GitHub makes all repository
secrets available. The `GITHUB_TOKEN` has whatever permissions are configured in
the repository's default token settings (Settings → Actions → General → Workflow
permissions) -- commonly read-write. A compromised agent can:

1. **Modify workflow files directly** -- push a workflow that runs arbitrary
   code. Requires the `workflow` PAT scope.
2. **Modify code that workflows execute** -- alter test files, build scripts, or
   application code that existing workflows run. Requires only
   `Contents: Read and write` (which the agent needs for normal git operations).

Path 1 can be closed by omitting the `workflow` scope from the agent's PAT (or
using a repository ruleset -- see
[Protecting Workflow Files](#1-protecting-workflow-files)). But path 2 is the
harder problem: the agent can modify any repository code, and most CI workflows
execute repository code (`uv run pytest`, `npm test`, build scripts).

Without sandboxing, the only way to close both paths is to use
`workflow_dispatch` triggers (manual-only), which sacrifices auto-triggered CI.

See [security.md](security.md#github-actions-workflow-escape) for the full
threat analysis.

## Solution: Sandbox Action

[`airutorg/sandbox-action`](https://github.com/airutorg/sandbox-action) runs CI
commands inside the Airut sandbox. The workflow triggers automatically on PRs,
but the agent-steerable code runs inside a container with network restrictions
and credential masking -- not directly on the runner.

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

For full action inputs, workflow examples, and image caching configuration, see
the [sandbox-action README](https://github.com/airutorg/sandbox-action#readme).

## Trust Model

The security of sandboxed CI relies on four invariants. Each is enforced by a
different control, and all four must hold simultaneously:

1. **Sandbox configuration comes from the default branch** --
   `.airut/sandbox.yaml`, `.airut/network-allowlist.yaml`, and
   `.airut/container/Dockerfile` are read from the base branch checkout on the
   host, not from the PR branch. The agent cannot tamper with the container
   image, network allowlist, or secret masking rules. The sandbox-action
   enforces this by checking out `github.event.pull_request.base.ref`.

   > **`workflow_dispatch` note:** For `workflow_dispatch` triggers there is no
   > PR context, so the action falls back to `github.ref_name` — the dispatched
   > branch. Sandbox configuration (Dockerfile, network allowlist, masked
   > secrets) comes from that branch, not the default branch. This is safe
   > because a human triggers the dispatch after reviewing the PR, but the
   > dispatcher should verify the branch's `.airut/` configuration before
   > triggering. For automated CI on PRs, use `pull_request` triggers.

2. **Workflow files are immutable to the agent** -- the agent must not be able
   to modify `.github/workflows/`. For `pull_request` events, GitHub executes
   the workflow YAML from the merge ref (`refs/pull/<number>/merge`), not from
   the base branch alone -- so PAT scope restriction or a push ruleset is the
   actual control that prevents the agent from altering the workflow.

3. **The `airut-sandbox` implementation is trusted** -- the agent must not be
   able to modify the sandbox code that enforces containment. For third-party
   repos, `airut-sandbox` is installed from PyPI (the agent cannot modify it).
   For the Airut repo itself, the default-branch checkout ensures the sandbox
   implementation is trusted.

4. **Only PR code runs inside the sandbox** -- the untrusted code (test suites,
   build scripts, application code from the PR) executes inside the container.
   Everything outside the container -- the workflow file, the checkout logic,
   the `airut-sandbox` invocation -- comes from trusted sources.

The only thing the agent controls is the code that runs inside the sandbox,
which is the intended behavior: CI tests the PR code in a sandboxed environment.

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

- **Classic PAT**: Grant `repo` scope, ensure `workflow` is **unchecked**.
  Existing classic PATs may have `workflow` enabled by default -- audit at
  GitHub → Settings → Developer settings → Personal access tokens. (Fine-grained
  PATs cannot be used with a dedicated bot account because they can only access
  repositories owned by the token's account, not repositories where the account
  is a collaborator.)

**Option B: Push rulesets (Teams and Enterprise plans)**

GitHub push rulesets can restrict changes to specific file paths. This option
requires a **GitHub Teams or Enterprise plan** -- push rulesets with file path
restrictions are not available on Free or Pro plans, or for public repositories
on those plans. For repositories without access to push rulesets, Option A (PAT
scope omission) is the only mechanism.

To configure:

1. Go to Settings → Rules → Rulesets → New push ruleset
2. Set enforcement status to **Active**
3. Under "Target branches", target all branches (`**`) or specific branch
   patterns where the agent pushes
4. Under "Bypass list", add only trusted administrators or apps that need to
   modify workflows
5. Under "Restrict file paths", add the pattern `**/.github/workflows/**/*`

Push rulesets block the push itself (regardless of target branch), which is the
desired behavior -- the agent cannot push workflow file changes to any branch.
**Both options can be combined** for defense in depth.

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

The sandbox reads `.airut/sandbox.yaml` and `.airut/network-allowlist.yaml` from
the base branch checkout. For the full configuration format and examples, see
the
[sandbox-action README](https://github.com/airutorg/sandbox-action#configuration).

If `network_sandbox: true` (the default), the container's outbound HTTP(S)
traffic is restricted to `.airut/network-allowlist.yaml`. See
[network-sandbox.md](network-sandbox.md) for the allowlist format and examples.

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

`airut-sandbox` is CI-agnostic -- it runs anywhere with a container runtime --
but the **workflow-level security guarantees** depend on the CI platform
enforcing equivalent constraints to those described in this guide. The security
requirements above are written for GitHub Actions; operators deploying on other
platforms must map them to their CI system's controls:

- **Workflow file protection**: On GitHub, omitting the `workflow` PAT scope
  prevents the agent from modifying `.github/workflows/`. On GitLab, Buildkite,
  Jenkins, and other systems, there may be no equivalent token-level scope
  restriction. Operators must use branch protection rules, CODEOWNERS, or
  path-based protections to prevent the agent from modifying CI configuration
  files (e.g., `.gitlab-ci.yml`, `Jenkinsfile`, `.buildkite/pipeline.yml`). If
  the platform's API does not respect these protections, consider using an
  external webhook-triggered pipeline where the agent's token has no write
  access to the repository containing the pipeline definition.

- **Default-branch checkout**: The `actions/checkout` `ref:` override pattern is
  GitHub-specific. Other CI systems have different default checkout behaviors --
  some check out the PR branch directly, others the merge result. Operators must
  ensure the host workspace contains only default-branch files before
  `airut-sandbox` runs, using whatever mechanism their CI platform provides.
  This is critical: if the host workspace contains PR-branch files, the agent
  can tamper with `.airut/` configuration.

- **Secrets availability**: GitHub makes repository secrets available to
  same-repo `pull_request` workflows but restricts them for fork PRs. Other
  platforms may have different policies. Operators should audit which secrets
  are exposed to agent-triggered pipelines and use masked secrets for all
  credentials regardless of platform.

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

| Risk                                          | Mitigation                                                                                          |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Sandbox escape via container vulnerability    | Same as gateway: `--cap-drop=ALL`, `no-new-privileges`                                              |
| Misconfigured workflow checks out PR branch   | Follow this guide; use sandbox-action which handles checkout                                        |
| Expression injection in workflow `run:`       | See below                                                                                           |
| Tainted workspace after sandbox               | Make sandbox step terminal; no post-sandbox steps                                                   |
| Agent modifies `airut-sandbox` implementation | Installed from PyPI/trusted source, not from PR branch                                              |
| Stale cached image with unpatched base OS     | `cache-max-age` (default one week) forces periodic rebuild; `cache-version` for manual invalidation |

**Expression injection:** GitHub Actions evaluates `${{ }}` expressions in
workflow YAML _before_ the `run:` script executes. Values like
`github.event.pull_request.title`, `github.head_ref` (branch name), and
`github.event.pull_request.body` are controlled by the PR author (the agent). If
a workflow interpolates these directly in a `run:` block, the agent can embed
shell commands in the PR title or branch name that execute on the runner
**outside the sandbox** -- the expression is evaluated at the workflow level,
not inside the container. Mitigation: pass untrusted GitHub context values via
`env:` variables (which are shell-escaped) rather than inline `${{ }}`
interpolation in `run:` scripts. The `sandbox-action` itself follows this
pattern.

## Image Caching Security

The sandbox action caches built container images across CI runs using
`actions/cache`. For usage details (inputs, cache invalidation, disabling), see
the
[sandbox-action README](https://github.com/airutorg/sandbox-action#image-caching).

The primary security concern is cache poisoning: a malicious PR tampers with a
cached image so that subsequent runs load the poisoned image. Four independent
defenses prevent this:

1. **Step ordering**: All cache operations run **before** the sandbox executes
   untrusted code. The sandbox is the terminal step -- no post-sandbox steps
   exist, so a compromised container cannot tamper with cached tarballs.
2. **No cache credentials in the container**: The container does not receive
   `ACTIONS_RUNTIME_TOKEN` or `ACTIONS_CACHE_URL` (it only gets explicitly
   declared env vars, not the runner's environment).
3. **Branch-scoped cache**: PR branches can read the base branch cache but
   cannot write to it (GitHub platform guarantee).
4. **Immutable cache keys**: Once saved, a cache entry cannot be overwritten
   (GitHub platform guarantee).

Neither image contains secrets -- credentials are injected at runtime via
masked-secret surrogates and proxy-level bind mounts.

For the full security analysis with defense-in-depth details, see
[spec/image.md](../spec/image.md#security).

## Fail-Secure Behavior

If `airut-sandbox` cannot run for any reason (not installed, container runtime
unavailable, config error), the workflow step fails and agent-steerable code
does not execute unsandboxed. **Never** structure a workflow where
agent-steerable code runs as a fallback when sandboxing fails.

## Further Reading

- [`airutorg/sandbox-action`](https://github.com/airutorg/sandbox-action) --
  Action usage documentation (inputs, examples, debugging, image caching)
- [security.md](security.md) -- Full security model and threat analysis
- [execution-sandbox.md](execution-sandbox.md) -- Container isolation details
- [network-sandbox.md](network-sandbox.md) -- Network allowlist and credential
  masking
- [spec/sandbox-cli.md](../spec/sandbox-cli.md) -- `airut-sandbox` CLI
  specification (configuration, lifecycle, resource isolation)
- [spec/sandbox-action.md](../spec/sandbox-action.md) -- Full action
  specification
- [spec/image.md](../spec/image.md#ci-image-caching) -- Image caching design and
  security model
