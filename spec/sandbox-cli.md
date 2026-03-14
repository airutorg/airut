# Sandbox CLI

Standalone CLI tool (`airut-sandbox`) for running commands inside the Airut
sandbox. Exposes the same container isolation, network allowlisting, and
credential masking that the gateway uses, as a standalone tool for CI pipelines
and other environments running agent-steerable code.

## Security Model

### Principle: Agent Containment

The agent must be contained within the Airut sandbox at all times. This includes
not only the agent during Airut task execution, but also any code the agent can
steer or influence running anywhere outside Airut -- CI pipelines, build
scripts, test suites, or any other execution environment.

### Default Branch Is Trusted

Airut's security model treats the default branch (typically main) as trusted.
The agent cannot push directly to the default branch -- repository branch
protection enforces this. All agent changes go through PRs that are merged by
humans after review.

This means a human reviews (by approving the PR) any changes the agent proposes
to sandbox configuration (`.airut/container/Dockerfile`,
`.airut/network-allowlist.yaml`, `.airut/sandbox.yaml`), workflow files, and
other trusted infrastructure.

### The CI Escape Vector

GitHub Actions (and other CI systems) are an environment where the agent can run
code outside the Airut sandbox. The agent pushes a PR branch, and CI workflows
execute code from that branch -- test suites, build scripts, linters -- on
runners with outbound internet access and access to CI secrets. This is a
sandbox escape: the agent's code runs unsandboxed on the runner.

**Note on secrets availability:** For same-repository PRs (branches within the
same repo, not forks), GitHub Actions makes all repository secrets available and
grants `GITHUB_TOKEN` write permissions. The agent pushes branches to the same
repository, so `pull_request` workflows triggered by agent PRs have full access
to secrets. This is why sandboxing CI execution matters -- the agent's code runs
with access to credentials that could be exfiltrated via the runner's
unrestricted network access.

The escape has two paths (documented in `doc/security.md`):

1. **Modify workflow files directly** -- push a workflow that runs arbitrary
   code. Requires the `workflow` PAT scope.
2. **Modify code that workflows execute** -- alter test files, build scripts, or
   application code that existing workflows run. Requires only
   `Contents: Read and write` (which the agent needs for normal git operations).

### Existing Mitigations (Without `airut-sandbox`)

Without `airut-sandbox`, **both** of the following mitigations are needed to
close both escape paths:

1. **Omit `workflow` scope from agent PAT** -- prevents the agent from creating
   or modifying workflow files. GitHub enforces this at the git push level. This
   closes path 1, but is not sufficient alone -- the agent can still modify code
   that existing workflows execute (path 2).
2. **Use `workflow_dispatch` for workflows that run agent-steerable code** --
   workflows triggered only by manual dispatch (`workflow_dispatch`) cannot be
   triggered by the agent. A human must review the changes and manually trigger
   the workflow. This closes path 2, but sacrifices auto-triggered CI.

Neither mitigation is sufficient on its own. Omitting the `workflow` scope
without `workflow_dispatch` leaves path 2 open: existing auto-triggered
workflows still execute agent-modified code on runners with full secret access.
Using `workflow_dispatch` without omitting the `workflow` scope leaves path 1
open: the agent can push a new workflow with an auto-trigger.

Workflows that run no agent-steerable code (e.g., fixed actions, pinned linter
configs) are safe to auto-trigger with only mitigation 1.

### What `airut-sandbox` Adds

`airut-sandbox` adds a third option: **auto-triggered workflows that run
agent-steerable code inside the sandbox**. The workflow invokes
`airut-sandbox run`, which runs the CI command inside the same container
isolation, network allowlisting, and credential masking that the Airut gateway
provides. Even if the agent injects malicious code into test suites or build
scripts, the sandbox prevents exfiltration.

Credential masking is particularly important in CI: same-repository
`pull_request` workflows have full access to repository secrets (unlike fork
PRs). By using masked secrets, the container never sees real credential values
-- only surrogates that the proxy replaces on matching outbound requests. This
means compromised test code cannot exfiltrate API keys even if it finds a way to
make network requests outside the allowlist.

| Workflow type                                         | Auto-trigger safe? | Why                                           |
| ----------------------------------------------------- | ------------------ | --------------------------------------------- |
| Runs no agent-steerable code                          | Yes                | Agent can't influence execution               |
| Runs agent-steerable code, **no sandbox**             | No                 | Must use `workflow_dispatch` (manual trigger) |
| Runs agent-steerable code, **inside `airut-sandbox`** | Yes                | Agent-steered code contained by sandbox       |

The security relies on the default-branch trust model:

- **Sandbox configuration** is loaded from the default branch checkout, not from
  the PR branch. The agent cannot tamper with the Dockerfile, network allowlist,
  or secret masking rules. This requires the workflow to explicitly check out
  the default branch.
- **Workflow files** cannot be modified by the agent because the PAT lacks the
  `workflow` scope. GitHub enforces this at the git push level -- any push that
  includes changes to `.github/workflows/` is rejected. Note: for `pull_request`
  events, GitHub executes the workflow YAML from the merge ref
  (`refs/pull/<number>/merge`), not from the base branch alone. The PAT
  restriction is the actual security control that prevents the agent from
  altering the workflow.
- **The `airut-sandbox` implementation** must come from a trusted source, not
  from the PR branch. The agent must not be able to modify the sandbox code that
  enforces containment. This has two cases:
  - **Airut repo itself**: The workflow checks out the default branch before
    running `airut-sandbox`. Since `airut-sandbox` is part of the repo, the
    default-branch checkout ensures the sandbox implementation is trusted.
  - **Third-party repos**: Install `airut-sandbox` from PyPI
    (`uv tool install airut`) or from the Airut repository's main branch. The
    sandbox implementation is not part of the consuming repo, so the agent
    cannot modify it regardless of what it pushes.
- **Wrapper scripts** that prepare the workspace (e.g., merging the PR commit)
  run inside the sandbox. They come from the default branch in practice (since
  that is what is checked out on the host), but the security model does not
  require them to be trusted -- they execute inside the same container isolation
  as the PR code itself.

The only thing the agent controls is the code that runs inside the sandbox,
which is the intended behavior -- CI tests the PR code in a sandboxed
environment.

### Non-GitHub CI Systems

The security model above describes GitHub-specific controls (PAT scope
restrictions, `pull_request` event semantics, `actions/checkout` behavior).
`airut-sandbox` itself is CI-agnostic -- it runs anywhere with a container
runtime -- but the **workflow-level security guarantees** depend on the CI
platform enforcing equivalent constraints. Operators deploying on non-GitHub
platforms must verify:

- **Workflow file protection**: On GitHub, omitting the `workflow` PAT scope
  prevents the agent from modifying `.github/workflows/`. On GitLab, Buildkite,
  Jenkins, and other systems, there may be no equivalent token-level scope
  restriction. Operators must use branch protection rules, CODEOWNERS, or
  path-based protections to prevent the agent from modifying CI configuration
  files (e.g., `.gitlab-ci.yml`, `Jenkinsfile`, `.buildkite/pipeline.yml`). If
  the platform's API does not respect these protections, consider using an
  external webhook-triggered pipeline where the agent's token has no write
  access to the repository containing the pipeline definition.

- **Default-branch checkout semantics**: The `actions/checkout` `ref:` override
  pattern is GitHub-specific. Other CI systems have different default checkout
  behaviors -- some check out the PR branch directly, others the merge result.
  Operators must ensure the host workspace contains only default-branch files
  before `airut-sandbox` runs, using whatever mechanism their CI platform
  provides.

- **Secrets availability**: GitHub makes repository secrets available to
  same-repo `pull_request` workflows but restricts them for fork PRs. Other
  platforms may have different policies. Operators should audit which secrets
  are exposed to agent-triggered pipelines and use masked secrets for all
  credentials regardless of platform.

### Fail-Secure Principle

Workflows that use `airut-sandbox` must be designed to **fail secure**: if the
sandbox cannot run for any reason (not installed, container runtime unavailable,
config error, infrastructure failure), the workflow step must fail and
agent-steerable code must not execute unsandboxed. This is the natural behavior
when `airut-sandbox run` is the workflow step command -- if `airut-sandbox` is
missing or fails to start, the step exits non-zero and no code runs.

**Never** structure a workflow where agent-steerable code runs as a fallback
when sandboxing fails. The correct failure mode is a failed CI check, not an
unsandboxed run.

### Residual Attack Surface

| Risk                                                 | Mitigation                                                                                         |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Agent pushes workflow file with `workflow` PAT scope | Omit `workflow` scope from agent PAT (GitHub enforces at git push level)                           |
| Workflow checks out PR branch before running sandbox | Workflow design: main-branch checkout first, PR code only inside sandbox                           |
| Agent modifies `airut-sandbox` implementation        | Install from PyPI/trusted source, or check out from default branch                                 |
| Sandbox escape via container vulnerability           | Same risk as gateway; mitigated by `--cap-drop=ALL`, `no-new-privileges`                           |
| Sandbox infrastructure failure                       | Fail-secure: workflow step fails, agent code does not run unsandboxed                              |
| Expression injection in workflow `run:` scripts      | Pass GitHub context via `env:` variables, not inline `${{ }}` interpolation                        |
| Tainted workspace after sandbox execution            | Make `airut-sandbox` the terminal job step; post-sandbox steps must not execute workspace binaries |

The primary operational risk is a misconfigured workflow that checks out the PR
branch (or the default merge ref) on the host before running `airut-sandbox`,
allowing the PR to tamper with `.airut/` config or sandbox implementation. On
`pull_request` events, `actions/checkout` without an explicit `ref:` checks out
the merge commit (`refs/pull/<number>/merge`), which includes PR changes -- this
is the default behavior and must be overridden. The reference workflow uses
`ref: ${{ github.event.pull_request.base.ref }}` to ensure only trusted
default-branch config is present. The PR SHA is passed as an argument to a
wrapper script that runs inside the sandbox.

## Motivation

The Airut gateway already has a production-quality sandbox: container isolation
with `--cap-drop=ALL`, network allowlisting via transparent proxy, credential
masking with format-preserving surrogates, and resource limits via cgroup v2.
`airut-sandbox` exposes this as a standalone CLI tool so that CI workflows (and
any other environment running agent-steerable code) can use the same sandbox.

### Why a CLI Tool, Not a Service

An earlier design (PR #227) proposed a full CI service with webhook handling,
executor, job queuing, and dashboard. The standalone CLI approach has
significant advantages:

- **No new infrastructure** -- no webhook server, executor process, systemd
  unit, or separate config file. The sandbox is a tool, not a service.
- **Works with any CI system** -- GitHub Actions, GitLab CI, Buildkite, local
  dev. The sandbox does not care who invokes it.
- **Preserves CI ecosystem** -- status checks, artifact upload, matrix builds,
  caching, marketplace actions all continue to work.
- **Lower operational cost** -- one tool to install, not a service to deploy and
  monitor.

## Design Goals

1. **Reuse, don't rebuild**: The CLI is a thin layer over the existing sandbox
   library. Container lifecycle, proxy management, secret masking, and network
   isolation are all existing code.
2. **Zero coupling to the gateway**: The CLI does not import from
   `airut.gateway`. It uses only the sandbox library and shared utilities.
3. **CI-native**: The tool works naturally inside CI jobs. Exit code
   passthrough, stdout/stderr streaming, and signal handling behave as expected.
4. **Minimal configuration**: Reads `.airut/` from the working directory by
   default. Secrets come from environment variables. No server config file.

## Architecture

### Component Overview

```
CI System (GitHub Actions, GitLab CI, etc.)
  |
  +- Workflow on default branch triggers on PR event
  +- Checks out default branch (trusted config)
  |
  v
airut-sandbox run -- scripts/sandbox-ci.sh <pr-sha>
  |                         (from default branch, runs inside sandbox)
  |
  +- Load .airut/ config (default branch, trusted)
  +- Build/reuse container image (Dockerfile from default branch)
  +- Start sandbox (container + network proxy + credential masking)
  +- Run wrapper script inside container
  |    +- Wrapper checks out PR ref (agent-steered code)
  |    +- Wrapper runs CI command (agent-steered code, sandboxed)
  +- Stream stdout/stderr to the caller
  +- Exit with the command's exit code
```

### Code Layout

```
airut (Python package)
├── sandbox/              # Shared: container lifecycle, proxy, secrets
│   ├── sandbox.py        #   Sandbox facade (startup, shutdown, image, tasks)
│   ├── task.py           #   AgentTask + CommandTask
│   ├── _run_container.py #   Container execution (podman run, process lifecycle)
│   ├── _image.py         #   Two-layer image build
│   ├── _proxy.py         #   Proxy lifecycle
│   ├── _network.py       #   Network args
│   ├── _entrypoint.py    #   Entrypoint generation (Claude vs passthrough)
│   ├── secrets.py        #   Secret masking
│   ├── event_log.py      #   Event log (agent tasks only)
│   ├── network_log.py    #   Network activity log
│   └── types.py          #   Shared types (Mount, ContainerEnv, ResourceLimits)
├── allowlist.py          # Shared: network allowlist parsing
├── yaml_env.py           # Shared: !env YAML tag resolution
├── sandbox_cli.py        # airut-sandbox CLI entry point
├── gateway/              # Gateway-only: email, Slack, channels
└── dashboard/            # Gateway-only: web monitoring
```

The CLI (`airut/sandbox_cli.py`) imports from `airut.sandbox`,
`airut.allowlist`, and `airut.yaml_env`. It does not import from
`airut.gateway`.

## CLI Interface

```
airut-sandbox run [OPTIONS] -- COMMAND [ARGS...]

Options:
  --config PATH          Sandbox config (default: .airut/sandbox.yaml)
  --dockerfile PATH      Path to Dockerfile (default: .airut/container/Dockerfile)
  --context-dir PATH     Build context directory (default: .airut/container/)
  --allowlist PATH       Network allowlist override
  --timeout SECONDS      Container timeout (overrides config)
  --container-command CMD  Container runtime (default: podman)
  --mount SRC:DST[:ro]   Additional mount (repeatable)
  --network-log FILE     Append network activity log to FILE
  --log FILE             Write sandbox log to FILE instead of stderr
  --verbose              Verbose logging (debug-level output on stderr)
  --quiet                Suppress all diagnostic output (errors only)
```

Entry point registered in `pyproject.toml`:

```toml
[project.scripts]
airut = "airut.cli:cli"
airut-sandbox = "airut.sandbox_cli:main"
```

The `--` separator is required to distinguish `airut-sandbox` options from the
command being sandboxed.

**`--allowlist` behavior**: When specified, this allowlist is used instead of
the default `.airut/network-allowlist.yaml`. The intended use case is providing
a **more restrictive** CI-specific allowlist (e.g., CI may only need
`api.github.com` while the gateway allowlist includes additional hosts for
development). There is no enforcement that the override is a subset -- this is a
configuration guideline, not a technical constraint. A more permissive override
would weaken security and should be avoided.

**`--network-log` behavior**: When specified, the network activity log is
appended to the given file (created if it does not exist) and persists after
exit. When not specified, a temporary log file is created and deleted on exit.
See Network Activity Log for details.

**`--log` behavior**: When specified, sandbox implementation log messages
(startup, image build, shutdown, etc.) are written to the given file instead of
stderr. The file is created if it does not exist and appended to if it already
exists. Parent directories are created automatically. When combined with
`--quiet`, only ERROR and above messages are written. This is useful for keeping
stdout/stderr clean (containing only the sandboxed command's output) while still
retaining a diagnostic log for debugging.

**Entrypoint output**: The container entrypoint is silent by default -- the
`update-ca-certificates` step redirects all output to `/dev/null`. When
`--verbose` is used, the entrypoint outputs CA certificate setup details to
stderr. This is controlled via the `AIRUT_VERBOSE` environment variable, which
the CLI injects into the container when `--verbose` is specified.

## Configuration

### Configuration Resolution

Configuration is resolved from multiple sources, with later sources overriding
earlier ones:

1. **Defaults** -- sensible defaults for all options
2. **`.airut/sandbox.yaml`** -- sandbox config for environment variables, masked
   secrets, signing credentials, network sandbox settings, and resource limits
3. **`.airut/network-allowlist.yaml`** -- network allowlist (shared with the
   gateway)
4. **CLI flags** -- explicit overrides for Dockerfile path, allowlist path,
   timeout, mounts, and container runtime

The CLI reads `.airut/` from the current working directory. In the CI pattern,
the CWD is the default-branch checkout, so all configuration comes from the
trusted default branch -- the agent cannot tamper with it. This is the same
trust model as the gateway, where network allowlists and container images are
always read from the default branch.

**All environment variables and secrets passed to the container are defined in
the config file.** There are no CLI flags for passing environment variables or
secrets -- this ensures the set of credentials available inside the sandbox is
controlled by the config file (which lives on the default branch and is reviewed
by humans), not by workflow arguments that might be modified in a PR.

### Sandbox Config (`.airut/sandbox.yaml`)

The sandbox config file defines what environment, secrets, and resource limits
the container receives. It uses the same `!env` tag as the gateway's server
config to resolve values from host environment variables at startup.

```yaml
# .airut/sandbox.yaml

# --- Environment Variables ---
# Plain env vars passed to the container. Use only for non-sensitive values
# or values that don't need exfiltration protection (e.g., CI flags).
env:
  CI: "true"
  PYTHONDONTWRITEBYTECODE: "1"

# Host env vars passed through to the container as plain values. Use sparingly
# -- most secrets should be masked (see below). Appropriate for values that
# are not security-sensitive (e.g., TERM, LANG) or that cannot work as masked
# secrets (e.g., values needed before network proxy is active).
pass_env:
  - TERM

# --- Masked Secrets (Recommended for all credentials) ---
# Masked secrets are the primary mechanism for passing credentials into the
# sandbox. The container receives a surrogate (fake) value; the network proxy
# replaces surrogates with real values only for requests matching the
# configured scopes and headers. This prevents exfiltration even if the
# sandboxed code is compromised.
masked_secrets:
  GH_TOKEN:
    value: !env GH_TOKEN
    scopes: ["api.github.com", "*.githubusercontent.com"]
    headers: ["Authorization"]

  ANTHROPIC_API_KEY:
    value: !env ANTHROPIC_API_KEY
    scopes: ["api.anthropic.com"]
    headers: ["x-api-key", "Authorization"]

# --- Signing Credentials (AWS SigV4/SigV4A) ---
# For AWS services, use signing credentials instead of masked secrets. The
# proxy generates surrogate AWS access keys and re-signs requests with real
# credentials, avoiding the need to expose raw keys inside the container.
signing_credentials:
  AWS_BEDROCK:
    type: aws-sigv4
    access_key_id: !env AWS_ACCESS_KEY_ID
    secret_access_key: !env AWS_SECRET_ACCESS_KEY
    session_token: !env AWS_SESSION_TOKEN  # optional
    scopes: ["*.amazonaws.com"]

# --- Network Sandbox ---
# Network sandboxing is enabled by default. It routes all container HTTP(S)
# traffic through a transparent proxy that enforces the network allowlist and
# performs credential masking/re-signing.
#
# Disabling the network sandbox removes exfiltration protection and disables
# credential masking (surrogates will not be replaced with real values, so
# API calls using masked secrets will fail). Only disable for commands that
# need unrestricted network access and do not handle secrets.
network_sandbox: true  # default; set to false to disable

# --- Resource Limits ---
resource_limits:
  memory: "4g"
  cpus: 2
  pids_limit: 256
  timeout: 600
```

**`!env` resolution**: All `!env` tags are resolved from host environment
variables at CLI startup. If a referenced variable is not set, the CLI exits
with code 125 and an error message. This is fail-closed -- a CI step that
expects credentials should not silently run without them.

**Config file is optional**: If `.airut/sandbox.yaml` does not exist, the CLI
runs with defaults (no env vars, no secrets, network sandbox enabled, default
resource limits). This is appropriate for sandboxing commands that need no
credentials.

**Security note**: The config file lives on the default branch (`.airut/`
directory). In the CI workflow pattern, the host filesystem contains the
default-branch checkout, so the agent cannot tamper with the list of env vars,
secrets, or network sandbox settings. This is the same trust model used for the
Dockerfile and network allowlist.

## Credential Handling

Credentials should be passed to the sandbox using the **most restrictive
mechanism** available. From most to least preferred:

| Mechanism               | When to use                                      | Exfiltration protection                                                                      |
| ----------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| **Signing credentials** | AWS services (SigV4/SigV4A)                      | Strongest: real keys never enter container; proxy re-signs requests                          |
| **Masked secrets**      | All other API tokens, passwords, credentials     | Strong: container sees only surrogates; proxy swaps for real values on matching scope+header |
| **`pass_env`**          | Non-sensitive values (CI flags, locale settings) | None: real value in container, exfiltrable if network sandbox is bypassed                    |

**Masked secrets should be the default for all credentials.** The `pass_env`
mechanism passes real secret values into the container as plain environment
variables. While the network sandbox prevents most exfiltration, a container
escape or sandbox misconfiguration would expose the real credential. Masked
secrets eliminate this risk -- even if the sandbox is compromised, only
surrogates are available inside the container.

**When `pass_env` is appropriate for secrets:**

- **Bootstrap credentials** needed before the network proxy is active (rare --
  the proxy starts before the container command runs)
- **Credentials for non-HTTP protocols** that the proxy cannot intercept (e.g.,
  SSH keys, database passwords) -- these are not supported by the masking proxy
  and must be passed as plain values. Consider whether the command actually
  needs these credentials in CI.

**When `pass_env` is appropriate for non-secrets:**

- Environment flags (`CI=true`, `PYTHONDONTWRITEBYTECODE=1`) -- use `env:` in
  the config instead (static values don't need host resolution)
- Locale/terminal settings (`TERM`, `LANG`)

## Workspace Mounting

By default, the current working directory is mounted read-write at `/workspace`
inside the container, and the container's working directory is set to
`/workspace`. This differs from the gateway (which mounts read-only) because CI
commands typically need write access: test reports, coverage files, formatter
auto-fixes, lockfile updates, and build artifacts all write to the working
directory.

Additional mounts are specified via `--mount`. To override the default with a
read-only workspace: `--mount .:/workspace:ro`.

## Exit Code Passthrough

The CLI exits with the sandboxed command's exit code. This is critical for CI
integration -- a failing test suite must cause the CI step to fail:

| Sandboxed command exit       | `airut-sandbox` exit | CI interpretation                                 |
| ---------------------------- | -------------------- | ------------------------------------------------- |
| 0                            | 0                    | Success                                           |
| Non-zero N                   | N                    | Failure                                           |
| 137 (OOM kill)               | 137                  | Failure (container killed by cgroup memory limit) |
| Timeout (SIGKILL)            | 124                  | Failure (matches `timeout(1)` convention)         |
| Sandbox infrastructure error | 125                  | Failure (matches `docker run` convention)         |

When a container is OOM-killed by the cgroup memory limit, podman returns exit
code 137 (128 + SIGKILL). The CLI passes this through and logs a diagnostic
message to stderr suggesting increasing `resource_limits.memory` in
`.airut/sandbox.yaml`.

## Signal Handling

The CLI forwards signals to the container process:

- **SIGTERM**: Forwarded to container (graceful shutdown). If the container
  doesn't exit within 5 seconds, SIGKILL.
- **SIGINT**: Same as SIGTERM (Ctrl-C in terminal or CI cancellation).

## Stdout/Stderr Streaming

The sandboxed command's stdout and stderr are streamed to the CLI's stdout and
stderr in real time. No buffering, no reformatting.

For `CommandTask`, the `_run_container()` function uses `stderr=None`
(pass-through to the parent process's stderr) instead of
`stderr=subprocess.PIPE` (which `AgentTask` uses to capture stderr for
`ExecutionResult`). Stdout is captured line-by-line via `subprocess.PIPE` and
both written to the CLI's stdout and passed to the `on_output` callback. This
gives real-time streaming for both streams.

The CLI's own log messages (sandbox startup, image build progress) go to stderr
to avoid polluting the command's stdout.

## Lifecycle

```
airut-sandbox run -- <command>
  |
  +- Parse CLI args
  +- Load .airut/sandbox.yaml (env, secrets, resource limits, network settings)
  +- Resolve !env tags from host environment (fail-closed on missing vars)
  +- Load .airut/network-allowlist.yaml (or --allowlist override)
  +- Set up network log (--network-log FILE or tempfile)
  +- Sandbox.startup() -- build proxy image, create egress network
  +- Sandbox.ensure_image() -- build/reuse two-layer container image
  +- Sandbox.create_command_task() -- prepare task with masked secrets
  +- task.execute(command) -- run command in container
  +- Sandbox.shutdown() -- remove egress network
  +- Clean up temp network log file (if not --network-log)
  +- Exit with command's exit code
```

For each invocation, the sandbox starts up and shuts down. There is no
persistent daemon. The proxy image and container images are cached by podman, so
subsequent invocations are fast (no rebuild unless content changes).

### Startup Overhead

Each `airut-sandbox run` invocation performs sandbox startup (orphan cleanup,
proxy image check, CA cert check, egress network creation) and shutdown (network
removal). This overhead is acceptable for single-step CI jobs but adds up for
pipelines with multiple sandboxed steps.

Workarounds for multi-step pipelines:

- **Combine steps**: Run all CI checks in a single `airut-sandbox run`
  invocation (e.g., `airut-sandbox run -- uv run scripts/ci.py` where `ci.py`
  runs lint, typecheck, and tests sequentially).
- **Persistent daemon mode**: Deferred to future work (see "Not In Scope").

### Image Staleness in CI

The sandbox's 24-hour image staleness check (see `spec/image.md`) triggers
periodic rebuilds to pick up upstream tool updates. In CI, where runners are
ephemeral and images are built from scratch, the staleness check is not
applicable -- images are always "fresh" because the in-memory build timestamp
cache starts empty on each invocation. The first build always runs; subsequent
builds within the same invocation (if any) reuse the cached image.

For CI runners with persistent podman image caches (self-hosted runners), the
staleness check applies normally.

### Crash Recovery

If `airut-sandbox` is killed by SIGKILL (CI timeout, host OOM), the container,
proxy, and internal network are orphaned. The next `airut-sandbox run`
invocation cleans these orphans during `Sandbox.startup()` (same mechanism the
gateway uses). This is the expected recovery path -- orphaned resources do not
accumulate across CI runs on persistent runners.

## Resource Isolation

The CLI and the gateway can run on the same host without conflicts. The sandbox
library's `SandboxConfig.resource_prefix` parameter controls the naming of
container resources:

| Resource        | Gateway (prefix `airut`) | CLI (prefix `airut-cli`) |
| --------------- | ------------------------ | ------------------------ |
| Egress network  | `airut-egress`           | `airut-cli-egress`       |
| Context network | `airut-conv-{id}`        | `airut-cli-conv-{id}`    |
| Proxy container | `airut-proxy-{id}`       | `airut-cli-proxy-{id}`   |

Each sandbox instance performs orphan cleanup scoped to its own prefix on
startup. The gateway's orphan cleanup removes only `airut-conv-*` and
`airut-proxy-*` resources; the CLI's cleanup removes only `airut-cli-conv-*` and
`airut-cli-proxy-*` resources. Neither interferes with the other.

The following resources are safely shared between gateway and CLI:

- **Proxy image** (`airut-proxy`) -- same binary, read-only after build
- **mitmproxy CA certificate** (`~/.airut-mitmproxy/`) -- same CA, shared trust
  store
- **Container images** (`airut-repo:*`, `airut:*`) -- content-addressed, no
  conflicts from concurrent reads

## Network Activity Log

The network proxy records all DNS queries and HTTP(S) requests to a log file
(same format as the gateway's `network-sandbox.log` -- see
`spec/network-sandbox.md`). The log provides a complete audit trail: DNS
resolutions, allowed requests, blocked requests, and upstream errors.

**How it works**: The proxy manager volume-mounts a host file into the proxy
container at `/network-sandbox.log`. Both the DNS responder and the mitmproxy
addon append to this file. Internally, the proxy manager expects a directory
(`network_log_dir`) and creates the file as
`network_log_dir/network-sandbox.log` (see `spec/network-sandbox.md`). The CLI
bridges the user-facing file path to this interface: it creates a temporary
directory, symlinks `network-sandbox.log` inside it to the user's target file
(or to a tempfile), and passes the temporary directory as `network_log_dir`.
This keeps the proxy manager interface unchanged while giving the CLI user
direct control over the output file path.

The CLI always logs the network log file path to stderr at startup (INFO level),
so users know where to find the audit trail even when using the default
temporary location.

**Default behavior** (no `--network-log`): The CLI creates a temporary file and
temporary directory (with the symlink). Both are deleted on exit, including
after errors or signals. The log's content is still observable during execution:
blocked requests (`BLOCKED`) and errors (`ERROR`) are written to both the log
file and the proxy container's stdout (which surfaces on stderr via the
container runtime), so they are visible in CI output without any special flag.

**Explicit file** (`--network-log FILE`): The CLI creates the file if it does
not exist, and appends to it if it already exists. The file persists after exit.
Append semantics allow multiple `airut-sandbox` invocations (e.g., separate CI
steps) to accumulate into a single log file. Each invocation's entries are
delimited by the `=== TASK START ... ===` marker that the proxy already writes.
This is useful for:

- **CI artifact upload** -- save the network log as a build artifact for
  post-hoc audit (e.g., `actions/upload-artifact` with the log path).
- **Debugging** -- inspect the full audit trail (including allowed requests and
  DNS) when troubleshooting network issues.
- **Compliance** -- retain a record of all outbound network activity from
  sandboxed CI runs.

When the network sandbox is disabled (`network_sandbox: false` in
`.airut/sandbox.yaml`), no proxy runs and no network log is written. The
`--network-log` flag is silently ignored (not an error).

## CI Integration Patterns (Future Work)

CI integration patterns (reference GitHub Actions workflows, wrapper scripts,
runner requirements, workflow design guidelines) are planned for a future stage.
The core security model and design guidelines are documented in the Security
Model section above. Key considerations for CI integration:

- Workflows must check out the default branch on the host before running
  `airut-sandbox` (not the merge ref or PR branch)
- The `airut-sandbox` binary must come from a trusted source (PyPI or default
  branch)
- GitHub context values should be passed via `env:` variables, not inline
  `${{ }}` interpolation, to avoid shell injection
- The `airut-sandbox` step should be the terminal step of the job (workspace is
  tainted after execution)
- Runners need rootless podman with cgroup v2 delegation

Full workflow examples and guidelines will be added when this stage is
implemented.

## Not In Scope

- **Persistent daemon mode** -- each invocation is standalone. A daemon mode
  (keeping the proxy running across invocations for faster startup) may be added
  later but is not part of this spec.
- **Dashboard** -- the CLI has no web UI. CI systems provide their own job
  monitoring.
- **Webhook handling** -- the CLI is invoked by the CI system, not by webhooks.
- **Job queuing / concurrency** -- handled by the CI system.
- **Protected file integrity checks** -- the sandbox runs whatever command it is
  given. File-level protection is handled by the default-branch trust model.
- **GitHub commit status updates** -- the CI system handles status reporting.
- **Fork PRs** -- fork PR security is a CI system concern (e.g., GitHub Actions
  `pull_request_target` vs. `pull_request` trigger selection).
