# Airut Sandbox CLI

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
PRs). By using masked secrets (§2.5), the container never sees real credential
values -- only surrogates that the proxy replaces on matching outbound requests.
This means compromised test code cannot exfiltrate API keys even if it finds a
way to make network requests outside the allowlist.

| Workflow type                                         | Auto-trigger safe? | Why                                           |
| ----------------------------------------------------- | ------------------ | --------------------------------------------- |
| Runs no agent-steerable code                          | Yes                | Agent can't influence execution               |
| Runs agent-steerable code, **no sandbox**             | No                 | Must use `workflow_dispatch` (manual trigger) |
| Runs agent-steerable code, **inside `airut-sandbox`** | Yes                | Agent-steered code contained by sandbox       |

The security relies on the default-branch trust model:

- **Sandbox configuration** is loaded from the default branch checkout, not from
  the PR branch. The agent cannot tamper with the Dockerfile, network allowlist,
  or secret masking rules. This requires the workflow to explicitly check out
  the default branch (see §3.1 and §3.3 guideline 2).
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
  are exposed to agent-triggered pipelines and use masked secrets (§2.5) for all
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

| Risk                                                 | Mitigation                                                                                                                 |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Agent pushes workflow file with `workflow` PAT scope | Omit `workflow` scope from agent PAT (GitHub enforces at git push level)                                                   |
| Workflow checks out PR branch before running sandbox | Workflow design: main-branch checkout first, PR code only inside sandbox                                                   |
| Agent modifies `airut-sandbox` implementation        | Install from PyPI/trusted source, or check out from default branch                                                         |
| Sandbox escape via container vulnerability           | Same risk as gateway; mitigated by `--cap-drop=ALL`, `no-new-privileges`                                                   |
| Sandbox infrastructure failure                       | Fail-secure: workflow step fails, agent code does not run unsandboxed                                                      |
| Expression injection in workflow `run:` scripts      | Pass GitHub context via `env:` variables, not inline `${{ }}` interpolation (see §3.3 guideline 9)                         |
| Tainted workspace after sandbox execution            | Make `airut-sandbox` the terminal job step; post-sandbox steps must not execute workspace binaries (see §3.3 guideline 10) |

The primary operational risk is a misconfigured workflow that checks out the PR
branch (or the default merge ref) on the host before running `airut-sandbox`,
allowing the PR to tamper with `.airut/` config or sandbox implementation. On
`pull_request` events, `actions/checkout` without an explicit `ref:` checks out
the merge commit (`refs/pull/<number>/merge`), which includes PR changes -- this
is the default behavior and must be overridden. The reference workflow (Stage 3)
uses `ref: ${{ github.event.pull_request.base.ref }}` to ensure only trusted
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

### Relationship to Existing Code

```
airut (Python package)
├── sandbox/              # Shared: container lifecycle, proxy, secrets
│   ├── sandbox.py        #   Sandbox facade (startup, shutdown, image, tasks)
│   ├── task.py           #   AgentTask (Claude Code execution) [renamed from Task]
│   ├── command_task.py   #   CommandTask (arbitrary command execution) [new]
│   ├── _run_container.py #   Shared container execution [new, extracted]
│   ├── _image.py         #   Two-layer image build
│   ├── _proxy.py         #   Proxy lifecycle
│   ├── _network.py       #   Network args
│   ├── _entrypoint.py    #   Entrypoint generation [parameterized]
│   ├── secrets.py        #   Secret masking
│   ├── event_log.py      #   Event log (agent tasks only)
│   ├── network_log.py    #   Network activity log
│   └── types.py          #   Shared types (Mount, ContainerEnv, ResourceLimits)
├── allowlist.py          # Shared: network allowlist parsing
├── cli.py                # Gateway CLI (existing)
├── sandbox_cli.py        # airut-sandbox CLI entry point [new]
├── gateway/              # Gateway-only: email, Slack, channels
└── dashboard/            # Gateway-only: web monitoring
```

The CLI (`airut/sandbox_cli.py`) imports from `airut.sandbox` and
`airut.allowlist`. It does not import from `airut.gateway`.

## Staged Implementation Plan

### Stage 1: Generic Sandbox Library

Make the sandbox library support both Claude Code execution and arbitrary
command execution. Currently the sandbox is coupled to Claude Code at the
execution layer (command construction, output parsing, result types). The
infrastructure layer (container lifecycle, networking, resource limits) is
already generic.

**Spec cross-references**: Stage 1 changes require updating `spec/sandbox.md`
(Task rename, new CommandTask) and `spec/image.md` (parameterized entrypoint
contract). These updates are included in the Stage 1 implementation.

#### 1.1 Move `ResourceLimits` to Sandbox Types

`ResourceLimits` is defined in `airut/gateway/config.py` but imported by
`airut/sandbox/task.py` and `airut/sandbox/sandbox.py`. Move it to
`airut/sandbox/types.py` so the sandbox has no gateway imports.

This requires moving `ResourceLimits` together with its supporting code:

- `_MEMORY_PATTERN` regex
- `_validate_memory()` function (used by `ResourceLimits.__post_init__()`)
- `_parse_memory_bytes()` function (used by `ResourceLimits.clamp()`)

The gateway config parsing function `_parse_resource_limits()` remains in
`airut/gateway/config.py` (it depends on `_resolve()`, which is gateway-specific
YAML resolution). The gateway's `config.py` imports `ResourceLimits` from
`airut.sandbox.types` instead.

#### 1.2 Extract Container Infrastructure

Factor out the generic container execution logic from `Task._run_container()`
into a lower-level function in `airut/sandbox/_run_container.py`. This function
handles:

- Building the `podman run` command (security flags, mounts, env, resource
  limits, network args)
- Process lifecycle (Popen, stdin/stdout/stderr, timeout, SIGKILL)
- Process tracking for `stop()`

The function is parameterized on the command to run (instead of hardcoding
`["claude", ...]`), what to write to stdin (optional), and how to process stdout
(line callback).

```
_run_container(
    container_command: str,             # "podman" or "docker"
    image_tag: str,
    mounts: list[Mount],                # all mounts (caller + task-specific)
    env: ContainerEnv,
    resource_limits: ResourceLimits,
    network_args: list[str],
    command: list[str],                 # e.g., ["claude", ...] or ["uv", "run", ...]
    stdin_data: str | None,             # prompt for Claude, None for CI
    on_stdout_line: Callable[[str], None] | None,
    timeout: int | None,
    process_tracker: _ProcessTracker,
) -> _RawResult
```

`_RawResult` contains only generic fields: `stdout`, `stderr`, `exit_code`,
`duration_ms`, `timed_out`.

Each task class is responsible for assembling its own mounts list (including
task-specific mounts like the `claude/` directory for `AgentTask`) and passing
the complete list to `_run_container()`.

#### 1.3 Refactor Task into AgentTask

Rename `Task` to `AgentTask`. It wraps `_run_container()` and adds
Claude-specific behavior:

- Constructs the `["claude", "--resume", ..., "--model", ..., "-p", "-", ...]`
  command
- Adds the `claude/` session state directory to the mounts list
- Parses stdout lines as `StreamEvent` via `parse_event()`
- Appends events to `EventLog`
- Calls `build_execution_result()` to produce `ExecutionResult`

The method signatures remain the same:

```
AgentTask.execute(prompt, *, session_id, model, on_event) -> ExecutionResult
AgentTask.stop() -> bool
```

The class rename (`Task` -> `AgentTask`) is a public API change. All callers
must be updated:

- `airut/sandbox/__init__.py` -- update exports and `__all__`
- `airut/sandbox/sandbox.py` -- `create_task()` return type annotation
- `airut/gateway/service/message_processing.py` -- gateway caller
- All tests in `tests/sandbox/` that reference `Task`

`create_task()` continues to work as before (returns `AgentTask`). New tests for
`CommandTask` and `create_command_task()` are added alongside.

#### 1.4 Add CommandTask

A new task class for running arbitrary commands in the sandbox:

```
CommandTask(
    execution_context_id: str,
    *,
    image_tag: str,
    mounts: list[Mount],
    env: ContainerEnv,
    execution_context_dir: Path,
    network_log_dir: Path | None,
    network_sandbox: NetworkSandboxConfig | None,
    resource_limits: ResourceLimits,
    container_command: str,
    proxy_manager: ProxyManager | None,
)

CommandTask.execute(
    command: list[str],
    *,
    on_output: Callable[[str], None] | None = None,
) -> CommandResult

CommandTask.stop() -> bool
```

`CommandResult` is a simple result type:

```python
@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
```

`CommandTask`:

- Does **not** create or mount a `claude/` directory
- Does **not** parse stdout as streaming JSON
- Does **not** write to `events.jsonl`
- Closes stdin immediately (passes `stdin_data=None` to `_run_container()`)
- Optionally invokes `on_output` callback per stdout line (for live streaming)
- Shares proxy start/stop, container security flags, resource limits, and
  process management with `AgentTask` via `_run_container()`

#### 1.5 Parameterize Entrypoint Generation

The entrypoint script currently hardcodes `exec claude "$@"`. Make
`get_entrypoint_content()` accept a parameter:

```python
def get_entrypoint_content(*, passthrough: bool = False) -> bytes: ...
```

When `passthrough=False` (default, agent tasks): `exec claude "$@"`. When
`passthrough=True` (command tasks): `exec "$@"`. Both entrypoints retain
`IS_SANDBOX=1` and CA certificate trust setup.

`Sandbox.ensure_image()` accepts an optional `passthrough_entrypoint` parameter,
which flows through to `build_overlay_image()`. The overlay image hash
incorporates the entrypoint content, so different entrypoints produce different
overlay images (correctly cached separately in both the in-memory
`_overlay_images` dict and podman's image store). The gateway and CLI will never
share a `Sandbox` instance, but even if they did, both overlay variants would
coexist without conflict.

#### 1.6 Update Sandbox API

`Sandbox` gains a `create_command_task()` method alongside the existing
`create_task()` (which continues to return `AgentTask`):

```
Sandbox.create_task(...)         -> AgentTask     # Claude Code execution
Sandbox.create_command_task(...) -> CommandTask    # Arbitrary command execution
```

Both methods share the same infrastructure: image tag, mounts, env, network
sandbox, resource limits, proxy manager. The difference is what task class is
instantiated and what per-task state is created: `AgentTask` creates the
`claude/` session directory and event log; `CommandTask` creates only the
network log (if `network_log_dir` is provided). The `network_log_dir` parameter
is accepted by both task types. For the gateway, this is the conversation
directory (persistent). For the CLI, it is a temporary directory containing a
symlink to the target log file (see §2.14).

### Stage 2: CLI Implementation

#### 2.1 Entry Point

A new CLI entry point registered in `pyproject.toml`:

```toml
[project.scripts]
airut = "airut.cli:cli"
airut-sandbox = "airut.sandbox_cli:main"
```

The existing `airut/cli.py` (gateway CLI) remains unchanged. The new
`airut/sandbox_cli.py` is a separate module.

#### 2.2 CLI Interface

```
airut-sandbox run [OPTIONS] -- COMMAND [ARGS...]

Options:
  --config PATH          Sandbox config (default: .airut/sandbox.yaml)
  --dockerfile PATH      Path to Dockerfile (default: .airut/container/Dockerfile)
  --context-dir PATH     Build context directory (default: .airut/container/)
  --allowlist PATH       Network allowlist override (must be subset of default)
  --timeout SECONDS      Container timeout (overrides config)
  --container-command CMD  Container runtime (default: podman)
  --mount SRC:DST[:ro]   Additional mount (repeatable)
  --network-log FILE     Append network activity log to FILE (created if needed; default: tempfile, deleted on exit)
  --verbose              Verbose logging (debug-level output on stderr)
  --quiet                Suppress all diagnostic output (errors only)
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
exit. When not specified (the default), the log is written to a temporary file
that is deleted when `airut-sandbox` exits. See §2.14 for details on log content
and lifecycle.

#### 2.3 Configuration Resolution

Configuration is resolved from multiple sources, with later sources overriding
earlier ones:

1. **Defaults** -- sensible defaults for all options
2. **`.airut/sandbox.yaml`** -- sandbox config for environment variables, masked
   secrets, signing credentials, network sandbox settings, and resource limits
   (see §2.4)
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

#### 2.4 Sandbox Config (`.airut/sandbox.yaml`)

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
directory). In the CI workflow pattern (§3.1), the host filesystem contains the
default-branch checkout, so the agent cannot tamper with the list of env vars,
secrets, or network sandbox settings. This is the same trust model used for the
Dockerfile and network allowlist.

#### 2.5 Credential Handling

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

#### 2.6 Workspace Mounting

By default, the current working directory is mounted read-write at `/workspace`
inside the container, and the container's working directory is set to
`/workspace`. This differs from the gateway (which mounts read-only) because CI
commands typically need write access: test reports, coverage files, formatter
auto-fixes, lockfile updates, and build artifacts all write to the working
directory.

Additional mounts are specified via `--mount`. To override the default with a
read-only workspace: `--mount .:/workspace:ro`.

#### 2.7 Exit Code Passthrough

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
message to stderr: "Container killed by memory limit (OOM). Consider increasing
--memory."

#### 2.8 Signal Handling

The CLI forwards signals to the container process:

- **SIGTERM**: Forwarded to container (graceful shutdown). If the container
  doesn't exit within 5 seconds, SIGKILL.
- **SIGINT**: Same as SIGTERM (Ctrl-C in terminal or CI cancellation).

#### 2.9 Stdout/Stderr Streaming

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

#### 2.10 Lifecycle

```
airut-sandbox run -- <command>
  |
  +- Parse CLI args
  +- Load .airut/sandbox.yaml (env, secrets, resource limits, network settings)
  +- Resolve !env tags from host environment (fail-closed on missing vars)
  +- Load .airut/network-allowlist.yaml (or --allowlist override)
  +- Create network log file (--network-log FILE or tempfile)
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

#### 2.11 Startup Overhead

Each `airut-sandbox run` invocation performs sandbox startup (orphan cleanup,
proxy image check, CA cert check, egress network creation) and shutdown (network
removal). This overhead is acceptable for single-step CI jobs but adds up for
pipelines with multiple sandboxed steps.

Workarounds for multi-step pipelines:

- **Combine steps**: Run all CI checks in a single `airut-sandbox run`
  invocation (e.g., `airut-sandbox run -- uv run scripts/ci.py` where `ci.py`
  runs lint, typecheck, and tests sequentially).
- **Persistent daemon mode**: Deferred to future work (see "Not In Scope").

#### 2.12 Image Staleness in CI

The sandbox's 24-hour image staleness check (see `spec/image.md`) triggers
periodic rebuilds to pick up upstream tool updates. In CI, where runners are
ephemeral and images are built from scratch, the staleness check is not
applicable -- images are always "fresh" because the in-memory build timestamp
cache starts empty on each invocation. The first build always runs; subsequent
builds within the same invocation (if any) reuse the cached image.

For CI runners with persistent podman image caches (self-hosted runners), the
staleness check applies normally.

#### 2.13 Crash Recovery

If `airut-sandbox` is killed by SIGKILL (CI timeout, host OOM), the container,
proxy, and internal network are orphaned. The next `airut-sandbox run`
invocation cleans these orphans during `Sandbox.startup()` (same mechanism the
gateway uses). This is the expected recovery path -- orphaned resources do not
accumulate across CI runs on persistent runners.

#### 2.14 Network Activity Log

The network proxy records all DNS queries and HTTP(S) requests to a log file
(same format as the gateway's `network-sandbox.log` -- see
`spec/network-sandbox.md` §Session Network Logging). The log provides a complete
audit trail: DNS resolutions, allowed requests, blocked requests, and upstream
errors.

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

### Stage 3: CI Integration Patterns

This stage is documentation and examples, not new code.

#### 3.1 GitHub Actions Usage

The workflow checks out main (trusted), then runs `airut-sandbox` with a wrapper
script that checks out the PR code inside the sandbox:

```yaml
name: CI
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  test:
    runs-on: self-hosted
    steps:
      # SECURITY: Explicitly check out the default branch, not the merge ref.
      # On pull_request events, actions/checkout without ref: checks out the
      # merge commit (refs/pull/<number>/merge), which includes PR changes to
      # .airut/ config. The ref: parameter ensures only trusted default-branch
      # config is on the host filesystem when airut-sandbox reads it.
      # fetch-depth: 0 so the wrapper script can checkout the PR SHA.
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.ref }}
          fetch-depth: 0

      - name: Run CI in sandbox
        env:
          # Pass the PR SHA via an environment variable, not inline in run:.
          # Interpolating ${{ github.event.* }} directly into run: scripts is
          # a shell injection vector. A git SHA is hex-safe, but establishing
          # the pattern invites copy-paste mistakes with unsafe fields like
          # pull_request.title. Environment variables are not subject to shell
          # expansion in the YAML value position.
          PR_SHA: ${{ github.event.pull_request.head.sha }}
          # Secrets are made available as host env vars for sandbox.yaml
          # !env resolution. The config file controls which secrets enter
          # the container and whether they are masked or plain.
          GH_TOKEN: ${{ secrets.GH_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          # .airut/sandbox.yaml defines secrets (masked), env vars, and
          # resource limits. Config is read from CWD (default branch, trusted).
          # scripts/sandbox-ci.sh checks out the PR inside the container.
          airut-sandbox run \
            -- scripts/sandbox-ci.sh "$PR_SHA"
```

The wrapper script lives on main and handles workspace preparation inside the
sandbox:

```bash
#!/usr/bin/env bash
# scripts/sandbox-ci.sh -- checked into repo on main branch
set -euo pipefail

if [ $# -eq 1 ]; then
    # PR CI: merge the PR commit into the default branch before running checks.
    # A plain "git checkout" would test the PR in isolation, missing integration
    # issues with changes that have landed on main since the PR branch diverged.
    # Using "git merge --no-edit" tests the integrated result, matching what the
    # repository will look like after the PR is actually merged.
    # If the merge fails (conflicts), exit non-zero so CI reports the failure.
    git merge --no-edit "$1"
fi

# Run the actual CI checks
exec uv run scripts/ci.py
```

**Why `git merge` instead of `git checkout`**: A plain `git checkout "$1"` tests
the PR code in isolation, without recent changes to main. This means CI may pass
even though the PR conflicts with or breaks against the current default branch.
Using `git merge --no-edit "$1"` inside the container tests the integrated
result -- the same code that will exist after the PR is merged. If the merge
fails (due to conflicts), CI exits non-zero, which is the correct behavior. Note
that if the repository requires branches to be up-to-date before merging (a
common branch protection rule), the merge and checkout approaches are
equivalent, since CI only runs when the PR branch already includes all main
commits.

**Security**: This follows the default-branch trust model from the Security
Model section. The workflow file, `.airut/` config, and the `airut-sandbox`
implementation all come from trusted sources (default branch for the Airut repo,
PyPI for third-party repos). The wrapper script comes from the default branch in
practice but does not need to be trusted -- it runs inside the sandbox alongside
the PR code.

**Why a wrapper script**: `airut-sandbox` is a generic sandboxed execution tool
-- it does not know about git, PRs, or CI. Workspace preparation (checkout,
environment setup, etc.) is the caller's responsibility. This keeps
`airut-sandbox` focused and allows different repos to use different CI patterns
without changing the tool itself.

For workflows triggered by `push` (e.g., post-merge CI on the default branch),
no wrapper script is needed -- the code is already trusted:

```yaml
on:
  push:
    branches: [main]

# ...
      - name: Run CI
        run: airut-sandbox run -- uv run scripts/ci.py
```

#### 3.2 Runner Requirements

The runner needs:

- **podman** (rootless) -- for container and proxy execution
- **cgroup v2** with cpu, memory, pids controllers delegated
- **airut package** installed (provides both `airut` and `airut-sandbox`)

**Self-hosted runners** (recommended): Pre-install podman and airut. This gives
full control over the runtime environment and avoids per-job setup overhead.

```bash
# Install airut-sandbox (included in the airut package)
uv tool install airut

# Verify
airut-sandbox run -- echo "sandbox works"
```

**GitHub-hosted runners** (`ubuntu-latest`): Ubuntu 24.04 includes podman, but
rootless podman with cgroup v2 delegation may require additional configuration
(systemd user slice setup). A setup action would handle this. Until such an
action exists, self-hosted runners are the supported path.

#### 3.3 Workflow Design Guidelines

These guidelines enforce the security model described in the Security Model
section:

01. **Omit `workflow` scope from agent PAT** -- the agent must not be able to
    create or modify workflow files. GitHub enforces this at the git push level.
    See `doc/security.md` for details.

02. **Explicitly check out the default branch on the host** -- the host
    filesystem must contain default-branch `.airut/` config and (for the Airut
    repo) the sandbox implementation when `airut-sandbox` starts. PR code should
    only be checked out inside the sandbox container (via wrapper script).
    **Warning:** on `pull_request` events, `actions/checkout` without an
    explicit `ref:` checks out the merge commit (`refs/pull/<number>/merge`),
    which merges PR changes into the base branch -- including any PR changes to
    `.airut/` config or sandbox code. Always use
    `ref: ${{ github.event.pull_request.base.ref }}` to ensure only trusted
    default-branch files are on the host.

03. **Use a trusted `airut-sandbox` installation** -- the agent must not be able
    to modify the sandbox implementation that enforces containment.

    - **Airut repo**: The default-branch checkout (guideline 2) provides the
      trusted sandbox implementation. Run `airut-sandbox` from the checked-out
      tree (e.g., `uv run airut-sandbox`).
    - **Third-party repos**: Install `airut-sandbox` from PyPI
      (`uv tool install airut`) or from the Airut repo's default branch. The
      sandbox is not part of the consuming repo, so the agent cannot modify it.

04. **Use `fetch-depth: 0`** -- the wrapper script needs the PR commit to be
    available in the git history. Shallow clones may not include it.

05. **Keep wrapper scripts on the default branch** -- the wrapper script runs
    inside the sandbox, so it does not need to be trusted from a security
    perspective. However, keeping it on the default branch is good practice: it
    ensures the CI invocation pattern is human-reviewed and stable, and it is
    naturally available since the host checks out the default branch (guideline
    2).

06. **Workflows running agent-steerable code without `airut-sandbox` must use
    `workflow_dispatch`** -- if a workflow runs repository code that the agent
    can modify but does not wrap it in `airut-sandbox`, it must require manual
    triggering so a human can review changes first. See the Security Model
    section for the full classification.

07. **Manual-trigger workflows for sensitive operations** -- deployment,
    release, and other workflows that need real (unmasked) credentials should
    use `workflow_dispatch` so they can only be triggered by humans.

08. **Design for fail-secure** -- if `airut-sandbox` is not available or fails
    to start, the workflow step must fail. Never structure a workflow where
    agent-steerable code runs as a fallback when sandboxing fails.

09. **Pass GitHub context via environment variables, not inline interpolation**
    -- never interpolate `${{ github.event.* }}` directly into `run:` scripts.
    Instead, assign the value to an `env:` variable and reference it as `$VAR`
    in the script. While some fields (like `head.sha`) are safe by construction
    (hex strings), the pattern encourages copy-paste with unsafe fields like
    `pull_request.title` or `pull_request.body`, which can contain arbitrary
    characters and enable shell injection on the host runner **before the
    sandbox starts**. Environment variables set via `env:` are not subject to
    shell expansion in the YAML value position.

10. **Treat the workspace as tainted after `airut-sandbox` runs** -- the CWD is
    mounted read-write into the container (`/workspace`). The sandboxed command
    (agent-steerable code) can modify any file in the workspace, including
    `.git/config`, `.git/hooks/*`, `Makefile`, `package.json` scripts, and other
    files that downstream tools may implicitly execute. If the workflow has
    steps after `airut-sandbox` (e.g., uploading artifacts, caching, or running
    any host-level command), those steps operate on the now-tainted workspace.
    For example, a modified `.git/config` with a malicious `core.sshCommand`
    would be executed by any subsequent `git` invocation on the host. **The
    `airut-sandbox` step should ideally be the terminal step of the job.** If
    subsequent steps are required, they must not execute binaries from the
    workspace (no `npm run`, no `git` commands, no `make`) and should treat the
    filesystem as untrusted. Safe post-sandbox steps include uploading specific
    files by path (e.g., `actions/upload-artifact` with an explicit path)
    without executing anything from the workspace tree.

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
