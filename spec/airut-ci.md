# Airut CI

A separate service (`airut-ci`) that runs CI jobs in the same sandbox
infrastructure as the Airut gateway. By executing CI within the Airut sandbox,
GitHub Actions (and similar external CI systems) are removed from the trust
boundary, closing the sandbox escape vector where an agent can craft workflow
files that run arbitrary code with CI secrets.

## Motivation

GitHub Actions workflows execute outside the Airut sandbox. An agent that can
push code to a branch can modify `.github/workflows/` to exfiltrate secrets,
access protected resources, or run arbitrary commands in the CI environment.
This is effectively unpatchable within GitHub Actions constraints -- the
execution environment is controlled by GitHub, not by Airut.

Airut already has a production-quality sandbox: container isolation with
`--cap-drop=ALL`, network allowlisting via transparent proxy, credential masking
with format-preserving surrogates, and resource limits via cgroup v2. Running CI
inside this sandbox gives CI the same security guarantees as agent execution.

## Design Goals

1. **Same sandbox, different task type**: CI jobs reuse the container isolation,
   network sandbox, and credential masking infrastructure. No new isolation
   mechanisms needed.
2. **Independent service**: Airut CI is configured, deployed, and managed
   separately from the gateway. Separate config file, separate systemd unit,
   separate process. Shares the `airut` Python package.
3. **Trusted command source**: The CI command to execute comes from the main
   branch, not from the PR being tested. The agent cannot tamper with what CI
   runs.
4. **Minimal scope**: No dashboard in the initial implementation. GitHub commit
   statuses provide visibility. Dashboard added in a later stage.

## Architecture

### Service Separation

```
airut (Python package)
├── sandbox/          # Shared: container lifecycle, proxy, secrets
├── git_mirror.py     # Shared: bare repo cache
├── allowlist.py      # Shared: network allowlist parsing
├── logging.py        # Shared: log formatting, secret redaction
├── version.py        # Shared: version resolution
├── gateway/          # Gateway-only: email, Slack, channels
├── dashboard/        # Gateway-only (initially): web monitoring
└── ci/               # CI-only: webhook, executor, GitHub status
```

Both services install from the same Python package. Two entry points:

```toml
[project.scripts]
airut = "airut.cli:cli"
airut-ci = "airut.ci.cli:cli"
```

### Component Overview

```
GitHub (webhook)
  |
  v
Webhook Server (HMAC-verified)
  |
  +- Parse event (PR opened/synchronize/reopened, push)
  +- Integrity check (protected files vs. label gate)
  |
  v
Executor
  |
  +- Update git mirror
  +- Set GitHub commit status → "pending"
  +- Checkout workspace at target SHA
  +- Read CI command from main branch config
  +- Start sandbox (container + proxy + secrets)
  +- Run command, capture stdout/stderr/exit code
  +- Set GitHub commit status → "success" or "failure"
  +- Cleanup
```

## Staged Implementation Plan

### Stage 1: Generic Sandbox Library

Make the sandbox library support both Claude Code execution and arbitrary
command execution. Currently the sandbox is coupled to Claude Code at the
execution layer (command construction, output parsing, result types). The
infrastructure layer (container lifecycle, networking, resource limits) is
already generic.

#### 1.1 Extract `ResourceLimits` from Gateway Config

`ResourceLimits` is defined in `airut/gateway/config.py` but imported by
`airut/sandbox/task.py` and `airut/sandbox/sandbox.py`. Move it to
`airut/sandbox/types.py` so the sandbox has no gateway imports.

#### 1.2 Extract Container Infrastructure

Factor out the generic container execution logic from `Task._run_container()`
into a lower-level function. This function handles:

- Building the `podman run` command (security flags, mounts, env, resource
  limits, network args)
- Process lifecycle (Popen, stdin/stdout/stderr, timeout, SIGKILL)
- Process tracking for `stop()`

The function is parameterized on the command to run (instead of hardcoding
`["claude", ...]`), what to write to stdin (optional), and how to process stdout
(line callback).

```
_run_container(
    container_command: str,
    image_tag: str,
    mounts: list[Mount],
    env: ContainerEnv,
    resource_limits: ResourceLimits,
    network_args: list[str],
    extra_mounts: list[tuple[Path, str]],   # e.g., claude/ dir
    command: list[str],                      # e.g., ["claude", ...] or ["uv", "run", ...]
    stdin_data: str | None,                  # prompt for Claude, None for CI
    on_stdout_line: Callable[[str], None] | None,
    timeout: int | None,
    process_tracker: _ProcessTracker,
) -> _RawResult
```

`_RawResult` contains only generic fields: `stdout`, `stderr`, `exit_code`,
`duration_ms`, `timed_out`.

#### 1.3 Refactor Task into AgentTask

Rename `Task` to `AgentTask`. It wraps `_run_container()` and adds Claude-
specific behavior:

- Constructs the `["claude", "--resume", ..., "--model", ..., "-p", "-", ...]`
  command
- Parses stdout lines as `StreamEvent` via `parse_event()`
- Appends events to `EventLog`
- Manages the `claude/` session state directory
- Calls `build_execution_result()` to produce `ExecutionResult`

Public API remains the same:

```
AgentTask.execute(prompt, *, session_id, model, on_event) -> ExecutionResult
AgentTask.stop() -> bool
```

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
- Writes stdout/stderr to a log file in `execution_context_dir` for later
  retrieval
- Optionally invokes `on_output` callback per stdout line (for live streaming)
- Shares proxy start/stop, container security flags, resource limits, and
  process management with `AgentTask` via `_run_container()`

#### 1.5 Parameterize Entrypoint Generation

The entrypoint script currently hardcodes `exec claude "$@"`. Make
`get_entrypoint_content()` accept a parameter:

```
get_entrypoint_content(command: str = "claude") -> bytes
```

For agent tasks, continues to use `exec claude "$@"`. For command tasks, uses
`exec "$@"` (pass-through to whatever command is specified).

`Sandbox.ensure_image()` accepts an optional `entrypoint_command` parameter. The
overlay image hash incorporates the entrypoint content, so different entrypoints
produce different overlay images (correctly cached separately).

#### 1.6 Update Sandbox.create_task()

`Sandbox` gains a `create_command_task()` method alongside the existing
`create_task()` (which continues to return `AgentTask`):

```
Sandbox.create_task(...)         -> AgentTask     # Claude Code execution
Sandbox.create_command_task(...) -> CommandTask    # Arbitrary command execution
```

Both methods share the same infrastructure: image tag, mounts, env, network
sandbox, resource limits, proxy manager. The difference is what task class is
instantiated and what state is created (claude/ dir vs. log file).

### Stage 2: Shared Infrastructure

Make supporting code reusable across the gateway and CI services.

#### 2.1 Shared Configuration Types

Extract configuration types that both services need into a shared module (e.g.,
`airut/config_types.py` or keep in `airut/sandbox/types.py`):

- `ResourceLimits` (done in Stage 1.1)
- Secret resolution types (plain secrets, masked secrets, signing credentials)
- Network sandbox configuration types

The gateway's `config.py` and the CI service's config module both import from
the shared types.

#### 2.2 Secret Resolution

Both services need to resolve `!env` tags in YAML and prepare secrets for the
sandbox (plain injection, surrogate generation, replacement maps). Extract the
secret resolution logic from `gateway/config.py` into a shared module.

#### 2.3 Git Mirror Integration

Both services use `GitMirrorCache` for bare repo clones. The git mirror module
is already standalone -- no changes needed. Both services instantiate their own
`GitMirrorCache` instances.

#### 2.4 Workspace Preparation

Both services need to clone a workspace from the mirror at a specific ref.
Extract the git checkout logic (clone from mirror, checkout ref, configure
identity) into a shared utility. The gateway's `ConversationManager` uses this
for conversations; the CI executor uses it for CI jobs.

### Stage 3: CI Service Implementation

#### 3.1 Configuration

CI service has its own server config file, separate from the gateway:

```yaml
# ~/.config/airut/airut-ci.yaml

container_command: podman    # or docker

webhook:
  host: "127.0.0.1"         # bind address (behind reverse proxy)
  port: 5201

resource_limits:             # server-wide ceilings (optional)
  timeout: 900
  memory: "8g"

repos:
  my-project:
    git_url: "https://github.com/org/my-project.git"
    webhook_secret: !env WEBHOOK_SECRET

    # CI command (read from main, not from PR branch)
    command: ["uv", "run", "scripts/ci.py"]

    # GitHub API token for commit status updates
    # Needs: repo:status (or broader repo scope)
    github_token: !env GH_TOKEN

    # Trigger rules
    triggers:
      pull_request: [opened, synchronize, reopened]

    # Secrets available in CI containers
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes: ["api.github.com"]
        headers: ["Authorization"]

    # Protected files -- CI skipped if modified without approval
    integrity:
      protected_patterns:
        - "scripts/ci.py"
        - ".airut/**"
      approval_label: "ci-approved"

    # Per-repo resource limits (clamped to server ceilings)
    resource_limits:
      timeout: 600
      memory: "4g"
      cpus: 4

    network:
      sandbox_enabled: true
```

#### 3.2 Webhook Server

HTTP server that receives GitHub webhook events. Responsibilities:

- **HMAC validation**: Verify `X-Hub-Signature-256` header against
  `webhook_secret`. Reject requests that fail validation.
- **Event dispatch**: Route `pull_request` and `push` events to the executor.
  Ignore other event types.
- **Repo routing**: Match webhook to configured repo by repository full name
  from the payload.
- **Idempotency**: Track `X-GitHub-Delivery` header to deduplicate redelivered
  webhooks.

The webhook server is a standalone WSGI application (Werkzeug), similar to the
gateway's dashboard server. It runs in a background thread.

#### 3.3 Executor

The executor manages CI job lifecycle:

01. **Parse trigger**: Extract repo, SHA, PR number (if applicable), branch from
    webhook payload.
02. **Integrity check**: Diff the PR against main. If any file matching
    `integrity.protected_patterns` is modified, check if the PR has the
    `integrity.approval_label`. If not, set commit status to "failure" with
    description "CI requires approval: protected files modified" and skip
    execution.
03. **Update mirror**: Fetch latest from origin.
04. **Prepare workspace**: Clone from mirror at the target SHA.
05. **Read CI command**: The command comes from the CI service config (which
    references what's in main). The workspace contains the PR code being tested.
06. **Prepare sandbox**: Build/reuse container image from `.airut/container/`
    (read from main branch mirror). Resolve secrets and create network sandbox
    config.
07. **Set commit status**: Set GitHub commit status to "pending".
08. **Execute**: Create `CommandTask`, run the configured command.
09. **Report result**: Set GitHub commit status based on exit code:
    - Exit 0 → "success"
    - Exit non-zero → "failure"
    - Timeout → "error" with description "CI timed out"
    - Infrastructure failure → "error"
10. **Cleanup**: Remove workspace.

#### 3.4 Cancel-in-Progress

When a new webhook arrives for the same (repo, PR number), cancel any in-flight
CI job for that PR:

- The executor maintains a map: `(repo_id, pr_number) → running_task`
- On new event, call `task.stop()` on the existing task (SIGTERM → SIGKILL)
- The cancelled job's commit status is superseded by the new job's status

#### 3.5 Concurrency

- Thread pool with configurable `max_concurrent_jobs` (default: 2)
- Jobs exceeding the limit are queued
- Per-repo fair scheduling: round-robin across repos when multiple jobs are
  queued

#### 3.6 GitHub Commit Status

Use the GitHub API to set commit statuses:

```
POST /repos/{owner}/{repo}/statuses/{sha}
{
  "state": "pending" | "success" | "failure" | "error",
  "target_url": "https://dashboard.example.com/ci/{job_id}",
  "description": "CI running...",
  "context": "airut-ci"
}
```

The `github_token` in config needs `repo:status` scope (or `repo` for private
repos).

The `target_url` is omitted in Stage 3 (no dashboard). Stage 4 adds it.

#### 3.7 Log Storage

CI stdout/stderr is stored in the execution context directory:

```
{storage_dir}/{repo_id}/ci/{job_id}/
├── stdout.log          # Full stdout
├── stderr.log          # Full stderr
├── network-sandbox.log # Network activity (if sandbox enabled)
└── job.json            # Job metadata (SHA, PR, status, duration, timestamps)
```

Retention: configurable, default 7 days. A periodic cleanup thread removes old
job directories.

#### 3.8 CLI

```
airut-ci run-service [--config PATH]     # Start CI service
airut-ci check                           # Verify config and dependencies
airut-ci install-service                 # Create systemd unit
airut-ci uninstall-service               # Remove systemd unit
```

### Stage 4: CI Dashboard

#### Stage 4a: Shared Dashboard Components

Before building the CI dashboard, extract reusable components from the gateway
dashboard:

- **VersionClock + VersionedStore** (`dashboard/versioned.py`): Already generic.
  No changes needed.
- **SSE infrastructure** (`dashboard/sse.py`): SSE message formatting, state
  stream generator, connection manager. Already generic.
- **WSGI application base**: Security headers, ETag support, health endpoint
  pattern. Extract into a shared base class or utility module.
- **Network log viewer**: The gateway dashboard's network log viewer
  (`/conversation/{id}/network` and SSE stream) can be reused for CI jobs. The
  `NetworkLog` class is already in the sandbox library.
- **HTML rendering utilities**: Shared CSS, page layout template, card
  components.

Components that remain gateway-specific:

- **TaskTracker**: Gateway-specific states (QUEUED, AUTHENTICATING, PENDING,
  EXECUTING). CI has simpler states (QUEUED, RUNNING, COMPLETED).
- **Boot progress reporting**: Gateway-specific boot phases (proxy, repos,
  ready).
- **Conversation/reply model**: Email-specific concept.
- **TodoItem tracking**: Claude-specific (TodoWrite tool calls).

#### Stage 4b: CI Dashboard Implementation

A web dashboard for CI job monitoring, similar in style to the gateway dashboard
but with CI-specific views.

##### Job States

```
QUEUED → RUNNING → COMPLETED
```

Completion reasons: `success`, `failure`, `error`, `cancelled`, `skipped`
(integrity check failed).

##### HTTP Endpoints

| Route                              | Method | Description                        |
| ---------------------------------- | ------ | ---------------------------------- |
| `/`                                | GET    | Main dashboard: recent CI jobs     |
| `/job/{job_id}`                    | GET    | Job detail: logs, status, metadata |
| `/job/{job_id}/network`            | GET    | Network logs viewer                |
| `/api/health`                      | GET    | Health check                       |
| `/api/jobs`                        | GET    | JSON API: job list (ETag)          |
| `/api/job/{job_id}`                | GET    | JSON API: single job               |
| `/api/job/{job_id}/stop`           | POST   | Cancel a running job               |
| `/api/events/stream`               | GET    | SSE: job state updates             |
| `/api/job/{job_id}/log`            | GET    | SSE: live stdout stream            |
| `/api/job/{job_id}/network/stream` | GET    | SSE: network log stream            |

##### Main Dashboard

Lists CI jobs grouped by status:

- **Running**: Job ID, repo, PR/branch, duration so far, live stdout tail
- **Completed**: Job ID, repo, PR/branch, result, duration, timestamp

Each job links to its detail page. The `target_url` in GitHub commit status
points to the job detail page.

##### Job Detail

- **Summary card**: Repo, PR number, branch, SHA (linked to GitHub), status,
  duration, timestamps
- **Stdout viewer**: Full stdout with ANSI color rendering, live-updating via
  SSE while job is running
- **Stderr section**: If non-empty
- **Network log link**: To `/job/{job_id}/network`

##### Configuration

```yaml
# In airut-ci.yaml
dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 5202
  base_url: "https://ci.example.com"   # For target_url in commit statuses
```

Port 5202 to avoid conflicts with the gateway dashboard (5200).

## Trusted Command Source

### Threat Model

An agent (or malicious PR author) can modify any file in the PR branch. If CI
runs code from the PR branch, the attacker controls the CI execution. The
sandbox prevents network exfiltration and credential leakage, but CI secrets may
grant different access than agent secrets (e.g., deploy keys, registry tokens).

### Mitigation

The CI command itself comes from the CI service's server configuration, which
references a command that exists in the main branch. The workspace is checked
out at the PR's SHA (the code being tested), but what command executes is
controlled by the server operator, not the PR author.

The container image (`.airut/container/Dockerfile`) and network allowlist
(`.airut/network-allowlist.yaml`) are read from the main branch mirror, not from
the PR branch. This is the same trust model the gateway already uses for network
allowlists.

### Protected File Integrity

For additional defense-in-depth, the CI service can be configured with protected
file patterns. If a PR modifies files matching these patterns, CI does not run
unless the PR has an approval label.

This prevents scenarios where:

- A PR modifies `scripts/ci.py` to skip checks or exfiltrate data
- A PR modifies `.airut/` configuration to weaken sandbox constraints
- A PR modifies the Dockerfile to install malicious tools

The approval label can only be added by users with write access to the repo. The
agent should not be granted permission to add labels (enforce via GitHub token
scoping: use a token without `issues:write` scope for the agent, and a separate
token with appropriate scope for humans).

```
PR modifies protected file?
  ├── No  → Run CI normally
  └── Yes → PR has approval label?
        ├── Yes → Run CI normally
        └── No  → Set status "failure: protected files modified, needs approval"
```

## Secret Scoping

CI jobs may need different secrets than agent tasks. The two services have
completely independent secret configurations:

| Concern           | Gateway                         | CI                              |
| ----------------- | ------------------------------- | ------------------------------- |
| Config file       | `~/.config/airut/airut.yaml`    | `~/.config/airut/airut-ci.yaml` |
| Secrets           | Per-repo in gateway config      | Per-repo in CI config           |
| Masked secrets    | Per-repo in gateway config      | Per-repo in CI config           |
| Network allowlist | `.airut/network-allowlist.yaml` | Same (from main branch)         |
| Container image   | `.airut/container/Dockerfile`   | Same (from main branch)         |

This clean separation means:

- CI can have secrets the agent never sees (deploy keys, registry tokens)
- The agent can have secrets CI doesn't need (Anthropic API key for agent tasks
  where CI doesn't invoke Claude)
- Compromise of one service's config doesn't affect the other

## Resource Scoping

CI and gateway run as separate processes. Their sandbox instances are
independent:

| Resource            | Sharing                                         |
| ------------------- | ----------------------------------------------- |
| Proxy image         | Both build the same image; podman deduplicates  |
| Egress network      | Separate instances (different names)            |
| Container images    | Shared via podman image cache (same Dockerfile) |
| Thread pools        | Separate (independent concurrency limits)       |
| Git mirrors         | Separate instances (separate cache directories) |
| Storage directories | Separate directory trees                        |

This avoids coordination between the two services. The only shared state is the
podman image cache, which is naturally deduplicated by content hash.

## Not In Scope

- **Matrix / GitLab / Bitbucket webhooks**: GitHub only in initial
  implementation. The architecture supports other providers but they are not
  specified here.
- **Artifact upload**: CI jobs handle their own artifact management (e.g.,
  uploading to GitHub releases). The CI service does not provide artifact
  storage.
- **Build matrix / parallel jobs**: Each webhook triggers one job running one
  command. Parallelism is handled within the CI command itself (e.g., `ci.py`
  running checks in sequence).
- **Re-run from dashboard**: The dashboard is read-only monitoring. Re-runs are
  triggered by pushing to the PR or redelivering the webhook from GitHub.
- **Webhook endpoint for non-GitHub sources**: Deferred to future work.
