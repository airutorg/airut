# Sandbox CLI

Standalone CLI tool (`airut-sandbox`) for running arbitrary commands inside the
Airut sandbox. Exposes the same container isolation, network allowlisting, and
credential masking that the gateway uses, as a standalone tool that can be
invoked from any environment.

For the CI-specific setup guide (GitHub Actions, security requirements, workflow
configuration), see [doc/ci-sandbox.md](../doc/ci-sandbox.md).

## Motivation

The Airut gateway runs Claude Code inside a production-quality sandbox:
container isolation with `--cap-drop=ALL`, network allowlisting via transparent
proxy, credential masking with format-preserving surrogates, and resource limits
via cgroup v2. `airut-sandbox` exposes this as a standalone CLI tool so that
**any** command can run inside the same sandbox — not just Claude Code sessions.

The primary use case is sandboxing agent-steerable code in CI pipelines, but the
tool is generic: it sandboxes whatever command it is given, regardless of who or
what invokes it.

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
airut-sandbox run -- <command>
  |
  +- Load .airut/ config from working directory
  +- Build/reuse container image (Dockerfile from .airut/container/)
  +- Start sandbox (container + network proxy + credential masking)
  +- Run command inside container
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
  --network-log-live     Print network activity to stderr during execution
  --log FILE             Write sandbox log to FILE instead of stderr
  --verbose              Enable informational logging (INFO level)
  --debug                Enable debug logging (DEBUG level, implies --verbose)
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
a **more restrictive** allowlist (e.g., CI may only need `api.github.com` while
the gateway allowlist includes additional hosts for development). There is no
enforcement that the override is a subset -- this is a configuration guideline,
not a technical constraint. A more permissive override would weaken security and
should be avoided.

**`--network-log` behavior**: When specified, the network activity log is
appended to the given file (created if it does not exist) and persists after
exit. When not specified, a temporary log file is created and deleted on exit.
See [Network Activity Log](#network-activity-log) for details.

**`--network-log-live` behavior**: When specified, network log lines are printed
to stderr in real time during execution, prefixed with `[net]`. Each line is
flushed immediately so output appears without buffering delay. This uses the
sandbox library's `on_network_line` callback, which tails the proxy's log file
at 0.5-second polling intervals. Can be combined with `--network-log` to both
persist the full log and stream it live. When the network sandbox is disabled,
the flag has no effect (no proxy runs, so there are no network log lines).

**`--log` behavior**: When specified, sandbox implementation log messages
(startup, image build, shutdown, etc.) are written to the given file instead of
stderr. The file is created if it does not exist and appended to if it already
exists. Parent directories are created automatically. This is useful for
capturing diagnostic logs without polluting the sandboxed command's output.

**Logging levels**: By default, only ERROR and above messages are emitted, so
the terminal shows only the sandboxed command's stdout and stderr. `--verbose`
enables INFO-level messages (sandbox startup, image build progress, shutdown).
`--debug` enables DEBUG-level messages (full container commands, internal
details) and implies `--verbose`. When `--log` is specified, the chosen level
applies to the log file; stderr receives no log output.

**Entrypoint output**: The container entrypoint is silent by default -- the
`update-ca-certificates` step redirects all output to `/dev/null`. When
`--verbose` or `--debug` is used, the entrypoint outputs CA certificate setup
details to stderr. This is controlled via the `AIRUT_VERBOSE` environment
variable, which the CLI injects into the container when `--verbose` or `--debug`
is specified.

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

The CLI reads `.airut/` from the current working directory.

**All environment variables and secrets passed to the container are defined in
the config file.** There are no CLI flags for passing environment variables or
secrets -- this ensures the set of credentials available inside the sandbox is
controlled by the config file, not by command-line arguments.

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
with code 125 and an error message. This is fail-closed -- missing credentials
should not silently result in an uncredentialed run.

**Config file is optional**: If `.airut/sandbox.yaml` does not exist, the CLI
runs with defaults (no env vars, no secrets, network sandbox enabled, default
resource limits). This is appropriate for sandboxing commands that need no
credentials.

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
  needs these credentials.

**When `pass_env` is appropriate for non-secrets:**

- Environment flags (`CI=true`, `PYTHONDONTWRITEBYTECODE=1`) -- use `env:` in
  the config instead (static values don't need host resolution)
- Locale/terminal settings (`TERM`, `LANG`)

## Workspace Mounting

By default, the current working directory is mounted read-write at `/workspace`
inside the container, and the container's working directory is set to
`/workspace`. This differs from the gateway (which mounts read-only) because
commands typically need write access: test reports, coverage files, formatter
auto-fixes, lockfile updates, and build artifacts all write to the working
directory.

Additional mounts are specified via `--mount`. To override the default with a
read-only workspace: `--mount .:/workspace:ro`.

## Exit Code Passthrough

The CLI exits with the sandboxed command's exit code:

| Sandboxed command exit       | `airut-sandbox` exit | Interpretation                                    |
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
(or to the `--log` file when specified) to avoid polluting the command's stdout.
By default (no `--verbose` or `--debug`), only ERROR messages are emitted, so
the terminal output consists solely of the sandboxed command's streams.

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
removal). This overhead is acceptable for single-command use but adds up for
pipelines with multiple sandboxed steps.

Workarounds for multi-step pipelines:

- **Combine steps**: Run all checks in a single `airut-sandbox run` invocation
  (e.g., `airut-sandbox run -- uv run scripts/ci.py` where `ci.py` runs lint,
  typecheck, and tests sequentially).
- **Persistent daemon mode**: Deferred to future work (see "Not In Scope").

### Image Staleness

The sandbox's 24-hour image staleness check (see `spec/image.md`) triggers
periodic rebuilds to pick up upstream tool updates. On ephemeral CI runners,
images are built from scratch every time (the in-memory build timestamp cache
starts empty). For hosts with persistent podman image caches, the staleness
check applies normally.

### Crash Recovery

If `airut-sandbox` is killed by SIGKILL (CI timeout, host OOM), the container,
proxy, and internal network are orphaned. The next `airut-sandbox run`
invocation cleans these orphans during `Sandbox.startup()` (same mechanism the
gateway uses). Orphaned resources do not accumulate across runs on persistent
hosts.

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

**How it works**: The proxy manager accepts a `network_log_path` file path,
touches it, and volume-mounts it into the proxy container at
`/network-sandbox.log`. Both the DNS responder and the mitmproxy addon append to
this file (see `spec/network-sandbox.md`). The CLI passes the user-specified
path (or a temporary file) directly to the proxy manager.

The CLI always logs the network log file path to stderr at startup (INFO level),
so users know where to find the audit trail even when using the default
temporary location.

**Default behavior** (no `--network-log`): The CLI creates a temporary file that
is deleted on exit, including after errors or signals. The log's content is
still observable during execution: blocked requests (`BLOCKED`) and errors
(`ERROR`) are written to both the log file and the proxy container's stdout
(which surfaces on stderr via the container runtime), so they are visible in
output without any special flag.

**Explicit file** (`--network-log FILE`): The CLI creates the file if it does
not exist, and appends to it if it already exists. The file persists after exit.
Append semantics allow multiple `airut-sandbox` invocations to accumulate into a
single log file. Each invocation's entries are delimited by the
`=== TASK START ... ===` marker that the proxy already writes. This is useful
for:

- **Artifact upload** -- save the network log as a build artifact for post-hoc
  audit.
- **Debugging** -- inspect the full audit trail (including allowed requests and
  DNS) when troubleshooting network issues.
- **Compliance** -- retain a record of all outbound network activity from
  sandboxed runs.

When the network sandbox is disabled (`network_sandbox: false` in
`.airut/sandbox.yaml`), no proxy runs and no network log is written. The
`--network-log` flag is silently ignored (not an error).

## Not In Scope

- **Persistent daemon mode** -- each invocation is standalone. A daemon mode
  (keeping the proxy running across invocations for faster startup) may be added
  later but is not part of this spec.
- **Dashboard** -- the CLI has no web UI.
- **Job queuing / concurrency** -- if used in CI, handled by the CI system.
- **Protected file integrity checks** -- the sandbox runs whatever command it is
  given. File-level protection (e.g., ensuring trusted config in CI) is handled
  by the caller.
