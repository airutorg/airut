# Sandbox Library

A standalone library (`airut/sandbox/`) for safe containerized execution of
headless Claude Code. The sandbox owns container lifecycle, network isolation,
event logging, and error detection. Protocol layers (email, Slack, automation)
define what Claude sees (prompts, repos, files, mounts); the sandbox handles how
it runs safely.

## Design Goals

1. **Clean separation**: The sandbox knows nothing about email, conversations,
   or protocol-specific layouts. Callers provide mounts, environment, and
   prompts.
2. **Owned state**: The sandbox owns `events.jsonl` (append-only event log),
   Claude session state (`.claude/`), and `network-sandbox.log` -- it creates,
   reads, and writes these files. Callers specify where to place them.
   Conversation metadata (`conversation.json`) is owned by the protocol layer
   (`airut/conversation/ConversationStore`), not the sandbox.
3. **Typed interface**: No `Any` in the public API. Proper types for allowlists,
   secrets, environment variables, events, and errors.
4. **Explicit lifecycle**: `AgentTask` and `CommandTask` have explicit
   lifecycles -- no context managers. `execute()` is `async` and runs the
   container; `stop()` interrupts from another thread via PID-based signaling.
5. **Outcome classification**: The sandbox classifies results into a single
   `Outcome` enum (success and error kinds) so callers can match on outcome
   rather than parsing stdout/stderr strings.
6. **Entrypoint generation**: The sandbox generates the container entrypoint in
   code, not from an external file. The entrypoint is fundamental to sandbox
   operation (IS_SANDBOX, CA trust). See `spec/image.md` for the two-layer image
   build that uses it.
7. **Secret masking**: The sandbox owns surrogate generation for masked secrets
   and signing credentials. Callers provide real secret values with scope
   metadata; the sandbox generates surrogates, injects them into the container
   environment, and configures the proxy replacement map. See
   `spec/masked-secrets.md` for surrogate format details.

## Execution Context

The sandbox's primary identifier is the **execution context ID** -- an opaque
string that scopes all persistent and runtime state. It groups:

- Event log (`events.jsonl`) and Claude session state (`.claude/` directory)
- Network resources (internal network, proxy container)
- Container naming

The sandbox does not know what the execution context ID represents. It could be
a conversation, a CI run, a one-shot script -- the sandbox treats it as a
grouping key for resources that should persist across multiple `execute()` calls
on the same task.

### Concept Mapping

Protocol layers map their own concepts to the sandbox's execution context:

| Protocol layer | Protocol concept | Sandbox concept        | Task type     |
| -------------- | ---------------- | ---------------------- | ------------- |
| Email gateway  | Conversation ID  | `execution_context_id` | `AgentTask`   |
| CLI            | Run ID           | `execution_context_id` | `AgentTask`   |
| CI automation  | Job ID           | `execution_context_id` | `CommandTask` |

The gateway maps its conversation ID to the sandbox's execution context ID when
creating a task:

```
task = sandbox.create_task(execution_context_id=conv_id, ...)        # AgentTask
task = sandbox.create_command_task(execution_context_id=job_id, ...) # CommandTask
```

This mapping is the only place where protocol-specific knowledge touches the
sandbox API. Everything inside the sandbox operates on the opaque
`execution_context_id`.

## Architecture

### Component Relationships

```
Caller (gateway, CLI, automation)
  |
  +- Sandbox                        # Top-level facade
  |    +- startup/shutdown          # Shared infrastructure
  |    +- ensure_image()            # Two-layer image build
  |    +- create_task()             # Per-execution AgentTask
  |    +- create_command_task()     # Per-execution CommandTask
  |
  +- AgentTask                      # Claude Code execution
  |    +- execute(prompt, ...)      # Proxy start -> container run -> proxy stop
  |    +- stop()                    # Interrupt from another thread
  |    +- event_log                 # Append-only event log (events.jsonl)
  |    +- network_log               # Read network activity
  |
  +- CommandTask                    # Arbitrary command execution
       +- execute(command)          # Proxy start -> container run -> proxy stop
       +- stop()                    # Interrupt from another thread
       +- network_log               # Read network activity
```

### Async Process Model

Container execution uses `asyncio.create_subprocess_exec` for non-blocking,
concurrent I/O. Both `AgentTask.execute()` and `CommandTask.execute()` are
`async def` methods. Callers at sync boundaries (gateway, CLI) use
`asyncio.run()` to invoke them.

**Stream reading**: stdout and stderr are read concurrently as binary streams,
decoded to UTF-8 with `errors="replace"`. Line-by-line callbacks
(`on_stdout_line`, `on_stderr_line`) fire as data arrives. Mutable accumulators
capture full output for the result object.

**Timeout handling**: `asyncio.wait_for()` wraps the stream-reading coroutine.
On timeout, the process is killed and partial accumulated output is preserved in
the result.

**Process lifecycle (`_ProcessTracker`)**: Stores the raw PID (not a subprocess
handle) for cross-thread safety. `stop()` sends `SIGTERM` via `os.kill()`, then
schedules a `threading.Timer` for `SIGKILL` after 5 seconds. This is
non-blocking -- the caller does not wait for process exit.

**Network log tailing**: When `on_network_line` is provided, an async task polls
the network log file concurrently alongside container execution, delivering new
lines to the callback as they appear.

### Lifecycle Layers

**Sandbox-scoped** (shared across all tasks):

- Egress network for proxy internet access
- Proxy container image
- CA certificate for TLS interception
- Container image cache (two-layer, content-addressed)

**Task-scoped** (per execution context):

- Internal network (`airut-conv-{id}`) routing container traffic through proxy
- Proxy container enforcing allowlist
- Container with mounts, env, and (for AgentTask) Claude session state

### Owned State

The sandbox creates and manages these files. Callers specify where to place them
via `execution_context_dir` and `network_log_path` in `create_task()` /
`create_command_task()`:

| File                  | Task type   | Purpose                                                     |
| --------------------- | ----------- | ----------------------------------------------------------- |
| `events.jsonl`        | `AgentTask` | Append-only event log of Claude streaming output (EventLog) |
| `claude/`             | `AgentTask` | Claude Code session state (mounted at `/root/.claude`)      |
| `network-sandbox.log` | Both        | Proxy request log (allowed/blocked requests)                |

The `claude/` subdirectory is created automatically inside
`execution_context_dir` and mounted by the sandbox. It must **not** appear in
the caller's mounts list. `CommandTask` does not create `events.jsonl` or
`claude/`.

Conversation metadata (`conversation.json`) is **not** owned by the sandbox. It
is managed by `airut/conversation/ConversationStore`, which the protocol layer
(e.g., the email gateway) is responsible for calling.

## Execution Flow

### AgentTask

```
await task.execute(prompt, session_id=..., model=..., effort=...,
                   on_event=..., on_stderr_line=..., on_network_line=...)
  |
  +- Start proxy (if network_sandbox configured)
  |    +- Allocate subnet, create internal network
  |    +- Start dual-homed proxy container
  |    +- Health check (poll ports 80/443)
  |
  +- Start network log tail task (if on_network_line provided)
  |
  +- Run Claude Code container (async subprocess)
  |    +- --cap-drop=ALL, --security-opt=no-new-privileges:true
  |    +- Apply resource limits (--memory, --cpus, --pids-limit)
  |    +- Prompt on stdin, read stdout/stderr concurrently as async streams
  |    +- Parse each stdout line as StreamEvent, invoke on_event callback
  |    +- Invoke on_stderr_line callback for each stderr line
  |    +- Wait with asyncio.wait_for() timeout (if configured)
  |
  +- Stop network log tail task
  |
  +- Stop proxy (always, even on failure)
  |
  +- Classify outcome
  |
  +- Return ExecutionResult
```

### CommandTask

```
await task.execute(["make", "test"], on_output=..., on_stderr=...,
                   on_network_line=...)
  |
  +- Start proxy (if network_sandbox configured)
  |
  +- Start network log tail task (if on_network_line provided)
  |
  +- Run container with command (async subprocess)
  |    +- --cap-drop=ALL, --security-opt=no-new-privileges:true
  |    +- Apply resource limits (--memory, --cpus, --pids-limit)
  |    +- Read stdout/stderr concurrently as async streams
  |    +- Invoke on_output callback for each stdout line
  |    +- Invoke on_stderr callback for each stderr line
  |    +- Wait with asyncio.wait_for() timeout (if configured)
  |
  +- Stop network log tail task
  |
  +- Stop proxy (always, even on failure)
  |
  +- Return CommandResult
```

**Note**: `CommandTask` does not implicitly write to `sys.stdout` or
`sys.stderr`. All output delivery is through explicit callbacks. Callers that
want terminal output must provide callbacks (e.g.,
`on_output=lambda line: sys.stdout.write(line)`).

## Resource Limits

Container resource limits are configured via `ResourceLimits`
(`airut/sandbox/types.py`) and passed through to podman flags. Both `AgentTask`
and `CommandTask` accept resource limits. All limits are optional -- when a
field is `None`, the corresponding flag is not passed and no limit is enforced.

| ResourceLimits field | Podman flags                  | Effect                     |
| -------------------- | ----------------------------- | -------------------------- |
| `timeout`            | `asyncio.wait_for(timeout=N)` | SIGKILL after N seconds    |
| `memory`             | `--memory=X --memory-swap=X`  | Hard memory limit, no swap |
| `cpus`               | `--cpus=N`                    | CPU core limit (float)     |
| `pids_limit`         | `--pids-limit=N`              | Fork bomb protection       |

Setting `--memory-swap` equal to `--memory` disables swap for the container,
preventing slow OOM thrashing.

### Configuration Layers

Resource limits flow from two configuration layers:

1. **Server config** (`~/.config/airut/airut.yaml`) — optional ceilings
2. **Repo config** (`.airut/airut.yaml`) — per-repo values, clamped to ceilings

See `spec/repo-config.md` for the full resolution logic.

### cgroup v2 Requirement

Resource limits require cgroup v2 with the `cpu`, `memory`, and `pids`
controllers delegated to the user running Airut. The `airut check` command
verifies this. This is the default on Ubuntu 22.04+, Fedora 34+, Debian 12+, and
RHEL 9+.

## Outcome Classification

| Outcome             | Detection                      | Caller action                                  |
| ------------------- | ------------------------------ | ---------------------------------------------- |
| `SUCCESS`           | Exit code 0, no error          | Use `response_text`                            |
| `TIMEOUT`           | Container killed by timeout    | Inform user, work saved in workspace           |
| `PROMPT_TOO_LONG`   | "Prompt is too long" in stdout | Retry with `session_id=None` + recovery prompt |
| `SESSION_CORRUPTED` | "API Error: 4" in output       | Retry with `session_id=None` + recovery prompt |
| `CONTAINER_FAILED`  | Non-zero exit, other errors    | Report error to user                           |

`ImageBuildError` is not an `Outcome` -- image build failures are raised from
`ensure_image()`, before task execution begins.

The sandbox never raises for expected execution failures. Only `SandboxError`
(and subclasses `ImageBuildError`, `ProxyError`) are raised, for unexpected
infrastructure failures.

## CommandResult

`CommandTask.execute()` returns `CommandResult` instead of `ExecutionResult`. It
has no Claude-specific fields (no outcome classification, no session ID, no
events):

| Field         | Type   | Description                                 |
| ------------- | ------ | ------------------------------------------- |
| `exit_code`   | `int`  | Process exit code                           |
| `stdout`      | `str`  | Raw stdout from the container               |
| `stderr`      | `str`  | Raw stderr from the container               |
| `duration_ms` | `int`  | Execution duration in milliseconds          |
| `timed_out`   | `bool` | Whether the container was killed by timeout |

## Event Log

The sandbox owns `events.jsonl` in the `execution_context_dir` provided to
`create_task()`. The `EventLog` class provides an append-only log of raw Claude
streaming JSON events, stored as newline-delimited JSON (one event per line).

### EventLog API

| Method              | Purpose                                                |
| ------------------- | ------------------------------------------------------ |
| `append_event()`    | Append a single StreamEvent (O(1) append, no rewrite)  |
| `start_new_reply()` | Write a blank-line delimiter between replies           |
| `read_all()`        | Read all events, grouped by reply (list of lists)      |
| `read_reply(index)` | Read events for a specific reply by zero-based index   |
| `tail(offset)`      | Read new events from a byte offset (efficient polling) |

Replies are separated by blank-line delimiters so events can be grouped by reply
when reading back.

### Design Rationale

- **Append-only**: Each `append_event()` opens the file in append mode, writes
  one line, and closes. No read-modify-write cycle -- writes are O(1) regardless
  of log size.
- **Safe for concurrent reads**: The dashboard can `tail()` the event log while
  Claude is still streaming, since appends do not modify existing content.
- **Separation of concerns**: The event log stores raw streaming data. Summary
  metadata (session IDs, usage, cost, response text) is stored in
  `conversation.json` by `airut/conversation/ConversationStore`, which is owned
  by the protocol layer -- not the sandbox.
