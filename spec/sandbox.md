# Sandbox Library

A standalone library (`lib/sandbox/`) for safe containerized execution of
headless Claude Code. The sandbox owns container lifecycle, network isolation,
session persistence, and error detection. Protocol layers (email, Slack,
automation) define what Claude sees (prompts, repos, files, mounts); the sandbox
handles how it runs safely.

## Design Goals

1. **Clean separation**: The sandbox knows nothing about email, conversations,
   or protocol-specific layouts. Callers provide mounts, environment, and
   prompts.
2. **Owned state**: The sandbox owns `context.json`, Claude session state
   (`.claude/`), and `network-sandbox.log` -- it creates, reads, and writes
   these files. Callers specify where to place them.
3. **Typed interface**: No `Any` in the public API. Proper types for allowlists,
   secrets, environment variables, events, and errors.
4. **Explicit lifecycle**: `Task` has an explicit lifecycle -- no context
   managers. `execute()` runs the container; `stop()` interrupts from another
   thread.
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

- Session state (`context.json`, `.claude/` directory)
- Network resources (internal network, proxy container)
- Container naming

The sandbox does not know what the execution context ID represents. It could be
a conversation, a CI run, a one-shot script -- the sandbox treats it as a
grouping key for resources that should persist across multiple `execute()` calls
on the same `Task`.

### Concept Mapping

Protocol layers map their own concepts to the sandbox's execution context:

| Protocol layer | Protocol concept | Sandbox concept        |
| -------------- | ---------------- | ---------------------- |
| Email gateway  | Conversation ID  | `execution_context_id` |
| CLI            | Run ID           | `execution_context_id` |
| CI automation  | Job ID           | `execution_context_id` |

The gateway maps its conversation ID to the sandbox's execution context ID when
creating a task:

```
task = sandbox.create_task(execution_context_id=conv_id, ...)
```

This mapping is the only place where protocol-specific knowledge touches the
sandbox API. Everything inside the sandbox operates on the opaque
`execution_context_id`.

## Architecture

### Component Relationships

```
Caller (gateway, CLI, automation)
  |
  +- Sandbox                    # Top-level facade
  |    +- startup/shutdown      # Shared infrastructure
  |    +- ensure_image()        # Two-layer image build
  |    +- create_task()         # Per-execution task
  |
  +- Task                       # Per-execution
       +- execute()             # Proxy start -> container run -> proxy stop
       +- stop()                # Interrupt from another thread
       +- session_store         # Read session state
       +- network_log           # Read network activity
```

### Lifecycle Layers

**Sandbox-scoped** (shared across all tasks):

- Egress network for proxy internet access
- Proxy container image
- CA certificate for TLS interception
- Container image cache (two-layer, content-addressed)

**Task-scoped** (per execution context):

- Internal network (`airut-conv-{id}`) routing container traffic through proxy
- Proxy container enforcing allowlist
- Claude Code container with mounts, env, and session state

### Owned State

The sandbox creates and manages these files. Callers specify where to place them
via `session_dir` and `network_log_dir` in `create_task()`:

| File                  | Purpose                                                |
| --------------------- | ------------------------------------------------------ |
| `context.json`        | Session metadata, reply history, execution context ID  |
| `claude/`             | Claude Code session state (mounted at `/root/.claude`) |
| `network-sandbox.log` | Proxy request log (allowed/blocked requests)           |

The `claude/` subdirectory is created automatically inside `session_dir` and
mounted by the sandbox. It must **not** appear in the caller's mounts list.

## Execution Flow

```
task.execute(prompt, session_id=..., model=..., on_event=...)
  |
  +- Start proxy (if network_sandbox configured)
  |    +- Allocate subnet, create internal network
  |    +- Start dual-homed proxy container
  |    +- Health check (poll ports 80/443)
  |
  +- Run Claude Code container
  |    +- Prompt on stdin, stream-json on stdout
  |    +- Parse each line as StreamEvent, invoke on_event callback
  |    +- Wait with timeout
  |
  +- Stop proxy (always, even on failure)
  |
  +- Classify outcome
  |
  +- Return ExecutionResult
```

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

## Session Persistence

The sandbox owns `context.json` in the `session_dir` provided to
`create_task()`. It stores:

- **execution_context_id** -- the opaque context identifier
- **replies** -- chronological list of Claude replies with session IDs, usage
  stats, cost, events, and request/response text
- **model** -- Claude model override for this context

### Session ID Extraction

When Claude execution completes normally, `session_id` comes from the `result`
event. When execution is interrupted (e.g., API error 529), the result event is
never emitted. The session store falls back to extracting `session_id` from the
`system/init` event, which is emitted early in execution.

### Streaming Updates

`update_or_add_reply()` supports streaming: it updates the last reply in-place
when the request text matches (same execution still streaming), or appends a new
reply when the request text differs (new execution in a resumed context).
