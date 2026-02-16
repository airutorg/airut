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

- Event log (`events.jsonl`) and Claude session state (`.claude/` directory)
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
       +- event_log             # Append-only event log (events.jsonl)
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
- Claude Code container with mounts, env, and Claude session state

### Owned State

The sandbox creates and manages these files. Callers specify where to place them
via `execution_context_dir` and `network_log_dir` in `create_task()`:

| File                  | Purpose                                                     |
| --------------------- | ----------------------------------------------------------- |
| `events.jsonl`        | Append-only event log of Claude streaming output (EventLog) |
| `claude/`             | Claude Code session state (mounted at `/root/.claude`)      |
| `network-sandbox.log` | Proxy request log (allowed/blocked requests)                |

The `claude/` subdirectory is created automatically inside
`execution_context_dir` and mounted by the sandbox. It must **not** appear in
the caller's mounts list.

Conversation metadata (`conversation.json`) is **not** owned by the sandbox. It
is managed by `airut/conversation/ConversationStore`, which the protocol layer
(e.g., the email gateway) is responsible for calling.

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
