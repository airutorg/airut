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
2. **Owned state**: The sandbox owns `session.json`, Claude session state
   (`.claude/`), and `network-sandbox.log` — it creates, reads, and writes these
   files. Callers specify where to place them.
3. **Typed interface**: No `Any` in the public API. Proper types for allowlists,
   secrets, environment variables, events, and errors.
4. **Explicit lifecycle**: `Task` has an explicit lifecycle — no context
   managers. `execute()` runs the container; `stop()` interrupts from another
   thread.
5. **Outcome classification**: The sandbox classifies results into a single
   `Outcome` enum (success and error kinds) so callers can match on outcome
   rather than parsing stdout/stderr strings.
6. **Entrypoint generation**: The sandbox generates the container entrypoint in
   code, not from an external file. The entrypoint is fundamental to sandbox
   operation (IS_SANDBOX, CA trust, dependency sync).
7. **Secret masking**: The sandbox owns surrogate generation for masked secrets
   and signing credentials. Callers provide real secret values with scope
   metadata; the sandbox generates surrogates, injects them into the container
   environment, and configures the proxy replacement map.

## Dependencies

This library depends on two shared modules:

- **`lib/claude_output/`** — Typed Claude streaming JSON output parsing.
  Provides `StreamEvent`, `Usage`, `ResultSummary`, and extraction functions
  (`parse_event()`, `extract_result_summary()`, `extract_response_text()`,
  `extract_session_id()`). Shared between the sandbox (output parsing during
  execution) and gateway (response text extraction, dashboard rendering).
- **`lib/allowlist.py`** — Typed network allowlist with YAML parsing and JSON
  serialization. Provides `Allowlist`, `AllowlistDomain`, `AllowlistUrlPattern`,
  `parse_allowlist_yaml()`, and `serialize_allowlist_json()`. The proxy
  container reads JSON (no PyYAML dependency).

## Architecture

### Package Structure

```
lib/sandbox/
  __init__.py              # Public API exports
  types.py                 # Mount, ContainerEnv, Outcome, ExecutionResult
  secrets.py               # MaskedSecret, SigningCredential, surrogate generation
  sandbox.py               # Sandbox class (top-level facade)
  task.py                  # Task class (per-execution)
  session.py               # SessionStore, SessionMetadata, SessionReply
  network_log.py           # NetworkLog reader
  _image.py                # Two-layer image building (internal)
  _entrypoint.py           # Entrypoint generation (internal)
  _proxy.py                # ProxyManager (internal)
  _network.py              # Container network args (internal)
  _output.py               # Output parsing integration (internal)
```

Internal modules (prefixed with `_`) are implementation details. The public API
is exported from `__init__.py`.

### Component Relationships

```
Caller (gateway, CLI, automation)
  │
  ├─ Sandbox                    # Top-level facade
  │    ├─ startup/shutdown      # Shared infrastructure
  │    ├─ ensure_image()        # Two-layer image build
  │    └─ create_task()         # Per-execution task
  │
  └─ Task                       # Per-execution
       ├─ execute()             # Proxy start → container run → proxy stop
       ├─ stop()                # Interrupt from another thread
       ├─ session_store         # Read session state
       └─ network_log           # Read network activity
```

## Type Definitions

### Mount

```python
@dataclass(frozen=True)
class Mount:
    """A volume mount for the container."""

    host_path: Path
    container_path: str
    read_only: bool = False
```

The caller builds mounts from its own layout. The sandbox does not know about
workspace, inbox, outbox, or storage directories — it receives generic mounts.

The `.claude` session state directory is **not** a caller mount — the sandbox
manages it internally (see `session_dir` in `create_task()`).

### Container Environment

```python
@dataclass(frozen=True)
class ContainerEnv:
    """Container environment variables.

    All values are redacted in log output (command-line logging).
    Container env vars are assumed to be secrets or secret-derived.
    """

    variables: dict[str, str]
```

### Network Allowlist

The sandbox uses the existing `lib/allowlist.py` module for allowlist types and
serialization. The caller parses YAML from the git mirror via
`parse_allowlist_yaml()` and passes the typed `Allowlist` to
`NetworkSandboxConfig`. The sandbox internally calls
`serialize_allowlist_json()` to produce JSON for the proxy container mount.

### Masked Secrets

The sandbox owns surrogate generation. Callers provide real secret values with
scope metadata; the sandbox generates surrogates, returns them so the caller can
inject them into `ContainerEnv`, and configures the proxy replacement map
internally.

```python
@dataclass(frozen=True)
class MaskedSecret:
    """A secret that should be masked with a surrogate in the container.

    The sandbox generates a surrogate token, the caller injects the
    surrogate into ContainerEnv, and the proxy swaps it for the real
    value when the request host matches a scope pattern.
    """

    env_var: str
    real_value: str
    scopes: tuple[str, ...]
    headers: tuple[str, ...]


@dataclass(frozen=True)
class SigningCredential:
    """AWS SigV4 signing credential for proxy re-signing.

    Unlike masked secrets (simple token replacement), signing credentials
    require the proxy to re-sign requests. The sandbox generates surrogates
    for the access key ID (and session token if present) and returns them
    so the caller can inject them into ContainerEnv.
    """

    access_key_id_env_var: str
    access_key_id: str
    secret_access_key_env_var: str
    secret_access_key: str
    session_token_env_var: str | None
    session_token: str | None
    scopes: tuple[str, ...]
```

### Surrogate Generation

The sandbox provides `prepare_secrets()` which takes masked secrets and signing
credentials, generates surrogates, and returns two things: (1) environment
variable mappings for the caller to include in `ContainerEnv`, and (2) an opaque
`SecretReplacements` object that the sandbox uses internally for proxy
configuration.

```python
@dataclass(frozen=True)
class SecretReplacements:
    """Opaque container for proxy replacement configuration.

    Created by prepare_secrets(). Passed to NetworkSandboxConfig.
    The caller does not inspect or modify this — the sandbox uses it
    internally to configure the proxy.
    """

    # Internal fields (not part of public API contract)
    ...


@dataclass(frozen=True)
class PreparedSecrets:
    """Result of surrogate generation.

    Contains the environment variables to inject into the container
    (with surrogates instead of real values) and the replacement
    configuration for the proxy.
    """

    env_vars: dict[str, str]
    replacements: SecretReplacements


def prepare_secrets(
    masked_secrets: list[MaskedSecret],
    signing_credentials: list[SigningCredential],
) -> PreparedSecrets:
    """Generate surrogates for secrets and signing credentials.

    For each masked secret, generates a surrogate that preserves the
    original token's format (length, charset, known prefix). For signing
    credentials, generates surrogates for access_key_id and session_token.

    Returns PreparedSecrets containing:
    - env_vars: Mapping of env var names to surrogate values. The caller
      merges these into ContainerEnv.variables.
    - replacements: Opaque replacement config for NetworkSandboxConfig.
    """
```

**Surrogate format:** Surrogates preserve the original token's length, character
set, and known prefix (e.g., `ghp_`, `sk-ant-`, `AKIA`, `ASIA`). Generation uses
`secrets.choice()` (cryptographically secure). AWS STS session tokens use a
fixed 512-character surrogate regardless of original length. See
`spec/masked-secrets.md` for full format details.

### Network Sandbox Configuration

```python
@dataclass(frozen=True)
class NetworkSandboxConfig:
    """Everything needed to set up network isolation for a task.

    Combines the allowlist (what hosts are reachable) with secret
    replacement rules (how credentials are protected at the proxy level).
    """

    allowlist: Allowlist
    replacements: SecretReplacements
```

### Outcome

A single enum for both success and error classification. The caller matches on
one value instead of checking two fields (`success` + `error_kind`).

```python
class Outcome(Enum):
    """Classifies execution result to guide caller behavior.

    The caller matches on Outcome to decide how to handle the result.
    """

    SUCCESS = "success"
    TIMEOUT = "timeout"
    PROMPT_TOO_LONG = "prompt_too_long"
    SESSION_CORRUPTED = "session_corrupted"
    CONTAINER_FAILED = "container_failed"
```

| Outcome             | Detection                      | Caller action                                  |
| ------------------- | ------------------------------ | ---------------------------------------------- |
| `SUCCESS`           | Exit code 0, no error          | Use `response_text`                            |
| `TIMEOUT`           | Container killed by timeout    | Inform user, work saved in workspace           |
| `PROMPT_TOO_LONG`   | "Prompt is too long" in stdout | Retry with `session_id=None` + recovery prompt |
| `SESSION_CORRUPTED` | "API Error: 4" in output       | Retry with `session_id=None` + recovery prompt |
| `CONTAINER_FAILED`  | Non-zero exit, other errors    | Report error to user                           |

Note: `IMAGE_BUILD_FAILED` is not in `Outcome` — image build failures are raised
as `ImageBuildError` from `ensure_image()`, since they occur before task
execution.

### Execution Result

```python
@dataclass(frozen=True)
class ExecutionResult:
    """Result of a sandbox task execution.

    Always returned — the sandbox does not raise for expected failures
    (timeout, prompt too long, session corrupted). Only raises
    SandboxError for truly unexpected infrastructure failures.
    """

    outcome: Outcome

    # Claude output
    session_id: str
    response_text: str
    events: list[StreamEvent]

    # Metrics
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    usage: Usage

    # Raw output (debugging)
    stdout: str
    stderr: str
    exit_code: int
```

`StreamEvent` and `Usage` come from `lib/claude_output/`.

## Sandbox Class

```python
@dataclass(frozen=True)
class SandboxConfig:
    """Construction-time configuration for the sandbox."""

    container_command: str = "podman"
    proxy_dir: Path = Path("proxy")
    upstream_dns: str = "1.1.1.1"
    max_image_age_hours: int = 24


class Sandbox:
    """Top-level sandbox manager.

    Manages shared infrastructure (proxy image, CA cert, egress network)
    and creates Task instances for individual executions.

    Thread Safety: Thread-safe. Multiple threads may call create_task()
    and ensure_image() concurrently. Image builds are serialized.
    """

    def __init__(self, config: SandboxConfig) -> None: ...

    def startup(self) -> None:
        """Prepare shared infrastructure.

        1. Clean orphaned resources from previous unclean shutdown.
        2. Build proxy container image.
        3. Ensure CA certificate exists.
        4. Create shared egress network.

        Must be called before create_task().

        Raises:
            SandboxError: If any setup step fails.
        """

    def shutdown(self) -> None:
        """Tear down all infrastructure. Stops any active tasks."""

    def ensure_image(
        self,
        dockerfile: bytes,
        context_files: dict[str, bytes],
    ) -> str:
        """Build or reuse two-layer container image.

        Builds the repo image from the provided Dockerfile and context
        files, then builds the overlay with the generated entrypoint.
        Images are cached by content hash with staleness checking.

        Args:
            dockerfile: Raw Dockerfile content.
            context_files: Additional files for build context (filename → content).

        Returns:
            Image tag for use in create_task().

        Raises:
            SandboxError: If image build fails.
        """

    def create_task(
        self,
        task_id: str,
        *,
        image_tag: str,
        mounts: list[Mount],
        env: ContainerEnv,
        session_dir: Path,
        network_log_dir: Path | None = None,
        network_sandbox: NetworkSandboxConfig | None = None,
        timeout_seconds: int = 300,
    ) -> Task:
        """Create a task for sandboxed execution.

        The sandbox owns:
        - session_dir/session.json — session metadata and history
        - session_dir/claude/ — Claude session state directory
          (mounted at /root/.claude in the container)
        - network_log_dir/network-sandbox.log — network activity log
          (if network_log_dir provided)

        The claude/ subdirectory is created automatically and mounted
        by the sandbox. It must not appear in the caller's mounts list.

        Does not start execution — call task.execute() to run.
        """
```

### Entrypoint Generation

The entrypoint is generated in code by `_entrypoint.py`, not read from an
external file. This is cleaner since the entrypoint is fundamental to sandbox
operation:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Allow Claude to run as root in sandbox environment
export IS_SANDBOX=1

# Trust mounted CA certificates (for network proxy)
if [ -f /usr/local/share/ca-certificates/mitmproxy-ca.crt ]; then
    update-ca-certificates 2>/dev/null || true
fi

# Sync Python dependencies on container start
if [ -f /workspace/pyproject.toml ]; then
    uv sync --quiet
fi

# Run Claude Code with all arguments passed through
exec claude "$@"
```

The entrypoint content is included in the overlay image hash, so changes to the
generated script trigger a rebuild.

### Image Build

Identical to the current two-layer strategy (see `spec/image.md`) with one
change: the entrypoint is generated rather than read from disk.

```
Layer 1: Repo Image
  Source: Dockerfile + context_files provided by caller
  Tag:    airut-repo:<sha256>

Layer 2: Overlay Image
  Source: Generated entrypoint
  Tag:    airut:<sha256-of-repo-tag-plus-entrypoint>
```

The caller reads the Dockerfile and context files from whatever source it uses
(git mirror, local files, etc.) and passes raw bytes. The sandbox does not know
about git mirrors.

## Task Class

```python
class EventCallback(Protocol):
    def __call__(self, event: StreamEvent) -> None: ...


class Task:
    """A single sandboxed Claude Code execution.

    Lifecycle:
        task = sandbox.create_task(...)
        session_id = task.session_store.get_session_id_for_resume()
        result = task.execute(prompt, session_id=session_id, model=model)

        # Inspect result.outcome to decide recovery
        match result.outcome:
            case Outcome.SUCCESS:
                use(result.response_text)
            case Outcome.PROMPT_TOO_LONG | Outcome.SESSION_CORRUPTED:
                last = task.session_store.get_last_successful_response()
                result = task.execute(recovery, session_id=None, model=model)

        # From another thread:
        task.stop()

    Thread Safety:
        execute() is not reentrant — only one execution at a time per Task.
        stop() is safe to call from another thread during execute().
    """

    @property
    def task_id(self) -> str: ...

    @property
    def session_store(self) -> SessionStore:
        """Access session state (read-only for callers)."""

    @property
    def network_log(self) -> NetworkLog | None:
        """Access network activity log (None if sandbox disabled)."""

    def execute(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        model: str = "sonnet",
        on_event: EventCallback | None = None,
    ) -> ExecutionResult:
        """Execute Claude Code in the sandbox.

        1. Start proxy (if network sandbox configured)
        2. Build podman command with mounts, env, network args
        3. Run container with prompt on stdin
        4. Stream events, invoke callback, update session store
        5. Stop proxy
        6. Classify result and return

        Proxy lifecycle is managed internally — the caller does not
        need try/finally around proxy start/stop.

        Args:
            prompt: User prompt to pass to Claude via stdin.
            session_id: Optional session ID for --resume. Pass None for
                a fresh session. The caller reads this from
                task.session_store and decides whether to use it.
            model: Claude model name (e.g., "opus", "sonnet").
            on_event: Optional callback for real-time streaming events.

        Returns:
            ExecutionResult — always returned, never raises for expected
            failures.

        Raises:
            SandboxError: Only for unexpected infrastructure failures.
        """

    def stop(self) -> bool:
        """Stop execution from another thread.

        Sends SIGTERM, waits 5 seconds, then SIGKILL.

        Returns:
            True if a running process was stopped, False if nothing running.
        """
```

### Execution Flow

```
task.execute(prompt, session_id=..., model=..., on_event=...)
  │
  ├─ Start proxy (if network_sandbox configured)
  │    ├─ Allocate subnet
  │    ├─ Create internal network
  │    ├─ Serialize allowlist to JSON temp file
  │    ├─ Serialize replacement map to JSON temp file
  │    ├─ Create network log file
  │    ├─ Start dual-homed proxy container
  │    └─ Health check (poll ports 80/443)
  │
  ├─ Build podman command
  │    ├─ Base: podman run --rm -i --log-driver=none
  │    ├─ Environment: -e VAR=value (redacted in logs)
  │    ├─ Mounts: caller mounts + session_dir/claude/:/root/.claude:rw
  │    ├─ Network: --network, --dns, CA cert mount + env vars
  │    └─ Claude: claude [--resume ID] --model M -p - --dangerously-skip-permissions
  │              --output-format stream-json --verbose
  │
  ├─ Run container
  │    ├─ Send prompt on stdin, close stdin
  │    ├─ Read stdout line-by-line
  │    │    ├─ Parse each line as StreamEvent (via lib/claude_output/)
  │    │    ├─ Invoke on_event callback
  │    │    └─ Buffer events for session store
  │    ├─ Wait with timeout
  │    └─ Read stderr
  │
  ├─ Stop proxy (always, even on failure)
  │
  ├─ Classify outcome
  │    ├─ Exit code 0, no error → Outcome.SUCCESS
  │    ├─ Timeout → Outcome.TIMEOUT
  │    ├─ "Prompt is too long" in stdout → Outcome.PROMPT_TOO_LONG
  │    ├─ "API Error: 4" in output → Outcome.SESSION_CORRUPTED
  │    └─ Other non-zero exit → Outcome.CONTAINER_FAILED
  │
  ├─ Update session store (finalize reply)
  │
  └─ Return ExecutionResult
```

### Streaming and Session Updates

During execution, the sandbox updates `session.json` progressively:

1. **On each event**: Buffer the event and update session store with partial
   data
2. **On result event**: Extract final metrics (cost, turns, session_id)
3. **After execution**: Finalize the reply with complete result

This ensures partial progress is visible to the dashboard even if the container
crashes mid-execution.

## Session Store

The sandbox owns `session.json`. It is created in the `session_dir` path
provided to `create_task()`.

```python
@dataclass(frozen=True)
class SessionReply:
    """Record of a single execution."""

    session_id: str
    timestamp: str  # ISO 8601
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    is_error: bool
    usage: Usage
    request_text: str
    response_text: str
    events: list[StreamEvent]


@dataclass
class SessionMetadata:
    """Full session history for a task."""

    task_id: str
    model: str | None
    replies: list[SessionReply]


class SessionStore:
    """Persistent session state.

    The sandbox creates and manages session.json. Callers read from it
    via task.session_store to get session_id for resumption and
    last successful response for recovery.
    """

    def __init__(self, session_dir: Path) -> None: ...

    def load(self) -> SessionMetadata | None: ...
    def get_session_id_for_resume(self) -> str | None: ...
    def get_last_successful_response(self) -> str | None: ...
    def get_model(self) -> str | None: ...
    def set_model(self, task_id: str, model: str) -> None: ...
```

### Session ID Extraction

When Claude execution completes normally, `session_id` comes from the `result`
event. When execution is interrupted (e.g., API error 529), the result event is
never emitted. The session store falls back to extracting `session_id` from the
`system/init` event, which is emitted early in execution.

## Network Log

The sandbox owns `network-sandbox.log`. It is created in `network_log_dir` (if
provided to `create_task()`).

```python
class NetworkLog:
    """Read access to the network sandbox log.

    The log file is created by the sandbox at proxy start and written
    to by the proxy container (DNS responder + mitmproxy addon).
    It persists after task completion for dashboard viewing.
    """

    def __init__(self, log_path: Path) -> None: ...

    @property
    def path(self) -> Path: ...
    def exists(self) -> bool: ...
    def read_raw(self) -> str: ...
```

The log format is unchanged from the current implementation (see
`spec/network-sandbox.md`).

## Exceptions

```python
class SandboxError(Exception):
    """Base exception for sandbox infrastructure failures.

    Raised only for unexpected errors — not for expected execution
    failures like timeout or prompt-too-long (those are returned as
    Outcome variants in ExecutionResult).
    """


class ImageBuildError(SandboxError):
    """Raised when container image build fails."""


class ProxyError(SandboxError):
    """Raised when proxy infrastructure fails."""
```

## Caller Integration Pattern

```python
# --- Service startup ---
sandbox = Sandbox(
    SandboxConfig(
        container_command="podman",
        proxy_dir=repo_root / "proxy",
        upstream_dns=upstream_dns,
    )
)
sandbox.startup()

# --- Per message ---
# Caller reads Dockerfile from git mirror
dockerfile = mirror.read_file(".airut/container/Dockerfile")
context_files = {
    name: mirror.read_file(f".airut/container/{name}")
    for name in mirror.list_directory(".airut/container")
    if name != "Dockerfile"
}
image_tag = sandbox.ensure_image(dockerfile, context_files)

# Caller builds mounts from its own layout
# Note: .claude is NOT included — the sandbox manages it via session_dir
mounts = [
    Mount(layout.workspace, "/workspace"),
    Mount(layout.inbox, "/inbox"),
    Mount(layout.outbox, "/outbox"),
    Mount(layout.storage, "/storage"),
]

# Caller provides real secrets with scope metadata
# Sandbox generates surrogates and returns env vars to inject
prepared = prepare_secrets(
    masked_secrets=[
        MaskedSecret(
            env_var="GH_TOKEN",
            real_value=server_config.secrets["GH_TOKEN"],
            scopes=("api.github.com", "*.githubusercontent.com"),
            headers=("Authorization",),
        ),
    ],
    signing_credentials=[
        SigningCredential(
            access_key_id_env_var="AWS_ACCESS_KEY_ID",
            access_key_id=server_config.secrets["AWS_ACCESS_KEY_ID"],
            secret_access_key_env_var="AWS_SECRET_ACCESS_KEY",
            secret_access_key=server_config.secrets["AWS_SECRET_ACCESS_KEY"],
            session_token_env_var="AWS_SESSION_TOKEN",
            session_token=server_config.secrets.get("AWS_SESSION_TOKEN"),
            scopes=("*.amazonaws.com",),
        ),
    ],
)

# Merge surrogate env vars with plain env vars
env = ContainerEnv(
    variables={**repo_config.container_env, **prepared.env_vars},
)

# Caller parses allowlist and builds network config
allowlist = parse_allowlist_yaml(
    mirror.read_file(".airut/network-allowlist.yaml")
)
network_cfg = (
    NetworkSandboxConfig(
        allowlist=allowlist,
        replacements=prepared.replacements,
    )
    if sandbox_enabled
    else None
)

task = sandbox.create_task(
    task_id=conv_id,
    image_tag=image_tag,
    mounts=mounts,
    env=env,
    session_dir=conversation_dir,
    network_log_dir=conversation_dir,
    network_sandbox=network_cfg,
    timeout_seconds=repo_config.timeout,
)

# Read session state for resumption
session_id = task.session_store.get_session_id_for_resume()

# Execute
result = task.execute(
    prompt=prompt,
    session_id=session_id,
    model=model,
    on_event=on_event,
)

# Handle result based on outcome
match result.outcome:
    case Outcome.SUCCESS:
        # Use result.response_text
        pass
    case Outcome.PROMPT_TOO_LONG | Outcome.SESSION_CORRUPTED:
        # Retry with fresh session
        last = task.session_store.get_last_successful_response()
        recovery = build_recovery_prompt(last, ...)
        result = task.execute(recovery, session_id=None, model=model)
    case Outcome.TIMEOUT:
        # Inform user, work is saved
        pass
    case Outcome.CONTAINER_FAILED:
        # Report error
        pass
```

## Migration

### What Moves Into `lib/sandbox/`

| Current location             | New location                       |
| ---------------------------- | ---------------------------------- |
| `lib/container/executor.py`  | `lib/sandbox/task.py`, `_image.py` |
| `lib/container/proxy.py`     | `lib/sandbox/_proxy.py`            |
| `lib/container/network.py`   | `lib/sandbox/_network.py`          |
| `lib/container/session.py`   | `lib/sandbox/session.py`           |
| `docker/airut-entrypoint.sh` | `lib/sandbox/_entrypoint.py`       |

### What Stays Outside

| Component               | Stays in                                    |
| ----------------------- | ------------------------------------------- |
| `ConversationLayout`    | `lib/container/conversation_layout.py`      |
| `ConversationManager`   | `lib/gateway/conversation.py`               |
| `TaskTracker`           | `lib/dashboard/tracker.py`                  |
| Claude output parsing   | `lib/claude_output/`                        |
| Allowlist types/parsing | `lib/allowlist.py`                          |
| Recovery logic          | `lib/gateway/service/message_processing.py` |
| Email context injection | Gateway layer                               |
| Allowlist YAML file     | `.airut/network-allowlist.yaml`             |
| Repo Dockerfile         | `.airut/container/Dockerfile`               |

### What Gets Deleted

| Deleted                      | Replaced by                  |
| ---------------------------- | ---------------------------- |
| `lib/container/executor.py`  | `lib/sandbox/task.py`        |
| `lib/container/proxy.py`     | `lib/sandbox/_proxy.py`      |
| `lib/container/network.py`   | `lib/sandbox/_network.py`    |
| `lib/container/session.py`   | `lib/sandbox/session.py`     |
| `docker/airut-entrypoint.sh` | `lib/sandbox/_entrypoint.py` |

`lib/container/` retains `conversation_layout.py` and `dns.py` (system DNS
resolver lookup for upstream DNS auto-detection).

### `lib/container/__init__.py` Update

After migration, `lib/container/__init__.py` exports only the conversation
layout and DNS utilities. All executor, proxy, session, and network exports move
to `lib/sandbox/__init__.py`.

## Documentation Changes

The following documents reference components that move into the sandbox library
and must be updated:

| Document                       | Changes needed                                             |
| ------------------------------ | ---------------------------------------------------------- |
| `spec/gateway-architecture.md` | Update component list, data flow diagram                   |
| `spec/image.md`                | Update entrypoint section (generated, not file)            |
| `spec/network-sandbox.md`      | Update component table, proxy lifecycle refs               |
| `spec/masked-secrets.md`       | Update data flow (replacement map types)                   |
| `spec/aws-sigv4-resigning.md`  | Update if it references executor/proxy paths               |
| `spec/dashboard.md`            | Update network log / session access pattern                |
| `doc/architecture.md`          | Update component overview diagram                          |
| `doc/execution-sandbox.md`     | Update session metadata section, container runtime section |
| `CLAUDE.md`                    | Update project structure section                           |

These updates should be included in the sandbox implementation PR, not as a
separate effort.
