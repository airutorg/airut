# Live Dashboard

Real-time dashboard updates via Server-Sent Events (SSE), replacing the current
polling/meta-refresh model with push-based state delivery.

## Overview

The dashboard currently uses HTML meta-refresh tags (5–30 second intervals) to
poll for updates. This spec introduces:

1. **VersionedStore** — a generic thread-safe versioned state container used by
   all dashboard-visible state
2. **Append-only log streaming** — offset-based tailing for `events.jsonl` and
   `network-sandbox.log`
3. **SSE transport** — Server-Sent Events endpoints that push state changes and
   log appends to connected browsers

### Design Principles

- **All dashboard-visible state must flow through a versioned interface.** No
  direct field mutations on shared mutable objects.
- **Immutable snapshots.** State objects are frozen dataclasses. Mutations
  create new instances via `dataclasses.replace()`.
- **Single version clock.** One global monotonic counter tracks all state
  changes. SSE clients wait on one condition variable.
- **Append-only logs use file offsets as cursors.** No versioning needed — the
  append-only property guarantees offset stability.

### Prerequisites

This spec assumes PR #72 (split `context.json` into `conversation.json` +
`events.jsonl`) has been merged. The new `EventLog` class with its `tail()`
method and `ConversationStore` are used throughout.

## Versioned State

### VersionClock

A single global monotonic counter shared by all versioned stores. Provides the
condition variable that SSE endpoints wait on.

```python
# lib/dashboard/versioned.py


class VersionClock:
    """Global monotonic version counter.

    Every state mutation in the system ticks this clock. SSE endpoints
    wait on it and wake when any state changes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._version: int = 0

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    def tick(self) -> int:
        """Increment version and notify all waiters. Returns new version."""
        with self._condition:
            self._version += 1
            self._condition.notify_all()
            return self._version

    def wait(self, known: int, timeout: float = 30.0) -> int | None:
        """Block until version > known, or timeout. Returns new version
        or None on timeout.

        Handles server restart: if known > current version, the client
        has a version from a previous server lifetime. Return immediately
        so the client resets to current state.
        """
        with self._condition:
            # Restart detection: client has a version from a previous
            # server lifetime. Return current version immediately so
            # the client gets a full state reset.
            if known > self._version:
                return self._version

            deadline = time.monotonic() + timeout
            while self._version <= known:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(timeout=remaining)
            return self._version
```

**Server restart handling**: The version counter resets to 0 on restart. If a
client reconnects with a version from a previous server lifetime (e.g.,
`Last-Event-ID: 100` when the server is at version 0), `wait()` detects that
`known > self._version` and returns immediately. The client receives a full
state snapshot at version 0 and resets its local state. No 30-second hang.

### VersionedStore

Generic container wrapping an immutable snapshot with a version number.

```python
# lib/dashboard/versioned.py

T = TypeVar("T")


@dataclass(frozen=True)
class Versioned(Generic[T]):
    """A value paired with its version number."""

    version: int
    value: T


class VersionedStore(Generic[T]):
    """Thread-safe versioned state container.

    Values must be immutable (frozen dataclasses, tuples, etc.).
    Each update increments the shared VersionClock.
    """

    def __init__(self, initial: T, clock: VersionClock) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self._version: int = 0
        self._value: T = initial

    def get(self) -> Versioned[T]:
        """Atomic read of current value + version."""
        with self._lock:
            return Versioned(self._version, self._value)

    def update(self, new_value: T) -> int:
        """Replace value, tick clock, return new version."""
        with self._lock:
            version = self._clock.tick()
            self._version = version
            self._value = new_value
            return version
```

### Contract

**Rule: if the dashboard displays it, it must live in a VersionedStore (or be an
append-only log with offset-based tailing).**

All state objects stored in a `VersionedStore` must be immutable — frozen
dataclasses or tuples. Mutations follow the pattern:

```python
old = store.get().value
new = dataclasses.replace(
    old, phase=BootPhase.PROXY, message="Starting proxy..."
)
store.update(new)
```

This guarantees:

- **Atomicity**: readers always see a consistent snapshot (no torn reads)
- **Versioning**: every change has a monotonic version number
- **Notification**: SSE waiters wake on every change

## State Objects

### BootState

Currently a mutable `@dataclass` with no thread safety — mutated in the boot
thread, read from HTTP threads. Convert to `frozen=True` and wrap in a
`VersionedStore`.

```python
# lib/dashboard/tracker.py


@dataclass(frozen=True)
class BootState:
    phase: BootPhase = BootPhase.STARTING
    message: str = "Initializing..."
    error_message: str | None = None
    error_type: str | None = None
    error_traceback: str | None = None
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
```

**Writer**: Gateway boot sequence (`EmailGatewayService._boot()`). Each phase
transition creates a new `BootState` via `replace()` and calls
`boot_store.update(new_state)`.

**Store**: `VersionedStore[BootState]`, created in
`EmailGatewayService.__init__`.

### RepoStates

Currently a `dict[str, RepoState]` with no thread safety. Convert `RepoState` to
`frozen=True` and store the collection as an immutable tuple.

```python
# lib/dashboard/tracker.py


@dataclass(frozen=True)
class RepoState:
    repo_id: str
    status: RepoStatus
    error_message: str | None = None
    error_type: str | None = None
    git_repo_url: str = ""
    imap_server: str = ""
    storage_dir: str = ""
    initialized_at: float = field(default_factory=time.time)
```

**Writer**: Gateway boot sequence (repo initialization). Builds a new tuple of
`RepoState` objects and calls `repos_store.update(new_tuple)`.

**Store**: `VersionedStore[tuple[RepoState, ...]]`, created in
`EmailGatewayService.__init__`.

### TaskTracker

TaskTracker has a rich mutation API and uses an internal `RLock`. Rather than
replacing it, TaskTracker integrates with the `VersionClock`:

- Accept a `VersionClock` at construction
- Call `clock.tick()` at the end of every mutating method (`add_task`,
  `start_task`, `complete_task`, `update_task_id`, `set_task_model`)
- Add a `get_snapshot()` method that returns `Versioned[tuple[TaskState, ...]]`
  — an atomic read of all tasks with the current version

The internal `_condition` variable (currently only notified in `complete_task`)
is replaced by the shared `VersionClock`'s condition. The `wait_for_completion`
method is updated to wait on the clock instead.

`TaskState` remains a mutable dataclass internally (TaskTracker's lock protects
it), but `get_snapshot()` returns copies to ensure the snapshot is stable.

### VersionInfo

Already immutable after creation. No changes needed. Can optionally be exposed
via the clock version for consistency, but it never changes after startup.

## Append-Only Log Streaming

### events.jsonl

The `EventLog` class (from PR #72) already has a
`tail(offset) → (events, new_offset)` method. This is the interface the SSE
endpoint uses.

**SSE endpoint**: `/api/conversation/{id}/events/stream`

**Protocol**:

1. Client connects with `?offset=0` (or last known offset)
2. Server calls `event_log.tail(offset)`
3. If new events exist, send them as SSE data, include new offset
4. If no new events and task is still running, poll `tail()` on interval
   (500ms–1s)
5. If task is completed, send a terminal event and close

**SSE event format**:

```
event: events
data: {"offset": 1234, "events": [<raw JSON objects>]}

event: done
data: {"offset": 1234}
```

**Active vs completed tasks**: For active tasks, the SSE endpoint polls
`EventLog.tail()` until the task completes. For completed tasks, this endpoint
is not used (the client loads all events via the existing JSON API).

### network-sandbox.log

Network logs are plain text, append-only, one line per entry, flushed after each
write by the proxy container.

**SSE endpoint**: `/api/conversation/{id}/network/stream`

**Protocol**: Same as events — offset-based tailing, but with byte offset on the
plain text file.

1. Client connects with `?offset=0`
2. Server reads from byte offset, sends new lines
3. Polls file size on interval (500ms–1s)
4. Sends terminal event when task completes

**SSE event format**:

```
event: lines
data: {"offset": 5678, "lines": ["allowed GET https://... -> 200", ...]}

event: done
data: {"offset": 5678}
```

**File tailing implementation**: The `NetworkLog` class gains a `tail(offset)`
method matching `EventLog.tail()`:

```python
def tail(self, offset: int = 0) -> tuple[list[str], int]:
    """Read new lines from byte offset.
    Returns (new_lines, new_offset)."""
```

## SSE Transport

### WSGI Compatibility

The dashboard uses werkzeug's `make_server` with `threaded=True` (one thread per
request). SSE connections hold a thread open for the duration. This requires
connection limits to prevent thread exhaustion.

SSE responses use werkzeug's `Response` with a generator body and
`Content-Type: text/event-stream`. The generator yields SSE-formatted strings
and blocks (via `VersionClock.wait()` or `time.sleep()`) between sends.

### Connection Limits

Each SSE connection holds a WSGI thread for its entire lifetime. Unbounded SSE
connections could exhaust the thread pool and prevent regular HTTP requests from
being served.

**Server-side limit**: A global `SSEConnectionManager` tracks active SSE
connections with a configurable maximum (default: 8). When a new SSE connection
arrives and the limit is reached, the server responds with
`429 Too Many Requests` and a `Retry-After: 5` header. The client falls back to
polling.

```python
# lib/dashboard/sse.py


class SSEConnectionManager:
    """Tracks active SSE connections to enforce limits."""

    def __init__(self, max_connections: int = 8) -> None:
        self._lock = threading.Lock()
        self._active: int = 0
        self._max: int = max_connections

    def try_acquire(self) -> bool:
        """Try to acquire an SSE slot. Returns False if at limit."""
        with self._lock:
            if self._active >= self._max:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        """Release an SSE slot."""
        with self._lock:
            self._active = max(0, self._active - 1)

    @property
    def active(self) -> int:
        with self._lock:
            return self._active
```

SSE handlers acquire a slot at connection start and release it in a `finally`
block when the generator exits (client disconnect or error).

### Polling Fallback with ETag

When SSE is unavailable (connection limit reached, JS disabled, or SSE
connection fails), the existing JSON API endpoints serve as a polling fallback.
To make polling efficient, they support conditional requests via `ETag`.

**ETag = version number**: The `/api/conversations`, `/api/repos`, and `/health`
endpoints include an `ETag` header with the current clock version:

```
HTTP/1.1 200 OK
ETag: "v42"
Cache-Control: no-cache
```

Clients poll with `If-None-Match`:

```
GET /api/conversations
If-None-Match: "v42"
```

If the version hasn't changed, the server returns `304 Not Modified` with no
body. This avoids re-serializing and re-transmitting unchanged state.

**Frontend fallback logic**:

```javascript
function connectLive(version) {
    const source = new EventSource(`/api/events/stream?version=${version}`);
    source.addEventListener('state', onState);
    source.onerror = () => {
        source.close();
        // Fall back to polling with ETag
        startPolling(version);
    };
}

function startPolling(version) {
    setInterval(async () => {
        const resp = await fetch('/api/conversations', {
            headers: { 'If-None-Match': `"v${version}"` }
        });
        if (resp.status === 200) {
            const data = await resp.json();
            updateDashboard(data);
            version = resp.headers.get('ETag');
        }
        // 304 = no change, skip update
    }, 5000);
}
```

This provides a clean degradation path: SSE for real-time when possible, ETag
polling (5s interval) as fallback, identical state format in both paths.

### Endpoints

| Endpoint                                | Purpose                               | Cursor         |
| --------------------------------------- | ------------------------------------- | -------------- |
| `/api/events/stream`                    | Task list + boot + repo state changes | Version number |
| `/api/conversation/{id}/events/stream`  | Claude streaming events               | Byte offset    |
| `/api/conversation/{id}/network/stream` | Network log lines                     | Byte offset    |

### State Stream (`/api/events/stream`)

Pushes a composite state snapshot whenever any versioned state changes.

**Protocol**:

1. Client connects with `?version=0`
2. Server reads current version from clock; if > client version, send
   immediately (catch-up)
3. Otherwise, `clock.wait(client_version)` blocks until change
4. On wake: send current state snapshot with version
5. Go to 3

**SSE event format**:

```
event: state
data: {"version": 42, "tasks": [...], "boot": {...}, "repos": [...]}
```

The `tasks` array contains task summary objects (same shape as
`/api/conversations` response). `boot` and `repos` contain their respective
state. The client replaces its entire local state on each event — no delta
patching.

**Why full snapshots, not deltas**: The state is small (max ~100 tasks + boot +
repos). Full snapshots avoid client-side state management complexity, delta
application bugs, and ordering issues. A full snapshot is typically \<10 KB.

### Connection Lifecycle

- **Admission**: SSE handler calls `connection_manager.try_acquire()`. If it
  returns `False`, respond with `429 Too Many Requests` and `Retry-After: 5`.
  Client falls back to polling.
- **Heartbeat**: Server sends a comment line (`: heartbeat`) every 15 seconds to
  detect dead connections.
- **Reconnection**: Standard SSE `retry:` field set to 1000ms. Browser
  reconnects automatically on disconnect.
- **Client `Last-Event-ID`**: Set to the last version/offset. Server uses this
  for catch-up on reconnect. If the version is from a previous server lifetime
  (greater than current), the server returns current state immediately (see
  restart handling above).
- **Cleanup**: When the generator detects a closed connection (write raises
  exception), it calls `connection_manager.release()` and exits cleanly. The
  `release()` call is in a `finally` block to guarantee execution.

## Dashboard Frontend Changes

### State Stream Integration

Replace meta-refresh with JavaScript `EventSource`:

```javascript
const source = new EventSource('/api/events/stream?version=0');
source.addEventListener('state', (e) => {
    const state = JSON.parse(e.data);
    updateDashboard(state);
    // Update version for reconnection
    source.url = `/api/events/stream?version=${state.version}`;
});
```

The `updateDashboard()` function re-renders the task columns, boot banner, and
repo status from the received state. This can be a full DOM replacement of the
dynamic sections (simplest) or targeted updates (optimized).

### Task Detail / Actions / Network Pages

These pages connect to the per-conversation SSE endpoints when the task is
active (IN_PROGRESS). When the task is completed, they show static content
loaded at page render time.

**Actions page**: Connects to `/api/conversation/{id}/events/stream`. New events
are rendered as HTML and appended to the timeline DOM.

**Network page**: Connects to `/api/conversation/{id}/network/stream`. New lines
are classified (allowed/blocked/error) and appended to the terminal DOM.

**Task detail page**: Connects to `/api/events/stream` to update the status
badge, timing information, and success/failure indicator in real time.

## Implementation Phases

The implementation is split into self-contained phases. Each phase produces a
working system — no phase leaves the codebase in an intermediate state.

### Phase 1: VersionedStore and Frozen State — IMPLEMENTED

**Goal**: Introduce `VersionClock` and `VersionedStore`. Convert `BootState` and
`RepoState` to frozen dataclasses. Update `TaskTracker` to use the clock. Fix
the existing thread-safety bugs.

**Scope**:

- New module: `lib/dashboard/versioned.py` — `VersionClock`, `VersionedStore`,
  `Versioned`
- Modify `lib/dashboard/tracker.py` — freeze `BootState`, `RepoState`;
  `TaskTracker` accepts `VersionClock`, calls `tick()` on mutations, adds
  `get_snapshot()`
- Modify `lib/gateway/service/gateway.py` — create `VersionClock`,
  `VersionedStore[BootState]`, `VersionedStore[tuple[RepoState, ...]]`; update
  boot sequence to use `store.update(replace(...))`
- Modify `lib/dashboard/handlers.py` — read from versioned stores instead of
  direct object access
- Modify `lib/dashboard/server.py` — accept versioned stores
- Update `spec/dashboard.md` — document versioned state contract
- Tests: full coverage of `versioned.py`, update existing tracker and dashboard
  tests

**Observable result**: Dashboard works exactly as before (still meta-refresh),
but state access is now atomic and versioned. Thread-safety bugs in BootState
and RepoState are fixed.

### Phase 2: SSE State Stream — IMPLEMENTED

**Goal**: Add the `/api/events/stream` SSE endpoint with connection limits and
polling fallback. Replace meta-refresh on the main dashboard with EventSource.

**Scope**:

- New module: `lib/dashboard/sse.py` — SSE response helpers (`format_sse_event`,
  `format_sse_comment`, `build_state_snapshot`, `sse_state_stream` generator),
  `SSEConnectionManager`, state-to-dict conversion helpers
- Modify `lib/dashboard/server.py` — add `/api/events/stream` route, accept
  `clock` parameter, create `SSEConnectionManager`
- Modify `lib/dashboard/handlers.py` — add `handle_events_stream()` handler that
  uses `VersionClock.wait()` and `SSEConnectionManager`; add `ETag` headers to
  JSON API endpoints (`/api/conversations`, `/api/repos`, `/health`) with
  `304 Not Modified` support via `If-None-Match`
- Frontend JS in `lib/dashboard/views/dashboard.py` — `EventSource` connection
  with fallback to ETag polling, `updateDashboard()` DOM updater that replaces
  boot banner, repos section, and task columns in real time
- Removed meta-refresh from main dashboard template
- Removed `boot_refresh_interval()` helper (no longer needed)
- Added IDs to dynamic DOM sections: `boot-container`, `repos-container`,
  `queued-header`, `queued-list`, `in-progress-header`, `in-progress-list`,
  `completed-header`, `completed-list`, `status-notice`
- Modify `lib/gateway/service/gateway.py` — pass `clock` to `DashboardServer`
- Tests: SSE handler tests, connection limit tests, ETag/304 tests, state stream
  generator tests, snapshot builder tests

**Observable result**: Main dashboard updates in real time when tasks are
queued, start, or complete. No more page refreshes. Falls back gracefully to
5-second ETag polling when SSE connections are exhausted. Task detail and other
pages still use meta-refresh (Phase 3).

### Phase 3: Log Stream Endpoints

**Goal**: Add per-conversation SSE endpoints for `events.jsonl` and
`network-sandbox.log` tailing. Update actions and network pages to use them.

**Scope**:

- Modify `lib/sandbox/network_log.py` — add `tail(offset)` method to
  `NetworkLog`
- Modify `lib/dashboard/server.py` — add `/api/conversation/{id}/events/stream`
  and `/api/conversation/{id}/network/stream` routes
- Modify `lib/dashboard/handlers.py` — add `handle_events_log_stream()` and
  `handle_network_log_stream()` handlers with file-tailing loops
- Modify `lib/dashboard/views/actions.py` — add JS for EventSource connection,
  append events to timeline DOM
- Modify `lib/dashboard/views/network.py` — add JS for EventSource connection,
  append log lines to terminal DOM
- Remove meta-refresh from actions and network page templates
- Update task detail page to use SSE for status updates (connect to state
  stream)
- Remove remaining meta-refresh tags from all pages
- Tests: log stream handler tests, NetworkLog.tail() tests

**Observable result**: Actions and network pages show live streaming output
during task execution. All pages are fully real-time — no meta-refresh anywhere.

## Testing Strategy

Each phase must maintain 100% test coverage.

**VersionedStore tests**: Thread-safety tests (concurrent reads/writes), version
monotonicity, wait/timeout behavior, immutability enforcement.

**SSE tests**: Mock clock/stores, verify SSE message format, verify catch-up on
connect, verify heartbeat, verify cleanup on disconnect.

**Log stream tests**: Mock EventLog.tail()/NetworkLog.tail(), verify
offset-based resumption, verify terminal event on task completion.

**Integration**: End-to-end test that submits a message, connects to SSE, and
verifies state transitions arrive in order.

## Migration

- **No breaking API changes.** Existing JSON API endpoints continue to work. SSE
  endpoints are additive.
- **Graceful degradation.** Three levels of fallback:
  1. **SSE available**: Real-time push updates, sub-second latency.
  2. **SSE unavailable** (connection limit, network issue): Automatic fallback
     to ETag polling (5-second interval). Same data format, slightly higher
     latency.
  3. **JavaScript disabled**: Server-rendered HTML shows current state at page
     load time. No auto-update — user refreshes manually. Acceptable for this
     use case.
