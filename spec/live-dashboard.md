# Live Dashboard

Real-time dashboard updates via Server-Sent Events (SSE). This is the companion
spec to [dashboard.md](dashboard.md), which covers the overall dashboard
architecture, endpoints, UI, and configuration.

## Overview

All dashboard pages receive real-time updates via SSE, with no polling or
meta-refresh. Three SSE endpoint types serve different update needs:

1. **State stream** — composite state snapshots (tasks, boot, repos) pushed on
   every version tick
2. **Event log stream** — per-conversation Claude streaming events from
   `events.jsonl`
3. **Network log stream** — per-conversation network log lines from
   `network-sandbox.log`

### Design Principles

- **All dashboard-visible state flows through a versioned interface.** No direct
  field mutations on shared mutable objects.
- **Immutable snapshots.** State objects are frozen dataclasses. Mutations
  create new instances via `dataclasses.replace()`.
- **Single version clock.** One global monotonic counter tracks all state
  changes. SSE clients wait on one condition variable.
- **Append-only logs use file offsets as cursors.** No versioning needed — the
  append-only property guarantees offset stability.

## Versioned State

### VersionClock

A single global monotonic counter shared by all versioned stores. Provides the
condition variable that SSE endpoints wait on.

- `tick()` increments the version and notifies all waiters
- `wait(known, timeout)` blocks until version > known, or returns None on
  timeout
- **Restart detection**: if `known > current version`, the client has a stale
  version from a previous server lifetime — return immediately so the client
  resets

### VersionedStore

Generic thread-safe container wrapping an immutable value with a version number.
Each `update()` replaces the value and ticks the shared clock.

### Contract

**Rule: if the dashboard displays it, it must live in a VersionedStore (or be an
append-only log with offset-based tailing).**

State objects in a `VersionedStore` must be immutable (frozen dataclasses or
tuples). This guarantees:

- **Atomicity**: readers always see a consistent snapshot (no torn reads)
- **Versioning**: every change has a monotonic version number
- **Notification**: SSE waiters wake on every change

## Append-Only Log Streaming

### events.jsonl

The `EventLog` class provides `tail(offset) -> (events, new_offset)` for
offset-based tailing of Claude streaming events.

### network-sandbox.log

The `NetworkLog` class provides `tail(offset) -> (lines, new_offset)` for
offset-based tailing of network log lines.

### Protocol

Both log streams follow the same pattern:

1. Client connects with `?offset=<N>` where N is the event log byte offset at
   page render time (embedded in the SSE script by the server)
2. Server calls `tail(offset)` and sends any new data
3. If no new data and task is still running, polls on interval (500ms)
4. Sends heartbeat comments every 15 seconds
5. When task completes, drains remaining data and sends terminal `done` event

## SSE Transport

### WSGI Compatibility

SSE connections hold a WSGI thread for their duration. The server uses
werkzeug's `make_server` with `threaded=True`.

### Connection Limits

A global `SSEConnectionManager` enforces a maximum of 8 concurrent SSE
connections. When the limit is reached, the server responds with
`429 Too Many Requests` and `Retry-After: 5`. The client falls back to polling.

### Endpoints

| Endpoint                                | Purpose                      | Cursor         |
| --------------------------------------- | ---------------------------- | -------------- |
| `/api/events/stream`                    | Task + boot + repo state     | Version number |
| `/api/conversation/{id}/events/stream`  | Claude streaming events      | Byte offset    |
| `/api/conversation/{id}/events/poll`    | Events polling fallback      | Byte offset    |
| `/api/conversation/{id}/network/stream` | Network log lines            | Byte offset    |
| `/api/conversation/{id}/network/poll`   | Network log polling fallback | Byte offset    |

### State Stream (`/api/events/stream`)

Pushes a composite state snapshot whenever any versioned state changes.

**SSE event format**:

```
event: state
data: {"version": 42, "tasks": [...], "boot": {...}, "repos": [...]}
```

Full snapshots (not deltas) — state is small enough that this avoids client-side
delta application complexity.

### Event Log Stream (`/api/conversation/{id}/events/stream`)

**SSE event format**:

```
event: html
data: {"offset": 1234, "html": "<div class=\"event\">...rendered HTML...</div>"}

event: done
data: {"offset": 1234}
```

Events are rendered server-side as HTML fragments using the same rendering
functions as the initial page load, ensuring consistent output between static
and streaming views.

### Network Log Stream (`/api/conversation/{id}/network/stream`)

**SSE event format**:

```
event: html
data: {"offset": 5678, "html": "<div class=\"log-line allowed\">...</div>"}

event: done
data: {"offset": 5678}
```

Network log lines are rendered server-side as HTML fragments using the same
rendering functions as the initial page load.

### Connection Lifecycle

- **Admission**: handler calls `connection_manager.try_acquire()`. If at limit,
  respond `429` with `Retry-After: 5`.
- **Heartbeat**: comment line (`: heartbeat`) every 15 seconds to detect dead
  connections.
- **Reconnection**: SSE `retry:` field set to 1000ms. Browser reconnects
  automatically.
- **Client `Last-Event-ID`**: set to last version/offset for catch-up on
  reconnect.
- **Cleanup**: `connection_manager.release()` in a `finally` block.

### Polling Fallback

When SSE is unavailable, all pages fall back to polling automatically.

**State-based pages** (main dashboard, task detail, repo detail) poll JSON API
endpoints with `ETag` / `If-None-Match` for `304 Not Modified` responses. On
change, they reload the page to get a fresh server render.

**Append-only log pages** (actions viewer, network viewer) poll dedicated
endpoints that return new content since the last offset:

- `GET /api/conversation/{id}/events/poll?offset=N`
- `GET /api/conversation/{id}/network/poll?offset=N`

These return `{offset, html, done}` JSON. The `offset` is used as the ETag (via
`If-None-Match` with format `"o<offset>"`). When no new content is available and
the ETag matches, the server returns `304`. The `done` field indicates whether
the task has completed, allowing the client to stop polling.

## Page Update Strategy

| Page           | SSE Source                              | Polling Fallback                               | Behavior                                      |
| -------------- | --------------------------------------- | ---------------------------------------------- | --------------------------------------------- |
| Main dashboard | `/api/events/stream`                    | `/api/conversations` (ETag, reload)            | Updates task lists, boot, repos               |
| Task detail    | `/api/events/stream`                    | `/api/conversations` (reload on completion)    | Updates status, timing; reloads on completion |
| Actions viewer | `/api/conversation/{id}/events/stream`  | `/api/conversation/{id}/events/poll` (append)  | Appends events to timeline                    |
| Network viewer | `/api/conversation/{id}/network/stream` | `/api/conversation/{id}/network/poll` (append) | Appends log lines                             |
| Repo detail    | `/api/events/stream`                    | `/api/repos` (ETag, reload)                    | Updates status badge, error section           |

Active tasks (QUEUED, IN_PROGRESS) connect to SSE. Completed tasks render static
content.

## Graceful Degradation

Three levels of fallback:

1. **SSE available**: real-time push, sub-second latency
2. **SSE unavailable** (connection limit, network issue): automatic polling
   fallback. State-based pages poll with ETag (5s interval) and reload on
   change. Append-only log pages poll dedicated endpoints (3s interval) and
   incrementally append new content, preserving scroll position.
3. **JavaScript disabled**: server-rendered HTML at page load, manual refresh
