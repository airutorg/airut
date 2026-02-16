# Dashboard

A minimal web dashboard for monitoring the Claude email service's task queue and
execution history.

## Overview

The email service processes requests asynchronously via email. This dashboard
provides visibility into queued, in-progress, and completed tasks without
requiring direct access to logs or the server console.

**Key principle**: Monitoring interface with minimal actions (stop running
tasks).

## Requirements

### Core Features

- Display tasks in three states: queued, in-progress, completed
- Show original email subject line for each task
- Show timing information:
  - Queued: time since added to queue
  - In-progress: execution duration so far
  - Completed: total execution time
- Allow inspecting individual task details
- In-memory task tracking for active tasks
- Load past tasks from disk when accessed via direct URL

### Non-Goals

- Authentication (reverse proxy handles this)
- Populating completed tasks list from disk on restart

## Architecture

### Components

The dashboard consists of these components in `airut/dashboard/`:

- **VersionClock + VersionedStore** (`versioned.py`): Global monotonic version
  counter and thread-safe versioned state containers. Every state mutation ticks
  the clock. SSE endpoints wait on it and wake on any change.
- **SSE** (`sse.py`): Server-Sent Events support for real-time dashboard
  updates. Includes SSE message formatting, state stream generator, and
  connection manager to enforce concurrent connection limits.
- **TaskTracker** (`tracker.py`): Thread-safe in-memory task state management
  with bounded history (default 100 completed tasks). Integrates with the shared
  `VersionClock`.
- **DashboardServer** (`server.py`): WSGI application using Werkzeug, runs in
  background thread.

### State Management

All dashboard-visible state flows through versioned interfaces. See
[live-dashboard.md](live-dashboard.md) for the full versioned state design
(VersionClock, VersionedStore, immutability contract, and append-only log
streaming).

Key stores:

- **BootState**: Frozen dataclass wrapped in `VersionedStore[BootState]`.
- **RepoStates**: Frozen dataclass collection wrapped in
  `VersionedStore[tuple[RepoState, ...]]`.
- **TaskTracker**: Uses internal locking and calls `VersionClock.tick()` on
  every mutation. Provides `get_snapshot()` for atomic reads.

### Data Flow

1. Email arrives → `TaskTracker.add_task()` → State: QUEUED
2. Thread pool picks up task → `TaskTracker.start_task()` → State: IN_PROGRESS
3. Execution completes → `TaskTracker.complete_task()` → State: COMPLETED
4. Dashboard request → Render task list or detail view

### Boot Progress Reporting

The dashboard starts immediately when the service launches — before the full
boot sequence (proxy setup, repo initialization) completes. This provides
visibility into startup progress and errors from the moment the service starts.

**Boot phases** (displayed as a banner on the main dashboard):

1. **Starting** — Service initializing
2. **Proxy** — Building proxy image and creating egress network
3. **Repos** — Starting repository listeners (git mirror update, IMAP
   connection)
4. **Ready** — Boot complete, service operational (banner hidden)
5. **Failed** — Boot error with full details (error type, message, traceback)

The main dashboard receives real-time updates via Server-Sent Events (SSE). When
SSE is unavailable, it falls back to ETag-based polling (5-second interval). See
`spec/live-dashboard.md` for the full SSE specification.

The `/health` endpoint reflects boot state: `"booting"` during startup,
`"error"` on boot failure, `"ok"` when running with live repos, `"degraded"`
when no repos are live.

**Resilient mode** (`--resilient` CLI flag): When enabled, boot failures don't
crash the service. Instead, the error is displayed on the dashboard and the
service stays alive. The systemd service unit uses this flag to avoid restart
loops caused by configuration issues. Default behavior (without the flag) is to
exit on boot failure.

### Graceful Repo Initialization

During service startup, each repository is initialized independently:

1. Service attempts to start listener for each configured repo
2. If a repo fails (e.g., IMAP auth error, git clone failure), error is recorded
3. Service continues with repos that succeeded
4. If ALL repos fail, service raises RuntimeError and exits (unless resilient
   mode)
5. Dashboard displays status of all repos (live and failed)

This enables partial operation when some repos have issues (e.g., temporary
credential problems) while others continue processing emails.

### HTTP Endpoints

| Route                                   | Method | Description                            |
| --------------------------------------- | ------ | -------------------------------------- |
| `/`                                     | GET    | Main dashboard with task lists         |
| `/version`                              | GET    | Structured version info (JSON)         |
| `/update`                               | GET    | Upstream update check (JSON)           |
| `/repo/{repo_id}`                       | GET    | Repository detail view                 |
| `/conversation/{conv_id}`               | GET    | Task detail view                       |
| `/conversation/{conv_id}/actions`       | GET    | Actions timeline viewer                |
| `/conversation/{conv_id}/network`       | GET    | Network logs viewer                    |
| `/api/repos`                            | GET    | JSON API for repository status (ETag)  |
| `/api/conversations`                    | GET    | JSON API for task list (ETag)          |
| `/api/conversation/{id}`                | GET    | JSON API for single task               |
| `/api/conversation/{id}/stop`           | POST   | Stop a running task                    |
| `/api/tracker`                          | GET    | JSON API for full tracker state (ETag) |
| `/api/events/stream`                    | GET    | SSE state stream (real-time updates)   |
| `/api/conversation/{id}/events/stream`  | GET    | SSE event log stream (per-task)        |
| `/api/conversation/{id}/network/stream` | GET    | SSE network log stream (per-task)      |
| `/health`                               | GET    | Health check endpoint (ETag)           |

### `GET /api/tracker`

Returns an atomic snapshot of the full task tracker state. Designed for
integration tests and monitoring tools that need a single request to retrieve
all task data with status counts.

**Response** (`application/json`):

```json
{
  "version": 42,
  "counts": {
    "queued": 1,
    "in_progress": 2,
    "completed": 10
  },
  "tasks": [
    {
      "conversation_id": "a1b2c3d4",
      "subject": "Help with task",
      "repo_id": "my-repo",
      "sender": "user@example.com",
      "status": "completed",
      "queued_at": 1700000000.0,
      "started_at": 1700000001.0,
      "completed_at": 1700000060.0,
      "success": true,
      "message_count": 1,
      "model": "sonnet"
    }
  ]
}
```

| Field             | Type             | Description                                                                |
| ----------------- | ---------------- | -------------------------------------------------------------------------- |
| `version`         | `int`            | Monotonic version clock value at time of snapshot                          |
| `counts`          | `dict`           | Task counts keyed by status (`queued`, `in_progress`, `completed`)         |
| `tasks`           | `list[object]`   | All tracked tasks (active + completed history)                             |
| `tasks[].status`  | `string`         | One of `queued`, `in_progress`, `completed`                                |
| `tasks[].success` | `bool \| null`   | `null` while not completed; `true`/`false` when done                       |
| `tasks[].model`   | `string \| null` | Claude model used (e.g., `"sonnet"`, `"opus"`), or `null` if not yet known |

Supports `ETag` / `If-None-Match` conditional requests — returns
`304 Not Modified` when the version clock has not advanced since the client's
last request.

## Configuration

### Environment Variables

| Variable             | Default     | Description                                     |
| -------------------- | ----------- | ----------------------------------------------- |
| `DASHBOARD_ENABLED`  | `true`      | Enable/disable dashboard                        |
| `DASHBOARD_HOST`     | `127.0.0.1` | Host to bind to                                 |
| `DASHBOARD_PORT`     | `5200`      | Port to bind to                                 |
| `DASHBOARD_BASE_URL` | (optional)  | Public URL for dashboard links in email replies |

Port 5200 chosen to avoid conflict with Fava (5100) and stay in unprivileged
range.

When `DASHBOARD_BASE_URL` is set, acknowledgment emails include a link to track
task progress (e.g.,
`https://dashboard.example.com/conversation/{conversation_id}`).

## Dependencies

Uses only existing project dependencies:

- **werkzeug**: WSGI utilities (via fava dependency)
- **threading**, **dataclasses**, **json**, **html**: stdlib

No new dependencies required.

## UI Design

### Main Dashboard

Three-column layout showing queued, in-progress, and completed tasks.

**Header** displays version information:

- Git commit SHA or version tag (monospace, links to `/version` JSON)
- Update status badge: green "up to date" or yellow "update available" (fetched
  asynchronously from `/update` to avoid blocking page load). Hover shows
  current and latest version.
- Service start timestamp

**Repository status section** (below header):

- Lists all configured repositories with status indicators
- Green dot for live repos, red dot for failed repos
- Summary count: "N live, M failed"
- Each repo links to its detail page
- Failed repos show error type as a hint

**Task cards** display:

- Conversation ID (linked to detail view)
- Email subject (truncated)
- Timing information
- Success/failure indicator for completed tasks

### Task Detail

Single task view showing:

- Full subject line
- Status with success/failure indication
- Claude model used (e.g., "opus", "sonnet")
- Timestamps (queued, started, completed)
- Duration breakdowns (queue time, execution time, total)
- Message count

### Repository Detail

Per-repository view showing:

- Repository ID and status (LIVE or FAILED)
- Git repository URL
- IMAP server hostname
- Storage directory path
- For failed repos: error type and message with full details

### Past Task Loading

When a task detail URL is accessed but the task is not in the in-memory tracker
(e.g., after a service restart), the dashboard attempts to load the task from
disk by reading the conversation file from the conversation directory.

This enables:

- Following links in acknowledgment emails after service restarts
- Viewing historical task details without keeping all tasks in memory
- API access to past task data including conversation statistics

Past tasks loaded from disk are marked as COMPLETED with a placeholder subject
(`[Past conversation {id}]`). The main dashboard completed tasks column is NOT
populated from disk—only direct URL access triggers disk loading.

### Styling

- Real-time updates via SSE on all pages (no polling or meta-refresh)
- Responsive layout (single column on mobile)
- Color coding: yellow (queued), blue (in-progress), green (success), red
  (failed)
- Boot banner: blue with spinner (in-progress), red with error details (failed)

## Security

- **No authentication**: Dashboard assumes it's behind a reverse proxy
- **Localhost binding**: Default to 127.0.0.1 to prevent accidental exposure
- **Minimal actions**: Only action is stopping running tasks

The dashboard exposes conversation IDs, email subjects, and timing information.
Acceptable for a single-user system behind authentication.

## Future Enhancements

- **Output preview**: Show last N lines of Claude output
- **Conversation browser**: View full conversation history
