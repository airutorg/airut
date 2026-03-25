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
- Real-time updates with sub-second latency

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
- **Templating** (`templating.py`): Jinja2 environment with auto-escaping,
  `importlib.resources`-based template loader, `render_template()` helper, and
  static file serving with content-hash ETags.
- **Templates** (`templates/`): Jinja2 templates split into `base.html`,
  `components/` (reusable fragments), and `pages/` (full page templates).
- **Static assets** (`static/`): CSS (`styles/`), JavaScript (`js/`), and
  vendored htmx (`vendor/`). Served via `/static/<path>` with ETag caching.

### State Management

All dashboard-visible state flows through versioned interfaces.

**Design principles:**

- **All dashboard-visible state flows through a versioned interface.** No direct
  field mutations on shared mutable objects.
- **Immutable snapshots.** State objects are frozen dataclasses. Mutations
  create new instances via `dataclasses.replace()`.
- **Single version clock.** One global monotonic counter tracks all state
  changes. SSE clients wait on one condition variable.
- **Append-only logs use file offsets as cursors.** No versioning needed — the
  append-only property guarantees offset stability.

**Contract: if the dashboard displays it, it must live in a VersionedStore (or
be an append-only log with offset-based tailing).**

State objects in a `VersionedStore` must be immutable (frozen dataclasses or
tuples). This guarantees:

- **Atomicity**: readers always see a consistent snapshot (no torn reads)
- **Versioning**: every change has a monotonic version number
- **Notification**: SSE waiters wake on every change

**Key stores:**

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

The `/api/health` endpoint reflects boot state: `"booting"` during startup,
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

| Route                                   | Method | Description                                 |
| --------------------------------------- | ------ | ------------------------------------------- |
| `/`                                     | GET    | Main dashboard with task lists              |
| `/static/<path>`                        | GET    | Static assets (CSS, JS, vendor)             |
| `/task/{task_id}`                       | GET    | Task detail view (primary detail page)      |
| `/conversation/{conv_id}`               | GET    | Conversation overview (all tasks + replies) |
| `/task/{task_id}/actions`               | GET    | Actions timeline viewer (by task)           |
| `/task/{task_id}/network`               | GET    | Network logs viewer (by task)               |
| `/conversation/{conv_id}/actions`       | GET    | Actions timeline viewer (by conversation)   |
| `/conversation/{conv_id}/network`       | GET    | Network logs viewer (by conversation)       |
| `/repo/{repo_id}`                       | GET    | Repository detail view                      |
| `/api/version`                          | GET    | Structured version info (JSON)              |
| `/api/update`                           | GET    | Upstream update check (JSON or HTML)        |
| `/api/repos`                            | GET    | JSON API for repository status (ETag)       |
| `/api/conversations`                    | GET    | JSON API for task list (ETag)               |
| `/api/task/{task_id}`                   | GET    | JSON API for single task by task_id         |
| `/api/conversation/{id}`                | GET    | JSON API for single task by conversation    |
| `/api/conversation/{id}/stop`           | POST   | Stop a running task                         |
| `/api/tracker`                          | GET    | JSON API for full tracker state (ETag)      |
| `/api/events/stream`                    | GET    | SSE state stream (real-time updates)        |
| `/api/task/{task_id}/events/stream`     | GET    | SSE state stream (task-scoped, HTML mode)   |
| `/api/conversation/{id}/events/stream`  | GET    | SSE event log stream (per-task)             |
| `/api/conversation/{id}/events/poll`    | GET    | Events polling fallback                     |
| `/api/conversation/{id}/network/stream` | GET    | SSE network log stream (per-task)           |
| `/api/conversation/{id}/network/poll`   | GET    | Network log polling fallback                |
| `/api/health`                           | GET    | Health check endpoint (ETag)                |
| `/api/config-status`                    | GET    | Config reload status badge (HTML)           |
| `/config`                               | GET    | Config editor page (global settings)        |
| `/api/config/field`                     | PATCH  | Set or clear a config field (form-encoded)  |
| `/api/config/diff`                      | GET    | Compare edit buffer vs live config (HTML)   |
| `/api/config/save`                      | POST   | Validate and write config YAML              |
| `/api/config/discard`                   | POST   | Reset edit buffer                           |
| `/api/config/add`                       | POST   | Add item to a collection field              |
| `/api/config/remove`                    | POST   | Remove item from a collection field         |

### `GET /api/tracker`

Returns an atomic snapshot of the full task tracker state. Designed for
integration tests and monitoring tools that need a single request to retrieve
all task data with status counts.

**Response** (`application/json`):

```json
{
  "version": 42,
  "counts": {
    "queued": 0,
    "authenticating": 0,
    "pending": 0,
    "executing": 1,
    "completed": 10
  },
  "tasks": [
    {
      "task_id": "a1b2c3d4e5f6",
      "conversation_id": "a1b2c3d4",
      "display_title": "Help with task",
      "repo_id": "my-repo",
      "sender": "user@example.com",
      "authenticated_sender": "user@example.com",
      "status": "completed",
      "completion_reason": "success",
      "queued_at": 1700000000.0,
      "started_at": 1700000001.0,
      "completed_at": 1700000060.0,
      "model": "sonnet",
      "reply_index": 0
    }
  ]
}
```

| Field                       | Type             | Description                                                                                   |
| --------------------------- | ---------------- | --------------------------------------------------------------------------------------------- |
| `version`                   | `int`            | Monotonic version clock value at time of snapshot                                             |
| `counts`                    | `dict`           | Task counts keyed by status (`queued`, `authenticating`, `pending`, `executing`, `completed`) |
| `tasks`                     | `list[object]`   | All tracked tasks (active + completed history)                                                |
| `tasks[].task_id`           | `string`         | Stable unique task identifier (12-char hex UUID)                                              |
| `tasks[].conversation_id`   | `string`         | Conversation ID (empty until assigned after authentication)                                   |
| `tasks[].status`            | `string`         | One of `queued`, `authenticating`, `pending`, `executing`, `completed`                        |
| `tasks[].completion_reason` | `string \| null` | Why the task completed (e.g., `"success"`, `"auth_failed"`), or `null` while active           |
| `tasks[].model`             | `string \| null` | Claude model used (e.g., `"sonnet"`, `"opus"`), or `null` if not yet known                    |
| `tasks[].reply_index`       | `int \| null`    | Index of this task's reply in the conversation (0-based), or `null` if not yet assigned       |

Supports `ETag` / `If-None-Match` conditional requests — returns
`304 Not Modified` when the version clock has not advanced since the client's
last request.

## Real-Time Updates

All dashboard pages receive real-time updates via SSE, with automatic fallback
to polling when SSE is unavailable.

### SSE Stream Types

Three SSE endpoint types serve different update needs:

| Endpoint                                | Purpose                       | Cursor         |
| --------------------------------------- | ----------------------------- | -------------- |
| `/api/events/stream`                    | Task + boot + repo state      | Version number |
| `/api/task/{id}/events/stream`          | Task-scoped state (HTML mode) | Version number |
| `/api/conversation/{id}/events/stream`  | Claude streaming events       | Byte offset    |
| `/api/conversation/{id}/network/stream` | Network log lines             | Byte offset    |

### State Stream (`/api/events/stream`)

Pushes a composite state snapshot whenever any versioned state changes. Full
snapshots (not deltas) — state is small enough that this avoids client-side
delta application complexity.

**JSON mode** (default):

```
event: state
data: {"version": 42, "tasks": [...], "boot": {...}, "repos": [...]}
```

**HTML mode** (`?format=html`): Sends separate named SSE events per dashboard
region, each containing pre-rendered HTML. The htmx SSE extension uses
`sse-swap="<event-name>"` to target each element independently:

- `boot-state`, `repos`
- `pending-header`, `pending-tasks`
- `executing-header`, `executing-tasks`
- `completed-header`, `completed-tasks`

### Append-Only Log Streams

Event log and network log streams send raw HTML fragments in the SSE `data:`
field with the byte offset in the SSE `id:` field. The htmx SSE extension uses
`sse-swap="html"` with `hx-swap="beforeend"` to append content directly.

```
id: 1234
event: html
data: <div class="event">...rendered HTML...</div>
```

Events are rendered server-side using the same rendering functions as the
initial page load, ensuring consistent output between static and streaming
views. A terminal `done` event signals task completion.

Both log streams follow the same protocol:

1. Client connects with `?offset=<N>` (byte offset at page render time)
2. Server tails the log file and sends new data as HTML fragments
3. Heartbeat comments (`: heartbeat`) every 15 seconds
4. When task completes, drains remaining data and sends `done` event

### SSE Transport

SSE connections hold a WSGI thread for their duration. A global connection
manager enforces a maximum of 8 concurrent SSE connections. When the limit is
reached, the server responds with `429 Too Many Requests` and `Retry-After: 5`.

Connection lifecycle:

- **Reconnection**: SSE `retry:` field set to 1000ms for automatic browser
  reconnection
- **Catch-up**: `Last-Event-ID` carries the last version/offset for resumption
- **Restart detection**: if the client's version exceeds the server's current
  version (stale from previous server lifetime), return immediately to force
  client reset
- **Visibility change**: when a tab returns from background, state-based pages
  reload immediately if the SSE connection is no longer open (avoids the htmx
  SSE extension's exponential backoff delay of up to 64 seconds)

### Page Update Strategy

| Page           | SSE Source                                   | htmx Swap                | Behavior                                         |
| -------------- | -------------------------------------------- | ------------------------ | ------------------------------------------------ |
| Main dashboard | `/api/events/stream?format=html`             | Per-region `sse-swap`    | Updates task lists, boot, repos via named events |
| Task detail    | `/api/task/{id}/events/stream`               | Per-field `sse-swap`     | Updates status, actions, timing, todo progress   |
| Actions viewer | `/api/conversation/{id}/events/stream`       | `sse-swap="html"` append | Appends events to timeline                       |
| Network viewer | `/api/conversation/{id}/network/stream`      | `sse-swap="html"` append | Appends log lines                                |
| Repo detail    | `/api/events/stream?format=html&repo_id=...` | Per-field `sse-swap`     | Updates status badge, error section              |

Active tasks connect to SSE via htmx. Completed tasks render static content
without SSE.

### Graceful Degradation

Four levels of fallback:

1. **SSE available**: real-time push via htmx SSE extension, sub-second latency
2. **Tab backgrounded**: `visibilitychange` listener detects tab return;
   state-based pages (dashboard, task detail, repo detail) reload immediately
   when SSE connection is no longer open, bypassing exponential backoff.
   Append-only pages (actions, network) rely on existing backoff/polling since
   they need offset-based resumption via `Last-Event-ID`.
3. **SSE unavailable** (connection limit, network issue): `sse-fallback.js`
   detects `htmx:sseError` and falls back to full page reload. Append-only log
   pages (actions, network) fall back to polling dedicated endpoints (3s
   interval) that return `{offset, html, done}` JSON.
4. **JavaScript disabled**: server-rendered HTML at page load, manual refresh

Polling fallback endpoints for append-only logs:

- `GET /api/conversation/{id}/events/poll?offset=N`
- `GET /api/conversation/{id}/network/poll?offset=N`

These return `{offset, html, done}` JSON with ETag support (format
`"o<offset>"`). The `done` field indicates task completion, allowing the client
to stop polling.

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

- **werkzeug**: WSGI utilities (via fava dependency)
- **jinja2**: Template engine with auto-escaping
- **htmx** (vendored): Declarative HTML-over-the-wire updates via htmx SSE
  extension. Vendored at `static/vendor/` — see `scripts/update_vendor.py`
- **threading**, **dataclasses**, **json**: stdlib

## UI Design

### Main Dashboard

Three-column layout showing queued, in-progress, and completed tasks.

**Server section** displays version and status information:

- Git commit SHA or version tag (monospace, links to GitHub release/commit page)
- Update status badge: green "up to date" or yellow "update available" (fetched
  asynchronously from `/api/update` to avoid blocking page load). Hover shows
  current and latest version.
- Config reload status badge: blue "restart pending" when a configuration change
  requires a server restart (fetched from `/api/config-status`, polled every
  30s)
- "Configure" button (right-aligned, links to config editor)

**Repository status section** (below server section):

- Lists all configured repositories with status indicators
- Green dot for live repos, red dot for failed repos
- Summary count: "N live, M failed"
- Each repo links to its detail page
- Failed repos show error type as a hint

**Task cards** display:

- Task ID (linked to `/task/{task_id}` detail view)
- Conversation ID badge (linked to `/conversation/{conv_id}`, shown only when
  assigned — auth-failed tasks with no conversation_id omit the badge)
- Email subject (truncated)
- Timing information
- Success/failure indicator for completed tasks

### Task Detail (`/task/{task_id}`)

Primary detail view for a single task. Every task has a `task_id` from creation,
so this works for all tasks including auth failures that never receive a
`conversation_id`.

**Summary card** — subject, repository, sender, status, action buttons. If
`conversation_id` is assigned, shows a link to `/conversation/{conv_id}`. Action
buttons (View Actions, View Network) are hidden when there is no
conversation_id.

**Progress section** (active tasks only) — live-updating checklist of Claude's
TodoWrite items. Shows completed (checkmark), in-progress (spinner with
activeForm label), and pending (circle) items. Updated in real-time via the
global SSE state stream (filtered by `task_id`), with automatic fallback to
ETag-based polling when SSE is unavailable. Todo state is tracked as a list of
`TodoItem` dataclass instances (`content`, `status`, `active_form`) — a typed
contract independent of the Claude output parser types. Todos are cleared when a
task completes (success or failure) so that stale progress data is never exposed
via the API or carried over when a conversation is resumed.

**Task Details card** — model, timestamps (queued, started, completed), duration
breakdowns (queue time, execution time, total), message count, cost, and turns
for this task's specific reply.

**Reply section** — shows only the reply associated with this specific task
(matched by `reply_index`). If the task has no associated reply (auth failure,
in-progress, etc.), shows the pending request text or nothing.

### Conversation Overview (`/conversation/{conv_id}`)

Aggregate view showing all tasks for a conversation. Email acknowledgment links
(`{base_url}/conversation/{conv_id}`) point here.

**Summary card** — conversation ID, aggregate stats (total reply count, total
cost, total turns, model).

**Task list** — all tasks for this conversation, each showing:

- Task ID (linked to `/task/{task_id}`)
- Status badge with icon
- Display title (truncated)
- Timing info (queue time, execution duration, etc.)

**Conversation Replies** — full per-reply history with cost, duration, turns,
session ID, token usage, and request/response text.

### Repository Detail

Per-repository view showing:

- Repository ID and status (LIVE or FAILED)
- Git repository URL
- IMAP server hostname
- Storage directory path
- For failed repos: error type and message with full details

### Past Task Loading

When a conversation URL is accessed but no tasks are in the in-memory tracker
(e.g., after a service restart), the dashboard attempts to load a synthetic task
from disk by reading the conversation file from the conversation directory.

This enables:

- Following links in acknowledgment emails after service restarts
- Viewing historical conversation details without keeping all tasks in memory
- API access to past task data including conversation statistics

Past tasks loaded from disk are marked as COMPLETED with a synthetic task_id
(`disk-{conv_id}`) and placeholder subject (`[Past conversation {id}]`). The
main dashboard completed tasks column is NOT populated from disk — only direct
URL access to `/conversation/{conv_id}` or `/task/disk-{conv_id}` triggers disk
loading. Both the HTML task detail page and the JSON API endpoint support the
`disk-{conv_id}` task ID format, falling back to disk when the task is not found
in memory.

### Actions Viewer (`/task/{task_id}/actions`)

Timeline of Claude streaming events (system, assistant text, tool use/result,
result summaries) for a conversation. Events are grouped per reply, paired with
request text and reply metadata. Uses the unified theme with a `.log-container`
card for monospace content. Also accessible via
`/conversation/{conv_id}/actions`.

**Subagent event annotation**: Events produced by Claude's subagent (Task tool)
calls are visually distinguished in the timeline:

- Events with a non-null `parent_tool_use_id` field are rendered with left
  indentation, a colored left border, and a badge showing
  `{subagent_type}:{short_id}` (where `short_id` is the last 6 characters of the
  `parent_tool_use_id`).
- Border and badge colors are assigned deterministically from a fixed palette of
  6 CSS color classes (`--subagent-color-0` through `--subagent-color-5`) based
  on the `parent_tool_use_id`, so events from the same subagent share a
  consistent color.
- The label map (`subagent_type` values like "Explore", "CodeReview", etc.) is
  built by pre-scanning the event group for Task `tool_use` blocks and
  extracting the `subagent_type` field from their `tool_input`.
- For SSE-streamed events (arriving after the initial page render), the Task
  context is not available, so a fallback label of `"subagent"` is used instead.

### Rendering Architecture

Pages are rendered server-side using Jinja2 templates with auto-escaping. Live
updates use htmx's SSE extension for declarative DOM updates — no custom
JavaScript SSE handlers.

- **Templates** (`templates/`): `base.html` defines the page skeleton with
  blocks for `title`, `styles`, `body`, `scripts`. Component templates
  (`components/`) are reused via `{% include %}`. Page templates (`pages/`)
  extend `base.html`.
- **Static CSS** (`static/styles/`): `base.css` (design tokens, CSS custom
  properties with `prefers-color-scheme` dark mode), `components.css` (reusable
  component styles — navbar, cards, badges, buttons), `pages.css` (page-specific
  layouts — dashboard grid, log containers, detail pages).
- **Static JS** (`static/js/`): `local-time.js` (timestamp formatting),
  `auto-scroll.js` (terminal auto-scroll), `actions.js` (event toggle),
  `sse-fallback.js` (htmx SSE connection status).
- **No inline styles or scripts**: CSP uses
  `script-src 'self'; style-src 'self'` (no `'unsafe-inline'`).

### Navigation

A persistent navigation bar appears on every page with:

- **Logo**: Links to the main dashboard (`/`).
- **Breadcrumbs**: Hierarchical path showing the user's position. Handlers pass
  a `breadcrumbs` list of `(label, url)` tuples to templates. The last crumb
  (current page) is rendered without a link. Example:
  `Main / my-repo / conv abc12345 / Task def67890`.

Breadcrumb structure per page:

| Page           | Breadcrumbs                                     |
| -------------- | ----------------------------------------------- |
| Dashboard      | _(none)_                                        |
| Repo detail    | `repo_id`                                       |
| Task detail    | `repo_id` > `conv {id}` > `Task {id}`           |
| Conversation   | `repo_id` > `conv {id}`                         |
| Actions viewer | `repo_id` > `conv {id}` > `Task {id}` > Actions |
| Network viewer | `repo_id` > `conv {id}` > `Task {id}` > Network |

### URL Structure for Access Control

URLs are grouped by access scope to support reverse proxy rules:

- `/task/*` — task detail, actions, network (per-task access)
- `/conversation/*` — conversation overview, actions, network (per-conversation)
- `/repo/*` — repository detail (per-repo access)
- `/` — main dashboard (admin-level)
- `/api/*` — JSON APIs and SSE streams

### Styling

- Unified theme across all pages (no separate dark terminal theme)
- Light/dark mode via `prefers-color-scheme` CSS media query (no JS toggle)
- Real-time updates via htmx SSE extension (no custom JS SSE handlers)
- Responsive layout (single column on mobile)
- Color coding: yellow (queued), blue (in-progress), green (success), red
  (failed)
- Boot banner: blue with spinner (in-progress), red with error details (failed)

## Security

- **No authentication**: Dashboard assumes it's behind a reverse proxy
- **Localhost binding**: Default to 127.0.0.1 to prevent accidental exposure
- **Non-loopback warning**: Logs a warning at startup if bound to a non-loopback
  address (e.g., `0.0.0.0`), reminding operators to place a reverse proxy with
  authentication in front
- **Security response headers**: Every response includes defense-in-depth
  headers regardless of reverse proxy configuration:
  - `X-Content-Type-Options: nosniff` — prevents MIME sniffing
  - `X-Frame-Options: DENY` — blocks iframe embedding (clickjacking)
  - `Content-Security-Policy` — restricts resource loading origins and blocks
    framing
- **CSRF protection on mutating endpoints**: The
  `POST /api/conversation/{id}/stop` endpoint requires an `X-Requested-With`
  header. Browsers will not send custom headers on cross-origin requests without
  a CORS preflight, and the dashboard sets no `Access-Control-Allow-*` headers,
  so the preflight is denied. This prevents malicious websites from triggering
  task stops via cross-origin POST
- **Minimal actions**: Only action is stopping running tasks

The dashboard exposes task IDs, conversation IDs, email subjects, and timing
information. Acceptable for a single-user system behind authentication.

## Future Enhancements

- **Output preview**: Show last N lines of Claude output
- **Conversation browser**: View full conversation history
