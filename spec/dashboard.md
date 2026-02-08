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
- Real-time streaming of task output

### Future Considerations

- Server-Sent Events (SSE) for live task updates
- View streaming output from Claude execution

## Architecture

### Components

The dashboard consists of two main components in `lib/dashboard/`:

- **TaskTracker**: Thread-safe in-memory task state management with bounded
  history (default 100 completed tasks)
- **DashboardServer**: WSGI application using Werkzeug, runs in background
  thread

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

During boot, the dashboard auto-refreshes every 5 seconds. After boot completes
(or fails), it returns to the normal 30-second refresh interval.

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

| Route                             | Method | Description                            |
| --------------------------------- | ------ | -------------------------------------- |
| `/`                               | GET    | Main dashboard with task lists         |
| `/.version`                       | GET    | Full git version info (plain text)     |
| `/repo/{repo_id}`                 | GET    | Repository detail view                 |
| `/conversation/{conv_id}`         | GET    | Task detail view                       |
| `/conversation/{conv_id}/session` | GET    | Raw session JSON                       |
| `/conversation/{conv_id}/actions` | GET    | Actions timeline viewer                |
| `/api/repos`                      | GET    | JSON API for repository status         |
| `/api/conversations`              | GET    | JSON API for task list                 |
| `/api/conversation/{id}`          | GET    | JSON API for single task               |
| `/api/conversation/{id}/stop`     | POST   | Stop a running task                    |
| `/health`                         | GET    | Health check endpoint (includes repos) |

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

- Git commit SHA (short 7-8 character form, monospace)
- Worktree status badge: green "clean" or red "modified"
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
disk by reading the session file from the conversation directory.

This enables:

- Following links in acknowledgment emails after service restarts
- Viewing historical task details without keeping all tasks in memory
- API access to past task data including session statistics

Past tasks loaded from disk are marked as COMPLETED with a placeholder subject
(`[Past conversation {id}]`). The main dashboard completed tasks column is NOT
populated from disk—only direct URL access triggers disk loading.

### Styling

- Auto-refresh: 30 seconds (dashboard), 10 seconds (task detail), 5 seconds
  (during boot)
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

- **SSE streaming**: Real-time updates without polling
- **Output preview**: Show last N lines of Claude output
- **Conversation browser**: View full conversation history
