# Auto-Updater Service

Automatic service update mechanism that keeps Airut synchronized with upstream
releases or the development branch.

## Overview

A systemd timer triggers periodic checks for repository updates. When updates
are available, services are reinstalled from the new code. The update process
coordinates with the email service via a lock file to avoid interrupting
in-progress work.

**Key principle**: Updates should never disrupt active email processing or
Claude execution.

## Update Channels

The updater supports two channels, selected at install time via `--channel`:

| Channel         | Target            | Default Interval | Description                      |
| --------------- | ----------------- | ---------------- | -------------------------------- |
| `rel` (default) | Latest `v*` tag   | 6 hours          | Stable tagged releases only      |
| `dev`           | `origin/main` tip | 30 minutes       | Tracks main branch (development) |

The channel is persisted in the generated `airut-updater.service` unit file's
`ExecStart` line, so it survives service restarts and self-updates.

The polling interval can be overridden with `--interval MINUTES` at install
time. The override is persisted in the generated `airut-updater.timer` unit.

## Architecture

### Components

- **airut-updater.timer** — Systemd timer triggering at channel-appropriate
  interval
- **airut-updater.service** — One-shot service running the update check
- **lib/install_services.py** — Update logic and service management
- **scripts/install_services.py** — Thin CLI entry point
- **UpdateLock** — File-based lock for coordinating with email service

### Update Flow

```
Timer triggers (per channel interval)
  -> install_services.py --update --channel <channel>
    -> Try to acquire update lock (non-blocking)
      -> If locked: Log "Email service busy", exit 0
      -> If acquired: Hold lock and continue
    -> git fetch origin [--tags for rel]
    -> Compare HEAD vs target
      -> dev: HEAD vs origin/main
      -> rel: HEAD vs latest v* tag commit
      -> If same: Exit (no updates)
      -> If different: Apply update
        -> Uninstall main services (not updater)
        -> dev: git checkout main && git reset --hard origin/main
        -> rel: git checkout <tag> (detached HEAD)
        -> uv sync (update dependencies)
        -> os.execv() to new installer with --skip-updater
          -> Reinstall services
          -> Lock auto-releases on exit
```

## Update Coordination

### Lock File Mechanism

The email service and auto-updater coordinate using an advisory file lock:

| Actor         | Lock Behavior                                     |
| ------------- | ------------------------------------------------- |
| Email service | Acquires lock when busy, releases when idle       |
| Auto-updater  | Tries non-blocking acquire; exits if lock is held |

**Lock file**: `.update.lock` in repository root (gitignored)

**Lock implementation**: Uses `fcntl.flock()` with `LOCK_EX | LOCK_NB`:

- Exclusive lock prevents concurrent access
- Non-blocking allows immediate failure detection
- Auto-releases on process exit (normal, crash, or SIGKILL)

### Busy State Definition

The email service is considered **busy** when:

- Processing one or more messages (futures pending in thread pool)
- Claude container is executing

The email service is considered **idle** when:

- No pending futures
- Waiting in poll loop for new messages

### Safety Guarantees

1. **No interrupted execution**: Updates only proceed when email service is idle
2. **Crash recovery**: `flock()` auto-releases if either service terminates
3. **No deadlock**: Non-blocking acquire means updater never waits indefinitely
4. **Retry on next interval**: Timer retries on next trigger, so updates apply
   soon after service becomes idle

## Configuration

### Install with Channel

```bash
# Default: rel channel, 6-hour polling
uv run scripts/install_services.py

# Explicit rel channel
uv run scripts/install_services.py --channel rel

# Dev channel (tracks main branch)
uv run scripts/install_services.py --channel dev

# Custom polling interval (any channel)
uv run scripts/install_services.py --channel dev --interval 15
```

### Systemd Timer (rel channel, default)

```ini
[Timer]
OnCalendar=*-*-* 0/6:00:00   # Every 6 hours
OnBootSec=1min                # 1 minute after boot
Persistent=true               # Catch up missed runs
```

### Systemd Timer (dev channel)

```ini
[Timer]
OnCalendar=*:0/30     # Every 30 minutes
OnBootSec=1min
Persistent=true
```

### Systemd Service

```ini
[Service]
Type=oneshot
WorkingDirectory=%h/airut
ExecStart=%h/.local/bin/uv run scripts/install_services.py --update --channel rel
```

## Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | Success (update applied or none) |
| 0    | Email service busy (skipped)     |
| 1    | Configuration error              |
| 2    | Git operation failed             |
| 3    | Systemd operation failed         |

Note: "Email service busy" exits with code 0 (not an error condition).

## Design Rationale

### Why File Locking Instead of Systemd Dependencies?

- **Cross-service coordination**: Systemd `After=` only controls startup order,
  not runtime coordination
- **Granular busy detection**: Lock acquired only during actual work, not while
  polling
- **Self-healing**: Lock auto-releases on abnormal exit without intervention

### Why Non-Blocking Acquire?

- **Fast failure**: Updater shouldn't wait; timer will retry on next interval
- **No deadlock risk**: Blocking acquire could hang if email service holds lock
  indefinitely
- **Simple logic**: Try once, succeed or skip

### Why Exit Code 0 When Busy?

- **Not an error**: Being busy is expected behavior
- **No systemd noise**: Prevents failed unit status in journal
- **Timer continues**: Systemd timer triggers regardless of exit code

### Why Two Channels?

- **rel**: Predictable, stable updates for production deployments. Only moves to
  explicitly tagged releases.
- **dev**: Continuous updates for development/testing. Mirrors the previous
  behavior of tracking `origin/main`.

### Why Persist Channel in Unit File?

The channel is embedded in the `ExecStart` line of `airut-updater.service`.
Since `--skip-updater` is passed during the self-update handoff (`os.execv`),
the updater unit is never regenerated during updates — preserving the originally
chosen channel and interval.
