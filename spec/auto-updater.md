# Auto-Updater Service

Automatic service update mechanism that keeps services synchronized with the
`origin/main` branch.

## Overview

A systemd timer triggers periodic checks for repository updates. When updates
are available, services are reinstalled from the new code. The update process
coordinates with the email service via a lock file to avoid interrupting
in-progress work.

**Key principle**: Updates should never disrupt active email processing or
Claude execution.

## Architecture

### Components

- **airut-updater.timer** - Systemd timer triggering every 5 minutes
- **airut-updater.service** - One-shot service running the update check
- **install_services.py** - Update logic and service management
- **UpdateLock** - File-based lock for coordinating with email service

### Update Flow

```
Timer triggers (every 5 min)
  -> install_services.py --update
    -> Try to acquire update lock (non-blocking)
      -> If locked: Log "Email service busy", exit 0
      -> If acquired: Hold lock and continue
    -> git fetch origin
    -> Compare HEAD vs origin/main
      -> If same: Exit (no updates)
      -> If different: Apply update
        -> Uninstall main services (not updater)
        -> git reset --hard origin/main
        -> uv sync (update dependencies)
        -> os.execv() to new installer
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
4. **Frequent retry**: Timer runs every 5 minutes, so updates apply soon after
   service becomes idle

## Configuration

### Systemd Timer

```ini
[Timer]
OnCalendar=*:0/5      # Every 5 minutes
OnBootSec=1min        # 1 minute after boot
Persistent=true       # Catch up missed runs
```

### Systemd Service

```ini
[Service]
Type=oneshot
WorkingDirectory=%h/airut
ExecStart=%h/.local/bin/uv run scripts/install_services.py --update
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

- **Fast failure**: Updater shouldn't wait; timer will retry in 5 minutes
- **No deadlock risk**: Blocking acquire could hang if email service holds lock
  indefinitely
- **Simple logic**: Try once, succeed or skip

### Why Exit Code 0 When Busy?

- **Not an error**: Being busy is expected behavior
- **No systemd noise**: Prevents failed unit status in journal
- **Timer continues**: Systemd timer triggers regardless of exit code
