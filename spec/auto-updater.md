# Auto-Updater Service

Automatic service update mechanism that keeps Airut synchronized with upstream
releases or the development branch.

## Overview

A systemd timer triggers periodic calls to `airut update`, which runs
`uv tool upgrade airut`. The upgrade pulls from whatever source was used at
`uv tool install` time (e.g., a GitHub repo URL or PyPI). The update process
coordinates with the email service via an advisory lock to avoid interrupting
in-progress work.

**Key principle**: Updates should never disrupt active email processing or
Claude execution.

## Update Channels

The update channel is determined by the install source, not by a runtime flag:

| Channel | Install Command                                                          | Description                      |
| ------- | ------------------------------------------------------------------------ | -------------------------------- |
| Dev     | `uv tool install airut --from git+https://github.com/airutorg/airut.git` | Tracks main branch (development) |
| Release | `uv tool install airut` (future, from PyPI)                              | Stable tagged releases only      |

`uv tool upgrade airut` re-resolves from the same source, so the channel is
sticky. To switch channels, reinstall with `--force` and a different source.

The polling interval defaults to 30 minutes and can be overridden with
`airut install-service --interval MINUTES`. The override is persisted in the
generated `airut-updater.timer` unit.

## Architecture

### Components

- **airut-updater.timer** — Systemd timer triggering at configured interval
- **airut-updater.service** — One-shot service running `airut update`
- **lib/install_services.py** — Update logic and service management
- **lib/airut.py** — CLI entry points (`update`, `install-service`,
  `uninstall-service`)
- **UpdateLock** — File-based lock for coordinating with email service

### Update Flow

```
Timer triggers (per configured interval)
  -> airut update
    -> Try to acquire update lock (non-blocking)
      -> If locked: Log "Email service busy", exit 0
      -> If acquired: Hold lock and continue
    -> uv tool upgrade airut
      -> Pulls from original install source
      -> If no new version: exits quietly
      -> If upgraded: new version is immediately active
    -> Lock auto-releases on exit
```

## Update Coordination

### Lock File Mechanism

The email service and auto-updater coordinate using an advisory file lock:

| Actor         | Lock Behavior                                     |
| ------------- | ------------------------------------------------- |
| Email service | Acquires lock when busy, releases when idle       |
| Auto-updater  | Tries non-blocking acquire; exits if lock is held |

**Lock file**: `$XDG_RUNTIME_DIR/airut/update.lock` (typically
`/run/user/<uid>/airut/update.lock`)

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

### Install Services

```bash
# Default: 30-minute polling
airut install-service

# Without auto-updater
airut install-service --skip-updater

# Custom polling interval
airut install-service --interval 60
```

### Systemd Timer

```ini
[Timer]
OnCalendar=*:0/30     # Every 30 minutes (default)
OnBootSec=1min
Persistent=true
```

### Systemd Service

```ini
[Service]
Type=oneshot
ExecStart=%h/.local/bin/airut update
```

## Exit Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | Success (update applied or none) |
| 0    | Email service busy (skipped)     |
| 1    | Upgrade command failed           |

Note: "Email service busy" exits with code 0 (not an error condition).

## Migration from Git-Clone Deployment

Existing deployments that use the old git-clone model with
`scripts/install_services.py` will automatically migrate when the updater
fetches a version containing the migration stub. The stub:

1. Uninstalls all old systemd services
2. Runs `uv tool install airut` from the GitHub repo
3. Runs `airut install-service` to create new-style unit files

After migration, the old script is never called again.

## Design Rationale

### Why `uv tool upgrade` Instead of Git Operations?

- **Hermetic installs**: `uv tool install` creates an isolated venv with pinned
  dependencies — no stale virtualenvs or dependency drift
- **No working directory**: No git clone to maintain, no `WorkingDirectory` in
  systemd units
- **Standard tooling**: Leverages uv's existing upgrade mechanism instead of
  custom git fetch/reset/sync logic
- **Future PyPI support**: Same command works for PyPI releases without code
  changes

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

### Why XDG Runtime Dir for Lock File?

- **Per-user isolation**: `/run/user/<uid>/airut/` is per-user and tmpfs-backed
- **No persistent state**: Lock file is transient; cleaned on reboot
- **Works with linger**: `XDG_RUNTIME_DIR` persists when linger is enabled
- **No git repo dependency**: Lock file doesn't require a working directory
