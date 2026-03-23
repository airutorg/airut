# Config Live Reload

Live-reload the server config file so changes take effect without restarting the
gateway service. Changes are classified by their existing `Scope` metadata and
applied at the appropriate granularity: per-task, per-repo, or server-wide.

## Goals

1. **Zero-downtime config changes** — task-scope and repo-scope changes apply
   without interrupting running tasks.
2. **Scope-aware application** — reuse the existing `Scope.TASK`, `Scope.REPO`,
   `Scope.SERVER` metadata to decide _how_ to apply each change.
3. **Safe by default** — parse errors, validation failures, and partial reload
   errors never crash the service or corrupt running state.
4. **Instant file detection** — use Linux `inotify` for sub-millisecond
   reaction, not polling.
5. **Observable** — reload events are logged, surfaced on the dashboard, and
   verifiable in integration tests by externally observable behavior.

## Non-Goals

- Cross-platform file watching. The gateway targets Linux; `inotify-simple` is
  Linux-only.
- Watching `.env` files. Only `airut.yaml` is watched. `.env` changes are picked
  up on reload by re-reading the environment (see Variable Resolution below).
- Dashboard config editor integration. The editor saves via
  `YamlConfigSource.save()`, which writes the file and triggers inotify
  naturally. The file is always the single source of truth for reload.

## Dependency

`inotify-simple>=2.0` — BSD-2-Clause license (already in the allow-list). Zero
transitive dependencies. Single-file pure Python wrapper around the Linux
`inotify(7)` syscall.

## Design

### Existing Foundation

The config system already provides the building blocks this spec consumes:

- **`Scope` enum** — every config field carries `Scope.SERVER`, `Scope.REPO`, or
  `Scope.TASK` metadata via `FieldMeta`.
- **`ConfigSnapshot`** — wraps a frozen config dataclass, tracks
  `provided_keys`, preserves raw YAML with `!var`/`!env` tags for round-trip.
- **`ServerConfig.from_source()`** — full pipeline: load, migrate, resolve vars,
  resolve env, parse, validate.

### Component Overview

```
                  ┌──────────────────────────┐
                  │   ConfigFileWatcher       │
                  │   (inotify on directory)  │
                  └────────────┬─────────────┘
                               │ file changed event
                               ▼
                  ┌──────────────────────────┐
                  │   GatewayService         │
                  │   ._on_config_changed()  │
                  └────────────┬─────────────┘
                               │ load + diff
                     ┌─────────┼─────────┐
                     ▼         ▼         ▼
                   TASK      REPO     SERVER
                   (swap)   (restart) (queue)
```

### ConfigFileWatcher

Module: `airut/config/watcher.py`.

Watches the config file's **parent directory** for `CLOSE_WRITE` and `MOVED_TO`
events on the config filename. Watching the directory (not the file) handles
editors that use atomic write-to-temp-then-rename patterns.

```python
class ConfigFileWatcher:
    def __init__(
        self, config_path: Path, on_change: Callable[[], None]
    ) -> None: ...
    def start(self) -> None: ...  # background daemon thread
    def stop(self) -> None: ...  # exits within ~1 second
    @property
    def ready(self) -> threading.Event: ...  # set once inotify watch is active
```

Key design choices:

- **`timeout=1000`** — the thread wakes every second to check `_running` for
  clean shutdown.
- **`read_delay=100`** — 100ms native debounce. After the first event arrives,
  inotify waits 100ms for more events before returning. Replaces any need for a
  custom debounce timer.
- **One callback per batch** — multiple events for the config file in a single
  `read()` call fire only one `on_change()`.
- **Daemon thread** — does not prevent process exit.

#### SIGHUP

The gateway also triggers reload on `SIGHUP`. The signal handler sets a
`threading.Event` which the watcher thread checks on each iteration. This avoids
performing heavy I/O (YAML parsing, config diffing) inside a signal handler.

When SIGHUP is received, inotify events are skipped to avoid redundant
double-reload.

### Reload Orchestration

Reload logic lives in `GatewayService._on_config_changed()`. It is the sole
entry point for all reloads (inotify and SIGHUP). Concurrent calls are dropped
(only one reload runs at a time).

#### Reload Flow

1. **Re-read and parse** — `reset_dotenv_state()` then
   `ServerConfig.from_source()`.
2. **Diff** — two-level strategy (see Diff Granularity).
3. **Log changes** — mask secrets.
4. **Apply by scope** — TASK (swap), REPO (restart/defer), SERVER (queue/defer).
5. **Update stored snapshot** — increment `_config_generation`.

If `from_source()` raises (YAML syntax error, validation failure, migration
error), the exception is caught and logged. The service continues with the
current config.

### Scope Application

#### TASK Scope — Immediate Atomic Swap

**Fields:** `model`, `effort`, `resource_limits` (per-repo), `container_env`.

These are read from `repo_handler.config` at the start of each task. In-flight
tasks already captured their config values into local variables and are
unaffected.

Action: single `handler.config = new_repo_cfg` pointer assignment per repo.
CPython's GIL makes this atomic with respect to any worker thread reading
`handler.config`.

#### REPO Scope — Listener Restart, Deferred if Busy

**Fields:** `git_repo_url`, `channels.*` (IMAP/SMTP/Slack credentials, polling
intervals, authorized senders), `secrets`, `masked_secrets`,
`signing_credentials`, `github_app_credentials`, `network_sandbox_enabled`.

These require restarting the affected repo's channel listeners.

For each repo with repo-scope changes:

1. Check if the repo has active tasks via
   `TaskTracker.has_active_tasks_for_repo(repo_id)`.
2. **If idle:** apply immediately — stop listeners, recreate adapters, start new
   listeners.
3. **If busy:** set `_pending_repo_reload[repo_id]` flag. After each task
   completion, `_check_pending_repo_reload(repo_id)` applies when the repo
   becomes idle.

If listener restart fails, the handler reverts to old config and attempts to
restart with old settings. If that also fails, the repo enters `FAILED` state.

**Adding repos:** create new `RepoHandler` and start listeners. No deferral
needed.

**Removing repos:** stop listeners and remove handler. Deferred if active tasks
exist.

#### SERVER Scope — Deferred Until Globally Idle

**Fields:** `max_concurrent_executions`, `shutdown_timeout_seconds`,
`conversation_max_age_days`, `image_prune`, `dashboard_enabled`,
`dashboard_host`, `dashboard_port`, `dashboard_base_url`, `container_command`,
`upstream_dns`, `resource_limits` (global default).

These affect shared infrastructure: thread pool, dashboard server, sandbox
proxy.

1. Store the pending server config.
2. Attempt immediate application if the service is already idle (no active
   tasks, no pending messages).
3. Otherwise, after each task completion, check if all repos are idle and apply.

While server reload is pending, the service continues normally. A new config
change replaces the pending config (latest wins).

**Note:** Sandbox-related fields (`container_command`, `upstream_dns`) and
`resource_limits` (global default) require a service restart. Dashboard settings
and `max_concurrent_executions` are applied via server reload.
`conversation_max_age_days`, `image_prune`, and `shutdown_timeout_seconds` are
re-read at use time (GC iteration / shutdown) so they take effect on reload
without restart.

### Variable and Environment Resolution

`vars:` and `!env` are resolved during `ServerConfig.from_source()` — before the
config reaches the reload logic. This means:

- **`!var` changes propagate automatically.** If `vars.mail_server` changes, all
  fields referencing `!var mail_server` get the new resolved value. The diff
  detects the _resolved_ value changed and classifies it by the downstream
  field's scope.
- **`!env` changes propagate on reload.** `reset_dotenv_state()` is called
  before `from_source()`. Note: `python-dotenv`'s `load_dotenv()` does not
  override variables already in `os.environ` — only new variables are picked up.
  Direct `os.environ` changes are always picked up since `!env` reads
  `os.environ` at parse time.
- **`vars:` has no scope of its own.** Changes propagate as changes to the
  fields that reference them, with their correct scopes.
- **No-op detection works on resolved values.** Renaming a var without changing
  its value produces zero diff.

### Diff Granularity

`ServerConfig` has two fields (`global_config`, `repos`), neither of which
carries `FieldMeta`. Therefore `diff_by_scope()` cannot be used directly on
`ConfigSnapshot[ServerConfig]`.

The reload orchestrator uses a **two-level diff strategy**:

1. **Global config diff:** simple equality check
   (`old.global_config != new.global_config`). All `GlobalConfig` fields are
   `Scope.SERVER`, so any change means server-scope reload.

2. **Per-repo diff:** iterate repos. For each repo present in both configs,
   compare `RepoServerConfig` field by field using `get_field_meta()` to
   classify each changed field:

   - If only `Scope.TASK` fields changed: already handled by the config swap.
   - If any `Scope.REPO` field changed: schedule repo listener restart.
   - Repos in new but not old: added (create + start).
   - Repos in old but not new: removed (stop + delete).

### Concurrency

#### Lock Ordering

Extends the existing invariant documented in `gateway.py`:

```
_reload_lock
  └→ _pending_messages_lock
       └→ tracker._lock
```

The ordering applies to **nested acquisition** only — if you hold an outer lock,
you may acquire an inner lock, but never the reverse.

The reload lock is non-blocking in `_on_config_changed()` (concurrent triggers
dropped) but blocking in `_check_pending_repo_reload()` (worker threads wait
briefly for any in-progress reload to finish).

#### Atomic Config Swap

`repo_handler.config` is a frozen dataclass. Swapping it is a single attribute
assignment, atomic under CPython's GIL. Worker threads see either the old or new
config, never a partial state.

#### Repo Reload Safety

Repo-scope reload stops listeners and recreates adapters. This must not happen
while a task is mid-execution:

1. `_pending_repo_reload[repo_id]` flag is set (not a lock).
2. In-flight tasks continue using their already-captured config.
3. `_execute_and_complete` calls `_check_pending_repo_reload(repo_id)` in its
   `finally` block, after `complete_task` and `_drain_pending`.
4. During the brief listener restart window, no new messages are accepted for
   that repo.

#### Server Reload Safety

Server-scope reload waits for all repos to be idle. The idle check confirms
there are no active tasks AND no pending messages in `_pending_messages`, so the
thread pool can be safely recreated without losing queued work.

### Dashboard Integration

**New `RepoStatus` values:** `RELOAD_PENDING` (waiting for tasks to drain) and
`RELOADING` (actively restarting listeners), added to the existing `RepoStatus`
enum.

**`/api/status` endpoint:** Returns service-level reload status:

```json
{
  "config_generation": 3,
  "server_reload_pending": false,
  "last_reload_error": null
}
```

`config_generation` is a monotonic integer starting at 0, incremented on each
successful reload.

### Error Handling

| Condition                                       | Behavior                                                                    |
| ----------------------------------------------- | --------------------------------------------------------------------------- |
| YAML syntax error                               | Log error, continue with current config                                     |
| Validation error (missing required field, etc.) | Log error, continue with current config                                     |
| Migration error                                 | Log error, continue with current config                                     |
| Var/env resolution error                        | Log error, continue with current config                                     |
| Repo listener restart fails                     | Revert to old config, attempt old listeners. If that fails: `FAILED` state. |
| Server reload fails                             | Log error, keep old config, do not retry                                    |

All error conditions are logged at ERROR level. The dashboard shows the last
reload error message.

## Relationship to Existing Specs

- **`spec/declarative-config.md`** — this spec implements the "future live
  reload" referenced in that spec's Non-Goals and Config Diffing sections. The
  `Scope` metadata defined there drives the reload behavior here.
- **`spec/repo-config.md`** — scope assignments per field are defined there.
- **`spec/gateway-architecture.md`** — the `RepoHandler` lifecycle and
  `GatewayService` orchestration are extended (not replaced) by the reload
  mechanism.
