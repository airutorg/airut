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
  naturally. The editor does not apply changes directly to in-memory state — it
  only writes the file. The watcher detects the write and applies the reload
  through the normal path. This is an explicit invariant: the file is always the
  single source of truth for reload.

## Dependency

Add `inotify-simple>=2.0` as a runtime dependency. BSD-2-Clause license (already
in the allow-list). Zero transitive dependencies. Single-file pure Python
wrapper around the Linux `inotify(7)` syscall.

## Design

### Existing Foundation

The config system already provides the building blocks this spec consumes:

- **`Scope` enum** — every config field carries `Scope.SERVER`, `Scope.REPO`, or
  `Scope.TASK` metadata via `FieldMeta`.
- **`diff_by_scope()`** — compares two `ConfigSnapshot` instances and groups
  changes by scope.
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

New module: `airut/config/watcher.py`.

Watches the config file's **parent directory** for `CLOSE_WRITE` and `MOVED_TO`
events on the config filename. Watching the directory (not the file) handles
editors that use atomic write-to-temp-then-rename patterns.

```python
class ConfigFileWatcher:
    """Watch a config file for changes via inotify."""

    def __init__(
        self,
        config_path: Path,
        on_change: Callable[[], None],
    ) -> None: ...

    def start(self) -> None:
        """Start background daemon thread."""

    def stop(self) -> None:
        """Stop watching. Thread exits within ~1 second."""
```

#### Watch Loop

```python
def _watch_loop(self) -> None:
    inotify = INotify()
    watch_flags = flags.CLOSE_WRITE | flags.MOVED_TO
    inotify.add_watch(str(self._config_dir), watch_flags)

    while self._running:
        events = inotify.read(timeout=1000, read_delay=100)
        for event in events:
            if event.name == self._config_name:
                self._on_change()
                break  # one callback per event batch

    inotify.close()
```

Key design choices:

- **`timeout=1000`** — the thread wakes every second to check `_running` for
  clean shutdown.
- **`read_delay=100`** — 100ms native debounce. After the first event arrives,
  inotify waits 100ms for more events before returning. The kernel also
  coalesces identical events. This replaces any need for a custom debounce
  timer.
- **One callback per batch** — if multiple events arrive for the config file in
  a single `read()` call, only one `on_change()` fires. Prevents redundant
  reloads.
- **Daemon thread** — thread is marked daemon so it does not prevent process
  exit.

#### SIGHUP

The gateway also triggers reload on `SIGHUP`. The signal handler sets a
`threading.Event` (`_reload_requested`) which the watcher thread checks on each
iteration. The watcher thread then calls `_on_config_changed()` from its normal
execution context — never from within the signal handler itself.

This avoids performing heavy I/O (YAML parsing, file reads, config diffing) in a
signal handler, which could cause reentrancy issues if the main thread holds a
lock when the signal arrives.

```python
signal.signal(signal.SIGHUP, lambda *_: service._reload_requested.set())
```

The watcher thread checks `_reload_requested` alongside inotify events. If
SIGHUP was received, the inotify events are skipped to avoid a redundant
double-reload:

```python
while self._running:
    events = inotify.read(timeout=1000, read_delay=100)
    if self._reload_requested.is_set():
        self._reload_requested.clear()
        self._on_change()
    else:
        for event in events:
            if event.name == self._config_name:
                self._on_change()
                break
```

### Reload Orchestration

Reload logic lives in `GatewayService._on_config_changed()`, not in a separate
class. The method is the sole entry point for all reloads (inotify and SIGHUP).
It is serialized: concurrent calls are dropped (only one reload runs at a time).

#### Reload Flow

```python
def _on_config_changed(self) -> None:
    if not self._reload_lock.acquire(blocking=False):
        return  # another reload is in progress

    try:
        # 1. Re-read and parse
        reset_dotenv_state()  # allow .env changes to take effect
        new_snapshot = ServerConfig.from_source(self._config_source)
        new_config = new_snapshot.value

        # 2. Diff: global_config and per-repo
        global_changes = self._diff_global(new_config)
        repo_changes = self._diff_repos(new_config)

        if not global_changes and not repo_changes:
            return  # no effective change

        # 3. Log changes (mask secrets)
        self._log_config_diff(global_changes, repo_changes)

        # 4. Apply by scope
        self._apply_task_scope(new_config)
        self._apply_repo_scope(new_config, repo_changes)
        self._apply_server_scope(new_config, global_changes)

        # 5. Update stored snapshot
        self._config_snapshot = new_snapshot
        self.config = new_config
        self._config_generation += 1
        self._last_reload_error = None

    except Exception:
        logger.exception("Config reload failed, keeping current config")
        self._last_reload_error = traceback.format_exc()
    finally:
        self._reload_lock.release()
```

If `from_source()` raises (YAML syntax error, validation failure, migration
error), the exception is caught and logged. The service continues with the
current config.

### Scope Application

#### TASK Scope — Immediate Atomic Swap

**Fields:** `model`, `effort`, `resource_limits` (per-repo), `container_env`.

These are read from `repo_handler.config` at the start of each task in
`process_message()` (lines ~331-342 of `message_processing.py`). In-flight tasks
already captured their config values into local variables and are unaffected.

**Action:**

```python
def _apply_task_scope(self, new_config: ServerConfig) -> None:
    for repo_id, new_repo_cfg in new_config.repos.items():
        handler = self.repo_handlers.get(repo_id)
        if handler:
            handler.config = new_repo_cfg
```

This is a single pointer assignment per repo. CPython's GIL makes this atomic
with respect to any worker thread reading `handler.config`. The next task picks
up the new config; the current task is unaffected.

Note: this also swaps the full `RepoServerConfig` which includes repo-scope
fields. That's intentional — repo-scope fields stored on the config object are
only _consumed_ when listeners restart (handled separately). The swap itself is
harmless for repo-scope fields.

#### REPO Scope — Listener Restart, Deferred if Busy

**Fields:** `git_repo_url`, `channels.*` (IMAP/SMTP/Slack credentials, polling
intervals, authorized senders), `secrets`, `masked_secrets`,
`signing_credentials`, `github_app_credentials`, `network_sandbox_enabled`.

These require restarting the affected repo's channel listeners (e.g. IMAP must
reconnect to a new server, Slack must use new tokens).

**Action:**

For each repo with repo-scope changes:

1. Check if the repo has active tasks. `TaskTracker.has_active_task()` takes a
   `conversation_id`, not a `repo_id`. A new method
   `TaskTracker.has_active_tasks_for_repo(repo_id: str) -> bool` is needed that
   scans all active tasks where `task.repo_id == repo_id`.
2. **If idle:** apply immediately — stop listeners, recreate adapters, start new
   listeners.
3. **If busy:** set `_pending_repo_reload[repo_id]` flag. After each task
   completion, `_execute_and_complete` calls
   `_check_pending_repo_reload(repo_id)` to apply when the repo becomes idle.

`_check_pending_repo_reload` uses `_reload_lock.acquire(blocking=True)` — this
is acceptable since it runs in a worker thread's `finally` block (not a critical
path) and the reload lock is held only briefly.

```python
def _apply_single_repo_reload(self, repo_id: str) -> None:
    handler = self.repo_handlers[repo_id]
    old_config = handler.config  # for rollback on failure

    # Stop existing listeners
    handler.stop()

    # Recreate adapters with new config (config already swapped)
    handler.adapters = create_adapters(handler.config)

    # Only recreate ConversationManager if git_repo_url changed
    if handler.config.git_repo_url != old_config.git_repo_url:
        handler.conversation_manager = ConversationManager(
            repo_url=handler.config.git_repo_url,
            storage_dir=handler.config.storage_dir,
        )

    # Start new listeners
    handler.start_listener()

    # Update dashboard repo state via _repos_store
    self._set_repo_status(repo_id, RepoStatus.LIVE)
```

`_set_repo_status(repo_id, status)` is a new helper that reads the current tuple
from `_repos_store`, replaces the entry for `repo_id`, and calls
`_repos_store.update()`. This is a read-modify-write on `VersionedStore`, which
is not internally atomic. Callers must hold `_reload_lock` for synchronization.
During boot (single-threaded), no lock is needed.

**Adding repos:** If the new config has repos not in the current config, create
new `RepoHandler` instances and start their listeners. No deferral needed since
there are no active tasks for a new repo.

**Removing repos:** If repos are absent from the new config, stop their
listeners and remove the handler. Must wait for active tasks to drain (same
deferred pattern as repo reload).

#### SERVER Scope — Deferred Until Globally Idle

**Fields:** `max_concurrent_executions`, `shutdown_timeout_seconds`,
`conversation_max_age_days`, `image_prune`, `dashboard_enabled`,
`dashboard_host`, `dashboard_port`, `dashboard_base_url`, `container_command`,
`upstream_dns`, `resource_limits` (global default).

These affect shared infrastructure: thread pool, dashboard server, sandbox
proxy.

**Action:**

1. Store the pending server config in `_pending_server_config`.
2. After each task completion, check if all repos are idle (no active tasks
   across the entire service).
3. When idle, apply: recreate thread pool (if `max_concurrent_executions`
   changed), restart dashboard (if dashboard settings changed), recreate sandbox
   (if `container_command` or `upstream_dns` changed).

Server-scope changes are rare (dashboard port, pool size). The idle-wait is
acceptable.

If a new config change arrives while a server reload is pending, the pending
config is replaced with the latest.

Note: the idle check confirms there are no active tasks AND no pending messages
in `_pending_messages`. This ensures the thread pool can be safely recreated
without losing queued work. Pending messages are submitted to
`self._executor_pool` when drained, so the new pool reference is used
automatically.

### Variable and Environment Resolution

`vars:` and `!env` are resolved during `ServerConfig.from_source()` — before the
config reaches the reload logic. This means:

- **`!var` changes propagate automatically.** If `vars.mail_server` changes, all
  fields referencing `!var mail_server` get the new resolved value. The diff
  detects the _resolved_ value changed and classifies it by the downstream
  field's scope.
- **`!env` changes propagate on reload.** `reset_dotenv_state()` is called
  before `from_source()`, allowing `.env` files to be re-read. However,
  `python-dotenv`'s `load_dotenv()` does not override variables already set in
  `os.environ`. This means `.env` changes to _existing_ variables are **not**
  picked up — only new variables are. Direct `os.environ` changes (e.g. from
  systemd `Environment=` or manual export) are always picked up since `!env`
  reads `os.environ` at parse time.
- **`vars:` has no scope of its own.** It's a resolution mechanism. Changes
  propagate as changes to the fields that reference them, with their correct
  scopes.
- **No-op detection works on resolved values.** Renaming a var without changing
  its value produces zero diff.

### Diff Granularity

`diff_by_scope()` compares two `ConfigSnapshot[T]` instances and classifies
changes by each field's `FieldMeta.scope`. It only works on dataclasses whose
fields carry `FieldMeta` annotations.

`ServerConfig` has two fields (`global_config`, `repos`), neither of which
carries `FieldMeta`. Therefore `diff_by_scope()` **cannot be used directly on
`ConfigSnapshot[ServerConfig]`** — both fields would default to `Scope.SERVER`.

The reload orchestrator uses a **two-level diff strategy**:

1. **Global config diff:** Compare old and new `GlobalConfig` directly. Since
   all `GlobalConfig` fields are `Scope.SERVER`, any change means server-scope
   reload. A simple equality check (`old.global_config != new.global_config`)
   suffices.

2. **Per-repo diff:** Iterate repos. For each repo present in both old and new
   configs, compare `RepoServerConfig` field by field using `get_field_meta()`
   to classify each changed field:

   - If only `Scope.TASK` fields changed: already handled by the config swap.
   - If any `Scope.REPO` field changed: schedule repo listener restart.
   - Repos in new but not old: added (create + start).
   - Repos in old but not new: removed (stop + delete).

```python
def _diff_global(self, new_config: ServerConfig) -> bool:
    """Return True if any GlobalConfig field changed."""
    return self.config.global_config != new_config.global_config


def _diff_repos(self, new_config: ServerConfig) -> dict[str, str]:
    """Return {repo_id: change_type} for repos that changed.

    change_type is one of: "task", "repo", "added", "removed".
    "task" means only task-scope fields changed (swap suffices).
    "repo" means at least one repo-scope field changed (listener restart).
    """
    result: dict[str, str] = {}
    old_repos = self.config.repos
    new_repos = new_config.repos

    for repo_id in new_repos.keys() - old_repos.keys():
        result[repo_id] = "added"
    for repo_id in old_repos.keys() - new_repos.keys():
        result[repo_id] = "removed"

    for repo_id in old_repos.keys() & new_repos.keys():
        old_cfg = old_repos[repo_id]
        new_cfg = new_repos[repo_id]
        if old_cfg == new_cfg:
            continue
        # Check if any repo-scope field changed
        has_repo_scope = False
        for f in dataclasses.fields(old_cfg):
            fm = get_field_meta(f)
            if fm and fm.scope == Scope.REPO:
                if getattr(old_cfg, f.name) != getattr(new_cfg, f.name):
                    has_repo_scope = True
                    break
        result[repo_id] = "repo" if has_repo_scope else "task"

    return result
```

### Concurrency

#### Lock Ordering

Extends the existing invariant documented in `gateway.py`:

```
_reload_lock
  └→ _pending_messages_lock
       └→ tracker._lock
```

The ordering applies to **nested acquisition** only — if you hold an outer lock,
you may acquire an inner lock, but never the reverse. Sequential acquire/release
(without nesting) does not violate the invariant.

The reload lock is non-blocking in `_on_config_changed()` (concurrent triggers
from the watcher are dropped) but blocking in `_check_pending_repo_reload()`
(worker threads wait briefly for any in-progress reload to finish).

#### Atomic Config Swap

`repo_handler.config` is a frozen dataclass. Swapping it is a single attribute
assignment, atomic under CPython's GIL. Worker threads reading
`repo_handler.config` see either the old or new config, never a partial state.

#### Repo Reload Safety

Repo-scope reload stops listeners and recreates adapters. This must not happen
while a task is mid-execution:

1. `_pending_repo_reload[repo_id]` is set (a flag, not a lock).
2. In-flight tasks continue using their already-captured config.
3. `_execute_and_complete` calls `_check_pending_repo_reload(repo_id)` in its
   `finally` block, after `complete_task` and `_drain_pending`.
4. The check uses `_reload_lock.acquire(blocking=True)` — blocking is acceptable
   since it runs in a worker thread's `finally` block (not a time-critical path)
   and the reload lock is held briefly. If a concurrent `_on_config_changed()`
   is in progress, the worker waits until it finishes, then checks and applies
   the pending reload.
5. During the brief listener restart window (~sub-second), no new messages are
   accepted for that repo.

#### Server Reload Safety

Server-scope reload waits for all repos to be idle. The idle check is performed
after each task completion. While server reload is pending:

- The service continues accepting and processing new messages normally.
- The pending state is visible on the dashboard.
- A new config change replaces the pending config (latest wins).

### Dashboard Integration

The dashboard displays reload status. This requires new enum values and a new
API endpoint.

**New `RepoStatus` values:** Add `RELOADING` and `RELOAD_PENDING` to the
existing `RepoStatus` enum (which currently has `LIVE` and `FAILED`):

- `RELOAD_PENDING` — repo has pending config changes, waiting for active tasks
  to drain.
- `RELOADING` — repo is actively restarting listeners.

**New `/api/status` endpoint:** Returns service-level status including the
config generation counter:

```json
{
  "config_generation": 3,
  "server_reload_pending": false,
  "last_reload_error": null
}
```

`config_generation` is a monotonic integer starting at 0, incremented on each
successful reload. Integration tests poll this endpoint to detect when a reload
has completed.

**Server reload pending:** Exposed via the `/api/status` endpoint's
`server_reload_pending` field.

**Last reload error:** If a reload failed (parse error, validation error, etc.),
the error message is exposed via `last_reload_error`. Cleared on the next
successful reload.

### Error Handling

| Condition                                       | Behavior                                                                                                                                                                                                        |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| YAML syntax error                               | Log error, continue with current config                                                                                                                                                                         |
| Validation error (missing required field, etc.) | Log error, continue with current config                                                                                                                                                                         |
| Migration error                                 | Log error, continue with current config                                                                                                                                                                         |
| Var/env resolution error                        | Log error, continue with current config                                                                                                                                                                         |
| Repo listener restart fails                     | Log error, revert to old config for that repo, attempt to restart old listeners. If old listeners also fail to start (e.g. IMAP server is down), the repo enters `FAILED` state — same as initial boot failure. |
| Server reload fails                             | Log error, this is critical — keep old config, do not retry                                                                                                                                                     |

All error conditions are logged at ERROR level with the exception traceback. The
dashboard shows the last reload error message.

### GatewayService Changes

1. **`__init__`:** Accept `config_source: ConfigSource | None` and store the
   initial `ConfigSnapshot`. Add `_reload_lock`, `_reload_requested`
   (`threading.Event`), `_pending_repo_reload`, `_pending_server_config`,
   `_config_generation` counter. When `config_source` is `None` (in-memory
   config), the watcher is not started and reload is disabled.
2. **`_boot`:** Start `ConfigFileWatcher` after boot completes (so the watcher
   doesn't fire during initial setup). Pass `_reload_requested` event to the
   watcher so it can check for SIGHUP triggers.
3. **`stop`:** Stop the watcher before stopping listeners.
4. **`_execute_and_complete` (finally block):** After `complete_task` and
   `_drain_pending`, call `_check_pending_repo_reload(repo_id)` and
   `_check_pending_server_reload()`.
5. **`main()`:** Pass the `ConfigSource` through to the service. Add SIGHUP
   handler that sets `_reload_requested`.

**Callers that need updating:**

- `main()` in `gateway.py` — pass `config_source` and `config_snapshot`.
- `IntegrationEnvironment.create_service()` in
  `tests/integration/gateway/environment.py` — pass `config_source` and
  `config_snapshot` for reload tests; existing non-reload tests continue to pass
  only `config` (watcher disabled).

### main() Changes

Create the `YamlConfigSource` once and reuse it for both initial load and reload
(avoids constructing a second source object):

```python
config_path = args.config or get_config_path()
source = YamlConfigSource(config_path)
snapshot = ServerConfig.from_source(source)
config = snapshot.value

service = GatewayService(
    config,
    config_source=source,
    config_snapshot=snapshot,
)

signal.signal(signal.SIGHUP, lambda *_: service._reload_requested.set())
```

## New and Modified Files

| File                                              | Change                                                                                                         |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `airut/config/watcher.py`                         | **New.** Config file watcher (inotify)                                                                         |
| `airut/gateway/service/gateway.py`                | **Modified.** Reload orchestration, `_on_config_changed()`, watcher lifecycle, SIGHUP support                  |
| `airut/gateway/dotenv_loader.py`                  | **Modified.** Update `reset_dotenv_state()` docstring — no longer testing-only, used in production reload path |
| `airut/gateway/service/message_processing.py`     | **Modified.** No changes needed — already reads `repo_handler.config` per-task                                 |
| `airut/dashboard/tracker.py`                      | **Modified.** Add `RepoStatus.RELOADING` / `RELOAD_PENDING`, add `has_active_tasks_for_repo(repo_id)` method   |
| `airut/dashboard/server.py`                       | **Modified.** Add `/api/status` endpoint exposing `config_generation`                                          |
| `tests/config/test_watcher.py`                    | **New.** Unit tests for file watcher                                                                           |
| `tests/gateway/service/test_config_reload.py`     | **New.** Unit tests for reload orchestration                                                                   |
| `tests/integration/gateway/test_config_reload.py` | **New.** E2E integration tests                                                                                 |

## Integration Test Plan

### Philosophy

Tests verify config reload by **externally observable behavior** — HTTP
requests, email connectivity, message routing, container invocation arguments.
They do not inspect internal state. Each test:

1. Starts a full `GatewayService` with a config YAML file on disk.
2. Waits for the service to be ready.
3. Modifies the YAML file.
4. Waits for reload to complete (via dashboard API generation counter).
5. Observes the change took effect via externally visible behavior.

### Test Infrastructure

#### ConfigFile Helper

```python
class ConfigFile:
    """Write and modify config YAML files for testing."""

    def __init__(self, path: Path, config: ServerConfig) -> None: ...

    def write(self) -> None:
        """Serialize current config to YAML and write to path.

        Converts the in-memory ServerConfig to a nested YAML dict using
        the existing flat_to_nested_global/repo helpers in
        airut.config.source, then writes via YamlConfigSource.save().
        This is non-trivial for RepoServerConfig with nested channel
        configs and credential pools — the helpers must be extended or
        a dedicated test serializer must be written.
        """

    def update(self, **overrides) -> None:
        """Update fields and write. Triggers inotify."""
```

#### IntegrationEnvironment Changes

- New `config_path` attribute: path to the YAML file on disk.
- New `config_file` attribute: `ConfigFile` instance for modifying the file.
- `create_service()` passes `config_source` and `config_snapshot` to
  `GatewayService` so it loads from file and starts the watcher.

#### Wait Helpers

```python
def wait_for_reload(service, generation: int, timeout: float = 5.0) -> None:
    """Wait until config_generation > generation."""


def wait_for_repo_status(
    service, repo_id: str, status: RepoStatus, timeout: float = 5.0
) -> None:
    """Wait until a repo reaches the given status."""
```

### Test Cases

All tests are in `tests/integration/gateway/test_config_reload.py`.

#### A. TASK-Scope Changes

These verify that task-scope changes take effect on the next task without any
listener restart or interruption.

**A1: `test_reload_model_change`**

1. Start service with `model: opus`.
2. Send message, wait for task completion.
3. Verify mock_claude was invoked with `--model opus`.
4. Modify config: `model: sonnet`. Wait for reload.
5. Send another message, wait for task completion.
6. Verify mock_claude was invoked with `--model sonnet`.

**A2: `test_reload_model_via_var_indirection`**

1. Start with `vars: {claude_model: opus}` and `model: !var claude_model`.
2. Send message, verify `--model opus`.
3. Modify vars: `claude_model: sonnet`. Wait for reload.
4. Send message, verify `--model sonnet`.
5. Validates that variable resolution works correctly through reload.

**A3: `test_reload_effort`**

1. Start with default effort (none).
2. Modify config: `effort: low`. Wait for reload.
3. Send message, verify mock_claude received `--effort low`.

**A4: `test_reload_resource_limits`**

1. Start with default resource limits.
2. Modify config: `resource_limits: {timeout_seconds: 30}`.
3. Send message, verify sandbox timeout is 30s.

**A5: `test_reload_container_env`**

1. Start with `container_env: {FOO: bar}`.
2. Modify: `container_env: {FOO: baz, NEW_VAR: hello}`.
3. Send message, verify container environment reflects change.

#### B. REPO-Scope Changes

These verify that repo-scope changes restart the affected repo's listeners
without affecting other repos or interrupting active tasks.

**B1: `test_reload_email_credentials`**

1. Start with email server on port P1.
2. Send message, verify processing succeeds.
3. Start second email server on port P2.
4. Modify config: point IMAP/SMTP to P2. Wait for reload.
5. Send message to P2 server, verify processing succeeds.

**B2: `test_reload_authorized_senders`**

1. Start with `authorized_senders: ["alice@test.local"]`.
2. Send from bob@test.local — verify UNAUTHORIZED completion.
3. Modify: `authorized_senders: ["alice@test.local", "bob@test.local"]`.
4. Wait for reload.
5. Send from bob@test.local — verify SUCCESS completion.

**B3: `test_reload_add_repo`**

1. Start with one repo (`project-a`).
2. Modify config: add `project-b` with its own email channel.
3. Wait for reload.
4. Send message to `project-b`, verify processing succeeds.
5. Send message to `project-a`, verify still works.

**B4: `test_reload_remove_repo`**

1. Start with two repos.
2. Modify config: remove one repo.
3. Wait for reload.
4. Verify removed repo's listener stopped (no new messages processed).
5. Verify remaining repo continues operating.

**B5: `test_reload_repo_deferred_during_task`**

1. Start service, send message with `slow` mock strategy (takes several
   seconds).
2. While task is executing, modify repo-scope config (e.g. authorized_senders).
3. Wait for task to complete. Verify SUCCESS (not interrupted).
4. Verify the config change took effect (send from newly authorized sender).

**B6: `test_reload_secrets`**

1. Start with `secrets: {API_KEY: old-key}`.
2. Modify: `secrets: {API_KEY: new-key}`. Wait for reload.
3. Send message, verify container received `API_KEY=new-key`.

**B7: `test_reload_secrets_via_env_indirection`**

1. Set `os.environ["TEST_API_KEY"] = "key-v1"`.
2. Start with `secrets: {API_KEY: !env TEST_API_KEY}`.
3. Send message, verify container received `API_KEY=key-v1`.
4. Set `os.environ["TEST_API_KEY"] = "key-v2"` (direct os.environ change).
5. Touch config file (triggers reload; `!env` re-reads os.environ at parse
   time).
6. Send message, verify container received `API_KEY=key-v2`.
7. Note: this test uses direct `os.environ` mutation, not `.env` file changes,
   because `python-dotenv` does not override existing variables.

#### C. SERVER-Scope Changes

These verify that server-scope changes are deferred until the service is idle
and then applied.

**C1: `test_reload_dashboard_port`**

1. Start with dashboard on dynamic port P1.
2. Verify dashboard accessible (HTTP GET `/api/version` returns 200).
3. Modify config: `dashboard_port: P2`. Wait for server reload.
4. Verify dashboard accessible on P2 (200).
5. Verify P1 no longer responds.

**C2: `test_reload_dashboard_toggle`**

1. Start with `dashboard_enabled: true`. Verify accessible.
2. Modify: `dashboard_enabled: false`. Wait for reload.
3. Verify dashboard no longer accessible.
4. Modify: `dashboard_enabled: true`. Wait for reload.
5. Verify dashboard accessible again.

**C3: `test_reload_server_deferred_until_idle`**

1. Start a `slow` task.
2. Modify a server-scope setting (dashboard port).
3. Verify the old dashboard is still running during task execution.
4. Wait for task completion.
5. Verify server-scope reload applied (new dashboard port active).

**C4: `test_reload_max_concurrent`**

1. Start with `max_concurrent_executions: 1`.
2. Submit two messages. Verify second task enters PENDING.
3. Wait for both to complete.
4. Modify: `max_concurrent_executions: 3`. Wait for reload.
5. Submit two messages. Verify both execute concurrently (both EXECUTING before
   either completes).

#### D. Error Handling and Edge Cases

**D1: `test_reload_invalid_yaml`**

1. Start service, verify working.
2. Write invalid YAML (syntax error) to config file.
3. Verify service continues operating with old config (send message, verify
   success).
4. Fix YAML. Verify next reload succeeds.

**D2: `test_reload_invalid_config`**

1. Write valid YAML but invalid config (missing required `git_repo_url`).
2. Verify service continues with old config.

**D3: `test_reload_rapid_writes`**

1. Write three config changes in rapid succession (within 100ms).
2. Verify only the final state takes effect (not intermediate states).

**D4: `test_reload_sighup`**

1. Modify config file.
2. Send `SIGHUP` to the service.
3. Verify reload happened (generation counter incremented).

**D5: `test_reload_no_change`**

1. Rewrite config file with identical content.
2. Verify no reload occurs (generation counter unchanged, no log output).

**D6: `test_reload_mixed_scopes`**

1. In a single edit, change `model` (TASK) + `authorized_senders` (REPO) +
   `dashboard_port` (SERVER).
2. Verify TASK change applies immediately (next task uses new model).
3. Verify REPO change applies after repo becomes idle.
4. Verify SERVER change applies after service becomes idle.

### Observability Assertions

Tests verify behavior through these external interfaces:

| What to verify         | How                                                         |
| ---------------------- | ----------------------------------------------------------- |
| Model/effort/env used  | Check mock_podman invocation log                            |
| Container environment  | Check mock_podman environment capture                       |
| Dashboard accessible   | HTTP GET to port, check status code                         |
| Dashboard port changed | Old port refuses connection, new port responds              |
| Email processed        | Response email arrives in test SMTP server                  |
| Authorization changed  | Send from new sender, verify success vs rejection           |
| Task not interrupted   | Task completes with SUCCESS (not INTERNAL_ERROR)            |
| Reload completed       | Poll new `/api/status` endpoint for `config_generation > N` |
| Secrets propagated     | Check mock_podman environment capture                       |

### Timing

All tests use explicit wait conditions with timeouts, not `time.sleep()`:

- `wait_for_reload(generation)` — polls dashboard API.
- `wait_for_conv_completion(conv_id)` — existing helper.
- `wait_for_repo_status(repo_id, status)` — polls repo store.

Default timeout: 10 seconds. Tests fail fast on unexpected state.

## Implementation Order

1. `ConfigFileWatcher` — file monitoring (unit-testable standalone).
2. `GatewayService` plumbing — store snapshot and source, add reload lock and
   pending state, wire watcher into boot/stop.
3. TASK-scope reload — simplest path, atomic swap.
4. REPO-scope reload — listener stop/start with deferred application.
5. SERVER-scope reload — shared infrastructure restart with idle-wait.
6. SIGHUP handler.
7. Dashboard reload indicators.
8. Integration tests.

Each step is independently testable and mergeable.

## Compatibility

- No breaking changes to existing config files or CLI arguments.
- `GatewayService.__init__` gains optional `config_source` and `config_snapshot`
  parameters; existing callers that pass only `config` continue to work (watcher
  is not started when `config_source` is `None`).
- Integration tests that construct `GatewayService` with in-memory config
  continue to work unchanged (no file watcher started).

## Relationship to Existing Specs

- **`spec/declarative-config.md`** — this spec implements the "future live
  reload" referenced in that spec's Non-Goals and Config Diffing sections. The
  `Scope` metadata and `diff_by_scope()` function defined there are consumed
  here.
- **`spec/repo-config.md`** — scope assignments per field are defined there and
  drive the reload behavior here.
- **`spec/gateway-architecture.md`** — the `RepoHandler` lifecycle and
  `GatewayService` orchestration described there are extended (not replaced) by
  the reload mechanism.
