# Periodic Tasks

Cron-triggered tasks for Airut. Schedules are defined per-repo in the server
config, executed in the standard sandbox, and results delivered to a configured
recipient via email. Recipients can reply to continue the conversation through
the normal channel flow.

This spec assumes the gateway architecture
([gateway-architecture.md](gateway-architecture.md)), sandbox
([sandbox.md](sandbox.md)), and the email channel adapter are implemented.

> **Scope note.** This spec covers email delivery only. The config schema uses a
> `deliver.channel` field to allow future extension to other channels (e.g.
> Slack), but only the `"email"` channel is implemented in this version. See
> [Open Items](#open-items) for Slack delivery considerations.

## Design Goals

1. **Reuse the existing sandbox pipeline.** Scheduled tasks use the same
   container images, mounts, network sandbox, secrets, and resource limits as
   interactive tasks. No parallel execution path.

2. **Reply-back works naturally.** When a scheduled task delivers its result,
   the conversation is registered with the delivery channel's state (email
   Message-ID with embedded conversation ID) so the recipient can reply and
   continue via the normal interactive flow.

3. **Two trigger modes.** Prompt mode always runs Claude. Script mode runs a
   command first and only invokes Claude when there is output to analyze or a
   failure to investigate.

4. **No new dependencies.** The cron parser is built-in. No external scheduling
   library.

5. **Shared executor pool.** Scheduled tasks compete with interactive tasks for
   the same worker threads. No separate concurrency limit — the existing
   `max_concurrent_executions` governs both.

6. **Clean separation from channels.** The scheduler is a service-level
   component, not a channel adapter. It creates conversations directly and
   delegates delivery to a thin method on the channel adapters.

## Trigger Modes

### Prompt Mode

The schedule specifies a `prompt:` string. On each fire, the scheduler creates a
fresh conversation and runs an `AgentTask` with that prompt. The result is
delivered to the configured recipient.

### Script Mode

The schedule specifies a `trigger:` block with a `command:` list. On each fire:

1. **Run `CommandTask`** in the sandbox with the same mounts as an `AgentTask`
   except Claude-related mounts (session directory, binary).

2. **Check result:**

   - Exit 0, empty stdout → done. Delete the conversation, no Claude run, no
     notification.
   - Exit 0, non-empty stdout → use stdout as the prompt and run `AgentTask`.
     The script is responsible for constructing whatever prompt it wants Claude
     to see (including any stderr it captured).
   - Non-zero exit → generate a system prompt including command, exit code, and
     both stdout and stderr, then run `AgentTask`.

3. **Deliver the `AgentTask` result** to the configured recipient.

Script mode is designed for automation workflows where a script does the
checking and constructs a prompt for Claude. The script controls what Claude
sees — its stdout becomes the prompt directly. For example, a CI watchdog script
might run the test suite and, on failure, output a prompt like "CI failed with
these errors: \<output>. Investigate and fix." If CI passes, the script produces
no output and Claude is not invoked.

Non-zero exit from the script itself indicates the script broke (not what it was
monitoring). In that case the system generates an error prompt with the command,
exit code, and any output so Claude can investigate the script failure.

### Container Mounts

| Mount           | AgentTask  | CommandTask |
| --------------- | ---------- | ----------- |
| `/workspace`    | yes        | yes         |
| `/inbox`        | yes        | yes         |
| `/outbox`       | yes        | yes         |
| `/storage`      | yes        | yes         |
| `/root/.claude` | yes (auto) | no          |
| `/opt/claude`   | yes (auto) | no          |

## Configuration

Schedules live under `schedules:` in each repo config, at the same level as
`channels:`.

```yaml
repos:
  my-repo:
    repo_url: "https://github.com/org/repo.git"
    email: { ... }
    slack: { ... }

    schedules:
      daily-review:
        cron: "0 9 * * 1-5"
        timezone: "Europe/Helsinki"
        prompt: "Review open PRs and summarize their status."
        deliver:
          channel: email
          to: "user@example.com"

      nightly-check:
        cron: "0 2 * * *"
        trigger:
          command: ["./scripts/nightly-check.sh"]
          timeout: 300
        output_limit: 204800              # optional, default 100KB
        deliver:
          channel: email
          to: "ops-team@example.com"
```

### Schema

All fields carry `FieldMeta` annotations for declarative config introspection.
The editor schema system auto-detects `schedules` as a `keyed_collection`
(`dict[str, ScheduleConfig]`) and renders nested sub-fields from
`ScheduleDelivery` and `ScheduleTrigger`.

```python
@dataclass(frozen=True)
class ScheduleTrigger:
    """Script trigger for a scheduled task."""

    command: list[str] = field(
        metadata=meta("Command to run as trigger script", Scope.REPO),
    )
    timeout: int | None = field(
        default=None,
        metadata=meta(
            "Timeout in seconds (empty = repo resource_limits default)",
            Scope.REPO,
        ),
    )


@dataclass(frozen=True)
class ScheduleDelivery:
    """Delivery target for a scheduled task result."""

    channel: str = field(
        metadata=meta(
            "Delivery channel (must match a key in channels:)", Scope.REPO
        ),
    )
    to: str = field(
        metadata=meta("Recipient address (email address)", Scope.REPO),
    )


@dataclass(frozen=True)
class ScheduleConfig:
    """A single periodic task schedule."""

    cron: str = field(
        metadata=meta(
            "5-field cron expression (minute hour dom month dow)", Scope.REPO
        ),
    )
    deliver: ScheduleDelivery = field(
        metadata=meta("Delivery target for task results", Scope.REPO),
    )
    timezone: str = field(
        default="UTC",
        metadata=meta("IANA timezone for cron evaluation", Scope.REPO),
    )
    prompt: str | None = field(
        default=None,
        metadata=meta(
            "Prompt text for prompt mode (mutually exclusive with trigger)",
            Scope.REPO,
        ),
    )
    trigger: ScheduleTrigger | None = field(
        default=None,
        metadata=meta(
            "Script trigger for script mode (mutually exclusive with prompt)",
            Scope.REPO,
        ),
    )
    model: str | None = field(
        default=None,
        metadata=meta("Override repo default model", Scope.TASK),
    )
    effort: str | None = field(
        default=None,
        metadata=meta("Override repo default effort level", Scope.TASK),
    )
    output_limit: int = field(
        default=102400,
        metadata=meta("Max script output bytes (default 100KB)", Scope.REPO),
    )
```

The `schedules` field is added to `RepoServerConfig` as a dict mapping schedule
name to `ScheduleConfig`, with `Scope.REPO` metadata.

### Delivery Target Syntax

| Target format      | Channel | Behavior              |
| ------------------ | ------- | --------------------- |
| `user@example.com` | email   | Send email to address |

### Validation

At config load time:

- Exactly one of `prompt` or `trigger` must be set.
- `deliver.channel` must match a configured channel type in the same repo
  (currently only `"email"` is supported).
- `cron` must be a valid 5-field expression (validated by `CronExpression`).
- `timezone` must be a valid IANA timezone (`ZoneInfo(timezone)` must succeed).

## Architecture

The scheduler is a **service-level component**, not a channel. It does not fit
the `ChannelListener`/`ChannelAdapter` pattern: there are no inbound messages to
authenticate, no acknowledgments to send, and delivery is decoupled from
reception. Instead, the scheduler lives alongside the executor pool and GC
thread:

```
GatewayService
+-- ThreadPoolExecutor (shared worker pool)
+-- DashboardServer
+-- GarbageCollector thread
+-- ConfigFileWatcher
+-- Scheduler                         <-- new
|   +-- scheduler thread
+-- RepoHandlers
    +-- ChannelAdapters (email, ...)
    +-- ConversationManager
```

### Why Not a Channel

A channel must implement `ChannelListener` (receive messages) and
`ChannelAdapter` (authenticate, parse, send replies). The scheduler has none of
these responsibilities — it generates tasks internally and uses existing
channels for delivery. Forcing it into the channel abstraction would require:

- A fake `RawMessage` with no real content
- A fake `authenticate_and_parse` that bypasses auth
- Suppressed acknowledgments
- Routing `send_reply` to a different recipient than the sender

Each of these is a special case that adds complexity. The scheduler as a
standalone component is simpler and more explicit.

## Cron Parser

Built-in 5-field cron parser with no external dependencies.

```
+-------------- minute (0-59)
| +------------ hour (0-23)
| | +---------- day of month (1-31)
| | | +-------- month (1-12)
| | | | +------ day of week (0-6, 0=Sunday)
| | | | |
* * * * *
```

### Syntax Per Field

| Syntax  | Example   | Meaning                                 |
| ------- | --------- | --------------------------------------- |
| `*`     | `*`       | All values in the field's range         |
| `N`     | `5`       | Specific value                          |
| `N-M`   | `1-5`     | Inclusive range                         |
| `*/S`   | `*/15`    | Every S values from start of range      |
| `N-M/S` | `0-30/10` | Every S values within range             |
| `A,B`   | `1,15`    | List (elements can be values or ranges) |

Day-of-week value `7` is treated as `0` (Sunday), matching Vixie cron. Named
months and days are not supported — numeric only.

### Day Matching Semantics

When both day-of-month and day-of-week are restricted (not `*`), they combine
with **OR** semantics: the cron fires if the day matches either field. This
follows the standard Vixie cron convention.

### Interface

```python
class CronExpression:
    """Parsed 5-field cron expression."""

    def __init__(self, expr: str) -> None:
        """Parse a cron expression.

        Raises ValueError if the expression is invalid.
        """

    def next_fire_time(self, after: datetime, tz: ZoneInfo) -> datetime:
        """Compute the next fire time strictly after the given instant.

        Args:
            after: Reference time (timezone-aware).
            tz: Timezone for cron evaluation (the cron expression is
                interpreted in this timezone).

        Returns:
            Timezone-aware datetime of the next fire.

        Raises:
            RuntimeError: If no match is found within 4 years.
        """
```

### Algorithm

Starting from `after + 1 minute` (truncated to the minute boundary in `tz`):

1. If month doesn't match → advance to the first matching month, reset
   day/hour/minute to their first matching values.
2. If day doesn't match (considering OR semantics for day-of-month and
   day-of-week) → advance to the next matching day, reset hour/minute.
3. If hour doesn't match → advance to next matching hour, reset minute.
4. If minute doesn't match → advance to next matching minute.
5. If advancing any field wraps around, increment the parent field and restart
   from that level.

The search window is capped at 4 years to handle edge cases like `0 0 29 2 *`
(Feb 29). Typical expressions resolve in a few iterations.

## Scheduler

### Class

```python
class Scheduler:
    """Cron scheduler for periodic tasks.

    Runs a background thread that sleeps until the next scheduled fire
    time, then submits tasks to the gateway's shared executor pool.
    """

    def __init__(self, service: GatewayService) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def rebuild_repo(self, repo_id: str) -> None: ...
    def remove_repo(self, repo_id: str) -> None: ...
```

### Internal State

```python
@dataclass
class _ResolvedSchedule:
    repo_id: str
    name: str
    config: ScheduleConfig
    cron: CronExpression
    tz: ZoneInfo
    next_fire: datetime  # timezone-aware, in UTC for comparison
```

The scheduler maintains a `dict[str, dict[str, _ResolvedSchedule]]` keyed by
`repo_id → schedule_name`. Protected by a lock for concurrent access from the
config reload path.

### Thread Loop

The scheduler thread runs a simple sleep loop:

1. Compute `now` in UTC.
2. Find all schedules where `next_fire <= now`.
3. For each due schedule: dispatch to the executor pool, recompute `next_fire`.
4. Sleep until the earliest `next_fire` or 60 seconds (whichever is shorter).
5. The 60-second cap ensures the thread wakes up to pick up schedules added by
   config reload without needing a wake-up signal.

The shutdown event interrupts the sleep for clean exit.

### Dispatch

The scheduler submits work to the gateway's shared `ThreadPoolExecutor`:

```python
service.tracker.add_task(task_id, f"scheduled: {name}", repo_id=repo_id)
service._executor_pool.submit(execute_scheduled_task, ...)
```

This means scheduled tasks share the `max_concurrent_executions` limit with
interactive tasks. If all workers are busy, the scheduled task queues until a
worker is free. This is acceptable — scheduled tasks are not latency-sensitive.

### Missed Schedules

No catch-up. If the service was down when a schedule should have fired, the
missed execution is skipped. On start, `next_fire` is computed relative to the
current time, so only future fires are scheduled.

## Execution

### Shared Core Extraction

Currently, `process_message()` in `message_processing.py` handles both channel
orchestration (acknowledgments, plan streaming, attachments, channel context)
and sandbox execution (image build, mounts, env, network sandbox, Claude binary,
task creation, execution, result handling). These two concerns are entangled.

The scheduled task feature requires the sandbox execution logic without the
channel orchestration. Rather than duplicating ~200 lines of code, extract the
shared core into a reusable function:

```python
@dataclass(frozen=True)
class SandboxTaskResult:
    """Result of a sandbox task execution."""

    outcome: Outcome
    conversation_id: str
    response_text: str  # Claude's response or error message
    usage_stats: UsageStats | None
    layout: ConversationLayout  # for outbox file access
    is_error: bool


def run_in_sandbox(
    service: GatewayService,
    repo_handler: RepoHandler,
    *,
    prompt: str,
    task_id: str,
    model: str,
    effort: str | None,
    conversation_id: str | None = None,
    on_event: EventCallback | None = None,
) -> SandboxTaskResult:
    """Execute a prompt in the sandbox and return the result.

    If ``conversation_id`` is None, creates a new conversation.
    If provided, resumes the existing conversation (used by script
    mode where the CommandTask already ran in the same workspace).

    Handles: conversation creation/resumption, git mirror update,
    image build, mount assembly, env/secrets, network sandbox,
    Claude binary, task creation, execution, prompt-too-long
    recovery, and reply recording.

    Does NOT handle: acknowledgments, plan streaming, attachments,
    channel context, or response delivery.
    """
```

After extraction, `process_message()` becomes a thin wrapper:

1. Validate message, save attachments, build channel context.
2. Send acknowledgment.
3. Set up plan streamer.
4. Call `run_in_sandbox(prompt=channel_context + body, ...)`.
5. Send reply/error via adapter.

And `execute_scheduled_task()` is another thin wrapper:

1. Build prompt (from config or script output).
2. Call `run_in_sandbox(prompt=..., ...)`.
3. Deliver result via `send_new_message()`.

### Extraction Boundary

**Moves into `run_in_sandbox()`:**

- Git mirror update and conversation initialization
- `build_task_env()` and `resource_limits` from repo config
- Container image build (`_build_image()`)
- Mount assembly (workspace, inbox, outbox, storage)
- Network sandbox config (allowlist, replacement map)
- Claude binary resolution
- Sandbox task creation and execution
- Prompt-too-long / session-corrupted recovery
- `ConversationStore` recording (model, effort, reply summaries)

**Stays in `process_message()`:**

- Empty message validation
- `send_acknowledgment()`
- `save_attachments()` and channel context / inbox note
- Model hint from parsed message
- Plan streamer creation and `on_event` callback wiring
- `send_reply()` / `send_error()` / `send_rejection()`
- `GitCloneError` and `ChannelSendError` handling

### `execute_scheduled_task()`

```python
def execute_scheduled_task(
    service: GatewayService,
    repo_handler: RepoHandler,
    schedule_name: str,
    config: ScheduleConfig,
    task_id: str,
) -> None:
    """Execute a scheduled task. Runs in the shared worker pool."""
```

**Prompt mode flow:**

1. Build prompt with schedule context.
2. Call `run_in_sandbox()`.
3. Deliver result.

**Script mode flow:**

1. Initialize conversation (mirror update, `conv_mgr.initialize_new()`).
2. Build `CommandTask` and execute the trigger command.
3. Evaluate the `CommandResult`:
   - Exit 0, empty output → delete conversation, complete task, return.
   - Otherwise → build prompt from output.
4. Call `run_in_sandbox()` with the same conversation.
5. Deliver result.

Script mode needs conversation initialization before `run_in_sandbox()` because
the `CommandTask` runs first in the same workspace. The function accepts an
optional existing `conversation_id` to support this two-step flow.

### Prompt Construction

The prompt sent to Claude has two parts: the **channel context header** and the
**prompt body**.

#### Channel Context Header

The header reuses the delivery channel's standard system prompt — the same
instructions about `/workspace`, `/inbox`, `/outbox`, `/storage`, formatting,
and tool limitations that interactive messages receive. This ensures Claude
behaves consistently whether it was triggered by a user message or a schedule.

Each adapter gains a `channel_context()` method that returns the base system
prompt string without requiring an inbound message. The existing
`authenticate_and_parse()` methods are refactored to call `channel_context()`
internally, eliminating the duplicated context strings:

```python
# On each concrete adapter (EmailChannelAdapter, and future adapters)
def channel_context(self) -> str:
    """Return the base system prompt for this channel type."""
```

The header prepends this context with a note identifying the scheduled task:

```
{adapter.channel_context()}

This is a scheduled task "{name}". Your response will be delivered
to {to} via {channel_type}.
```

For email delivery, `channel_context()` returns the email adapter's standard
instructions (markdown supported, outbox for files, storage for persistence, no
AskUserQuestion).

#### Prompt Body

**Prompt mode** — the configured `prompt:` string is used directly:

```
{channel_context_header}

{schedule.prompt}
```

**Script mode, exit 0, non-empty output** — the script's stdout is the prompt.
The script is responsible for constructing whatever instructions it wants Claude
to see:

```
{channel_context_header}

{script_stdout, truncated to output_limit}
```

**Script mode, non-zero exit** — the script itself failed, so the system
generates a prompt:

```
{channel_context_header}

The scheduled trigger script failed unexpectedly.

Command: {command}
Exit code: {exit_code}

Output:
{stdout+stderr, truncated to output_limit}

Investigate the failure and report findings.
```

#### Example: CI Watchdog Script

A typical script mode workflow — a shell script that runs CI and constructs a
prompt only on failure:

```bash
#!/bin/bash
# .airut/scripts/ci-watchdog.sh
output=$(uv run scripts/ci.py --fix 2>&1)
if [ $? -ne 0 ]; then
    cat <<PROMPT
CI checks failed. Investigate the failures below and create a fix.
Run \`uv run scripts/ci.py --fix\` to verify your fix before finishing.

CI output:
$output
PROMPT
fi
# If CI passed: no output, exit 0 → Claude is not invoked
```

The script exits 0 in both cases — CI pass (no output, no Claude) and CI fail
(constructed prompt, Claude runs). A non-zero exit would mean the watchdog
script itself is broken, triggering the system-generated error prompt.

### Output Truncation

Script output is capped at `output_limit` bytes (default 100KB). For exit 0,
only stdout is used (the script controls the prompt). For non-zero exit, stdout
and stderr are concatenated (diagnostic context). If truncated, a note is
appended:

```
[...truncated at 100KB, total output was 2.3MB]
```

## Delivery

Delivery sends the result via the configured channel **and** registers the
conversation with that channel's state so replies route back naturally.

### `send_new_message()` on Channel Adapters

The email adapter gains a new public method for sending unsolicited messages.
This method is **not** part of the `ChannelAdapter` protocol because the
parameters are inherently channel-specific (email needs a subject line and
inline attachments; future channels will have different signatures). The
`delivery.py` module dispatches on the adapter type:

```python
adapter = repo_handler.adapters[schedule.deliver.channel]
if isinstance(adapter, EmailChannelAdapter):
    adapter.send_new_message(to, subject, body, conversation_id, attachments)
else:
    raise ValueError(f"Unsupported delivery channel: {type(adapter)}")
```

```python
# EmailChannelAdapter
def send_new_message(
    self,
    to: str,
    subject: str,
    body: str,
    conversation_id: str,
    attachments: list[tuple[str, bytes]],
) -> None:
    """Send a new (non-reply) email and register for reply routing."""
```

The method handles state registration internally — the Message-ID embeds the
conversation ID so replies route back through the normal interactive flow.

### Email Delivery

```python
subject = f"[ID:{conversation_id}] {schedule_name}"
message_id = generate_message_id(conversation_id, from_address)
responder.send_reply(
    to=to,
    subject=subject,
    body=body,
    message_id=message_id,
    attachments=attachments,
)
```

No `in_reply_to` or `references` — this is a new conversation. When the
recipient replies, their client sets `In-Reply-To` to the Message-ID, which
encodes the conversation ID in `<airut.{conv_id}...@domain>` format. The IMAP
listener picks it up, `extract_conversation_id_from_headers()` extracts the
conversation ID, and the conversation resumes through the normal interactive
flow. The `[ID:{conv_id}]` subject provides a fallback.

### Error Delivery

If the `AgentTask` fails (timeout, container error, prompt-too-long without
recovery), deliver an error message with the failure details and any partial
output. If delivery itself fails (SMTP error), log the error and do not retry.

### No-Notification Case

Script mode, exit 0, empty output: the conversation is deleted immediately. No
Claude run, no delivery, no dashboard entry beyond the brief completed task.

## Dashboard

Scheduled tasks appear on the dashboard identically to interactive tasks:

| Field           | Value                        |
| --------------- | ---------------------------- |
| Title           | `scheduled: {schedule_name}` |
| Sender          | `scheduler`                  |
| Repo            | Associated repo              |
| Conversation ID | Normal conversation ID       |

The stop button works via the same `register_active_task()` / `stop()`
mechanism. No dashboard code changes are needed — `TaskTracker` already supports
all required fields.

## Config Reload

Schedules are `Scope.REPO`. On config reload:

1. The config diff detects schedule changes as repo-scope changes (since
   `schedules` is a `Scope.REPO` field, any change triggers a repo-scope
   reload).
2. `_apply_single_repo_reload()` stops and restarts channel listeners. After the
   listener restart succeeds, it calls `scheduler.rebuild_repo(repo_id)` to
   synchronize the scheduler's state with the new config. The scheduler call
   happens after adapter recreation, so the scheduler always sees current
   adapter instances.
3. The scheduler removes all `_ResolvedSchedule` entries for that repo,
   re-parses from the new config, and computes fresh `next_fire` times.

On repo removal: `_remove_repo()` calls `scheduler.remove_repo(repo_id)`.

This is atomic per-repo and does not affect other repos' schedules. The
scheduler thread picks up changes on its next wake-up (within 60 seconds).

**Adapter reference safety.** The scheduler's `deliver_result()` looks up the
adapter from `repo_handler.adapters` at delivery time (not cached at schedule
creation). This means adapter recreation during repo reload does not invalidate
scheduler state — the scheduler always gets the current adapter.

## Lifecycle

### Startup

The scheduler starts after repos are live, during the `_boot()` sequence. No new
`BootPhase` is needed — the scheduler start is lightweight (spawns a thread) and
happens as a step within the existing REPOS → READY transition:

```
_boot()
  +-- Phase: proxy (sandbox.startup)
  +-- Phase: repos (start listeners)
  +-- self._scheduler.start()             <-- new, before READY
  +-- Phase: ready
```

### Shutdown

The scheduler stops before the executor pool, during `stop()`:

```
stop()
  +-- scheduler.stop()                    <-- new (before pool shutdown)
  +-- sandbox.shutdown()
  +-- stop repo listeners
  +-- executor_pool.shutdown()
  +-- dashboard.stop()
```

### Conversation Lifecycle

- Each execution creates a fresh conversation. No persistence across runs.
- Conversations are cleaned up by the existing GC thread.
- If a recipient replies, the conversation stays alive and resumes normally. The
  reply enters through the channel listener and follows the standard
  `submit_message()` → `process_message()` path, which acquires the
  per-conversation lock as usual.
- Script-mode no-output runs delete the conversation immediately.
- Scheduled task execution does not acquire a per-conversation lock because each
  run creates a unique conversation that no other task can reference yet. The
  lock becomes relevant only after delivery, when the recipient can reply.

## Dashboard Config Editor

The schedule block is visible and editable in the dashboard's per-repo config
editor. The declarative config system handles most of the integration
automatically, but two areas need explicit work: editor schema wiring and a
skeleton factory for new schedules.

### Schema Integration

`schedules: dict[str, ScheduleConfig]` on `RepoServerConfig` is auto-detected as
`type_tag="keyed_collection"` by `editor_schema.py`. The schema builder
recursively walks `ScheduleConfig` fields:

- `cron`, `timezone`, `model`, `effort`, `output_limit` → `type_tag="scalar"`
- `prompt` → `type_tag="scalar"` with `multiline=True` override (added to
  `FIELD_OVERRIDES`)
- `deliver` → `type_tag="nested"` with `nested_fields` from `ScheduleDelivery`
  (two scalar sub-fields: `channel`, `to`)
- `trigger` → `type_tag="nested"` with `nested_fields` from `ScheduleTrigger`
  (one `list_str` sub-field: `command`, one scalar: `timeout`)

The editor renders each schedule as a collapsible card (keyed_collection.html
template) with its sub-fields inline. Adding and removing schedules uses the
standard `add_item`/`remove_item` API.

No YAML structure mapping is needed — `ScheduleConfig`, `ScheduleDelivery`, and
`ScheduleTrigger` field names match their YAML keys directly.

### Editor Field Overrides

One override is added to `FIELD_OVERRIDES` in `editor_schema.py`:

| Field                   | Override         | Reason                           |
| ----------------------- | ---------------- | -------------------------------- |
| `ScheduleConfig.prompt` | `multiline=True` | Prompts are typically multi-line |

`ScheduleTrigger.command` needs no override — `list_str` renders inline by
default.

### Skeleton Factory

When adding a new schedule via the editor, a skeleton with required fields is
inserted:

```python
def _make_schedule_skeleton() -> dict[str, Any]:
    return {
        "cron": "0 9 * * 1-5",
        "deliver": {"channel": "email", "to": ""},
    }
```

The handler for `POST /api/config/add` with `path="repos.{repo_id}.schedules"`
calls this skeleton factory, matching the existing pattern for channels
(email/slack skeletons). Optional fields (`timezone`, `prompt`, `trigger`,
`model`, `effort`, `output_limit`) are omitted from the skeleton and take their
defaults.

### Diff Expansion to Scalar Level

The review dialog must expand schedule changes to individual scalar fields, not
opaque summaries. For example, changing a schedule's delivery address should
show:

```
repos.my-repo.schedules.daily.deliver.to    user@old.com → user@new.com
```

Not:

```
repos.my-repo.schedules.daily.deliver       (2 entries) → (2 entries)
```

The existing `diff_dict_field()` → `_expand_item_fields()` pipeline in
`editor.py` handles this via `collect_leaf_fields()`, which recursively flattens
nested `EditorFieldSchema` trees to scalar leaves. The `_expand_item_fields()`
function uses `get_raw_value(dict, leaf.path)` for path-based navigation into
nested structures, so `ScheduleConfig` fields nested inside `ScheduleDelivery`
and `ScheduleTrigger` expand correctly to their full dot-delimited paths.

### Dirty Count

The dirty count header (`X-Dirty-Count`) already counts per-key changes for
`keyed_collection` fields via `count_dict_field_changes()`. Each added, removed,
or modified schedule counts as one dirty entry (counted by key, not by
sub-field). This is consistent with how `masked_secrets` and other keyed
collections are counted.

### Variable Support

Schedule fields support `!var` references for sharing values across repos:

```yaml
vars:
  weekday_morning: "0 9 * * 1-5"
  ops_email: "ops@example.com"

repos:
  repo-a:
    schedules:
      daily-review:
        cron: !var weekday_morning
        deliver:
          channel: email
          to: !var ops_email
```

This works automatically — `resolve_var_refs()` walks the raw dict recursively
and replaces `VarRef` objects at any depth. The editor shows the `!var` source
tag and supports changing to/from variable references via the standard source
switcher (literal / !env / !var tabs).

Boolean fields are excluded from `!var` eligibility, but `ScheduleConfig` has no
boolean fields, so no override is needed.

## Implementation

### File Structure

```
airut/gateway/scheduler/
+-- __init__.py          # Exports: Scheduler, ScheduleConfig, etc.
+-- cron.py              # CronExpression parser
+-- config.py            # ScheduleConfig, ScheduleDelivery, ScheduleTrigger
+-- scheduler.py         # Scheduler class (thread loop, dispatch)
+-- execution.py         # execute_scheduled_task()
+-- delivery.py          # deliver_result() routing to email adapter
```

### Changes to Existing Files

| File                                          | Change                                            |
| --------------------------------------------- | ------------------------------------------------- |
| `airut/gateway/config.py`                     | Add `schedules` field to `RepoServerConfig`       |
| `airut/gateway/service/gateway.py`            | Scheduler lifecycle, reload hooks                 |
| `airut/gateway/service/message_processing.py` | Extract `run_in_sandbox()` shared core            |
| `airut/gateway/email/adapter.py`              | Add `send_new_message()`, `channel_context()`     |
| `airut/config/editor_schema.py`               | Add `FIELD_OVERRIDES` for `ScheduleConfig.prompt` |
| `airut/dashboard/handlers_config.py`          | Schedule skeleton factory, add/remove handling    |

### Implementation Phases

The feature can be implemented in four independent phases that each produce a
working, testable increment:

**Phase 1: Cron parser.** `CronExpression` class with `next_fire_time()`.
Self-contained module with no gateway dependencies. Validated purely through
unit tests. This is the only component with algorithmic complexity (DST, field
wrapping, OR day semantics) and benefits from being implemented and tested in
isolation.

**Phase 2: Shared core extraction.** Extract `run_in_sandbox()` from
`process_message()`. This is a pure refactor — no new features, no behavior
change. The existing test suite validates that interactive message processing
still works. This phase de-risks the integration by establishing the shared
interface before scheduled tasks depend on it.

**Phase 3: Scheduler, execution, and config editor.** `Scheduler` class,
`ScheduleConfig` dataclasses, `execute_scheduled_task()`, `GatewayService`
integration (lifecycle, config reload), and dashboard config editor support
(`FieldMeta` annotations, skeleton factory, `FIELD_OVERRIDES`). At this point
scheduled tasks can execute and log results, and schedules are editable in the
dashboard, but delivery is stubbed (logged, not sent).

**Phase 4: Delivery and reply-back.** `deliver_result()`, `send_new_message()`
on the email adapter. Completes the feature with end-to-end delivery and reply
routing. Reply-back works automatically via the existing email conversation ID
round-tripping (Message-ID encoding → In-Reply-To extraction).

## Open Items

- **Slack delivery.** The config schema supports `deliver.channel: "slack"` but
  only `"email"` is implemented. Slack delivery has several open design
  questions:

  - Airut's Slack integration uses **Agents & AI Apps** assistant threads. There
    is no API to create assistant threads programmatically, so scheduled results
    would need to be sent as **regular DMs** via `conversations.open` +
    `chat.postMessage`. These appear in the bot's DM Messages tab, not the AI
    Apps Chat/History tabs — a UX compromise.
  - Regular DMs use Slack's `mrkdwn` format (or `markdown` blocks restricted to
    AI Apps). Claude's standard markdown output would need markdown → mrkdwn
    conversion to render correctly in regular DMs.
  - Reply-back requires an additional `@app.event("message")` handler outside
    the Bolt `Assistant` middleware to catch regular DM thread replies.
  - Requires `im:write` scope addition to the Slack app manifest.

- **Schedule-level secrets.** Schedules inherit the repo's secrets. If a trigger
  script needs credentials that shouldn't be exposed to interactive tasks, a
  per-schedule `secrets:` override could be added later.

- **Persistent conversations.** Each execution is fresh. A `persistent: true`
  option could reuse the same conversation across runs, allowing Claude to
  accumulate context (useful for daily standups or trend analysis).

- **Concurrency guard.** If a scheduled task takes longer than the cron
  interval, the next fire will start a second instance. A `max_concurrent: 1`
  option could prevent overlapping executions for the same schedule.
