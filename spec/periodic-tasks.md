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
> Slack), but only the `"email"` channel is implemented in this version.

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

### Non-Goals

- **Slack delivery.** Config schema supports `deliver.channel: "slack"` but only
  `"email"` is implemented.
- **Schedule-level secrets.** Schedules inherit the repo's secrets pool.
- **Persistent conversations.** Each execution is fresh — no state carried
  between runs.
- **Concurrency guard.** If a scheduled task exceeds the cron interval, the next
  fire starts a second instance.

## Trigger Modes

### Prompt Mode

The schedule specifies a `prompt:` string. On each fire, the scheduler creates a
fresh conversation and runs an `AgentTask` with that prompt. The result is
delivered to the configured recipient.

### Script Mode

The schedule specifies a `trigger_command:` shell string. On each fire:

1. **Run `CommandTask`** in the sandbox with the same mounts as an `AgentTask`
   except Claude-related mounts (session directory, binary).

2. **Check result:**

   - Exit 0, empty stdout → done. Delete the conversation, no Claude run, no
     notification.
   - Exit 0, non-empty stdout → use stdout as the prompt and run `AgentTask`.
     The script constructs whatever prompt it wants Claude to see.
   - Non-zero exit → generate a system prompt including command, exit code, and
     both stdout and stderr, then run `AgentTask`.

3. **Deliver the `AgentTask` result** to the configured recipient.

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
channel blocks.

```yaml
repos:
  my-repo:
    repo_url: "https://github.com/org/repo.git"
    email: { ... }

    schedules:
      daily-review:
        cron: "0 9 * * 1-5"
        timezone: "Europe/Helsinki"
        subject: "Daily PR Review"
        prompt: "Review open PRs and summarize their status."
        deliver:
          channel: email
          to: "user@example.com"

      nightly-check:
        cron: "0 2 * * *"
        trigger_command: "./scripts/nightly-check.sh"
        trigger_timeout: 300
        output_limit: 204800
        deliver:
          channel: email
          to: "ops-team@example.com"
```

### Schema

| Field             | Type          | Default    | Description                                    |
| ----------------- | ------------- | ---------- | ---------------------------------------------- |
| `cron`            | `str`         | (required) | 5-field cron expression                        |
| `deliver.to`      | `str`         | (required) | Recipient address                              |
| `deliver.channel` | `str`         | `"email"`  | Delivery channel type                          |
| `subject`         | `str \| None` | `None`     | Override email subject (empty = schedule name) |
| `timezone`        | `str \| None` | `None`     | IANA timezone (empty = server local time)      |
| `prompt`          | `str \| None` | `None`     | Prompt text (mutually exclusive with trigger)  |
| `trigger_command` | `str \| None` | `None`     | Shell command for script mode                  |
| `trigger_timeout` | `int \| None` | `None`     | Timeout override (empty = repo default)        |
| `model`           | `str \| None` | `None`     | Override repo default model                    |
| `effort`          | `str \| None` | `None`     | Override repo default effort level             |
| `output_limit`    | `int`         | `102400`   | Max script output bytes                        |

### Validation

At config load time:

- Exactly one of `prompt` or `trigger_command` must be set.
- `deliver.channel` must match a configured channel type in the same repo.
- `cron` must be a valid 5-field expression (validated by `CronExpression`).
- `timezone`, when set, must be a valid IANA timezone (`ZoneInfo(timezone)` must
  succeed). When absent, the server's local timezone is used.

## Architecture

The scheduler is a **service-level component**, not a channel. It does not fit
the `ChannelListener`/`ChannelAdapter` pattern: there are no inbound messages to
authenticate, no acknowledgments to send, and delivery is decoupled from
reception.

```
GatewayService
+-- ThreadPoolExecutor (shared worker pool)
+-- DashboardServer
+-- GarbageCollector thread
+-- ConfigFileWatcher
+-- Scheduler
|   +-- scheduler thread
+-- RepoHandlers
    +-- ChannelAdapters (email, ...)
    +-- ConversationManager
```

### Internal State

The scheduler maintains a `dict[str, dict[str, _ResolvedSchedule]]` keyed by
`repo_id → schedule_name`. Each resolved schedule holds the parsed
`CronExpression`, timezone, and next fire time. Protected by a lock for
concurrent access from the config reload path.

### Thread Loop

1. Compute `now` in UTC.
2. Find all schedules where `next_fire <= now`.
3. For each due schedule: dispatch to the executor pool, recompute `next_fire`.
4. Sleep until the earliest `next_fire` or 60 seconds (whichever is shorter).
5. The 60-second cap ensures the thread wakes up to pick up schedules added by
   config reload without needing a wake-up signal.

The shutdown event interrupts the sleep for clean exit.

### Dispatch

The scheduler submits `execute_scheduled_task` to the gateway's shared
`ThreadPoolExecutor`. Scheduled tasks share the `max_concurrent_executions`
limit with interactive tasks. If all workers are busy, the scheduled task queues
until a worker is free.

### Missed Schedules

No catch-up. If the service was down when a schedule should have fired, the
missed execution is skipped. On start, `next_fire` is computed relative to the
current time.

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

### Syntax

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

### Algorithm

Starting from `after + 1 minute` (truncated to the minute boundary):

1. If month doesn't match → advance to the first matching month, reset
   day/hour/minute to their first matching values.
2. If day doesn't match (considering OR semantics for day-of-month and
   day-of-week) → advance to the next matching day, reset hour/minute.
3. If hour doesn't match → advance to next matching hour, reset minute.
4. If minute doesn't match → advance to next matching minute.
5. If advancing any field wraps around, increment the parent field and restart
   from that level.

The search window is capped at 4 years to handle edge cases like `0 0 29 2 *`
(Feb 29).

## Execution

### Shared Core

Scheduled tasks reuse `run_in_sandbox()` — the shared core extracted from
`process_message()`. This function handles conversation creation, git mirror
update, image build, mount assembly, env/secrets, network sandbox, Claude
binary, task execution, and prompt-too-long recovery. The caller provides only
the prompt, model, and effort level.

### Prompt Mode Flow

1. Build prompt with channel context header and configured prompt body.
2. Call `run_in_sandbox()`.
3. Deliver result.

### Script Mode Flow

1. Initialize conversation (mirror update, `initialize_new()`).
2. Build `CommandTask` and execute the trigger command.
3. Evaluate exit code and output:
   - Exit 0, empty output → delete conversation, complete task, return.
   - Otherwise → build prompt from output.
4. Call `run_in_sandbox()` with the same conversation.
5. Deliver result.

Script mode initializes the conversation before `run_in_sandbox()` because the
`CommandTask` runs first in the same workspace. The function accepts an optional
`conversation_id` to support this two-step flow.

### Prompt Construction

The prompt has two parts: a **channel context header** and the **prompt body**.

The header reuses the delivery channel's `channel_context()` method — the same
system prompt that interactive messages receive — plus a note identifying the
scheduled task:

```
{adapter.channel_context()}

This is a scheduled task "{name}". Your response will be delivered
to {to} via {channel_type}.
```

**Prompt mode body:** the configured `prompt:` string.

**Script mode, exit 0:** the script's stdout (truncated to `output_limit`).

**Script mode, non-zero exit:** a system-generated prompt with command, exit
code, and combined stdout/stderr.

### Output Truncation

Script output is capped at `output_limit` bytes (default 100KB). If truncated, a
note is appended: `[...truncated at 100KB, total output was 2.3MB]`.

## Delivery

Delivery sends the result via the configured channel and registers the
conversation so replies route back naturally.

### Email Delivery

The email adapter's `send_new_message()` generates a structured Message-ID
embedding the conversation ID, sends via SMTP, and returns. No `in_reply_to` or
`references` — this is a new conversation. When the recipient replies, their
client sets `In-Reply-To` to the Message-ID. The IMAP listener picks it up,
`extract_conversation_id_from_headers()` extracts the conversation ID, and the
conversation resumes through the normal interactive flow.

Subject format: `[ID:{conversation_id}] {subject or schedule_name}`

When the schedule has a `subject` field set, it is used instead of the schedule
name.

`send_new_message()` is **not** part of the `ChannelAdapter` protocol because
the parameters are inherently channel-specific. The `delivery.py` module
dispatches on the adapter type (`isinstance` check).

### Error Delivery

If the `AgentTask` fails (timeout, container error), an error message is
delivered with failure details. If delivery itself fails (SMTP error), the error
is logged without retry.

### No-Notification Case

Script mode, exit 0, empty output: the conversation is deleted immediately. No
Claude run, no delivery.

## Config Reload

Schedules are `Scope.REPO`. On config reload:

1. The config diff detects schedule changes as repo-scope changes.
2. `_apply_single_repo_reload()` calls `scheduler.rebuild_repo(repo_id)` after
   the listener restart succeeds.
3. The scheduler removes all resolved schedules for that repo, re-parses from
   the new config, and computes fresh `next_fire` times.

On repo removal: `_remove_repo()` calls `scheduler.remove_repo(repo_id)`
immediately, regardless of task deferral.

**Adapter reference safety.** `deliver_result()` looks up the adapter from
`repo_handler.adapters` at delivery time (not cached), so adapter recreation
during reload does not invalidate scheduler state.

## Lifecycle

### Startup

The scheduler starts after repos are live, during `_boot()`, before the READY
phase. It is lightweight — spawns a single thread.

### Shutdown

The scheduler stops before the executor pool during `stop()`.

### Conversation Lifecycle

- Each execution creates a fresh conversation. No persistence across runs.
- Conversations are cleaned up by the existing GC thread.
- If a recipient replies, the conversation resumes through the standard channel
  flow.
- Script-mode no-output runs delete the conversation immediately.

## Dashboard

### Task Display

Scheduled tasks appear on the dashboard identically to interactive tasks. The
title is `scheduled: {schedule_name}`, sender is `scheduler`. The stop button
works via the existing `register_active_task()` / `stop()` mechanism.

### Config Editor

The schedule block is editable in the dashboard's per-repo config editor. The
declarative config system handles most of the integration automatically:

- `schedules: dict[str, ScheduleConfig]` is auto-detected as a
  `keyed_collection`.
- `ScheduleConfig.prompt` has a `multiline=True` override in `FIELD_OVERRIDES`.
- Adding a new schedule inserts a skeleton with `cron` and `deliver` fields
  pre-populated.
- Schedule fields support `!var` references via the standard variable resolution
  pipeline.
