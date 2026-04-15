# Periodic Tasks

Airut can run scheduled tasks on a cron schedule, executing them in the same
sandbox as interactive tasks and delivering results via email. Recipients can
reply to the delivery email to continue the conversation through the normal
channel flow.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Overview](#overview)
- [Configuration](#configuration)
  - [Prompt Mode](#prompt-mode)
  - [Script Mode](#script-mode)
  - [Schedule Fields](#schedule-fields)
- [Timezone Handling](#timezone-handling)
- [Delivery and Reply-Back](#delivery-and-reply-back)
- [How It Works](#how-it-works)
- [Troubleshooting](#troubleshooting)

<!-- mdformat-toc end -->

## Overview

Periodic tasks let you run Claude on a schedule — daily code reviews, nightly
health checks, weekly summaries. There are two modes:

- **Prompt mode** — runs Claude with a fixed prompt on every fire
- **Script mode** — runs a command first, then optionally invokes Claude based
  on the command's output

Scheduled tasks share the worker pool with interactive tasks
(`max_concurrent_executions`). They use the same container images, mounts,
network sandbox, and secrets as interactive channel messages.

## Configuration

Schedules are defined per-repo in the server config
(`~/.config/airut/airut.yaml`) under `repos.<repo_id>.schedules`. Each schedule
has a name (used as the default email subject), a cron expression, and a
delivery target. Set the optional `subject` field to override the email subject
line.

### Prompt Mode

Runs Claude with the configured prompt on every cron fire:

```yaml
repos:
  my-repo:
    repo_url: "https://github.com/org/repo.git"
    email: { ... }

    schedules:
      daily-report:
        cron: "0 9 * * 1-5"          # 9:00 AM, Monday-Friday
        timezone: "Europe/Helsinki"
        prompt: "Review open PRs and summarize their status."
        deliver:
          channel: email
          to: "dev-team@example.com"
```

### Script Mode

Runs a command first. Claude is invoked only when the command produces output or
fails:

```yaml
    schedules:
      nightly-check:
        cron: "0 2 * * *"            # 2:00 AM daily
        trigger_command: "./scripts/nightly-check.sh"
        trigger_timeout: 300
        output_limit: 204800          # 200KB max script output
        deliver:
          to: "ops-team@example.com"
```

Script mode behavior based on exit code:

| Exit code | stdout    | Action                                                    |
| --------- | --------- | --------------------------------------------------------- |
| 0         | empty     | No notification, conversation deleted                     |
| 0         | non-empty | Script stdout becomes the prompt for Claude               |
| non-zero  | any       | Error details (command, exit code, output) sent to Claude |

The intended pattern is "notify only when something needs attention" — the
script acts as a filter. For example, a nightly CI health check script might run
the test suite: if all tests pass, it exits 0 with no output, and Claude is not
triggered. If tests fail, the script outputs the failure details as a prompt for
Claude (e.g., "The following tests failed: ... Please investigate and create a
fix"), and Claude analyzes the failures, creates a fix, and delivers the result
via email. The recipient can then reply to continue the conversation.

### Schedule Fields

| Field             | Type          | Default    | Description                                    |
| ----------------- | ------------- | ---------- | ---------------------------------------------- |
| `cron`            | `str`         | (required) | 5-field cron expression                        |
| `deliver.to`      | `str`         | (required) | Recipient address                              |
| `deliver.channel` | `str`         | `"email"`  | Delivery channel type                          |
| `enable`          | `bool`        | `true`     | Whether the schedule is active                 |
| `subject`         | `str \| None` | `None`     | Override email subject (empty = schedule name) |
| `timezone`        | `str \| None` | `None`     | IANA timezone (empty = server local time)      |
| `prompt`          | `str \| None` | `None`     | Prompt text (mutually exclusive with trigger)  |
| `trigger_command` | `str \| None` | `None`     | Shell command for script mode                  |
| `trigger_timeout` | `int \| None` | `None`     | Timeout override (empty = repo default)        |
| `model`           | `str \| None` | `None`     | Override repo default model                    |
| `effort`          | `str \| None` | `None`     | Override repo default effort level             |
| `output_limit`    | `int`         | `102400`   | Max script output bytes                        |

Exactly one of `prompt` or `trigger_command` must be set. The `deliver.channel`
must match a configured channel type in the same repo (only `"email"` is
currently supported).

Set `enable: false` to temporarily disable a schedule without removing it from
config. When omitted, schedules are enabled by default.

## Timezone Handling

The `timezone` field accepts any IANA timezone name (e.g., `"America/New_York"`,
`"Europe/Helsinki"`, `"Asia/Tokyo"`). When omitted, the server's local timezone
is used, detected from the `TZ` environment variable, `/etc/timezone`, or
`/etc/localtime` symlink (falling back to UTC).

Cron expressions are evaluated in the specified timezone, including DST
transitions.

## Delivery and Reply-Back

Results are delivered via the configured channel (currently email only). The
email subject includes the conversation ID:
`[ID:{conversation_id}] {subject or schedule_name}`. When the `subject` field is
set in the schedule config, it overrides the schedule name in the subject line.

When a recipient replies to a delivery email, their email client sets
`In-Reply-To` to the original Message-ID. The IMAP listener extracts the
conversation ID from the header, and the conversation resumes through the normal
interactive flow — the recipient can ask follow-up questions, request changes,
or continue the analysis.

If the task fails (timeout, container error), an error message is delivered with
failure details. If delivery itself fails (SMTP error), the error is logged
without retry.

## How It Works

The scheduler is a service-level component that runs a single background thread.
On each tick it checks which schedules are due, dispatches them to the shared
worker pool, and sleeps until the next fire time (capped at 60 seconds for
responsiveness to config changes).

Scheduled tasks appear on the dashboard identically to interactive tasks, with
the title `scheduled: {schedule_name}` and sender `scheduler`. The stop button
works normally.

Key behaviors:

- **No catch-up** — if the service was down when a schedule should have fired,
  the missed execution is skipped
- **No concurrency guard** — if a task exceeds its cron interval, the next fire
  starts a second instance
- **Fresh conversations** — each execution creates a new conversation with no
  state carried between runs
- **Config reload** — schedule changes are picked up via live config reload, no
  restart needed

See [spec/periodic-tasks.md](../spec/periodic-tasks.md) for the full
implementation specification.

## Troubleshooting

**Schedule not firing:**

- Check that `enable` is not set to `false`
- Verify the cron expression with a cron calculator
- Check that the timezone is correct (logs show next fire times at startup)
- Ensure the delivery channel is configured on the same repo

**Script mode not triggering Claude:**

- Exit 0 with empty stdout means no notification — verify the script produces
  output when it should
- Check `output_limit` if large output is being truncated

**Delivery failures:**

- Check SMTP connectivity and credentials
- Verify the `deliver.to` address is valid
- Check service logs: `journalctl --user -u airut | grep scheduled`

**Reply-back not working:**

- Ensure the email channel is configured on the same repo
- Verify the recipient's reply includes the `In-Reply-To` header (some clients
  strip it)
