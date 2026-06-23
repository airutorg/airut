# Slack Channel

Slack as a messaging channel for Airut, enabling users to interact with Claude
Code through Slack — both 1:1 DMs (via Slack's Agents & AI Apps platform) and
`@`-mention-driven engagement in public and private channels.

This spec assumes the protocol-agnostic gateway
([gateway-architecture.md](gateway-architecture.md)) is implemented. The Slack
channel plugs into the existing `ChannelAdapter`, `ChannelListener`, and
`ChannelConfig` protocols alongside the email channel. Multiple channels per
repo are supported — see [multi-repo.md](multi-repo.md).

## Interaction Model

### Agents & AI Apps Mode (DMs)

The Slack app uses Slack's **Agents & AI Apps** feature, which replaces the
standard bot DM Messages tab with two purpose-built tabs:

- **Chat tab** — starts a new conversation. Opens in a split-view side panel on
  desktop, so the user can keep working in Slack while the bot processes.
- **History tab** — lists past conversations with titles, allowing users to
  resume.

This solves the fundamental threading UX problem in bot DMs: users naturally
type at the top level, but Airut needs threaded conversations for isolation.
Agents & AI Apps mode makes every interaction a thread by default — the user
cannot send unthreaded messages.

### Why Not Standard Bot DMs

In standard bot DMs, threading is unreliable. Users habitually type at the top
level, creating ambiguity about which conversation a message belongs to. The bot
would need to constantly redirect users into threads, adding friction. Agents &
AI Apps mode eliminates this by making threads the only interaction surface.

### Channel Mode

In channel mode, the bot lives in workspace channels (public or private) like
any other member. Engagement is `@`-mention driven so the bot does not
participate in unrelated conversation:

- The bot starts treating a thread as an Airut conversation the first time a
  message in that thread `@`-mentions the bot. The mention may be the top-level
  message of a brand-new thread, or a reply inside an existing thread that the
  bot has not yet joined.
- Once engaged, every subsequent message in that thread is treated as additional
  input — no further `@`-mention required. This makes the bot feel like a
  participant rather than a command-line tool.
- The bot ignores messages in threads it has not been invited to via mention.
- The bot ignores its own messages and messages from bot users. This is what
  stops two Airut instances sharing a channel from `@`-mentioning each other
  into an unbounded back-and-forth, and is enforced at two independent layers
  (see [Bot Messages Are Never Accepted](#bot-messages-are-never-accepted)).

This complements rather than replaces the DM surface — both can be active for
the same repo simultaneously.

### Conversation Lifecycle

**DM (Agents & AI Apps) flow:**

```
User opens Airut in Slack (top bar icon or split-view)
  -> assistant_thread_started event
  -> Bot shows greeting
  -> User sends a message
    -> message.im event with thread_ts
    -> Bot maps thread to Airut conversation (new or resumed)
    -> Bot sets status "is working on this..." during prep, clears it
       before the run starts (composer unlocks for follow-ups)
    -> Sandbox executes Claude Code
    -> Bot replies in thread with result
    -> Bot sets thread title from conversation topic
  -> User sends follow-up in same thread
    -> Same Airut conversation resumes
  -> User opens Chat tab again later
    -> New thread -> new Airut conversation
  -> User opens History tab, clicks old thread
    -> Continues existing Airut conversation
```

**Channel flow:**

```
User invites bot to a channel via /invite @airut
  -> No Airut state created until first mention

User posts top-level message: "@airut please look at this bug"
  -> app_mention event (also delivered as message.channels)
  -> Bot adds :eyes: reaction (instant ack)
  -> Bot maps (channel_id, message.ts) to a new Airut conversation
  -> Bot replies in thread with result
  -> Bot swaps :eyes: for :white_check_mark: (success) or :x: (failure)

User replies in the same thread (no mention required)
  -> message.channels event with thread_ts matching the engaged thread
  -> Bot adds :eyes: reaction
  -> Resumes the Airut conversation
  -> On completion, swaps :eyes: for :white_check_mark: / :x:

User mentions bot inside an existing thread that bot has not joined
  -> app_mention with thread_ts pointing at an older root message
  -> Bot fetches conversations.replies to read prior thread history
  -> Bot creates an Airut conversation rooted on that thread_ts
  -> Prior thread messages are formatted into the initial prompt
  -> Bot replies in thread with result

User talks in a channel without @-mentioning the bot
  -> Event delivered but dropped: thread is not in the mapping store
     and the message text contains no <@BOT_USER_ID> token
```

### Conversation Identity

Each Slack thread maps to one Airut conversation. The same scheme covers both
the DM and channel surfaces:

| Slack concept                                 | Airut concept       |
| --------------------------------------------- | ------------------- |
| `channel_id` (DM or channel) + `thread_ts`    | Conversation ID     |
| New DM thread (via Chat tab)                  | New conversation    |
| New channel thread rooted on an `app_mention` | New conversation    |
| Message in an existing thread that bot joined | Resume conversation |

The adapter maintains a mapping between `(channel_id, thread_ts)` and Airut
conversation IDs, persisted as a JSON file in the repo's state directory so it
survives service restarts. This matches the email adapter's file-based approach
— simple, no external dependencies, and the data is small (one entry per
conversation). The schema is the same for DM and channel surfaces; the channel
ID's prefix (`D` for DM, `C`/`G` for public/private channels) is incidental to
lookup.

### Channel Engagement Rule

For each non-DM message, the adapter decides whether to engage:

1. If the event carries a `bot_id` (a bot-authored message, including the Airut
   bot's own posts): drop. A `subtype` also drops the event, **except** content
   subtypes such as `file_share` (a file upload, even one with a text comment),
   which carry genuine user input — otherwise a file posted into an engaged
   thread would be silently lost. The `app_mention` handler drops on any
   `subtype` (file uploads never arrive as `app_mention`); the
   `message.channels`/`.groups` handler keeps the content subtypes. The `bot_id`
   guard is identical in both, so a bot that `@`-mentions Airut cannot trigger a
   run. See [Bot Messages Are Never Accepted](#bot-messages-are-never-accepted).
2. If `(channel_id, thread_ts)` (using `message.ts` for top-level messages)
   resolves to a known conversation: engage. This is the "sticky thread" path
   that lets follow-ups land without re-mention.
3. Else if the message text contains the bot's `<@BOT_USER_ID>` token: engage,
   replaying thread history if the mention is mid-thread (next section).
4. Else: drop silently.

DM (`message.im`) events bypass step 3 entirely — every DM is by definition
addressed to the bot. The bot's own user ID is resolved once at startup. The
mention token is matched as a literal substring so the `<@BOT_USER_ID|airut>`
form (used when a display name is available) also matches.

A single channel mention is delivered as both an `app_mention` and a
`message.channels`/`message.groups` event. The listener deduplicates on
`(channel_id, ts)` so the message is processed exactly once.

### Thread History Replay

When the bot is mentioned mid-thread for the first time, it fetches the prior
messages with `conversations.replies(channel, ts=thread_ts)` and folds them into
the initial prompt so Claude has the same context as a human reading the thread.
Subsequent messages in the now-engaged thread arrive one at a time and do not
require replay.

The replayed history is rendered as a preamble appended to `channel_context`:

```
The user invited you into an existing Slack thread.  The messages
below are the conversation that preceded the invocation, in order.
Use them as background; the invocation that triggered you is the
attributed message that follows this preamble.

[<display name 1>]: <message body>
[<display name 2>]: <message body>
...
[<display name N>]: <message body>
```

The invocation itself is **not** repeated in the preamble: it is delivered
through the normal user-message path with its per-message
`[<sender> <timestamp>]` attribution header (see
[gateway-architecture.md](gateway-architecture.md)), which doubles as the seam
between background and invocation. The triggering message (matched by `ts`), bot
posts, and system/edit subtypes (join/leave, edits) are dropped from the
preamble. File uploads (subtype `file_share`) are **kept**: their files are
downloaded into `inbox/` alongside the invocation's own attachments, and the
rendered line notes them as `[attached: <names>]`, so a file shared before the
bot was invited is still available to Claude.

Display names come from the authorizer's user cache; missing entries fall back
to the raw user ID. Inbound mention tokens inside the replayed bodies are
resolved through the same path as the invocation message so Claude sees
human-readable names rather than opaque IDs (see
[Person Identification](#person-identification)).

History replay is bounded to the most recent **200 messages** in the thread;
older messages are summarized as `[N earlier messages omitted]` to keep the
prompt size predictable. In practice channel threads almost never exceed this;
it is a safety bound rather than a tuning parameter.

### Thread Titles

On the DM surface the adapter sets a thread title (visible in the History tab)
after the first successful reply, derived from the user's first message
(truncated). This helps users find and resume past conversations.

In channels the title is **not** set — `assistant.threads.setTitle` is a DM-only
(Agents & AI Apps) API. Channel threads are discovered by their root message,
which is sufficient context for human readers.

### Status Indicators

Slack locks the thread composer (disables the send button) while an assistant
loading status is active, releasing it only when the app next posts to the
thread. A long-lived "is working on this..." status held for the whole run would
therefore prevent the user from sending follow-up messages — defeating message
coalescing, which exists precisely to absorb a burst of messages sent during a
busy conversation.

To avoid this, the gateway does not manage statuses directly. It reports
**lifecycle phases** to the adapter via
`ChannelAdapter.report_phase(parsed, phase)`, and each adapter decides how to
surface them. This keeps channel-specific presentation policy — including
Slack's composer-locking quirk — out of the channel-agnostic gateway. The
gateway emits:

- `TaskPhase.PREPARING` at the start, before conversation creation/resume.
- `TaskPhase.RUNNING` immediately before the sandbox run begins.

The Slack adapter scopes the loading status to the **preparation window only**:
`PREPARING` sets `"is working on this..."` and `RUNNING` clears it, unlocking
the composer for the duration of the run. The Slack-specific text and the
locking behaviour both live in the adapter. A coalesced message never reaches
the gateway's phase-reporting path, so it never re-locks the composer.

Statuses are a DM-only API. In a channel the adapter instead drives a reaction
lifecycle on the triggering message: a `:eyes:` reaction on arrival (instant
acknowledgement that survives in the thread's history), swapped on completion
for `:white_check_mark:` (success) or `:x:` (failure). For channel messages
`report_phase` ignores `PREPARING`/`RUNNING` (no status to set) and acts only on
the terminal `COMPLETED`/`FAILED` phases. Every reaction call is non-fatal — if
the API fails (missing permission, message deleted) the adapter logs a warning
and continues.

The completion swap covers the **whole coalesced burst**: each arriving channel
message is acknowledged with its own `:eyes:` and its timestamp is accumulated
on the surviving pending message, so when the merged task finishes every
constituent message has its `:eyes:` replaced.

If preparation fails before `RUNNING`, the status is cleared implicitly by the
error notification: prep-failure paths post via `send_error()`, and Slack clears
an active status on the next thread post. (If that post also fails because Slack
is unreachable, the status cannot be cleared anyway.)

### Asynchronous Execution Model

Slack follows the same async model as the email channel: the bot acknowledges
the request immediately, then works asynchronously and replies when done.

1. **Acknowledgment.** During prep the adapter shows a loading status (DM) or
   adds a `:eyes:` reaction (channel); see
   [Status Indicators](#status-indicators). For new conversations it also posts
   "I've started working on this and will reply shortly" to the thread, with a
   dashboard link if one is configured. The threaded message is posted only on
   the first message that triggers a fresh execution, whereas the `:eyes:`
   reaction is added per arriving message — so a coalesced channel message still
   gets a reaction but does not produce a second "I've started" post.
2. **Execution.** Claude Code runs in a container via the sandbox. No streaming
   of intermediate output to Slack. The composer is unlocked during the run, so
   follow-up messages can be sent and are coalesced into the active
   conversation.
3. **Reply.** The complete response is converted to Slack `mrkdwn` and posted to
   the thread via `chat.postMessage` using the `text` parameter. In a channel
   the in-flight `:eyes:` reaction is then swapped for `:white_check_mark:`
   (success) or `:x:` (failure) on every message the task consumed.

This avoids the complexity of streaming action blocks back to Slack and keeps
the interaction model consistent with the email channel. The dashboard provides
real-time progress visibility for users who want it.

### Channel Context (System Prompt)

The `channel_context` field on `ParsedMessage` is prepended to the user's
message as instructions for Claude. The Slack adapter mirrors the email channel
context, with "Slack" replacing "email" references:

```
User is interacting with this session via Slack and will receive your
last reply as a Slack message. After the reply, everything not in
/workspace, /inbox, and /storage is reset. Markdown formatting (except
tables) is supported in your responses. To send files back to the user, place them
in the /outbox directory root (no subdirectories). Use /storage to
persist files across messages.

IMPORTANT: AskUserQuestion and plan mode tools (EnterPlanMode/
ExitPlanMode) do not work over Slack. If you need clarification, include
questions in your response text and the user will reply via Slack.
```

Both channels use the same async execution model where interactive tools
(AskUserQuestion, plan mode) are unavailable.

### Message Formatting

Claude emits standard Markdown, but Slack renders its own `mrkdwn` syntax
(`*bold*`, `_italic_`, `<url|text>` links, `•` bullets, no headings). Rather
than ship Markdown through Slack's Block Kit `markdown` block and rely on its
server-side translation — historically a source of bugs around bare URLs,
adjacent emphasis, and headings — the adapter performs an **explicit,
source-of-truth conversion** from CommonMark to `mrkdwn` and sends the result
via the plain `text` parameter (no `blocks` payload).

Mapping rules:

| Markdown                | mrkdwn                                    |
| ----------------------- | ----------------------------------------- |
| `**bold**`              | `*bold*`                                  |
| `*italic*` / `_italic_` | `_italic_`                                |
| `~~strike~~`            | `~strike~`                                |
| `# H1` … `###### H6`    | `*<text>*` on its own line (no headings)  |
| `[text](url)`           | `<url\|text>`                             |
| Bare URL                | `<url>`                                   |
| `` `code` ``            | `` `code` `` (unchanged)                  |
| Fenced \`\`\`\` `lang ` | ```` ``` ``` ```` (language hint dropped) |
| Unordered list          | `• <item>`, nested with leading spaces    |
| Ordered list            | `<n>. <item>`                             |
| `> quote`               | `> quote` (unchanged)                     |
| Markdown table          | Aligned fenced code block                 |
| `---` / `***` / `___`   | `———` (Unicode em-dash line)              |
| `<`, `>`, `&`           | Escaped to `&lt;` / `&gt;` / `&amp;`      |
| `- [ ]` / `- [x]`       | `• ☐ …` / `• ☑ …`                         |

Slack does not render Markdown tables, so tables are pre-processed into
column-aligned fenced code blocks (monospace alignment is the best available
presentation). Escaping of the literal `<`, `>`, and `&` characters that
`mrkdwn` reserves happens as a final pass on text nodes only — link URLs and
code spans pass through unescaped so the `<…>` link syntax survives.

After `mrkdwn` rendering, replies additionally pass through outbound mention
rewriting, which converts unambiguous `@displayname`, `#channelname`, and
`@groupname` tokens to their Slack reference forms so they render as real
mentions. See [Person Identification](#person-identification).

### Message Size Limits

A `mrkdwn` `text` message accepts up to **40,000 characters**, so most responses
ship as a single message. For longer responses:

1. A body within 40,000 characters is sent as a single `chat.postMessage`.
2. A larger body is split at paragraph boundaries (then line boundaries, then
   hard-sliced if a single line exceeds the ceiling) into multiple in-thread
   messages, so no chunk exceeds 40,000 characters.
3. A body that splits into more than five chunks is uploaded as a `response.md`
   file attachment in the thread.

### Task Progress Display

Claude's `TodoWrite` tool emits task progress during execution. The Slack
channel displays this progress in the user's thread in real time by posting a
message and updating it in place. Only `TodoWrite` events trigger updates —
individual tool-use events (Read, Bash, etc.) are not streamed — which keeps the
display focused on the plan overview and avoids rate limiting from
high-frequency tool calls.

The `PlanStreamer` protocol in `channel.py` defines the channel-agnostic
interface: `update(items)` for `TodoWrite` events and `finalize()` for
completion. The Slack implementation posts a `mrkdwn`-formatted message with
emoji status indicators (`⚪` pending, `🔄` in-progress, `✅` completed) and
updates it via `chat.update`. The email adapter returns `None` from
`create_plan_streamer()` (email has no progress display equivalent).

Behavioural contract:

- The message is posted **lazily** on the first `update()` — if Claude never
  uses `TodoWrite`, no progress message is created.
- Rapid updates are **debounced** so only the latest state is sent, preventing
  rate limiting when Claude emits many `TodoWrite` calls in quick succession.
- The plan message is a **separate** message in the thread, posted before the
  final reply.
- All progress posts/updates are **non-fatal** (logged as warnings). Losing plan
  updates is acceptable; the final reply and dashboard are unaffected.

Slack's `chat.startStream` / `appendStream` / `chat.stopStream` API with
`task_display_mode="plan"` was considered but rejected because (1) plan blocks /
task cards don't render on mobile Slack clients, (2) streams require keepalive
timers to prevent server-side idle expiry, adding fragile complexity, and (3)
`chat.update` gives full control over formatting with standard `mrkdwn` that
renders consistently everywhere.

### Person Identification

Channel conversations involve more than the bot and a single user. Claude needs
to know *who* is talking and *whom* they refer to in order to respond
intelligibly ("Alice asked X, Bob then suggested Y"), and the bot's own replies
need to render `@mentions` and `#channel-links` correctly so they land like a
normal Slack message.

Two operations cover this, applied to every Slack message (DM and channel):

- **Inbound resolution** converts Slack mention tokens in incoming message
  bodies (and replayed thread history) into human-readable strings before they
  are folded into the prompt.
- **Outbound rewriting** converts unambiguous `@name`, `#name`, and `@group`
  tokens in replies back into Slack mention syntax after the CommonMark →
  `mrkdwn` render.

Resolution reuses the authorizer's user and user-group caches (no extra
`users.info` traffic) plus a lazily populated channel name → ID cache. For a DM
the outbound candidate set is just the sender, so rewriting stays conservative
there.

#### Inbound mention resolution

| Slack token                              | Rendered as                                                                                                |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `<@U12345>`                              | `@<display name>`                                                                                          |
| `<@U12345\|alice>`                       | `@<display name>` (display name preferred over the link label so the prompt is consistent across messages) |
| `<#C12345\|general>`                     | `#general`                                                                                                 |
| `<!subteam^S98765\|engineering>`         | `@engineering`                                                                                             |
| `<!channel>` / `<!here>` / `<!everyone>` | `@channel` / `@here` / `@everyone` (kept literal, never rewritten back outbound)                           |
| Bare URL inside `<https://…>`            | `https://…`                                                                                                |

When the bot's own ID appears in the invocation message it is removed entirely
(it is redundant context for Claude), but it is preserved in replayed history
(where it carries information about whether the bot was previously addressed).

#### Outbound mention rewriting

The output is scanned for `@token` and `#token`, and each is matched against a
per-thread candidate set:

1. **Candidate set.** The lookup table is composed of the triggering message's
   sender, every distinct author seen in the replayed thread history, and every
   member of any user group named in the repo's authorization rules (e.g.
   `user_group: engineering`). This keeps rewriting conservative — the bot will
   not silently `@mention` a workspace member who has never been part of the
   thread.

   **Limitation.** Deployments that authorize via `workspace_members: true` (the
   default for most installs) have no `user_group` rule, so the candidate set is
   just the participants of the current thread. A name Claude writes referring
   to a workspace member who has never posted in the thread falls through to
   "zero matches" and renders as plain text rather than a Slack ping. This is
   acceptable — the alternative (loading every workspace member) would require
   expensive `users.list` calls and would still be ambiguous for common names. A
   live mention is only produced by a bare `@name` token (written outside code
   spans) that resolves against the candidate set. Hand-writing a raw
   `<@USERID>` token does **not** work: the `mrkdwn` renderer escapes `<`/`>`
   for echo-safety before the rewriter runs (see
   [Display name in `ParsedMessage`](#display-name-in-parsedmessage)), so the
   token becomes inert text. There is currently no supported way to ping a
   workspace member who is absent from the candidate set.

2. **Match.** For each token, look for an exact (case-insensitive) match against
   the candidate set's `display_name`, then `real_name`, then `name` (Slack
   handle), in that order. Bot users are excluded.

3. **Resolve.** One match → rewrite to the appropriate Slack token (`<@U…>`,
   `<#C…|name>`, `<!subteam^S…|handle>`). Zero matches → leave the literal
   `@token` alone (plain text, no notification). More than one match → leave
   alone (ambiguous).

Broadcast tokens (`@channel`, `@here`, `@everyone`) and the bot's own ID are
**never** rewritten outbound, regardless of authorization. The first prevents
accidental noisy pings; the second avoids the bot pinging itself.

The token grammar for outbound scanning is conservative: `@` or `#` must be at a
word boundary, the name body is `[A-Za-z0-9._-]+`, and the following character
must be a word boundary. This avoids rewriting tokens inside URLs, email
addresses, or code spans; code spans and fenced code blocks are excluded
entirely.

#### Display name in `ParsedMessage`

The `sender` field is set to the raw Slack user ID — the canonical trust anchor,
recorded as the dashboard's `authenticated_sender`. The human-readable display
name is carried separately in `sender_display` (`DisplayName <U123>`), resolved
from the authorizer's cache, and is used in two places: embedded in the rendered
prompt via the per-message attribution header (see
[gateway-architecture.md](gateway-architecture.md)) so Claude sees the human
name without calling a tool, and shown as the dashboard's `sender` field so task
cards are scannable by name rather than opaque ID. The same readable form is
produced for rejected senders (auth failures), so the dashboard names them too —
consistent with email, which surfaces the (unverified) `From` header. The
bracketed ID is a bare `<U12345678>`, **not** `<@U12345678>`, so the resolved ID
is never itself live-mention syntax. The display-name half is user-controlled
and is trusted from an authorized sender (consistent with the message body);
echo-safety comes from the outbound `mrkdwn` renderer, which escapes `<`/`>`/`&`
so any mention markup Claude reproduces is inert.

### File Handling

**Inbound** (user → bot): Users can attach files in a Slack DM or channel
message. The adapter extracts file metadata during parsing and downloads the
files via the Slack API (using the bot token) into the conversation's `inbox/`
directory, matching the email adapter's two-phase pattern. Downloads are gated
to known Slack file-hosting hosts so the bot token is never sent to an arbitrary
URL appearing in an event payload.

Slack delivers a file upload as a message with subtype `file_share`, so the
channel listener admits that subtype (see
[Channel Engagement Rule](#channel-engagement-rule)) and mid-thread replay
collects files from prior messages as well — attachments posted both before and
after the bot joined a thread reach `inbox/`. When several attachments share a
filename (within one message, across a coalesced burst, across replayed history,
or across turns), later files are written under a `-N`-suffixed name rather than
overwriting earlier ones (shared with the email adapter via
`unique_inbox_path`). On the DM surface the Agents & AI Apps middleware already
admits `file_share`, so no extra carve-out is needed there.

**Outbound** (bot → user): Files from `outbox/` are uploaded to the thread via
Slack's `files_upload_v2` method.

## Authorization Model

### Design Goals

- No manual user ID enumeration — leverage Slack's workspace structure
- Deny by default — at least one rule must match
- Exclude guests and external users automatically
- Support both broad (workspace-wide) and narrow (group/user) policies
- For channel mode, also allow operators to restrict *which channels* the bot
  will engage in, even when invited

### Channel Allowlist

In addition to per-user rules, the Slack config accepts an optional
`allowed_channels` list of channel IDs. When present and non-empty, the adapter
only engages in those channels:

```yaml
slack:
  allowed_channels:
    - C0123456789 # #engineering
    - C9876543210 # #incident-bridge
```

- Channels are referenced by **ID**, not name. Channel names can change; IDs are
  stable, which is why Slack itself recommends IDs for durable references. The
  trade-off is discoverability: an ID like `C0123456789` is opaque, so operators
  must look it up (e.g. a channel's *Copy link* in Slack, or the API). The
  dashboard config editor exposes `allowed_channels` as an editable list but
  does not provide a channel picker.
- When `allowed_channels` is unset or empty, the bot engages in any channel it
  has been invited to (the "Slack membership is the gate" model). This keeps
  small deployments simple.
- Filtering happens at the listener boundary before authorization runs: an event
  for a non-allowed channel is dropped silently (no `:eyes:` reaction, no
  rejection message). This avoids leaking the bot's presence to a channel where
  it should be inert.
- DM events (`message.im` and assistant thread events) bypass the allowlist
  entirely — a DM's channel ID is unique per `(user, bot)` pair and is already
  gated by the `authorized` rules.

This is a defence-in-depth layer over Slack channel membership, not a
replacement: removing the bot from a channel still stops events at the Slack
side.

### Authorization Rules

The config supports three rule types, evaluated in order. The first match grants
access:

```yaml
slack:
  authorized:
    # Allow all full workspace members (most common for internal tools)
    - workspace_members: true

    # Restrict to specific user group(s) -- Slack handle like @engineering
    - user_group: engineering

    # Restrict to specific users (fallback for fine-grained control)
    - user_id: U12345678
```

Rules can be combined. For example, "all of engineering plus two specific
contractors":

```yaml
slack:
  authorized:
    - user_group: engineering
    - user_id: U11111111
    - user_id: U22222222
```

#### `workspace_members`

Grants access to all full workspace members when set to `true`. Setting it to
`false` has no effect (the rule never matches and is silently skipped; config
parsing logs a warning). The adapter resolves the sender via `users.info` and
requires: not a multi-channel guest (`is_restricted`), not a single-channel
guest (`is_ultra_restricted`), not a bot, and a matching workspace `team_id`
(not an external Slack Connect user).

Slack's Agents & AI Apps mode additionally **natively blocks guest users** from
apps with this feature enabled — a platform-level enforcement that complements
the application-level check.

#### `user_group`

Grants access to members of a Slack user group (the groups behind handles like
`@engineering`). Group membership is resolved via `usergroups.users.list` and
group names to IDs via `usergroups.list`; if a configured group name doesn't
exist, the service logs a warning but continues. Requires the `usergroups:read`
scope.

#### `user_id`

Grants access to a specific Slack user by ID — the most explicit form, a
fallback when workspace- or group-level rules are too broad. User IDs are stable
across name changes.

### Baseline Checks (Always Applied)

Regardless of which rule matches, the authorizer always rejects bot users
(`is_bot`), external users (`team_id` mismatch), and deactivated users
(`deleted`). These prevent accidental access even if a broad rule like
`workspace_members: true` is configured.

### Bot Messages Are Never Accepted

Messages authored by a bot — any other Slack app, an incoming webhook, or
another Airut instance — are never accepted, on **any** surface (DM,
`app_mention`, or `message.channels`/`.groups`). The motivating hazard is an
unbounded loop: if two Airut bots share a channel and one could be triggered by
the other's posts, a single mention could ping-pong between them indefinitely.

This is enforced at two independent layers:

1. **Listener guard (cheap, early).** Both channel handlers drop events carrying
   a `bot_id` before any work is queued — no `:eyes:` reaction, no worker task,
   no API call, no dedup slot consumed. A bot post that `@`-mentions Airut
   arrives as an `app_mention` (and a `message.*` duplicate); both are dropped
   here. System/edit subtypes are dropped too, but content subtypes such as
   `file_share` are kept (so uploaded files survive); the `bot_id` check
   enforces the no-loop invariant independently of subtype.
2. **Authorizer baseline (defense in depth).** Even if an event reached the
   worker, the authorizer rejects any sender whose Slack profile has `is_bot`
   set (see [Baseline Checks](#baseline-checks-always-applied)). This covers the
   DM surface and backstops the listener guard.

Bots carry `bot_id` even when they post under an associated bot *user*, so the
listener guard does not depend on resolving that user via `users.info`.

### Request Authentication (Socket Mode)

Slack offers two mechanisms for verifying that events originate from Slack:
signing-secret verification (HTTP mode) and a pre-authenticated WebSocket
(Socket Mode). Airut uses **Socket Mode exclusively**: the app initiates an
outbound WebSocket connection using an app-level token (`xapp-...`), verified
during the `apps.connections.open` handshake. Once connected, all events arrive
over this authenticated channel — no per-event signature verification is needed,
and the Bolt SDK skips signature checks in Socket Mode.

The security boundary is the app-level token: anyone with the token can
establish a connection and receive events, so it must be protected like any
other credential (stored via `!env`, registered with `SecretFilter`). The `user`
field in Socket Mode events is guaranteed by Slack to be the actual sender —
there is no equivalent of email spoofing. The only authorization concern is
whether the authenticated user is *allowed* to use the bot, handled by the rules
above.

## Security Considerations

### Comparison to Email Security

| Concern                 | Email                           | Slack                                    |
| ----------------------- | ------------------------------- | ---------------------------------------- |
| Identity verification   | DMARC on trusted headers        | Pre-authenticated WebSocket (app token)  |
| Request authentication  | N/A (IMAP pull model)           | App-level token authenticates connection |
| Sender spoofing risk    | High (DMARC mitigates)          | None (platform-enforced identity)        |
| Authorization           | `authorized_senders` patterns   | `authorized` rules                       |
| Guest exclusion         | N/A                             | Platform-level + application-level       |
| External user exclusion | N/A                             | `team_id` check                          |
| Transport security      | TLS (IMAP/SMTP)                 | TLS (WebSocket)                          |
| Credential exposure     | Email password/OAuth2 in config | Bot token + app token in config          |

### Credential Management

The Slack app requires two tokens, both scoped per repo (each repo has its own
Slack app, matching the email model of one mailbox per repo):

- **Bot token** (`xoxb-...`): acts as the app for all API calls. Stored under
  `slack.bot_token`.
- **App-level token** (`xapp-...`): used for Socket Mode connections. Stored
  under `slack.app_token`.

Both support `!env` tags for environment-variable resolution and are registered
with `SecretFilter` for log redaction, matching the email adapter's handling of
credentials.

### Network Model

Socket Mode means the service initiates an outbound WebSocket connection to
Slack's servers — compatible with Airut's typical deployment behind a firewall:
no inbound HTTP endpoint, no public DNS, no TLS certificates needed. The Bolt
SDK manages the WebSocket lifecycle including automatic reconnection.

### Rate Limiting

The adapter must respect Slack's rate limits (message posting ~1/second/channel;
`users.info` Tier 4; `usergroups.users.list` Tier 2). Caching user info and
group membership is the primary mitigation — the adapter does not make API calls
in hot paths that can be served from cache.

### Workspace Isolation

A single Airut deployment may serve multiple repos, each with its own Slack app
(different bot token). Airut supports **one Slack app per repo**, matching the
email model of one mailbox per repo. Multi-repo routing through a single Slack
app is a future consideration.

## Configuration

### Server Config (per-repo)

Slack config is a per-repo block, parallel to `email:`, living under
`repos.<name>`. A repo can have both `email:` and `slack:` active simultaneously
(see [multi-repo.md](multi-repo.md)); a Slack-only repo omits the `email:`
block. At least one channel must be present per repo. For the full field
reference (tokens, authorization rules, `allowed_channels`, examples), see
[`config/airut.example.yaml`](../config/airut.example.yaml).

The config exposes:

- `bot_token` / `app_token` — required credentials (see Credential Management).
- `authorized` — the authorization rules; at least one is required.
- `allowed_channels` — optional channel-ID allowlist (see
  [Channel Allowlist](#channel-allowlist)).

### Slack App Setup

A ready-to-use app manifest is provided at
[`config/slack-app-manifest.json`](../config/slack-app-manifest.json).

**Creating the app:**

1. Go to [api.slack.com/apps?new_app=1](https://api.slack.com/apps?new_app=1)
2. Choose **From a manifest**, select your workspace
3. Paste the JSON manifest and create the app
4. Under **Basic Information -> App-Level Tokens**, click **Generate Token and
   Scopes**, name it (e.g., `airut-socket-mode`), add the `connections:write`
   scope, and generate. Copy the `xapp-...` token — this is `SLACK_APP_TOKEN`.
5. Under **OAuth & Permissions**, click **Install to Workspace** and authorize.
   Copy the **Bot User OAuth Token** (`xoxb-...`) — this is `SLACK_BOT_TOKEN`.
6. Under **Basic Information**, upload the app icon (the manifest format does
   not support icon URLs — they must be uploaded via the UI).

The icon is available at `https://airut.org/assets/logo-square-white-bg.png`.

The manifest configures:

**Required features:** Agents & AI Apps toggle enabled, Socket Mode enabled, bot
user enabled (always online).

**Required scopes (bot token):**

| Scope               | Purpose                                                                              |
| ------------------- | ------------------------------------------------------------------------------------ |
| `assistant:write`   | Thread titles, status indicators (DM-only)                                           |
| `chat:write`        | Send messages                                                                        |
| `im:history`        | Read DM history (for thread context)                                                 |
| `users:read`        | User info for authorization and display-name resolution                              |
| `files:read`        | Read user-uploaded files                                                             |
| `files:write`       | Upload outbox files to threads                                                       |
| `app_mentions:read` | Receive `app_mention` events in channels                                             |
| `channels:history`  | Read public-channel thread history (`conversations.replies`)                         |
| `groups:history`    | Read private-channel thread history (`conversations.replies`)                        |
| `reactions:write`   | Add/remove channel acknowledgement reactions (`:eyes:` → `:white_check_mark:`/`:x:`) |

**Optional scopes:**

| Scope             | Purpose                                                                            |
| ----------------- | ---------------------------------------------------------------------------------- |
| `usergroups:read` | Required for `user_group` rules and outbound `@group` rewriting                    |
| `channels:read`   | Required for outbound `#channel` rewriting and dashboard channel-ID lookup by name |

The four channel scopes (`app_mentions:read`, `channels:history`,
`groups:history`, `reactions:write`) back channel mode; DM-only deployments can
omit them without affecting DM operation. `im:read` is **not** required — all DM
references arrive via Socket Mode events and no API method queries DM metadata.

**Required event subscriptions (bot events):**

| Event                              | Purpose                                               |
| ---------------------------------- | ----------------------------------------------------- |
| `assistant_thread_started`         | New conversation started (DM)                         |
| `assistant_thread_context_changed` | User switched channels (Agents & AI Apps, DM only)    |
| `message.im`                       | User message in DM thread                             |
| `app_mention`                      | Bot was `@`-mentioned in a channel                    |
| `message.channels`                 | Follow-up messages in engaged public-channel threads  |
| `message.groups`                   | Follow-up messages in engaged private-channel threads |

`app_mention` is required even though the same message is also delivered as
`message.channels`/`message.groups`: it is the canonical engagement signal Slack
recommends. The listener deduplicates the two deliveries on `(channel_id, ts)`
(see [Channel Engagement Rule](#channel-engagement-rule)).

## Architecture

### Protocol Alignment

The Slack channel implements the three channel protocols from
`gateway/channel.py`:

- **`ChannelConfig`** — provides `channel_type` (`"slack"`) and `channel_info`
  for dashboard display.
- **`ChannelListener`** — wraps the Bolt SDK's Socket Mode handler to implement
  `start(submit)`, `stop()`, and `status`.
- **`ChannelAdapter`** — implements the message-handling methods (see the table
  below) plus the `listener` property and `create_plan_streamer`.

`RepoHandler` remains fully channel-agnostic, driving the listener through the
protocol interfaces with no channel-specific code paths. The adapter factory
dispatches on the channel config type to construct the right adapter.

### Adapter Method Contract

| `ChannelAdapter` method    | Slack behaviour                                                                                                                                                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authenticate_and_parse()` | Check authorization via the authorizer; make the engagement decision; replay mid-thread history via `conversations.replies`; resolve inbound mention tokens; in a channel add the `:eyes:` reaction                                   |
| `save_attachments()`       | Download files listed on the parsed message using the bot token (gated to Slack file hosts), save to `inbox_dir`                                                                                                                      |
| `send_acknowledgment()`    | Register the thread mapping and post the "I've started" confirmation (with optional dashboard link)                                                                                                                                   |
| `report_phase()`           | DM: `PREPARING` → set loading status, `RUNNING` → clear it. Channel: `COMPLETED`/`FAILED` → swap `:eyes:` for `:white_check_mark:`/`:x:` on every acknowledged message; `PREPARING`/`RUNNING` are ignored                             |
| `send_reply()`             | Render Markdown → `mrkdwn`, apply outbound mention rewriting against the per-thread candidate set, post via the `text` parameter (splitting/file-upload past the size limit), upload outbox files, and set the thread title (DM only) |
| `send_error()`             | Post error text to the thread                                                                                                                                                                                                         |

### Listener

The listener wraps the Bolt `App` and `SocketModeHandler`. Unlike the email
listener, which manages its own polling/IDLE loop, it delegates event dispatch
to the Bolt Socket Mode event loop. `SocketModeHandler.connect()` is
**non-blocking** — it starts the WebSocket in a background thread and returns
immediately — so the listener starts without blocking the calling thread, and
the handler manages automatic reconnection internally.

It wires two sets of handlers:

- **Agents & AI Apps middleware (DMs):** `thread_started` (greeting),
  `thread_context_changed` (logged), and `user_message` (wraps the event in a
  `RawMessage` and submits it to the worker pool). Authentication happens in the
  worker thread, not in the event handler.
- **Direct channel handlers:** `app_mention` is the primary engagement signal;
  `message.channels`/`message.groups` are submitted only when the thread is
  already engaged or the body mentions the bot. Both handlers drop events
  carrying a `bot_id`, so bot-authored mentions never trigger a run (see
  [Bot Messages Are Never Accepted](#bot-messages-are-never-accepted)); they
  also drop system/edit subtypes while keeping content subtypes like
  `file_share`, so uploaded files are not lost. The membership check is done
  inline against the in-memory thread store (no API call) so noisy channels do
  not flood the worker pool. The listener also drops events for channels outside
  `allowed_channels` before any submit, and deduplicates the
  `app_mention`/`message.*` double-delivery on `(channel_id, ts)` via a bounded
  LRU (256 entries, oldest-first eviction, no time-based expiry).

The bot's own user ID is resolved once at startup (via `auth.test`) and shared
with the adapter so mention tokens can be recognised without re-resolving.

### Parsed Message

The Slack adapter's parsed-message type extends `ParsedMessage` with the state
needed for reply threading and deferred work: the channel ID and thread
timestamp, the list of `(filename, url)` pairs for deferred attachment download,
the list of acknowledged message timestamps (seeded with the triggering message
and extended on each coalesced follow-up, so the completion swap covers the
whole burst), an `is_channel` flag (gates the DM-only `setStatus`/`setTitle`
calls), and the set of user IDs eligible for outbound `@`-mention rewriting
(sender, replayed thread authors, configured user-group members). Coalescing is
polymorphic: the adapter's `coalesce()` override extends the
acknowledged-timestamp list **and the pending file-download list** on top of the
base entry merge, so attachments on a message that coalesces into a busy
conversation are still saved to `inbox/`. The core sees a `ParsedMessage`; the
adapter downcasts to access these fields when sending replies.

### Thread-to-Conversation Store

A file-backed store maps `channel_id:thread_ts` keys to Airut conversation IDs,
persisted as a small JSON file in the repo's state directory and loaded into
memory at startup (matching the email adapter's persistence pattern). It
supports lookup, registration, and retention-based pruning: the garbage
collector calls `ChannelAdapter.cleanup_conversations()` after each per-repo
sweep with the set of surviving conversation IDs, and the store removes any
mapping whose conversation ID is not in that set. This keeps the store in sync
with the conversation directory without it needing to know about conversation
lifecycle directly.

### Authorizer

The authorizer evaluates authorization rules against cached Slack API data: a
`users.info` cache (5-minute TTL, thread-safe) storing role flags, `team_id`,
and display name; and a `usergroups.users.list` membership cache (5-minute TTL
per group, with group handle-to-ID resolution done lazily), which falls back to
stale data rather than failing if a refresh errors. Baseline checks run before
rule evaluation; rules are evaluated in order, first match wins. The same caches
back display-name resolution and the outbound mention candidate set, so those
paths add no extra Slack API traffic.

### Dashboard Integration

Slack conversations appear in the dashboard identically to email conversations —
no dashboard code changes are needed. The dashboard works with `TaskState` and
`ConversationMetadata`, neither of which contains channel-specific fields;
`sender` carries the Slack user ID and `sender_display` the resolved
`DisplayName <U123>`. With multi-channel ([multi-repo.md](multi-repo.md)) the
dashboard gains per-channel health info, independent of the Slack implementation
itself.

### Dependencies

`slack-bolt` (which bundles `slack-sdk`) is a required core dependency rather
than an optional extra. This avoids conditional imports, test-time module
patching, and type/coverage exclusions; the ~2MB install cost is negligible.
Deployments that don't use Slack simply omit the `slack:` block — the dependency
is present but dormant. All Slack modules are fully type-checked and included in
coverage, like the rest of the codebase.

### Testing

Slack tests follow the same patterns as email tests, mocking the Slack
`WebClient` and `SocketModeHandler` so no real connection is needed: per-module
unit tests, adapter tests that construct the adapter directly with mocked
dependencies and a real thread store, and listener tests that verify handler
registration and submit-callback wiring.

## Open Items

Future considerations beyond the current design:

- **Suggested prompts**: configurable prompts shown when opening the Chat tab,
  via `set_suggested_prompts()` in the `thread_started` handler.
- **Model selection**: email uses subaddressing (`airut+opus@`); Slack currently
  uses the repo default model. Could add a command prefix or prompt-based
  selection.
- **Response streaming**: stream the final response as it generates.
- **Multi-repo routing**: a single Slack app serving multiple repos with
  thread-level routing.
- **Canvas integration**: use Slack Canvases for long-form output exceeding
  message size limits.
- **Per-channel author overrides**: let `allowed_channels` take a richer shape
  (e.g. `{id: C123, authorized: [...]}`) so a channel can have a narrower set of
  authorized users than the repo's global rules.
- **Edited messages**: currently treated as new messages; could update the
  prompt in place when an edit lands during the coalescing window.
