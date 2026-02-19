# Slack Channel

Slack as a messaging channel for Airut, enabling users to interact with Claude
Code through Slack DMs using Slack's Agents & AI Apps platform.

This spec assumes the protocol-agnostic gateway
([gateway-architecture.md](gateway-architecture.md)) is implemented. The Slack
channel plugs into the existing `ChannelAdapter`, `ChannelListener`, and
`ChannelConfig` protocols alongside the email channel. Multiple channels per
repo are supported — see [multi-repo.md](multi-repo.md).

## Interaction Model

### Agents & AI Apps Mode

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

### Why Not Channel-Only

Channel @mentions are natural for quick one-off questions but poor for
multi-turn conversations. Threads in busy channels get buried, and the
notification model doesn't match long-running tasks. Channel @mentions could be
supported as a future extension but are not part of the initial implementation.

### Conversation Lifecycle

```
User opens Airut in Slack (top bar icon or split-view)
  -> assistant_thread_started event
  -> Bot shows greeting
  -> User sends a message
    -> message.im event with thread_ts
    -> Bot sets status: "is working on this..."
    -> Bot maps thread to Airut conversation (new or resumed)
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

### Conversation Identity

Each Slack thread maps to one Airut conversation:

| Slack concept                           | Airut concept       |
| --------------------------------------- | ------------------- |
| `channel_id` (DM channel) + `thread_ts` | Conversation ID     |
| New thread (via Chat tab)               | New conversation    |
| Message in existing thread              | Resume conversation |

The adapter maintains a mapping between `(channel_id, thread_ts)` and Airut
conversation IDs. This mapping is persisted as a JSON file in the repo's state
directory (`{STATE_DIR}/slack_threads.json`) so it survives service restarts.
This matches the email adapter's file-based approach — simple, no external
dependencies, and the data is small (one entry per conversation).

### Thread Titles

The adapter sets a thread title (visible in the History tab) after the first
successful reply. The title is derived from the user's first message (truncated)
or from the conversation topic if Claude provides one. This helps users find and
resume past conversations.

### Status Indicators

While a task is executing, the adapter calls `assistant.threads.setStatus` to
show progress (e.g., "is working on this..."). The status clears automatically
when the bot sends its reply.

### Asynchronous Execution Model

Slack follows the same async model as the email channel: the bot acknowledges
the request immediately, then works asynchronously and replies when done.

1. **Acknowledgment**: When a message is received, the listener's `user_message`
   handler calls `set_status("is working on this...")` to show a loading
   indicator immediately (before dispatching to the worker thread). Later,
   `send_acknowledgment()` posts a message to the thread: "I've started working
   on this and will reply shortly." If a dashboard URL is configured, the
   message includes a link to track progress. This message is always sent (not
   just when dashboard is configured) because these requests take a long time
   and a short confirmation sets the right expectation.
2. **Execution**: Claude Code runs in a container via the sandbox. No streaming
   of intermediate output to Slack.
3. **Reply**: The complete response is posted to the thread via
   `chat.postMessage` with Block Kit `markdown` blocks. The status indicator
   clears automatically when the reply is sent.

This avoids complexity from streaming action blocks back to Slack and keeps the
interaction model consistent with the email channel. The dashboard provides
real-time progress visibility for users who want it.

### Channel Context (System Prompt)

The `channel_context` field on `ParsedMessage` is prepended to the user's
message as instructions for Claude. The Slack adapter uses the same structure as
the email adapter but adapted for the Slack interaction model:

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

The Slack channel context mirrors the email channel context, with "Slack"
replacing "email" references. Both channels use the same async execution model
where interactive tools (AskUserQuestion, plan mode) are unavailable.

### Message Formatting

Slack's Block Kit includes a **`markdown` block type** (`"type": "markdown"`)
designed specifically for AI apps. This block accepts standard Markdown and
Slack translates it into properly rendered Slack formatting. This is significant
because Claude's output is standard Markdown — no format conversion is needed
(unlike the email channel which converts Markdown to HTML).

The adapter sends replies via `chat.postMessage` using a `blocks` payload
containing one or more `markdown` blocks:

```json
{
  "channel": "D12345678",
  "thread_ts": "1234567890.123456",
  "blocks": [
    {
      "type": "markdown",
      "text": "**Here is the response**\n\nStandard markdown content..."
    }
  ]
}
```

Supported standard Markdown in the `markdown` block:

- Headings, bold, italic, strikethrough
- Ordered and unordered lists
- Blockquotes
- Code blocks (without syntax highlighting)
- Links and images

Not supported: tables, horizontal rules, syntax highlighting, task lists.

Note that a single `markdown` block may result in multiple blocks after Slack's
translation step.

**Markdown sanitization**: The adapter sanitizes unsupported Markdown features
before sending via `_sanitize_for_slack()` in `send_reply()`. This applies the
following transformations in order:

1. **Tables** → fenced code blocks. Markdown table patterns (lines with `|`
   separators and a header-divider row of `|---|`) are wrapped in ```` ``` ````
   blocks to preserve alignment as monospaced plain text.
2. **Code fence language hints** → stripped. A fence like ```` ```python ````
   becomes plain ```` ``` ```` since Slack does not support syntax highlighting
   and would render the language tag as visible text.
3. **Horizontal rules** → em-dash separator (`———`). Rules (`---`, `***`, `___`)
   are replaced with a Unicode em-dash line. Rules inside fenced code blocks are
   preserved.

Task lists (`- [ ]`, `- [x]`) degrade gracefully — the checkbox syntax appears
as literal text within a list item, which is readable without conversion.

### Message Size Limits

A single `markdown` block accepts up to **12,000 characters**. A message can
contain up to **50 blocks**, though in practice the total payload limit means
the effective ceiling is around **~13,000 characters** across all blocks in a
single message.

For Claude responses that exceed the single-block limit:

1. **Primary strategy**: Split into multiple `markdown` blocks within a single
   message, breaking at natural boundaries (paragraph breaks, code block
   boundaries). This keeps the response as one message in the thread.
2. **Secondary strategy**: If the response exceeds ~13K characters total, split
   into multiple messages in the same thread.
3. **Fallback**: For extremely long responses, upload as a text/markdown file
   attachment in the thread.

### Block Validation Fallback

Slack's `markdown` block type may reject certain content with an
`invalid_blocks` error even when the content is within size limits. When this
happens, the adapter retries the message as plain text (using the `text`
parameter with no `blocks` payload). Plain-text messages support up to 40,000
characters and use Slack's mrkdwn formatting, which covers most common Markdown
constructs. Content beyond 40,000 characters is truncated by Slack, which is
acceptable compared to a complete delivery failure. This fallback applies to
every `chat.postMessage` call in the message delivery pipeline (single-message,
multi-message split, etc.).

### File Handling

**Inbound** (user -> bot): Users can attach files in the Slack DM. The adapter
downloads them via the Slack API (`files` array in the event payload, fetched
using the bot token) and saves to the conversation's `inbox/` directory via the
`save_attachments()` method. File metadata (URLs, names) is extracted during
`authenticate_and_parse()` and retained on the `SlackParsedMessage` for deferred
download in `save_attachments()`, matching the email adapter's two-phase
pattern.

**Outbound** (bot -> user): Files from `outbox/` are uploaded to the thread via
Slack's `files_upload_v2` method (which handles the upload URL and completion
internally).

## Authorization Model

### Design Goals

- No manual user ID enumeration — leverage Slack's workspace structure
- Deny by default — at least one rule must match
- Exclude guests and external users automatically
- Support both broad (workspace-wide) and narrow (group/user) policies

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

### `workspace_members` Rule

Grants access to all full workspace members when set to `true`. Setting
`workspace_members: false` has no effect (the rule never matches and is silently
skipped); config parsing logs a warning in this case.

At runtime, the adapter calls `users.info` on the sender and checks:

- `is_restricted == false` (not a multi-channel guest)
- `is_ultra_restricted == false` (not a single-channel guest)
- `is_bot == false` (not a bot)
- `team_id` matches the workspace (not an external Slack Connect user)

This is a single API call per message. Results should be cached with a
reasonable TTL (e.g., 5 minutes) since user roles change infrequently.

Additionally, Slack's Agents & AI Apps mode **natively blocks guest users** from
accessing apps with this feature enabled. This is a platform-level enforcement
that complements our application-level check.

### `user_group` Rule

Grants access to members of a Slack user group (the groups behind handles like
`@engineering`). The adapter resolves group membership via
`usergroups.users.list` at startup and refreshes periodically (e.g., every 5
minutes). Authorization checks membership in the cached set.

Scope required: `usergroups:read`.

Group names are resolved to group IDs via `usergroups.list` at startup. If a
configured group name doesn't exist, the service logs a warning but continues
(other rules may still grant access).

### `user_id` Rule

Grants access to a specific Slack user by ID. This is the most explicit form and
serves as a fallback when workspace-level or group-level rules are too broad.
User IDs are stable across name changes and can be found in Slack user profiles.

### Baseline Checks (Always Applied)

Regardless of which rule matches, the adapter always rejects:

- Bot users (`is_bot == true`)
- External users (`team_id` mismatch)
- Deactivated users (`deleted == true`)

These checks prevent accidental access even if a broad rule like
`workspace_members: true` is configured.

### Request Authentication (Socket Mode)

Slack provides two mechanisms for verifying that events originate from Slack:

1. **Signing secret verification** (HTTP mode): Each request includes an
   `x-slack-signature` header — an HMAC-SHA256 of the request body using the
   app's signing secret. The app verifies this signature to confirm
   authenticity. This is required when receiving events via HTTP endpoints.

2. **Pre-authenticated WebSocket** (Socket Mode): The app initiates an outbound
   WebSocket connection using an app-level token (`xapp-...`). The token is
   verified during the `apps.connections.open` call that generates a dynamic
   WebSocket URL. Once connected, all events arrive over this authenticated
   channel — no per-event signature verification is needed.

Since Airut uses **Socket Mode exclusively**, signing secret verification is not
required. The Bolt SDK's `RequestVerification` middleware explicitly skips
signature checks when running in Socket Mode (the `_can_skip` method returns
`True`). The security boundary is the app-level token: anyone with the token can
establish a WebSocket connection and receive events. This token must be
protected with the same care as any other credential (stored via `!env`,
registered with `SecretFilter`).

The `user` field in Socket Mode events is guaranteed by Slack to be the actual
sender — there is no equivalent of email spoofing. The only authorization
concern is whether the authenticated user is *allowed* to use the bot, which is
handled by the authorization rules described above.

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

- **Bot token** (`xoxb-...`): Acts as the app. Used for all API calls
  (`chat.postMessage`, `users.info`, etc.). Stored in server config under
  `slack.bot_token`.
- **App-level token** (`xapp-...`): Used for Socket Mode WebSocket connections.
  Stored in server config under `slack.app_token`.

Both tokens support `!env` tags for environment variable resolution (recommended
for secrets) but can also be specified as inline strings in the config file.
They are registered with `SecretFilter` for log redaction, matching the email
adapter's handling of credentials.

### Network Model

The Slack channel uses **Socket Mode exclusively** — the service initiates an
outbound WebSocket connection to Slack's servers. This is compatible with
Airut's typical deployment behind a firewall: no inbound HTTP endpoint, no
public DNS, no TLS certificates needed. The Bolt SDK's `SocketModeHandler`
manages the WebSocket lifecycle including automatic reconnection.

### Rate Limiting

The adapter must respect Slack's rate limits:

- Message posting: ~1 message/second/channel
- `users.info`: Tier 4 (~100+ requests/minute)
- `usergroups.users.list`: Tier 2 (~20 requests/minute)

Caching user info and group membership is the primary mitigation. The adapter
should not make API calls in hot paths that can be served from cache.

### Workspace Isolation

A single Airut deployment may serve multiple repos, each with its own Slack app
(different bot token). Alternatively, a single Slack app could serve multiple
repos, with channel or thread routing determining which repo handles a message.

The initial implementation supports **one Slack app per repo** (matching the
email model of one mailbox per repo). Multi-repo routing through a single Slack
app is a future consideration.

## Configuration

### Server Config (per-repo)

Slack config is a per-repo block, parallel to `email:`. A repo can have both
`email:` and `slack:` active simultaneously (see
[multi-repo.md](multi-repo.md)). The `slack:` block lives under `repos.<name>`:

```yaml
repos:
  my-project:
    git:
      repo_url: https://github.com/you/my-project.git

    email:
      # ... email config (optional, can coexist with slack)

    slack:
      # Bot token (xoxb-...) -- from OAuth & Permissions page
      bot_token: !env SLACK_BOT_TOKEN

      # App-level token (xapp-...) -- for Socket Mode
      app_token: !env SLACK_APP_TOKEN

      # Authorization rules (at least one required)
      authorized:
        - workspace_members: true
        # - user_group: engineering
        # - user_id: U12345678

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes: ["api.github.com"]
        headers: ["Authorization"]
```

A Slack-only repo omits the `email:` block entirely. At least one channel must
be present per repo. See [multi-repo.md](multi-repo.md) for the full
multi-channel data model.

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

**Required features:**

- Agents & AI Apps toggle: enabled
- Socket Mode: enabled
- Bot user: enabled, always online

**Required scopes (bot token):**

| Scope             | Purpose                                       |
| ----------------- | --------------------------------------------- |
| `assistant:write` | Thread titles, status indicators (auto-added) |
| `chat:write`      | Send messages                                 |
| `im:history`      | Read DM history (for thread context)          |
| `users:read`      | User info for authorization                   |
| `files:read`      | Read user-uploaded files                      |
| `files:write`     | Upload outbox files to threads                |

**Optional scopes:**

| Scope             | Purpose                                            |
| ----------------- | -------------------------------------------------- |
| `usergroups:read` | Required only if `user_group` rules are configured |

Note: `im:read` is **not** required. All DM references (channel IDs, thread
timestamps) arrive via Socket Mode events, and no API method in the
implementation queries DM metadata. `im:history` is included for thread context
access but `im:read` adds no value.

**Required event subscriptions (bot events):**

| Event                              | Purpose                   |
| ---------------------------------- | ------------------------- |
| `assistant_thread_started`         | New conversation started  |
| `assistant_thread_context_changed` | User switched channels    |
| `message.im`                       | User message in DM thread |

## Implementation

### Protocol Alignment

The Slack channel implements the three channel protocols defined in
`gateway/channel.py`:

- **`ChannelConfig`** — `SlackChannelConfig` provides `channel_type` and
  `channel_info` for dashboard display.
- **`ChannelListener`** — `SlackChannelListener` implements `start(submit)`,
  `stop()`, and `status` using the Bolt SDK's Socket Mode handler.
- **`ChannelAdapter`** — `SlackChannelAdapter` implements all seven adapter
  methods (`listener` property + six message handling methods).

`RepoHandler` remains fully channel-agnostic, calling `adapter.listener.start()`
/ `adapter.listener.stop()` with no channel-specific code paths.

### File Structure

```
airut/gateway/slack/
+-- __init__.py
+-- adapter.py         # SlackChannelAdapter (implements ChannelAdapter)
+-- config.py          # SlackChannelConfig (implements ChannelConfig)
+-- listener.py        # SlackChannelListener (implements ChannelListener)
+-- authorizer.py      # Authorization rule evaluation + user info cache
+-- thread_store.py    # Thread-to-conversation mapping persistence
```

### `SlackChannelConfig`

Frozen dataclass implementing `ChannelConfig`, parallel to `EmailChannelConfig`:

```python
@dataclass(frozen=True)
class SlackChannelConfig(ChannelConfig):
    """Slack channel configuration."""

    bot_token: str
    app_token: str
    authorized: tuple[dict[str, str | bool], ...] = ()

    def __post_init__(self) -> None:
        SecretFilter.register_secret(self.bot_token)
        SecretFilter.register_secret(self.app_token)
        if not isinstance(self.authorized, tuple):
            object.__setattr__(self, "authorized", tuple(self.authorized))
        if not self.authorized:
            raise ValueError("At least one authorization rule is required")

    @property
    def channel_type(self) -> str:
        return "slack"

    @property
    def channel_info(self) -> str:
        return "Slack (Socket Mode)"
```

### `SlackChannelListener`

Implements `ChannelListener` by wrapping the Bolt SDK's `App` and
`SocketModeHandler`. This is the key difference from the email listener: the
email listener manages its own polling/IDLE loop in a thread, while the Slack
listener delegates event dispatch to the Bolt SDK's Socket Mode event loop.

```python
class SlackChannelListener:
    """Socket Mode listener implementing ChannelListener protocol."""

    def __init__(
        self,
        config: SlackChannelConfig,
        *,
        app: App | None = None,
        handler: SocketModeHandler | None = None,
    ) -> None:
        self._app = app or App(token=config.bot_token)
        self._handler = handler or SocketModeHandler(
            self._app, config.app_token
        )
        self._status = ChannelStatus(health=ChannelHealth.STARTING)
        self._started = False

    def start(self, submit: Callable[[RawMessage[Any]], bool]) -> None:
        if self._started:
            return
        self._submit = submit
        self._register_handlers()
        self._install_connection_listeners()
        self._handler.connect()
        self._started = True
        self._status = ChannelStatus(health=ChannelHealth.CONNECTED)

    def stop(self) -> None:
        self._handler.close()
        self._status = ChannelStatus(
            health=ChannelHealth.FAILED, message="stopped"
        )

    @property
    def status(self) -> ChannelStatus:
        return self._status
```

Key detail: `SocketModeHandler.connect()` is **non-blocking** — it starts the
WebSocket connection in a background thread and returns immediately. This allows
`RepoHandler.start_listener()` to start the Slack listener without blocking,
unlike `handler.start()` which blocks the calling thread. The handler manages
automatic reconnection internally.

The listener registers event handlers via the Bolt SDK's `Assistant` middleware:

- `thread_started` — sends a greeting message.
- `thread_context_changed` — logged but no action needed.
- `user_message` — wraps the event payload in `RawMessage[dict]` and calls the
  `submit` callback, which feeds into the same worker thread pool as email
  messages. Authentication happens in the worker thread, not in the Socket Mode
  event handler.

### Connection to ChannelAdapter Interface

The `SlackChannelAdapter` implements all `ChannelAdapter` methods from
`gateway/channel.py`:

| ChannelAdapter method      | Slack implementation                                                                                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `listener` (property)      | Returns the `SlackChannelListener` instance                                                                                                                                           |
| `authenticate_and_parse()` | Check authorization rules via `SlackAuthorizer`, extract body and file metadata from event payload, resolve conversation ID from thread mapping                                       |
| `save_attachments()`       | Download files listed in `SlackParsedMessage.slack_file_urls` using bot token, save to `inbox_dir`                                                                                    |
| `send_acknowledgment()`    | Register thread mapping, `chat.postMessage` with confirmation text and optional dashboard link (status is set by the listener before dispatch)                                        |
| `send_reply()`             | Sanitize unsupported Markdown (tables, code fence languages, horizontal rules), split if >12K chars, `chat.postMessage` with `markdown` blocks, upload outbox files, set thread title |
| `send_error()`             | `chat.postMessage` with error text in thread                                                                                                                                          |
| `send_rejection()`         | `chat.postMessage` with rejection reason in thread, with optional dashboard link                                                                                                      |

### `SlackParsedMessage`

Subclass of `ParsedMessage` carrying Slack-specific state for reply threading
and deferred file download:

```python
@dataclass
class SlackParsedMessage(ParsedMessage):
    """Slack-specific parsed message."""

    slack_channel_id: str  # DM channel (D-prefixed)
    slack_thread_ts: str  # Thread timestamp
    slack_file_urls: list[tuple[str, str]] = field(default_factory=list)
    # List of (filename, download_url) for deferred download in save_attachments()
```

The `sender` field (inherited from `ParsedMessage`) is set to the Slack user ID
(e.g., `U12345678`) as the canonical identifier. The authorizer's user info
cache (from `users.info` calls) stores display names alongside role data; the
dashboard can display the cached display name when available, falling back to
the raw user ID.

The `display_title` field is set from the first message text (truncated to ~60
chars) for dashboard display. The `channel_context` field is set to the
Slack-specific system prompt described in the Channel Context section above.

The core sees a `ParsedMessage`; the `SlackChannelAdapter` downcasts to access
Slack-specific fields when sending replies.

### Thread-to-Conversation Mapping

The `SlackThreadStore` manages the mapping between Slack threads and Airut
conversation IDs:

```python
class SlackThreadStore:
    """File-backed thread-to-conversation mapping."""

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "slack_threads.json"
        self._lock = threading.Lock()
        self._data: dict[str, str] = {}  # "channel_id:thread_ts" -> conv_id
        self._load()

    def get_conversation_id(
        self, channel_id: str, thread_ts: str
    ) -> str | None:
        """Look up Airut conversation ID for a Slack thread."""

    def register(self, channel_id: str, thread_ts: str, conv_id: str) -> None:
        """Register a new thread-to-conversation mapping and persist."""

    def retain_only(self, active_conversation_ids: set[str]) -> int:
        """Remove entries whose conversation ID is not in the active set."""
```

The store uses a simple JSON file in the repo's state directory, matching the
email adapter's file-based persistence pattern. The file is small (one entry per
conversation) and loaded into memory at startup.

**Pruning.** The garbage collector calls
`ChannelAdapter.cleanup_conversations()` after each per-repo sweep, passing the
set of surviving conversation IDs. The Slack adapter delegates to
`SlackThreadStore.retain_only()`, which removes any thread mapping whose
conversation ID is not in the active set and persists the result. This keeps the
thread store in sync with the conversation directory without the store needing
to know about conversation lifecycle directly.

### Adapter Factory Integration

The `adapter_factory.py` dispatches on channel config type. With multi-channel
support, `create_adapters()` returns a dict of channel type to adapter:

```python
def create_adapters(config: RepoServerConfig) -> dict[str, ChannelAdapter]:
    from airut.gateway.config import EmailChannelConfig
    from airut.gateway.email.adapter import EmailChannelAdapter
    from airut.gateway.slack.adapter import SlackChannelAdapter
    from airut.gateway.slack.config import SlackChannelConfig

    adapters: dict[str, ChannelAdapter] = {}
    for channel_type, channel_config in config.channels.items():
        if isinstance(channel_config, EmailChannelConfig):
            adapters[channel_type] = EmailChannelAdapter.from_config(
                channel_config, repo_id=config.repo_id
            )
        elif isinstance(channel_config, SlackChannelConfig):
            adapters[channel_type] = SlackChannelAdapter.from_config(
                channel_config, repo_id=config.repo_id
            )
        else:
            raise ValueError(
                f"Unknown channel config type: {type(channel_config).__name__}"
            )
    return adapters
```

**No changes to `RepoHandler`** are needed for the Slack channel itself.
`RepoHandler` is fully channel-agnostic — it uses `adapter.listener.start()`,
`adapter.listener.stop()`, and `adapter.listener.status` through the protocol
interfaces. The multi-channel refactoring (iterating over multiple adapters) is
a separate concern handled in [multi-repo.md](multi-repo.md).

### Authorizer

The `SlackAuthorizer` evaluates authorization rules with cached Slack API data:

- **User info cache**: `users.info` results cached with 5-minute TTL.
  Thread-safe with locking. Stores `UserInfo` dataclass with `is_bot`,
  `is_restricted`, `is_ultra_restricted`, `team_id`, `deleted`, and
  `display_name` fields.
- **Group membership cache**: `usergroups.users.list` results cached with
  5-minute TTL per group. Group handle-to-ID resolution done once lazily via
  `usergroups.list`. Stale cache fallback: if group member fetch fails, returns
  stale cache rather than failing.
- **Baseline checks**: Always rejects bots, deactivated users, and external
  users (team_id mismatch) before evaluating rules.
- **Rule evaluation**: Iterates rules in order, first match wins.

### Dashboard Integration

Slack conversations appear in the dashboard identically to email conversations.
The existing `TaskState` already stores all needed fields:

- `conversation_id`: Set from the Airut conversation ID (same as email)
- `display_title`: Set from the user's first message (truncated — email uses the
  email subject)
- `sender`: Set to the Slack user ID (canonical identifier — email uses the
  sender email address)
- `repo_id`: Set from the repo config (same as email)
- `model`: Set from the repo config default (Slack has no model selection UX)

No dashboard code changes are needed. The dashboard is already channel-agnostic
— it works with `TaskState` and `ConversationMetadata`, neither of which
contains channel-specific fields. Slack conversations will appear in the same
task list, actions viewer, and conversation detail pages as email conversations.

With multi-channel ([multi-repo.md](multi-repo.md)), the dashboard's `RepoState`
gains per-channel health info via `ChannelInfo` objects. This is independent of
the Slack implementation itself.

### Bolt SDK Dependencies

New dependency: `slack-bolt>=1.20` (includes `slack-sdk`). Added as a core
dependency in `pyproject.toml`:

```toml
[project]
dependencies = [
    # ... existing deps ...
    "slack-bolt>=1.20",
]
```

Making `slack-bolt` a required dependency (rather than an optional extra)
simplifies the codebase: no conditional imports, no `sys.modules` patching in
tests, no `ty` exclusions, and no runtime import scanning exceptions. The
package adds ~2MB to the install, which is negligible compared to the existing
dependency tree. Deployments that don't use Slack simply don't configure a
`slack:` block — the dependency is present but dormant.

The Slack modules must be fully type-checked (no `ty` exclusions) and included
in coverage reporting. The earlier implementation attempt excluded
`airut/gateway/slack/` from type checking — this is not acceptable. All Slack
code follows the same quality standards as the rest of the codebase.

### Testing Strategy

Slack tests follow the same patterns as email tests. Since `slack-bolt` is a
core dependency, no special import handling is needed:

- **Unit tests**: Each module (`SlackChannelConfig`, `SlackAuthorizer`,
  `SlackThreadStore`, `SlackChannelAdapter`, `SlackChannelListener`) has
  dedicated test files with mocked Slack API calls (mock `WebClient`, mock
  `SocketModeHandler`).
- **Adapter integration**: Create `SlackChannelAdapter` directly with mock
  dependencies (mock authorizer, mock WebClient, real thread store), bypassing
  `from_config()` to control the test environment.
- **Listener tests**: Mock the Bolt `App` and `SocketModeHandler` to test event
  handler registration and submit callback wiring without needing a real Slack
  connection.

## Open Items

Work remaining after the initial Slack channel implementation:

- **Documentation under `doc/`**: Add Slack setup and configuration guide to
  `doc/` (parallel to the existing email/M365 documentation). Include app
  creation walkthrough, token configuration, and authorization rule examples.
- **Task progress via plan blocks**: Stream real-time TodoWrite progress to
  Slack threads using `chat.startStream` / `chat.appendStream` /
  `chat.stopStream`. The dashboard's SSE infrastructure already captures these
  events.
- **Suggested prompts**: Configurable prompts shown when opening the Chat tab
  (`set_suggested_prompts()` in the `thread_started` handler). Requires adding
  `slack.suggested_prompts` to config parsing.
- **Slack integration tests**: End-to-end tests with a mock Socket Mode server,
  parallel to the email integration tests.
- **Model selection**: Email uses subaddressing (`airut+opus@`); Slack currently
  uses the repo default model. Could add command prefix or prompt-based
  selection.
- **Channel @mentions**: Support `@mention` in channels for one-shot requests
  (requires `app_mention` event, `app_mentions:read` + `channels:history`
  scopes).
- **Response streaming**: Stream final response as it generates via the
  streaming API.
- **Multi-repo routing**: Single Slack app serving multiple repos with
  thread-level routing.
- **Canvas integration**: Use Slack Canvases for long-form output exceeding
  message size limits.
