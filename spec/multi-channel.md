# Multi-Channel Per Repository

A single repository can receive messages from multiple channels simultaneously
(e.g., email and Slack). Channels are sibling keys at the repo level in the
server config — no wrapper object, no schema migration for existing deployments.

## Goals

1. **Multiple channels per repo.** A repo can have both `email:` and `slack:`
   (and future channel types) active at the same time.
2. **No YAML schema change.** Channel blocks remain repo-level siblings
   (`repos.<id>.email`, `repos.<id>.slack`). Existing email-only configs work
   without modification.
3. **Independent channel lifecycles.** Each channel has its own listener thread,
   health tracking, and failure isolation. A Slack outage does not affect email
   processing.
4. **Shared conversations.** All channels for a repo share the same conversation
   store and git mirror. Conversation IDs are unique per repo regardless of
   originating channel.
5. **Channel-scoped conversations.** Each conversation belongs to the channel
   that created it. Cross-channel conversation resumption is not supported — a
   Slack message cannot resume an email conversation or vice versa. The
   originating adapter is used for all replies within a conversation.
6. **Minimal core changes.** The protocol-agnostic core (`GatewayService`,
   `process_message`) requires no structural changes. The adapter is already
   threaded through the entire message processing pipeline.

## Server Configuration

Channel blocks are sibling keys under each repo. At least one channel must be
present. Multiple channels of different types are allowed; multiple channels of
the same type are not (one `email:` block per repo, one `slack:` block per
repo).

```yaml
repos:
  my-repo:
    git:
      repo_url: https://github.com/user/repo.git

    email:
      imap_server: mail.example.com
      imap_port: 993
      smtp_server: mail.example.com
      smtp_port: 587
      username: bot@example.com
      password: !env EMAIL_PASSWORD
      from: "Bot <bot@example.com>"
      authorized_senders:
        - admin@example.com
      trusted_authserv_id: mail.example.com

    slack:
      app_token: !env SLACK_APP_TOKEN
      bot_token: !env SLACK_BOT_TOKEN
      authorized:
        - workspace_members: true

    secrets:
      GH_TOKEN: !env GH_TOKEN

    network:
      sandbox_enabled: true
```

An email-only repo looks identical to today:

```yaml
repos:
  email-only-repo:
    git:
      repo_url: https://github.com/user/repo.git
    email:
      imap_server: mail.example.com
      # ... same as current config
    secrets:
      GH_TOKEN: !env GH_TOKEN
```

### Known Repo-Level Keys

The parser distinguishes channel keys from non-channel keys using a registry:

| Key                   | Type        |
| --------------------- | ----------- |
| `git`                 | Non-channel |
| `secrets`             | Non-channel |
| `masked_secrets`      | Non-channel |
| `signing_credentials` | Non-channel |
| `network`             | Non-channel |
| `email`               | Channel     |
| `slack`               | Channel     |

Channel detection:

```python
CHANNEL_KEYS = {"email", "slack"}  # Extend as new channels are added

found_channels = CHANNEL_KEYS & raw.keys()
if not found_channels:
    raise ConfigError(f"{prefix}: no channel configured (add email: or slack:)")
```

### Validation Rules

- **At least one channel** per repo (replaces the current "email required"
  check).
- **No duplicate inboxes** across repos for email channels (existing check,
  unchanged).
- **No duplicate Slack workspaces** across repos for Slack channels (new,
  analogous to the IMAP inbox check).
- **Legacy email field detection** (`_LEGACY_EMAIL_FIELDS`) is unchanged — it
  catches `authorized_senders` etc. at the repo level regardless of whether
  `email:` is present.

## Data Model Changes

### `RepoServerConfig`

The `channel` field (singular `ChannelConfig`) becomes `channels` (mapping of
channel type to config):

```python
@dataclass(frozen=True)
class RepoServerConfig:
    repo_id: str
    git_repo_url: str
    channels: dict[str, ChannelConfig]  # was: channel: EmailChannelConfig
    secrets: dict[str, str] = field(default_factory=dict)
    masked_secrets: dict[str, MaskedSecret] = field(default_factory=dict)
    signing_credentials: dict[str, SigningCredential] = field(
        default_factory=dict
    )
    network_sandbox_enabled: bool = True
```

The convenience properties `channel_type` and `channel_info` are removed. Code
that needs them iterates `channels` directly.

### `RepoHandler`

The `adapter` field (singular `ChannelAdapter`) becomes `adapters` (mapping of
channel type to adapter):

```python
class RepoHandler:
    config: RepoServerConfig
    adapters: dict[str, ChannelAdapter]  # was: adapter: ChannelAdapter
    conversation_manager: ConversationManager
```

### `create_adapter` -> `create_adapters`

The existing `adapter_factory.py` factory function returns a dict instead of a
single adapter:

```python
def create_adapters(
    config: RepoServerConfig,
) -> dict[str, ChannelAdapter]:
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

## Listener Lifecycle

### Startup

`RepoHandler.start_listener()` starts all channel listeners. Each listener
receives a submit callback that captures the originating adapter:

```python
def start_listener(self) -> None:
    self.conversation_manager.mirror.update_mirror()
    for channel_type, adapter in self.adapters.items():
        adapter.listener.start(
            submit=lambda msg, a=adapter: self._submit_message(msg, a)
        )
```

### Shutdown

`RepoHandler.stop()` stops all listeners:

```python
def stop(self) -> None:
    for adapter in self.adapters.values():
        adapter.listener.stop()
```

### Threading Model

Each channel listener manages its own threads (email uses IMAP IDLE/poll, Slack
uses Socket Mode). All listeners for all repos share the same
`ThreadPoolExecutor` for message processing:

```
Main thread:                   startup -> spawn all listener threads -> wait
Thread "repo1-email-listener": IMAP poll/idle loop
Thread "repo1-slack-listener": Socket Mode event loop
Thread "repo2-email-listener": IMAP poll/idle loop
Worker threads (shared):       message processing + Claude execution
```

## Message Routing

### Submit Path

The submit callback carries the originating adapter so the correct adapter is
used throughout the message lifecycle (authentication, reply delivery):

```python
def _submit_message(
    self,
    message: RawMessage[Any],
    adapter: ChannelAdapter,
) -> bool:
    return self.service.submit_message(message, self, adapter)
```

`GatewayService.submit_message()` gains an `adapter` parameter:

```python
def submit_message(
    self,
    raw_message: RawMessage[Any],
    repo_handler: RepoHandler,
    adapter: ChannelAdapter,
) -> bool:
    # ... existing task tracking ...
    future = self._executor_pool.submit(
        self._process_message_worker,
        raw_message,
        task_id,
        repo_handler,
        adapter,
    )
```

### Worker Thread

`_process_message_worker` receives the adapter as a parameter instead of
resolving it from `repo_handler.adapter`:

```python
def _process_message_worker(
    self,
    raw_message: RawMessage[Any],
    task_id: str,
    repo_handler: RepoHandler,
    adapter: ChannelAdapter,  # was: adapter = repo_handler.adapter
) -> None: ...
```

The rest of the worker is unchanged — `adapter` is already passed to
`_execute_and_complete()` and `process_message()` as a separate parameter.

### PendingMessage

`PendingMessage` already stores the adapter reference:

```python
@dataclass
class PendingMessage:
    parsed: ParsedMessage
    task_id: str
    repo_handler: RepoHandler
    adapter: ChannelAdapter  # already present
```

No change needed.

## Conversation Scoping

### Per-Repo, Channel-Independent IDs

Conversation IDs are 8-character random hex strings, generated per repo.
Multiple channels for the same repo share the same conversation ID namespace and
storage directory:

```
~/.local/state/airut/{repo_id}/
+-- git-mirror/
+-- conversations/
    +-- abc12345/      # created via email
    |   +-- conversation.json
    |   +-- workspace/
    |   +-- ...
    +-- def67890/      # created via Slack
        +-- ...
```

### No Cross-Channel Resume

A conversation created via email can only be resumed via email. A Slack message
with a conversation ID that was created by email is treated as a new
conversation (the Slack adapter won't recognize email-originated conversation
IDs because they use different identification mechanisms — email threading
headers vs. Slack thread timestamps).

This is a natural consequence of how each channel identifies conversations:

- **Email**: Conversation ID is embedded in the email subject line and matched
  via In-Reply-To/References headers.
- **Slack**: Conversation ID is mapped from Slack thread timestamps via a thread
  store.

There is no mechanism for one channel to reference the other's conversation
identifiers, and adding one would create confusing UX (how would a Slack user
know to type an email conversation ID?).

## Dashboard Changes

### `RepoState`

The `channel_info` field (single string) becomes a list of per-channel info:

```python
@dataclass(frozen=True)
class ChannelInfo:
    channel_type: str  # "email", "slack"
    info: str  # "mail.example.com", "Slack (Socket Mode)"
    health: ChannelHealth


@dataclass(frozen=True)
class RepoState:
    repo_id: str
    status: RepoStatus
    channels: list[ChannelInfo]  # was: channel_info: str
    # ... remaining fields unchanged
```

### Dashboard UI

- Repo detail page shows per-channel health indicators.
- Task cards can optionally show which channel originated the task (via
  `channel_type` on `TaskState`, if added).

### SSE Events

The `/api/events` SSE stream includes the channel list in repo state updates:

```json
{
  "repo_id": "my-repo",
  "status": "live",
  "channels": [
    {"type": "email", "info": "mail.example.com", "health": "connected"},
    {"type": "slack", "info": "Slack (Socket Mode)", "health": "connected"}
  ]
}
```

## Config Parsing Changes

### `_parse_repo_server_config`

The parser detects which channel keys are present and parses each one:

```
def _parse_repo_server_config(repo_id, raw):
    prefix = f"repos.{repo_id}"

    # Legacy field detection (unchanged)
    legacy_found = sorted(_LEGACY_EMAIL_FIELDS & raw.keys())
    if legacy_found:
        raise ConfigError(...)

    # Detect channel blocks
    found_channels = CHANNEL_KEYS & raw.keys()
    if not found_channels:
        raise ConfigError(...)

    # Parse each channel
    channels = {}
    if "email" in raw:
        channels["email"] = _parse_email_channel_config(raw["email"], prefix)
    if "slack" in raw:
        channels["slack"] = _parse_slack_channel_config(raw["slack"], prefix)

    return RepoServerConfig(
        repo_id=repo_id,
        git_repo_url=...,
        channels=channels,
        ...
    )
```

### Cross-Repo Validation

`ServerConfig.__post_init__` validates per-channel-type constraints across
repos:

```
# No duplicate IMAP inboxes (existing, adapted for multi-channel)
seen_inboxes: dict[tuple[str, str], str] = {}
for repo_id, repo in self.repos.items():
    email_config = repo.channels.get("email")
    if email_config is None or not isinstance(email_config, EmailChannelConfig):
        continue
    inbox_key = (
        email_config.imap_server.lower(),
        email_config.username.lower(),
    )
    if inbox_key in seen_inboxes:
        raise ConfigError(...)
    seen_inboxes[inbox_key] = repo_id
```

## Implementation Order

The multi-channel support is implemented in two phases. Phase 1 is a pure
refactoring — it changes the internal data model from single-channel to
multi-channel without adding any new channel implementations. Phase 2 adds Slack
(or any other channel) as a separate feature on top.

### Phase 1: Refactor to Multi-Channel Data Model

These changes are purely structural. The gateway supports exactly one channel
type (email) but the internals model it as "a list of channels that happens to
have one entry."

01. **`RepoServerConfig.channel` -> `channels: dict[str, ChannelConfig]`** —
    Change the field type. Update `__post_init__`, remove `channel_type` and
    `channel_info` convenience properties.

02. **`_parse_repo_server_config`** — Detect channel keys dynamically instead of
    hardcoding `email:` as mandatory. Parse each found channel block into its
    config type.

03. **`create_adapter` -> `create_adapters`** in `adapter_factory.py` — Return
    `dict[str, ChannelAdapter]`. For now, only email is recognized.

04. **`RepoHandler.adapter` -> `adapters: dict[str, ChannelAdapter]`** — Update
    `start_listener()` to loop over all adapters with per-adapter submit
    callbacks. Update `stop()` to stop all adapters.

05. **`_submit_message` and `submit_message`** — Add `adapter` parameter to
    carry the originating adapter through the submit path.

06. **`_process_message_worker`** — Accept `adapter` as parameter instead of
    reading `repo_handler.adapter`.

07. **Dashboard `RepoState`** — Change `channel_info: str` to
    `channels: list[ChannelInfo]`. Update SSE events, handlers, and views.

08. **`ServerConfig.__post_init__`** — Update duplicate inbox validation to
    iterate `repo.channels.get("email")` instead of `repo.channel`.

09. **Update `repo-config.md`** — Reflect the multi-channel model in existing
    specs.

10. **Tests** — Update all tests that reference `config.channel`,
    `repo_handler.adapter`, or construct `RepoServerConfig` with a single
    channel. Add tests for repos with multiple channel configs.

### Phase 2: Add Slack Channel (Separate Feature)

Depends on the Slack channel spec ([slack-channel.md](slack-channel.md)). Adds
`SlackChannelConfig`, `SlackChannelAdapter`, `SlackChannelListener`, and
`SlackThreadStore` alongside the existing email channel. Core functionality only
— async message handling, authorization, thread mapping, file handling.

### Phase 3: Post-Initial Slack Features

After the core Slack channel is working end-to-end:

1. **Task progress via plan blocks** — Stream TodoWrite progress to Slack
   threads using `chat.startStream` / `appendStream` / `stopStream` with
   `TaskUpdateChunk` and `PlanUpdateChunk`. See the "Post-Initial Features"
   section in [slack-channel.md](slack-channel.md).
2. **Suggested prompts** — Configurable prompts shown when users open the Chat
   tab.

## Backwards Compatibility

**YAML config:** Fully backwards compatible. Existing configs with a single
`email:` block work without modification. The parser detects `email:` as a
channel key and creates a single-entry `channels` dict.

**Python API:** This is a breaking change to internal APIs.
`RepoServerConfig.channel` becomes `channels`, `RepoHandler.adapter` becomes
`adapters`. Per the project's "no legacy shims" rule, all references are updated
in one pass with no backwards-compatibility wrappers.
