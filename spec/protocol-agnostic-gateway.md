# Protocol-Agnostic Gateway

Refactor the gateway to separate email-specific protocol handling from the
generic message processing and orchestration core. This enables future messaging
channels (Slack, etc.) to plug in without modifying the core.

## Motivation

The gateway currently mixes email-specific logic (IMAP, SMTP, DMARC, MIME
parsing) with protocol-agnostic orchestration (conversation management, sandbox
execution, session resumption, dashboard tracking). Separating these concerns:

1. Makes email support easier to reason about and test in isolation
2. Establishes clear boundaries for adding new channels
3. Reduces the risk of breaking email when adding Slack later

## Design Principles

- **Move files, don't rewrite them.** The email logic is correct and
  well-tested. This refactoring reorganizes it into a subpackage and extracts a
  thin interface at the boundary. No email behavior changes.
- **Minimal abstraction.** One protocol interface (`ChannelAdapter`) with the
  methods the core actually calls today. No speculative methods for hypothetical
  future channels.
- **Channel-specific event loops.** Each channel owns its listener lifecycle
  (IMAP IDLE, WebSocket, HTTP webhook). The shared contract is: call
  `service.submit_parsed_message()` when you have something to process.
- **Config nesting, not flattening.** Email-specific config fields move under an
  `email:` key (already the case in the YAML file; the dataclass catches up).

## Directory Structure

### Before

```
airut/gateway/
├── __init__.py
├── config.py                      # Server + repo config
├── conversation.py                # ConversationManager
├── dotenv_loader.py
├── listener.py                    # EmailListener (IMAP)
├── microsoft_oauth2.py            # M365 OAuth2 token provider
├── parsing.py                     # Email MIME parsing
├── responder.py                   # EmailResponder (SMTP)
├── security.py                    # DMARC auth + sender authorization
└── service/
    ├── __init__.py
    ├── email_replies.py           # Email reply orchestration
    ├── gateway.py                 # EmailGatewayService
    ├── message_processing.py      # process_message() — mixed
    ├── repo_handler.py            # RepoHandler — mixed
    └── usage_stats.py
```

### After

```
airut/gateway/
├── __init__.py                    # Public API (re-exports)
├── config.py                      # Server + repo config (restructured)
├── conversation.py                # ConversationManager (unchanged)
├── channel.py                     # ChannelAdapter protocol + ParsedMessage
├── dotenv_loader.py               # (unchanged)
│
├── service/                       # Protocol-agnostic orchestration
│   ├── __init__.py
│   ├── gateway.py                 # GatewayService (renamed)
│   ├── repo_handler.py            # RepoHandler (refactored)
│   ├── message_processing.py      # process_message() — protocol-agnostic
│   └── usage_stats.py             # (unchanged)
│
└── email/                         # Email channel implementation
    ├── __init__.py
    ├── adapter.py                 # EmailChannelAdapter (implements ChannelAdapter)
    ├── listener.py                # EmailListener (moved from gateway/)
    ├── responder.py               # EmailResponder (moved from gateway/)
    ├── security.py                # SenderAuthenticator, SenderAuthorizer (moved)
    ├── parsing.py                 # MIME parsing, quote stripping (moved)
    ├── replies.py                 # send_reply, send_acknowledgment (moved)
    └── microsoft_oauth2.py        # OAuth2 token provider (moved)
```

### What Moves

| File (before)                      | File (after)                        | Changes      |
| ---------------------------------- | ----------------------------------- | ------------ |
| `gateway/listener.py`              | `gateway/email/listener.py`         | Import paths |
| `gateway/responder.py`             | `gateway/email/responder.py`        | Import paths |
| `gateway/security.py`              | `gateway/email/security.py`         | Import paths |
| `gateway/parsing.py`               | `gateway/email/parsing.py`          | Import paths |
| `gateway/microsoft_oauth2.py`      | `gateway/email/microsoft_oauth2.py` | Import paths |
| `gateway/service/email_replies.py` | `gateway/email/replies.py`          | Import paths |
| `gateway/conversation.py`          | (stays)                             | No changes   |
| `gateway/dotenv_loader.py`         | (stays)                             | No changes   |
| `gateway/service/usage_stats.py`   | (stays)                             | No changes   |

### What Gets Refactored

| File                                    | Change                                                    |
| --------------------------------------- | --------------------------------------------------------- |
| `gateway/config.py`                     | Extract `EmailChannelConfig` from `RepoServerConfig`      |
| `gateway/service/gateway.py`            | Rename `EmailGatewayService` → `GatewayService`           |
| `gateway/service/repo_handler.py`       | Use `ChannelAdapter` instead of direct email components   |
| `gateway/service/message_processing.py` | Accept `ParsedMessage` instead of `email.message.Message` |
| NEW `gateway/channel.py`                | `ChannelAdapter` protocol + `ParsedMessage` dataclass     |
| NEW `gateway/email/adapter.py`          | `EmailChannelAdapter` implementing `ChannelAdapter`       |

## Channel Adapter Protocol

### `ParsedMessage`

A protocol-agnostic representation of an incoming message, produced by the
channel adapter before the core processes it.

```python
@dataclass
class ParsedMessage:
    """Protocol-agnostic parsed message."""

    sender: str
    """Authenticated sender identifier (email address, Slack user ID, etc.)."""

    body: str
    """Extracted message body (quotes stripped, markup converted)."""

    conversation_id: str | None
    """Existing conversation ID if this is a reply, None for new conversations."""

    model_hint: str | None
    """Model override from the channel (email subaddressing, Slack command, etc.).
    Only used for new conversations; ignored on resume."""

    attachments: list[str]
    """Filenames of attachments saved to the inbox directory by the adapter.

    The adapter writes attachment files to the conversation's inbox directory
    during authenticate_and_parse(). These files persist across conversation
    turns as part of the conversation state (the inbox directory is mounted
    into the container at /inbox). No cleanup is needed — files accumulate
    naturally and are garbage-collected with the conversation."""

    channel_context: str
    """Channel-specific context instructions prepended to the prompt.
    E.g., 'User is interacting via email interface...'"""
```

**No `raw` field.** The core does not need the original protocol-specific
message. The adapter creates `ParsedMessage` and receives it back in
`send_reply()` / `send_acknowledgment()` / `send_error()`. Any protocol-specific
state needed for replies (email References header, Slack thread_ts, etc.) is the
adapter's responsibility to track internally — either on its own instance or in
a protocol-specific subclass of `ParsedMessage`.

For email, the `EmailChannelAdapter` creates an `EmailParsedMessage` (a
`ParsedMessage` subclass) that carries the additional fields needed for reply
threading (original Message-ID, References, decoded subject). The core treats it
as a plain `ParsedMessage`; the adapter downcasts when constructing replies.

### `ChannelAdapter`

The interface between the protocol-agnostic core and channel-specific
implementations. Uses `typing.Protocol` for structural subtyping — no base class
inheritance required.

```python
class ChannelAdapter(Protocol):
    """Interface for channel-specific message handling.

    Implementations handle authentication, parsing, and response delivery
    for a specific messaging protocol (email, Slack, etc.).
    """

    def authenticate_and_parse(self, raw_message: Any) -> ParsedMessage | None:
        """Authenticate the sender and parse the message.

        Returns a ParsedMessage if authentication and authorization succeed,
        or None if the message should be rejected (with appropriate logging).

        This combines authentication, authorization, and parsing into a single
        call because the details are deeply protocol-specific (DMARC headers,
        MIME structure, Slack request signatures, etc.) and there's no benefit
        to the core knowing about these intermediate steps.
        """
        ...

    def send_acknowledgment(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        model: str,
        dashboard_url: str | None,
    ) -> None:
        """Send a 'working on it' notification to the user."""
        ...

    def send_reply(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        response_text: str,
        usage_footer: str,
        outbox_files: list[Path],
    ) -> None:
        """Send the final response with optional file attachments."""
        ...

    def send_error(
        self,
        parsed: ParsedMessage,
        conversation_id: str | None,
        error_message: str,
    ) -> None:
        """Send an error notification to the user."""
        ...
```

### Why `authenticate_and_parse` Is One Method

The alternative — separate `authenticate()`, `authorize()`, and `parse()`
methods — would force the core to orchestrate protocol-specific steps it doesn't
need to understand. For email, authentication requires inspecting DMARC headers
in the raw MIME message; for Slack, it means verifying HMAC signatures on the
HTTP request body. The core only needs to know: "is this a valid message I
should process?" The channel answers that question.

The adapter still uses `SenderAuthenticator`, `SenderAuthorizer`, and the
parsing functions internally — this is about the interface the core sees, not
about removing those classes.

## Message Processing Flow

### Before (Email-Coupled)

```python
def process_message(
    service: EmailGatewayService,
    message: Message,  # email.message.Message
    task_id: str,
    repo_handler: RepoHandler,
) -> tuple[bool, str | None]:
    sender = message.get("From", "")
    subject = decode_subject(message)
    authenticated = repo_handler.authenticator.authenticate(message)
    authorized = repo_handler.authorizer.is_authorized(authenticated)
    body = extract_body(message)
    attachments = extract_attachments(message, inbox_dir)
    send_acknowledgment(...)
    # ... execute ...
    send_reply(...)
```

### After (Protocol-Agnostic)

```python
def process_message(
    service: GatewayService,
    parsed: ParsedMessage,  # Already authenticated + parsed
    task_id: str,
    repo_handler: RepoHandler,
) -> tuple[bool, str | None]:
    # Authentication and parsing already done by adapter
    adapter = repo_handler.channel_adapter
    adapter.send_acknowledgment(parsed, conversation_id, model, dashboard_url)
    # ... execute (unchanged: conversation manager, sandbox, mounts) ...
    adapter.send_reply(parsed, conversation_id, response_text, footer, files)
```

The core no longer imports anything from `airut.gateway.email`. It works
entirely through `ParsedMessage` and `ChannelAdapter`.

## Listener Architecture

Each channel owns its event loop. The shared contract is calling
`service.submit_parsed_message()` with a `ParsedMessage`.

### Email Listener (Existing Pattern, Preserved)

The `EmailListener` + IMAP IDLE/polling loop stays in `RepoHandler` as a
channel-specific concern. The listener thread calls
`adapter.authenticate_and_parse()` on each raw message and submits successful
results to the service executor.

```python
# In RepoHandler (simplified)
def _listener_loop(self) -> None:
    for raw_message in self._email_listener.fetch_unread():
        parsed = self._adapter.authenticate_and_parse(raw_message)
        if parsed is not None:
            self._submit_parsed_message(parsed)
```

### Future: Slack Listener

Slack would use Socket Mode (WebSocket) or Events API (HTTP webhook). The
listener pattern is different but the submission contract is the same:

```python
# Hypothetical SlackListener (for illustration only)
@app.event("message")
def handle_message(event, say):
    parsed = slack_adapter.authenticate_and_parse(event)
    if parsed is not None:
        service.submit_parsed_message(parsed)
```

## RepoHandler Changes

### Before

`RepoHandler` directly owns email components:

```python
class RepoHandler:
    listener: EmailListener
    responder: EmailResponder
    authenticator: SenderAuthenticator
    authorizer: SenderAuthorizer
    conversation_manager: ConversationManager
```

### After

`RepoHandler` owns a `ChannelAdapter` and a channel-specific listener:

```python
class RepoHandler:
    channel_adapter: ChannelAdapter
    conversation_manager: ConversationManager
    # Listener lifecycle is channel-specific;
    # for email, RepoHandler still manages the EmailListener thread.
```

The `EmailChannelAdapter` internally holds `EmailListener`, `EmailResponder`,
`SenderAuthenticator`, and `SenderAuthorizer`. These classes are unchanged —
only their owner changes.

## Channel Selection

`RepoHandler` determines which channel to instantiate based on the presence of
channel config blocks:

- If `email:` is present → create `EmailChannelAdapter`
- If no channel block is present → raise `ConfigError`

For now, exactly one channel must be configured per repo. When multi-channel
support is added later, the constraint relaxes to "at least one." If multiple
channel blocks are present before that support exists, the config parser raises
`ConfigError`:

```
repos.my-project: multiple channel configurations found (email, slack).
Only one channel per repo is currently supported.
```

This is checked at config parse time, not at runtime, so `airut check` catches
it.

## Config Changes

### `RepoServerConfig` Restructuring

Email-specific fields move into a nested `EmailChannelConfig`:

```python
@dataclass
class EmailChannelConfig:
    """Email channel configuration (IMAP + SMTP)."""

    imap_server: str
    imap_port: int
    smtp_server: str
    smtp_port: int
    username: str
    password: str
    from_address: str
    authorized_senders: list[str]
    trusted_authserv_id: str
    poll_interval_seconds: int = 60
    use_imap_idle: bool = True
    idle_reconnect_interval_seconds: int = 29 * 60
    smtp_require_auth: bool = True
    microsoft_internal_auth_fallback: bool = False
    microsoft_oauth2_tenant_id: str | None = None
    microsoft_oauth2_client_id: str | None = None
    microsoft_oauth2_client_secret: str | None = None


@dataclass
class RepoServerConfig:
    """Per-repo server-side configuration."""

    repo_id: str
    git_repo_url: str
    email: EmailChannelConfig  # Required (for now; Optional when Slack exists)
    secrets: dict[str, str] = field(default_factory=dict)
    masked_secrets: dict[str, MaskedSecret] = field(default_factory=dict)
    signing_credentials: dict[str, SigningCredential] = field(
        default_factory=dict
    )
    network_sandbox_enabled: bool = True
```

### Server Config YAML

The YAML structure is already nested under `email:` in the example config, so
most users won't need changes. Fields that are currently at the repo level but
are email-specific move under `email:`:

```yaml
repos:
  my-project:
    git:
      repo_url: https://github.com/you/my-project.git

    email:
      imap_server: mail.example.com
      imap_port: 993
      smtp_server: mail.example.com
      smtp_port: 587
      username: airut
      password: !env EMAIL_PASSWORD
      from: "Airut <airut@example.com>"

      # These move under email: (currently at repo level)
      authorized_senders:
        - you@example.com
      trusted_authserv_id: mail.example.com
      microsoft_internal_auth_fallback: false

      imap:
        poll_interval: 30
        use_idle: true
        idle_reconnect_interval: 1740

      microsoft_oauth2:
        tenant_id: !env AZURE_TENANT_ID
        client_id: !env AZURE_CLIENT_ID
        client_secret: !env AZURE_CLIENT_SECRET

    # Shared across all channels
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes: ["api.github.com"]
        headers: ["Authorization"]
```

Fields that move under `email:`:

- `authorized_senders` — email-specific (Slack would have its own user/channel
  allowlist)
- `trusted_authserv_id` — email-specific (DMARC concept)
- `microsoft_internal_auth_fallback` — email-specific (Exchange concept)
- `imap:` block — already logically under email

Fields that stay at repo level:

- `git:` — shared across all channels
- `secrets:`, `masked_secrets:`, `signing_credentials:` — shared across all
  channels
- `network:` — shared across all channels

### Legacy Config Detection

The config parser detects legacy field placement and **refuses to start**. This
is a hard error, not a deprecation warning. When email-specific fields appear at
the repo level instead of under `email:`, the parser raises a `ConfigError`:

```
repos.my-project: 'authorized_senders' must be nested under 'email:'.
Move it to repos.my-project.email.authorized_senders.
See config/airut.example.yaml for the current format.
```

**Hard failure is critical for `authorized_senders` and `trusted_authserv_id`.**
These are security controls. If the parser silently ignored a stale
`authorized_senders` at the repo level, the gateway could start with an empty
allowlist under `email:` — effectively open to the world. The parser must check
for these specific legacy keys and fail loudly:

```python
_LEGACY_EMAIL_FIELDS = {
    "authorized_senders",
    "trusted_authserv_id",
    "microsoft_internal_auth_fallback",
}

for key in _LEGACY_EMAIL_FIELDS:
    if key in raw:
        raise ConfigError(
            f"repos.{repo_id}: '{key}' must be nested under 'email:'. "
            f"Move it to repos.{repo_id}.email.{key}. "
            f"See config/airut.example.yaml for the current format."
        )
```

The `airut check` command already catches `ConfigError` and displays it, so
users running `airut check` after an upgrade will see clear migration
instructions. The gateway service itself also calls `ServerConfig.from_yaml()`
at startup and will fail to start with the same error.

## Renames

| Before                     | After              | Reason                    |
| -------------------------- | ------------------ | ------------------------- |
| `EmailGatewayService`      | `GatewayService`   | No longer email-specific  |
| `service/email_replies.py` | `email/replies.py` | Moved to email subpackage |

No other renames. `EmailListener`, `EmailResponder`, `SenderAuthenticator`,
`SenderAuthorizer` keep their names — they are email-specific and their names
correctly reflect that.

## Test Organization

Tests mirror the source layout:

```
tests/gateway/
├── email/                          # Email-specific tests (moved)
│   ├── test_listener.py
│   ├── test_responder.py
│   ├── test_security.py
│   ├── test_parsing.py
│   ├── test_microsoft_oauth2.py
│   └── test_replies.py            # Was test_email_replies.py
├── service/                        # Core service tests (updated)
│   ├── test_gateway.py
│   ├── test_message_processing.py
│   ├── test_repo_handler.py
│   └── test_usage_stats.py
├── test_config.py                  # Config tests (add migration tests)
├── test_conversation.py
└── test_integration.py
```

## Spec Updates

The following existing specs need updates to reflect the new structure:

- **`spec/gateway-architecture.md`** — Update component list, data flow diagram,
  and file references. The "Email Protocol" section stays but is identified as
  channel-specific. Add a "Channel Abstraction" section.
- **`spec/repo-config.md`** — Update server config schema to show nested
  `email:` structure.

## Implementation Order

1. **Create `gateway/email/` subpackage and move files.** Update all import
   paths. This is a pure move — no logic changes. All tests should pass with
   only import path updates.

2. **Introduce `ParsedMessage` and `ChannelAdapter` in `gateway/channel.py`.**
   No consumers yet; just the types.

3. **Create `EmailChannelAdapter`** in `gateway/email/adapter.py`. It wraps the
   existing `SenderAuthenticator`, `SenderAuthorizer`, parsing functions, and
   `EmailResponder` behind the `ChannelAdapter` interface.

4. **Refactor `process_message()`** to accept `ParsedMessage` instead of
   `email.message.Message`. Move email-specific extraction (DMARC, MIME parsing,
   subject decoding, model subaddressing, channel context string) into
   `EmailChannelAdapter.authenticate_and_parse()`.

5. **Refactor `RepoHandler`** to use `ChannelAdapter`. The IMAP listener thread
   calls `adapter.authenticate_and_parse()` and submits `ParsedMessage` to the
   service.

6. **Rename `EmailGatewayService` → `GatewayService`.**

7. **Restructure `RepoServerConfig`** to nest email fields under
   `EmailChannelConfig`. Add legacy field detection with migration errors.
   Update `config/airut.example.yaml`.

8. **Update specs** (`gateway-architecture.md`, `repo-config.md`).

Steps 1-3 can land as one commit. Steps 4-6 as a second. Step 7 as a third
(config is a separate concern with its own migration story). Step 8 alongside
the relevant code changes.

## What This Does NOT Include

- **Slack implementation.** This spec covers only the refactoring to make the
  gateway protocol-agnostic. Slack support is a separate follow-up.
- **Abstract base classes.** `ChannelAdapter` is a `typing.Protocol`, not an
  ABC. No inheritance hierarchy.
- **Generic listener interface.** Each channel owns its event loop. There's no
  `Listener` protocol because the listener patterns are too different (IMAP
  polling vs WebSocket vs HTTP webhook) to meaningfully abstract.
- **Multi-channel per repo.** A repo has one channel. Supporting both email and
  Slack for the same repo simultaneously is a future consideration, not part of
  this refactoring.
