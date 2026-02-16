# Gateway

Protocol-agnostic gateway for interacting with codebases via Claude Code.
Enables authorized users to send instructions via messaging channels (email,
etc.) and receive Claude's responses with full conversation state management.

## Overview

A persistent Python daemon that monitors messaging channels, spins up ephemeral
Claude Code sessions in containers, and replies with results. Each conversation
maps to an isolated git checkout with persistent `.claude/` session state.

**Key principle**: Messaging channels as stateful interfaces to Claude Code,
with git-based conversation isolation and container-based execution for
security.

## Architecture

### Channel Abstraction

The gateway separates protocol-agnostic orchestration (conversation management,
sandbox execution, session resumption, dashboard tracking) from channel-specific
protocol handling (email IMAP/SMTP, etc.) via two core types in
`gateway/channel.py`:

- **`ParsedMessage`** — Protocol-agnostic dataclass produced by the channel
  adapter after authentication and parsing. Contains sender, body,
  conversation_id, model_hint, attachments, and channel_context.
- **`ChannelAdapter`** — `typing.Protocol` defining the interface between the
  core and channel implementations: `authenticate_and_parse()`,
  `save_attachments()`, `send_acknowledgment()`, `send_reply()`, `send_error()`,
  `send_rejection()`.

Each channel implements `ChannelAdapter` (e.g., `EmailChannelAdapter` in
`gateway/email/adapter.py`). The core works entirely through `ParsedMessage` and
`ChannelAdapter` — it imports nothing from channel-specific subpackages.

### Components

**Protocol-agnostic core** (`gateway/service/`):

- **GatewayService** — Orchestration, thread pool, lifecycle management
- **RepoHandler** — Per-repo state: channel adapter, conversation manager
- **ConversationManager** — Git checkout management and state persistence
- **Sandbox** — Container lifecycle, network isolation, and execution
  (`airut/sandbox/`)

**Email channel** (`gateway/email/`):

- **EmailChannelAdapter** — Implements `ChannelAdapter` for email. Owns all
  email sub-components (listener, responder, authenticator, authorizer) via
  `from_config()` factory. `RepoHandler` accesses email functionality only
  through the adapter.
- **EmailListener** — IMAP polling loop
- **EmailResponder** — SMTP reply construction with threading support
- **SenderAuthenticator** — DMARC verification on trusted headers
- **SenderAuthorizer** — Sender allowlist checking

### Data Flow

```
Channel (e.g., IMAP Server)
  -> Listener (e.g., EmailListener poll/IDLE)
    -> RepoHandler._submit_message(raw_message)
      -> GatewayService.submit_message(raw_message, handler)
        -> Register temp task in tracker
        -> Submit to worker thread pool
    -> GatewayService._process_message_worker()  [worker thread]
      -> ChannelAdapter.authenticate_and_parse()
        -> (email: DMARC + sender auth + MIME parsing)
      -> Duplicate detection (reject if conversation already active)
      -> ConversationManager
        -> Initialize/resume git checkout
        -> ChannelAdapter.save_attachments()
      -> Sandbox (Task)
        -> Spawn Podman container
        -> Mount conversation directories
        -> Run claude CLI
      -> ChannelAdapter.send_reply()
        -> (email: SMTP with threading headers)
```

## Conversation State Management

### Directory Structure

Each conversation is an isolated session with git workspace and metadata.
Storage uses XDG state directory: `~/.local/state/airut/<repo_id>/`.

```
{STATE_DIR}/
├── git-mirror/                  # Local git mirror for fast clones
│   └── (bare git repository)
├── conversations/                    # All conversations
│   ├── abc12345/                # Conversation ID (8-char hex)
│   │   ├── conversation.json    # Conversation metadata (NOT mounted to container)
│   │   ├── events.jsonl         # Streaming event log (NOT mounted to container)
│   │   ├── workspace/           # Git workspace (mounted at /workspace)
│   │   │   ├── .git/            # Git repository
│   │   │   └── ...              # Full project structure
│   │   ├── claude/              # Claude Code session state (mounted at /root/.claude)
│   │   ├── inbox/               # Channel attachments (mounted at /inbox)
│   │   ├── outbox/              # Files to attach to reply (mounted at /outbox)
│   │   └── storage/             # Conversation-scoped persistent data (mounted at /storage)
│   └── def67890/                # Another session
│       ├── conversation.json
│       ├── events.jsonl
│       └── workspace/
```

**Key Points:**

- `conversation.json` stores conversation metadata (session IDs, reply
  summaries, model) **outside the workspace**. Owned by `ConversationStore`
  (`airut/conversation/`), written at state transitions only (not during
  streaming).
- `events.jsonl` stores raw streaming JSON events as an append-only
  newline-delimited log **outside the workspace**. Owned by `EventLog`
  (`airut/sandbox/`), written during streaming. Reply groups are separated by
  blank lines.
- Session directories (claude, inbox, outbox, storage) are mounted separately
  from the workspace to keep the git repo clean
- `git-mirror/` enables fast clones by avoiding network transfer
  - Clones do NOT use `--reference` or `--shared` flags
  - These flags create `.git/objects/info/alternates` file pointing to mirror
  - When workspace is mounted in container, git cannot access paths outside the
    mount point
  - This causes "unable to find alternate object database" errors
  - Instead, we perform regular clones that copy all objects into workspace
  - All git objects are self-contained within the workspace directory
  - **Container constraint**: The workspace must be fully self-contained with no
    references to host filesystem paths outside the workspace

### Lifecycle

| Event                    | Action                                                                                                             |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| **New conversation**     | Generate 8-char ID, create `conversations/{id}/`, clone from mirror to `workspace/`                                |
| **Resume conversation**  | Verify workspace exists, load session from `conversation.json`, preserve local state                               |
| **User requests sync**   | Claude runs `git fetch origin && git rebase origin/main` manually in workspace                                     |
| **Conversation timeout** | Garbage collect conversations with no activity for 7 days (configurable via `execution.conversation_max_age_days`) |

**Critical**: Conversations do NOT auto-sync with master to preserve Claude's
work in progress. User must explicitly instruct Claude to update.

## Email Protocol

### Model Selection

Users can select which Claude model to use via email subaddressing (plus
addressing):

- **Format**: `username+model@domain` (e.g., `airut+opus@example.com`,
  `airut+haiku@example.com`)
- **New conversation**: Model extracted from To address and stored in session
- **Resumed conversation**: Stored model is used; any model in To address is
  ignored
- **No model specified**: Uses `default_model` from repo config (defaults to
  "opus")

**Supported models**: `opus`, `sonnet`, `haiku` (or any valid Claude Code model
name)

**Implementation**: Model is passed to Claude Code via `--model` CLI parameter,
not embedded in settings.json.

**Acknowledgment**: The auto-reply includes the model being used: "Your request
has been received and is now being processed by opus."

### Conversation Identification

Conversations are identified using a two-layer approach:

1. **Primary — Threading headers**: Outbound emails include a structured
   `Message-ID` of the form `<airut.{conv_id}.{timestamp}@{domain}>`. When a
   reply arrives, the `In-Reply-To` and `References` headers are scanned for
   Airut Message-IDs to extract the conversation ID. This is standards-compliant
   (RFC 5322), invisible to users, and preserved by all compliant MTAs.

2. **Fallback — Subject tag**: The `[ID:xyz123]` tag in the subject line is
   still included on all outbound emails and checked when no Airut Message-ID is
   found in headers. This covers edge cases like forwarded messages where the
   `References` chain may break.

**Resolution order** for inbound messages:

- Check `In-Reply-To` header for `<airut.{conv_id}.*>` pattern
- Check `References` header (newest first) for same pattern
- Fall back to `[ID:xyz123]` in subject
- None found → new conversation

### Message Parsing

**Body extraction** from MIME messages:

- Prefer `text/html` parts in multipart messages for reliable quote handling
- Fall back to `text/plain` when no HTML part is available
- Decode using the charset declared in the MIME part headers (e.g. `big5`,
  `iso-8859-1`), falling back to UTF-8 when no charset is declared
- HTML is converted to plain text with markdown-like formatting (bold, italic,
  links, tables, lists, headings, code blocks) via `airut/html_to_text`
- Non-multipart messages use the content type to decide: `text/html` is
  converted, everything else is used as-is

**Quote stripping** uses client-specific HTML structural markers (more reliable
than text-based heuristics) to identify quoted content. Two strategies:

*Container elements* — content inside the element is quoted:

- Outlook web/mobile: `<div id="mail-editor-reference-message-container">`
- Gmail: `<div class="gmail_quote">`
- Yahoo: `<div class="yahoo_quoted">`
- Thunderbird/Apple Mail: `<blockquote type="cite">`
- Thunderbird: `<div class="moz-cite-prefix">`

*Boundary elements* — everything from this element to end of body is quoted:

- Outlook desktop: `<div id="divRplyFwdMsg">` (the `From:/Sent:/To:/Subject:`
  header is inside this div, but the quoted body is in sibling elements)

Quote blocks followed by non-quote content (inline replies) are rendered as
markdown blockquotes (`> ` prefixed lines) so the LLM sees the context the user
replied to. Trailing quote blocks with no reply after them are replaced with
`[quoted text removed]`.

**Attachment handling**:

- Decode all attachments from MIME multipart
- Save to `{REPO_DIR}/inbox/` preserving original filenames
- Prepend to prompt:
  `"I have placed new files in the inbox/ folder: {filenames}. {user_prompt}"`

### Response Construction

**Headers** for threading:

- `Message-ID: <airut.{conv_id}.{timestamp}@{domain}>` (structured for
  header-based conversation resolution on future replies)
- `In-Reply-To: {original_message_id}`
- `References: {original_references}, {original_message_id}`
- `Subject: Re: [ID:xyz123] {original_subject}`

**Usage statistics footer**: Successful response emails include a footer with
execution statistics when available:

- Cost: API cost in USD (e.g., `Cost: $0.0123`)
- Web searches: Number of web search tool invocations
- Web fetches: Number of web fetch tool invocations

Example footer: `Cost: $0.0423 | Web searches: 2 | Web fetches: 1`

**Dashboard link**: When `DASHBOARD_BASE_URL` is configured, acknowledgment
emails (sent when a task is queued) include a link to track progress:
`{DASHBOARD_BASE_URL}/conversation/{conversation_id}`

## Container Execution

### Volume Mount Strategy

All conversations are fully isolated with per-conversation configuration (see
also [doc/execution-sandbox.md](../doc/execution-sandbox.md) for the security
perspective):

| Mount                                               | Purpose                             | Mode       |
| --------------------------------------------------- | ----------------------------------- | ---------- |
| `{STORAGE}/conversations/{ID}/workspace:/workspace` | Conversation workspace              | Read-write |
| `{STORAGE}/conversations/{ID}/claude:/root/.claude` | Per-conversation session state      | Read-write |
| `{STORAGE}/conversations/{ID}/inbox:/inbox`         | Channel attachments                 | Read-write |
| `{STORAGE}/conversations/{ID}/outbox:/outbox`       | Files to attach to reply            | Read-write |
| `{STORAGE}/conversations/{ID}/storage:/storage`     | Conversation-scoped persistent data | Read-write |

**Complete isolation:** Each conversation has its own workspace and session
state. No host directories (SSH keys, gitconfig, gh config) are mounted. All
session-specific directories (claude state, inbox, outbox, storage) live outside
the git workspace to keep it clean. The container filesystem is ephemeral —
everything outside the mounted directories is destroyed after each task
execution.

**Claude Code settings:** The `.claude/settings.json` file is version-controlled
in the repository and mounted as part of the workspace. It contains static
settings like attribution preferences.

**Git authentication:** The container image includes a static `.gitconfig` that
uses `gh auth git-credential` as the credential helper, which authenticates via
`GH_TOKEN` environment variable. This eliminates the need for SSH keys or host
git configuration.

**Git identity:** The container uses static values (`Airut` / `airut@airut.org`)
for git user name and email, configured in the Dockerfile.

### Container Environment Variables

The executor passes environment variables defined in the `container_env:`
section of `.airut/airut.yaml` (repo config) to the container. Values can be
inline strings or `!secret` references resolved from the server's secrets pool.
Only entries with non-empty resolved values are passed.

See [repo-config.md](repo-config.md) for the full schema and examples.

**Note:** `conversation.json` and `events.jsonl` are stored in
`{STORAGE}/conversations/{ID}/` and are **NOT** mounted to the container,
ensuring session metadata and event logs cannot be modified by Claude.

### Security Isolation

- **Complete conversation isolation**: Each conversation has its own workspace,
  claude session state, inbox, outbox, and storage with no shared state
- **No host mounts**: No SSH keys, host gitconfig, or credential files mounted
  from host
- **Environment-only authentication**: All credentials (Claude API, GitHub
  token, R2, etc.) passed via environment variables
- **Read-write workspace**: Container can only modify conversation-specific
  directories
- **Network allowlist**: Containers on internal network with transparent
  DNS-spoofing proxy (see [network-sandbox](../doc/network-sandbox.md))
- **Resource limits**: Timeout configurable per-repo (default 300 seconds)

### Image Build Strategy

Container images use a two-layer build (repo base + server overlay) with
content-addressed caching and 24-hour staleness rebuilds. See
[image.md](image.md) for full details.

Images are built at task start (not service startup), so Dockerfile changes take
effect after merging to main without a server restart.

### Session Resumption

The service stores conversation metadata in `conversation.json` within each
conversation directory (`{STORAGE}/conversations/{ID}/conversation.json`),
outside the container workspace. This file contains the conversation_id, model,
and an ordered list of reply summaries (each with session_id, timestamp,
duration_ms, total_cost_usd, num_turns, is_error, usage, request_text,
response_text). It is managed by `ConversationStore` (`airut/conversation/`) and
written only at state transitions.

**Resumption flow**:

1. Before execution, load session metadata from `conversation.json`
2. If a previous session_id exists, pass `--resume {session_id}` to Claude
3. After execution, record the new reply summary for future resumption
4. Claude maintains conversation context across messages

**Unresumable session recovery**: When a resumed session fails due to an
unresumable error, the service automatically retries with a fresh session. The
recovery prompt includes the agent's last successful response for continuity and
instructs the agent to check the workspace for ongoing work and be transparent
about the context loss. Two classes of errors trigger this recovery:

- **Prompt too long** — context compaction boundary exceeded ("Prompt is too
  long" in stdout)
- **Session corrupted** — API 4xx client errors (e.g., `invalid_request_error`
  from mismatched `tool_use_id`/`tool_result` pairs) indicating the session
  state is invalid and cannot be resumed

See `airut/conversation/conversation_store.py` for the `ConversationStore` and
`ConversationMetadata` data model.

### Actions History

The service captures Claude's full actions history using streaming JSON output
(`--output-format stream-json --verbose`). Events are stored in `events.jsonl`
as an append-only newline-delimited JSON stream, managed by `EventLog`
(`airut/sandbox/event_log.py`). Each event is written as a single line during
streaming, and reply groups are separated by blank lines. Events are displayed
in the dashboard's actions viewer (`/conversation/{id}/actions`).

## Configuration

Configuration is split into two layers:

- **Server config** (`~/.config/airut/airut.yaml`) — deployment infrastructure,
  mail credentials, operator controls, and a `secrets` pool. Values use `!env`
  tags to resolve from environment variables. A `.env` file is automatically
  loaded from `~/.config/airut/.env` (and from the working directory, if
  present) before resolving tags.
- **Repo config** (`.airut/airut.yaml`) — repo-specific behavior: model,
  timeout, network allowlist, and container environment variables. Loaded from
  the git mirror at the start of each task. Uses `!secret` tags to reference the
  server's secrets pool; `!env` tags are rejected.

See [repo-config.md](repo-config.md) for the full repo config schema, YAML tag
semantics, and loading flow.

## Security Model

### Authentication and Authorization

Two logically separate layers, both required. See
[authentication.md](authentication.md) for detailed design.

1. **Authentication** (`SenderAuthenticator`): Verifies sender identity via
   DMARC on trusted `Authentication-Results` headers.
2. **Authorization** (`SenderAuthorizer`): Checks authenticated sender against
   the allowed sender list.

**Rationale**: Separating authentication from authorization allows extending
either layer independently (e.g., adding domain-based rules to authorization
without touching DMARC logic).

### Credential Management

- **Claude credentials**: `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`
  configured in `container_env:` (use `!env` tags for secrets)
- **Email credentials**: Either password auth or Microsoft OAuth2 (XOAUTH2):
  - **Password auth**: `password: !env EMAIL_PASSWORD` in server config
  - **Microsoft OAuth2**: `email.microsoft_oauth2:` block with `tenant_id`,
    `client_id`, and `client_secret` (all supporting `!env` tags). Uses MSAL
    Client Credentials flow with XOAUTH2 SASL mechanism for both IMAP and SMTP.
    When OAuth2 is configured, the `password` field is optional.
- **Git credentials**: `GH_TOKEN` in `container_env:` with
  `gh auth git-credential` helper (no SSH keys mounted)
- **AI service credentials**: Configured in `container_env:` (e.g.,
  `GEMINI_API_KEY: !env GEMINI_API_KEY`)

No host credential files are mounted — all authentication uses environment
variables passed via the config file. See `config/airut.example.yaml` for the
full list.

### Attack Surface

| Risk                  | Mitigation                                                                         |
| --------------------- | ---------------------------------------------------------------------------------- |
| Unauthorized access   | Sender whitelist + mandatory DMARC/SPF verification                                |
| Email spoofing        | Always-on DMARC checks (no disable option)                                         |
| Command injection     | Claude Code runs in isolated container                                             |
| Data exfiltration     | Network allowlist via mitmproxy (see [network-sandbox](../doc/network-sandbox.md)) |
| Resource exhaustion   | Execution timeout + conversation GC                                                |
| Malicious attachments | Saved to `inbox/`, Claude decides how to handle                                    |

## Error Handling

### Git Failures

- **Clone fails**: Reply "System Error: Could not initialize workspace"
- **Repo corruption**: Auto-delete conversation directory, retry clone

### Container Failures

- **Podman crash**: Reply with stderr logs
- **Timeout**: Kill container, reply "Execution timed out after 300 seconds"
- **Build failure**: Reply "System Error: Container image unavailable"

### Email Failures

- **IMAP disconnect**: Retry with exponential backoff (10s, 30s, 60s, 300s)
- **SMTP send failure**: Log error, retry once, then mark conversation as failed
- **Parse error**: Reply "Could not parse your message. Please resend."

### Conversation Limit

**Hard limit**: 100 active conversations. When limit reached, garbage collect
oldest inactive conversations.

## Design Rationale

### Why Git Clones Instead of Shared Repo?

- **Isolation**: Each conversation can modify files without conflicts
- **State preservation**: Claude's changes persist across messages
- **Rollback**: Can delete corrupted conversation without affecting others
- **Audit trail**: Each conversation has independent git history

### Why Ephemeral Containers?

The container filesystem (outside mounted directories) is rebuilt from the
repository's default branch at every task start. This enables a self-service
workflow: the agent can propose changes to its own environment (Dockerfile,
network allowlist, repo config) via a PR, and once the user merges it, the next
task automatically runs with those changes. Persistent mounts (`/workspace`,
`/storage`, etc.) preserve conversation state across this rebuild cycle.

### Why Podman Instead of Direct Execution?

- **Security**: Isolates Claude Code with `--dangerously-skip-permissions`
- **Resource limits**: Container timeout prevents runaway processes
- **Consistency**: Same environment as interactive usage
- **Credential isolation**: Each conversation has separate Claude session

### Why Email Instead of Web UI?

- **Asynchronous**: User doesn't need to wait for Claude's response
- **Accessible**: Works from any email client (phone, desktop, web)
- **Stateful**: Email threading provides natural conversation history
- **Simple**: No custom client needed, no authentication UI

### Why Quote Stripping?

- **Token efficiency**: Prevent exponential growth of quoted history
- **Focus**: Claude sees new instructions prominently, with quoted context only
  when the user replied inline to specific points
- **Context preservation**: Email headers maintain threading for user

## Parallel Execution

The service supports processing multiple conversations concurrently using a
thread pool.

### Thread Pool Architecture

- **Worker pool**: `ThreadPoolExecutor` with configurable size
  (`MAX_CONCURRENT_EXECUTIONS`, default: 3)
- **Message flow**: IMAP polling runs in main thread; messages are submitted to
  the worker pool for parallel execution
- **Graceful shutdown**: Waits for pending executions with configurable timeout
  (`SHUTDOWN_TIMEOUT_SECONDS`, default: 60)

### Concurrency Safety

| Component           | Strategy                                                                |
| ------------------- | ----------------------------------------------------------------------- |
| IMAP operations     | Main thread only (IMAP not thread-safe)                                 |
| Container execution | Per-conversation locks prevent parallel processing of same conversation |
| Image builds        | Serialized via `_build_lock`; cached by content hash with staleness     |

### Per-Conversation Locking

Messages to the same conversation are serialized to prevent race conditions:

1. Extract conversation ID from subject
2. If existing conversation: acquire per-conversation lock before processing
3. If new conversation: no lock needed (unique ID generated)

This allows parallel processing of different conversations while ensuring
sequential processing within each conversation.

## Future Enhancements

None currently planned. Previous items (rich HTML email, task stop/cancel) have
been implemented.

## Not In Scope

- **Web UI for task submission**: Channel-based interfaces only (email, etc.)
- **Real-time chat**: Channels are asynchronous
- **Collaboration**: Single authorized sender per deployment
- **Conversation export**: Use git log for audit trail
