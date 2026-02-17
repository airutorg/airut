# Architecture

Airut is a protocol-agnostic gateway for headless Claude Code interaction. It
currently supports email as a channel — send instructions, receive results,
reply to continue the conversation. The architecture separates channel-specific
protocol handling from the core orchestration to support future channels.

## Concepts

Airut organizes work around three concepts:

- **Conversation** — a message thread from a channel. One thread = one
  conversation, identified by an 8-character hex ID. A conversation owns a git
  workspace, persistent Claude session state, and a sandboxed execution
  environment. Tasks within a conversation execute serially — only one task runs
  at a time. Parallelism occurs across different conversations, not within one.
- **Task** — an individual execution within a conversation. Each inbound message
  triggers one task. A conversation contains one or more tasks, executed one at
  a time in the order received.
- **Session** — Claude Code's persistent context, identified by a `session_id`
  stored in `conversation.json`. Used with `--resume` to continue Claude's
  context across tasks within a conversation.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Conversation                                 │
│                                                                     │
│   ┌─────────────────┐    ┌─────────────────┐    ┌───────────────┐   │
│   │  Git Checkout   │ +  │  Claude Code    │ +  │   Sandbox     │   │
│   │  (workspace)    │    │  Session        │    │   (network,   │   │
│   │                 │    │  (context)      │    │   container)  │   │
│   └─────────────────┘    └─────────────────┘    └───────────────┘   │
│                                                                     │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐                             │
│   │ Task 1  │→ │ Task 2  │→ │ Task 3  │→ ...  (serial execution)    │
│   └─────────┘  └─────────┘  └─────────┘                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

Reply to continue the conversation. The agent picks up where it left off with
full context of previous work.

## Technical Architecture

This section describes how the implementation realizes the concepts above.

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           GatewayService                                │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    RepoHandler (per repository)                  │   │
│  │                                                                  │   │
│  │  Listener ──▶ ChannelAdapter.authenticate_and_parse()            │   │
│  │       │                                         │                │   │
│  │       │       ConversationManager ◀─────────────┘                │   │
│  │       │                  │                                       │   │
│  │       │       Sandbox (airut/sandbox/) ◀─────────────────┐       │   │
│  │       │                  │                               │       │   │
│  │       ▼                  ▼                               │       │   │
│  │  ChannelAdapter ◀──── Task execution ◀──── ProxyManager (int.)   │   │
│  │  .send_reply()                                                   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────┐   │
│  │ ThreadPool      │  │ TaskTracker     │  │ Dashboard (optional)   │   │
│  │ (concurrency)   │  │ (monitoring)    │  │                        │   │
│  └─────────────────┘  └─────────────────┘  └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

Components are scoped to different levels of the system. The scope determines
each component's lifetime and what resources it can access.

**Service-scoped** — one instance per server process, shared across all repos:

- **GatewayService** — Top-level orchestrator that manages repo handlers, shared
  thread pool, dashboard, and graceful shutdown
- **Sandbox** (`airut/sandbox/`) — Manages container execution, proxy
  infrastructure, execution context state, and image builds
- **ThreadPool** — Limits concurrent task execution across repositories
- **TaskTracker** — Tracks task status for dashboard and monitoring
- **Dashboard** — Optional web UI for viewing conversations and network logs

**Repo-scoped** — one instance per repository, lives for the server lifetime:

- **RepoHandler** — Per-repository component that owns all repo-scoped
  components below
- **ChannelAdapter** — Protocol-specific message handling (authentication,
  parsing, replies). For email: `EmailChannelAdapter` wraps the listener,
  authenticator, authorizer, and responder.
- **EmailListener** — Polls IMAP inbox (or uses IDLE) for incoming messages
- **ConversationManager** — Creates/resumes conversations, manages git mirror
  and workspaces
- **Sandbox Task** — Per-execution task created by the Sandbox; runs Claude Code
  in a container with proxy, mounts, and execution context management
- **GitMirrorCache** — Bare mirror repository for fast local clones

**Conversation-scoped** — created when a new email thread starts, persists
across all tasks in that conversation:

- **Conversation directory** — Contains workspace, Claude state, inbox/outbox
- **Git workspace** — Full clone from the git mirror
- **Claude session state** — `conversation.json` (metadata), `events.jsonl`
  (streaming events), and `/root/.claude` state for `--resume` across tasks
- **Conversation lock** — Serializes task execution within a conversation

**Task-scoped** — created when processing an inbound message, destroyed when the
task completes:

- **Container process** — Podman container running Claude Code
- **Proxy container** — mitmproxy instance enforcing the network allowlist
- **Internal network** (`airut-conv-{id}`) — Routes container traffic through
  the proxy. Named by conversation ID since serial execution means at most one
  task uses it at a time.

### How It Maps to the Concepts

| Concept            | Implementation                                                  |
| ------------------ | --------------------------------------------------------------- |
| Conversation       | Conversation ID + conversation directory                        |
| Git checkout       | `ConversationManager` clones from git mirror                    |
| Claude session     | Session ID stored in `conversation.json`, passed via `--resume` |
| Container sandbox  | `Sandbox`/`Task` runs Podman with controlled mounts             |
| Network sandbox    | `ProxyManager` (internal to sandbox) enforces allowlist         |
| Parallel execution | `ThreadPoolExecutor` with configurable `max_concurrent`         |

### Sandbox Concept Mapping

The sandbox library (`airut/sandbox/`) is protocol-agnostic — it knows nothing
about email, conversations, or gateway-specific layouts. The gateway bridges its
own concepts to the sandbox's neutral interface:

| Gateway concept  | Sandbox concept         | Mapping                                  |
| ---------------- | ----------------------- | ---------------------------------------- |
| Conversation ID  | `execution_context_id`  | Passed to `create_task()`                |
| Conversation dir | `execution_context_dir` | Gateway builds paths, sandbox uses them  |
| Inbound message  | `Task.execute()` call   | One message → one `execute()` invocation |

The `execution_context_id` is an opaque string to the sandbox — it scopes
execution context state and network resources without knowing that it represents
a conversation. See [spec/sandbox.md](../spec/sandbox.md) for the sandbox's own
API documentation.

### Authentication and Authorization

The channel adapter is responsible for authenticating and authorizing inbound
messages before the core processes them. This is a single
`authenticate_and_parse()` call that returns a `ParsedMessage` on success or
`None` to reject the message. The core does not know how authentication works —
it only sees the result.

Each channel implements authentication differently. The email channel uses a
two-layer approach (see [Email Channel](#email-channel) below for details):

1. **Authentication** (`SenderAuthenticator`) — Verifies sender identity via
   DMARC on trusted `Authentication-Results` headers
2. **Authorization** (`SenderAuthorizer`) — Checks authenticated sender against
   the repository's allowlist

### Request Flow

```
Inbound message
    │
    ▼
Listener ──▶ ChannelAdapter.authenticate_and_parse()
    │              │
    │              ├──▶ Returns ParsedMessage or None (rejected)
    │              │
    ▼              ▼
ConversationManager
    │
    ├──▶ Resolve conversation ID, or generate new ID
    │
    ├──▶ Create conversation directory, or resume existing
    │
    ├──▶ Clone workspace from git mirror (new) or reuse (resume)
    │
    ├──▶ ChannelAdapter.save_attachments() ──▶ inbox/
    │
    ▼
Sandbox (airut/sandbox/)
    │
    ├──▶ Build container image (cached by content hash)
    │
    ├──▶ Create Task with mounts, env, session dir
    │
    ├──▶ Prepend channel context to prompt (gateway layer)
    │
    ├──▶ Task.execute():
    │        Start proxy (network sandbox)
    │        Run Claude Code container with mounts:
    │            /workspace  ← conversation workspace
    │            /inbox      ← channel attachments
    │            /outbox     ← files to attach to reply
    │        For existing sessions, pass --resume {session_id}
    │        Capture output, classify outcome
    │        Stop proxy
    │
    ▼
ChannelAdapter.send_reply()
    │
    ▼
Listener cleanup
```

### Email Channel

The email channel (`gateway/email/`) implements `ChannelAdapter` as
`EmailChannelAdapter`, wrapping the email-specific components:

- **EmailListener** — IMAP polling (or IDLE) for incoming messages
- **SenderAuthenticator** — DMARC verification on trusted headers
- **SenderAuthorizer** — Sender allowlist checking
- **EmailResponder** — SMTP reply construction with threading headers

**Email lifecycle:** Airut treats the IMAP inbox as a work queue. After
processing a message (whether successful or not), it permanently deletes the
message from the inbox. This is why each repository requires a dedicated email
account — Airut will process and delete every message it finds.

**Email request flow** (channel-specific detail within the generic flow above):

```
IMAP inbox
    │
    ▼
EmailListener (poll or IDLE)
    │
    ├──▶ SenderAuthenticator (DMARC on trusted headers)
    │
    ├──▶ SenderAuthorizer (allowlist check)
    │
    ├──▶ Parse MIME body, strip quotes, decode attachments
    │
    ├──▶ Extract conversation ID from headers or subject [ID:...]
    │
    ├──▶ Extract model hint from subaddressing (user+opus@...)
    │
    ▼
    ... (generic flow: ConversationManager → Sandbox → Task) ...
    │
    ▼
EmailResponder
    │
    ├──▶ Format response with Claude output
    │
    ├──▶ Attach files from /outbox
    │
    ├──▶ Set In-Reply-To, References for threading
    │
    ▼
SMTP send
    │
    ▼
EmailListener
    │
    └──▶ Delete original message from IMAP inbox (expunge)
```

### Storage Structure

Each conversation maps to a directory under the XDG state dir
(`~/.local/state/airut/<repo_id>/`):

```
{state_dir}/
├── git-mirror/              # Bare mirror for fast clones
└── conversations/
    └── {conversation-id}/       # 8-char hex ID
        ├── conversation.json    # Session metadata (NOT mounted to container)
        ├── events.jsonl         # Streaming events (append-only)
        ├── network-sandbox.log  # Proxy request log (allowed/blocked)
        ├── workspace/           # Git checkout → /workspace
        ├── claude/              # Claude state → /root/.claude
        ├── inbox/               # Attachments → /inbox
        ├── outbox/              # Reply files → /outbox
        └── storage/             # Persistent scratch space → /storage
```

The git mirror is refreshed before each task starts. After refreshing, the
per-repo configuration (`.airut/airut.yaml`), container Dockerfile
(`.airut/container/Dockerfile`), and network allowlist
(`.airut/network-allowlist.yaml`) are read from the mirror's default branch.
Workspaces are full clones (no shared objects) for isolation.

### Multi-Repository Architecture

A single server manages multiple repositories with per-repo isolation:

| Per-Repository                     | Shared Across Repos            |
| ---------------------------------- | ------------------------------ |
| Channel inbox (e.g., IMAP account) | Thread pool (`max_concurrent`) |
| Authorized senders                 | Dashboard                      |
| Secrets pool                       | Proxy infrastructure           |
| Storage directory                  |                                |
| Git mirror                         |                                |

Each repository has its own `RepoHandler` with isolated components.

### Configuration

Airut uses a two-layer configuration model:

**Server config** (`~/.config/airut/airut.yaml`) — deployment infrastructure
managed by the operator:

- Email credentials (IMAP/SMTP)
- Authorized senders and trusted auth servers
- Repository URL and storage paths
- Secrets pool (values repos can reference)
- Concurrency limits and dashboard settings

**Repo config** (`.airut/airut.yaml`) — per-repository behavior checked into the
target repo:

- Default model and timeout
- Container environment variables (with `!secret` references to server secrets)
- Network allowlist toggle

This separation lets repos declare what they need (e.g., "I need GH_TOKEN")
while the server controls actual secret values. Repo config is read from the git
mirror at task start, so changes take effect after merge without server restart.

See [spec/repo-config.md](../spec/repo-config.md) for the full schema.

## Key Design Decisions

### Email as Interface

Email provides natural conversation threading, works from any device, requires
no custom client, and handles the asynchronous nature of agent work. The
`[ID:xyz123]` tag in subject lines tracks conversation state.

### Container Isolation

Each task runs in a rootless Podman container with:

- Mounted workspace (git checkout)
- Separate Claude session state directory
- Network sandbox via mitmproxy (see [network-sandbox.md](network-sandbox.md))
- Environment-only credentials (no host mounts)

See [execution-sandbox.md](execution-sandbox.md) for details.

### File-Based State

Conversation state is stored as files on disk — no database. Each conversation
has a directory containing workspace, Claude session state, inbox/outbox for
attachments. This keeps the system simple and inspectable.

### Multi-Repository Support

A single server can manage multiple repositories. Each gets its own email inbox,
authorized senders, secrets, and storage. Tasks across repos share a global
concurrency limit.

## Limitations

Airut is designed for **small-scale deployments**:

- Single operator managing a few repositories
- Not multi-tenant — all repos share one server
- No web UI for task submission (channel-based only)

**Claude Code only** — no support for other agentic frameworks. The container
runs Claude Code with `--dangerously-skip-permissions` in sandbox mode.

**Git repositories only** — workspaces are git checkouts. Some configuration
(`.airut/` directory) must be checked into the target repository.

## Further Reading

- [security.md](security.md) — Authentication, authorization, credential
  management
- [execution-sandbox.md](execution-sandbox.md) — Container isolation details
- [network-sandbox.md](network-sandbox.md) — Network allowlist and proxy
- [deployment.md](deployment.md) — Installation and configuration
- [spec/gateway-architecture.md](../spec/gateway-architecture.md) — Detailed
  implementation spec
