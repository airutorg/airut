# Architecture

Airut is an email gateway for headless Claude Code interaction. It treats Claude
as a correspondent you exchange emails with — send instructions, receive
results, reply to continue the conversation.

## Conceptual Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Email Conversation                           │
│                                                                     │
│   ┌─────────────────┐    ┌─────────────────┐    ┌───────────────┐   │
│   │  Git Checkout   │ +  │  Claude Code    │ +  │   Sandbox     │   │
│   │  (workspace)    │    │  Session        │    │   (network,   │   │
│   │                 │    │  (context)      │    │   container)  │   │
│   └─────────────────┘    └─────────────────┘    └───────────────┘   │
│                                                                     │
│   Each email thread maps to an isolated agent session with its      │
│   own repository checkout and persistent Claude context.            │
└─────────────────────────────────────────────────────────────────────┘
```

An email conversation in Airut is:

- **A git checkout** — the agent's workspace, cloned from the target repository
- **A Claude Code session** — persistent context across messages via `--resume`
- **A sandboxed environment** — container isolation, network allowlist

Reply to continue the conversation. The agent picks up where it left off with
full context of previous work.

## Technical Architecture

This section describes how the implementation realizes the conceptual model.

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         EmailGatewayService                             │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    RepoHandler (per repository)                  │   │
│  │                                                                  │   │
│  │  EmailListener ──▶ Authenticator ──▶ Authorizer                  │   │
│  │       │                                   │                      │   │
│  │       │           ConversationManager ◀───┘                      │   │
│  │       │                   │                                      │   │
│  │       │           ClaudeExecutor ◀────────────────────┐          │   │
│  │       │                   │                           │          │   │
│  │       ▼                   ▼                           │          │   │
│  │  EmailResponder ◀─── Container execution ◀─── ProxyManager       │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────┐   │
│  │ ThreadPool      │  │ TaskTracker     │  │ Dashboard (optional)   │   │
│  │ (concurrency)   │  │ (monitoring)    │  │                        │   │
│  └─────────────────┘  └─────────────────┘  └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

**Components:**

- **EmailGatewayService** — Top-level orchestrator that manages repo handlers,
  shared thread pool, dashboard, and graceful shutdown
- **RepoHandler** — Per-repository component that owns email listener,
  authenticator, conversation manager, and executor
- **EmailListener** — Polls IMAP inbox (or uses IDLE) for incoming messages
- **SenderAuthenticator** — Verifies DMARC pass on trusted headers
- **SenderAuthorizer** — Checks sender against repository allowlist
- **ConversationManager** — Creates/resumes sessions, manages git workspaces
- **ClaudeExecutor** — Builds images and runs Claude Code in containers
- **ProxyManager** — Manages per-task mitmproxy containers for network sandbox
- **EmailResponder** — Sends replies via SMTP with proper threading headers
- **ThreadPool** — Limits concurrent task execution across repositories
- **TaskTracker** — Tracks task status for dashboard and monitoring
- **Dashboard** — Optional web UI for viewing tasks and network logs

### How It Maps to the Conceptual Model

| Concept            | Implementation                                             |
| ------------------ | ---------------------------------------------------------- |
| Email conversation | Conversation ID (`[ID:xyz123]`) + session directory        |
| Git checkout       | `ConversationManager` clones from git mirror               |
| Claude session     | Session ID stored in `session.json`, passed via `--resume` |
| Container sandbox  | `ClaudeExecutor` runs Podman with controlled mounts        |
| Network sandbox    | `ProxyManager` runs mitmproxy enforcing allowlist          |
| Parallel execution | `ThreadPoolExecutor` with configurable `max_concurrent`    |

### Request Flow

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
    ▼
ConversationManager
    │
    ├──▶ Parse [ID:...] from subject, or generate new ID
    │
    ├──▶ Create session directory, or resume existing
    │
    ├──▶ Clone workspace from git mirror (new) or reuse (resume)
    │
    ▼
ClaudeExecutor
    │
    ├──▶ Build container image (cached by content hash)
    │
    ├──▶ Start proxy container (network sandbox)
    │
    ├──▶ Prepend email prelude to prompt (notes email interface,
    │    mentions /inbox attachments and /outbox for replies)
    │
    ├──▶ Run Claude Code container with mounts:
    │        /workspace  ← session workspace
    │        /inbox      ← email attachments
    │        /outbox     ← files to attach to reply
    │    For existing conversations, pass --resume {session_id}
    │
    ├──▶ Capture output, store session metadata for resume
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
```

### Storage Structure

Each conversation maps to a session directory:

```
{storage_dir}/
├── git-mirror/              # Bare mirror for fast clones
└── sessions/
    └── {conversation-id}/       # 8-char hex ID
        ├── session.json         # Session metadata (NOT mounted to container)
        ├── network-sandbox.log  # Proxy request log (allowed/blocked)
        ├── workspace/           # Git checkout → /workspace
        ├── claude/              # Claude state → /root/.claude
        ├── inbox/               # Attachments → /inbox
        └── outbox/              # Reply files → /outbox
```

The git mirror is refreshed before each task starts. After refreshing, the
per-repo configuration (`.airut/airut.yaml`), container Dockerfile
(`.airut/container/Dockerfile`), and network allowlist
(`.airut/network-allowlist.yaml`) are read from the mirror's default branch.
Workspaces are full clones (no shared objects) for isolation.

### Multi-Repository Architecture

A single server manages multiple repositories with per-repo isolation:

| Per-Repository             | Shared Across Repos            |
| -------------------------- | ------------------------------ |
| Email inbox (IMAP account) | Thread pool (`max_concurrent`) |
| Authorized senders         | Dashboard                      |
| Secrets pool               | Proxy infrastructure           |
| Storage directory          |                                |
| Git mirror                 |                                |

Each repository has its own `RepoHandler` with isolated components.

### Configuration

Airut uses a two-layer configuration model:

**Server config** (`config/airut.yaml`) — deployment infrastructure managed by
the operator:

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
- Separate session state directory
- Network sandbox via mitmproxy (see [network-sandbox.md](network-sandbox.md))
- Environment-only credentials (no host mounts)

See [execution-sandbox.md](execution-sandbox.md) for details.

### File-Based State

Session state is stored as files on disk — no database. Each conversation has a
directory containing workspace, Claude session state, inbox/outbox for
attachments. This keeps the system simple and inspectable.

### Multi-Repository Support

A single server can manage multiple repositories. Each gets its own email inbox,
authorized senders, secrets, and storage. Tasks across repos share a global
concurrency limit.

## Limitations

Airut is designed for **small-scale deployments**:

- Single operator managing a few repositories
- Not multi-tenant — all repos share one server
- No web UI for task submission (email only)

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
