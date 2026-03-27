# Multi-Repository Support

A single Airut daemon manages tasks for multiple independent Git repositories,
each with its own messaging channels, authorization, secrets, and storage.

## Goals

1. **Multiple repositories per server.** A single Airut daemon manages tasks for
   several independent Git repositories.
2. **Per-repo channels.** Each repository has one or more channel adapters (e.g.
   email, Slack). Email channels must not share an IMAP inbox — that would
   create a shared task queue and violate isolation. Each Slack app (bot token)
   maps to one repo.
3. **Per-repo authorization.** Each repo has its own authorization rules. Email
   uses `auth.authorized_senders` and `auth.trusted_authserv_id`; Slack uses
   `authorized` rules (workspace members, user groups, user IDs). Different
   people can be authorized for different repos.
4. **No shared state between repos.** Storage, git mirrors, conversations,
   secrets, and email accounts are fully isolated per repo. The only shared
   resources are the global task limit and infrastructure (dashboard, proxy
   gateway, container runtime).
5. **Shared git mirror within a repo.** Sessions for the same repository share
   the git mirror (as today).
6. **Global task limit.** Tasks across all repositories count toward a single
   `max_concurrent` limit.
7. **Dashboard visibility.** The dashboard shows which repository a task belongs
   to and who issued it.
8. **Clean break.** No backwards compatibility with the single-repo config
   format. The old flat config is replaced entirely.

## Server Configuration

The server config (`~/.config/airut/airut.yaml`) has global settings at the top
level and everything repo-specific under `repos.<name>`. See
[`config/airut.example.yaml`](../config/airut.example.yaml) for the complete
field reference, and [repo-config.md](repo-config.md) for per-repo schema
details.

### Key Design Decisions

- **Secrets are per-repo.** Both repos can have a `GH_TOKEN` entry in their
  credential pools, but the server resolves them from different environment
  variables (`GH_TOKEN_AIRUT` vs `GH_TOKEN_OTHER`). This applies to `secrets`,
  `masked_secrets`, `signing_credentials`, and `github_app_credentials` alike.
- **SMTP is per-repo.** Replies come from the same email address that receives
  tasks for that repo.
- **Authorization is per-repo and per-channel.** Email uses
  `email.auth.authorized_senders` (address patterns). Slack uses
  `slack.authorized` (workspace/group/user rules). Each repo is independent.
- **`email.auth.trusted_authserv_id` is per-repo** since email settings differ
  per repo.

### Validation Rules

At config load time:

- **No duplicate inboxes:** No two repos may share the same
  `(imap.server, account.username)` pair. This enforces the "no shared task
  queue" constraint.
- **At least one channel per repo:** Each repo must have at least one channel
  block (`email:`, `slack:`, or both). Channel keys must match recognized types.

The `repos` mapping may be empty. When empty, the gateway starts in
dashboard-only mode (no channels, no task processing). This allows first-time
users to start the service without running `airut init` and configure repos via
the dashboard config editor.

## Repo Configuration

All per-repo configuration (model, effort, resource limits, network, credential
pools) lives in the server config under `repos.<name>`. There is no repo-side
`airut.yaml` for the gateway. Only `.airut/network-allowlist.yaml` and
`.airut/container/Dockerfile` remain in the repository.

## Storage Layout

Each repo gets fully isolated storage. No files are shared between repos.

```
~/.local/state/airut/
├── airut/                        # Per-repo storage root
│   ├── git-mirror/               # Shared across conversations for this repo
│   └── conversations/
│       ├── abc12345/             # See doc/architecture.md for full layout
│       │   ├── conversation.json
│       │   ├── workspace/
│       │   └── ...
│       └── ...
└── another-repo/                 # Second repo, fully isolated
    ├── git-mirror/
    └── conversations/
        └── ...
```

See [doc/architecture.md](../doc/architecture.md#storage-structure) for the full
conversation directory layout.

## Architecture

### Component Ownership

```
GatewayService (orchestrator)
├── repos: dict[str, RepoHandler]
│   ├── "airut" → RepoHandler
│   │   ├── config: RepoServerConfig
│   │   ├── adapters: dict[str, ChannelAdapter]
│   │   │   ├── "email" → EmailChannelAdapter
│   │   │   │   ├── listener: EmailChannelListener (per-repo IMAP)
│   │   │   │   ├── responder: EmailResponder   (per-repo SMTP)
│   │   │   │   ├── authenticator: SenderAuthenticator
│   │   │   │   └── authorizer: SenderAuthorizer
│   │   │   └── "slack" → SlackChannelAdapter
│   │   │       ├── listener: SlackChannelListener (Socket Mode)
│   │   │       ├── authorizer: SlackAuthorizer
│   │   │       └── thread_store: SlackThreadStore
│   │   ├── conversation_manager: ConversationManager (per-repo storage)
│   │   └── sandbox: Sandbox                (per-repo mirror for images)
│   └── "another-repo" → RepoHandler
│       └── ...
├── proxy_manager: ProxyManager     (shared gateway, per-conversation proxy)
├── tracker: TaskTracker            (shared, tasks tagged with repo + sender)
├── dashboard: DashboardServer      (shared)
└── executor_pool: ThreadPoolExecutor (shared, global max_concurrent)
```

| Component             | Scope    | Rationale                                                     |
| --------------------- | -------- | ------------------------------------------------------------- |
| `ChannelAdapter`      | Per-repo | Wraps channel-specific components (listener, responder, auth) |
| `ConversationManager` | Per-repo | Different storage directory and git mirror                    |
| `Sandbox`             | Per-repo | Different mirror (for image builds from Dockerfile)           |
| `ProxyManager`        | Shared   | Gateway infra shared; per-conversation proxy uses allowlist   |
| `TaskTracker`         | Shared   | Global view, tasks tagged with `repo_id`                      |
| `DashboardServer`     | Shared   | Single dashboard for all repos                                |
| `ThreadPoolExecutor`  | Shared   | Global `max_concurrent` limit across repos                    |

### Listener Threading Model

Each channel listener runs in its own internal thread(s):

```
Main thread:                    startup → start listeners → wait for shutdown
Thread "airut-email-listener":  IMAP poll_loop() or idle_loop()
Thread "airut-slack-listener":  Socket Mode WebSocket (managed by Bolt SDK)
Thread "other-email-listener":  IMAP poll_loop() or idle_loop()
Worker threads (shared):        message processing + Claude execution
```

Messages from any listener are submitted to the shared `ThreadPoolExecutor`,
which enforces the global `max_concurrent` limit. Listener threads are
lightweight (mostly blocked in IDLE, sleep, or WebSocket recv) and don't compete
with workers.

Signal handling: `SIGTERM`/`SIGINT` sets `running = False` and calls
`interrupt()` on all listeners.

### RepoHandler

`RepoHandler` encapsulates all per-repo components and runs the listener loop:

```python
class RepoHandler:
    """Per-repo components and listener threads."""

    config: RepoServerConfig
    adapters: dict[str, ChannelAdapter]  # keyed by channel type
    conversation_manager: ConversationManager
    sandbox: Sandbox
```

Message processing logic (in `GatewayService._process_message`) moves to
`RepoHandler`. It uses the shared executor pool and task tracker via a
back-reference to the service.

### Proxy Manager

The `ProxyManager` is shared across repos. Its gateway infrastructure (egress
network, proxy image, CA cert) is set up once at startup. Per-conversation proxy
containers are started based on each repo's `network.allowlist_enabled` setting.

Currently `ProxyManager` holds a mirror reference to read the network allowlist.
With multi-repo, `start_task_proxy` receives the allowlist content from the
`RepoHandler`, which reads it from its own mirror.

## Configuration Classes

The config dataclasses (`GlobalConfig`, `EmailChannelConfig`,
`SlackChannelConfig`, `RepoServerConfig`, `ServerConfig`, and credential types)
carry declarative `FieldMeta` annotations for documentation, scope, and secret
flags. See [declarative-config.md](declarative-config.md) for the metadata
system and [repo-config.md](repo-config.md) for the per-repo schema.

All per-repo settings (model, effort, resource limits, network, credential
pools) are parsed from the server config at startup.

## Dashboard Changes

`TaskState` gains two new fields:

- `repo_id: str` — which repository this task belongs to
- `sender: str` — identity of the person who sent the task (email address or
  Slack user ID)

Dashboard UI changes:

- Task cards show repo name as a badge/tag
- Task cards show sender identity
- Task detail view includes repo and sender
- No filtering by repo (keep it simple for now)

## Channel Protocols

No changes to individual channel protocols. Email conversation IDs, subject
tagging, model selection via subaddressing, and threading all work the same.
Slack thread mapping and authorization rules are per-repo. The only difference
is that each repo has its own channel credentials (email address, Slack app).

## Migration

This is a clean break. The old flat config format is not supported. To migrate:

1. Restructure `config/airut.yaml` to the new `repos:` format
2. Update `~/.config/airut/.env` with per-repo secret variable names

No code maintains backwards compatibility with the old format.
