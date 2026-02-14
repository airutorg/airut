# Multi-Repository Support

A single Airut daemon manages tasks for multiple independent Git repositories,
each with its own email inbox, authorization, secrets, and storage.

## Goals

1. **Multiple repositories per server.** A single Airut daemon manages tasks for
   several independent Git repositories.
2. **Per-repo email inbox.** Each repository pulls tasks from its own IMAP
   inbox. Repos must not share an inbox — that would create a shared task queue
   and violate isolation.
3. **Per-repo authorization.** Each repo has its own `authorized_senders` list
   and `trusted_authserv_id`. Different people can be authorized for different
   repos.
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

The server config (`config/airut.yaml`) is restructured. Global settings live at
the top level. Everything repo-specific moves under `repos.<name>`.

```yaml
# Global settings (shared across all repos)
execution:
  max_concurrent: 3
  shutdown_timeout: 60
  conversation_max_age_days: 7

dashboard:
  enabled: true
  host: 127.0.0.1
  port: 5200
  base_url: dashboard.example.com

container_command: podman

# Per-repo configuration
repos:
  airut:
    git:
      repo_url: https://github.com/airutorg/airut.git

    storage_dir: ~/email-service-storage/airut

    email:
      imap_server: mail.example.com
      imap_port: 993
      smtp_server: mail.example.com
      smtp_port: 587
      username: airut
      password: !env EMAIL_PASSWORD_AIRUT
      from: "Airut <airut@example.com>"

    authorized_senders:
      - admin@example.com
    trusted_authserv_id: mail.example.com

    imap:
      poll_interval: 30
      use_idle: true
      idle_reconnect_interval: 1740

    # Per-repo secrets pool
    secrets:
      CLAUDE_CODE_OAUTH_TOKEN: !env CLAUDE_CODE_OAUTH_TOKEN
      GH_TOKEN: !env GH_TOKEN_AIRUT
      R2_ACCESS_KEY_ID: !env R2_ACCESS_KEY_ID

  another-repo:
    git:
      repo_url: https://github.com/other/repo.git
    storage_dir: ~/email-service-storage/another-repo
    email:
      imap_server: mail.example.com
      imap_port: 993
      smtp_server: mail.example.com
      smtp_port: 587
      username: bot
      password: !env EMAIL_PASSWORD_OTHER
      from: "Bot <bot@example.com>"
    authorized_senders:
      - someone@example.com
    trusted_authserv_id: mail.example.com
    imap:
      use_idle: true
    secrets:
      GH_TOKEN: !env GH_TOKEN_OTHER
```

### Key Design Decisions

- **Secrets are per-repo.** Both repos can declare `GH_TOKEN: !secret GH_TOKEN`
  in their `.airut/airut.yaml`, but the server resolves them from different
  environment variables (`GH_TOKEN_AIRUT` vs `GH_TOKEN_OTHER`). This applies to
  `secrets`, `masked_secrets`, and `signing_credentials` alike.
- **SMTP is per-repo.** Replies come from the same email address that receives
  tasks for that repo.
- **`authorized_senders` is a list** supporting multiple senders per repo with
  optional domain wildcards (e.g., `*@company.com`). Each repo is independent.
- **`trusted_authserv_id` is per-repo** since email settings differ per repo.

### Validation Rules

At config load time:

- **No duplicate inboxes:** No two repos may share the same
  `(imap_server, username)` pair. This enforces the "no shared task queue"
  constraint.
- **At least one repo:** The `repos` mapping must have at least one entry.
- **Unique storage_dirs:** No two repos may share the same `storage_dir`.

## Repo Configuration

The repo config (`.airut/airut.yaml`) is unchanged. It remains per-repo by
nature — each repository has its own `.airut/airut.yaml` in its git mirror. The
`from_mirror()` method receives the per-repo `secrets` dict from the server
config.

## Storage Layout

Each repo gets fully isolated storage. No files are shared between repos.

```
~/email-service-storage/
├── airut/                        # Per-repo storage root
│   ├── git-mirror/               # Shared across conversations for this repo
│   └── conversations/
│       ├── abc12345/
│       │   ├── context.json
│       │   ├── workspace/
│       │   ├── claude/
│       │   ├── gitconfig
│       │   ├── inbox/
│       │   └── outbox/
│       └── ...
└── another-repo/                 # Second repo, fully isolated
    ├── git-mirror/
    └── conversations/
        └── ...
```

## Architecture

### Component Ownership

```
EmailGatewayService (orchestrator)
├── repos: dict[str, RepoHandler]
│   ├── "airut" → RepoHandler
│   │   ├── config: RepoServerConfig
│   │   ├── listener: EmailListener         (per-repo IMAP)
│   │   ├── responder: EmailResponder       (per-repo SMTP)
│   │   ├── authenticator: SenderAuthenticator (per-repo authserv_id)
│   │   ├── authorizer: SenderAuthorizer    (per-repo authorized_senders)
│   │   ├── conversation_manager: ConversationManager (per-repo storage)
│   │   └── executor: ClaudeExecutor        (per-repo mirror for images)
│   └── "another-repo" → RepoHandler
│       └── ...
├── proxy_manager: ProxyManager     (shared gateway, per-conversation proxy)
├── tracker: TaskTracker            (shared, tasks tagged with repo + sender)
├── dashboard: DashboardServer      (shared)
└── executor_pool: ThreadPoolExecutor (shared, global max_concurrent)
```

| Component             | Scope    | Rationale                                                   |
| --------------------- | -------- | ----------------------------------------------------------- |
| `EmailListener`       | Per-repo | Different IMAP inbox per repo                               |
| `EmailResponder`      | Per-repo | Different SMTP credentials and from address                 |
| `SenderAuthenticator` | Per-repo | Different `trusted_authserv_id`                             |
| `SenderAuthorizer`    | Per-repo | Different `authorized_senders`                              |
| `ConversationManager` | Per-repo | Different storage directory and git mirror                  |
| `ClaudeExecutor`      | Per-repo | Different mirror (for image builds from Dockerfile)         |
| `ProxyManager`        | Shared   | Gateway infra shared; per-conversation proxy uses allowlist |
| `TaskTracker`         | Shared   | Global view, tasks tagged with `repo_id`                    |
| `DashboardServer`     | Shared   | Single dashboard for all repos                              |
| `ThreadPoolExecutor`  | Shared   | Global `max_concurrent` limit across repos                  |
| `UpdateLock`          | Shared   | One update lock for the server process                      |

### Listener Threading Model

Each repo's listener runs in its own daemon thread:

```
Main thread:                startup → spawn listener threads → wait for shutdown
Thread "airut-listener":    poll_loop() or idle_loop()
Thread "other-listener":    poll_loop() or idle_loop()
Worker threads (shared):    message processing + Claude execution
```

Messages from any listener are submitted to the shared `ThreadPoolExecutor`,
which enforces the global `max_concurrent` limit. Listener threads are
lightweight (mostly blocked in IDLE or sleep) and don't compete with workers.

Signal handling: `SIGTERM`/`SIGINT` sets `running = False` and calls
`interrupt()` on all listeners.

### RepoHandler

`RepoHandler` encapsulates all per-repo components and runs the listener loop:

```python
class RepoHandler:
    """Per-repo components and listener thread."""

    config: RepoServerConfig
    listener: EmailListener
    responder: EmailResponder
    authenticator: SenderAuthenticator
    authorizer: SenderAuthorizer
    conversation_manager: ConversationManager
    executor: ClaudeExecutor
```

Message processing logic (currently in `EmailGatewayService._process_message`)
moves to `RepoHandler`. It uses the shared executor pool and task tracker via a
back-reference to the service.

### Proxy Manager

The `ProxyManager` is shared across repos. Its gateway infrastructure (egress
network, proxy image, CA cert) is set up once at startup. Per-conversation proxy
containers are started based on each repo's `network.allowlist_enabled` setting.

Currently `ProxyManager` holds a mirror reference to read the network allowlist.
With multi-repo, `start_task_proxy` receives the allowlist content from the
`RepoHandler`, which reads it from its own mirror.

## Configuration Classes

```python
@dataclass(frozen=True)
class GlobalConfig:
    """Global server settings (not repo-specific)."""

    max_concurrent_executions: int
    shutdown_timeout_seconds: int
    conversation_max_age_days: int
    dashboard_enabled: bool
    dashboard_host: str
    dashboard_port: int
    dashboard_base_url: str | None
    container_command: str


@dataclass(frozen=True)
class RepoServerConfig:
    """Per-repo server-side configuration."""

    repo_id: str
    git_repo_url: str
    storage_dir: Path
    imap_server: str
    imap_port: int
    smtp_server: str
    smtp_port: int
    email_username: str
    email_password: str
    email_from: str
    authorized_senders: list[str]
    trusted_authserv_id: str
    poll_interval_seconds: int
    use_imap_idle: bool
    idle_reconnect_interval_seconds: int
    smtp_require_auth: bool
    secrets: dict[str, str]
    masked_secrets: dict[str, MaskedSecret]
    signing_credentials: dict[str, SigningCredential]


@dataclass(frozen=True)
class ServerConfig:
    """Complete server configuration."""

    global_config: GlobalConfig
    repos: dict[str, RepoServerConfig]
```

`RepoConfig` (loaded from `.airut/airut.yaml` in the git mirror) is unchanged.
Its `from_mirror()` receives the per-repo `secrets`, `masked_secrets`, and
`signing_credentials` dicts.

## Dashboard Changes

`TaskState` gains two new fields:

- `repo_id: str` — which repository this task belongs to
- `sender: str` — email address of the person who sent the task

Dashboard UI changes:

- Task cards show repo name as a badge/tag
- Task cards show sender email
- Task detail view includes repo and sender
- No filtering by repo (keep it simple for now)

## Email Protocol

No changes to the email protocol itself. Conversation IDs, subject tagging,
model selection via subaddressing, and threading all work the same. The only
difference is that each repo has its own email address, so users send to
different addresses for different repos.

## Migration

This is a clean break. The old flat config format is not supported. To migrate:

1. Restructure `config/airut.yaml` to the new `repos:` format
2. Move `storage_dir` contents into a repo-specific subdirectory
3. Update `.env` with per-repo secret variable names

No code maintains backwards compatibility with the old format.
