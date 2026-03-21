# Repo Configuration

All per-repo configuration lives in the **server config**
(`~/.config/airut/airut.yaml`). There is no repo-side `airut.yaml` for the
gateway. The server config is the single source of truth for model, effort,
resource limits, container environment, network sandbox toggle, and all
credential pools.

Repository-side files that remain in `.airut/`:

- `.airut/network-allowlist.yaml` — network sandbox allowlist (read from git
  mirror's default branch at task start)
- `.airut/container/Dockerfile` — repo-defined container base image
- `.airut/sandbox.yaml` — sandbox CLI config (used by `airut-sandbox` /
  `sandbox-action` only, not the gateway)

## Per-Repo Schema in Server Config

Each repo is defined under `repos.<repo_id>` in the server config:

```yaml
repos:
  my-project:
    # Channels (at least one required)
    email: { ... }
    slack: { ... }

    # Git repository
    git:
      repo_url: https://github.com/org/repo.git

    # Claude model (default: "opus")
    # Channel hints (e.g. email subaddressing) override this for new
    # conversations.  Resumed conversations keep their stored model.
    model: opus

    # Effort level passed as --effort to Claude Code (optional)
    # effort: max

    # Per-repo resource limits (all optional, clamped to server ceilings)
    # resource_limits:
    #   timeout: 6000
    #   memory: "4g"
    #   cpus: 2
    #   pids_limit: 256

    # Network sandbox toggle (default: true)
    # network:
    #   sandbox_enabled: true

    # Plain environment variables for containers (non-secret values)
    # container_env:
    #   BUCKET_NAME: "my-bucket"

    # Credential pools (all entries auto-inject as container env vars)
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes: ["github.com", "api.github.com"]
        headers: ["Authorization"]

    # signing_credentials: { ... }
    # github_app_credentials: { ... }
```

### Fields

| Field                        | Type    | Default  | Description                                      |
| ---------------------------- | ------- | -------- | ------------------------------------------------ |
| `model`                      | string  | `"opus"` | Claude model for new conversations               |
| `effort`                     | string  | *(none)* | Effort level passed as `--effort` to Claude Code |
| `resource_limits.timeout`    | int     | *(none)* | Max container execution time in seconds (>= 10)  |
| `resource_limits.memory`     | string  | *(none)* | Memory limit, e.g. `"2g"`, `"512m"`              |
| `resource_limits.cpus`       | float   | *(none)* | CPU limit (>= 0.01, supports fractional cores)   |
| `resource_limits.pids_limit` | int     | *(none)* | Process limit (>= 1)                             |
| `network.sandbox_enabled`    | bool    | `true`   | Whether to enforce network allowlist             |
| `container_env`              | mapping | `{}`     | Plain (non-secret) environment variables         |
| `secrets`                    | mapping | `{}`     | Plain secrets injected as env vars               |
| `masked_secrets`             | mapping | `{}`     | Surrogate-based scoped credentials               |
| `signing_credentials`        | mapping | `{}`     | AWS SigV4 re-signing credentials                 |
| `github_app_credentials`     | mapping | `{}`     | Proxy-managed GitHub App token rotation          |

## Credential Auto-Injection

All credential pool entries auto-inject into the container as environment
variables by their key name. There is no separate `container_env` mapping needed
to reference credentials — declaring a secret in any credential pool
automatically makes it available as an env var.

**Priority ordering** for duplicate env var names (highest wins):

1. `github_app_credentials` keys
2. `signing_credentials` field `.name` values
3. `masked_secrets` keys
4. `secrets` keys
5. `container_env` keys

When the same env var name appears in multiple pools, the highest-priority pool
wins. This allows upgrading a credential from plain `secrets` to
`masked_secrets` without removing the old entry (though removing it is cleaner).

All resolved values are registered for log redaction.

## Model and Effort

The `model` field defaults to `"opus"`. For new conversations, the priority is:

| Priority | Model                             | Effort                       |
| -------- | --------------------------------- | ---------------------------- |
| 1        | channel `model_hint` (e.g. email) | `repos.<id>.effort` (server) |
| 2        | `repos.<id>.model` (server)       | *(none -- Claude default)*   |

Resumed conversations always use the model and effort stored at conversation
creation time, regardless of current server config.

## Resource Limit Clamping

Per-repo resource limits are clamped to server-wide ceilings. For each field
independently:

```
effective = min(repo_value, server_ceiling)  if both set
          = repo_value                       if only repo set
          = None (no limit)                  if neither set
```

Memory comparison is done in bytes (e.g. `"4g"` vs `"8g"`).

### Server-Wide Ceilings

```yaml
# ~/.config/airut/airut.yaml (server config, top level)
resource_limits:
  timeout: 7200       # Max allowed timeout (seconds)
  memory: "8g"        # Max allowed memory
  cpus: 4             # Max allowed CPUs
  pids_limit: 1024    # Max allowed process count
```

All fields are optional. Omitted fields mean no ceiling for that dimension.
These are **ceilings only** — they do not inject defaults. A repo that omits a
field gets no limit for that dimension, regardless of the server ceiling.

## What Stays in the Repository

### Network Allowlist

`.airut/network-allowlist.yaml` remains in the repository. It is read from the
git mirror's default branch at task start. The agent can propose changes via PR,
but a human must review and merge before the change takes effect.

### Container Dockerfile

`.airut/container/Dockerfile` remains in the repository. The container image is
rebuilt from the repository's default branch at every task start.

### Sandbox CLI Config

`.airut/sandbox.yaml` is used by `airut-sandbox run` (the standalone CLI for CI
pipelines). It is not used by the Airut gateway service.

## Server Config Reference

Per-repo config is nested under `repos.<repo_id>`. Global settings live at the
top level.

- `email.*` — Email channel settings nested under `email:`:
  - `email.imap_server`, `email.smtp_server` — Mail server connectivity
  - `email.username`, `email.password` — Credentials
  - `email.from` — Sender address
  - `email.authorized_senders`, `email.trusted_authserv_id` — Access control
  - `email.microsoft_oauth2.*` — Microsoft OAuth2 Client Credentials for M365
    (tenant_id, client_id, client_secret). When configured, XOAUTH2 SASL is used
    for both IMAP and SMTP instead of password auth. The `email.password` field
    becomes optional when OAuth2 is configured.
  - `email.microsoft_internal_auth_fallback` — Fallback auth for internal M365
  - `email.imap.*` — Polling and idle configuration
- `slack.*` — Slack channel settings nested under `slack:`:
  - `slack.bot_token` — Bot User OAuth Token (`xoxb-...`)
  - `slack.app_token` — App-level token for Socket Mode (`xapp-...`)
  - `slack.authorized` — Authorization rules: `workspace_members`, `user_group`,
    `user_id`. See [slack-channel.md](slack-channel.md#authorization-rules)
- `git.repo_url` — Repository to clone
- `model` — Claude model for new conversations (default: `"opus"`)
- `effort` — Effort level for Claude Code (optional)
- `resource_limits.*` — Per-repo resource limits (timeout, memory, cpus,
  pids_limit), clamped to server-wide ceilings
- `network.sandbox_enabled` — Network sandbox toggle (default: `true`)
- `container_env` — Plain (non-secret) environment variables for containers
- `secrets` — Plain secrets injected as container env vars
- `masked_secrets` — Surrogate-based scoped credentials
- `signing_credentials` — AWS SigV4 re-signing credentials
- `github_app_credentials` — Proxy-managed GitHub App token rotation
- `execution.*` — `max_concurrent`, `shutdown_timeout`,
  `conversation_max_age_days`, `image_prune`
- `dashboard.*` — Web UI configuration
- `container_command` — Container runtime (podman/docker)
- `resource_limits.*` (top-level) — Server-wide resource limit ceilings

**Important:** All channel-specific fields must be nested under their channel
block (`email:` or `slack:`). A repo must have at least one channel block
configured. Multiple channels can coexist under the same repo — each runs its
own listener and feeds messages through the shared processing pipeline.

## Loading Flow

1. Service starts, loads server config (`ServerConfig.from_yaml()`)
2. Per-repo settings (model, effort, resource limits, network, container_env,
   all credential pools) are parsed from the server config
3. Mirror is updated (`mirror.update_mirror()`)
4. Network allowlist and container Dockerfile are read from the mirror's default
   branch
5. Credential pool entries are resolved and prepared (surrogates generated for
   masked/signing/GitHub App credentials)
6. All resolved env var values are registered with `SecretFilter`
7. Fields are validated (timeout >= 10, etc.)

## Multi-Repo Support

The server supports multiple repositories. Each repo is defined under `repos:`
in the server config with its own channel blocks (e.g. `email:` for IMAP/SMTP),
storage directory, and credential pools. A repo can have multiple channel blocks
configured simultaneously. See `multi-repo.md` for the full design.

## Proxy Manager Lifecycle

Since `network.sandbox_enabled` is per-repo, the `ProxyManager` is always
created and its gateway infrastructure (egress network, proxy image, CA cert) is
set up at startup. Per-conversation proxy containers are only started when the
repo has `network.sandbox_enabled: true`.
