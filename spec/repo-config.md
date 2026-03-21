# Repo Configuration

The server config (`~/.config/airut/airut.yaml`) is the **sole source** for all
repo settings. The gateway does not read `.airut/airut.yaml` from repos.

Files that remain in the repo:

- `.airut/network-allowlist.yaml` — agent proposes changes via PR
- `.airut/container/Dockerfile` — repo-specific build context
- `.airut/sandbox.yaml` — sandbox-cli only (not used by gateway)

## Server Per-Repo Config

All operational settings live under `repos.<repo_id>` in the server config:

```yaml
repos:
  my-project:
    model: opus                       # Default Claude model
    effort: max                       # Default effort level (optional)

    resource_limits:                  # Container resource limits (all optional)
      timeout: 6000                   # Max execution time in seconds (>= 10)
      memory: "4g"                    # Memory limit, e.g. "2g", "512m"
      cpus: 2                         # CPU limit (float, e.g. 1.5)
      pids_limit: 256                 # Process limit (fork bomb protection)

    network:
      sandbox_enabled: true           # Enforce network allowlist

    # Secrets pool — auto-injected as container env vars.
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN

    # Non-secret inline env vars for containers.
    container_env:
      R2_ACCOUNT_ID: "7ef1d25e..."

    # Credential types (auto-inject surrogates):
    masked_secrets: { ... }
    signing_credentials: { ... }
    github_app_credentials: { ... }

    git:
      repo_url: https://github.com/org/repo.git
    email: { ... }
    slack: { ... }
```

### Per-Repo Fields

| Field                        | Type    | Default  | Description                                       |
| ---------------------------- | ------- | -------- | ------------------------------------------------- |
| `model`                      | string  | `"opus"` | Claude model for new conversations                |
| `effort`                     | string  | *(none)* | Effort level passed as `--effort` to Claude Code  |
| `resource_limits.timeout`    | int     | *(none)* | Max container execution time in seconds (>= 10)   |
| `resource_limits.memory`     | string  | *(none)* | Memory limit, e.g. `"2g"`, `"512m"`               |
| `resource_limits.cpus`       | float   | *(none)* | CPU limit (>= 0.01, supports fractional cores)    |
| `resource_limits.pids_limit` | int     | *(none)* | Process limit (>= 1)                              |
| `network.sandbox_enabled`    | bool    | `true`   | Whether to enforce network allowlist              |
| `secrets`                    | mapping | `{}`     | Secret pool — auto-injected as container env vars |
| `container_env`              | mapping | `{}`     | Non-secret env vars for containers                |
| `masked_secrets`             | mapping | `{}`     | Scope-restricted secrets with proxy replacement   |
| `signing_credentials`        | mapping | `{}`     | AWS SigV4 credentials for proxy re-signing        |
| `github_app_credentials`     | mapping | `{}`     | GitHub App credentials with token rotation        |

## Container Environment Resolution

The final `container_env` dict passed to the container is built by merging these
layers (later layers win on key conflict):

```
1. Server repos.<id>.secrets         — auto-injected (pool key = env var name)
2. Server repos.<id>.container_env   — non-secret inline values
3. Credential surrogates             — from masked_secrets, signing_credentials,
                                       github_app_credentials (auto-injected)
```

Priority within layer 3: signing > GitHub App > masked > plain.

## Model and Effort Resolution

Precedence for new conversations:

| Priority | Model                       | Effort                       |
| -------- | --------------------------- | ---------------------------- |
| 1        | `repos.<id>.model` (server) | `repos.<id>.effort` (server) |
| 2        | channel `model_hint`        | *(none — Claude default)*    |
| 3        | `"opus"` (built-in default) |                              |

Resumed conversations always use the model and effort stored at conversation
creation time.

## Resource Limit Resolution

```
effective = server repos.<id>.resource_limits
            clamp to global resource_limits ceilings
```

Memory comparison is done in bytes (e.g. `"4g"` vs `"8g"`).

## Network Sandbox

Controlled solely by `repos.<id>.network.sandbox_enabled` (default: `true`).

See
[doc/network-sandbox.md](../doc/network-sandbox.md#enablingdisabling-the-sandbox)
for details and
[masked secrets interaction](../spec/masked-secrets.md#network-sandbox-requirement).

## Server-Wide Settings

### Global Resource Limit Ceilings

```yaml
# ~/.config/airut/airut.yaml (top-level)
resource_limits:
  timeout: 7200       # Max allowed timeout (seconds)
  memory: "8g"        # Max allowed memory
  cpus: 4             # Max allowed CPUs
  pids_limit: 1024    # Max allowed process count
```

These are **ceilings only** — per-repo limits are clamped to these values.

### Other Server-Wide Fields

- `email.*` — Email channel settings nested under `email:`
- `slack.*` — Slack channel settings nested under `slack:`
- `git.repo_url` — Repository to clone
- `execution.*` — `max_concurrent`, `shutdown_timeout`,
  `conversation_max_age_days`, `image_prune`
- `dashboard.*` — Web UI configuration
- `container_command` — Container runtime (podman/docker)

**Important:** All channel-specific fields must be nested under their channel
block (`email:` or `slack:`). A repo must have at least one channel block.

## Loading Flow

1. Service starts, loads server config (`ServerConfig.from_yaml()`)
2. Mirror is updated (`mirror.update_mirror()`)
3. Per-conversation: `RepoConfig.from_server_config(server_config)`:
   1. Build `container_env` from server secrets + server container_env
   2. Auto-inject credential surrogates for all configured credentials
   3. Clamp resource limits to global ceilings
4. Fields are validated (timeout >= 10, etc.)

## Multi-Repo Support

The server supports multiple repositories. Each repo is defined under `repos:`
in the server config with its own channel blocks, storage directory, and secrets
pool. See `multi-repo.md` for the full design.

## Proxy Manager Lifecycle

Since `network.sandbox_enabled` is per-repo (per-conversation), the
`ProxyManager` is always created and its gateway infrastructure (egress network,
proxy image, CA cert) is set up at startup. Per-conversation proxy containers
are only started when the effective sandbox setting is `true`.
