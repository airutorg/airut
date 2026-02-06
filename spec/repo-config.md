# Repo Configuration

Airut splits configuration into two layers: **server config**
(`config/airut.yaml`) for deployment infrastructure and secrets, and **repo
config** (`.airut/airut.yaml`) for repo-specific behavior. Repo config is loaded
from the git mirror at the start of each task, so changes take effect after
merge to main without server restart.

## Repo Config Schema

File: `.airut/airut.yaml` (loaded from git mirror, not workspace)

```yaml
default_model: opus                    # Default Claude model
timeout: 6000                         # Max container execution time (seconds)

network:
  sandbox_enabled: true                # Enforce .airut/network-allowlist.yaml

container_env:                         # Environment variables for containers
  GH_TOKEN: !secret GH_TOKEN          # Required secret (error if missing)
  API_KEY: !secret? API_KEY           # Optional secret (skip if missing)
  R2_ACCOUNT_ID: "7ef1d25e..."        # Inline value (non-secret)
```

### Fields

| Field                     | Type    | Default  | Description                                       |
| ------------------------- | ------- | -------- | ------------------------------------------------- |
| `default_model`           | string  | `"opus"` | Claude model when not specified via subaddressing |
| `timeout`                 | int     | `300`    | Max container execution time in seconds (>= 10)   |
| `network.sandbox_enabled` | bool    | `true`   | Whether to enforce network allowlist              |
| `container_env`           | mapping | `{}`     | Environment variables passed to containers        |

### YAML Tags

- **`!secret NAME`** — Resolve value from the server's `secrets` pool. Errors if
  the server doesn't export that name.
- **`!secret? NAME`** — Optional secret. Resolve from the server's `secrets`
  pool if available; silently skip the entry if the secret is not defined. Use
  this for secrets that may or may not be configured on the server (e.g.,
  alternative authentication methods).
- **`!env` is NOT allowed** — Repo config cannot read server environment
  variables. This prevents repos from accessing arbitrary server state.

### Container Environment Variables

Values in `container_env` can be:

- **Inline strings** — Plain values committed to the repo (non-secrets like
  bucket names, account IDs).
- **`!secret` references** — Resolved from the server's secrets pool at task
  start. The repo declares which secrets it needs; the server provides the
  values.

Only entries that resolve to non-empty values are passed to the container. All
resolved values are registered for log redaction.

## Server Config Changes

The server config (`config/airut.yaml`) retains deployment-specific settings:

- `email.*` — Mail server connectivity and credentials
- `authorized_senders`, `trusted_authserv_id` — Access control
- `git.repo_url` — Repository to clone
- `storage_dir` — Server filesystem path
- `imap.*` — Polling configuration
- `execution.*` — `max_concurrent`, `shutdown_timeout`,
  `conversation_max_age_days`
- `dashboard.*` — Web UI configuration
- `container_command` — Container runtime (podman/docker)

The `container_env` block is replaced by `secrets` — a named pool of values that
repos can reference via `!secret`:

```yaml
secrets:
  CLAUDE_CODE_OAUTH_TOKEN: !env CLAUDE_CODE_OAUTH_TOKEN
  GH_TOKEN: !env GH_TOKEN
  R2_ACCESS_KEY_ID: !env R2_ACCESS_KEY_ID
```

Fields moved to repo config: `execution.timeout`, `execution.default_model`,
`container_env`.

### Server-Side Network Sandbox Override

The server config retains an optional `network.sandbox_enabled` field per repo
as a server-side override. The effective sandbox state is the logical AND of
both settings — either side can disable the sandbox independently. See
[doc/network-sandbox.md](../doc/network-sandbox.md#enablingdisabling-the-sandbox)
for details and
[masked secrets interaction](../spec/masked-secrets.md#network-sandbox-requirement).

## Loading Flow

1. Service starts, loads server config (`ServerConfig.from_yaml()`)
2. Mirror is updated (`mirror.update_mirror()`)
3. Per-task: `RepoConfig.from_mirror(mirror, server_secrets)` reads
   `.airut/airut.yaml` from the mirror's default branch
4. YAML is parsed with a custom loader that handles `!secret` and rejects `!env`
5. `!secret` references are resolved against the server's `secrets` dict
6. Resolved `container_env` values are registered with `SecretFilter`
7. Fields are validated (timeout >= 10, etc.)

## Multi-Repo Support

The server supports multiple repositories. Each repo is defined under `repos:`
in the server config with its own IMAP/SMTP, authorized sender, storage
directory, and secrets pool. See `multi-repo.md` for the full design.

## Proxy Manager Lifecycle

Since `network.sandbox_enabled` is now per-repo (per-task), the `ProxyManager`
is always created and its gateway infrastructure (egress network, proxy image,
CA cert) is set up at startup. Per-task proxy containers are only started when
the repo config has `sandbox_enabled: true`.
