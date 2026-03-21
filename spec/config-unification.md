# Config Unification

Move all repo configuration into the server config. The gateway no longer reads
`.airut/airut.yaml` from the git mirror.

## Motivation

The previous split between server config and repo config created friction:

- **Most repo config fields are never changed by the agent.** Unlike
  `network-allowlist.yaml` (which the agent proposes changes to via PR),
  `airut.yaml` is static configuration that operators set once.
- **Duplication.** Model, effort, and network sandbox were configurable on both
  sides with override semantics. Resource limits had ceilings on the server and
  values in the repo.
- **Config is scattered.** Managing an Airut deployment required editing both
  the server YAML and each repo's `.airut/airut.yaml`. This blocked a planned
  dashboard UI for config management.
- **`!secret` indirection was unnecessary.** Every known deployment used
  `KEY: !secret KEY` (same name on both sides). The `!secret?` optional pattern
  was a hack for servers with different secret pools.

## Design

### Server config is the sole source

All per-repo operational settings are configured under `repos.<id>` in the
server config:

```yaml
repos:
  my-project:
    model: opus
    effort: max

    resource_limits:
      timeout: 6000
      memory: "4g"
      cpus: 2
      pids_limit: 256

    network:
      sandbox_enabled: true

    container_env:              # Non-secret env vars
      R2_ACCOUNT_ID: "7ef1d25e..."
      CI: "true"

    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN
    masked_secrets: { ... }
    github_app_credentials: { ... }
    git:
      repo_url: https://github.com/org/repo.git
    email: { ... }
```

### Auto-injection replaces `!secret`

All entries in `repos.<id>.secrets` are automatically injected into the
container environment using the pool key as the env var name. Masked secrets,
signing credentials, and GitHub App credentials auto-inject surrogates under
their credential key name.

The `!secret`/`!secret?` YAML tag system is removed entirely. There is no
repo-side YAML to parse.

### Container environment resolution

The final `container_env` dict passed to the container is built by layering
(later layers win on key conflict):

```
1. Server repos.<id>.secrets       -- auto-injected as env vars (key = env name)
2. Server repos.<id>.container_env -- non-secret inline values
3. Credential surrogates           -- from masked_secrets, signing_credentials,
                                      github_app_credentials (auto-injected)
```

Credential surrogates (layer 3) overwrite plain secrets (layer 1) for the same
key name. Priority: signing > GitHub App > masked > plain.

### What stays in `.airut/`

- **`network-allowlist.yaml`** -- must stay in repo. The agent proposes changes
  via PR; humans review before merge.
- **`container/Dockerfile`** -- must stay in repo. Build context is
  repo-specific.
- **`sandbox.yaml`** -- already separate (sandbox-cli only, not used by
  gateway).

### Model and effort resolution

| Priority | Model                       | Effort                       |
| -------- | --------------------------- | ---------------------------- |
| 1        | `repos.<id>.model` (server) | `repos.<id>.effort` (server) |
| 2        | channel `model_hint`        | *(none -- Claude default)*   |
| 3        | `"opus"` (built-in default) |                              |

### Resource limit resolution

```
per_repo_limits = server repos.<id>.resource_limits
                  clamped to global resource_limits (ceiling)
```

### Network sandbox

Controlled solely by `repos.<id>.network.sandbox_enabled` (default: `true`).

## Schema Changes

### New fields in `RepoServerConfig`

| Field             | Type    | Default            | Description                                  |
| ----------------- | ------- | ------------------ | -------------------------------------------- |
| `resource_limits` | object  | `ResourceLimits()` | Per-repo resource limits (not just ceilings) |
| `container_env`   | mapping | `{}`               | Non-secret env vars for containers           |

The existing `model` and `effort` fields change semantics from "override" to
"primary source" but remain structurally identical.

### Removed

- `RepoConfig.from_mirror()` -- replaced by `RepoConfig.from_server_config()`
- `_resolve_container_env()` -- no longer needed (no `!secret` resolution)
- `_SecretRef`, `_make_repo_loader`, `_reject_stray_secret_refs` -- all removed
- `_SigningSecretInfo`, `_build_signing_secret_map` -- only used by above
- `RepoConfig.CONFIG_PATH` -- no file to read

## Migration

Operators who had `.airut/airut.yaml` checked in need to:

1. Move `container_env` entries (like `GH_TOKEN: !secret GH_TOKEN`) to the
   server config's `secrets` pool (the key IS the env var name now)
2. Move `default_model` / `default_effort` to server `model` / `effort`
3. Move `resource_limits` to server per-repo `resource_limits`
4. Move `network.sandbox_enabled` to server per-repo `network.sandbox_enabled`
5. Delete `.airut/airut.yaml`

The recommended repo workflow: only check in `.airut/network-allowlist.yaml` and
optionally `.airut/container/Dockerfile`.
