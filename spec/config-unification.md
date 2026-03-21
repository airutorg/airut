# Config Unification

Move repo-level configuration (`.airut/airut.yaml`) into the server config so
that all operational settings are managed in one place. This enables future
dashboard-based config management and eliminates the need for repos to maintain
an `airut.yaml` file.

## Motivation

The current split between server config and repo config creates friction:

- **Most repo config fields are never changed by the agent.** Unlike
  `network-allowlist.yaml` (which the agent proposes changes to via PR),
  `airut.yaml` is static configuration that operators set once.
- **Duplication.** Model, effort, and network sandbox are already configurable
  on both sides with override semantics. Resource limits have ceilings on the
  server and values in the repo.
- **Config is scattered.** Managing an Airut deployment requires editing both
  the server YAML and each repo's `.airut/airut.yaml`. This blocks a planned
  dashboard UI for config management.

## Design

### Server config becomes the primary source

All fields currently in `.airut/airut.yaml` become configurable per-repo in the
server config under `repos.<id>`:

```yaml
repos:
  my-project:
    model: opus                       # was default_model in repo config
    effort: max                       # was default_effort in repo config

    resource_limits:                  # was in repo config; server had ceilings only
      timeout: 6000
      memory: "4g"
      cpus: 2
      pids_limit: 256

    network:
      sandbox_enabled: true           # was in both (logical AND)

    container_env:                    # NEW: non-secret env vars for containers
      R2_ACCOUNT_ID: "7ef1d25e..."
      CI: "true"

    # Existing fields (unchanged):
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
      GH_TOKEN: !env GH_TOKEN
    masked_secrets: { ... }
    github_app_credentials: { ... }
    git:
      repo_url: https://github.com/org/repo.git
    email: { ... }
```

### Plain secrets are auto-injected as container env vars

All entries in `repos.<id>.secrets` are automatically injected into the
container environment using the pool key as the env var name. This replaces the
`!secret` indirection in repo config for the common case (where env var name =
secret pool key, which is true for all known deployments).

Masked secrets, signing credentials, and GitHub App credentials continue to
generate surrogates that are auto-injected into the container environment under
their credential key name. No repo-side `container_env` declaration is needed.

The new `repos.<id>.container_env` block provides non-secret inline values
(bucket names, flags, etc.) that are also injected.

### Repo config is optional (backwards compatibility)

If `.airut/airut.yaml` exists in the repo, it is loaded and its values are
merged on top of the server-derived defaults. **Repo config wins on conflict**
for `container_env` entries (per-key merge). For scalar fields (`model`,
`effort`, `resource_limits`, `network.sandbox_enabled`), the server value takes
precedence (matching current override behavior).

If the file does not exist, `RepoConfig` is built entirely from server config
values with built-in defaults. No error is raised.

### What stays in `.airut/`

- **`network-allowlist.yaml`** -- must stay in repo. The agent proposes changes
  via PR; humans review before merge. This is the right workflow.
- **`container/Dockerfile`** -- must stay in repo. Build context is
  repo-specific.
- **`sandbox.yaml`** -- already separate (sandbox-cli only, not used by
  gateway).
- **`airut.yaml`** -- optional. If present, provides `container_env` overrides
  (e.g., renaming secrets to different env var names via `!secret` tags).

## Schema Changes

### New fields in `RepoServerConfig`

| Field             | Type    | Default            | Description                                  |
| ----------------- | ------- | ------------------ | -------------------------------------------- |
| `resource_limits` | object  | `ResourceLimits()` | Per-repo resource limits (not just ceilings) |
| `container_env`   | mapping | `{}`               | Non-secret env vars for containers           |

The existing `model` and `effort` fields change semantics from "override" to
"primary source" but remain structurally identical.

### Server-wide `resource_limits` remain as ceilings

The global `resource_limits` block retains its role as a ceiling. Per-repo
limits (whether from server per-repo config or repo-side config) are still
clamped to the global ceiling.

### Container environment resolution order

The final `container_env` dict passed to the container is built by merging these
layers (later layers win on key conflict):

**When no repo-side `container_env` exists** (common case — server-only config):

```
1. Server repos.<id>.secrets       -- auto-injected as env vars (key = env var name)
2. Server repos.<id>.container_env -- non-secret inline values
3. Credential surrogates           -- from masked_secrets, signing_credentials,
                                      github_app_credentials (auto-injected)
```

Credential surrogates (layer 3) overwrite plain secrets (layer 1) for the same
key name. Priority: signing > GitHub App > masked > plain.

**When repo-side `container_env` exists** (backwards-compat for renaming
secrets):

```
1. Server repos.<id>.secrets       -- auto-injected as env vars
2. Server repos.<id>.container_env -- non-secret inline values
3. Repo container_env entries      -- resolved via _resolve_container_env
                                      (!secret refs generate surrogates)
```

Layer 3 (repo-side) can rename secrets via `!secret` tags, add inline values, or
override any key from layers 1-2. Only credentials explicitly referenced via
`!secret` in the repo `container_env` get surrogates; unreferenced credentials
remain as plain values from layer 1.

### Model and effort resolution

Unchanged from current behavior (built-in default made explicit):

| Priority | Model                                 | Effort                                 |
| -------- | ------------------------------------- | -------------------------------------- |
| 1        | `repos.<id>.model` (server)           | `repos.<id>.effort` (server)           |
| 2        | channel `model_hint`                  | repo `default_effort` (if file exists) |
| 3        | repo `default_model` (if file exists) | *(none -- Claude default)*             |
| 4        | `"opus"` (built-in default)           |                                        |

### Network sandbox resolution

Simplified: when repo config exists, the effective value is the logical AND of
server and repo settings (current behavior). When repo config does not exist,
only the server setting applies.

### Resource limit resolution

```
per_repo_limits = server repos.<id>.resource_limits   (primary)
                  merged with repo .airut/airut.yaml   (if exists, fills gaps only)
                  clamped to global resource_limits     (ceiling)
```

"Fills gaps only" means repo-side limits only apply for fields not set in the
server per-repo config.

## Implementation

### `config.py` changes

1. Add `resource_limits: ResourceLimits` and `container_env: dict[str, str]` to
   `RepoServerConfig`.

2. Parse these new fields in `_parse_repo_server_config()`.

3. Add `RepoServerConfig` parameter to `RepoConfig.from_mirror()` (replaces the
   individual `server_secrets`, `masked_secrets`, etc. parameters).

4. In `RepoConfig.from_mirror()`:

   - Try to read `.airut/airut.yaml` from the mirror. If the file does not
     exist, use an empty dict as `raw`.
   - Build the base `container_env` from server config: start with
     `server_config.secrets`, overlay `server_config.container_env`.
   - Resolve credential surrogates for masked/signing/app credentials into the
     env dict.
   - If repo config exists, resolve its `container_env` entries and merge on top
     (repo wins per key).
   - For scalar fields: use server values as defaults, repo values fill gaps.

### `message_processing.py` changes

5. Pass the full `RepoServerConfig` to `RepoConfig.from_mirror()` instead of
   unpacking individual fields.

### Config example and spec updates

6. Update `config/airut.example.yaml` with the new per-repo fields.

7. Update `spec/repo-config.md` to reflect the new resolution order.

## Migration

No breaking changes. Existing setups with `.airut/airut.yaml` continue to work
identically. Operators can gradually move settings to server config and
eventually remove the repo-side file.

The recommended new-repo workflow becomes: configure everything in server
config, only check in `.airut/network-allowlist.yaml` and optionally
`.airut/container/Dockerfile`.
