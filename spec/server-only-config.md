# Server-Only Configuration

## Summary

Move all configuration currently in `.airut/airut.yaml` (repo config) to the
server config (`~/.config/airut/airut.yaml`), making server config the single
source of truth for all operational settings. Repo-side `.airut/airut.yaml` is
no longer read by the gateway.

## Motivation

1. **Repo config is redundant** — Server config already has override fields for
   `model`, `effort`, `network.sandbox_enabled`, and resource limit ceilings.
   The repo config just duplicates these with extra indirection.

2. **`!secret` indirection is unused** — The renaming capability
   (`MY_TOKEN: !secret GH_TOKEN`) exists but is never used in practice. Secret
   names always match env var names.

3. **Complexity cost** — The `!secret`/`!secret?` resolution chain (~520 lines)
   parses YAML with a custom loader, creates placeholder objects, resolves them
   against 4 credential pools with priority ordering, generates surrogates, and
   clamps resource limits. All of this indirection serves no practical purpose.

4. **Dashboard config editing** — Long-term goal is managing server config from
   the web dashboard. This is only practical when config is not scattered
   between repo and server.

## Design

### What stays in the repo

- `.airut/network-allowlist.yaml` — Agent proposes changes to this.
- `.airut/container/Dockerfile` — Agent proposes changes to this.
- `.airut/sandbox.yaml` — Used by `sandbox-action`, not by the gateway.
- `.airut/README.md` — Updated to document the remaining files.

### What moves to server config

All fields from `.airut/airut.yaml` move to per-repo server config:

| Old location (repo)              | New location (server `repos.<id>.*`)                         |
| -------------------------------- | ------------------------------------------------------------ |
| `default_model`                  | `model` (existing field, semantics change)                   |
| `default_effort`                 | `effort` (existing field, semantics change)                  |
| `resource_limits.*`              | `resource_limits.*` (existing field, semantics change)       |
| `network.sandbox_enabled`        | `network.sandbox_enabled` (existing field, semantics change) |
| `container_env` (inline values)  | `container_env` (new field)                                  |
| `container_env` (`!secret` refs) | Automatic — credentials inject by name                       |

### Server config per-repo schema (new)

```yaml
repos:
  my-project:
    git:
      repo_url: https://github.com/org/repo.git

    # Default Claude model for new conversations.
    # Channel hints (email subaddressing) override this.
    # Resumed conversations use their stored model.
    # Default: "opus"
    model: opus

    # Default effort level for Claude Code.
    # Omit to use Claude Code's built-in default.
    # effort: max

    # Container resource limits (all optional — omitted = no limit).
    # resource_limits:
    #   timeout: 6000
    #   memory: "4g"
    #   cpus: 2
    #   pids_limit: 256

    # Network sandbox (default: true).
    # network:
    #   sandbox_enabled: true

    # Plain environment variables passed to containers.
    # For non-secret values like account IDs, bucket names, etc.
    # container_env:
    #   R2_ACCOUNT_ID: "7ef1d25e..."

    # Credentials — all entries auto-inject into container env.
    # The key name becomes the environment variable name.
    secrets:
      ANTHROPIC_API_KEY: !env ANTHROPIC_API_KEY
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes: ["api.github.com", "*.githubusercontent.com"]
        headers: ["Authorization"]
    # signing_credentials: ...
    # github_app_credentials: ...

    email: ...
    slack: ...
```

### Credential auto-injection

All credentials from all pools are automatically injected into the container
environment using their key/name as the env var name. No manual mapping needed.

**Resolution priority** (when the same env var name appears in multiple pools):

1. Signing credentials (by field `.name`)
2. GitHub App credentials (by key)
3. Masked secrets (by key)
4. Plain secrets (by key)
5. `container_env` (by key) — lowest priority, plain values only

This matches the existing priority order. The only change is that it's implicit
(all credentials inject) rather than explicit (`!secret` references).

### Semantics changes

**`model` and `effort`**: Previously these were "server overrides" that took
precedence over repo defaults. Now they are simply the defaults (since repo
config no longer exists). Channel hints still override `model` for new
conversations. Resumed conversations still use stored values.

New precedence for new conversations:

| Priority | Model                | Effort              |
| -------- | -------------------- | ------------------- |
| 1        | channel `model_hint` | `repos.<id>.effort` |
| 2        | `repos.<id>.model`   | *(Claude default)*  |
| 3        | `"opus"` (fallback)  |                     |

**`resource_limits`**: Previously repo set values and server set ceilings, with
clamping. Now server sets values directly. The server-wide `resource_limits`
block remains as ceilings — per-repo values are clamped to these. This preserves
the safety mechanism (server-wide ceiling prevents any single repo from
consuming excessive resources).

**`network.sandbox_enabled`**: Previously AND of server and repo flags. Now a
single server-side flag. Default: `true`.

### What gets removed from code

1. **`RepoConfig` class** — Eliminated. Its fields move to `RepoServerConfig`.
2. **`RepoConfig.from_mirror()`** — No longer reads `.airut/airut.yaml`.
3. **`_SecretRef`** class and YAML constructors — Eliminated.
4. **`_make_repo_loader()`** — Eliminated.
5. **`_resolve_container_env()`** — Replaced by `_build_container_env()` that
   works directly from server config credential pools.
6. **`_reject_stray_secret_refs()`**, **`_check_secret_ref()`** — Eliminated.
7. **`_build_signing_secret_map()`** — Inlined into new env builder.
8. **Resource limit clamping in `RepoConfig._from_raw()`** — Moves to
   `RepoServerConfig` post-init or to message processing.

### New code

A new function `build_task_env()` (or similar) on `RepoServerConfig` builds the
container environment and replacement map per-task:

1. Iterate signing credentials → generate surrogates, add to env + replacement
   map
2. Iterate GitHub App credentials → generate surrogates, add to env +
   replacement map
3. Iterate masked secrets → generate surrogates, add to env + replacement map
4. Iterate plain secrets → add directly to env
5. Merge `container_env` (plain values) — skip any keys already set by
   credentials
6. Return `(container_env: dict[str, str], replacement_map: ReplacementMap)`

This replaces both `RepoConfig.from_mirror()` and `_resolve_container_env()`.

### `message_processing.py` changes

Before:

```python
repo_config, replacement_map = RepoConfig.from_mirror(
    conv_mgr.mirror,
    repo_handler.config.secrets,
    repo_handler.config.masked_secrets,
    repo_handler.config.signing_credentials,
    repo_handler.config.github_app_credentials,
    server_sandbox_enabled=repo_handler.config.network_sandbox_enabled,
    server_resource_limits=service.global_config.resource_limits,
)
model = server_model or parsed.model_hint or repo_config.default_model
effort = server_effort or repo_config.default_effort
env = ContainerEnv(variables=repo_config.container_env)
```

After:

```python
container_env, replacement_map = repo_handler.config.build_task_env()
model = parsed.model_hint or repo_handler.config.model or "opus"
effort = repo_handler.config.effort
env = ContainerEnv(variables=container_env)
```

### Backwards compatibility

**Warning on ignored repo config**: If `.airut/airut.yaml` exists in a repo's
git mirror, log a warning at task start:

```
Repo 'X': .airut/airut.yaml found but ignored — all configuration
is now in server config. See doc/repo-onboarding.md for migration.
```

This helps operators notice and clean up stale repo config files.

### Breaking change

Repos that use `!secret` to rename env vars (`MY_TOKEN: !secret GH_TOKEN`) will
break. This capability is not used in practice. No migration path is provided
for this case — operators must rename their credential keys in server config to
match the desired env var name.

## Documentation updates

Every file that references repo config, `.airut/airut.yaml`, `!secret`,
`container_env` in repo context, `default_model`, `default_effort`, or resource
limit clamping must be updated.

### Spec files

| File                            | Changes                                                               |
| ------------------------------- | --------------------------------------------------------------------- |
| `spec/repo-config.md`           | Major rewrite — remove repo config schema, document server-only model |
| `spec/multi-repo.md`            | Update config class references, remove `RepoConfig` mentions          |
| `spec/gateway-architecture.md`  | Update config flow description                                        |
| `spec/masked-secrets.md`        | Remove `!secret` references, document auto-injection                  |
| `spec/aws-sigv4-resigning.md`   | Remove `!secret` references for signing credentials                   |
| `spec/github-app-credential.md` | Remove `!secret` references if any                                    |

### Doc files

| File                       | Changes                                              |
| -------------------------- | ---------------------------------------------------- |
| `doc/repo-onboarding.md`   | Remove "Configure Repo Settings" step for airut.yaml |
| `doc/gerrit-onboarding.md` | Same                                                 |
| `doc/execution-sandbox.md` | Update resource limits section                       |
| `doc/network-sandbox.md`   | Update sandbox_enabled description (single flag)     |
| `doc/security.md`          | Update credential isolation description              |
| `doc/email-setup.md`       | Update if it references container_env                |
| `doc/github-app-setup.md`  | Update secret references                             |
| `doc/deployment.md`        | Update if it references repo config                  |

### Config and repo files

| File                        | Changes                                                                |
| --------------------------- | ---------------------------------------------------------------------- |
| `config/airut.example.yaml` | Add `container_env`, `model`, `resource_limits` to per-repo section    |
| `.airut/README.md`          | Remove airut.yaml documentation, keep allowlist/container/sandbox docs |
| `.airut/airut.yaml`         | Delete                                                                 |
| `CLAUDE.md`                 | Update project structure and config references                         |

### Test files

| File                                                | Changes                                           |
| --------------------------------------------------- | ------------------------------------------------- |
| `tests/gateway/test_config.py`                      | Rewrite RepoConfig tests → RepoServerConfig tests |
| `tests/gateway/service/test_message_processing.py`  | Update to use server config                       |
| `tests/integration/gateway/test_resource_limits.py` | Update for server-side limits                     |
| `tests/integration/gateway/environment.py`          | Remove .airut/airut.yaml fixture                  |

## Implementation order

1. Add `container_env`, `model` default, `resource_limits` to `RepoServerConfig`
2. Add `build_task_env()` method to `RepoServerConfig`
3. Update `message_processing.py` to use server config directly
4. Remove `RepoConfig` class and all `!secret` machinery
5. Update all tests
6. Update all specs and docs
7. Delete `.airut/airut.yaml`
8. Run CI, fix issues
