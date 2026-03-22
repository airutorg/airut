# Declarative Configuration

A declarative configuration layer that decouples schema definition from
serialization, tracks user-set values, supports schema migration, and exposes
per-field metadata for UI rendering.

## Goals

1. **Format-agnostic** — swap YAML for TOML, JSON, or a database without
   changing config classes.
2. **Self-documenting** — each field carries human-readable documentation,
   constraints, and scope metadata, extractable at runtime for UI generation.
3. **Schema migration** — version-stamped configs with a chain of migration
   functions, applied automatically on load.
4. **Config diffing** — compare in-use config against freshly loaded config,
   grouped by reload scope.
5. **Scoped reload** — each field declares when changes take effect (server
   restart, repo reload, or next task), enabling future partial-reload support.
6. **Round-trip fidelity** — track which values the user explicitly set;
   serialize only those, never baking defaults into the file.

## Non-Goals

- Preserving YAML comments or formatting on round-trip.
- Supporting multiple config file merging / layered file sources. The server has
  a single config source; `!env` tags and `.env` files handle secret injection.
- Runtime config hot-reload (future work that builds on the scoping groundwork).

## Design

### No New Dependencies

The implementation builds on stdlib `dataclasses` and `dataclasses.field`
metadata, which the config system already uses. No external libraries are added.

### Field Metadata

Every config field carries a `FieldMeta` in its
`dataclasses.field(metadata=...)` with four attributes: `doc` (human-readable
description), `scope` (reload scope), `secret` (informational flag for UI
masking), and `since_version` (schema version that introduced the field). The
metadata dict uses the key `"airut_config"` to avoid collisions with other
metadata consumers.

Fields without `FieldMeta` (e.g. computed fields, internal state) are excluded
from schema introspection and serialization.

### Secret Handling

`FieldMeta.secret` is an **informational flag** for UI rendering (e.g. masking
password inputs, hiding values in diff output). It does **not** automatically
register values with `SecretFilter`.

Secret registration remains in `__post_init__` methods as it is today. The
existing manual calls to `SecretFilter.register_secret()` in
`EmailChannelConfig`, `SlackChannelConfig`, and `RepoServerConfig` are
unchanged. Derived secrets (surrogates) continue to be registered in
`_build_task_env()`.

### Which Classes Get Annotated

All frozen config dataclasses that represent user-visible settings receive
`FieldMeta` annotations:

- `GlobalConfig` — server-wide settings
- `RepoServerConfig` — per-repo settings
- `EmailChannelConfig` — email channel settings
- `SlackChannelConfig` — Slack channel settings
- `ResourceLimits` — container resource limits

**Excluded** from `FieldMeta` annotations:

- `MaskedSecret`, `SigningCredential`, `SigningCredentialField`,
  `GitHubAppCredential` — credential pool entries have dynamic keys (the user
  chooses env var names) and variable structure. They cannot be represented as
  fixed-schema UI forms. The UI will handle credential pools through a
  specialized key-value editor, not through `schema_for_ui()`.
- `ServerConfig` — a thin container for `GlobalConfig` + repos dict; not
  directly user-editable.
- Internal types like `ReplacementEntry`, `SigningCredentialEntry`,
  `GitHubAppEntry` — runtime-only, never in config files.

### Config Source Protocol

A `ConfigSource` protocol decouples loading and saving from the serialization
format. Implementations provide `load() -> dict[str, Any]` and
`save(data: dict[str, Any]) -> None`.

`ServerConfig.from_source(source)` calls `source.load()`, applies migrations,
then runs the existing resolution/validation pipeline.
`ServerConfig.from_yaml()` constructs a `YamlConfigSource` and delegates to
`from_source()`.

### YAML Structure Mapping

The YAML config uses nested sub-blocks (e.g. `execution.max_concurrent`,
`dashboard.host`, `email.imap.poll_interval`) that map to flat dataclass field
names (e.g. `max_concurrent_executions`, `dashboard_host`,
`poll_interval_seconds`). This nesting is a **serialization concern**, not a
schema concern.

`FieldMeta` intentionally does **not** encode YAML paths. The YAML structure is
a property of `YamlConfigSource`, not of the config schema. A future
`TomlConfigSource` or `DatabaseConfigSource` may use an entirely different
structure.

- **Serialization mapping** lives in `ConfigSource` implementations. Each source
  knows how to map its format to/from the canonical flat dict.
- **`to_dict()`** produces a flat dict keyed by dataclass field names (the
  canonical representation). `ConfigSource.save()` transforms this flat dict
  into the format-specific structure.
- **`provided_keys`** tracks dataclass field names (flat), not YAML paths.

### Tracking User-Set Values

`ConfigSnapshot[T]` wraps a frozen config dataclass, tracking which fields the
user explicitly set in the source data versus which fell through to defaults.
`to_dict(include_defaults=False)` serializes only user-set fields, preserving
round-trip fidelity.

#### Computing `provided_keys`

`provided_keys` uses **dataclass field names** (flat), not YAML keys. A field is
"provided" when its corresponding raw dict key exists, regardless of the
resolved value:

- `password: !env PASSWORD` where `$PASSWORD` is unset — the key exists, so the
  field **is** provided. Resolution may still raise `ConfigError`, but
  provenance tracking is separate from validation.
- `password:` (YAML null) — the key exists, so the field **is** provided.
- Key absent from YAML entirely — the field is **not** provided; the default
  applies.

This means `provided_keys` tracks **user intent** ("the user wrote this key in
the config file") rather than **resolved availability**.

#### Handling Nested and Polymorphic Fields

For `RepoServerConfig.channels` (`dict[str, ChannelConfig]`), each channel
config is wrapped in a `ConfigSnapshot`. `to_dict()` recurses into nested
`ConfigSnapshot` values. For dict-typed fields like `secrets`, `masked_secrets`,
and `container_env`, the entire dict is the value — if the YAML key exists, the
whole dict is "provided." There is no per-entry tracking within these dicts
(credential pool entries use dynamic user-chosen keys).

#### Round-Trip Flow

```
load()           apply_migrations()    resolve + track provided
Source ──────► raw nested dict ──────► raw nested dict ──────► ConfigSnapshot
(YAML)         + config_version        (migrated)               .value (dataclass)
                                                                .provided_keys

                          to_dict(defaults=False)     save()
ConfigSnapshot ──────► flat canonical dict ──────► Source
                       (user-set only)              (YAML)
```

**`!env` tags and round-trip:** `to_dict()` output contains **resolved** values,
not `EnvVar` placeholders. A round-trip through `to_dict()` + `save()` replaces
`!env` references with their resolved string values. This is acceptable because
config files using `!env` tags are typically not edited via UI round-trip; users
who want to preserve `!env` tags edit the YAML file directly.

### Schema Migration

Each config file carries a `config_version` integer (defaults to `1` when
absent). On load, migrations are applied sequentially from the file's version to
the current version.

#### Migration Contract

Each migration function:

- Takes a raw `dict` (the full config as parsed from the source, pre-resolution)
- Returns a new `dict` (the transformed config)
- Must be **idempotent** (safe to apply to already-migrated data)
- Must not resolve `EnvVar` placeholders — those are resolved after migration
- Must handle missing keys gracefully (the key may not exist in every config)

Migrations run in `ServerConfig.from_source()` after `source.load()` and before
resolution/validation.

#### Security-Sensitive Migrations

Some migrations involve fields that affect authorization (e.g.
`authorized_senders`). For these, the migration function must **reject the
config with a `ConfigError`** rather than silently transforming it.

The rule: migration functions may automatically transform **non-security** field
renames and restructuring, but must raise `ConfigError` for changes that could
affect authentication or authorization if the automatic transformation has a
bug.

### Config Diffing

Two functions support comparing config states:

- `diff_configs[T]` — returns `{field_name: (old_value, new_value)}` for
  differing fields. Only compares fields set in at least one snapshot. Nested
  `ConfigSnapshot` values are unwrapped for comparison.
- `diff_by_scope[T]` — groups changes by reload scope. Returns
  `{Scope: {field_name: (old, new)}}` with all scopes present (empty scopes have
  empty dicts). Fields without `FieldMeta` default to `Scope.SERVER`.

Diff output contains actual values; consumers must check `FieldMeta.secret` and
mask values before logging or UI display.

#### Use Cases

- **Dashboard UI**: show which settings changed and whether a restart is needed.
- **Future live reload**: if `diff_by_scope()` returns changes only in
  `Scope.TASK`, apply them without any restart. If `Scope.REPO` changes exist,
  restart only affected repos.
- **Audit**: log what changed on config reload (with secret masking).

### Schema Introspection

`schema_for_ui(config_cls)` extracts UI-friendly `FieldSchema` records from any
annotated config class. Each record includes field name, type annotation as
string, default value, required flag, documentation, scope, and secret flag.

The UI calls `schema_for_ui(GlobalConfig)` and `schema_for_ui(RepoServerConfig)`
to render settings forms. Credential pool entries are not covered — the UI
handles these through specialized key-value editors.

## Scope Assignments

All config fields are assigned one of three scopes. Scopes describe the
**intended** granularity of reload. Currently all changes require a full server
restart. The scope metadata enables future partial-reload support.

### `Scope.SERVER` — Requires Full Server Restart

Settings that affect server-wide infrastructure or shared resources:

- `execution.max_concurrent` — thread pool size
- `execution.shutdown_timeout` — shutdown behavior
- `execution.conversation_max_age_days` — GC policy
- `execution.image_prune` — GC policy
- `dashboard.*` — HTTP server lifecycle
- `container_command` — container runtime binary
- `upstream_dns` — proxy DNS configuration

### `Scope.REPO` — Reloadable Per-Repo

Settings scoped to a repository, reloadable by restarting only that repo's
handler:

- `repos.*.git.repo_url` — git mirror target
- `repos.*.email.*` — email channel credentials and settings
- `repos.*.slack.*` — slack channel tokens and authorization
- `repos.*.secrets` — credential pools
- `repos.*.masked_secrets` — scoped credentials
- `repos.*.signing_credentials` — AWS re-signing
- `repos.*.github_app_credentials` — GitHub App tokens
- `repos.*.network.sandbox_enabled` — proxy toggle

### `Scope.TASK` — Applied Per-Task

Settings read at task creation time, effective immediately:

- `repos.*.model` — Claude model for new conversations
- `repos.*.effort` — effort level for new conversations
- `repos.*.resource_limits.*` — per-repo container limits (timeout, memory,
  cpus, pids)
- `repos.*.container_env` — plain environment variables

## Compatibility

### Config File Format

No breaking changes. Existing YAML files work without modification:

- `config_version` defaults to `1` when absent.
- Migrations are applied transparently on load.
- The YAML structure and `!env` tag behavior are unchanged.

### Python API

`ServerConfig.from_yaml()` continues to work unchanged. New code uses
`ServerConfig.from_source()` and `ConfigSnapshot`, but the old path is
preserved.

### Relationship to spec/repo-config.md

This spec defines the config **infrastructure** (metadata, migration, diffing,
round-trip). `spec/repo-config.md` remains the authoritative reference for the
config **schema** (what fields exist, their types, defaults, and semantics).
