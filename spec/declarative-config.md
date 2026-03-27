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
- Runtime config hot-reload — now covered by
  [config-reload.md](config-reload.md), which builds on the scoping groundwork
  defined here.

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
- `MaskedSecret` — masked secret credential entries
- `SigningCredentialField` — name/value pair within signing credentials
- `SigningCredential` — AWS SigV4 signing credential entries
- `GitHubAppCredential` — GitHub App credential entries

Credential types use `Scope.REPO` (they live under per-repo config). Secret
values (`MaskedSecret.value`, `SigningCredentialField.value`,
`SigningCredential.access_key_id/secret_access_key/session_token`,
`GitHubAppCredential.private_key`) are marked with `secret=True`.

**Excluded** from `FieldMeta` annotations:

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
`ConfigSnapshot` values. For dict-typed fields like `secrets` and
`masked_secrets`, the entire dict is the value — if the YAML key exists, the
whole dict is "provided." There is no per-entry tracking within these dicts
(credential pool entries use dynamic user-chosen keys).

#### Round-Trip Flow

```
load()           apply_migrations()    deepcopy → _raw    resolve vars + fields
Source ──────► raw nested dict ──────► raw dict ──────────► ConfigSnapshot
(YAML)         + config_version        (migrated)           .value (dataclass)
                                                            .provided_keys
                                                            .raw (preserved doc)

                  .raw (edit in place)          save()
ConfigSnapshot ──────────────────────► raw dict ──────► Source
                                       (tags intact)    (YAML)
```

**Tag-preserving round-trip:** `ConfigSnapshot.raw` holds a deep copy of the raw
YAML dict with `VarRef` and `EnvVar` objects preserved. The dashboard config
editor reads and modifies `.raw` directly, then saves via
`YamlConfigSource.save()` which uses custom YAML representers to emit `!var` and
`!env` tags. This preserves indirection end-to-end.

`to_dict()` continues to return **resolved** values for diffing and
change-detection. It is not used for the save path.

### Config Variables

A `vars:` top-level section and `!var` YAML tag provide value indirection.
Variables let multiple repos share values (server addresses, API keys, tokens)
from a single definition.

#### Syntax

```yaml
vars:
  mail_server: mail.example.com
  anthropic_key: sk-ant-api03-aBcDeFgHiJkLmNoPqRsT...
  azure_secret: !env AZURE_CLIENT_SECRET

repos:
  my-project:
    email:
      imap_server: !var mail_server
      smtp_server: !var mail_server
      password: !env EMAIL_PASSWORD    # !env still works directly
    secrets:
      ANTHROPIC_API_KEY: !var anthropic_key

  another-project:
    email:
      imap_server: !var mail_server
      smtp_server: !var mail_server
```

Variable values are **literals** or **`!env` references**. The `vars:` section
is a flat mapping — keys are variable names, values are scalars.

`!var name` references a variable by name, usable anywhere a YAML scalar value
is expected.

#### Design Boundaries

- No string interpolation (`${var}` embedding). `!var` replaces the entire
  scalar.
- No nested namespaces (`!var mail.server`). Flat `name: value` mapping.
- No var-to-var references (`vars: x: !var y`). Single-pass resolution, no cycle
  detection needed.

#### Resolution Pipeline

```
source.load()
  │  raw YAML dict with EnvVar + VarRef + vars: section
  ▼
apply_migrations()
  │  migrated raw dict (tags and vars: still present)
  ▼
doc_raw = deepcopy(raw)                    ← preserved for round-trip
  │
vars_table = resolve_vars_section(raw)     ← {name: resolved_str | None}
  │
work_raw = resolve_var_refs(raw, vars_table)
  │  VarRef replaced with resolved values; EnvVar still present
  │  vars: key removed
  ▼
ServerConfig._from_raw(work_raw)
  │  _resolve() handles EnvVar as today, builds frozen dataclasses
  ▼
ConfigSnapshot(instance, provided_keys, doc_raw)
```

Key properties:

- **`_from_raw()` and `_resolve()` are unchanged.** They never see `VarRef`.
- **`VarRef` and `EnvVar` flow through migrations unresolved**, consistent with
  the migration contract ("must not resolve `EnvVar` placeholders").
- **The vars table is ephemeral.** Computed during loading, used to resolve
  `VarRef` in the work copy, discarded. The `vars:` section in `doc_raw` is the
  durable source of truth.

#### Change Detection

Operates on **resolved values** — variable changes propagate automatically. When
a var value changes, all fields referencing it resolve differently, and
`diff_configs()` detects the changes. `diff_by_scope()` classifies them by the
scope of each referencing field. Variables don't need their own scope.

Edge case: renaming a var (without changing its value) produces zero diff. Same
resolved values → no effective change.

#### Dashboard Editor Interaction

The dashboard editor operates on `snapshot.raw`:

1. Read resolved values from `snapshot.value` for display. Detect indirection
   from `snapshot.raw` where values are `VarRef` / `EnvVar`.
2. Edit `snapshot.raw` directly — set literal, `!var`, or `!env`. Edit
   `raw["vars"]` to add / remove / rename variables.
3. Validate by resolving the modified raw dict through the resolution pipeline.
4. Save via `YamlConfigSource.save()` with tag representers.

#### Error Handling

| Condition                                 | Behavior                                                              |
| ----------------------------------------- | --------------------------------------------------------------------- |
| `!var unknown_name` (not in `vars:`)      | `ConfigError` at load time                                            |
| `!var` in vars values (`vars: x: !var y`) | `ConfigError` — var-to-var not allowed                                |
| `vars:` section absent                    | No-op, backward compatible                                            |
| `vars:` section empty                     | No-op                                                                 |
| `!var` used as mapping key                | `ConfigError` — scalar values only                                    |
| Non-scalar var value (list, dict)         | `ConfigError` — variable values must be scalars                       |
| Var value is `!env UNSET_VAR`             | `None` in vars table; downstream required-field validation catches it |

#### Secret Handling

Variables don't carry their own secret metadata. A variable used in a
`secret=True` field has its resolved value registered automatically through the
existing field-level mechanism in `__post_init__`. The dashboard derives which
vars hold secrets by cross-referencing `raw` values against field schema
metadata.

#### Schema Version

No config migration needed. `vars:` is a new top-level key silently ignored by
`_from_raw()` if not extracted first. Config version stays at 2. The feature is
purely additive.

#### Retiring .env

With `vars:`, secrets can live directly in `airut.yaml` — a local,
non-version-controlled file with the same security posture as `.env`.

- `!env` and `.env` loading remain functional. No breaking changes.
- New documentation recommends `vars:` for sharing values and consolidation.
- `.env` becomes optional — recommended only for environments that prefer
  env-var injection (containers, systemd `EnvironmentFile=`, etc.).

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

The UI calls `schema_for_ui()` on all annotated config classes — including
credential types (`MaskedSecret`, `SigningCredential`, `SigningCredentialField`,
`GitHubAppCredential`) — to render settings forms. Keyed credential collections
use `schema_for_ui()` on the item type to generate sub-forms within expandable
card widgets.

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
- `container_command` — container runtime binary (test-only, hidden from editor)
- `upstream_dns` — proxy DNS configuration

### `Scope.REPO` — Reloadable Per-Repo

Settings scoped to a repository, reloadable by restarting only that repo's
handler:

- `repos.*.git.repo_url` — git mirror target
- `repos.*.email.*` — email channel credentials and settings
- `repos.*.slack.*` — slack channel tokens and authorization
- `repos.*.network.sandbox_enabled` — proxy toggle
- `repos.*.container.path` — container directory path

### `Scope.TASK` — Applied Per-Task

Settings read at task creation time, effective immediately:

- `repos.*.model` — Claude model for new conversations
- `repos.*.effort` — effort level for new conversations
- `repos.*.resource_limits.*` — per-repo container limits (timeout, memory,
  cpus, pids)
- `repos.*.secrets` — plain secrets injected as env vars
- `repos.*.masked_secrets` — scoped secrets with proxy replacement
- `repos.*.signing_credentials` — AWS SigV4 re-signing credentials
- `repos.*.github_app_credentials` — proxy-managed GitHub App tokens

## Compatibility

### Config File Format

No breaking changes. Existing YAML files work without modification:

- `config_version` defaults to `1` when absent.
- Migrations are applied transparently on load.
- The YAML structure and `!env` tag behavior are unchanged.

### Python API

`from_source()` and `from_yaml()` return `ConfigSnapshot[ServerConfig]` instead
of `ServerConfig`. All callers access the resolved config via `.value`.

`to_dict()` continues to return resolved values. `diff_configs()` and
`diff_by_scope()` are unchanged.

Existing YAML files without `vars:` work identically — `resolve_vars_section()`
returns an empty table, `resolve_var_refs()` is a no-op.

### Relationship to spec/repo-config.md

This spec defines the config **infrastructure** (metadata, migration, diffing,
round-trip, variables). `spec/repo-config.md` remains the authoritative
reference for the config **schema** (what fields exist, their types, defaults,
and semantics). The `vars:` section and `!var` tag are documented there as part
of the config schema.
