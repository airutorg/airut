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

Every config field carries a `FieldMeta` dataclass in its
`dataclasses.field(metadata=...)`:

```python
from dataclasses import dataclass
from enum import Enum


class Scope(Enum):
    """When does a change to this setting take effect?"""

    SERVER = "server"  # Requires full server restart
    REPO = "repo"  # Reloadable per-repo without server restart
    TASK = "task"  # Applied per-task, effective immediately


@dataclass(frozen=True)
class FieldMeta:
    """Declarative metadata for a config field."""

    doc: str  # Human-readable description
    scope: Scope  # Reload scope
    secret: bool = False  # Auto-register with SecretFilter
    since_version: int = 1  # Schema version that introduced this
    removed_version: int | None = None  # Schema version that removed it
    yaml_key: str | None = (
        None  # Override key name in YAML (None = use field name)
    )
```

A helper keeps field declarations concise:

```python
def meta(doc: str, scope: Scope, **kwargs) -> dict[str, FieldMeta]:
    """Attach FieldMeta via dataclass field(metadata=meta(...))."""
    return {"config": FieldMeta(doc=doc, scope=scope, **kwargs)}
```

### Annotated Config Classes

Existing frozen dataclasses gain metadata without changing their runtime
behavior. Validation stays in `__post_init__` methods.

```python
@dataclass(frozen=True)
class GlobalConfig:
    max_concurrent_executions: int = field(
        default=3,
        metadata=meta(
            "Maximum parallel Claude containers across all repos",
            Scope.SERVER,
        ),
    )
    shutdown_timeout_seconds: int = field(
        default=60,
        metadata=meta(
            "Seconds to wait for running tasks during graceful shutdown",
            Scope.SERVER,
        ),
    )
    dashboard_enabled: bool = field(
        default=True,
        metadata=meta(
            "Enable the web dashboard for task monitoring", Scope.SERVER
        ),
    )
    dashboard_host: str = field(
        default="127.0.0.1",
        metadata=meta("Dashboard HTTP server bind address", Scope.SERVER),
    )
    dashboard_port: int = field(
        default=5200,
        metadata=meta("Dashboard HTTP server port", Scope.SERVER),
    )
    # ... remaining fields follow the same pattern
```

Fields without `FieldMeta` (e.g. computed fields, internal state) are excluded
from schema introspection and serialization.

### Config Source Protocol

A `ConfigSource` protocol decouples loading and saving from the serialization
format:

```python
from typing import Protocol


class ConfigSource(Protocol):
    """Read/write raw config dicts from any backing store."""

    def load(self) -> dict[str, Any]:
        """Load raw config dict. Values may contain EnvVar placeholders."""
        ...

    def save(self, data: dict[str, Any]) -> None:
        """Write raw config dict back to the backing store."""
        ...
```

Implementations:

- `YamlConfigSource(path)` — current YAML file loading (wraps existing
  `yaml.load` with `make_env_loader()`)
- Future: `TomlConfigSource`, `JsonConfigSource`, `DatabaseConfigSource`

`ServerConfig` gains a `from_source(source: ConfigSource)` class method that
calls `source.load()`, applies migrations, then runs the existing
resolution/validation pipeline. The current `from_yaml()` becomes a thin wrapper
that constructs a `YamlConfigSource` and delegates to `from_source()`.

### Tracking User-Set Values

A `ConfigSnapshot` wrapper tracks which fields the user explicitly set (present
in the source data) versus which fell through to defaults:

```python
class ConfigSnapshot[T]:
    """Wraps a frozen config dataclass, tracking which fields were set."""

    def __init__(self, instance: T, provided_keys: frozenset[str]):
        self._instance = instance
        self._provided_keys = provided_keys

    @property
    def value(self) -> T:
        """The underlying config dataclass instance."""
        return self._instance

    @property
    def provided_keys(self) -> frozenset[str]:
        """Field names that were explicitly set in the source data."""
        return self._provided_keys

    def to_dict(self, *, include_defaults: bool = False) -> dict[str, Any]:
        """Serialize to dict.

        When include_defaults is False (the default), only fields in
        provided_keys are included — defaults are not baked in.
        """
        ...
```

The parser builds `provided_keys` by checking which keys exist in the raw dict
before applying defaults. Nested config objects (e.g. `EmailChannelConfig`
inside `RepoServerConfig`) are themselves wrapped in `ConfigSnapshot`, so
user-set tracking is recursive.

#### Round-Trip Flow

```
┌──────────┐    load()     ┌──────────┐   resolve/validate   ┌──────────────┐
│  Source   │ ──────────► │ raw dict │ ─────────────────► │ ConfigSnapshot│
│ (YAML)   │              │ + version│                     │   .value      │
└──────────┘              └──────────┘                     │   .provided   │
                                                           └──────┬───────┘
                                                                  │
                                          to_dict(defaults=False) │
                                                                  ▼
┌──────────┐    save()     ┌──────────┐◄──────────────────────────┘
│  Source   │ ◄─────────── │ raw dict │  only user-set values
│ (YAML)   │              │ + version│
└──────────┘              └──────────┘
```

When saving, `ConfigSnapshot.to_dict(include_defaults=False)` produces a dict
containing only the fields the user explicitly set. The `ConfigSource.save()`
implementation writes this dict back in the target format. Defaults are never
persisted.

### Schema Migration

Each config file carries a `config_version` integer (defaults to `1` when
absent). On load, migrations are applied sequentially from the file's version to
the current version:

```python
#: Current schema version. Bump when adding a migration.
CURRENT_CONFIG_VERSION: int = 2

#: Migration functions keyed by the version they migrate FROM.
#: Each takes a raw dict and returns the transformed raw dict.
MIGRATIONS: dict[int, Callable[[dict[str, Any]], dict[str, Any]]] = {
    1: _migrate_v1_to_v2,
}
```

#### Migration Contract

Each migration function:

- Takes a raw `dict` (the full config as parsed from the source, pre-resolution)
- Returns a new `dict` (the transformed config)
- Must be **idempotent** (safe to apply to already-migrated data)
- Must not resolve `EnvVar` placeholders — those are resolved after migration
- Must handle missing keys gracefully (the key may not exist in every config)

#### Migration Triggers

Migrations run in `ServerConfig.from_source()` after `source.load()` and before
resolution/validation:

```
source.load() → apply_migrations() → resolve/validate → ConfigSnapshot
```

After loading, if the file's version is behind `CURRENT_CONFIG_VERSION`, the
gateway logs a warning suggesting the user run `airut config migrate` to update
the file on disk (optional — the in-memory migration is always applied).

#### Replacing Legacy Field Detection

The current ad-hoc `_LEGACY_EMAIL_FIELDS` detection in
`_parse_repo_server_config` becomes the `_migrate_v1_to_v2` function. The
detection-and-error pattern is replaced by automatic transformation with a
logged warning.

### Config Diffing

Two functions support comparing config states:

```python
def diff_configs(
    current: ConfigSnapshot[T],
    new: ConfigSnapshot[T],
) -> dict[str, tuple[Any, Any]]:
    """Return {field_name: (old_value, new_value)} for differing fields.

    Only compares fields that are set in at least one snapshot.
    Nested ConfigSnapshot values are compared recursively.
    """
    ...


def diff_by_scope(
    current: ConfigSnapshot[T],
    new: ConfigSnapshot[T],
) -> dict[Scope, dict[str, tuple[Any, Any]]]:
    """Group config changes by their reload scope.

    Returns {Scope.SERVER: {...}, Scope.REPO: {...}, Scope.TASK: {...}}.
    Empty scopes are included with empty dicts.
    """
    ...
```

#### Use Cases

- **Dashboard UI**: show which settings changed and whether a restart is needed.
- **Future live reload**: if `diff_by_scope()` returns changes only in
  `Scope.TASK`, apply them without any restart. If `Scope.REPO` changes exist,
  restart only affected repos.
- **Audit**: log what changed on config reload.

### Schema Introspection

A function extracts UI-friendly schema information from any annotated config
class:

```python
def schema_for_ui(config_cls: type) -> list[FieldSchema]:
    """Extract field metadata for UI rendering."""
    ...


@dataclass(frozen=True)
class FieldSchema:
    """UI-consumable field description."""

    name: str  # Field name
    type_name: str  # Human-readable type (e.g. "int", "str", "bool")
    default: Any  # Default value (MISSING if required)
    required: bool  # True if no default
    doc: str  # Human-readable description
    scope: str  # "server", "repo", or "task"
    secret: bool  # Whether the field holds a secret
```

The UI calls `schema_for_ui(GlobalConfig)` and `schema_for_ui(RepoServerConfig)`
to render settings forms with labels, defaults, and scope indicators.

## Scope Assignments

All config fields are assigned one of three scopes:

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

Settings that are scoped to a repository and could be reloaded by restarting
only that repo's handler:

- `repos.*.git.repo_url` — git mirror target
- `repos.*.email.*` — email channel credentials and settings
- `repos.*.slack.*` — slack channel tokens and authorization
- `repos.*.secrets` — credential pools
- `repos.*.masked_secrets` — scoped credentials
- `repos.*.signing_credentials` — AWS re-signing
- `repos.*.github_app_credentials` — GitHub App tokens
- `repos.*.network.sandbox_enabled` — proxy toggle

### `Scope.TASK` — Applied Per-Task

Settings that are read at task creation time and don't require any restart:

- `repos.*.model` — Claude model for new conversations
- `repos.*.effort` — effort level for new conversations
- `repos.*.resource_limits.*` — container limits (timeout, memory, cpus, pids)
- `repos.*.container_env` — plain environment variables
- `resource_limits.*` (server-wide defaults) — used when repo doesn't override

## File Layout

```
airut/
  config_schema.py    # FieldMeta, Scope, meta(), FieldSchema, schema_for_ui()
  config_snapshot.py  # ConfigSnapshot
  config_source.py    # ConfigSource protocol, YamlConfigSource
  config_migration.py # CURRENT_CONFIG_VERSION, MIGRATIONS, apply_migrations()
  config_diff.py      # diff_configs(), diff_by_scope()
  gateway/
    config.py         # Existing module — gains metadata on fields,
                      # from_source() method, ConfigSnapshot integration
```

## Implementation Plan

### Phase 1: Schema Infrastructure

Add `config_schema.py` with `FieldMeta`, `Scope`, `meta()`, `FieldSchema`, and
`schema_for_ui()`. Pure additions, no changes to existing behavior.

### Phase 2: Annotate Fields

Add `metadata=meta(...)` to all fields in `GlobalConfig`, `EmailChannelConfig`,
`SlackChannelConfig`, `RepoServerConfig`, and `ResourceLimits`. Existing
behavior unchanged — metadata is inert until read.

### Phase 3: Config Source

Add `ConfigSource` protocol and `YamlConfigSource`. Refactor
`ServerConfig.from_yaml()` to delegate to `from_source()`. No behavior change.

### Phase 4: User-Set Tracking

Add `ConfigSnapshot` and integrate it into the parsing pipeline. The parser
records which raw dict keys were present before applying defaults. Returned
`ServerConfig` is wrapped in `ConfigSnapshot`.

### Phase 5: Schema Migration

Add `config_migration.py`. Move `_LEGACY_EMAIL_FIELDS` logic into
`_migrate_v1_to_v2`. Add `config_version` handling to `from_source()`.

### Phase 6: Config Diffing

Add `config_diff.py` with `diff_configs()` and `diff_by_scope()`.

Each phase is a separate PR. Phases 1-3 are backward-compatible and can merge
independently.

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

### Testing

- Each migration function has unit tests with before/after dicts.
- `ConfigSnapshot.to_dict(include_defaults=False)` is tested to verify
  round-trip produces only user-set values.
- `schema_for_ui()` is tested to verify it extracts correct metadata.
- `diff_by_scope()` is tested to verify correct scope grouping.
