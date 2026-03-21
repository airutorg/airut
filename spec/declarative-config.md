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
    secret: bool = False  # Informational flag for UI (see Secret Handling)
    since_version: int = 1  # Schema version that introduced this field
```

A helper keeps field declarations concise:

```python
def meta(doc: str, scope: Scope, **kwargs) -> dict[str, FieldMeta]:
    """Attach FieldMeta via dataclass field(metadata=meta(...))."""
    return {"airut_config": FieldMeta(doc=doc, scope=scope, **kwargs)}
```

The metadata dict uses the key `"airut_config"` to avoid collisions with other
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
    dashboard_base_url: str | None = field(
        default=None,
        metadata=meta(
            "Public URL for dashboard links in emails (None = omit links)",
            Scope.SERVER,
        ),
    )
    container_command: str = field(
        default="podman",
        metadata=meta(
            "Container runtime command (podman or docker)", Scope.SERVER
        ),
    )
    upstream_dns: str | None = field(
        default=None,
        metadata=meta(
            "Upstream DNS server for proxy resolution (None = auto-detect)",
            Scope.SERVER,
        ),
    )
    # ... remaining fields follow the same pattern
```

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
  `yaml.load` with `make_env_loader()`). The `load()` method calls
  `load_dotenv_once()` before parsing to ensure `!env` tags can resolve.
- Future: `TomlConfigSource`, `JsonConfigSource`, `DatabaseConfigSource`

`ServerConfig` gains a `from_source(source: ConfigSource)` class method that
calls `source.load()`, applies migrations, then runs the existing
resolution/validation pipeline. The current `from_yaml()` becomes a thin wrapper
that constructs a `YamlConfigSource` and delegates to `from_source()`.

### YAML Structure Mapping

The YAML config uses nested sub-blocks (e.g. `execution.max_concurrent`,
`dashboard.host`, `email.imap.poll_interval`) that map to flat dataclass field
names (e.g. `max_concurrent_executions`, `dashboard_host`,
`poll_interval_seconds`). This nesting is a **serialization concern**, not a
schema concern.

The mapping between nested YAML paths and flat dataclass fields is handled by
the parsing layer — specifically the `_from_raw()`,
`_parse_repo_server_config()`, and `_parse_*_channel_config()` functions that
already perform this mapping today. These functions translate nested YAML dicts
into flat dataclass constructor kwargs.

`FieldMeta` intentionally does **not** encode YAML paths. The YAML structure is
a property of `YamlConfigSource`, not of the config schema. A future
`TomlConfigSource` or `DatabaseConfigSource` may use an entirely different
structure. Instead:

- **Serialization mapping** lives in `ConfigSource` implementations. Each source
  knows how to map its format to/from the canonical flat dict that `to_dict()`
  produces.
- **`to_dict()`** produces a flat dict keyed by dataclass field names (the
  canonical representation). `ConfigSource.save()` transforms this flat dict
  into the format-specific structure (e.g. nesting `dashboard_host` under
  `dashboard.host` for YAML).
- **`provided_keys`** tracks dataclass field names (flat), not YAML paths. The
  parser maps raw YAML keys to field names during construction.

#### Flat-to-Nested Mapping for YAML

`YamlConfigSource.save()` uses a static mapping to reconstruct the nested YAML
structure from the flat canonical dict:

```python
#: Maps flat field names to nested YAML paths.
_YAML_STRUCTURE: dict[str, tuple[str, ...]] = {
    "max_concurrent_executions": ("execution", "max_concurrent"),
    "shutdown_timeout_seconds": ("execution", "shutdown_timeout"),
    "dashboard_enabled": ("dashboard", "enabled"),
    "dashboard_host": ("dashboard", "host"),
    "dashboard_port": ("dashboard", "port"),
    "dashboard_base_url": ("dashboard", "base_url"),
    "poll_interval_seconds": ("imap", "poll_interval"),
    "use_imap_idle": ("imap", "use_idle"),
    # ... etc. Fields not listed map to their own name at the top level.
}
```

This mapping is co-located with `YamlConfigSource`, not with the config schema.
Other `ConfigSource` implementations define their own mappings (or none if the
format uses flat keys natively).

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
        """Serialize to flat dict keyed by dataclass field names.

        When include_defaults is False (the default), only fields in
        provided_keys are included — defaults are not baked in.
        Nested ConfigSnapshot values are serialized recursively.
        """
        ...
```

#### Computing `provided_keys`

`provided_keys` uses **dataclass field names** (flat), not YAML keys. The
parsing functions compute them by tracking which raw dict keys they actually
read before applying defaults.

For `GlobalConfig`, where multiple YAML sub-blocks map to one dataclass:

```python
# In _from_raw():
execution = raw.get("execution", {})
dashboard = raw.get("dashboard", {})

provided = set()
if "max_concurrent" in execution:
    provided.add("max_concurrent_executions")
if "shutdown_timeout" in execution:
    provided.add("shutdown_timeout_seconds")
if "enabled" in dashboard:
    provided.add("dashboard_enabled")
# ... etc.
```

A field is "provided" when its corresponding raw dict key exists, regardless of
the resolved value. Specifically:

- `password: !env PASSWORD` where `$PASSWORD` is unset — the key `password`
  exists in the raw dict, so the field **is** provided. Resolution may still
  raise `ConfigError` if the field is required, but the provenance tracking is
  separate from validation.
- `password:` (YAML null) — the key exists, so the field **is** provided.
- Key absent from YAML entirely — the field is **not** provided; the default
  applies.

This means `provided_keys` tracks **user intent** ("the user wrote this key in
the config file") rather than **resolved availability**.

#### Handling Nested and Polymorphic Fields

For `RepoServerConfig.channels` (`dict[str, ChannelConfig]`), the `channels`
field as a whole is tracked in `provided_keys` by channel type. Each channel
config within it is itself wrapped in a `ConfigSnapshot`:

```python
channels: dict[str, ConfigSnapshot[ChannelConfig]]
```

`to_dict()` recurses into nested `ConfigSnapshot` values. For dict-typed fields
like `secrets`, `masked_secrets`, and `container_env`, the entire dict is the
value — if the YAML key exists, the whole dict is "provided." There is no
per-entry tracking within these dicts (credential pool entries use dynamic
user-chosen keys, not fixed schema fields).

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

When saving, `ConfigSnapshot.to_dict(include_defaults=False)` produces a flat
canonical dict with only user-set fields. `ConfigSource.save()` transforms this
into the format-specific structure (e.g. nesting for YAML) and writes it.

**`!env` tags and round-trip:** The `to_dict()` output contains **resolved**
values, not `EnvVar` placeholders. A round-trip through `to_dict()` + `save()`
replaces `!env` references with their resolved string values. This is acceptable
because:

- Config files using `!env` tags are typically not edited via UI round-trip; the
  UI would set concrete values.
- Users who want to preserve `!env` tags edit the YAML file directly.
- A future enhancement could optionally preserve `EnvVar` placeholders by
  storing them alongside resolved values, but this is not required for the
  initial implementation.

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

#### Security-Sensitive Migrations

Some migrations involve fields that affect authorization (e.g.
`authorized_senders`). For these, the migration function must **reject the
config with a `ConfigError`** rather than silently transforming it. The current
`_LEGACY_EMAIL_FIELDS` detection raises `ConfigError` with explicit migration
instructions — this behavior is preserved in the migration function.

The rule: migration functions may automatically transform **non-security** field
renames and restructuring, but must raise `ConfigError` for changes that could
affect authentication or authorization if the automatic transformation has a
bug.

```python
def _migrate_v1_to_v2(raw: dict) -> dict:
    """Migrate v1 → v2: detect legacy email field placement."""
    for repo_id, repo in raw.get("repos", {}).items():
        legacy = {"authorized_senders", "trusted_authserv_id"} & repo.keys()
        if legacy:
            # Security-critical: refuse to auto-migrate, require manual fix
            raise ConfigError(
                f"repos.{repo_id}: {', '.join(sorted(legacy))} must be "
                f"nested under 'email:'. See config/airut.example.yaml."
            )
    return raw
```

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

#### Secret Masking in Diffs

Diff output for fields with `secret=True` in `FieldMeta` must be masked before
logging or UI display. The diff functions return actual values (needed for
applying changes), but consumers must check `FieldMeta.secret` and replace
values with `"<changed>"` when displaying to users or writing to logs.

#### Use Cases

- **Dashboard UI**: show which settings changed and whether a restart is needed.
- **Future live reload**: if `diff_by_scope()` returns changes only in
  `Scope.TASK`, apply them without any restart. If `Scope.REPO` changes exist,
  restart only affected repos.
- **Audit**: log what changed on config reload (with secret masking).

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

    name: str  # Field name (dataclass field name)
    type_name: str  # Python annotation as string (e.g. "str | None")
    default: Any  # Default value (MISSING if required)
    required: bool  # True if no default
    doc: str  # Human-readable description
    scope: str  # "server", "repo", or "task"
    secret: bool  # Whether the field holds a secret
```

`type_name` uses Python's annotation string representation (`str(annotation)`),
e.g. `"int"`, `"str | None"`, `"bool"`. Complex types like `dict[str, str]` and
`list[str]` are rendered as-is. The UI interprets these strings to choose
appropriate input widgets.

The UI calls `schema_for_ui(GlobalConfig)` and `schema_for_ui(RepoServerConfig)`
to render settings forms with labels, defaults, and scope indicators. Credential
pool entries (`MaskedSecret`, `SigningCredential`, etc.) are not covered by
`schema_for_ui()` — the UI handles these through specialized key-value editors.

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
- `resource_limits.*` (server-wide defaults) — currently read from
  `GlobalConfig` at startup and not re-read per-task; will move to `Scope.TASK`
  when live-reload is implemented

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
- `repos.*.resource_limits.*` — per-repo container limits (timeout, memory,
  cpus, pids)
- `repos.*.container_env` — plain environment variables

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
`ServerConfig.from_yaml()` to delegate to `from_source()`. `YamlConfigSource`
includes the `_YAML_STRUCTURE` mapping for save-time nesting. No behavior
change.

### Phase 4: Schema Migration

Add `config_migration.py`. Move `_LEGACY_EMAIL_FIELDS` logic into
`_migrate_v1_to_v2` (preserving the `ConfigError` for security-sensitive
fields). Add `config_version` handling to `from_source()`. This phase can be
implemented before or after Phase 5 — the migration operates on the raw dict
before `ConfigSnapshot` exists.

### Phase 5: User-Set Tracking

Add `ConfigSnapshot` and integrate it into the parsing pipeline. The parser
records which raw dict keys were present before applying defaults. This requires
modifying `_from_raw()`, `_parse_repo_server_config()`, and
`_parse_*_channel_config()` to track provided keys alongside existing resolution
logic — a significant refactor of the parsing functions.

### Phase 6: Config Diffing

Add `config_diff.py` with `diff_configs()` and `diff_by_scope()`.

Each phase is a separate PR. Phases 1-3 are backward-compatible and can merge
independently. Phase 4 is independent of Phase 5. Phase 6 depends on Phase 5.

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
When this spec is implemented, the "Loading Flow" section of
`spec/repo-config.md` should be updated to reference the migration step.

### Testing

- Each migration function has unit tests with before/after dicts.
- `ConfigSnapshot.to_dict(include_defaults=False)` is tested to verify
  round-trip produces only user-set values.
- `schema_for_ui()` is tested to verify it extracts correct metadata.
- `diff_by_scope()` is tested to verify correct scope grouping.
- Secret masking in diff output is tested.
