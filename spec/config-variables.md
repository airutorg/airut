# Config Variables

Value indirection for the server config via a `vars:` section and `!var` YAML
tag. Variables let multiple repos share values (server addresses, API keys,
tokens) from a single definition, and survive in-memory round-trip for dashboard
config editing.

## Goals

1. **DRY shared values** — define a value once, reference it from any number of
   repos or fields via `!var name`.
2. **Round-trip fidelity** — `!var` and `!env` references survive in-memory
   through `ConfigSnapshot`, enabling a dashboard config editor that can load,
   modify, and save config without destroying indirection.
3. **Single-file config** — secrets and shared values live in `airut.yaml`
   alongside the rest of the config, retiring `.env` as the primary mechanism.
4. **Transparent change detection** — variable value changes propagate through
   existing `diff_configs()` / `diff_by_scope()` with zero special-casing.

## Non-Goals

- String interpolation (`${var}` embedding within a value). `!var` replaces the
  entire scalar. Partial-value interpolation can be added later if needed.
- Nested variable namespaces (`!var mail.server`). Variables are a flat
  `name: value` mapping.
- Var-to-var references (`vars: x: !var y`). Single-pass resolution, no cycle
  detection needed.
- Templating. This is config-level DRY, not Jinja/Helm.

## Syntax

### `vars:` Section

A new top-level key in `airut.yaml`:

```yaml
vars:
  mail_server: mail.example.com
  anthropic_key: sk-ant-api03-aBcDeFgHiJkLmNoPqRsT...
  gh_token: ghp_1234567890abcdef
  azure_secret: !env AZURE_CLIENT_SECRET
```

Variable values are **literals** or **`!env` references**. The `vars:` section
is a flat mapping — keys are variable names, values are scalars.

### `!var` Tag

References a variable by name. Usable anywhere a YAML scalar value is expected:

```yaml
repos:
  my-project:
    email:
      imap_server: !var mail_server
      smtp_server: !var mail_server
      password: !env EMAIL_PASSWORD          # !env still works directly
    secrets:
      ANTHROPIC_API_KEY: !var anthropic_key
    masked_secrets:
      GH_TOKEN:
        value: !var gh_token
        scopes: ["api.github.com"]
        headers: ["Authorization"]

  another-project:
    email:
      imap_server: !var mail_server
      smtp_server: !var mail_server
    secrets:
      ANTHROPIC_API_KEY: !var anthropic_key
```

## Design

### Two Representations

Every loaded config exists in two forms simultaneously:

| Layer               | Purpose                                    | Contents                                                      |
| ------------------- | ------------------------------------------ | ------------------------------------------------------------- |
| **Resolved config** | Runtime use by gateway code                | Frozen dataclasses with final typed values                    |
| **Raw document**    | Round-trip serialization, dashboard editor | YAML dict with `VarRef` / `EnvVar` objects preserved in-place |

`ConfigSnapshot` holds both. Gateway code reads `.value` (resolved). The
dashboard editor reads `.raw` (document). Diffing operates on resolved values.
Saving serializes the raw document.

### YAML Tag Types

Two placeholder classes in `airut/yaml_env.py`:

```python
class EnvVar:
    """Placeholder for an unresolved !env VAR_NAME tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name


class VarRef:
    """Placeholder for an unresolved !var VAR_NAME tag."""

    def __init__(self, var_name: str) -> None:
        self.var_name = var_name
```

Both are registered as YAML tag constructors in `make_env_loader()`. The
`YamlValue` type alias is extended to include `VarRef`.

### Resolution Pipeline

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

- **`_from_raw()` and `_resolve()` are unchanged.** They never see `VarRef`. The
  existing call sites of `_resolve()` are untouched.
- **`VarRef` and `EnvVar` flow through migrations unresolved**, consistent with
  the existing migration contract ("must not resolve `EnvVar` placeholders").
- **The vars table is ephemeral.** It is computed during loading, used to
  resolve `VarRef` in the work copy, and does not need to persist on the
  snapshot. The `vars:` section in `doc_raw` is the durable source of truth.

#### `resolve_vars_section()`

Reads the `vars:` key from the raw dict and resolves each value:

1. Validate that no value is a `VarRef` (var-to-var not allowed).
2. Resolve `EnvVar` values via `raw_resolve()` (same as existing `!env`
   handling).
3. Return `dict[str, str | None]` — the resolved vars table.

#### `resolve_var_refs()`

Walks the raw dict tree. For every `VarRef` encountered:

1. Look up `var_name` in the vars table. Raise `ConfigError` if not found.
2. Replace the `VarRef` with the resolved value (string or `None`).
3. Remove the `vars:` key from the dict (consumed; downstream code never sees
   it).

`EnvVar` objects are left in place — `_resolve()` handles them later.

### ConfigSnapshot (Extended)

```python
class ConfigSnapshot[T]:
    _instance: T  # resolved config
    _provided_keys: frozenset[str]  # which fields user explicitly set
    _raw: dict[str, Any]  # complete raw YAML dict (vars: included,
    #   VarRef / EnvVar preserved)
```

New property:

```python
@property
def raw(self) -> dict[str, Any]:
    """Raw YAML dict with tags and vars: preserved (for editor / save)."""
    return self._raw
```

`to_dict()` is unchanged — returns flat dict with **resolved** values for
diffing. The raw document is accessed via `.raw` for round-trip serialization.

### YAML Save with Tag Representers

Custom YAML representers emit tags on save:

```python
def var_representer(dumper, data):
    return dumper.represent_scalar("!var", data.var_name)


def env_representer(dumper, data):
    return dumper.represent_scalar("!env", data.var_name)
```

Registered on a custom `Dumper` subclass used by `YamlConfigSource.save()`.
Round-trip: load YAML → `ConfigSnapshot` → edit `.raw` → save YAML. All `!var`
and `!env` tags are preserved end-to-end.

### `from_source()` Return Type

`from_source()` changes to return `ConfigSnapshot[ServerConfig]` instead of
`ServerConfig`. `from_yaml()` follows suit.

Gateway and CLI code at the call sites changes from:

```python
config = ServerConfig.from_yaml(config_path=args.config)
```

to:

```python
snapshot = ServerConfig.from_yaml(config_path=args.config)
config = snapshot.value
```

## Change Detection

Operates on **resolved values** — variable changes propagate automatically:

1. User changes `vars.mail_server` from `old.mail.com` to `new.mail.com`.
2. Both repos' `imap_server` and `smtp_server` fields resolve differently.
3. `diff_configs()` detects the resolved value changes in each repo.
4. `diff_by_scope()` classifies them as `Scope.REPO` (per field metadata).
5. Future reload logic restarts only affected repo handlers.

**Variables don't need their own scope.** The scope of a variable change is
determined by the scopes of the fields that reference it. A variable used in
both `Scope.SERVER` and `Scope.REPO` fields triggers both scopes. This falls out
of the existing diff infrastructure with no special handling.

Edge case: renaming a var (without changing its value) produces zero diff. Same
resolved values → no effective change. Correct behavior.

## Dashboard Config Editor

The dashboard editor operates on the raw document:

1. **Schema** — `schema_for_ui()` provides field names, types, docs, scopes,
   secret flags. Unchanged from current design.
2. **Read** — resolved values from `snapshot.value` for display. Reference
   indicators from `snapshot.raw` where values are `VarRef` / `EnvVar`.
3. **Edit** — modify `snapshot.raw` directly. Set literal, `!var`, or `!env`.
   Edit `raw["vars"]` to add / remove / rename variables.
4. **Validate** — resolve the modified raw dict through
   `ServerConfig._from_raw(work_raw)` (after var resolution) to validate the
   config resolves without errors before writing to disk.
5. **Save** — `yaml.dump(snapshot.raw)` with tag representers.
6. **Diff** — `diff_by_scope()` on old vs. new resolved instances shows what
   scope of restart is needed.

## Retiring .env

With `vars:`, the primary pattern for secrets becomes:

```yaml
vars:
  anthropic_key: sk-ant-api03-...
  gh_token: ghp_...
```

The server config at `~/.config/airut/airut.yaml` is a local,
non-version-controlled file with the same security posture as `.env` in the same
directory. One file is simpler than two.

**Migration path:**

1. `!env` and `.env` loading remain functional. No breaking changes.
2. New documentation recommends `vars:` for sharing values and consolidation.
3. `.env` becomes optional — recommended only for environments that prefer
   env-var injection (containers, systemd `EnvironmentFile=`, etc.).

## Error Handling

| Condition                                 | Behavior                                                              |
| ----------------------------------------- | --------------------------------------------------------------------- |
| `!var unknown_name` (not in `vars:`)      | `ConfigError` at load time                                            |
| `!var` in vars values (`vars: x: !var y`) | `ConfigError` — var-to-var not allowed                                |
| `vars:` section absent                    | No-op, backward compatible                                            |
| `vars:` section empty                     | No-op                                                                 |
| `!var` used as mapping key                | `ConfigError` — scalar values only                                    |
| Var value is `!env UNSET_VAR`             | `None` in vars table; downstream required-field validation catches it |

## Secret Handling

Variables don't carry their own secret metadata. Secret handling is unchanged:

- `__post_init__` methods register resolved values with `SecretFilter` for log
  redaction.
- `FieldMeta.secret` flags fields for UI masking.
- A variable used in a `secret=True` field has its resolved value registered
  automatically through the existing field-level mechanism.
- The dashboard derives which vars hold secrets by cross-referencing `raw`
  values against field schema metadata.

## Schema Version

No config migration needed. `vars:` is a new top-level key silently ignored by
`_from_raw()` if not extracted first. `!var` tags cause a YAML constructor error
on code without the `!var` registration — expected behavior when running an
older version against a config using the new feature.

Config version stays at 2. The feature is purely additive.

## Compatibility

### Config File Format

No breaking changes. Existing YAML files without `vars:` work identically —
`resolve_vars_section()` returns an empty table, `resolve_var_refs()` is a
no-op.

### Python API

**Breaking change:** `from_source()` and `from_yaml()` return
`ConfigSnapshot[ServerConfig]` instead of `ServerConfig`. All callers access the
resolved config via `.value`. This requires updating the call site in
`gateway.py` and the three call sites in `cli.py`.

`to_dict()` continues to return resolved values. `diff_configs()` and
`diff_by_scope()` are unchanged.

### Relationship to Other Specs

- [declarative-config.md](declarative-config.md) — defines the config
  infrastructure that variables build on (`ConfigSnapshot`, `ConfigSource`,
  `to_dict()`, diffing, scopes). The round-trip flow diagram in that spec will
  be updated to show the var resolution step and the `_raw` attribute.
- [repo-config.md](repo-config.md) — remains the authoritative reference for the
  config schema. Will be updated to document the `vars:` section and `!var` tag.

## Implementation

### New Code

**`airut/yaml_env.py`** — add `VarRef` class and `!var` tag constructor. Extend
`YamlValue` type alias to include `VarRef`. Register `!var` in
`make_env_loader()`.

**`airut/config/vars.py`** (new module) — `resolve_vars_section()` and
`resolve_var_refs()`.

### Modified Code

**`airut/config/snapshot.py`** — extend `ConfigSnapshot` with `_raw` attribute
and `raw` property.

**`airut/config/source.py`** — register YAML representers for `VarRef` and
`EnvVar` on a custom `Dumper` for `YamlConfigSource.save()`.

**`airut/gateway/config.py`** — insert var extraction and resolution into
`from_source()` pipeline. Change return type to `ConfigSnapshot[ServerConfig]`.

**`airut/gateway/service/gateway.py`** — update call site to use
`snapshot.value`.

**`airut/cli.py`** — update three `from_yaml()` call sites to use
`snapshot.value`.

**`config/airut.example.yaml`** — add commented `vars:` section with examples.

**`spec/declarative-config.md`** — update round-trip flow diagram and `!env`
round-trip paragraph to reflect the new `_raw`-based round-trip path.
