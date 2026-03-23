# Web Config Editor

A schema-driven web UI for editing `airut.yaml` server configuration, integrated
into the existing dashboard. The editor leverages the declarative config system
(`FieldMeta`, `schema_for_ui()`, `ConfigSnapshot.raw`) so new config fields
appear automatically without UI code changes. A two-level diff strategy
(matching `spec/config-reload.md`) provides a scope-annotated review step before
saving. File saves trigger reload via the existing inotify watcher.

## Goals

1. **Schema-driven** — form controls are generated from `FieldMeta` annotations
   at runtime. Adding a new field to a config dataclass with `meta()` is
   sufficient for it to appear in the editor.
2. **Tag-aware editing** — users can set any field to a literal value, `!var`
   reference, or `!env` reference. Tags are preserved through the round-trip.
3. **Diff before save** — changes are validated through the full config pipeline
   and presented as a scope-grouped diff before writing.
4. **Reload feedback** — after saving, the editor confirms whether the inotify
   watcher picked up the change and reports any reload errors.
5. **Variable management** — the `vars:` section is editable inline, with
   validation that all `!var` references resolve.

## Non-Goals

- Editing `.env` files. The editor only modifies `airut.yaml`.
- Secret masking in the editor UI. Secrets are shown in plain text (the
  dashboard already assumes a trusted, authenticated reverse proxy).
- Authentication. Inherits the dashboard's model (reverse proxy).
- YAML comment or formatting preservation. Consistent with
  `spec/declarative-config.md`.
- A raw YAML text editor mode (potential future enhancement).

## Design

### Editing Model: Raw YAML, Not Resolved Values

The editor operates on `ConfigSnapshot.raw` — the pre-resolution YAML dict with
`!var` and `!env` tags intact. Users edit raw values and can switch any field
between literal, `!var`, and `!env` modes. The diff preview resolves both the
current and edited configs to show actual effective changes.

This avoids the "lossy round-trip" problem where saving resolved values would
destroy tag references and bake defaults into the file.

### Backend API

Four new endpoints under `/api/config/`, plus a page route at `/config`.

#### `GET /api/config/schema`

Returns UI metadata for all config types. This drives form generation — the
frontend renders controls based solely on this response.

```json
{
  "global": [
    {
      "name": "max_concurrent_executions",
      "type_name": "int",
      "default": 3,
      "required": false,
      "doc": "Maximum parallel Claude containers across all repos",
      "scope": "server",
      "secret": false,
      "yaml_path": ["execution", "max_concurrent"]
    }
  ],
  "email_channel": [ ... ],
  "slack_channel": [ ... ],
  "repo": [ ... ]
}
```

Implementation:

- Calls `schema_for_ui()` for `GlobalConfig`, `RepoServerConfig`,
  `EmailChannelConfig`, `SlackChannelConfig`.
- Augments each entry with `yaml_path` from the `_YAML_*_STRUCTURE` mappings in
  `airut/config/source.py`. Fields not in a mapping use `(field_name,)` as the
  path (the field name is the YAML key). Currently `_YAML_GLOBAL_STRUCTURE`,
  `_YAML_EMAIL_STRUCTURE`, and `_YAML_REPO_STRUCTURE` exist. Slack fields
  (`bot_token`, `app_token`, `authorized`) are direct keys under `slack:` and
  have no mapping — they use `(field_name,)`.
- Returns plain dicts (not `FieldSchema` dataclasses) since `yaml_path` is a
  serialization concern not part of the core schema type.
- Result is cacheable (changes only with code updates).

**Complex field types.** Most fields map to simple form controls. Two notable
exceptions:

- `SlackChannelConfig.authorized` (`tuple[dict[str, str | bool], ...]`) — a
  sequence of authorization rule dicts with polymorphic keys
  (`workspace_members`, `user_group`, `user_id`). The editor renders this as a
  rule list editor with a rule-type selector per entry.
- `ResourceLimits` — a nested dataclass with sub-fields (`timeout`, `memory`,
  `cpus`, `pids_limit`). The schema endpoint includes `ResourceLimits` fields as
  a separate `resource_limits` section. The frontend renders these as a grouped
  sub-form.

New function in `airut/config/schema.py`:

```python
def full_schema_for_api() -> dict[str, list[dict[str, Any]]]:
    """Complete schema for the config editor API.

    Returns dicts (not FieldSchema) with yaml_path added, grouped
    by config type.  Includes resource_limits as a separate section.
    """
```

#### `GET /api/config`

Returns the current raw config document with `EnvVar` and `VarRef` encoded as
JSON-safe markers, plus `config_generation` for optimistic concurrency.

```json
{
  "config_generation": 3,
  "config": {
    "config_version": 2,
    "vars": {
      "mail_server": "mail.example.com",
      "api_key": {"__tag__": "env", "name": "ANTHROPIC_KEY"}
    },
    "execution": {
      "max_concurrent": 3
    },
    "repos": {
      "my-project": {
        "git": { "repo_url": "https://..." },
        "email": {
          "password": {"__tag__": "var", "name": "mail_password"}
        }
      }
    }
  }
}
```

`config_generation` is the monotonic reload counter from the gateway. The
frontend sends it back with save requests for optimistic concurrency checking.

**Tag encoding.** JSON cannot represent YAML custom tags, so `EnvVar` and
`VarRef` are serialized as:

- `{"__tag__": "env", "name": "VAR_NAME"}` for `!env`
- `{"__tag__": "var", "name": "VAR_NAME"}` for `!var`

On receive (preview/save), the backend decodes these back to `EnvVar`/`VarRef`.

**Data source.** The gateway service holds `_config_snapshot` which has `.raw`.
Access is provided via the `config_callback` described in Gateway Service
Integration below.

#### `POST /api/config/preview`

Accepts an edited raw config (JSON with `__tag__` markers). Validates by running
the full parse pipeline (`apply_migrations` → `resolve_vars_section` →
`resolve_var_refs` → `ServerConfig._from_raw`). Returns a structured diff.

**Request body:** same structure as `GET /api/config` response.

**Response (valid):**

```json
{
  "valid": true,
  "diff": {
    "server": [
      {
        "field": "max_concurrent_executions",
        "doc": "Maximum parallel Claude containers across all repos",
        "old": 3,
        "new": 5,
        "repo": null
      }
    ],
    "repo": [],
    "task": [
      {
        "field": "model",
        "doc": "Claude model to use",
        "old": "opus",
        "new": "sonnet",
        "repo": "my-project"
      }
    ]
  },
  "warnings": [
    "server-scope changes require service restart or idle period"
  ]
}
```

**Response (invalid):**

```json
{
  "valid": false,
  "error": "repos.my-project.email.imap_port: value 99999 is not a valid port (1-65535)",
  "diff": null,
  "warnings": []
}
```

**Validation pipeline:**

1. `json_to_raw(request_json)` — decode `__tag__` markers to `EnvVar`/`VarRef`
2. `apply_migrations(raw)` — schema migration
3. `resolve_vars_section(deepcopy(raw))` + `resolve_var_refs(...)` — resolve for
   validation
4. `ServerConfig._from_raw(resolved)` — full validation (catches type errors,
   constraint violations, missing required fields)
5. Two-level diff (see Diff Strategy below)
6. Annotate diff entries with `FieldMeta.doc` for each changed field
7. Generate warnings for server-scope changes

**Diff strategy.** `ServerConfig` has two fields (`global_config`, `repos`),
neither of which carries `FieldMeta`. Therefore `diff_by_scope()` cannot be
called directly on `ConfigSnapshot[ServerConfig]` (as documented in
`spec/config-reload.md`). The preview uses the same two-level strategy as the
reload orchestrator:

1. **Global config:** compare `GlobalConfig` field by field. All `GlobalConfig`
   fields are `Scope.SERVER`, so any difference is a server-scope change. Direct
   attribute comparison suffices — no `ConfigSnapshot` wrapper needed.
2. **Per-repo:** for each repo present in both configs, compare
   `RepoServerConfig` fields using `get_field_meta()` to classify changes by
   scope. Include `repo` name in each `FieldChange` entry.
3. **Repo additions/removals:** repos in the new config but not the current are
   listed as `"added"` entries; repos in the current but not the new are listed
   as `"removed"` entries. These are classified as `Scope.REPO`.

This produces a flat list of `FieldChange` entries grouped by scope name
(`"server"`, `"repo"`, `"task"`).

#### `POST /api/config/save`

Request body includes the edited config (same structure as the `config` field
from `GET /api/config`) plus `config_generation` from the load response:

```json
{
  "config_generation": 3,
  "config": { ... }
}
```

Validates, checks optimistic concurrency, writes YAML, waits for reload.

**Response:**

```json
{
  "saved": true,
  "config_generation": 7,
  "reload_status": "applied",
  "warnings": [
    "server-scope changes will apply when all tasks complete"
  ]
}
```

**Save flow:**

1. Run same validation as preview (reject invalid configs before writing)
2. Create timestamped backup of current config file
3. Write YAML with tag representers. `ConfigSnapshot.raw` is already in nested
   YAML format (it is the pre-resolution deep copy from `from_source()`), so no
   `flat_to_nested_*` conversion is needed. The `editor.py` module writes
   directly using `make_tag_dumper()` (not via `YamlConfigSource.save()`) to
   implement atomic write-to-temp-then-rename: write to a temporary file in the
   same directory, then `os.rename()` (atomic on Linux when source and
   destination are on the same filesystem). This is the same pattern that text
   editors use, and the inotify watcher already handles `MOVED_TO` events for
   this case.
4. Poll `_config_generation` for up to 2 seconds (inotify typically fires within
   100ms)
5. Check `_last_reload_error` — if set, return the error
6. Return success with generation number and scope summary

**`reload_status` values:**

- `"applied"` — generation incremented, no error
- `"reload_error"` — generation incremented but reload raised an error
- `"pending"` — generation did not increment within 2 seconds (rare)

**CSRF protection:** Requires `X-Requested-With` header, matching the existing
pattern for `POST /api/conversation/{id}/stop`.

#### `GET /config`

Server-rendered config editor page. Extends `base.html` with the standard navbar
and breadcrumbs (`Config`). Breadcrumb structure: just `Config` (single level,
like the main dashboard).

If the `config_callback` returns `None` (no editable config source), the page
displays a "Config editing not available" message explaining that the server was
not started with a YAML config file.

### Reload Integration

**Approach: file write + inotify.** The editor writes via atomic
write-to-temp-then-rename (using `make_tag_dumper()` from
`airut/config/source.py`) and the existing `ConfigFileWatcher` detects the
`MOVED_TO` event. No explicit reload trigger is needed because:

- The watcher is already battle-tested for atomic writes and debouncing.
- Editing via the web UI behaves identically to editing with a text editor.
- No new reload code path to maintain.
- `_config_generation` provides the feedback mechanism.

After save, the backend polls `_config_generation` (checking every 50ms for up
to 2 seconds) to confirm reload. If `_last_reload_error` is set, the error is
returned. If reload fails, the **previous valid config remains active** — the
user can fix the error and re-save.

#### Concurrency

- Save uses atomic write-to-temp-then-rename (see Save flow above).
- `_on_config_changed()` uses non-blocking `_reload_lock` (concurrent triggers
  dropped).
- Two simultaneous web saves: last writer wins. Both trigger reload; second
  reload sees its own values.
- Web save while manual file edit: last writer wins (consistent with any
  file-based config).

#### Optimistic Concurrency

The save request includes the `config_generation` value from when the editor
loaded the config. If the current generation differs (config was changed
externally between load and save), the save is rejected with a `409 Conflict`
response and the user is prompted to reload. This prevents silently overwriting
changes made by another user or manual file edit.

### Config Backup

Before every save, the editor creates a timestamped backup:

```
~/.config/airut/airut.1711152000123.bak
```

The timestamp uses millisecond precision (`int(time.time() * 1000)`) to avoid
collisions on rapid saves. Implementation keeps the 5 most recent backups and
prunes older ones. This provides a safety net for accidental misconfiguration.
Backup management is in `airut/config/editor.py`.

### Frontend Architecture

Following dashboard conventions: Jinja2 server-rendered page, htmx for
interactions, vanilla JS for schema-driven form generation.

#### Page Layout

```
┌─────────────────────────────────────────────────┐
│  navbar  (Dashboard > Config)                   │
├─────────────────────────────────────────────────┤
│  Status bar: Config v2  |  Last reload: OK      │
├─────────────────────────────────────────────────┤
│  ┌─── Variables ────────────────────────────┐   │
│  │  mail_server: mail.example.com           │   │
│  │  api_key: !env ANTHROPIC_KEY             │   │
│  │  [+ Add variable]                        │   │
│  └──────────────────────────────────────────┘   │
├─────────────────────────────────────────────────┤
│  ┌─── Global Settings ─────────────────────┐   │
│  │  Group: execution                        │   │
│  │    max_concurrent  [3]  (server)  [?]    │   │
│  │  Group: dashboard                        │   │
│  │    host  [127.0.0.1]  (server)           │   │
│  └──────────────────────────────────────────┘   │
├─────────────────────────────────────────────────┤
│  ┌─── Repo: my-project ────────────────────┐   │
│  │  Tabs: General | Email | Slack |         │   │
│  │        Secrets | Advanced                │   │
│  │                                          │   │
│  │  git.repo_url: https://...  (repo)       │   │
│  │  model: sonnet  (task)                   │   │
│  └──────────────────────────────────────────┘   │
│  [+ Add repository]                             │
├─────────────────────────────────────────────────┤
│  [Review Changes]                               │
└─────────────────────────────────────────────────┘
```

#### Schema-Driven Form Generation

The frontend JavaScript fetches `/api/config/schema` once and generates form
controls based on `type_name`:

| `type_name`      | Control                                 |
| ---------------- | --------------------------------------- |
| `str`            | Text input                              |
| `str \| None`    | Text input with "unset" checkbox        |
| `int`            | Number input                            |
| `bool`           | Checkbox                                |
| `list[str]`      | Tag input (comma-separated, add/remove) |
| `dict[str, str]` | Key-value pair editor                   |

Each field input has a **value mode selector** (small dropdown):

- **Literal** — direct value entry
- **`!var`** — dropdown of defined variables
- **`!env`** — text input for environment variable name

The mode is determined from the raw config value: `__tag__` objects select the
corresponding mode; other values select literal.

Fields are grouped by their `yaml_path` prefix (e.g., all fields with path
starting with `execution` appear under an "execution" heading). Each field
displays a scope badge (`server`, `repo`, `task`) and a tooltip from the `doc`
string.

#### Diff Review

When "Review Changes" is clicked:

1. Frontend serializes the form to the raw JSON structure
2. `POST /api/config/preview` validates and diffs
3. If valid: display changes grouped by scope in a review panel

```
┌─── Review Changes ──────────────────────────────┐
│                                                  │
│  Server-scope (restart when idle):               │
│    max_concurrent_executions: 3 → 5              │
│    "Maximum parallel Claude containers"          │
│                                                  │
│  Task-scope (immediate):                         │
│    my-project / model: opus → sonnet             │
│    "Claude model to use"                         │
│                                                  │
│  [Cancel]                        [Save Changes]  │
└──────────────────────────────────────────────────┘
```

4. On "Save Changes": `POST /api/config/save`
5. Show success/error banner with reload status

If invalid: display the validation error inline above the review button.

#### Variables Editor

The variables section is a dynamic key-value editor:

- Each row: `[name] : [value mode ▾] [value] [× delete]`
- Value modes: literal or `!env` (not `!var` — var-to-var is forbidden)
- "Add variable" button appends a row
- Deleting a variable referenced by `!var` elsewhere triggers a warning in
  preview validation

Changes to variables are included in the diff preview (they affect resolved
values of referencing fields).

#### Credential Pool Editors

`secrets`, `masked_secrets`, `signing_credentials`, `github_app_credentials`
have dynamic user-chosen keys and are not covered by `schema_for_ui()`. These
use key-value editors operating on the raw YAML structure:

- `secrets`: simple key-value (string → string, with tag mode selector)
- `masked_secrets`: key → sub-form with `MaskedSecret` fields
- `signing_credentials`: key → sub-form with `SigningCredential` fields
- `github_app_credentials`: key → sub-form with `GitHubAppCredential` fields

These editors work directly on the raw config dict. Credential type sub-form
fields are described in the schema endpoint as separate type definitions.

#### Static Assets

| File                          | Purpose                             |
| ----------------------------- | ----------------------------------- |
| `templates/pages/config.html` | Page template extending `base.html` |
| `static/js/config-editor.js`  | Schema-driven form generation       |
| `static/styles/config.css`    | Editor-specific styles              |

### Gateway Service Integration

The gateway passes a new callback to `DashboardServer`:

```python
config_callback: Callable[
    [], tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
]
```

This provides:

- `ConfigSnapshot.raw` — current raw config for loading into the editor
- `YamlConfigSource` — for saving (provides `.path` for backup creation and
  atomic write)
- `int` — current `_config_generation` (for optimistic concurrency and reload
  polling)

The callback returns `None` if the service has no config source (e.g., test mode
or non-YAML source). When `None`, the config editor page shows a "Config editing
not available" message and the API endpoints return `503 Service Unavailable`.

### Handling Schema Gaps

#### Schema-Driven Fields (Automatic)

All fields with `FieldMeta` annotations (`GlobalConfig`, `RepoServerConfig`,
`EmailChannelConfig`, `SlackChannelConfig`, `ResourceLimits`). Form generation
is fully automatic.

#### Dynamic-Key Sections (Key-Value Editors)

`vars:`, `secrets`, `masked_secrets`, `signing_credentials`,
`github_app_credentials`. These use specialized key-value editors as described
above.

#### Unknown Keys (Passthrough)

Any YAML keys not recognized by the schema are preserved in `.raw` and passed
through on save. The editor displays them in a read-only "Other" section as
formatted JSON. This ensures forward compatibility — a newer config format
doesn't lose data when edited by an older UI version.

## New Code

### `airut/config/editor.py` (New Module)

Core editor logic, independent of the dashboard HTTP layer:

```python
def raw_to_json(raw: dict[str, Any]) -> dict[str, Any]:
    """Encode EnvVar/VarRef as JSON-safe __tag__ dicts."""


def json_to_raw(data: dict[str, Any]) -> dict[str, Any]:
    """Decode __tag__ dicts back to EnvVar/VarRef objects."""


def validate_raw(raw: dict[str, Any]) -> ServerConfig:
    """Run full validation pipeline on a raw config dict.

    Replicates the ServerConfig.from_source() pipeline without
    requiring a ConfigSource:  apply_migrations → deepcopy →
    resolve_vars_section → resolve_var_refs → _from_raw.

    Returns the resolved ServerConfig or raises ConfigError.
    """


def preview_changes(
    current_config: ServerConfig,
    edited_json: dict[str, Any],
) -> PreviewResult:
    """Validate edited config and compute scope-grouped diff.

    Uses the two-level diff strategy: global equality check +
    per-repo field-by-field comparison with get_field_meta()
    for scope classification.
    """


def backup_config(source_path: Path) -> Path:
    """Create timestamped backup, prune to keep latest 5."""


@dataclass(frozen=True)
class PreviewResult:
    valid: bool
    error: str | None
    diff: dict[str, list[FieldChange]] | None  # keyed by scope name
    warnings: list[str]


@dataclass(frozen=True)
class FieldChange:
    field: str
    doc: str
    old: Any
    new: Any
    repo: str | None  # None for global fields
```

### Modified Files

| File                          | Changes                                    |
| ----------------------------- | ------------------------------------------ |
| `airut/config/schema.py`      | Add `full_schema_for_api()` with yaml_path |
| `airut/dashboard/handlers.py` | Add config editor endpoint handlers        |
| `airut/dashboard/server.py`   | Add routes, `config_callback` parameter    |

### Dashboard Server Changes

New routes added to `DashboardServer._url_map`:

```python
(Rule("/config", endpoint="config_editor"),)
(Rule("/api/config/schema", endpoint="api_config_schema"),)
(Rule("/api/config", endpoint="api_config"),)
(Rule("/api/config/preview", endpoint="api_config_preview", methods=["POST"]),)
(Rule("/api/config/save", endpoint="api_config_save", methods=["POST"]),)
```

## Security

### Access Control

The config editor inherits the dashboard's access model: no built-in
authentication, assumes a reverse proxy. Anyone who can access the dashboard can
edit the config. This is consistent — dashboard already exposes task details,
sender addresses, and repo URLs.

Document in `doc/security.md`: the config editor allows viewing and modifying
all server configuration including secrets, and must only be exposed behind an
authenticated reverse proxy.

### CSRF Protection

Both POST endpoints (`/api/config/preview` and `/api/config/save`) require the
`X-Requested-With` header. Preview is included because it processes untrusted
input through the config pipeline and returns current config values (including
secrets) in the diff — a cross-origin POST could exfiltrate config data.
Browsers block cross-origin custom headers without CORS preflight, and the
dashboard sets no CORS headers.

### Secret Values in API Responses

The `GET /api/config` and `POST /api/config/preview` responses include secret
values in plaintext. This is consistent with the Non-Goals (no secret masking)
and the dashboard's trust model (reverse proxy provides authentication). The
`declarative-config.md` spec notes that diff output contains actual values and
consumers must check `FieldMeta.secret` before logging — the editor API
responses are not logged.

### Input Validation

The save endpoint runs the full `ServerConfig` validation pipeline before
writing. Invalid configs are rejected with descriptive error messages — no
invalid YAML is ever written to disk.

## Integration Tests

Tests live in `tests/integration/dashboard/test_config_editor.py`.

### Schema Endpoint

| Test                                       | Validates                                        |
| ------------------------------------------ | ------------------------------------------------ |
| `test_schema_returns_all_annotated_fields` | Every `FieldMeta`-annotated field present        |
| `test_schema_includes_yaml_paths`          | `yaml_path` matches `_YAML_*_STRUCTURE` mappings |
| `test_schema_excludes_unannotated`         | Fields without `FieldMeta` are absent            |
| `test_schema_field_properties`             | `type_name`, `default`, `required` are correct   |

### Config Load

| Test                               | Validates                                         |
| ---------------------------------- | ------------------------------------------------- |
| `test_load_returns_tags`           | `__tag__` markers for `!env` and `!var` values    |
| `test_load_preserves_vars_section` | `vars:` included in response                      |
| `test_load_preserves_nesting`      | Nested YAML structure matches file on disk        |
| `test_load_round_trip_no_change`   | Load → save without edits produces identical YAML |

### Preview

| Test                                 | Validates                                         |
| ------------------------------------ | ------------------------------------------------- |
| `test_preview_valid_change`          | Changed field appears in diff with old/new values |
| `test_preview_groups_by_scope`       | Changes in correct scope groups                   |
| `test_preview_server_scope_warning`  | Server-scope changes include restart warning      |
| `test_preview_invalid_port`          | Invalid value → `valid: false` with error         |
| `test_preview_missing_required`      | Removing required field → `valid: false`          |
| `test_preview_var_change_propagates` | Changing var shows changes in referencing fields  |
| `test_preview_undefined_var_ref`     | `!var` to undefined var → `valid: false`          |
| `test_preview_no_changes`            | Identical config → `valid: true`, empty diff      |

### Save

| Test                             | Validates                                    |
| -------------------------------- | -------------------------------------------- |
| `test_save_writes_yaml`          | File on disk matches expected YAML content   |
| `test_save_preserves_tags`       | `!env` and `!var` tags present in saved YAML |
| `test_save_triggers_reload`      | `config_generation` increments after save    |
| `test_save_returns_generation`   | Response includes new `config_generation`    |
| `test_save_invalid_rejected`     | Invalid config → 400, file unchanged         |
| `test_save_creates_backup`       | Backup file exists after save                |
| `test_save_requires_csrf_header` | Missing `X-Requested-With` → 403             |
| `test_save_stale_generation`     | Stale `config_generation` → 409 Conflict     |

### Reload Integration

| Test                                  | Validates                                         |
| ------------------------------------- | ------------------------------------------------- |
| `test_task_scope_applied_immediately` | Changed `model` effective for next task           |
| `test_repo_scope_restarts_listener`   | Changed channel settings trigger listener restart |
| `test_server_scope_deferred`          | Server-scope change deferred, warning returned    |
| `test_reload_error_reported`          | Parse-valid but runtime-invalid config → error    |
| `test_concurrent_saves`               | Two rapid saves → consistent final state          |

### Variables

| Test                              | Validates                                    |
| --------------------------------- | -------------------------------------------- |
| `test_add_variable`               | New var appears in saved config              |
| `test_remove_referenced_variable` | Preview error when var still has `!var` refs |
| `test_var_with_env_value`         | `!env` in var value preserved in save        |
| `test_var_to_var_rejected`        | `!var` inside `vars:` → validation error     |

## Relationship to Existing Specs

- **`spec/declarative-config.md`** — this spec implements the dashboard editor
  interaction described in that spec's Config Variables section. Uses
  `schema_for_ui()`, `ConfigSnapshot.raw`, `get_field_meta()`, and the
  round-trip pipeline.
- **`spec/config-reload.md`** — this spec relies on the inotify watcher for
  reload triggering, as noted in that spec's Non-Goals. The file is always the
  single source of truth.
- **`spec/dashboard.md`** — extends the dashboard with a new page and API
  endpoints. Follows existing patterns for routing, handlers, templates, and
  security headers.
- **`spec/repo-config.md`** — the config schema documented there drives the
  editor's form generation via `FieldMeta`.
