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
- Secrets are visually masked in form inputs (password fields) but transmitted
  in plaintext via the API. The dashboard assumes a trusted reverse proxy.
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

Returns UI metadata for all config types, grouped by config type (`global`,
`email_channel`, `slack_channel`, `repo`, `resource_limits`). Each entry
includes `yaml_path` from the `_YAML_*_STRUCTURE` mappings for YAML nesting.
This drives form generation — the frontend renders controls based solely on this
response.

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
  "repo": [ ... ],
  "resource_limits": [ ... ]
}
```

Result is cacheable (changes only with code updates).

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

**Tag encoding.** JSON cannot represent YAML custom tags, so `EnvVar` and
`VarRef` are serialized as:

- `{"__tag__": "env", "name": "VAR_NAME"}` for `!env`
- `{"__tag__": "var", "name": "VAR_NAME"}` for `!var`

On receive (preview/save), the backend decodes these back to `EnvVar`/`VarRef`.

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
  "error": "repos.my-project.email.imap_port: value 99999 is not a valid port",
  "diff": null,
  "warnings": []
}
```

**Diff strategy.** Uses the same two-level strategy as the reload orchestrator:

1. **Global config:** compare `GlobalConfig` field by field using
   `get_field_meta()` for scope classification.
2. **Per-repo:** for each repo present in both configs, compare
   `RepoServerConfig` fields by scope. Include repo name in each change entry.
3. **Repo additions/removals:** classified as `Scope.REPO`.

This produces change entries grouped by scope name (`"server"`, `"repo"`,
`"task"`).

#### `POST /api/config/save`

Request body includes the edited config plus `config_generation` (required):

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
3. Atomic write-to-temp-then-rename using `make_tag_dumper()`. The inotify
   watcher detects the `MOVED_TO` event.
4. Poll `_config_generation` for up to 2 seconds (inotify typically fires within
   100ms)
5. Check `_last_reload_error` — if set, return the error
6. Return success with generation number

**`reload_status` values:**

- `"applied"` — generation incremented, no error
- `"reload_error"` — generation incremented but reload raised an error
- `"pending"` — generation did not increment within 2 seconds (rare)

#### `GET /config`

Server-rendered config editor page. Extends `base.html` with the standard navbar
and breadcrumbs. If the config callback returns `None` (no editable config
source), the page displays a "Config editing not available" message.

### Reload Integration

The editor writes via atomic write-to-temp-then-rename and the existing
`ConfigFileWatcher` detects the `MOVED_TO` event. No explicit reload trigger is
needed because:

- The watcher is already battle-tested for atomic writes and debouncing.
- Editing via the web UI behaves identically to editing with a text editor.
- No new reload code path to maintain.
- `_config_generation` provides the feedback mechanism.

If reload fails, the **previous valid config remains active** — the user can fix
the error and re-save.

### Concurrency

- Save uses atomic write-to-temp-then-rename with unique temp file names.
- `_on_config_changed()` uses non-blocking `_reload_lock` (concurrent triggers
  dropped).
- Two simultaneous web saves: last writer wins. Both trigger reload; second
  reload sees its own values.
- Web save while manual file edit: last writer wins (consistent with any
  file-based config).

### Optimistic Concurrency

The save request requires the `config_generation` value from when the editor
loaded the config. If the current generation differs (config was changed
externally between load and save), the save is rejected with `409 Conflict` and
the user is prompted to reload. This prevents silently overwriting changes made
by another user or manual file edit.

### Config Backup

Before every save, the editor creates a timestamped backup:

```
~/.config/airut/airut.1711152000123.bak
```

The timestamp uses millisecond precision to avoid collisions on rapid saves. The
5 most recent backups are kept; older ones are pruned.

### Frontend

Following dashboard conventions: Jinja2 server-rendered page with vanilla JS for
schema-driven form generation.

#### Page Layout

```
┌─────────────────────────────────────────────────┐
│  navbar  (Dashboard > Config)                   │
├─────────────────────────────────────────────────┤
│  Status bar: Config v2  |  Generation: 3        │
├─────────────────────────────────────────────────┤
│  Variables                                      │
│    mail_server: mail.example.com                │
│    api_key: !env ANTHROPIC_KEY                  │
│    [+ Add variable]                             │
├─────────────────────────────────────────────────┤
│  Global Settings                                │
│    Group: execution                             │
│      max_concurrent  [3]  (server)              │
│    Group: dashboard                             │
│      host  [127.0.0.1]  (server)               │
├─────────────────────────────────────────────────┤
│  Repo: my-project                               │
│    git.repo_url: https://...  (repo)            │
│    model: sonnet  (task)                        │
│    Email Channel                                │
│      imap_server: ...                           │
├─────────────────────────────────────────────────┤
│  [Review Changes]                               │
└─────────────────────────────────────────────────┘
```

#### Schema-Driven Form Generation

The frontend fetches `/api/config/schema` once and generates form controls based
on `type_name`:

| `type_name` | Control                    |
| ----------- | -------------------------- |
| `str`       | Text input                 |
| `int`       | Number input               |
| `bool`      | Checkbox                   |
| `list[str]` | Comma-separated text input |

Each field input has a **value mode selector** (dropdown): Literal, `!var`, or
`!env`. The mode is determined from the raw config value: `__tag__` objects
select the corresponding mode; other values select literal.

Fields are grouped by their `yaml_path` prefix (e.g., all fields under
`execution` appear under an "execution" heading). Each field displays a scope
badge and the `doc` string.

#### Variables Editor

Dynamic key-value editor for the `vars:` section:

- Each row: `[name] : [value mode] [value] [delete]`
- Value modes: literal or `!env` (not `!var` — var-to-var is forbidden)
- Deleting a variable referenced by `!var` elsewhere triggers a warning in
  preview validation

#### Diff Review

"Review Changes" serializes the form to JSON, posts to `/api/config/preview`,
and displays changes grouped by scope in a review panel. "Save Changes" posts to
`/api/config/save` with the same data.

### Gateway Service Integration

The gateway passes a callback to `DashboardServer`:

```python
config_callback: Callable[
    [], tuple[ConfigSnapshot[ServerConfig], YamlConfigSource, int] | None
]
```

This provides:

- `ConfigSnapshot.raw` — current raw config for loading
- `YamlConfigSource` — for saving (provides `.path` for backup and atomic write)
- `int` — current `_config_generation` (concurrency and reload polling)

Returns `None` if no editable config source is available (non-YAML source or
test mode). When `None`, the editor page shows an unavailable message and API
endpoints return `503`.

## Security

### Access Control

Inherits the dashboard's access model: no built-in authentication, assumes a
reverse proxy. Anyone who can access the dashboard can edit the config.

### CSRF Protection

Both POST endpoints require the `X-Requested-With` header. Preview is included
because it processes untrusted input and returns current config values
(including secrets) in the diff. Browsers block cross-origin custom headers
without CORS preflight, and the dashboard sets no CORS headers.

### Secret Values in API Responses

API responses include secret values in plaintext. This is consistent with the
dashboard's trust model (reverse proxy provides authentication). The editor API
responses are not logged.

### Input Validation

The save endpoint runs the full `ServerConfig` validation pipeline before
writing. Invalid configs are rejected — no invalid YAML is ever written to disk.

## Relationship to Existing Specs

- **`spec/declarative-config.md`** — uses `schema_for_ui()`,
  `ConfigSnapshot.raw`, `get_field_meta()`, and the round-trip pipeline.
- **`spec/config-reload.md`** — relies on the inotify watcher for reload. The
  file is always the single source of truth.
- **`spec/dashboard.md`** — extends the dashboard with a new page and API
  endpoints. Follows existing patterns for routing, handlers, and templates.
- **`spec/repo-config.md`** — the config schema drives form generation via
  `FieldMeta`.
