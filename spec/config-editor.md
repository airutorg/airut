# Config Editor

A web editor for the server configuration, integrated into the dashboard. The
editor uses an **edit buffer** pattern: the server holds a mutable copy of the
config in memory, the client sends granular field-level mutations via htmx, and
a separate save operation writes the result to disk after showing a diff
preview.

## Goals

1. **Schema-driven rendering** — form elements generated from `FieldMeta`
   annotations. Adding a field with `metadata=meta(...)` automatically surfaces
   it in the editor. Individual pages can customize layout (card grouping,
   column arrangement) while field widgets are always schema-generated.
2. **Edit buffer with granular mutations** — the server holds a mutable copy of
   the raw config dict. The client sends per-field set/clear operations and
   collection add/remove operations. No bulk form submission.
3. **Diff before save** — a save flow that shows the user exactly what changed,
   grouped by reload scope, before writing to disk.
4. **Full type coverage** — nested dataclasses, `list[str]`, `dict[str, str]`,
   keyed collections (`dict[str, MaskedSecret]`), tagged union lists (Slack
   `authorized`).
5. **Value source control** — every scalar field supports a source selector: Not
   set, Literal, `!env`, `!var`.
6. **Round-trip fidelity** — `!env` and `!var` tags survive load-edit-save
   cycles. Unset fields are excluded from the config file.
7. **Incremental delivery** — the edit buffer pattern naturally supports
   building the UI in phases. Global settings, repos, channels, and credentials
   can ship independently.

## Non-Goals

- Preserving YAML comments or formatting (lossy save is acceptable).
- Undo/redo history.
- Multi-user concurrent editing (single-user system behind reverse proxy).
- Editing config from the CLI (the editor is dashboard-only).
- Per-field real-time validation (validation runs on save only).
- Exposing YAML structure in the UI (the editor abstracts over the file format).

## Dependency

No new dependencies. The editor uses the existing stack: Werkzeug (WSGI), Jinja2
(templates), htmx (vendored), stdlib `dataclasses` and `typing`.

## Design

### Edit Buffer

The core abstraction. A singleton held by the dashboard server — one edit
session at a time (single-user system).

```python
class EditBuffer:
    """Server-side mutable copy of config for editing."""

    _raw: dict[str, Any]  # mutable deep copy of ConfigSnapshot.raw
    _generation: int  # _config_generation at buffer creation
    _dirty: bool  # any mutations applied since creation?
```

#### Lifecycle

1. **Created** on first `GET /config` when no buffer exists (or existing buffer
   was discarded). Deep-copies `ConfigSnapshot.raw` and records current
   `_config_generation`.
2. **Mutated** by PATCH and POST API calls. Each mutation modifies `_raw`
   in-place and sets `_dirty = True`.
3. **Persists** across page navigations — state lives on the server, not in the
   browser form. Opening `/config` in two tabs operates on the same buffer.
4. **Discarded** on:
   - Explicit discard (`POST /api/config/discard`)
   - Successful save (`POST /api/config/save`)
   - External config change (inotify / SIGHUP bumps `_config_generation`, making
     `_generation` stale)
5. **No idle timeout** while dirty. A clean (non-dirty) buffer may be discarded
   freely. A dirty buffer persists until explicitly discarded or invalidated by
   an external change.

#### Staleness Detection

The server compares `buffer._generation == current _config_generation` on **save
only**. Mutations (PATCH, add, remove) do **not** check staleness — the user can
continue editing even if the underlying config changed. This avoids interrupting
a multi-field edit session due to an unrelated config touch.

Staleness is enforced at the point of commitment:

- **On save:** if stale, return 409 with a banner: "Config changed externally
  since you started editing. Review changes and reload."
- **On page load:** if a stale dirty buffer exists, show a warning banner at the
  top of the page. The user can choose to continue editing (and will see the 409
  on save) or discard and reload.

Unsaved changes in a stale buffer are lost on discard — this is the expected
trade-off for a single-user system. Three-way merge adds complexity without
meaningful benefit when only one person edits the config.

### Data Flow

```
Browser (htmx)
  GET /config                  → Render page from EditBuffer + schema
  PATCH /api/config/field      → Mutate single field in buffer
  POST /api/config/add         → Add item to collection in buffer
  POST /api/config/remove      → Remove item from collection in buffer
  GET /api/config/diff         → Compare buffer vs live config
  POST /api/config/save        → Validate buffer → atomic YAML write
  POST /api/config/discard     → Reset buffer

                                 ↓ save writes YAML (atomic temp+rename)

Config File (~/.config/airut/airut.yaml)

                                 ↓ inotify CLOSE_WRITE

ConfigFileWatcher → GatewayService._on_config_changed()
                    → diff, apply by scope, increment _config_generation
```

The editor writes the YAML file and relies on the existing `ConfigFileWatcher` +
reload pipeline. No new reload codepath is introduced.

### Existing Foundation

The editor builds on infrastructure from `spec/declarative-config.md` and
`spec/config-reload.md`:

- **`FieldMeta` + `meta()`** — per-field metadata (doc, scope, secret,
  since_version) on all config dataclasses.
- **`ConfigSnapshot`** — wraps frozen config, tracks `provided_keys`, preserves
  `raw` dict with `EnvVar`/`VarRef` objects for round-trip.
- **`ConfigSource` protocol** — `load()` / `save()` with `YamlConfigSource`
  implementation that handles `!env`/`!var` YAML tags.
- **YAML structure mappings** — `YAML_GLOBAL_STRUCTURE`, `YAML_EMAIL_STRUCTURE`,
  `YAML_REPO_STRUCTURE` for flat-to-nested conversion.
- **`_config_generation`** — monotonic counter incremented on each successful
  reload, exposed via `/api/status`.
- **`_last_reload_error`** — traceback string from the most recent failed
  reload.
- **`diff_configs()` / `diff_by_scope()`** — compare two config snapshots, group
  changes by reload scope.

### FieldMeta on Credential Types

All credential types already have `FieldMeta` annotations (added in commit
`863daf1`). This means the entire config tree is self-describing, and
`schema_for_editor()` can walk all types recursively without any hardcoded
registry.

Annotated credential types:

- `MaskedSecret` — `value`, `scopes`, `headers`, `allow_foreign_credentials`
- `SigningCredential` — `access_key_id`, `secret_access_key`, `session_token`,
  `scopes`
- `SigningCredentialField` — `name`, `value`
- `GitHubAppCredential` — all 8 fields (`app_id`, `private_key`,
  `installation_id`, `scopes`, `allow_foreign_credentials`, `base_url`,
  `permissions`, `repositories`)

### Editor Schema

Module: `airut/config/editor.py`.

#### `EditorFieldSchema`

Describes a single field or composite structure for UI rendering:

```python
@dataclass(frozen=True)
class EditorFieldSchema:
    name: str  # display name
    path: str  # dot-delimited path in raw dict (e.g. "dashboard.port")
    type_tag: str  # widget type (see table below)
    python_type: str  # "str", "int", "float", "bool", etc.
    default: object  # MISSING sentinel if required; Any type is
    # justified since defaults span str/int/bool/None
    required: bool
    doc: str  # from FieldMeta
    scope: str  # "server", "repo", "task"
    secret: bool
    multiline: bool = False
    nested_fields: list[EditorFieldSchema] | None = None
    item_class_name: str | None = None
    item_fields: list[EditorFieldSchema] | None = None
    tagged_union_rules: list[tuple[str, str, str]] | None = None
    env_eligible: bool = True
    var_eligible: bool = True
```

For optional/union types (`T | None`), the `None` is stripped and the inner type
determines the `type_tag`. The `required` flag and `default` reflect whether
`None` means "field is optional" vs "field has no default."

**Type tags** classify each field for widget selection:

| Type tag            | Python type                                      | Widget          |
| ------------------- | ------------------------------------------------ | --------------- |
| `scalar`            | `str`, `int`, `float`, `bool`                    | Text/toggle     |
| `list_str`          | `list[str]`, `tuple[str, ...]`, `frozenset[str]` | Vertical list   |
| `dict_str_str`      | `dict[str, str]`                                 | Key-value rows  |
| `nested`            | Any `@dataclass` with FieldMeta                  | Inline fieldset |
| `keyed_collection`  | `dict[str, <dataclass>]`                         | Expandable card |
| `tagged_union_list` | Slack `authorized` pattern                       | Rule list       |

#### `schema_for_editor()`

Walks dataclass fields recursively to produce `EditorFieldSchema` trees. Uses
`FieldMeta` for metadata and `YAML_*_STRUCTURE` mappings to compute the `path`
for each field.

1. For each field with `FieldMeta`, produce an `EditorFieldSchema`.
2. Map type annotation to `type_tag` using the table above.
3. If field type is a `@dataclass` with `FieldMeta` fields, recurse → populate
   `nested_fields`.
4. If field type is `dict[str, <dataclass>]`, introspect the item class →
   populate `item_fields` and `item_class_name`.
5. For tagged union fields, populate `tagged_union_rules`.

**Path computation:** Uses `YAML_GLOBAL_STRUCTURE`, `YAML_EMAIL_STRUCTURE`, and
`YAML_REPO_STRUCTURE` to map flat dataclass field names to nested YAML paths.
Fields not in any structure mapping use their dataclass field name directly as
the path segment. Slack channel fields have no `YAML_SLACK_STRUCTURE` — they map
1:1 to their dataclass field names within the `slack:` block (e.g.,
`repos.{id}.slack.bot_token`).

**Relationship to `schema_for_ui()`:** The existing `schema_for_ui()` returns
flat `FieldSchema` records (name, type, default, doc). It continues to exist for
non-editor consumers (e.g., example config generation, CLI help).
`schema_for_editor()` is a richer, recursive variant that adds YAML paths, type
tags, and composite type structure needed by the editor UI.

### Schema-Driven Rendering with Page Customization

Field widgets (scalar inputs, source selectors, list/dict/collection widgets)
are **always generated from the schema** — `EditorFieldSchema` determines the
widget type, label, help text, source options, and default value. Adding a new
`FieldMeta`-annotated field to a config dataclass automatically makes it appear
in the editor with the correct widget and documentation.

However, **page layout is template-controlled**: each page template decides how
to group fields into cards, arrange cards into sections, and order sections on
the page. This means:

- The `config.html` template explicitly lists which cards appear and in what
  order (Execution, Dashboard, Container & Network, Resource Limits).
- The `config_repo.html` template controls per-repo card ordering.
- Templates call a shared `render_field(schema, buffer)` macro for each field,
  which dispatches to the appropriate widget template based on `type_tag`.
- Adding a new field to (say) `GlobalConfig` makes it appear automatically in
  the appropriate card. Adding an entirely new card grouping requires a template
  change.

This balances automatic schema discovery with deliberate page design.

#### `InMemoryConfigSource`

A read-only `ConfigSource` for pre-save validation. Only `load()` is meaningful
— `save()` is not called during the validation path
(`ServerConfig.from_source()` only calls `load()`).

```python
class InMemoryConfigSource:
    """Read-only ConfigSource wrapping a pre-built dict."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def load(self) -> dict[str, Any]:
        return self._data

    def save(self, data: dict[str, Any]) -> None:
        raise NotImplementedError("In-memory source is read-only")
```

Used for pre-save validation:
`ServerConfig.from_source(InMemoryConfigSource(d))` exercises the full pipeline
without touching the file.

### Edit Buffer Operations

All operations work on the raw YAML dict using **dot-delimited paths** that
mirror the YAML structure (e.g., `execution.max_concurrent`,
`repos.my-project.email.imap.poll_interval`). These are the paths the user would
see in the config file.

#### Set Field

Sets a single scalar field to a literal, `!env`, or `!var` value. Navigates the
path in `_raw`, creating intermediate dicts as needed.

- `source=literal` → store coerced Python value (`int`, `float`, `bool`, or
  `str`)
- `source=env` → store `EnvVar(var_name)`
- `source=var` → store `VarRef(var_name)`
- `source=unset` → remove the key from the dict. If the parent dict becomes
  empty, prune it recursively.

#### Add Item

Adds to a list (append empty string) or keyed collection (create entry with
given key and default structure). The server returns an HTML fragment for the
new item, which htmx appends to the DOM.

For channel add (`repos.{id}.email`, `repos.{id}.slack`), creates the channel
block with required-field placeholders. For repo add (`repos.{key}`), creates a
minimal repo skeleton.

#### Remove Item

Removes from a list (by index) or keyed collection (by key). Also handles
channel removal and repo removal. The client removes the DOM element client-side
on success.

### Unified Source Selector

Every scalar field gets a **four-state segmented control**:

```
┌──────────┬─────────┬──────┬──────┐
│ Not set  │ Literal │ !env │ !var │
└──────────┴─────────┴──────┴──────┘
```

**Not set** — field excluded from config. Input shows effective default as
placeholder text (grayed out). Field row uses `--bg-inset` background.

**Literal** — user types a value directly.

**!env** — user types an environment variable name. A resolved-value hint below
shows the current env var value (or "(not set)").

**!var** — user types a config variable name. A resolved-value hint below shows
the resolved value.

Clicking a segment sends `PATCH /api/config/field` with the new source (and
value if switching from unset). The server mutates the buffer and responds. htmx
swaps the field fragment to reflect the new state.

#### Which Fields Get Which Options

| Field type                  | Not set | Literal | !env | !var |
| --------------------------- | ------- | ------- | ---- | ---- |
| Required `str` (no default) | No      | Yes     | Yes  | Yes  |
| Optional `str \| None`      | Yes     | Yes     | Yes  | Yes  |
| `str` with default          | Yes     | Yes     | Yes  | Yes  |
| `int` / `float`             | Yes\*   | Yes     | Yes  | Yes  |
| `bool`                      | Yes\*   | Yes     | No   | No   |

\*"Not set" available only when the field has a default (is not required).

`!env` and `!var` both resolve to strings; `int`/`float` fields coerce the
resolved string during validation (same as direct `!env` usage). `bool` fields
exclude `!env`/`!var` because boolean coercion from strings is ambiguous and
booleans are always safe to set literally.

### Composite Type Widgets

All driven by the schema tree — no widget is hardcoded to a specific field name.

#### Nested Dataclass (`ResourceLimits`)

Inline fieldset within a card. Each sub-field uses the standard scalar widget
with source selector. The whole block can be toggled to "Not set" at the global
level (where the type is `ResourceLimits | None`).

Desktop layout uses a 2-column grid; mobile stacks vertically.

#### List of Strings (`list[str]`, `tuple[str, ...]`, `frozenset[str]`)

Vertical list with add/remove. Each item is a text input with source selector.
Per-item [x] remove button. [+ Add] button sends `POST /api/config/add`.

```
Authorized Senders                                  [+ Add]
┌────────────────────────────────────────────────────────────┐
│  [Literal] [you@example.com                         ] [x]  │
│  [Literal] [*@company.com                           ] [x]  │
└────────────────────────────────────────────────────────────┘
```

#### Dict of Strings (`dict[str, str]`)

Key-value rows with add/remove. Keys are plain text inputs. Values get source
selectors.

```
Secrets                                              [+ Add]
┌────────────────────────────────────────────────────────────┐
│  Key: [ANTHROPIC_API_KEY]  Value: [!env] [ANTHROPIC_A.] [x]│
│  Key: [OTHER_TOKEN      ]  Value: [Literal] [sk-ant..] [x] │
└────────────────────────────────────────────────────────────┘
```

#### Keyed Collection (`dict[str, <dataclass>]`)

Expandable card per entry. Collapsed shows key + summary. Expanded shows full
sub-form with all sub-fields rendered recursively.

Used for `masked_secrets`, `signing_credentials`, `github_app_credentials`.

For signing credentials, the editor emits the `type: aws-sigv4` discriminator
automatically. For GitHub App credentials, `type: github-app`. These are
read-only in the card header.

`private_key` (GitHubAppCredential) uses `<textarea>` for multiline PEM keys.

#### Tagged Union List (Slack `authorized`)

Each item has a rule type dropdown and type-specific value input:

```
Authorization Rules                                  [+ Add]
┌────────────────────────────────────────────────────────────┐
│  [workspace_members ▾]  [✓ enabled]                   [x]  │
│  [user_group        ▾]  [engineering                ] [x]  │
│  [user_id           ▾]  [U12345678                  ] [x]  │
└────────────────────────────────────────────────────────────┘
```

Rule type metadata is encoded in a `TAGGED_UNION_RULES` mapping:

```python
TAGGED_UNION_RULES = {
    "SlackChannelConfig.authorized": [
        ("workspace_members", "bool", "Allow all workspace members"),
        ("user_group", "str", "User group handle"),
        ("user_id", "str", "Slack user ID"),
    ],
}
```

#### Channel Config (Structural)

Rendered as channel sections per repo:

- Configured channels show their sub-form.
- Unconfigured channels show [+ Add Email Channel] / [+ Add Slack Channel].
- Configured channels have a [Remove Channel] button with confirmation.

Add/remove sends `POST /api/config/add` or `POST /api/config/remove` with the
channel path.

## HTTP Endpoints

### Page Routes

| Route                     | Method | Description                                 |
| ------------------------- | ------ | ------------------------------------------- |
| `/config`                 | GET    | Global settings (execution, dashboard, ...) |
| `/config/repos/<repo_id>` | GET    | Per-repo settings for a single repository   |

The editor is organized into **sub-pages**. `/config` shows global (server-wide)
settings and a list of configured repos with links. Each repo has its own page
at `/config/repos/<repo_id>` showing git, channels, model, credentials, etc.

All pages share the same `EditBuffer` — navigating between pages does not lose
unsaved changes.

The top bar shows "Configuration" as a breadcrumb on all editor pages. Per-repo
pages show "Configuration / \<repo_id>".

### API Routes

| Route                 | Method | Description                           |
| --------------------- | ------ | ------------------------------------- |
| `/api/config/field`   | PATCH  | Set or clear a single field           |
| `/api/config/add`     | POST   | Add item to list/dict/collection      |
| `/api/config/remove`  | POST   | Remove item from list/dict/collection |
| `/api/config/diff`    | GET    | Compare buffer vs live config         |
| `/api/config/save`    | POST   | Validate + write YAML                 |
| `/api/config/discard` | POST   | Reset edit buffer                     |

### `GET /config`

Global settings page. Server-side rendered from `EditorFieldSchema` tree +
current `EditBuffer` state. If no buffer exists, creates one from current
`ConfigSnapshot.raw`. Returns full HTML page extending `base.html`.

Includes a repo list at the bottom: each configured repo shown as a card with
its ID, channel summary, and a link to `/config/repos/<repo_id>`. An \[+ Add
Repository\] button is included for creating new repos.

### `GET /config/repos/<repo_id>`

Per-repo settings page for a single repository. Rendered from the same
`EditBuffer`. Shows all repo-level fields: git, channels, model & execution,
resource limits, credentials, container environment.

Returns 404 if the repo_id does not exist in the current edit buffer.

### `PATCH /api/config/field`

Accepts JSON body:

```json
{"path": "dashboard.port", "source": "literal", "value": 5201}
{"path": "repos.my-project.email.password", "source": "env", "value": "EMAIL_PW"}
{"path": "repos.my-project.model", "source": "unset"}
```

Requires `X-Requested-With` header (CSRF protection, sent by htmx
automatically).

**Response:** HTML fragment for the updated field widget. htmx swaps the field
element in-place (`hx-swap="outerHTML"`). The response reflects the new buffer
state.

No validation is performed on individual field mutations — validation runs only
on save. This avoids noisy errors during mid-edit states (e.g., partially
configured OAuth2). Staleness is not checked on mutations either — only on save
(see Staleness Detection).

### `POST /api/config/add`

Accepts JSON body:

```json
{"path": "repos.my-project.email.authorized_senders"}
{"path": "repos.my-project.masked_secrets", "key": "NEW_TOKEN"}
{"path": "repos", "key": "new-project"}
{"path": "repos.my-project.email"}
```

Mutates the edit buffer (appends to list, creates keyed entry, creates channel
block). Returns an HTML fragment for the new item, which htmx appends to the
container (`hx-swap="beforeend"`).

### `POST /api/config/remove`

Accepts JSON body:

```json
{"path": "repos.my-project.email.authorized_senders", "index": 2}
{"path": "repos.my-project.masked_secrets", "key": "OLD_TOKEN"}
{"path": "repos.old-project"}
{"path": "repos.my-project.email"}
```

Mutates the edit buffer. Returns `200 OK`. The client removes the DOM element
client-side (no server-rendered response needed — the element is simply
deleted).

### `GET /api/config/diff`

Compares the edit buffer against the current live config. Returns an HTML
fragment showing changes grouped by reload scope.

The diff is computed by:

1. Resolving the edit buffer through
   `ServerConfig.from_source(InMemoryConfigSource(buffer._raw))`.
2. Comparing the resolved snapshot against the current live snapshot using
   `diff_by_scope()`.
3. Rendering changes as structured data: path, old value, new value, scope,
   field doc.

The response includes a scope summary: how many changes per scope, and whether a
server restart is required.

### `POST /api/config/save`

**Save flow:**

1. Check `buffer._generation` against current `_config_generation`. If stale,
   return stale-warning fragment.
2. Validate via `ServerConfig.from_source(InMemoryConfigSource(buffer._raw))`.
3. On validation failure: return error banner with details.
4. On success: write via `YamlConfigSource.save()` (atomic temp+rename).
5. Discard the edit buffer.
6. Return success banner with scope summary.

**Response fragments (swapped into `#save-result`):**

- **200:** Success banner with scope summary ("Applied. 2 changes (repo scope,
  no restart needed)").
- **422:** Validation error banner with details.
- **409:** Stale config banner with reload prompt.

### `POST /api/config/discard`

Discards the edit buffer. Returns redirect or success indicator. The page
reloads to show current live config.

## htmx Interaction Patterns

### Field Edit

```html
<div class="cfg-field" id="field-dashboard-port"
     hx-target="this" hx-swap="outerHTML">
  <label class="field-label">Port</label>
  <span class="cfg-scope server">server</span>
  <div class="cfg-source">
    <button hx-patch="/api/config/field"
            hx-vals='{"path":"dashboard.port","source":"unset"}'
            hx-headers='{"Content-Type":"application/json"}'>
      Not set
    </button>
    <button class="active">Literal</button>
  </div>
  <input type="number" value="5200"
         hx-patch="/api/config/field"
         hx-trigger="change"
         hx-vals='{"path":"dashboard.port","source":"literal"}'
         hx-headers='{"Content-Type":"application/json"}'
         name="value">
  <span class="cfg-help">Dashboard HTTP server port</span>
</div>
```

Each field is self-contained. Changing the value or clicking a source button
sends a PATCH. The server responds with the updated field HTML.

### Add Item

```html
<button hx-post="/api/config/add"
        hx-vals='{"path":"repos.my-project.email.authorized_senders"}'
        hx-target="#authorized-senders-list"
        hx-swap="beforeend"
        hx-headers='{"Content-Type":"application/json"}'>
  + Add
</button>
```

### Remove Item

```html
<button hx-post="/api/config/remove"
        hx-vals='{"path":"repos.my-project.email.authorized_senders","index":1}'
        hx-target="closest .cfg-list-item"
        hx-swap="delete">
  &times;
</button>
```

htmx's `hx-swap="delete"` removes the target element on successful response.

### Save Flow

```html
<button hx-get="/api/config/diff"
        hx-target="#diff-modal-body"
        hx-swap="innerHTML"
        onclick="document.getElementById('diff-modal').showModal()">
  Review &amp; Save
</button>

<dialog id="diff-modal">
  <div id="diff-modal-body"><!-- diff content loaded here --></div>
  <form method="dialog">
    <button hx-post="/api/config/save"
            hx-target="#save-result"
            hx-swap="innerHTML">
      Confirm Save
    </button>
    <button value="cancel">Cancel</button>
  </form>
</dialog>
```

### Dirty Indicator

The save bar shows an unsaved-changes count. Updated client-side: each
successful PATCH/add/remove increments a counter. Save/discard resets it.

```html
<div class="cfg-save-bar">
  <span id="dirty-count" class="cfg-dirty hidden">3 unsaved changes</span>
  <button hx-get="/api/config/diff" ...>Review &amp; Save</button>
  <button hx-post="/api/config/discard"
          hx-confirm="Discard all unsaved changes?">Discard</button>
</div>
```

### Stale Banner

When any API call returns a stale indicator, JavaScript shows a banner:

```html
<div id="stale-banner" class="cfg-banner warning hidden">
  Config changed externally. Unsaved changes will be lost.
  <a href="/config">Reload</a>
</div>
```

## Page Layout

Two page types, both using existing `.page` max-width (960px) and `.card`
pattern. Every editor page includes the save bar and stale banner — changes on
any page are tracked in the shared edit buffer.

### Global Settings Page (`/config`)

```
/config
├─ Navbar (existing, breadcrumb: "Configuration")
├─ .page
│  ├─ Save bar: dirty count + [Review & Save] [Discard]
│  ├─ #save-result (target for save/error banners)
│  ├─ #stale-banner (hidden by default)
│  │
│  ├─ Section: Server Settings
│  │  ├─ Card: Execution (max_concurrent, shutdown_timeout, conv_max_age, image_prune)
│  │  ├─ Card: Dashboard (enabled, host, port, base_url)
│  │  ├─ Card: Container & Network (container_command, upstream_dns)
│  │  └─ Card: Resource Limits — server default (nested ResourceLimits)
│  │
│  ├─ Section: Variables
│  │  └─ Card: vars section (dict[str, str] widget, values support !env)
│  │
│  ├─ Section: Repositories
│  │  ├─ Repo card: {repo_id} — summary (channels, model) + link to detail page
│  │  ├─ Repo card: {repo_id} — ...
│  │  └─ [+ Add Repository] button
│  │
│  └─ Footer: Save bar (mirrors top bar)
│
└─ Scripts: htmx + config-editor.js
```

### Repository Settings Page (`/config/repos/<repo_id>`)

```
/config/repos/{repo_id}
├─ Navbar (existing, breadcrumb: "Configuration / {repo_id}")
├─ .page
│  ├─ Save bar: dirty count + [Review & Save] [Discard]
│  ├─ #save-result
│  ├─ #stale-banner
│  │
│  ├─ Card: Git (repo_url)
│  ├─ Card: Email Channel (all EmailChannelConfig fields, or [+ Add])
│  ├─ Card: Slack Channel (all SlackChannelConfig fields, or [+ Add])
│  ├─ Card: Model & Execution (model, effort, network_sandbox_enabled)
│  ├─ Card: Resource Limits — per repo (nested ResourceLimits)
│  ├─ Card: Credentials
│  │  ├─ Secrets (dict_str_str widget)
│  │  ├─ Masked Secrets (keyed collection)
│  │  ├─ Signing Credentials (keyed collection)
│  │  └─ GitHub App Credentials (keyed collection)
│  ├─ Card: Container Environment (dict_str_str widget)
│  │
│  ├─ [Remove Repository] (with confirmation)
│  │
│  └─ Footer: Save bar
│
└─ Scripts: htmx + config-editor.js
```

### Scope Badges

Each card header shows a small badge indicating reload scope:

- **server** — blue (`--status-info`): requires restart
- **repo** — green (`--status-success`): reloadable per-repo
- **task** — amber (`--status-warning`): applied per-task immediately

### Field Labels

Follow the existing `.field-label` pattern (11px, uppercase, letter-spacing
0.05em, `--text-tertiary`). The doc string from `FieldMeta` is shown below the
input as a help line (12px, `--text-tertiary`, normal case).

### Responsive Behavior

- Desktop (>700px): field label + source selector on one line, input below.
  Resource limits use 2-column grid.
- Mobile (\<=700px): everything stacks vertically. Same breakpoint as existing
  `.task-row`.

## Validation

Validation runs **only on save**, not on individual field mutations. This avoids
noisy errors during mid-edit states (e.g., partially configured OAuth2 where
only `tenant_id` is filled in).

### Save Validation

1. Pass `buffer._raw` through
   `ServerConfig.from_source(InMemoryConfigSource(raw))`.
2. This exercises the full pipeline: migrations, variable resolution, field
   parsing, `__post_init__()` validation.
3. **Validation fails:** return 422 with error banner. YAML file untouched.
4. **Validation passes:** write atomically, return success.

### Safety Guardrails

- **Dashboard self-disable warning:** setting `dashboard.enabled: false`
  triggers a confirmation dialog warning that the dashboard will become
  inaccessible.
- **Zero repos rejected:** validation catches the zero-repos case.
- **Required field empty:** validation catches missing required fields.
- **Invalid config never written:** the validation step prevents any write that
  would break `ServerConfig.from_source()`.

## Optimistic Concurrency

Uses `GatewayService._config_generation` as the concurrency token:

1. **Buffer creation:** records current `_config_generation`.
2. **On page load:** if dirty buffer exists with stale generation, show warning
   banner. User can continue editing or discard.
3. **On save:** checks generation before writing. Stale → 409 with reload
   prompt. Mutations (PATCH, add, remove) do not check staleness.
4. **External changes:** inotify/SIGHUP increments generation. The staleness is
   detected on next page load or save attempt.

## Atomic Save

`YamlConfigSource.save()` is enhanced to write atomically using temp+rename:

```python
def save(self, data: dict[str, Any]) -> None:
    self.path.parent.mkdir(parents=True, exist_ok=True)
    tmp = self.path.with_suffix(".yaml.tmp")
    with open(tmp, "w") as f:
        yaml.dump(
            data,
            f,
            Dumper=make_tag_dumper(),
            default_flow_style=False,
            sort_keys=False,
        )
    tmp.rename(self.path)  # atomic on same filesystem
```

The config file watcher checks the event filename against the config filename
exactly (`airut.yaml`). The `CLOSE_WRITE` on `.yaml.tmp` does not match, so it
is ignored. The subsequent `MOVED_TO` on `airut.yaml` (from the rename) triggers
the reload.

## Security

### CSRF Protection

All mutation endpoints (`PATCH /api/config/field`, `POST /api/config/*`) require
an `X-Requested-With` header, matching the existing pattern on
`POST /api/conversation/{id}/stop`. htmx sends this automatically. CORS
preflight blocks cross-origin requests with custom headers.

### Secret Handling

Fields marked `secret=True` are rendered as plain text inputs. Secret values are
shown in full in the diff preview as well. The dashboard is single-user behind a
reverse proxy — masking adds friction without security benefit.

The `secret` flag in `FieldMeta` remains for other consumers (log redaction,
`SecretFilter`) but does not affect editor rendering or diff output.

### Access Control

Same model as the existing dashboard: no authentication (reverse proxy handles
it), localhost binding by default, same security response headers.

## Dashboard Integration

"Configure" button on the **main dashboard page** (in the `version_info.html`
component, not in the top navigation bar). The button is always present when the
config editor route is registered (Phase 1+). No separate feature flag — if the
editor code is deployed, it's available.

```html
<a href="/config" class="action-btn primary"
   style="font-size:12px; padding:3px 10px;">
  Configure
</a>
```

The config editor is a separate section of the dashboard — navigating to
`/config` leaves the task monitoring view. The top bar breadcrumb provides
navigation context.

### Breadcrumbs

| Page            | Breadcrumbs                |
| --------------- | -------------------------- |
| Global settings | Configuration              |
| Repo settings   | Configuration / \<repo_id> |

## Styling

New file: `airut/dashboard/static/styles/config.css`.

Extends the existing design system. No new colors, fonts, or spacing values:

- **`.cfg-field`** — field row with `set`/`unset` background states.
- **`.cfg-source`** — segmented control. Active segment uses `--accent`.
- **`.cfg-input`** — text input (`--font-mono`, 13px).
- **`.cfg-nested`** — bordered fieldset with responsive grid.
- **`.cfg-expandable`** — collapsible card for keyed collections.
- **`.cfg-list-item`** / **`.cfg-dict-entry`** — flex rows for items.
- **`.cfg-add-btn`** — dashed-border button for adding items.
- **`.cfg-save-bar`** — sticky header with save/discard and dirty count.
- **`.cfg-banner`** — feedback banners (success/error/warning/info).
- **`.cfg-diff`** — diff display: old/new values, scope badges.

Light/dark mode handled via existing `prefers-color-scheme` custom properties.
Responsive breakpoint at 700px matches existing pages.

## New Files

| File                                                          | Purpose                                                                          |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `airut/config/editor.py`                                      | `EditorFieldSchema`, `schema_for_editor()`, `EditBuffer`, `InMemoryConfigSource` |
| `airut/dashboard/handlers_config.py`                          | `ConfigEditorHandlers`: page, field, add, remove, diff, save, discard            |
| `airut/dashboard/templates/pages/config.html`                 | Global settings page template                                                    |
| `airut/dashboard/templates/pages/config_repo.html`            | Per-repo settings page template                                                  |
| `airut/dashboard/templates/components/config/field.html`      | Recursive field dispatch macro                                                   |
| `airut/dashboard/templates/components/config/scalar.html`     | Scalar input + source selector                                                   |
| `airut/dashboard/templates/components/config/list.html`       | List widget                                                                      |
| `airut/dashboard/templates/components/config/dict.html`       | Dict widget                                                                      |
| `airut/dashboard/templates/components/config/nested.html`     | Nested dataclass fieldset                                                        |
| `airut/dashboard/templates/components/config/collection.html` | Keyed collection (expandable cards)                                              |
| `airut/dashboard/templates/components/config/union_list.html` | Tagged union list widget                                                         |
| `airut/dashboard/static/js/config-editor.js`                  | Dirty counter, stale detection, dialog helpers                                   |
| `airut/dashboard/static/styles/config.css`                    | Config editor styles                                                             |

## Relationship to Existing Specs

- **`spec/declarative-config.md`** — this spec builds on `FieldMeta` annotations
  (including credential types, already annotated) and adds `schema_for_editor()`
  alongside `schema_for_ui()`.
- **`spec/config-reload.md`** — the editor writes YAML and relies on the
  existing inotify + reload pipeline.
- **`spec/dashboard.md`** — the editor is a new page following the same
  rendering architecture and security model.
- **`spec/repo-config.md`** — the editor renders the schema defined there.

## Implementation Phases

The edit buffer design supports incremental delivery. Each phase is
independently shippable and testable.

### Phase 1: Foundation + Global Settings

**Scope:** EditBuffer, API endpoints, global config page.

**Backend:**

- `EditBuffer` class with set_field, validate, diff, save, discard
- `InMemoryConfigSource` for validation
- `EditorFieldSchema` and `schema_for_editor()` for `GlobalConfig` and
  `ResourceLimits`
- All API endpoints: PATCH field, GET diff, POST save/discard
- Atomic save in `YamlConfigSource`
- Staleness detection
- Route registration in `DashboardServer`

**Frontend:**

- `/config` global settings page with save bar, stale banner, save-result target
- Repo list section (summary cards with links, no editing yet)
- Scalar field widget with source selector
- Nested dataclass widget (for `ResourceLimits`)
- Diff modal with scope grouping
- `config-editor.js` (dirty counter, stale handling, dialog)
- `config.css`

**Templates:**

- `pages/config.html`, `components/config/field.html`,
  `components/config/scalar.html`, `components/config/nested.html`

**Not included:** repo editing, channels, credentials, list/dict/collection
widgets. Repo cards on `/config` link to repo detail pages but those pages are
not yet implemented.

### Phase 2: Repos + Simple Fields

**Scope:** Per-repo settings page with scalar/nested fields.

**Backend:**

- `schema_for_editor()` extended for `RepoServerConfig`
- Add/remove repo operations in `EditBuffer`
- Repo skeleton generation for add
- `GET /config/repos/<repo_id>` handler

**Frontend:**

- `/config/repos/<repo_id>` page with per-repo cards: Git, Model & Execution,
  Resource Limits
- [+ Add Repository] button on `/config` page
- [Remove Repo] with confirmation on repo detail page

**Templates:**

- `pages/config_repo.html`

### Phase 3: Channels

**Scope:** Email and Slack channel configuration.

**Backend:**

- `schema_for_editor()` extended for `EmailChannelConfig`, `SlackChannelConfig`
- Add/remove channel operations in `EditBuffer`

**Frontend:**

- Email channel card with all fields (IMAP, SMTP, OAuth2, authorized_senders)
- Slack channel card with fields (bot_token, app_token)
- List widget for `authorized_senders`
- Tagged union list widget for Slack `authorized`
- [+ Add Email/Slack Channel] / [Remove Channel]

**Templates:**

- `components/config/list.html`, `components/config/union_list.html`

### Phase 4: Credentials + Dict Fields

**Scope:** All credential types and dict-based fields.

**Backend:**

- `schema_for_editor()` extended for `MaskedSecret`, `SigningCredential`,
  `SigningCredentialField`, `GitHubAppCredential` (FieldMeta annotations already
  exist on these types)

**Frontend:**

- Dict widget for `secrets`, `container_env`
- Keyed collection widget for `masked_secrets`, `signing_credentials`,
  `github_app_credentials`
- Expandable cards with nested sub-forms

**Templates:**

- `components/config/dict.html`, `components/config/collection.html`

### Phase 5: Variables

**Scope:** `vars:` section editing with cross-reference hints.

**Backend:**

- Vars section in edit buffer
- Variable reference resolution for hints

**Frontend:**

- Variables card with dict widget
- `!var` hints in field widgets showing resolved value
- Variable rename/delete awareness

## Test Plan

Tests for each phase. Unit tests for `EditBuffer` and schema; integration tests
for HTTP endpoints.

### EditBuffer Unit Tests

| Test                             | Verifies                                   |
| -------------------------------- | ------------------------------------------ |
| `test_create_from_snapshot`      | Buffer deep-copies raw, records generation |
| `test_set_literal_field`         | Scalar set updates raw dict                |
| `test_set_env_field`             | EnvVar stored in raw dict                  |
| `test_set_var_field`             | VarRef stored in raw dict                  |
| `test_unset_field`               | Key removed, empty parents pruned          |
| `test_set_nested_path`           | Intermediate dicts created                 |
| `test_add_list_item`             | Item appended to list                      |
| `test_add_keyed_collection_item` | Entry created with key                     |
| `test_remove_list_item`          | Item removed by index                      |
| `test_remove_keyed_item`         | Entry removed by key                       |
| `test_add_repo`                  | Repo skeleton created                      |
| `test_remove_repo`               | Repo removed, others intact                |
| `test_add_channel`               | Channel block created with placeholders    |
| `test_remove_channel`            | Channel block removed                      |
| `test_dirty_tracking`            | Clean after create, dirty after mutation   |
| `test_validate_success`          | Valid buffer passes full pipeline          |
| `test_validate_failure`          | Invalid buffer returns error               |
| `test_staleness_detection`       | Stale when generation mismatches           |

### API Integration Tests

| Test                              | Verifies                                         |
| --------------------------------- | ------------------------------------------------ |
| `test_config_page_loads`          | GET /config → 200, creates buffer                |
| `test_repo_page_loads`            | GET /config/repos/{id} → 200                     |
| `test_repo_page_404`              | GET /config/repos/nonexistent → 404              |
| `test_patch_field_literal`        | PATCH returns updated HTML fragment              |
| `test_patch_field_env`            | EnvVar in buffer after PATCH                     |
| `test_patch_field_unset`          | Key removed from buffer after PATCH              |
| `test_patch_stale_buffer`         | Returns stale warning when generation mismatches |
| `test_add_list_item_returns_html` | POST add returns item fragment                   |
| `test_remove_item`                | POST remove succeeds, buffer updated             |
| `test_diff_shows_changes`         | GET diff returns structured change list          |
| `test_diff_groups_by_scope`       | Changes grouped by server/repo/task              |
| `test_save_valid_config`          | POST save → 200, YAML written, buffer discarded  |
| `test_save_invalid_config`        | POST save → 422, YAML unchanged                  |
| `test_save_stale_config`          | POST save → 409 when generation mismatches       |
| `test_save_triggers_reload`       | Generation increments after save                 |
| `test_discard_resets_buffer`      | POST discard → buffer cleared                    |
| `test_csrf_required`              | Requests without X-Requested-With → 403          |

### Round-Trip Tests

| Test                               | Verifies                             |
| ---------------------------------- | ------------------------------------ |
| `test_save_preserves_env_tags`     | `!env` references survive round-trip |
| `test_save_preserves_var_tags`     | `!var` references survive round-trip |
| `test_save_preserves_vars_section` | `vars:` section preserved            |
| `test_save_only_set_fields`        | Unset fields absent from YAML        |
| `test_save_sets_config_version`    | Output has `config_version: 2`       |

### Composite Type Tests

| Test                                 | Verifies                                  |
| ------------------------------------ | ----------------------------------------- |
| `test_list_add_and_save`             | Multiple authorized_senders in YAML       |
| `test_list_remove_and_save`          | Item absent after removal                 |
| `test_dict_save_secrets`             | Key-value pairs with !env preserved       |
| `test_masked_secret_round_trip`      | MaskedSecret with scopes → correct reload |
| `test_signing_credential_round_trip` | SigningCredential → correct reload        |
| `test_github_app_round_trip`         | GitHubAppCredential → correct reload      |
| `test_slack_authorized_round_trip`   | Tagged union rules → correct reload       |

### Safety Tests

| Test                                | Verifies                               |
| ----------------------------------- | -------------------------------------- |
| `test_dashboard_disable_warning`    | `enabled: false` → warning in response |
| `test_atomic_write`                 | Save uses temp+rename                  |
| `test_invalid_config_not_written`   | Validation fail → YAML unchanged       |
| `test_external_change_invalidates`  | Config change → buffer marked stale    |
| `test_concurrent_tabs_share_buffer` | Two requests see same buffer state     |
