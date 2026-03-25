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
   `_config_generation`. If `raw` is `None` (synthetic snapshot without YAML
   backing), the editor returns an error — editing requires a file-backed
   config.
2. **Mutated** by PATCH and POST API calls. Each mutation modifies `_raw`
   in-place and sets `_dirty = True`.
3. **Persists** across page navigations — state lives on the server, not in the
   browser form. Opening `/config` in two tabs operates on the same buffer.
4. **Discarded** on explicit discard (`POST /api/config/discard`).
5. **Marked clean** on successful save (`POST /api/config/save`). The buffer is
   retained (not discarded) so the redirect page load shows saved values even
   before the file watcher reloads. Once the watcher bumps `_config_generation`,
   `_ensure_buffer` auto-refreshes the stale clean buffer on the next page load.
6. **No idle timeout** while dirty. A clean (non-dirty) buffer may be discarded
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
- **Auto-refresh:** if a buffer is stale but clean (no unsaved edits), it is
  silently replaced with a fresh copy from the current snapshot on next page
  load. This handles the post-save case where the file watcher has reloaded.

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

### Editor Schema

Module: `airut/config/editor_schema.py` (re-exported from
`airut/config/editor.py`).

#### `EditorFieldSchema`

Describes a single field or composite structure for UI rendering:

```python
@dataclass(frozen=True)
class EditorFieldSchema:
    name: str  # display name
    path: str  # dot-delimited path in raw dict (e.g. "dashboard.port")
    type_tag: str  # widget type (see table below)
    python_type: str  # "str", "int", "float", "bool", etc.
    default: object  # MISSING sentinel if required
    required: bool
    doc: str  # from FieldMeta
    scope: str  # "server", "repo", "task"
    secret: bool
    multiline: bool = False  # use textarea (set via FIELD_OVERRIDES)
    nested_fields: list[EditorFieldSchema] | None = None
    item_class_name: str | None = None
    item_fields: list[EditorFieldSchema] | None = None
    tagged_union_rules: list[tuple[str, str, str]] | None = None
    env_eligible: bool = True
    var_eligible: bool = True
```

**Type tags** classify each field for widget selection:

| Type tag            | Python type                                      | Widget          |
| ------------------- | ------------------------------------------------ | --------------- |
| `scalar`            | `str`, `int`, `float`, `bool`                    | Text/select     |
| `list_str`          | `list[str]`, `tuple[str, ...]`, `frozenset[str]` | Vertical list   |
| `dict_str_str`      | `dict[str, str]`                                 | Key-value rows  |
| `nested`            | Any `@dataclass` with FieldMeta                  | Inline fieldset |
| `keyed_collection`  | `dict[str, <dataclass>]`                         | Expandable card |
| `tagged_union_list` | Slack `authorized` pattern                       | Rule list       |

#### `schema_for_editor()`

Walks dataclass fields recursively to produce `EditorFieldSchema` trees. Uses
`FieldMeta` for metadata and `YAML_*_STRUCTURE` mappings to compute the `path`
for each field.

#### `InMemoryConfigSource`

A read-only `ConfigSource` for pre-save validation:

```python
class InMemoryConfigSource:
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
`repos.my-project.email.imap.poll_interval`).

#### Set Field

- `source=literal` → store coerced Python value (`int`, `float`, `bool`, or
  `str`)
- `source=env` → store `EnvVar(var_name)`
- `source=var` → store `VarRef(var_name)`
- `source=unset` → remove the key from the dict. If the parent dict becomes
  empty, prune it recursively.

#### Add Item

Adds to a list (append empty string) or keyed collection (create entry with
given key and default structure).

#### Remove Item

Removes from a list (by index) or keyed collection (by key).

#### Set List Item

Updates a single item in a `list[str]` field by index.

#### Set Tagged Union Item

Updates a single item in a tagged union list by index, replacing it with a new
`{key: value}` dict.

### Unified Source Selector

Every scalar field gets a segmented control:

```
┌──────────┬─────────┬──────┬──────┐
│ Not set  │ Literal │ !env │ !var │
└──────────┴─────────┴──────┴──────┘
```

| Field type                  | Not set | Literal | !env | !var |
| --------------------------- | ------- | ------- | ---- | ---- |
| Required `str` (no default) | No      | Yes     | Yes  | Yes  |
| Optional `str \| None`      | Yes     | Yes     | Yes  | Yes  |
| `str` with default          | Yes     | Yes     | Yes  | Yes  |
| `int` / `float`             | Yes\*   | Yes     | Yes  | Yes  |
| `bool`                      | Yes\*   | Yes     | No   | No   |

\*"Not set" available only when the field has a default (is not required).

### Boolean Fields

Boolean fields use a `<select>` dropdown with `true`/`false` options instead of
a checkbox. This avoids CSP issues with inline event handlers (the server sets
`script-src 'self'`) and provides a consistent visual appearance matching other
field types.

### Dirty Count

The dirty count tracks the number of leaf fields that actually differ between
the edit buffer and the live config snapshot. It is computed **server-side** by
comparing each leaf field in the editor schema, using the same per-field
comparison logic as the diff endpoint.

The count is communicated to the client in two ways:

1. **Page load** — page routes pass `dirty_count` to the template, which renders
   button `disabled` state and dirty-count span visibility server-side. This
   ensures the UI is correct on first load (e.g. after a JS redirect following
   an "Add Repository" action).
2. **AJAX mutations** — the count is returned in the `X-Dirty-Count` response
   header from all mutation endpoints (PATCH field, POST add, POST remove). The
   client reads this header and updates the display.

This approach is accurate even when a field is edited then reverted to its
original value (count correctly returns to 0).

The "Review & Save" and "Discard" buttons are **disabled** when the dirty count
is 0, preventing no-op saves.

## HTTP Endpoints

### Page Routes

| Route                     | Method | Description                                 |
| ------------------------- | ------ | ------------------------------------------- |
| `/config`                 | GET    | Global settings (execution, dashboard, ...) |
| `/config/repos/<repo_id>` | GET    | Per-repo settings (Phase 2)                 |

### API Routes

| Route                 | Method | Description                           |
| --------------------- | ------ | ------------------------------------- |
| `/api/config/field`   | PATCH  | Set or clear a single field           |
| `/api/config/add`     | POST   | Add item to list/dict/collection      |
| `/api/config/remove`  | POST   | Remove item from list/dict/collection |
| `/api/config/diff`    | GET    | Compare buffer vs live config         |
| `/api/config/save`    | POST   | Validate + write YAML                 |
| `/api/config/discard` | POST   | Reset edit buffer                     |

### `PATCH /api/config/field`

Accepts **form-encoded** body (not JSON):

```
path=dashboard.port&source=literal&value=5201
path=dashboard.host&source=env&value=DASH_HOST
path=dashboard.enabled&source=unset
```

Requires `X-Requested-With` header (CSRF protection). Returns HTML fragment for
the updated field widget. htmx swaps the field element in-place
(`hx-swap="outerHTML"`). Response includes `X-Dirty-Count` header with the
current number of fields that differ from the live config.

No validation is performed on individual field mutations — validation runs only
on save. Staleness is not checked on mutations either — only on save.

### `POST /api/config/add`

Accepts form-encoded body: `path=repos.my-project.email.authorized_senders` or
`path=repos&key=new-project`. Returns `200 OK` with `X-Dirty-Count` header.

### `POST /api/config/remove`

Accepts form-encoded body: `path=...&index=2` or `path=...&key=OLD_TOKEN`.
Returns `200 OK` with `X-Dirty-Count` header.

### `GET /api/config/diff`

Compares the edit buffer against the current live config per leaf field. Returns
an HTML fragment showing changes grouped by reload scope, with per-field entries
(field path, old value, new value, scope badge).

### `POST /api/config/save`

**Save flow:**

1. Check `buffer._generation` against current `_config_generation`. If stale,
   return 409 with error fragment.
2. Validate via `ServerConfig.from_source(InMemoryConfigSource(buffer._raw))`.
3. On validation failure: return 422 with error fragment.
4. On success: write via `YamlConfigSource.save()` (atomic temp+rename).
5. Mark buffer clean (retain for redirect page load).
6. Return 200 with `HX-Redirect: /config`.

### `POST /api/config/discard`

Discards the edit buffer. Returns 200 with `HX-Redirect: /config`.

## htmx Interaction Patterns

All mutation endpoints use form-encoded bodies (not JSON). Field widgets use
`hx-vals` for path/source and `hx-include="this"` with `name="value"` for the
input value.

### Field Edit

```html
<div class="cfg-field" id="field-dashboard-port"
     hx-target="this" hx-swap="outerHTML">
  <div class="cfg-field-header">
    <span class="cfg-label">port</span>
    <span class="cfg-scope cfg-server">server</span>
    <div class="cfg-source">
      <button hx-patch="/api/config/field"
              hx-vals='{"path":"dashboard.port","source":"unset"}'
              hx-headers='{"X-Requested-With":"XMLHttpRequest"}'>
        Not set
      </button>
      <button class="active" ...>Literal</button>
    </div>
  </div>
  <input class="cfg-input" type="number" value="5200"
         hx-patch="/api/config/field"
         hx-trigger="change"
         hx-vals='{"path":"dashboard.port","source":"literal"}'
         hx-headers='{"X-Requested-With":"XMLHttpRequest"}'
         name="value" hx-include="this">
  <span class="cfg-help">Dashboard HTTP server port</span>
</div>
```

### Boolean Field

```html
<select class="cfg-input"
        hx-patch="/api/config/field"
        hx-trigger="change"
        hx-vals='{"path":"dashboard.enabled","source":"literal"}'
        hx-headers='{"X-Requested-With":"XMLHttpRequest"}'
        name="value" hx-include="this">
  <option value="true" selected>true</option>
  <option value="false">false</option>
</select>
```

### Save Flow

The "Review & Save" button fetches the diff via `hx-get="/api/config/diff"` and
swaps it into `#diff-modal-body`. A `htmx:afterSwap` event listener opens the
dialog via `dialog.showModal()`. The cancel button uses `addEventListener` (not
inline `onclick`) to comply with CSP `script-src 'self'`.

### Dirty Indicator and Button State

The save bar shows an unsaved-changes count after the action buttons. On page
load the server passes `dirty_count` to the template, which conditionally
renders the button `disabled` attribute and span visibility. After AJAX
mutations the count is read from the `X-Dirty-Count` response header and the
display is updated by JavaScript.

```html
<div class="cfg-save-bar">
  <button id="review-save-btn" class="cfg-btn primary"
          {{ '' if dirty_count else 'disabled' }} ...>
    Review &amp; Save
  </button>
  <button id="discard-btn" class="cfg-btn danger"
          {{ '' if dirty_count else 'disabled' }} ...>
    Discard
  </button>
  <span id="dirty-count"
        class="cfg-dirty {{ '' if dirty_count else 'hidden' }}">
    ...
  </span>
</div>
```

## Page Layout

### Global Settings Page (`/config`)

```
/config
├─ Navbar (breadcrumb: "Configuration")
├─ .page
│  ├─ Save bar: [Review & Save] [Discard] dirty count
│  ├─ Stale banner (shown when buffer dirty + stale)
│  │
│  ├─ Section: Server Settings
│  │  ├─ Card: Execution
│  │  ├─ Card: Dashboard
│  │  ├─ Card: Container & Network
│  │  └─ Card: Resource Limits — server default (nested)
│  │
│  ├─ Section: Repositories
│  │  └─ Repo cards: summary + link to detail page
│  │
│  └─ Diff dialog (modal)
│
└─ Scripts: htmx + config-editor.js
```

### Scope Badges

Each card header shows a small badge indicating reload scope:

- **server** — blue (`--status-info`): requires restart
- **repo** — green (`--status-success`): reloadable per-repo
- **task** — amber (`--status-warning`): applied per-task immediately

## Validation

Validation runs **only on save**, not on individual field mutations. This avoids
noisy errors during mid-edit states.

1. Pass `buffer._raw` through
   `ServerConfig.from_source(InMemoryConfigSource(raw))`.
2. **Validation fails:** return 422 with error banner. YAML file untouched.
3. **Validation passes:** write atomically, return success with redirect.

## Optimistic Concurrency

Uses `GatewayService._config_generation` as the concurrency token:

1. **Buffer creation:** records current `_config_generation`.
2. **On page load:** if dirty buffer exists with stale generation, show warning
   banner.
3. **On save:** checks generation before writing. Stale → 409.
4. **On page load with stale clean buffer:** auto-refresh from current snapshot.

## Security

### CSRF Protection

All mutation endpoints require `X-Requested-With` header. htmx sends this via
`hx-headers`. CORS preflight blocks cross-origin custom headers.

### CSP Compliance

The server sets `script-src 'self'` which blocks inline event handlers. All
JavaScript behavior uses event listeners in `config-editor.js`, not inline
`onclick`/`onchange` attributes.

### Access Control

Same model as the existing dashboard: no authentication (reverse proxy handles
it), localhost binding by default.

## Styling

File: `airut/dashboard/static/styles/config.css`.

Extends the existing design system with no new colors, fonts, or spacing values:

- **`.cfg-save-bar`** — flex container with action buttons and dirty count.
- **`.cfg-field`** — field row with `set`/`unset` background states.
- **`.cfg-source`** — segmented control. Active segment uses `--accent`.
- **`.cfg-input`** — text/number/select input (`--font-mono`, 13px).
- **`.cfg-btn`** — action buttons with `:disabled` state (opacity 0.4).
- **`.cfg-banner`** — feedback banners (success/error/warning/info).
- **`.cfg-dialog`** — centered modal (`margin: auto` for `<dialog>`).
- **`.cfg-diff-table`** — diff display: old/new values, scope badges.

## New Files

| File                                                           | Purpose                                          |
| -------------------------------------------------------------- | ------------------------------------------------ |
| `airut/config/editor.py`                                       | `EditBuffer`, `InMemoryConfigSource`, re-exports |
| `airut/config/editor_schema.py`                                | `EditorFieldSchema`, `schema_for_editor()`       |
| `airut/dashboard/handlers_config.py`                           | `ConfigEditorHandlers`: all HTTP handlers        |
| `airut/dashboard/templates/pages/config.html`                  | Global settings page template                    |
| `airut/dashboard/templates/pages/config_repo.html`             | Per-repo settings page template                  |
| `airut/dashboard/templates/components/config/field.html`       | Recursive field dispatch macro                   |
| `airut/dashboard/templates/components/config/scalar.html`      | Scalar input + source selector                   |
| `airut/dashboard/templates/components/config/nested.html`      | Nested dataclass fieldset                        |
| `airut/dashboard/templates/components/config/diff_result.html` | Diff result fragment                             |
| `airut/dashboard/templates/components/config/save_result.html` | Save error fragment                              |
| `airut/dashboard/static/js/config-editor.js`                   | Dirty counter, dialog helpers, button state      |
| `airut/dashboard/static/styles/config.css`                     | Config editor styles                             |

## Implementation Phases

### Phase 1: Foundation + Global Settings (implemented)

**Backend:** `EditBuffer`, `InMemoryConfigSource`, `EditorFieldSchema`,
`schema_for_editor()`, all API endpoints, staleness detection, server-side dirty
count computation, route registration in `DashboardServer`.

**Frontend:** `/config` global settings page with save bar, stale banner, diff
modal, scalar field widget with source selector (text/number/select dropdown for
bools), nested dataclass widget (ResourceLimits), repo list (summary cards with
links). `config-editor.js` (server-reported dirty counter, dialog helpers,
button enable/disable). `config.css`.

**Not included:** repo editing, channels, credentials, list/dict/collection
widgets.

### Phase 2: Repos + Simple Fields (implemented)

Per-repo settings page with scalar/nested fields. `GET /config/repos/<repo_id>`
handler. Add/remove repo operations. Repo skeleton generation.

### Phase 3: Channels (implemented)

Email and Slack channel configuration. List widget for `authorized_senders`.
Tagged union list widget for Slack `authorized`. Add/remove channel operations.

### Phase 4: Credentials + Dict Fields

All credential types (`MaskedSecret`, `SigningCredential`,
`GitHubAppCredential`) and dict-based fields. Keyed collection widget with
expandable cards.

### Phase 5: Variables

`vars:` section editing with cross-reference hints. Variable rename/delete
awareness.
