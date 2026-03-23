# Config Editor

A schema-driven web editor for the server configuration file, integrated into
the dashboard. The editor renders the full config form from declarative
`FieldMeta` annotations — adding a field to a config dataclass automatically
surfaces it in the editor with zero template changes.

## Goals

1. **Schema-driven rendering** — every form element is generated recursively
   from `FieldMeta` annotations. No field is hardcoded in templates. Adding a
   new config field with `metadata=meta(...)` automatically makes it appear.
2. **Full type coverage** — handle all composite types in the config: nested
   dataclasses, `list[str]`, `dict[str, str]`, keyed collections of structured
   types (`dict[str, MaskedSecret]` etc.), and tagged union lists (Slack
   `authorized`).
3. **Value source control** — every scalar field supports a unified selector for
   value source: Not set (use default), Literal, `!env`, `!var`. This replaces
   the need for separate clear/reset controls.
4. **Round-trip fidelity** — `!env` and `!var` tags survive load-edit-save
   cycles. Unset fields are excluded from the YAML file (defaults are never
   baked in).
5. **Validation before write** — proposed changes are validated through the full
   `ServerConfig.from_source()` pipeline before touching the YAML file. Invalid
   config is never written.
6. **Optimistic concurrency** — uses the existing `_config_generation` counter
   to detect concurrent edits (including external file changes via inotify).
7. **Observable reload feedback** — after save, the editor reports whether the
   server successfully reloaded, shows any reload errors, and indicates when a
   restart is required for server-scope changes.
8. **Consistent dashboard aesthetic** — reuses existing CSS custom properties,
   component patterns, and responsive breakpoints.

## Non-Goals

- Preserving YAML comments or formatting (lossy save is acceptable).
- Undo/redo history.
- Multi-user concurrent editing (single-user system behind reverse proxy).
- Editing config from the CLI (the editor is dashboard-only).
- Live preview of config changes before save.

## Dependency

No new dependencies. The editor uses the existing stack: Werkzeug (WSGI), Jinja2
(templates), htmx (vendored), stdlib `dataclasses` and `typing`.

## Design

### Data Flow

```
Browser (HTMX)
  GET /config           → Full page with form (schema-driven)
  POST /api/config      → Validate + write YAML → result fragment
  POST /api/config/add  → Render new list/dict/collection item fragment

                          ↓ writes YAML (atomic temp+rename)

Config File (~/.config/airut/airut.yaml)

                          ↓ inotify CLOSE_WRITE

ConfigFileWatcher → GatewayService._on_config_changed()
                    → diff, apply by scope (task/repo/server)
```

The editor reads the current `ConfigSnapshot.raw` (preserving `!env`/`!var`
tags), validates proposed changes through the full `ServerConfig.from_source()`
pipeline, and writes back to the YAML file. The existing `ConfigFileWatcher`
detects the change and triggers the normal reload path. No new reload codepath
is introduced.

### Existing Foundation

The editor builds on infrastructure from `spec/declarative-config.md` and
`spec/config-reload.md`:

- **`FieldMeta` + `meta()`** — per-field metadata (doc, scope, secret,
  since_version) on all config dataclasses.
- **`ConfigSnapshot`** — wraps frozen config, tracks `provided_keys` (user-set
  fields), preserves `raw` dict with `EnvVar`/`VarRef` objects for round-trip.
- **`ConfigSource` protocol** — `load()` / `save()` with `YamlConfigSource`
  implementation that handles `!env`/`!var` YAML tags.
- **YAML structure mappings** — `YAML_GLOBAL_STRUCTURE`, `YAML_EMAIL_STRUCTURE`,
  `YAML_REPO_STRUCTURE` for flat-to-nested conversion. Note: there is no
  `YAML_SLACK_STRUCTURE` — Slack channel config uses direct dict keys matching
  the dataclass field names. The editor's `form_to_raw_dict()` passes Slack
  config through without flat-to-nested conversion.
- **`_config_generation`** — monotonic counter incremented on each successful
  reload, exposed via `/api/status`.
- **`_last_reload_error`** — traceback string from the most recent failed
  reload.

### FieldMeta Extension to Credential Types

The existing `schema_for_ui()` covers `GlobalConfig`, `RepoServerConfig`,
`EmailChannelConfig`, `SlackChannelConfig`, and `ResourceLimits`. The
declarative-config spec explicitly excludes credential types (`MaskedSecret`,
`SigningCredential`, `SigningCredentialField`, `GitHubAppCredential`) from
`FieldMeta` annotations, stating they would be handled through specialized
key-value editors.

The config editor reverses this decision: **add `FieldMeta` annotations to all
credential types** so the entire config tree is self-describing. This enables
`schema_for_editor()` to walk all types recursively without any hardcoded
registry.

Types to annotate:

- `MaskedSecret` — `value`, `scopes`, `headers`, `allow_foreign_credentials`
- `SigningCredential` — `access_key_id`, `secret_access_key`, `session_token`,
  `scopes`
- `SigningCredentialField` — `name`, `value`
- `GitHubAppCredential` — all 8 fields (`app_id`, `private_key`,
  `installation_id`, `scopes`, `allow_foreign_credentials`, `base_url`,
  `permissions`, `repositories`)

The Slack `authorized` field already has `FieldMeta`. The tagged union rule
types (`workspace_members`, `user_group`, `user_id`) are handled via a small
metadata extension (see Tagged Union List below).

**Impact on `spec/declarative-config.md`:** The "Excluded from `FieldMeta`
annotations" list is updated — credential types move to the annotated set. The
rationale ("dynamic keys, variable structure") is superseded by the recursive
schema walker which handles keyed collections natively.

### Editor Schema

Module: `airut/config/editor.py`.

#### `EditorFieldSchema`

Extends the existing `FieldSchema` with recursive structure for composite types:

```python
@dataclass(frozen=True)
class EditorFieldSchema:
    name: str
    yaml_path: tuple[str, ...]  # nested YAML location
    type_tag: str  # see Type Tags below
    python_type: str  # "str", "int", "float", "bool", etc.
    default: Any  # MISSING if required
    required: bool
    doc: str
    scope: str  # "server", "repo", "task"
    secret: bool
    multiline: bool = False  # use textarea
    nested_fields: list[EditorFieldSchema] | None = None
    item_class_name: str | None = None
    item_fields: list[EditorFieldSchema] | None = None
    tagged_union_rules: list[tuple[str, str, str]] | None = None
    env_eligible: bool = True  # can use !env
    var_eligible: bool = True  # can use !var
```

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

Walks dataclass fields recursively to produce `EditorFieldSchema` trees:

1. For each field with `FieldMeta`, produce an `EditorFieldSchema`.
2. Map type annotation to `type_tag` using the table above.
3. If field type is a `@dataclass` with `FieldMeta` fields, recurse into it →
   populate `nested_fields`.
4. If field type is `dict[str, <dataclass>]`, introspect the item class →
   populate `item_fields` and `item_class_name`.
5. For tagged union fields, populate `tagged_union_rules`.

#### `form_to_raw_dict()`

Parses dot-delimited form field names into a nested dict suitable for
`YamlConfigSource.save()`:

1. Group form fields by path prefix.
2. For each field, read the `_source` and `_value` hidden inputs.
3. `source=unset` → field omitted from dict (uses default).
4. `source=literal` → literal value (coerced to `int`/`float`/`bool` as needed).
5. `source=env` → `EnvVar(value)`.
6. `source=var` → `VarRef(value)`.
7. Lists/dicts assembled from indexed items.
8. Return raw dict in the same structure as `YamlConfigSource.load()` output.

#### `InMemoryConfigSource`

```python
class InMemoryConfigSource:
    """ConfigSource that returns a pre-built dict for validation."""

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

### Unified Source Selector

Every scalar field gets a **four-state segmented control** that combines value
source selection with the "not set" state:

```
┌──────────┬─────────┬──────┬──────┐
│ Not set  │ Literal │ !env │ !var │
└──────────┴─────────┴──────┴──────┘
```

**Not set** — field is excluded from the config file. The input area shows the
effective default value as placeholder text (grayed out). The field row uses
`--bg-inset` background. This is the "clear" action.

**Literal** — user types a literal value directly.

**!env** — user types an environment variable name (e.g., `EMAIL_PASSWORD`).
Below the input, a resolved-value hint shows the current value (or "(not set)"
if the env var is unset).

**!var** — user types a config variable name (referencing the `vars:` section).
Below the input, a resolved-value hint shows the resolved value.

#### Which Fields Get Which Options

| Field type                  | Not set | Literal | !env | !var |
| --------------------------- | ------- | ------- | ---- | ---- |
| Required `str` (no default) | No      | Yes     | Yes  | Yes  |
| Optional `str \| None`      | Yes     | Yes     | Yes  | Yes  |
| `str` with default          | Yes     | Yes     | Yes  | Yes  |
| `int` / `float`             | Yes\*   | Yes     | Yes  | No   |
| `bool`                      | Yes\*   | Yes     | No   | No   |

\*"Not set" available only when the field has a default (is not required).

#### Form Encoding

Each field emits two form inputs:

```html
<input type="hidden" name="path.to.field._source" value="env">
<input type="text" name="path.to.field._value" value="EMAIL_PASSWORD">
```

For "Not set": `_source=unset`, no `_value` emitted (or ignored).

### Composite Type Widgets

Eight composite types require specialized rendering. All are driven by the
schema tree — no widget is hardcoded to a specific field name.

#### Type 1: Nested Dataclass (`ResourceLimits`)

**Where used:** `GlobalConfig.resource_limits`,
`RepoServerConfig.resource_limits`

Inline fieldset within a card. Each sub-field uses the standard scalar widget
with unified source selector. The whole block can be toggled to "Not set" at the
global level (where the type is `ResourceLimits | None`). Per-repo
`resource_limits` is non-optional (defaults to `ResourceLimits()` with all-None
sub-fields), so the top-level "Not set" toggle is only available at the global
level.

Desktop layout uses a 2-column grid; mobile stacks vertically.

#### Type 2: List of Strings (`list[str]`, `tuple[str, ...]`, `frozenset[str]`)

**Where used:** `authorized_senders`, `scopes` (frozenset), `headers` (tuple),
`repositories` (tuple)

Vertical list with add/remove. Each item is a text input. String items get
source selectors (Literal/!env/!var). Per-item [x] remove button is distinct
from field-level "Not set" which controls the entire list.

```
Authorized Senders                                  [+ Add]
┌────────────────────────────────────────────────────────────┐
│  [Literal] [you@example.com                         ] [x]  │
│  [Literal] [*@company.com                           ] [x]  │
└────────────────────────────────────────────────────────────┘
```

#### Type 3: Dict of Strings (`dict[str, str]`)

**Where used:** `secrets`, `container_env`, `permissions`

Key-value rows with add/remove. Keys are plain text inputs (always literals).
Values get source selectors.

```
Secrets                                              [+ Add]
┌────────────────────────────────────────────────────────────┐
│  Key: [ANTHROPIC_API_KEY]  Value: [!env] [ANTHROPIC_A.] [x]│
│  Key: [OTHER_TOKEN      ]  Value: [Literal] [sk-ant..] [x] │
└────────────────────────────────────────────────────────────┘
```

#### Type 4: Keyed Collection (`dict[str, MaskedSecret]`)

Expandable card per entry. Collapsed shows key + summary. Expanded shows full
sub-form with all sub-fields rendered recursively via `item_fields`.

The key (dict key) is a text input. The value is a nested form generated from
`MaskedSecret`'s `FieldMeta`-annotated fields: `value` (scalar with source
selector), `scopes` (list_str widget), `headers` (list_str widget),
`allow_foreign_credentials` (bool toggle).

#### Type 5: Keyed Collection (`dict[str, SigningCredential]`)

Same expandable card pattern. Each `SigningCredentialField` sub-field (name +
value) renders as a two-field inline group. `session_token` is optional
(`SigningCredentialField | None`). `scopes` uses the list_str widget.

The YAML representation includes a `type: aws-sigv4` discriminator field that is
not part of the `SigningCredential` dataclass but is required for parsing. The
editor emits this field automatically on save (read-only display in the card).

#### Type 6: Keyed Collection (`dict[str, GitHubAppCredential]`)

Same expandable card. `private_key` uses a `<textarea>` (multiline PEM key).
`permissions` is an optional `dict[str, str]` widget. `repositories` is an
optional `tuple[str, ...] | None` list widget.

Like signing credentials, the YAML representation includes a `type: github-app`
discriminator field emitted automatically on save.

#### Type 7: Tagged Union List (Slack `authorized`)

Each item has a **rule type dropdown** and a **type-specific value input**:

```
Authorization Rules                                  [+ Add]
┌────────────────────────────────────────────────────────────┐
│  [workspace_members ▾]  [✓ enabled]                   [x]  │
│  [user_group        ▾]  [engineering                ] [x]  │
│  [user_id           ▾]  [U12345678                  ] [x]  │
└────────────────────────────────────────────────────────────┘
```

Rule type metadata is encoded in a `TAGGED_UNION_RULES` mapping — the only
hardcoded schema mapping in the system:

```python
TAGGED_UNION_RULES = {
    "SlackChannelConfig.authorized": [
        ("workspace_members", "bool", "Allow all workspace members"),
        ("user_group", "str", "User group handle"),
        ("user_id", "str", "Slack user ID"),
    ],
}
```

#### Type 8: Channel Config (Structural)

Rendered as channel sections per repo. Not a generic widget — structural
orchestration that renders channel sub-forms using the recursive schema:

- Configured channels show their sub-form.
- Unconfigured channels show [+ Add Email Channel] / [+ Add Slack Channel].
- Configured channels have a [Remove Channel] button with confirmation.

### Page Layout

Single scrollable page at `/config`. Uses the existing `.page` max-width
constraint (960px) and `.card` pattern. Despite nested YAML, the UI flattens
into vertical flow with labeled sections.

```
/config page
├─ Navbar (existing, breadcrumb: "Configuration")
├─ .page (max-width: 960px)
│  ├─ Header bar: "Server Configuration" + [Save] [Discard] + generation info
│  ├─ #save-result (HTMX target for save feedback)
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
│  ├─ Section: Repository — {repo_id}  (repeated per repo)
│  │  ├─ Card: Git (repo_url)
│  │  ├─ Card: Email Channel (all EmailChannelConfig fields, or [+ Add])
│  │  ├─ Card: Slack Channel (all SlackChannelConfig fields, or [+ Add])
│  │  ├─ Card: Model & Execution (model, effort, network_sandbox_enabled)
│  │  ├─ Card: Resource Limits — per repo (nested ResourceLimits)
│  │  ├─ Card: Credentials
│  │  │  ├─ Secrets (dict_str_str widget)
│  │  │  ├─ Masked Secrets (keyed collection)
│  │  │  ├─ Signing Credentials (keyed collection)
│  │  │  └─ GitHub App Credentials (keyed collection)
│  │  └─ Card: Container Environment (dict_str_str widget)
│  │
│  ├─ [+ Add Repository] button
│  │
│  └─ Footer bar: [Save] [Discard]
│
└─ Scripts: htmx + config-editor.js
```

### Scope Badges

Each card header shows a small badge indicating reload scope, reusing existing
badge styling:

- **server** — blue (`--status-info` colors): requires restart
- **repo** — green (`--status-success` colors): reloadable per-repo
- **task** — amber (`--status-warning` colors): applied per-task immediately

### Field Labels

Follow the existing `.field-label` pattern (11px, uppercase, letter-spacing
0.05em, `--text-tertiary`). The doc string from `FieldMeta` is shown below the
input as a help line (12px, `--text-tertiary`, normal case).

### Responsive Behavior

- Desktop (>700px): field label + source selector on one line, input below.
  Resource limits and similar use 2-column grid.
- Mobile (\<=700px): everything stacks vertically. Source selector wraps below
  the label. Same `@media` breakpoint as existing `.task-row`.

## HTTP Endpoints

### New Routes

| Route             | Method | Handler                      | Description                          |
| ----------------- | ------ | ---------------------------- | ------------------------------------ |
| `/config`         | GET    | `handle_config_page`         | Full editor page (schema-driven)     |
| `/api/config`     | POST   | `handle_config_save`         | Validate + write YAML                |
| `/api/config/add` | POST   | `handle_config_add_fragment` | Render new list/dict/collection item |

### `GET /config`

Server-side rendered from the `EditorFieldSchema` tree + current
`ConfigSnapshot.raw`. Returns a full HTML page extending `base.html`.

### `POST /api/config`

Accepts `application/x-www-form-urlencoded` form data. Hidden `_generation`
field carries the optimistic concurrency token.

**Save flow:**

1. Parse form data via `form_to_raw_dict()`.
2. Check `_generation` against current `_config_generation`.
3. Validate via `ServerConfig.from_source(InMemoryConfigSource(raw_dict))`.
4. On success: write via `YamlConfigSource.save()` (atomic temp+rename).
5. Return response HTML fragment to `#save-result`.

**Response fragments:**

- `200`: `<div class="cfg-banner success">Saved. ...</div>`
- `422`: `<div class="cfg-banner error">Validation failed: ...</div>`
- `409`:
  `<div class="cfg-banner warning">Config changed externally. <a href="/config">Reload</a></div>`

### `POST /api/config/add`

Accepts JSON body:
`{"type": "list_item"|"dict_entry"|"collection_entry", "path": "repos.my-project.email.authorized_senders"}`.

Returns an HTML fragment for a new empty item row with an incremented index.
Used by the [+ Add] buttons via htmx `hx-post` with `hx-swap="beforeend"`.

## HTMX Interaction Patterns

### Page Load

```html
<form id="config-form"
      hx-post="/api/config"
      hx-target="#save-result"
      hx-swap="innerHTML">
  <input type="hidden" name="_generation" value="{{ config_generation }}">
  <!-- All form fields with path-based names -->
</form>
```

### Add Item

```html
<button hx-post="/api/config/add"
        hx-vals='{"type":"list_item","path":"repos.my-project.email.authorized_senders"}'
        hx-target="#authorized-senders-list"
        hx-swap="beforeend">
  + Add
</button>
```

### Remove Item (Client-Side)

```html
<button class="cfg-remove-btn"
        onclick="this.closest('.cfg-list-item').remove()">
  &times;
</button>
```

No server round-trip for removal — the DOM element is simply removed. The save
operation serializes only what remains in the form.

### Source Selector Toggle (Client-Side)

`config-editor.js` handles:

- Click on source segment → update hidden `_source` field, toggle input state
  (disabled for "Not set", text for others), update CSS class.
- Show/hide resolved-value hint for `!env`/`!var`.
- Unsaved changes guard (`beforeunload`).
- Dashboard-disable confirmation dialog.

### Expand/Collapse (Client-Side)

```html
<div class="cfg-expandable" onclick="this.classList.toggle('open')">
```

Same pattern as the existing `.event-header` toggle in the actions viewer.

## Optimistic Concurrency Control

Uses `GatewayService._config_generation` as the concurrency token:

1. **On page load:** hidden `_generation` field set to current generation.
2. **On save:** POST includes `_generation`. Server compares to current.
3. **Stale (409):** generation mismatch → user sees reload prompt.
4. **Current (200):** validate, write YAML, return success.

External edits (direct YAML file changes, SIGHUP-triggered reload) increment the
generation via the existing inotify/reload path. The next editor save with the
old generation receives 409.

## Validation and Error Feedback

### Pre-Save Validation

1. Reconstruct raw dict from form data via `form_to_raw_dict()`, respecting
   `!env`/`!var`/`unset` sources.
2. Pass through `ServerConfig.from_source(InMemoryConfigSource(dict))`.
3. **Validation fails:** return 422 with error banner. YAML file is not touched.
4. **Validation passes:** write YAML atomically, return 200 with success banner
   including scope summary (which scopes were affected).

### Post-Save Feedback

After save, brief poll of `/api/status`:

- `config_generation` incremented, no error → "Applied successfully" (green
  banner).
- `_last_reload_error` set → "Saved but server error: ..." (amber banner).
- `server_reload_pending` → "Saved, restart required for some changes" (blue
  banner).

### Safety Guardrails

- **Dashboard self-disable warning:** setting `dashboard.enabled: false`
  triggers a confirmation dialog warning that the dashboard (including the
  editor) will become inaccessible.
- **Zero repos rejected:** validation catches the zero-repos case.
- **Required field empty:** shown with red border + inline error.
- **Invalid config never written:** the validation step prevents any write that
  would break `ServerConfig.from_source()`.

## Atomic Save

Currently `YamlConfigSource.save()` writes directly via `open(path, "w")`.
Enhance it to write atomically using temp+rename:

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

This prevents the inotify watcher from seeing partial writes. The temp file uses
`.yaml.tmp` suffix so the watcher (which filters for the config filename)
ignores it.

## Security

### CSRF Protection

The `POST /api/config` and `POST /api/config/add` endpoints require an
`X-Requested-With` header, matching the existing pattern on
`POST /api/conversation/{id}/stop`. htmx sends this header automatically. CORS
preflight blocks cross-origin POST with custom headers.

### Secret Handling

Fields marked `secret=True` in `FieldMeta` are rendered as password inputs
(masked). The actual secret value is available in the form for editing but not
visible by default. Resolved value hints for `!env` on secret fields show
`••••••••` instead of the real value.

### Access Control

The editor runs within the existing dashboard security model:

- No authentication (reverse proxy handles it).
- Localhost binding by default.
- Same security response headers (CSP, X-Frame-Options, etc.).

The `/config` route is grouped with `/` (admin-level access) for reverse proxy
rules.

## Dashboard Integration

"Configure" button in the `version_info.html` component on the main dashboard
(not in the navbar):

```html
{% if config_editor_enabled %}
<a href="/config" class="action-btn primary"
   style="font-size:12px; padding:3px 10px;">
  Configure
</a>
{% endif %}
```

Uses the existing `.action-btn.primary` styling (teal button, white text). The
button is conditionally rendered — the editor can be disabled without removing
the dashboard.

### Breadcrumbs

| Page          | Breadcrumbs   |
| ------------- | ------------- |
| Config editor | Configuration |

Follows the existing breadcrumb pattern (single crumb, no parent link since it's
a top-level page like the dashboard).

## New Files

| File                                                          | Purpose                                                                                  |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `airut/config/editor.py`                                      | `EditorFieldSchema`, `schema_for_editor()`, `form_to_raw_dict()`, `InMemoryConfigSource` |
| `airut/dashboard/handlers_config.py`                          | `ConfigEditorHandlers`: page, save, add-fragment                                         |
| `airut/dashboard/templates/pages/config.html`                 | Config editor page template                                                              |
| `airut/dashboard/templates/components/config/field.html`      | Recursive field dispatch macro                                                           |
| `airut/dashboard/templates/components/config/scalar.html`     | Scalar input + source selector                                                           |
| `airut/dashboard/templates/components/config/bool.html`       | Bool toggle widget                                                                       |
| `airut/dashboard/templates/components/config/list.html`       | Generic list widget                                                                      |
| `airut/dashboard/templates/components/config/dict.html`       | Generic dict widget                                                                      |
| `airut/dashboard/templates/components/config/nested.html`     | Nested dataclass fieldset                                                                |
| `airut/dashboard/templates/components/config/collection.html` | Keyed collection (expandable cards)                                                      |
| `airut/dashboard/templates/components/config/union_list.html` | Tagged union list widget                                                                 |
| `airut/dashboard/static/js/config-editor.js`                  | Source toggle, unsaved guard, expand/collapse                                            |
| `airut/dashboard/static/styles/config.css`                    | Config editor styles                                                                     |

## Styling

New file: `airut/dashboard/static/styles/config.css`.

Extends the existing design system. No new colors, fonts, or spacing values. Key
patterns:

- **`.cfg-field`** — field row with `set`/`unset` background states
  (`--bg-surface` vs `--bg-inset`).
- **`.cfg-source`** — segmented control for source selection. Active segment
  uses `--accent` background. Compact sizing (11px font, 2px 8px padding).
- **`.cfg-input`** — text input matching dashboard typography (`--font-mono`,
  13px). Focus ring uses `--accent`.
- **`.cfg-nested`** — bordered fieldset for nested dataclasses with responsive
  grid (`grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))`).
- **`.cfg-expandable`** — collapsible card for keyed collections with
  header/body toggle.
- **`.cfg-list-item`** / **`.cfg-dict-entry`** — flex/grid rows for list and
  dict items.
- **`.cfg-add-btn`** — dashed-border button for adding items.
- **`.cfg-save-bar`** — header bar with save/discard buttons and generation
  info.
- **`.cfg-banner`** — feedback banners (success/error/warning/info) matching
  existing status color tokens.

Light/dark mode is handled automatically via the existing `prefers-color-scheme`
CSS custom properties in `base.css`.

Responsive breakpoint at 700px matches existing pages.

## Relationship to Existing Specs

- **`spec/declarative-config.md`** — this spec extends the FieldMeta system to
  credential types and adds `schema_for_editor()` alongside `schema_for_ui()`.
  The "Dashboard Editor Interaction" section in that spec describes the
  round-trip flow this editor implements.
- **`spec/config-reload.md`** — the editor writes the YAML file and relies on
  the existing inotify + reload pipeline. The Non-Goals section of that spec
  notes: "Dashboard config editor integration. The editor saves via
  `YamlConfigSource.save()`, which writes the file and triggers inotify
  naturally."
- **`spec/dashboard.md`** — the editor is a new page within the dashboard,
  following the same rendering architecture, security model, and URL structure.
- **`spec/repo-config.md`** — the editor renders the schema defined there. Scope
  assignments and field semantics are authoritative in that spec.

## E2E Integration Test Plan

Tests in `tests/integration/dashboard/test_config_editor.py`.

### 1. Page Load — Schema-Driven Rendering

| Test                              | Verifies                                                            |
| --------------------------------- | ------------------------------------------------------------------- |
| `test_config_page_loads`          | GET /config → 200, contains `<form>`                                |
| `test_all_global_fields_rendered` | Every `GlobalConfig` FieldMeta field's doc appears in HTML          |
| `test_all_repo_fields_rendered`   | Every `RepoServerConfig` FieldMeta field's doc appears              |
| `test_all_email_fields_rendered`  | Every `EmailChannelConfig` field appears                            |
| `test_all_slack_fields_rendered`  | SlackChannelConfig fields when Slack configured                     |
| `test_unset_fields_show_defaults` | Fields not in provided_keys → class="unset", default as placeholder |
| `test_set_fields_show_values`     | Fields in provided_keys → class="set", actual value                 |
| `test_env_fields_show_env_source` | `!env` tags → source selector shows "!env" active                   |
| `test_var_fields_show_var_source` | `!var` tags → source selector shows "!var" active                   |

### 2. Save — Round-Trip Fidelity

| Test                               | Verifies                                                 |
| ---------------------------------- | -------------------------------------------------------- |
| `test_save_unchanged_config`       | POST no changes → reload produces identical ServerConfig |
| `test_save_preserves_env_tags`     | `!env` references survive round-trip                     |
| `test_save_preserves_var_tags`     | `!var` references survive round-trip                     |
| `test_save_preserves_vars_section` | `vars:` section preserved in output                      |
| `test_save_only_set_fields`        | Unsetting field removes from YAML; defaults not baked in |
| `test_save_sets_config_version`    | Output has `config_version: 2`                           |

### 3. Validation

| Test                               | Verifies                           |
| ---------------------------------- | ---------------------------------- |
| `test_save_rejects_empty_repo_url` | Missing required → 422             |
| `test_save_rejects_invalid_port`   | Port range → 422                   |
| `test_save_rejects_invalid_memory` | Bad memory string → 422            |
| `test_save_rejects_no_repos`       | Zero repos → 422                   |
| `test_save_rejects_duplicate_imap` | Same IMAP inbox → 422              |
| `test_save_rejects_oauth2_partial` | Partial OAuth2 → 422               |
| `test_validation_preserves_form`   | Error returns banner, not redirect |

### 4. Optimistic Concurrency

| Test                                  | Verifies                               |
| ------------------------------------- | -------------------------------------- |
| `test_save_current_generation`        | Matching generation → 200              |
| `test_save_stale_generation`          | Old generation → 409                   |
| `test_generation_increments`          | After save, generation higher          |
| `test_external_edit_bumps_generation` | Direct YAML edit → generation up → 409 |

### 5. Composite Types

| Test                                 | Verifies                                      |
| ------------------------------------ | --------------------------------------------- |
| `test_list_add_item`                 | POST /api/config/add for list → new item HTML |
| `test_list_save_multiple`            | 3 authorized_senders → all in YAML            |
| `test_list_save_empty`               | Remove all → field absent from YAML           |
| `test_dict_save_secrets`             | Key-value pairs with !env preserved           |
| `test_masked_secret_round_trip`      | MaskedSecret with scopes → correct reload     |
| `test_signing_credential_round_trip` | SigningCredential → correct reload            |
| `test_github_app_round_trip`         | GitHubAppCredential → correct reload          |
| `test_slack_authorized_round_trip`   | Tagged union rules → correct reload           |

### 6. Repo & Channel Management

| Test                     | Verifies                   |
| ------------------------ | -------------------------- |
| `test_add_repo`          | New repo in saved YAML     |
| `test_remove_repo`       | Repo absent, others intact |
| `test_add_email_channel` | Channel section in YAML    |
| `test_add_slack_channel` | Channel section in YAML    |
| `test_remove_channel`    | Channel absent from YAML   |

### 7. Safety

| Test                              | Verifies                                  |
| --------------------------------- | ----------------------------------------- |
| `test_dashboard_disable_warning`  | `enabled: false` → warning in response    |
| `test_port_change_warning`        | Port change → warning                     |
| `test_atomic_write`               | Save uses temp+rename (no partial writes) |
| `test_invalid_config_not_written` | Validation fail → YAML unchanged          |

### 8. Config Reload Integration

| Test                        | Verifies                                  |
| --------------------------- | ----------------------------------------- |
| `test_save_triggers_reload` | Generation increments within 2s           |
| `test_reload_error_shown`   | Channel error → visible via /api/status   |
| `test_scope_summary`        | Server-scope → "restart required" message |

### 9. Dashboard Button

| Test                             | Verifies                       |
| -------------------------------- | ------------------------------ |
| `test_dashboard_has_config_link` | GET / contains link to /config |
| `test_config_link_not_in_navbar` | Navbar has no /config link     |
