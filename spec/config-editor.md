# Config Editor

A web-based config editor integrated into the dashboard. Uses the declarative
config schema to recursively render form fields, with no editor code changes
needed when config fields are added or removed.

## Goals

1. **Schema-driven rendering** — form fields are materialized from `FieldMeta`
   annotations and type hints. Adding a field to a config dataclass
   automatically makes it editable.
2. **Full value source support** — each scalar field can be set as a literal,
   `!env`, or `!var` reference, with a picker to switch between modes.
3. **Safe round-trip** — validate through the full `ServerConfig.from_source()`
   pipeline before writing to disk. Invalid configs never reach the file.
4. **Composable** — recursive rendering handles nested dataclasses, lists,
   dicts, and credential pools without per-type template code.
5. **Mobile-friendly** — flat vertical layout regardless of schema nesting
   depth.

## Non-Goals

- Preserving YAML comments or formatting. The editor produces clean YAML via
  `YamlConfigSource.save()`.
- Secret masking in the editor UI. All values are displayed as plain text.
- Client-side undo. Reloading the page re-reads from disk.
- Multi-user collaboration or locking beyond generation-based conflict
  detection.

## Relationship to Existing Specs

- **`spec/declarative-config.md`** — provides `FieldMeta`, `schema_for_ui()`,
  `ConfigSnapshot.raw`, and the round-trip flow that the editor builds on.
- **`spec/config-reload.md`** — the editor writes the config file; inotify
  detects the change and the reload mechanism applies it. The editor does not
  interact with the reload system directly.
- **`spec/dashboard.md`** — the editor extends the dashboard with new routes and
  pages, following the same architecture (Jinja2, htmx, CSS custom properties,
  security headers).
- **`spec/repo-config.md`** — defines the config schema (field types, defaults,
  validation rules) that the editor renders.

## Design

### Architecture

```
Browser (htmx + minimal JS)             Server (Python)
──────────────────────────               ──────────────────

GET /config                              → config index (global + repo list)
GET /config/global                       → global settings form
GET /config/repo/<id>                    → repo settings form

POST /api/config/global                  → validate + write global section
POST /api/config/repo/<id>              → validate + write repo section
POST /api/config/repo                   → create new repo
DELETE /api/config/repo/<id>            → remove repo
```

### Data Flow

**Page load:**

```
snapshot.raw
  → extract field values (detect EnvVar/VarRef per field)
  → render_form(schema, raw_values, resolved_defaults)
  → HTML form with value source selectors
```

**Save:**

```
form POST (field values + value source tags + __generation)
  → check __generation matches current (reject if stale)
  → parse_config_form(schema, form_data)
  → build raw dict with EnvVar/VarRef objects
  → merge into existing snapshot.raw (preserve vars:, config_version, etc.)
  → validate via ServerConfig.from_source(DictConfigSource(merged))
  → on success: YamlConfigSource.save(merged) → inotify → server reload
  → on failure: return validation errors to UI
```

### DictConfigSource

An in-memory `ConfigSource` for pre-save validation:

```python
class DictConfigSource:
    """ConfigSource backed by an in-memory dict."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def load(self) -> dict[str, Any]:
        return deepcopy(self._data)

    def save(self, data: dict[str, Any]) -> None:
        raise NotImplementedError
```

The editor constructs a `DictConfigSource` from the merged raw dict and runs
`ServerConfig.from_source()` to validate. If this succeeds, the actual YAML file
is written. If it raises `ConfigError`, the error is returned to the UI.

### File Permission Preservation

`YamlConfigSource.save()` currently creates files with the default umask. The
editor must preserve the existing file's permissions:

1. `stat()` the config file before writing to capture mode bits.
2. Write the new content (atomic write via temp file + `os.replace()`).
3. `chmod()` the new file to the original mode.

This ensures that a config file with restrictive permissions (e.g., `0600`)
retains those permissions after editing.

## Navigation

The navbar (top bar) gains a "Config" breadcrumb link. Config pages use
sub-navigation via breadcrumbs:

| Page          | Breadcrumbs            |
| ------------- | ---------------------- |
| Config index  | `Config`               |
| Global config | `Config` > `Global`    |
| Repo config   | `Config` > `<repo_id>` |

### Config Index Page (`/config`)

- Global settings card (link to `/config/global`)
- List of repositories with status badges (link to `/config/repo/<id>`)
- "Add repository" button
- Config status banner: shows `last_reload_error` from `/api/status` if set, and
  `server_reload_pending` state

## Schema-Driven Form Rendering

### Type Classification

`FieldSchema.type_name` is a string representation of the Python type
annotation. The editor classifies it into rendering categories:

| `type_name` pattern              | Category        | Widget                         |
| -------------------------------- | --------------- | ------------------------------ |
| `str`                            | scalar string   | `<input type="text">`          |
| `int`                            | scalar int      | `<input type="number" step=1>` |
| `float`                          | scalar float    | `<input type="number">`        |
| `bool`                           | scalar bool     | `<select>` (true/false/unset)  |
| `str \| None`                    | optional string | `<input type="text">`          |
| `int \| None`                    | optional int    | `<input type="number">`        |
| `float \| None`                  | optional float  | `<input type="number">`        |
| `list[str]`                      | string list     | repeatable text inputs         |
| `dict[str, str]`                 | string dict     | key-value pair rows            |
| `dict[str, MaskedSecret]`        | credential pool | key + nested credential form   |
| `dict[str, SigningCredential]`   | credential pool | key + nested credential form   |
| `dict[str, GitHubAppCredential]` | credential pool | key + nested credential form   |
| `ResourceLimits`                 | nested          | recurse into sub-schema        |
| `ResourceLimits \| None`         | nested optional | recurse into sub-schema        |
| `tuple[dict[...], ...]`          | rule list       | repeatable dict groups         |

A `classify_field_type(type_name: str)` function returns an enum value used by
the Jinja2 rendering macros to select the appropriate widget.

### Enhancing `schema_for_ui()`

`FieldSchema` gains a `type_info` field for structured type classification:

```python
@dataclass(frozen=True)
class TypeInfo:
    """Structured type classification for form rendering."""

    category: str  # "scalar", "optional", "list", "dict", "nested"
    base_type: str  # "str", "int", "float", "bool"
    value_type: str | None = None  # inner type for list/dict
    nested_class: type | None = None  # for nested dataclasses


@dataclass(frozen=True)
class FieldSchema:
    name: str
    type_name: str
    type_info: TypeInfo  # NEW
    default: Any
    required: bool
    doc: str
    scope: str  # "server", "repo", or "task"
    secret: bool
```

`schema_for_ui()` populates `type_info` by inspecting the type annotation. This
avoids parsing type strings in templates.

### Rendering Macros

A Jinja2 macro `render_field` dispatches to the appropriate widget based on
`type_info.category`. Illustrative pseudo-code:

```jinja2
{% macro render_field(name, field, raw_value, default) %}
  <div class="config-field {{ 'config-field--default' if not is_set }}">
    <div class="config-field-header">
      <label>{{ name }}</label>
      <span class="config-field-doc">{{ field.doc }}</span>
    </div>

    {# Value source selector for scalar fields #}
    {% if field.type_info.category in ('scalar', 'optional') %}
      {{ value_source_selector(name, raw_value) }}
    {% endif %}

    {# Widget dispatched by type_info.category #}
    {{ widget_for_type(name, field, raw_value, default) }}
  </div>
{% endmacro %}
```

Exact template structure (macros vs. includes, filter names) is an
implementation detail.

### Value Source Selector

For each scalar field, a radio group selects the value source:

```
( Literal )  ( !env )  ( !var )
[___value input_______________]
```

The selector reads `raw_value` to determine the initial state:

- `isinstance(raw_value, EnvVar)` → `!env` selected, show `var_name`
- `isinstance(raw_value, VarRef)` → `!var` selected, show `var_name`
- Otherwise → `Literal` selected, show the value

Switching between modes swaps the input between a value field and a
reference-name field. This is done with ~10 lines of vanilla JS (event
delegation on radio change) rather than htmx, to avoid a server round-trip on
every click.

### Unset Fields (Default Indication)

Fields not in `snapshot.provided_keys` (not explicitly set by the user):

- Container has class `config-field--default`
- Gray background (`var(--bg-inset)`)
- Input placeholder shows the effective default value
- A "set" button transitions to explicitly-set state

Fields explicitly set by the user:

- Normal background
- A "clear" button removes the value (reverts to default)

State is tracked via a hidden input
`<input type="hidden" name="<field>__set" value="true|false">`.

### Recursive Composite Types

**Nested dataclasses** (`ResourceLimits`):

`schema_for_ui(ResourceLimits)` returns its fields. The macro detects
`category="nested"` and calls `render_fieldset`, which iterates over the
sub-schema calling `render_field` for each child. Rendered as a bordered group
with the dataclass name as a section header.

**`list[str]`** (e.g., `authorized_senders`):

Vertical list of text inputs. Each entry has a remove button. "Add" button
appends a new input. Uses a `<template>` element cloned by JS (~10 lines).

**`dict[str, str]`** (e.g., `secrets`, `container_env`):

Key-value pair rows: `[key input] [value input] [remove]`. "Add" button appends
a new row. Each value field also gets a value source selector.

**Credential pools** (`dict[str, MaskedSecret]`, etc.):

Each entry renders as a collapsible section: key input + nested form for the
credential type's fields. These types are not annotated with `FieldMeta`, so
their field structure is hardcoded in the editor template (they have dynamic
keys and variable structure that cannot be represented via `schema_for_ui()`).

**Slack authorization rules** (`tuple[dict[str, str|bool], ...]`):

Repeatable groups of key-value inputs. "Add rule" button appends a new group.

## Form Submission

### POST Data Format

Form fields use structured naming:

```
max_concurrent_executions__set=true
max_concurrent_executions__source=literal
max_concurrent_executions__value=5

email.password__set=true
email.password__source=env
email.password__ref=EMAIL_PASSWORD

secrets__keys[]=ANTHROPIC_API_KEY
secrets__values[]=sk-ant-...
secrets__sources[]=literal
```

Each field submits:

- `__set` — whether the field is explicitly set (vs. using default)
- `__source` — `literal`, `env`, or `var`
- `__value` / `__ref` — the actual value or reference name

### Server-Side Parsing

`parse_config_form(form_data, schema)` converts form submissions to a raw config
dict:

- Fields with `__set=false` are omitted (default applies).
- Fields with `__source=env` produce `EnvVar(ref)`.
- Fields with `__source=var` produce `VarRef(ref)`.
- Fields with `__source=literal` produce coerced values (int, bool, str, etc.).
- List and dict fields are assembled from indexed/arrayed inputs.

### Concurrent Edit Detection

A hidden field `<input type="hidden" name="__generation" value="N">` carries the
`config_generation` counter from page load time.

On POST, the server compares `__generation` against the current
`_config_generation`. If they differ (config was modified externally since the
page loaded), the save is rejected with a "config changed externally — please
reload" error. The user reloads to see the current state.

## Vars Section Editor

The `vars:` top-level section has its own editor panel on the global config
page. It renders as a key-value list:

| Variable Name | Value            | Source  |
| ------------- | ---------------- | ------- |
| mail_server   | mail.example.com | literal |
| anthropic_key | sk-ant-api03-... | literal |
| azure_secret  | AZURE_SECRET     | !env    |

Each var value gets a source selector (literal / !env) — but not `!var`, since
var-to-var references are forbidden.

The editor reads and writes `snapshot.raw["vars"]` directly.

## Reload Status Feedback

After saving, the editor provides feedback using the existing `/api/status`
endpoint:

1. Editor shows "Saved successfully" banner immediately after successful write.
2. htmx polls `/api/status` (`hx-get` with `hx-trigger="load delay:500ms"`).
3. If `config_generation` incremented and `last_reload_error` is null: config
   applied successfully.
4. If `last_reload_error` is non-null: red error banner with the traceback.
5. If `server_reload_pending` is true: info banner "Server restart pending
   (waiting for active tasks to complete)".

This covers both pre-save validation errors (returned from the POST) and
post-save runtime errors (from the server reload).

## Styling

The editor uses the same CSS custom properties as the rest of the dashboard,
extended with editor-specific variables:

```css
--bg-field-default: var(--bg-inset);
--border-field-focus: var(--accent);
--bg-field-error: var(--status-error-bg);
```

### Field Layout

Fields render as a flat vertical list. Nested groups use left-border indentation
rather than horizontal nesting, keeping horizontal space usage minimal for
mobile:

```css
.config-field {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border-light);
}

.config-field--default {
    background: var(--bg-field-default);
}

.config-field--default input::placeholder {
    color: var(--text-tertiary);
    opacity: 1;
}

.config-fieldset {
    border-left: 3px solid var(--border);
    padding-left: 16px;
}

.config-fieldset-legend {
    font-family: var(--font-mono);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
}
```

### Inputs

```css
.config-field input,
.config-field select {
    width: 100%;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-surface);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 13px;
}

.config-field input:focus {
    border-color: var(--border-field-focus);
    outline: none;
    box-shadow: 0 0 0 2px var(--accent-subtle);
}
```

### Save Bar

Sticky bottom bar with save button and status:

```css
.config-actions {
    position: sticky;
    bottom: 0;
    background: var(--bg-surface);
    border-top: 1px solid var(--border);
    padding: 12px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
```

## Safety

### Pre-Save Validation

Every save runs through the full `ServerConfig.from_source()` pipeline via
`DictConfigSource`. This catches all the same errors as a server reload: missing
required fields, port range violations, duplicate IMAP inboxes, broken
`!env`/`!var` references, etc.

### Dashboard Self-Protection

If the user disables the dashboard or changes its port, the editor disappears
after the config is applied — this is expected and acceptable. The validation
pipeline itself does not prevent this.

### Config File Integrity

The editor always writes a complete, valid config file. Partial writes are
prevented by atomic write (temp file + rename). The existing config is never
corrupted, even if the editor process is killed mid-save.

## Client-Side JavaScript

The editor requires a small amount of vanilla JS (estimated ~50-100 lines) for:

1. **List add/remove** — clone `<template>` elements, remove list items
2. **Value source switching** — toggle between literal and reference inputs on
   radio change
3. **Set/clear field** — toggle `__set` hidden input and CSS class

All other interactivity uses htmx (`hx-post` for save, `hx-get` for status
polling). No JS framework.

## File Organization

### New Files

```
airut/config/form.py                   — TypeInfo, parse_config_form(),
                                         DictConfigSource
airut/dashboard/config_editor.py       — route handlers, form rendering context
airut/dashboard/templates/pages/
  config_index.html                    — config overview page
  config_global.html                   — global settings form
  config_repo.html                     — per-repo settings form
airut/dashboard/templates/components/
  config_field.html                    — render_field macro
  config_list.html                     — list/dict field macros
  config_status.html                   — reload status banner
airut/dashboard/static/styles/
  config.css                           — config editor styles
airut/dashboard/static/js/
  config.js                            — list add/remove, source switching
```

### Modified Files

```
airut/config/schema.py                 — TypeInfo, FieldSchema.type_info
airut/config/source.py                 — preserve file permissions in save()
airut/dashboard/server.py              — register config editor routes
airut/dashboard/templates/
  components/navbar.html               — add Config link
airut/dashboard/static/styles/
  base.css                             — config editor CSS variables
```

## Security

Config editor endpoints follow the same security model as the rest of the
dashboard:

- **No authentication** — reverse proxy handles access control.
- **CSRF protection** — POST/DELETE endpoints require `X-Requested-With` header
  (same pattern as the existing stop endpoint).
- **CSP** — no inline scripts or styles; `config.js` is served from
  `/static/js/`.
- **Security headers** — all config editor responses include the same
  `X-Content-Type-Options`, `X-Frame-Options`, and `Content-Security-Policy`
  headers as other dashboard pages.

## Integration Test Plan

Integration tests validate the full round-trip: form rendering → submission →
validation → file write → inotify → server reload → observable behavior change.
They use the existing integration test infrastructure
(`tests/integration/gateway/`).

### E2E Tests

**E1: Global config edit cycle.** Start gateway with known config. GET
`/config/global` → verify form loads with current values. POST
`/api/config/global` changing `max_concurrent_executions` to 5. Wait for config
reload (poll `/api/status` until generation increments). GET `/api/health` →
verify new value is in effect. GET `/config/global` → verify form shows updated
value.

**E2: Repo config edit with channel changes.** POST `/api/config/repo/test`
changing `poll_interval_seconds` to 120. Wait for reload. Verify repo status
transitions through `RELOAD_PENDING` → `LIVE` in tracker.

**E3: Invalid config rejected, service unaffected.** POST `/api/config/global`
with `max_concurrent_executions=0`. Assert error response. Verify config file
unchanged (checksum). Verify service still running with old config.

**E4: Add and remove repo.** POST `/api/config/repo` with new repo data. Wait
for reload → verify new repo in health. DELETE `/api/config/repo/new-repo`. Wait
for reload → verify repo removed.

**E5: Concurrent external edit detection.** Load config page (capture
generation). Modify config file externally. Wait for reload (generation
increments). POST with stale generation. Assert rejected.

**E6: EnvVar round-trip.** Set `TEST_PASSWORD=secret123` in environment. POST
config with password source=env, ref=TEST_PASSWORD. Wait for reload. Read YAML
file → verify `!env TEST_PASSWORD` tag. Verify resolved config has `secret123`.

**E7: Config status shows reload errors.** Write broken config directly to file
(bypass editor). Wait for reload attempt. GET `/api/status` → verify
`last_reload_error` set. GET `/config` → verify error banner. Fix config via
editor. Wait for reload → verify error cleared.

**E8: File permissions preserved.** Set config file to mode `0o600`. POST valid
config change. Verify file mode is still `0o600`.

**E9: VarRef round-trip.** Create config with `vars:` section and a field using
`!var`. Edit via form, save. Read YAML → verify `!var` tag preserved.

### Unit Tests

Unit tests for form parsing and rendering live alongside dashboard tests.

**Form parsing** (`tests/test_config_form.py`):

- Parse literal scalar (str, int, float, bool coercion)
- Parse `!env` source → `EnvVar` object
- Parse `!var` source → `VarRef` object
- Unset fields omitted from output
- List fields assembled from indexed inputs
- Dict fields assembled from key/value arrays
- `DictConfigSource` validates valid configs without error
- `DictConfigSource` raises `ConfigError` for invalid configs
- `TypeInfo` classification for all type annotation patterns

**Rendering** (`tests/dashboard/test_config_editor.py`):

- Config index page lists all repos
- Global form renders all `GlobalConfig` fields
- Repo form renders all `RepoServerConfig` + channel fields
- Unset fields have `config-field--default` class and show placeholder
- `EnvVar` fields show `!env` radio selected
- `VarRef` fields show `!var` radio selected
- Save valid config writes to disk
- Save invalid config returns errors without writing
- Concurrent edit detection rejects stale generation
- List field add/remove round-trip
- Dict field round-trip
- File permissions preserved on save

## Implementation Phases

### Phase 1: Core Infrastructure

- `TypeInfo` addition to `FieldSchema`
- `DictConfigSource` for validation
- `parse_config_form()` with all type handlers
- File permission preservation in `save()`
- Unit tests for form parsing

### Phase 2: Read-Only Rendering

- Config index page with navigation
- Global config form (display only, no save)
- Repo config form (display only, no save)
- `render_field` macro with all widget types
- Default/set field visual distinction
- EnvVar/VarRef detection and display

### Phase 3: Save Flow

- POST handlers for global and repo config
- Validation pipeline integration
- Concurrent edit detection
- Success/error feedback UI
- Reload status polling

### Phase 4: List and Dict Editing

- `config.js` for add/remove
- List fields (authorized_senders, etc.)
- Dict fields (secrets, container_env)
- Credential pool editors (masked_secrets, signing_credentials, github_app)
- Slack authorization rules

### Phase 5: Repo Management and Vars

- Add/remove repos
- Vars section editor
- Integration tests
