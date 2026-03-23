# Web Config Editor

Status: **implemented**

## Overview

A web UI integrated into the existing dashboard for editing the server
configuration file (`airut.yaml`). Leverages the declarative config metadata
(`FieldMeta`, `schema_for_ui()`) so that new fields appear automatically without
UI code changes. Uses HTMX for interactivity and the existing inotify-based
reload mechanism for applying changes.

### Goals

1. **Schema-driven rendering** — form fields generated from `schema_for_ui()`
   and `FieldSchema` metadata. Adding a field to a config dataclass with
   `FieldMeta` is sufficient for it to appear in the editor.
2. **Repo-per-page** — global settings on one page, each repo on its own page,
   to keep pages manageable.
3. **Variable support** — users can edit the `vars:` section and use `!var` /
   `!env` as config values.
4. **Add/remove repos** — create new repos from a template, delete existing
   ones.
5. **File-is-truth** — the editor reads from and writes to the YAML file.
   Changes trigger the existing inotify-based reload. No new reload path.
6. **No secret special-casing** — secrets shown in plain text in the editor.
7. **HTMX-first** — server-rendered HTML fragments, no client-side framework.

### Non-goals

- Editing `.env` files (out of scope per requirements).
- Multi-user collaboration or optimistic locking.
- Undo/history (git tracks the config file already).
- Creating the config file from scratch (bootstrap remains manual).

## Architecture

### Page Structure

```
/config                         → Config index (redirect to /config/global)
/config/global                  → Global settings + variables
/config/repo/<repo_id>          → Single repo settings
/config/repo/<repo_id>/delete   → Confirm repo deletion (POST)
/config/repo/new                → New repo form (POST creates, redirects)
```

All pages share the existing dashboard layout (`base.html`, `navbar.html`). A
config-specific sidebar or nav section lists global + all repo IDs for quick
navigation.

### Data Flow

```
┌─────────┐   GET /config/global   ┌──────────────┐
│ Browser │ ◄────────────────────── │ Dashboard    │
│  HTMX   │                        │ Server       │
│         │   POST /config/global   │              │
│         │ ──────────────────────► │ 1. Parse form│
│         │                        │ 2. Validate  │
│         │   200 HTML fragment     │ 3. Merge raw │
│         │ ◄────────────────────── │ 4. Save YAML │
│         │                        │              │
│         │                        │   inotify    │
│         │                        │      │       │
│         │                        │      ▼       │
│         │                        │ GatewayService│
│         │                        │ _on_config_  │
│         │                        │  changed()   │
│         │                        └──────────────┘
```

1. **GET** — load current `ConfigSnapshot`, render form from `.raw` dict
   (preserving `!var`/`!env` tags) combined with `schema_for_ui()` metadata.
2. **POST** — parse form data, validate, merge into the raw dict, save via
   `YamlConfigSource.save()`. The file write triggers inotify, which triggers
   the existing reload pipeline.
3. **Response** — on success, return the re-rendered form with a success banner
   (and reload scope indicator). On validation error, return the form with
   inline errors. HTMX replaces the form content in-place.

### Reload Integration

The editor writes the file and relies entirely on the existing inotify-based
`ConfigFileWatcher`. This is the simplest and most correct approach:

- **Single source of truth** — the file is authoritative. The reload spec
  explicitly states this.
- **No new code paths** — no programmatic reload trigger needed.
- **Consistent behavior** — editing via the web UI behaves identically to
  editing via a text editor.
- **Error handling** — parse/validation errors during reload are logged and
  surfaced via `/api/status` (`last_reload_error`). The editor can poll this
  endpoint to show reload status.

After a successful save, the editor page shows:

- A success banner with the affected scope (task/repo/server).
- If server-scope fields changed: a note that changes will apply when the server
  is idle (or immediately if already idle).
- If repo-scope fields changed: a note about listener restart (immediate or
  deferred).
- The editor re-reads and re-renders the form from the newly-saved file to
  confirm round-trip fidelity.

The editor can poll `/api/status` to show `config_generation` changes and
`last_reload_error` feedback.

## Schema-Driven Form Rendering

### Field Rendering Pipeline

```python
# Pseudocode for rendering a config section
schema = schema_for_ui(GlobalConfig)  # List[FieldSchema]
raw = snapshot.raw  # dict with !var/!env preserved

for field in schema:
    raw_value = lookup_raw_value(
        raw, field.name
    )  # may be str, EnvVar, VarRef, or missing
    render_field(field, raw_value)
```

Each `FieldSchema` provides:

- `name` — field name (used as form input name)
- `type_name` — Python type annotation string (for choosing input widget)
- `default` — default value (shown as placeholder)
- `required` — whether the field is required
- `doc` — human-readable description (shown as help text)
- `scope` — reload scope (shown as badge: "server", "repo", "task")
- `secret` — not used for special-casing (per requirements)

### Input Type Mapping

The template maps `type_name` to HTML input types:

| `type_name`              | Widget                             | Notes                      |
| ------------------------ | ---------------------------------- | -------------------------- |
| `str`                    | `<input type="text">`              | Standard text input        |
| `str \| None`            | `<input type="text">`              | Empty string = None        |
| `int`                    | `<input type="number">`            | Integer validation         |
| `int \| None`            | `<input type="number">`            | Empty = None               |
| `float \| None`          | `<input type="number" step="0.1">` |                            |
| `bool`                   | `<select>` (true/false/default)    | Three-state for optional   |
| `list[str]`              | `<textarea>`                       | One item per line          |
| `dict[str, str]`         | Key-value table                    | Dynamic rows (add/remove)  |
| `ResourceLimits \| None` | Nested fieldset                    | Sub-fields rendered inline |

### Value Indirection (Variables and Environment)

Each field has a **value mode** selector that determines how the value is
specified:

```
┌─────────────────────────────────────────────────────┐
│ IMAP Server              [scope: repo]              │
│ ┌──────────┐ ┌────────────────────────────────────┐ │
│ │ ▼ literal │ │ mail.example.com                   │ │
│ │   !var    │ └────────────────────────────────────┘ │
│ │   !env    │                                        │
│ └──────────┘ IMAP server hostname                    │
└─────────────────────────────────────────────────────┘
```

Three modes:

1. **literal** — direct value in the input field.
2. **!var** — dropdown/text input selecting a variable name from the `vars:`
   section. Shows resolved value as read-only hint.
3. **!env** — text input for environment variable name. Shows resolved value
   (from `os.environ`) as read-only hint, or "(unset)" if not defined.

The mode selector is a `<select>` next to each field. Switching modes uses
`hx-get` to swap the input widget. The form always submits the raw
representation (literal value, `!var:name`, or `!env:NAME`).

### Form Submission Encoding

Each field submits two values:

- `field.<name>.mode` — one of `literal`, `var`, `env`
- `field.<name>.value` — the literal value, variable name, or env var name

Example form data:

```
field.imap_server.mode=var
field.imap_server.value=mail_server
field.model.mode=literal
field.model.value=sonnet
field.password.mode=env
field.password.value=EMAIL_PASSWORD
```

The server reconstructs the raw dict:

- `literal` → plain Python value (coerced by type)
- `var` → `VarRef("mail_server")`
- `env` → `EnvVar("EMAIL_PASSWORD")`

## Page Designs

### Global Settings Page (`/config/global`)

Two sections:

**1. Variables (`vars:`)**

A key-value editor for the `vars:` section. Each row has:

- Variable name (text input, must be valid identifier)
- Value mode (literal or `!env`) — note: `!var` is not allowed in `vars:`
- Value (text input)
- Delete button

An "Add Variable" button appends a new row (HTMX `hx-post` to `/config/vars/add`
returns a new row fragment).

**2. Global Config Fields**

Schema-driven form rendered from `schema_for_ui(GlobalConfig)`. Fields grouped
by YAML nesting (execution, dashboard, network, resource_limits) using
`<fieldset>` with `<legend>`.

Grouping derived from `YAML_GLOBAL_STRUCTURE`: fields sharing the same first
path element are grouped together. Fields not in the structure mapping are
placed in a "General" group.

### Repo Page (`/config/repo/<repo_id>`)

Sections:

**1. Repo Identity**

- Repo ID (read-only display, cannot be changed after creation)
- Git repo URL

**2. Channel: Email** (collapsible `<details>`) Schema-driven form from
`schema_for_ui(EmailChannelConfig)`. Grouped using a custom grouping table (not
derived from `YAML_EMAIL_STRUCTURE`, since most email fields map to top-level
paths). Groups: "Connection" (`imap_server`, `imap_port`, `smtp_server`,
`smtp_port`), "Authentication" (`username`, `password`, `authorized_senders`,
`trusted_authserv_id`, `smtp_require_auth`, `microsoft_internal_auth_fallback`),
"Polling" (`poll_interval_seconds`, `use_imap_idle`,
`idle_reconnect_interval_seconds`), "Microsoft OAuth2"
(`microsoft_oauth2_tenant_id`, `microsoft_oauth2_client_id`,
`microsoft_oauth2_client_secret`), "Display" (`from_address`). Only shown if an
email channel exists. "Add Email Channel" / "Remove Email Channel" buttons
toggle presence.

**3. Channel: Slack** (collapsible `<details>`) Schema-driven form from
`schema_for_ui(SlackChannelConfig)` for scalar fields (`bot_token`,
`app_token`). The `authorized` field has type
`tuple[dict[str, str | bool], ...]` with polymorphic entries
(`workspace_members`, `user_group`, or `user_id`) and requires a hand-coded
card-based editor similar to credential pools. Each authorization rule is a card
with a type selector and value input. Only shown if a Slack channel exists. "Add
Slack Channel" / "Remove Slack Channel" buttons toggle presence.

**4. Model & Execution** (task-scope fields)

- `model`, `effort`, `resource_limits`, `container_env`

**5. Network**

- `network_sandbox_enabled`

**6. Credentials** (collapsible sections)

Credential pools (`secrets`, `masked_secrets`, `signing_credentials`,
`github_app_credentials`) have dynamic, user-chosen keys and cannot be
represented as fixed-schema forms. These use a different UI pattern:

**Plain Secrets** (`secrets:`): Key-value table (like `container_env`).

**Masked Secrets** (`masked_secrets:`): Each entry is a card with:

- Key name (text input)
- Value (text input + mode selector for `!env`/`!var`/literal)
- Scopes (textarea, one pattern per line)
- Headers (textarea, one pattern per line)
- `allow_foreign_credentials` (checkbox)
- Delete button

"Add Masked Secret" button appends a new card.

**Signing Credentials** (`signing_credentials:`): Each entry is a card with
nested fields for `access_key_id`, `secret_access_key`, `session_token` (each
with name + value sub-fields and mode selector), plus scopes.

**GitHub App Credentials** (`github_app_credentials:`): Each entry is a card
with fields for `app_id`, `private_key`, `installation_id`, `scopes`,
`allow_foreign_credentials`, `base_url`, `permissions` (key-value),
`repositories` (list).

### New Repo Page (`/config/repo/new`)

Minimal form:

- Repo ID (text input, validated as valid identifier and unique)
- Git repo URL (text input, required)
- Channel type (checkbox: email, slack, or both)

On submit, creates a minimal repo entry in the raw config with defaults and
redirects to `/config/repo/<repo_id>` for full configuration.

### Repo Deletion (`POST /config/repo/<repo_id>/delete`)

Confirmation page with repo ID and a warning about active tasks. POST removes
the repo from the raw dict, saves, and redirects to `/config/global`.

## HTMX Interaction Patterns

### Form Submission

```html
<form hx-post="/config/global"
      hx-target="#config-form"
      hx-swap="innerHTML">
  <!-- fields -->
  <button type="submit">Save</button>
</form>
```

On submit, the server validates, saves, and returns the re-rendered form (with
success/error banners). HTMX replaces the form content in-place. No full page
reload.

### Value Mode Switching

```html
<select name="field.imap_server.mode"
        hx-get="/config/field-input?name=imap_server&type=str"
        hx-target="#input-imap_server"
        hx-swap="innerHTML"
        hx-include="this">
  <option value="literal">Literal</option>
  <option value="var">!var</option>
  <option value="env">!env</option>
</select>
<span id="input-imap_server">
  <input type="text" name="field.imap_server.value" value="...">
</span>
```

When the mode changes, HTMX fetches a new input fragment appropriate for the
selected mode:

- **literal** — standard input with current resolved value
- **!var** — dropdown of defined variable names + resolved value hint
- **!env** — text input for env var name + resolved value hint

### Dynamic Credential Entries

"Add" buttons use `hx-post` to append new credential card fragments:

```html
<button hx-post="/config/repo/my-project/masked-secret/add"
        hx-target="#masked-secrets-list"
        hx-swap="beforeend">
  Add Masked Secret
</button>
```

"Delete" buttons remove their parent card client-side. Since credentials are
submitted as indexed form data, omitting a card from the DOM means it is
excluded from the next form POST. No separate DELETE endpoint is needed:

```html
<button type="button"
        onclick="if(confirm('Remove masked secret?')) this.closest('.credential-card').remove()"
        >
  Delete
</button>
```

Note: this uses a minimal inline `onclick` rather than an HTMX endpoint. The CSP
policy does not allow inline scripts, so this handler must be registered via a
small event-delegation snippet in a static JS file (e.g., `config.js`) that
listens for clicks on `[data-remove-card]` buttons and removes the closest
`.credential-card`.

### Config Sidebar Navigation

```html
<nav id="config-nav" hx-get="/config/nav"
     hx-trigger="load" hx-swap="innerHTML">
  <!-- populated with global + repo links -->
</nav>
```

The nav fragment is re-fetched after repo add/delete to reflect changes.

### Reload Status Polling

After save, a status element polls `/api/status`. The server renders an HTML
fragment that includes the `hx-get` trigger only while reload is pending. Once
the reload completes (or fails), the returned fragment omits the trigger,
stopping the poll:

```html
<!-- Initial: server includes hx-get to continue polling -->
<div id="reload-status"
     hx-get="/config/reload-status?gen=4"
     hx-trigger="load delay:500ms"
     hx-swap="outerHTML">
  Reloading...
</div>

<!-- After reload completes: server returns fragment without hx-get -->
<div id="reload-status">
  Config reloaded successfully (generation 5).
</div>
```

## Server-Side Implementation

### New Module: `airut/dashboard/config_editor.py`

Encapsulates all config editor logic. Registered as additional routes in
`DashboardServer`.

```python
class ConfigEditor:
    """Config editor request handlers.

    Reads and writes config via ConfigSource. Forms are rendered from
    schema metadata — no per-field code needed for new fields.
    """

    def __init__(
        self,
        config_source: YamlConfigSource,
        status_callback: Callable[[], dict[str, object]] | None = None,
    ) -> None:
        self.source = config_source
        self._status_callback = status_callback

    def _load_raw(self) -> dict[str, Any]:
        """Load the raw config dict from the YAML source."""
        return self.source.load()

    def _save(self, raw: dict[str, Any]) -> None:
        """Save raw dict to YAML (triggers inotify reload)."""
        self.source.save(raw)
```

Key methods (each takes `request` and relevant URL args, returns `Response`):

- `handle_global(request)` — dispatches GET/POST for global config
- `handle_repo(request, repo_id)` — dispatches GET/POST for repo config
- `handle_repo_new(request)` — dispatches GET/POST for new repo creation
- `handle_repo_delete(request, repo_id)` — dispatches GET/POST for repo deletion
- `handle_config_index(request)` — redirect to `/config/global`
- `handle_field_input(request)` — return input fragment for mode switch
- `handle_nav(request)` — return sidebar nav fragment
- `handle_credential_add(request, repo_id)` — return new credential card
- `handle_vars_add(request)` — return new variable row
- `handle_reload_status(request)` — return reload status fragment (self-polling
  until config generation advances past expected value)

### Form Parsing

A generic `parse_form_fields()` function processes the `field.*` form data:

```python
def parse_form_fields(
    form: dict[str, str],
    schema: list[FieldSchema],
) -> dict[str, Any]:
    """Parse form submission into raw config values.

    For each field in schema, reads field.<name>.mode and
    field.<name>.value from the form data. Returns a dict
    mapping field names to raw values (str, VarRef, EnvVar,
    or typed Python values).
    """
```

This function is schema-driven — it iterates `schema` and processes whatever
fields exist. New fields added to the schema are automatically handled.

### Validation

Two levels of validation:

1. **Form-level** — basic type coercion and required field checks. Done in
   `parse_form_fields()`. Returns inline errors.

2. **Config-level** — full config validation via `ServerConfig.from_source()`.
   The editor saves the raw dict, then immediately re-loads to validate. If
   validation fails, the save is still persisted (the inotify reload will also
   fail and log the error, keeping the old config active). The editor shows the
   validation error and the user can fix it.

   This two-step approach avoids duplicating validation logic. The config
   dataclass `__post_init__` methods are the single source of truth for
   validation.

   **Alternative considered:** validate before saving. Rejected because this
   would require resolving `!env` and `!var` tags, which may fail for legitimate
   reasons (env var not yet set). The reload pipeline already handles this
   gracefully.

### Template Structure

```
templates/
  config/
    layout.html              — Config page layout (sidebar + content area)
    global.html              — Global settings page
    repo.html                — Repo settings page
    repo_new.html            — New repo form
    repo_delete.html         — Deletion confirmation
    components/
      field.html             — Single schema-driven field (macro)
      field_input.html       — Input widget for a field (mode-dependent)
      fieldset.html          — Grouped fields (macro)
      variable_row.html      — Single variable editor row
      credential_card.html   — Dynamic credential entry card
      nav.html               — Sidebar navigation fragment
      save_result.html       — Success/error banner after save
```

The `field.html` macro is the core of schema-driven rendering:

```jinja2
{% macro render_field(field, raw_value, vars) %}
<div class="config-field" id="field-{{ field.name }}">
  <label for="input-{{ field.name }}">
    {{ field.name | replace('_', ' ') | title }}
    <span class="scope-badge scope-{{ field.scope }}">{{ field.scope }}</span>
  </label>

  {% set mode = detect_mode(raw_value) %}
  <div class="field-controls">
    <select name="field.{{ field.name }}.mode"
            hx-get="/config/field-input?name={{ field.name }}&type={{ field.type_name }}"
            hx-target="#input-{{ field.name }}"
            hx-swap="innerHTML"
            hx-include="this">
      <option value="literal" {{ 'selected' if mode == 'literal' }}>Literal</option>
      <option value="var" {{ 'selected' if mode == 'var' }}>!var</option>
      <option value="env" {{ 'selected' if mode == 'env' }}>!env</option>
    </select>
    <span id="input-{{ field.name }}">
      {% include "config/components/field_input.html" %}
    </span>
  </div>

  <small class="field-doc">{{ field.doc }}</small>
  {% if not field.required %}
  <small class="field-default">Default: {{ field.default }}</small>
  {% endif %}
</div>
{% endmacro %}
```

### Scope Display After Save

After saving, the server computes the diff between old and new config using
`diff_by_scope()` and renders a scope summary:

```
Changes saved successfully.
  - task scope: model (opus → sonnet) — effective on next task
  - repo scope: imap_server — listener restart pending
  - server scope: max_concurrent_executions — applied when idle
```

This reuses the existing `diff_by_scope()` function.

### Route Registration

New routes added to `DashboardServer.__init__()`:

```python
# Config editor routes
(Rule("/config", endpoint="config_index"),)
(Rule("/config/global", endpoint="config_global", methods=["GET", "POST"]),)
(Rule("/config/repo/new", endpoint="config_repo_new", methods=["GET", "POST"]),)
(
    Rule(
        "/config/repo/<repo_id>",
        endpoint="config_repo",
        methods=["GET", "POST"],
    ),
)
(
    Rule(
        "/config/repo/<repo_id>/delete",
        endpoint="config_repo_delete",
        methods=["GET", "POST"],
    ),
)
(Rule("/config/field-input", endpoint="config_field_input"),)
(Rule("/config/nav", endpoint="config_nav"),)
(Rule("/config/reload-status", endpoint="config_reload_status"),)
(Rule("/config/vars/add", endpoint="config_vars_add", methods=["POST"]),)
(
    Rule(
        "/config/repo/<repo_id>/credential/add",
        endpoint="config_credential_add",
        methods=["POST"],
    ),
)
```

### CSRF Protection

Mutating endpoints (POST) require the `X-Requested-With` header, matching the
existing pattern used by `POST /api/conversation/{id}/stop`. The dashboard
currently sets this header per-element via `hx-headers` attributes. For the
config editor, set it globally via a `<meta>` tag in the config layout template:

```html
<meta name="htmx-config" content='{"headers":{"X-Requested-With":"XMLHttpRequest"}}'>
```

This ensures all HTMX requests from config editor pages include the header
without per-element repetition.

## Key Design Decisions

### 1. File Write + inotify vs. Programmatic Reload

**Decision:** Write file, rely on inotify.

**Rationale:**

- The reload spec explicitly states the file is the single source of truth.
- No new code paths = no new bugs.
- Consistent with CLI/text-editor workflows.
- The 100ms inotify debounce + read_delay provides fast feedback.
- Error handling is already robust (parse errors keep old config).

### 2. Raw Dict Editing vs. Dataclass Manipulation

**Decision:** Edit the raw dict (with `VarRef`/`EnvVar` preserved), not resolved
dataclass instances.

**Rationale:**

- Preserves `!var` and `!env` tags through round-trip.
- The `ConfigSnapshot.raw` property exists precisely for this use case.
- Avoids resolving env vars that may not be set on the dashboard host.
- Matches the existing round-trip design documented in `config/source.py`.

### 3. Validate After Save vs. Before Save

**Decision:** Save first, then validate by re-loading.

**Rationale:**

- Avoids duplicating validation logic.
- The reload pipeline gracefully handles errors (keeps old config).
- Allows saving configs with unresolved `!env` vars (legitimate during setup).
- The user sees both form-level errors (immediate) and config-level errors
  (after re-load attempt).

**Trade-off:** A bad save means the file temporarily contains invalid YAML. This
is acceptable because:

- The service continues with the old config.
- The editor immediately shows the error.
- The user can fix it in the next save.
- This matches the behavior of editing the file in a text editor.

### 4. Schema-Driven vs. Hand-Coded Forms

**Decision:** Schema-driven rendering from `schema_for_ui()`.

**Rationale:**

- New fields added to config dataclasses appear automatically.
- Field documentation, defaults, and scope badges come from metadata.
- Reduces maintenance burden and prevents UI/config drift.
- The `FieldSchema` type already exists and is designed for this purpose.

**Limitation:** Credential pools (`masked_secrets`, `signing_credentials`,
`github_app_credentials`) have dynamic keys and complex nested structures that
don't fit the `FieldMeta` annotation pattern. These require hand-coded
templates. This is acceptable because:

- Credential types change rarely.
- Their structure is complex enough to warrant custom UI.
- The schema-driven approach handles the ~30 simple fields automatically.

### 5. Flat Field Grouping

**Decision:** Group fields by their YAML nesting structure.

**Rationale:**

- `YAML_GLOBAL_STRUCTURE` already maps fields to nested paths like
  `("execution", "max_concurrent")`.
- Fields sharing the same first path element naturally belong together.
- This produces groups like "Execution", "Dashboard", "Network" without any
  additional metadata.
- Adding a new YAML group just requires a new structure mapping entry.

## Credential Pool Editing

Credential pools require special handling because they have:

- User-chosen key names (not fixed schema)
- Complex nested structures (e.g., `SigningCredential` has sub-fields)
- Dynamic number of entries

### Template Design

Each credential type has a dedicated card template:

**Masked Secret Card:**

```
┌─ GH_TOKEN ─────────────────────────────────────────┐
│ Key:    [GH_TOKEN          ]                        │
│ Value:  [!env ▼] [GH_TOKEN_VALUE    ]               │
│ Scopes: [api.github.com          ]                  │
│         [*.githubusercontent.com ]                  │
│ Headers:[Authorization           ]                  │
│ ☐ Allow foreign credentials                         │
│                                    [Delete]         │
└─────────────────────────────────────────────────────┘
```

### Form Encoding for Credentials

Credentials use indexed form names:

```
masked_secret.0.key=GH_TOKEN
masked_secret.0.value.mode=env
masked_secret.0.value.value=GH_TOKEN
masked_secret.0.scopes=api.github.com\n*.githubusercontent.com
masked_secret.0.headers=Authorization
masked_secret.0.allow_foreign=false
masked_secret.1.key=SLACK_TOKEN
...
```

The server reconstructs the credential dicts from indexed form data.

## Variable Editing

The `vars:` section is edited as a key-value table on the global page:

```
┌─ Variables ─────────────────────────────────────────┐
│ Name              Mode      Value                   │
│ [mail_server    ] [literal] [mail.example.com     ] │
│ [anthropic_key  ] [literal] [sk-ant-api03-...     ] │
│ [gh_token       ] [!env   ] [GH_TOKEN             ] │
│                                                     │
│                              [+ Add Variable]       │
└─────────────────────────────────────────────────────┘
```

Variables support two modes (not three): `literal` and `!env`. The `!var` mode
is not available for variables (no var-to-var references, enforced by
`resolve_vars_section()`).

When a variable is referenced by config fields, deleting it shows a warning
listing the affected fields. The delete still proceeds (the reload will fail
with "undefined variable" error, and the user can fix it).

## Styling

Reuses the existing CSS variable system. New styles in a
`static/styles/config.css` file:

- `.config-field` — field container with label, input, doc text
- `.scope-badge` — colored badge for scope (task=green, repo=blue,
  server=orange), matching the existing `.badge` pattern
- `.config-sidebar` — left sidebar with repo navigation
- `.credential-card` — bordered card for credential entries
- `.field-controls` — flex container for mode selector + input
- `.save-result` — success/error banner
- `.variable-row` — row in the variables table

Dark mode support via existing `@media (prefers-color-scheme: dark)` custom
properties.

## Test Plan

### Unit Tests

**Schema-driven rendering tests** (`tests/dashboard/test_config_editor.py`):

1. `test_render_field_literal` — field with literal value renders correct input
   type and value.
2. `test_render_field_var_ref` — field with `VarRef` renders var mode selected,
   variable name in input.
3. `test_render_field_env_var` — field with `EnvVar` renders env mode selected,
   env var name in input.
4. `test_render_field_types` — each `type_name` maps to correct HTML input
   widget (text, number, select, textarea).
5. `test_render_field_required` — required fields show required indicator, no
   default hint.
6. `test_render_field_defaults` — optional fields show default value as
   placeholder.
7. `test_render_field_scope_badge` — scope badge renders with correct class and
   text.
8. `test_schema_driven_field_discovery` — adding a new field to a test config
   class causes it to appear in rendered output without template changes.

**Form parsing tests** (`tests/dashboard/test_config_form_parsing.py`):

09. `test_parse_literal_str` — literal string parsed correctly.
10. `test_parse_literal_int` — literal int coerced from string.
11. `test_parse_literal_bool` — literal bool from select value.
12. `test_parse_var_ref` — var mode produces `VarRef`.
13. `test_parse_env_var` — env mode produces `EnvVar`.
14. `test_parse_empty_optional` — empty optional field omitted from result.
15. `test_parse_empty_required` — empty required field returns validation error.
16. `test_parse_invalid_int` — non-numeric int field returns validation error.

**Credential parsing tests**:

17. `test_parse_masked_secret` — indexed form data reconstructs
    `MaskedSecret`-compatible raw dict.
18. `test_parse_signing_credential` — nested credential fields parsed correctly.
19. `test_parse_github_app_credential` — all sub-fields parsed correctly.
20. `test_parse_credential_add_remove` — adding/removing entries works.

**Raw dict merge tests**:

21. `test_merge_global_fields` — form data merged into raw dict at correct
    nested paths.
22. `test_merge_repo_fields` — repo form data merged correctly.
23. `test_merge_preserves_unedited` — fields not in the form are preserved.
24. `test_merge_channel_add_remove` — adding/removing channels updates raw dict.

**Variable editing tests**:

25. `test_vars_add_literal` — new literal variable added to raw dict.
26. `test_vars_add_env` — new env variable added as `EnvVar`.
27. `test_vars_delete` — variable removed from raw dict.
28. `test_vars_rename` — variable key change updates raw dict.

**Security tests**:

29. `test_post_without_csrf_header_rejected` — POST to `/config/global` without
    `X-Requested-With` header returns 403.
30. `test_post_with_csrf_header_accepted` — POST with the header succeeds.

### Integration Tests

Integration tests follow the existing pattern in
`tests/integration/gateway/test_config_reload.py`, using `ConfigFile` helper and
`IntegrationEnvironment`.

**E1: Global config round-trip**

1. Start service with known config.
2. GET `/config/global`, verify form shows current values.
3. POST `/config/global` with changed `max_concurrent_executions`.
4. Verify YAML file updated correctly.
5. Wait for reload (`config_generation` incremented).
6. GET `/config/global` again, verify new value shown.

**E2: Repo config round-trip**

1. Start service with one repo.
2. GET `/config/repo/<id>`, verify all fields shown.
3. POST with changed `model` (task scope).
4. Verify file updated and reload applied immediately.

**E3: Variable indirection round-trip**

1. Create config with `vars: {server: mail.example.com}` and repo using
   `!var server` for `imap_server`.
2. GET `/config/global`, verify variable shown.
3. POST changing variable value.
4. Verify repo's `imap_server` field still shows `!var server` (tag preserved)
   but resolved value updated.

**E4: Add new repo**

1. POST `/config/repo/new` with repo_id and git URL.
2. Verify repo appears in config file.
3. Wait for reload.
4. Verify repo appears in dashboard repo list.
5. GET `/config/repo/<new_id>` succeeds.

**E5: Remove repo**

1. Start with two repos.
2. POST `/config/repo/<id>/delete`.
3. Verify repo removed from config file.
4. Wait for reload.
5. Verify repo removed from dashboard.

**E6: Credential editing**

1. Start with repo having masked secret.
2. GET repo page, verify credential card shown.
3. POST with modified scope pattern.
4. Verify YAML updated correctly.
5. Add new masked secret via POST.
6. Verify both secrets present in file.

**E7: Validation error handling**

1. POST `/config/global` with invalid `max_concurrent_executions` (0).
2. Verify form returns with inline error.
3. Verify config file unchanged (form-level validation catches it).

**E8: Config-level error after save**

1. POST repo config removing required `git_repo_url`.
2. Verify file is saved (write succeeds).
3. Verify `/api/status` shows `last_reload_error`.
4. Verify service continues with old config.
5. Fix the error via another POST.
6. Verify reload succeeds.

**E9: Channel add/remove**

1. Start with repo having only email channel.
2. POST adding Slack channel with required fields.
3. Verify YAML contains slack block.
4. POST removing email channel.
5. Verify YAML no longer contains email block.

**E10: Env var mode preservation**

1. Set `os.environ["TEST_SECRET"]` to a value.
2. Create config with `password: !env TEST_SECRET`.
3. GET repo page, verify field shows `!env` mode with env var name.
4. POST form without changing the field.
5. Verify YAML still contains `!env TEST_SECRET` (not resolved value).

### Test Coverage Requirements

- All new code in `airut/dashboard/config_editor.py` must have 100% test
  coverage.
- All new templates must be exercised by at least one test (rendered and checked
  for key elements).
- Integration tests cover the full save-reload-verify cycle.

## Security Considerations

- **CSRF:** All mutating endpoints require `X-Requested-With` header (HTMX sets
  this automatically). No cross-origin `<form>` POST can succeed.
- **No auth:** The dashboard has no built-in authentication. The config editor
  inherits this — it assumes the dashboard is behind a reverse proxy or bound to
  localhost. This is consistent with the existing security model.
- **Secret display:** Per requirements, secrets are shown in plain text. The
  `secret` field metadata is not used for masking.
- **File permissions:** The YAML file retains its existing filesystem
  permissions. The editor does not change ownership or mode.
- **CSP:** All editor UI uses existing CSP headers (no inline scripts or
  styles).

## Future Considerations

- **Optimistic locking** — if multi-user editing becomes a concern, add an
  ETag/version check on save (compare file mtime or content hash).
- **Config history** — could show git log of config file changes.
- **Dry-run validation** — resolve and validate before saving, with explicit
  "save anyway" option for configs with unresolved env vars.
- **Config import/export** — download/upload YAML directly.
