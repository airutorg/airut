# Dashboard HTMX + Jinja2 Migration

Migrate the dashboard from string-based HTML generation to Jinja2 templates with
htmx for live updates. This is a full, one-shot migration of all views — not a
piecemeal adoption.

## Motivation

The current dashboard view layer (~4,400 lines in `views/`) generates all HTML
via Python f-strings, embeds JavaScript as Python string literals, and defines
CSS as Python functions returning strings. This approach has scaling problems as
the dashboard grows:

1. **No tooling support** — HTML/CSS/JS inside Python strings get no syntax
   highlighting, linting, autocompletion, or formatting from editors or CI.
2. **Duplication** — rendering logic is duplicated between server-side Python
   (initial page load) and client-side JavaScript (SSE updates). Task cards,
   boot state, todo progress, and duration formatting each exist in two
   independent implementations that must be kept in sync.
3. **XSS surface** — manual `html.escape()` calls are the only defense. A single
   missed call in a f-string creates a vulnerability. Template engines
   auto-escape by default.
4. **Maintenance cost** — adding a new view requires ~500-800 lines of
   string-building Python. Modifying shared styling means editing Python
   functions that return CSS strings.

## Goals

- Replace all f-string HTML generation with Jinja2 templates
- Replace all inline JavaScript SSE/polling logic with htmx attributes
- Unify CSS into static files with a shared design system
- Eliminate rendering duplication between server and client
- Preserve all existing functionality and SSE live-update behavior
- Maintain the current zero-build-step, no-npm deployment model

## Non-Goals

- Changing the WSGI server or migrating to async (separate effort if needed)
- Adding authentication (remains behind reverse proxy)
- Redesigning the visual appearance (colors, layout stay the same)
- Adding new dashboard features (this is a refactor, not a feature release)

## Architecture

### Template Engine

Jinja2 templates in `airut/dashboard/templates/`, included in the wheel via
`pyproject.toml` package data configuration. Jinja2 must be added as an
**explicit dependency** in `pyproject.toml` — while it is currently installed as
a transitive dependency, Werkzeug made Jinja2 optional in 2.x (only required for
`DebuggedApplication`), so the project cannot rely on it being present without
declaring it directly.

Templates are loaded at runtime using `importlib.resources` (for wheel installs)
with a filesystem fallback (for editable/development installs). This is the same
pattern used by `_bundled/assets/` and `_bundled/proxy/`.

```
airut/dashboard/templates/
  base.html               — shared HTML skeleton, head, meta, CSP
  components/
    boot_state.html       — boot progress/error banner
    logo.html             — inline SVG logo
    version_info.html     — version badge and update check
    repos_section.html    — repository status grid
    task_card.html        — single task card (used in dashboard + task list)
    reply_card.html       — reply with usage stats and text sections
    action_buttons.html   — view actions / view network / stop
    todo_progress.html    — progress checklist items
  pages/
    dashboard.html        — main three-column dashboard
    task_detail.html      — single task detail view
    conversation.html     — conversation overview (all tasks + replies)
    actions.html          — dark-themed event timeline
    network.html          — dark-themed network log viewer
    repo_detail.html      — repository detail view
```

### Template Conventions

**Auto-escaping**: enabled globally (`autoescape=True`). All variables are
escaped by default. The `|safe` filter is used only for pre-rendered HTML
fragments (e.g., SVG logo, SSE-streamed event HTML).

**Template inheritance**: all pages extend `base.html`, which defines blocks for
`title`, `styles`, `content`, and `scripts`. Light-themed pages and dark-themed
pages use different style blocks but share the same base.

**Components**: reusable fragments loaded via `{% include %}` with explicit
variable passing. Components are self-contained — they declare their expected
variables in a comment at the top of the file.

### Static Assets

CSS moves from Python functions to static files. JavaScript that must remain
client-side (timezone conversion, auto-scroll, event toggle) moves to static JS
files:

```
airut/dashboard/static/
  styles/
    base.css              — reset, typography, shared variables (CSS custom properties)
    light.css             — light theme (dashboard, task detail, conversation, repo)
    dark.css              — dark theme (actions, network)
    components.css        — component-specific styles (cards, badges, buttons, etc.)
  js/
    local-time.js         — convert data-timestamp attributes to local timezone
    auto-scroll.js        — auto-scroll for append-only pages (actions, network)
    actions.js            — toggleEvent() for collapsible JSON blocks
  vendor/
    htmx.min.js           — htmx 2.x (~14 KB gzipped)
    sse.js                — htmx SSE extension (~2 KB)
    VERSION               — tracks vendored version for update checks
```

**CSS custom properties** replace hardcoded color values scattered across Python
functions. All colors, spacing, and font stacks are defined as variables in
`base.css`:

```css
:root {
  --color-link: #337ab7;
  --color-queued: #f0ad4e;
  --color-executing: #5bc0de;
  --color-success: #5cb85c;
  --color-failed: #d9534f;
  --font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: ui-monospace, "SF Mono", Monaco, monospace;
  /* subagent palette — deterministic color classes */
  --subagent-color-0: #e06c75;
  --subagent-color-1: #61afef;
  --subagent-color-2: #98c379;
  --subagent-color-3: #d19a66;
  --subagent-color-4: #c678dd;
  --subagent-color-5: #56b6c2;
}
```

**Subagent colors**: the current inline `style="color: {color}"` and
`style="border-left-color: {color}"` attributes on subagent badges and event
containers are replaced with CSS classes `.subagent-color-0` through
`.subagent-color-5`. The server assigns the class name (based on the same
`tool_use_id` hash) instead of an inline style value. This eliminates the need
for `'unsafe-inline'` in `style-src`.

Static files are served by a new `/static/` route handler. No build step — files
are served directly. Templates and static files are included in wheel builds via
`pyproject.toml` package data (same mechanism as `_bundled/`). Responses include
`Cache-Control` with content-hash-based ETags for efficient caching.

### htmx Integration

htmx replaces all custom JavaScript for live updates. It is loaded from a single
`<script>` tag in `base.html`, served as a vendored static file (no CDN
dependency). The htmx SSE extension (`ext/sse.js`) is also vendored.

**Version**: htmx 2.x (stable at time of writing). Both `htmx.min.js` (~14 KB
gzipped) and `sse.js` (~2 KB) are committed to the repository under
`airut/dashboard/static/vendor/`.

#### Content-Security-Policy Update

The current CSP header allows inline scripts and styles because all JS and CSS
are inline. After migration:

- `script-src 'self'` — only static JS files from the same origin (no more
  inline scripts, no `'unsafe-inline'`)
- `style-src 'self'` — only static CSS files (no more inline styles, subagent
  colors use CSS classes instead of inline `style` attributes)

This is a security improvement: inline injection attacks are blocked by CSP even
if template auto-escaping were somehow bypassed.

**Achieving this requires**: all inline `<script>` tags and `onclick` handlers
move to static JS files; all inline `style` attributes move to CSS classes. The
actions view `toggleEvent()` function uses `addEventListener` with event
delegation (on the container) instead of per-element `onclick` attributes. The
initial scroll-to-bottom (`window.scrollTo`) on actions/network pages moves to
`auto-scroll.js`.

### Live Update Patterns with htmx

htmx provides two mechanisms that map to the existing SSE patterns. The key
architectural change is that **the server always renders HTML** — the client
never constructs DOM from JSON. This eliminates the current duplication where
both Python and JavaScript independently render the same components.

#### Pattern 1: SSE-Driven Fragment Replacement

Used by: **main dashboard**, **task detail**, **repo detail**.

Currently these pages connect to `/api/events/stream`, receive JSON state
snapshots, and reconstruct HTML in JavaScript. With htmx, the SSE endpoint sends
**pre-rendered HTML fragments** instead of JSON, and htmx swaps them into the
DOM.

**Server-side change**: the state stream SSE endpoint gains a new HTML mode,
selected via a `?format=html` query parameter. The `EventSource` API does not
support custom `Accept` headers, so content negotiation via `Accept` is not
feasible. When `format=html` is set, the endpoint renders Jinja2 template
fragments and sends them as named SSE events. Without the parameter, it sends
JSON as today (backward compatible).

**SSE event format** (HTML mode):

Each dashboard region is sent as a **separate named SSE event**. The htmx SSE
extension matches each event name to an element with a corresponding `sse-swap`
attribute and replaces that element's content. One SSE event maps to exactly one
DOM target.

```
event: boot-state
data: <div id="boot-container">...rendered boot banner...</div>

event: repos
data: <div id="repos-container">...rendered repo grid...</div>

event: pending-header
data: <h2 id="pending-header">Pending (3)</h2>

event: pending-tasks
data: <div id="pending-list">...task cards...</div>

event: executing-header
data: <h2 id="executing-header">Executing (1)</h2>

event: executing-tasks
data: <div id="executing-list">...task cards...</div>

event: completed-header
data: <h2 id="completed-header">Done (7)</h2>

event: completed-tasks
data: <div id="completed-list">...task cards...</div>
```

**Template markup**:

```html
<div id="dashboard-live" hx-ext="sse"
     sse-connect="/api/events/stream?format=html">

  <div sse-swap="boot-state" hx-swap="innerHTML">
    {% include "components/boot_state.html" %}
  </div>

  <div sse-swap="repos" hx-swap="innerHTML">
    {% include "components/repos_section.html" %}
  </div>

  <h2 id="pending-header" sse-swap="pending-header" hx-swap="outerHTML">
    Pending ({{ pending_count }})
  </h2>
  <div id="pending-list" sse-swap="pending-tasks" hx-swap="innerHTML">
    {% for task in pending_tasks %}
      {% include "components/task_card.html" %}
    {% endfor %}
  </div>
  <!-- executing and completed columns follow same pattern -->
</div>
```

htmx's SSE extension connects to the endpoint, listens for named events, and
swaps the received HTML into elements with matching `sse-swap` attributes. Each
`sse-swap` value corresponds to exactly one SSE event name.

**Task detail and repo detail** use the same state stream but with page-specific
query parameters (e.g., `?format=html&task_id=abc123`). The endpoint only sends
events relevant to the requested entity, reducing unnecessary rendering and
bandwidth.

#### Pattern 2: SSE Append-Only Streaming

Used by: **actions viewer**, **network logs viewer**.

These pages stream pre-rendered HTML via SSE. The current SSE format wraps HTML
inside JSON (`{"offset": N, "html": "..."}`). This format is **incompatible**
with htmx's `sse-swap`, which expects raw HTML as the SSE data field. The SSE
endpoints are changed to send raw HTML fragments, with the offset tracked via
the SSE `id:` field instead:

**New SSE format**:

```
id: 1234
event: html
data: <div class="event">...rendered event...</div>

id: 2048
event: done
data:
```

The `id:` field carries the byte offset (previously in the JSON `offset` field).
The browser's `EventSource` automatically sends `Last-Event-ID` on reconnection,
preserving resume behavior.

**Template markup**:

```html
<div id="events-container" hx-ext="sse"
     sse-connect="/api/conversation/{{ conversation_id }}/events/stream?offset={{ offset }}"
     sse-swap="html"
     hx-swap="beforeend">
  <!-- initial server-rendered content -->
  {% for event in events %}
    {% include "components/event_line.html" %}
  {% endfor %}
</div>
```

`hx-swap="beforeend"` appends new content rather than replacing. This matches
the current behavior.

**Scroll preservation**: htmx does not auto-scroll on append. A static JS file
(`static/js/auto-scroll.js`) handles auto-scrolling when the user is at the
bottom, matching current behavior. This is ~15 lines, loaded via `<script src>`.

**Polling fallback endpoints** (`/api/conversation/{id}/events/poll` and
`/api/conversation/{id}/network/poll`) are also updated to return raw HTML with
the offset in the response headers (e.g., `X-Log-Offset`) rather than in a JSON
wrapper, so they can be consumed by `hx-get` with `hx-swap="beforeend"`.

#### Polling Fallback

htmx does **not** automatically fall back from SSE to polling. When the SSE
connection fails, the htmx SSE extension fires an `htmx:sseError` event and
attempts reconnection. If reconnection also fails (e.g., 429 response), the
client must explicitly activate polling.

The fallback is implemented with a small static JS file (~20 lines) that:

1. Listens for `htmx:sseError` on the SSE container
2. After N consecutive failures, hides the SSE container and shows a polling
   container that uses `hx-get` with `hx-trigger="every 5s"` to fetch the same
   HTML fragments
3. Periodically attempts SSE reconnection and switches back if successful

For **state-based pages** (dashboard, task detail, repo detail), the polling
container issues `hx-get` requests to new endpoints that render the same Jinja2
fragments as the SSE HTML mode (e.g., `GET /api/events/poll?format=html`).

For **append-only pages** (actions, network), the polling container uses the
existing poll endpoints (updated to return raw HTML as described above) with
`hx-swap="beforeend"`.

The existing ETag-based JSON polling endpoints remain available for API clients
and integration tests.

#### Update Check

The current `update_check_script()` fetches `/api/update` and dynamically
constructs DOM elements with conditional styling. This migrates to:

- `hx-get="/api/update?format=html"` with `hx-trigger="load"` on the update
  status placeholder element
- A new HTML response mode on `/api/update` that renders the version status
  badge (link vs span, CSS class, title attribute) as a Jinja2 fragment
- No custom JavaScript needed

#### Stop Button

The current `render_stop_script()` POSTs to the stop endpoint and updates the
button text/state. This migrates to:

- `hx-post="/api/conversation/{id}/stop"` on the button element
- `hx-headers='{"X-Requested-With": "XMLHttpRequest"}'` for CSRF protection
- The stop endpoint returns an HTML fragment (e.g., "Stop signal sent" or error
  message) that htmx swaps into the button area
- `hx-swap="outerHTML"` replaces the button with the response fragment

### Eliminated JavaScript

After migration, the following custom JavaScript is **removed entirely**:

| Current JS                                         | Lines | Replacement                                |
| -------------------------------------------------- | ----- | ------------------------------------------ |
| `_sse_live_script()` (dashboard SSE + rendering)   | ~400  | htmx `sse-connect` + `sse-swap`            |
| `_sse_task_detail_script()` (task SSE + rendering) | ~200  | htmx `sse-connect` + `sse-swap`            |
| `_sse_events_script()` (actions SSE append)        | ~75   | htmx `sse-connect` + `hx-swap="beforeend"` |
| `_sse_network_script()` (network SSE append)       | ~75   | htmx `sse-connect` + `hx-swap="beforeend"` |
| `_sse_repo_detail_script()` (repo SSE + rendering) | ~85   | htmx `sse-connect` + `sse-swap`            |
| `renderTaskCard()` (client-side task card)         | ~80   | server-rendered via Jinja2                 |
| `renderBootState()` (client-side boot banner)      | ~40   | server-rendered via Jinja2                 |
| `renderTodos()` (client-side progress)             | ~50   | server-rendered via Jinja2                 |
| `formatDuration()` (duplicated 3x)                 | ~30   | server-side `format_duration()` only       |
| `formatTimestamp()` (duplicated 2x)                | ~20   | server-side only                           |
| `escapeHtml()` (manual XSS prevention)             | ~10   | Jinja2 auto-escaping                       |

**Remaining JavaScript** (static files, ~80 lines total):

- `static/js/local-time.js` — converts `data-timestamp` attributes to local
  timezone on `DOMContentLoaded` (inherently client-side)
- `static/js/auto-scroll.js` — auto-scroll logic for append-only pages,
  including initial scroll-to-bottom on page load (~15 lines)
- `static/js/actions.js` — `toggleEvent()` for collapsible JSON blocks, attached
  via event delegation on the container element (~10 lines)
- `static/js/sse-fallback.js` — SSE-to-polling fallback coordination (~20 lines)

### Server-Side Changes

#### Handler Refactoring

The `handlers.py` module currently delegates to view functions that return
complete HTML strings. After migration, handlers delegate to Jinja2 template
rendering:

```python
# Before
def handle_index(request: Request) -> Response:
    # ... gather data ...
    html = render_dashboard(tasks, boot_state, repos, version_info)
    return Response(html, content_type="text/html")


# After
def handle_index(request: Request) -> Response:
    # ... gather data (unchanged) ...
    html = render_template(
        "pages/dashboard.html",
        tasks=tasks,
        boot_state=boot_state,
        repos=repos,
        version_info=version_info,
    )
    return Response(html, content_type="text/html")
```

A `render_template()` helper wraps `jinja2.Environment.get_template().render()`
with the template directory and shared context (formatters, version info).

#### SSE Endpoint Changes

The state stream endpoint (`/api/events/stream`) gains an HTML mode via query
parameter:

- `?format=html` (htmx) — renders Jinja2 fragments, sends as separate named SSE
  events (`boot-state`, `repos`, `pending-header`, `pending-tasks`,
  `executing-header`, `executing-tasks`, `completed-header`, `completed-tasks`,
  `task-detail`, `repo-detail`)
- No `format` parameter (default) — sends JSON as today (backward compatible)

The event log and network log SSE endpoints change their data format: raw HTML
in the `data:` field with byte offset in the `id:` field (replacing the current
JSON wrapper `{"offset": N, "html": "..."}`). The `done` event remains unchanged
(empty data). This is a **breaking change** to the SSE wire format for these two
endpoints, but no external consumers exist — only the dashboard JS (being
replaced) uses them.

#### New HTML Endpoints

| Endpoint                           | Purpose                                                                                 |
| ---------------------------------- | --------------------------------------------------------------------------------------- |
| `GET /api/update?format=html`      | Version status badge as HTML fragment                                                   |
| `POST /api/conversation/{id}/stop` | Returns HTML fragment (existing endpoint, new response format when `Accept: text/html`) |

#### New Static File Handler

A `/static/<path>` route serves files from the static directory. Templates and
static files are included in wheel builds via `pyproject.toml` package data
configuration. Responses include `Cache-Control` with content-hash-based ETags
for efficient caching.

### Views Module Refactoring

The current `views/` module is **deleted entirely** after migration:

| Current file                                | Disposition                                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------------- |
| `views/styles.py` (1,174 lines)             | Replaced by `static/styles/*.css`                                                |
| `views/components.py` (~800 lines)          | Replaced by `templates/components/*.html`                                        |
| `views/dashboard.py` (~400 lines)           | Replaced by `templates/pages/dashboard.html`                                     |
| `views/task_detail.py` (~400 lines)         | Replaced by `templates/pages/task_detail.html`                                   |
| `views/conversation_detail.py` (~300 lines) | Replaced by `templates/pages/conversation.html`                                  |
| `views/actions.py` (~500 lines)             | Replaced by `templates/pages/actions.html` + `templates/components/event_*.html` |
| `views/network.py` (~300 lines)             | Replaced by `templates/pages/network.html`                                       |
| `views/repo_detail.py` (~200 lines)         | Replaced by `templates/pages/repo_detail.html`                                   |

The rendering logic in the event-type-specific renderers (10 event renderers, 8
tool renderers in `actions.py`) moves to Jinja2 template macros or include files
in `templates/components/`.

`formatters.py` is retained — Jinja2 templates call formatting functions via
registered template globals/filters.

## Shared Design System

The migration is an opportunity to unify duplicated styling patterns into a
coherent shared design system.

### CSS Architecture

**Layer 1 — Variables** (`base.css`): CSS custom properties for all colors,
spacing, font stacks, border radii, and shadows. Both light and dark themes
reference these variables. Includes subagent color palette as
`.subagent-color-N` classes.

**Layer 2 — Theme** (`light.css`, `dark.css`): Theme-specific overrides of
variables (e.g., `--bg`, `--text`, `--card-bg`). Pages include one theme file.

**Layer 3 — Components** (`components.css`): Reusable component classes that
work in both themes by referencing theme variables. Classes like `.card`,
`.badge`, `.field`, `.status-dot`, `.task-card`, `.reply-card`, `.usage-grid`.

This replaces the current pattern where each page-specific CSS function
(`dashboard_styles()`, `task_detail_styles()`, etc.) independently re-defines
card styles, badge colors, and field layouts.

### Component Consolidation

Components that currently exist as Python functions generating HTML are
refactored into Jinja2 templates with clear interfaces:

| Component     | Current                                                               | After                           | Shared across             |
| ------------- | --------------------------------------------------------------------- | ------------------------------- | ------------------------- |
| Task card     | `render_task_card()` in Python + `renderTaskCard()` in JS             | `task_card.html`                | Dashboard, conversation   |
| Boot banner   | `render_boot_state()` in Python + `renderBootState()` in JS           | `boot_state.html`               | Dashboard                 |
| Todo progress | `_render_progress_section()` in Python + `renderTodos()` in JS        | `todo_progress.html`            | Task detail               |
| Reply card    | `_render_reply_inner()` + `_render_reply_card()` + 2 section variants | `reply_card.html`               | Task detail, conversation |
| Repo card     | inline HTML in `render_repos_section()`                               | `repo_card.html`                | Dashboard, repo detail    |
| Duration      | `format_duration()` in Python + `formatDuration()` in JS (3 copies)   | `format_duration` Jinja2 filter | All pages                 |

## Migration Strategy

The migration is executed as a single atomic change — no intermediate state
where some pages use templates and others use f-strings. This avoids maintaining
two rendering systems simultaneously.

### Ordering

01. **Set up infrastructure**: Jinja2 environment, template loader (with
    `importlib.resources` support), static file handler, vendored htmx files,
    `render_template()` helper, `pyproject.toml` package data configuration
02. **Create static CSS files**: extract from `views/styles.py`, unify into the
    shared design system with CSS custom properties
03. **Create static JS files**: extract `local_time_script()`, `toggleEvent()`,
    auto-scroll logic, and SSE fallback into static files
04. **Create base template**: `base.html` with blocks, htmx script tag, CSS
    links, CSP headers
05. **Create component templates**: extract from `views/components.py`, one
    template per component
06. **Migrate pages** (all at once): convert each page view from Python
    f-strings to Jinja2 template, replacing inline JS with htmx attributes
07. **Update SSE endpoints**: add `?format=html` mode for state stream; change
    event/network log streams to raw HTML with `id:` offset
08. **Add HTML response modes**: `/api/update?format=html` for version badge,
    stop endpoint HTML response
09. **Update handlers**: switch from view function calls to `render_template()`
    calls
10. **Delete old views module**: remove `views/` entirely
11. **Update tests**: tests should verify rendered template output, SSE HTML
    fragments, and htmx attribute presence

### Test Strategy

- **Unit tests** render templates with mock data and assert expected HTML
  structure (element IDs, htmx attributes, content)
- **SSE tests** verify that HTML-mode state stream sends valid HTML fragments
  with correct SSE event names, and that event/network streams send raw HTML
  with offset in `id:` field
- **Component tests** verify each template component renders correctly in
  isolation
- **Existing handler tests** are updated to expect the same HTTP semantics
  (status codes, content types, ETag behavior) with template-rendered output
- **100% coverage** requirement is maintained — templates are exercised through
  handler tests

## Vendored Dependency Management

htmx and its SSE extension are vendored as static files rather than fetched from
a CDN. This preserves the zero-external-dependency deployment model but creates
a responsibility to track security patches.

### Version Tracking

A `VERSION` file in `static/vendor/` records the vendored htmx version:

```
htmx 2.0.4
htmx-ext-sse 2.2.2
```

### Security Update Checking

A CI check (`scripts/check_vendor_security.py`) runs as part of the security
workflow in `ci.py`. It:

1. Reads `VERSION` from the vendored directory
2. Fetches the latest release version from the htmx GitHub releases API
   (`https://api.github.com/repos/bigskysoftware/htmx/releases/latest`)
3. Fetches the htmx security advisories from the GitHub advisories API
   (`https://api.github.com/repos/bigskysoftware/htmx/security-advisories`)
4. **Fails CI** if the vendored version has a known security advisory
5. **Warns** (without failing) if a newer version is available

This check only requires network access to `api.github.com` (already in the
network allowlist for the `airutorg/*` paths). The htmx repo paths must be added
to `.airut/network-allowlist.yaml`:

```yaml
# htmx vendored dependency security checks (read-only)
- host: api.github.com
  path: /repos/bigskysoftware/htmx*
  methods: [GET]
```

### Update Script

A companion script (`scripts/update_vendor.py`) downloads the latest htmx
release and updates the vendored files:

1. Fetches the latest release tag from the GitHub API
2. Downloads `htmx.min.js` and `ext/sse.js` from the release assets (via
   `https://unpkg.com/htmx.org@{version}/dist/htmx.min.js` and the extensions
   package)
3. Writes the files to `static/vendor/`
4. Updates the `VERSION` file
5. Prints a summary of what changed

The necessary download URLs must also be added to the network allowlist:

```yaml
# htmx vendored dependency downloads (update script only)
- host: unpkg.com
  path: /htmx.org*
  methods: [GET, HEAD]
- host: unpkg.com
  path: /htmx-ext-sse*
  methods: [GET, HEAD]
```

Running the update is a manual process — the script is invoked when the CI check
warns about a new version or when a security advisory is published. The updated
files are committed and go through normal PR review.

### CI Integration

Add to `ci.py` steps (security workflow):

```python
(
    Step(
        name="Vendor security check",
        command="uv run python scripts/check_vendor_security.py",
        workflow="security",
    ),
)
```

## Dependencies

| Dependency         | Status                     | Notes                                        |
| ------------------ | -------------------------- | -------------------------------------------- |
| Jinja2             | Add as explicit dependency | Currently transitive but not guaranteed      |
| htmx 2.x           | Vendored static file       | `static/vendor/htmx.min.js` (~14 KB gzipped) |
| htmx SSE extension | Vendored static file       | `static/vendor/sse.js` (~2 KB)               |

No npm, no Node.js, no build step. The deployment model is unchanged.

## Security

### Improvements

- **Auto-escaping** — Jinja2 escapes all template variables by default,
  eliminating the class of XSS bugs from missed `html.escape()` calls
- **Stricter CSP** — `script-src 'self'` and `style-src 'self'` block inline
  injection (currently `'unsafe-inline'` is required). Achievable because all
  inline scripts move to static JS files and all inline styles move to CSS
  classes
- **No `|safe` without review** — usage of the `|safe` filter is limited to
  known pre-rendered HTML (SVG logo, SSE event fragments) and should be audited
  in code review
- **Vendored dependency tracking** — CI checks for security advisories against
  vendored htmx files

### Preserved

- CSRF protection on `POST /api/conversation/{id}/stop` — htmx sends the
  `X-Requested-With` header via `hx-headers` attribute
- Localhost binding default and non-loopback warning
- Security response headers (X-Content-Type-Options, X-Frame-Options, CSP)
- No authentication (reverse proxy responsibility)

## Compatibility

### Backward Compatible

- All JSON API endpoints (`/api/*`) are unchanged
- ETag-based conditional requests work identically
- Integration tests using JSON APIs require no changes
- Health check endpoint is unchanged

### Breaking (Internal Only)

- The `views/` Python module is removed — no external consumers exist
- The state stream SSE endpoint has a new `?format=html` mode (default behavior
  unchanged)
- Event log and network log SSE endpoints change data format from JSON-wrapped
  to raw HTML with offset in `id:` field — no external consumers, only dashboard
  JS (being replaced)
- CSP header changes from allowing `'unsafe-inline'` to `'self'` only

### Spec Updates Required

The following companion specs must be updated when this migration is
implemented:

- **`spec/live-dashboard.md`** — update SSE event formats for event/network log
  streams (raw HTML + `id:` offset instead of JSON wrapper); update polling
  fallback description (htmx-coordinated fallback instead of page reload);
  document the new `?format=html` mode on the state stream
- **`spec/dashboard.md`** — note the Jinja2 + htmx architecture in the
  Components section; update Dependencies section to include Jinja2 as explicit
  dependency

## Future Considerations

This migration establishes the foundation for planned dashboard extensions:

- **Server configuration views** — new pages are added by creating a Jinja2
  template and a handler, reusing shared components and CSS. No f-string HTML
  assembly required.
- **WSGI to ASGI migration** — if the 8-connection SSE limit becomes a
  bottleneck, migrating to Starlette/ASGI is a separate effort. The Jinja2
  templates and htmx attributes are framework-agnostic and transfer unchanged.
- **Additional interactivity** — htmx supports forms, dialogs, and partial page
  updates natively. Server configuration editing (forms, validation, save) maps
  cleanly to htmx patterns without adding a JavaScript framework.
- **Conversation detail live updates** — the conversation detail page currently
  renders statically. With the htmx infrastructure in place, adding SSE updates
  (e.g., for an active conversation) requires only adding `sse-connect` and
  `sse-swap` attributes to the template.
