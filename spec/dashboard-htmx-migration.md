# Dashboard HTMX + Jinja2 Migration

Migrate the dashboard from string-based HTML generation to Jinja2 templates with
htmx for live updates. This is a full, one-shot migration of all views — not a
piecemeal adoption.

## Motivation

The current dashboard (~7,600 lines) generates all HTML via Python f-strings,
embeds JavaScript as Python string literals, and defines CSS as Python functions
returning strings. This approach has scaling problems as the dashboard grows:

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
- No new runtime dependencies beyond Jinja2 (already a transitive dependency via
  Werkzeug)

## Non-Goals

- Changing the WSGI server or migrating to async (separate effort if needed)
- Adding authentication (remains behind reverse proxy)
- Changing the SSE protocol, endpoints, or data formats
- Redesigning the visual appearance (colors, layout stay the same)
- Adding new dashboard features (this is a refactor, not a feature release)

## Architecture

### Template Engine

Jinja2 templates in `airut/dashboard/templates/`, bundled into the wheel via
`airut/_bundled/templates/`. Jinja2 is already a transitive dependency
(Werkzeug's `DebuggedApplication` and other utilities depend on it) so this adds
no new package to the dependency tree.

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

CSS moves from Python functions to static files:

```
airut/dashboard/static/
  styles/
    base.css              — reset, typography, shared variables (CSS custom properties)
    light.css             — light theme (dashboard, task detail, conversation, repo)
    dark.css              — dark theme (actions, network)
    components.css        — component-specific styles (cards, badges, buttons, etc.)
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
  /* ... */
}
```

Static files are served by a new `/static/` route handler. No build step — files
are served directly (or from `_bundled/` when running from a wheel).

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
- `style-src 'self'` — only static CSS files (no more inline styles)

This is a security improvement: inline injection attacks are blocked by CSP even
if template auto-escaping were somehow bypassed.

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

**Server-side change**: the state stream SSE endpoint gains a new response mode.
When the request `Accept` header includes `text/html` (set by htmx), it renders
Jinja2 template fragments and sends them as SSE events. When `Accept` is
`application/json` (API clients, polling fallback), it sends JSON as before.

**SSE event format** (new HTML mode):

```
event: boot-state
data: <div id="boot-container">...rendered boot banner...</div>

event: repos
data: <div id="repos-container">...rendered repo grid...</div>

event: tasks
data: <div id="pending-list">...</div>
data: <div id="executing-list">...</div>
data: <div id="completed-list">...</div>
```

**Template markup**:

```html
<div id="dashboard-live" hx-ext="sse"
     sse-connect="/api/events/stream">

  <div id="boot-container" sse-swap="boot-state">
    {% include "components/boot_state.html" %}
  </div>

  <div id="repos-container" sse-swap="repos">
    {% include "components/repos_section.html" %}
  </div>

  <div id="pending-list" sse-swap="tasks">
    {% for task in pending_tasks %}
      {% include "components/task_card.html" %}
    {% endfor %}
  </div>
  <!-- ... -->
</div>
```

htmx's SSE extension connects to the endpoint, listens for named events, and
swaps the received HTML into elements with matching `sse-swap` attributes.

**Task detail and repo detail** use the same state stream but filter
server-side: the endpoint only sends events relevant to the requested task/repo.
This is a server-side optimization — htmx replaces whatever element the
`sse-swap` attribute targets.

#### Pattern 2: SSE Append-Only Streaming

Used by: **actions viewer**, **network logs viewer**.

These pages already stream pre-rendered HTML via SSE. The only change is
replacing the custom JS append logic with htmx SSE attributes.

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

**Scroll preservation**: htmx does not auto-scroll on append. A small inline
script (the only remaining custom JS) handles auto-scrolling when the user is at
the bottom, matching current behavior. This is ~15 lines, down from ~75 lines
per page.

#### Polling Fallback

When SSE is unavailable (429 connection limit, network issues), htmx
automatically falls back to polling via `hx-trigger="every 5s"` on a hidden
element that issues `hx-get` requests returning the same HTML fragments. This
replaces the current manual `setInterval` + `fetch` + ETag polling logic.

The existing ETag-based JSON polling endpoints remain available for API clients
and integration tests. The HTML polling endpoints are new, lightweight wrappers
that render the same Jinja2 fragments.

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

**Remaining JavaScript** (~50 lines total across all pages):

- `local_time_script()` — converts UTC timestamps to local timezone (inherently
  client-side, cannot be done server-side)
- `update_check_script()` — async fetch to `/api/update` to avoid blocking page
  load (can migrate to `hx-get` with `hx-trigger="load"`)
- `render_stop_script()` — task stop button POST (migrates to
  `hx-post="/api/conversation/{id}/stop"` with `hx-headers` for CSRF)
- Auto-scroll logic for append-only pages (~15 lines)
- `toggleEvent()` for collapsible JSON blocks in actions view (~5 lines)

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

The state stream endpoint (`/api/events/stream`) gains content negotiation:

- `Accept: text/html` (htmx) → renders Jinja2 fragments, sends as separate named
  SSE events (`boot-state`, `repos`, `tasks`, `task-detail:{id}`,
  `repo-detail:{id}`)
- `Accept: application/json` (API clients) → sends JSON as today (backward
  compatible)

The event log and network log SSE endpoints are unchanged — they already send
pre-rendered HTML.

#### New Static File Handler

A `/static/<path>` route serves files from the static directory. In development,
files are read from `airut/dashboard/static/`. When installed as a wheel, files
are read from `airut/_bundled/static/`. Responses include `Cache-Control` with
content-hash-based ETags for efficient caching.

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
reference these variables.

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

1. **Set up infrastructure**: Jinja2 environment, template loader, static file
   handler, vendored htmx files, `render_template()` helper
2. **Create static CSS files**: extract from `views/styles.py`, unify into the
   shared design system with CSS custom properties
3. **Create base template**: `base.html` with blocks, htmx script tag, CSS
   links, CSP headers
4. **Create component templates**: extract from `views/components.py`, one
   template per component
5. **Migrate pages** (all at once): convert each page view from Python f-strings
   to Jinja2 template, replacing inline JS with htmx attributes
6. **Update SSE endpoints**: add content negotiation for HTML fragment responses
7. **Update handlers**: switch from view function calls to `render_template()`
   calls
8. **Delete old views module**: remove `views/` entirely
9. **Update tests**: tests should verify rendered template output, SSE HTML
   fragments, and htmx attribute presence

### Test Strategy

- **Unit tests** render templates with mock data and assert expected HTML
  structure (element IDs, htmx attributes, content)
- **SSE tests** verify that HTML-mode state stream sends valid HTML fragments
  with correct SSE event names
- **Component tests** verify each template component renders correctly in
  isolation
- **Existing handler tests** are updated to expect the same HTTP semantics
  (status codes, content types, ETag behavior) with template-rendered output
- **100% coverage** requirement is maintained — templates are exercised through
  handler tests

## Dependencies

| Dependency         | Status                            | Notes                                          |
| ------------------ | --------------------------------- | ---------------------------------------------- |
| Jinja2             | Already transitive (via Werkzeug) | Add as explicit dependency in `pyproject.toml` |
| htmx 2.x           | Vendored static file              | `static/vendor/htmx.min.js` (~14 KB gzipped)   |
| htmx SSE extension | Vendored static file              | `static/vendor/sse.js` (~2 KB)                 |

No npm, no Node.js, no build step. The deployment model is unchanged.

## Security

### Improvements

- **Auto-escaping** — Jinja2 escapes all template variables by default,
  eliminating the class of XSS bugs from missed `html.escape()` calls
- **Stricter CSP** — `script-src 'self'` and `style-src 'self'` block inline
  injection (currently `'unsafe-inline'` is required)
- **No `|safe` without review** — usage of the `|safe` filter is limited to
  known pre-rendered HTML (SVG logo, SSE event fragments) and should be audited
  in code review

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
- SSE protocol for event log and network log streams is unchanged
- Integration tests using JSON APIs require no changes
- Health check endpoint is unchanged

### Breaking (Internal)

- The `views/` Python module is removed — no external consumers exist
- The state stream SSE endpoint sends HTML when `Accept: text/html` (new
  behavior), JSON when `Accept: application/json` (existing behavior)
- CSP header changes from allowing `'unsafe-inline'` to `'self'` only

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
