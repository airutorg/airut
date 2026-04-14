# Markdown to HTML Pipeline

Converts markdown text to email-friendly HTML. Used by the email channel to
format agent responses before sending.

## Goals

1. **CommonMark compliance** — parse markdown correctly, including edge cases
   that matter for LLM-generated content (nested structures, mixed formatting,
   ambiguous delimiters).
2. **Email-friendly output** — produce HTML that renders consistently across
   email clients (no `<p>` tags, no `<h1>`–`<h6>`, inline styles where needed).
3. **Robustness** — never throw on malformed input. Unrecognized syntax degrades
   to literal text.
4. **Extensibility** — parser and renderer are separate. Adding a new output
   format (e.g. Slack mrkdwn) means writing a new renderer, not a new parser.

## Architecture

```
                    table              ┌─ EmailRenderer ──▶ HTML for email
markdown text ──▶ pre-process ──▶ mistune parser ──┤
                                       └─ (future renderers)
```

**Parser**: mistune v3 (`mistune>=3.2,<4`), a zero-dependency CommonMark parser.
The `table` and `table_in_quote` plugins are enabled.

**Pre-processor**: `_prepare_tables()` fixes two mistune table plugin
limitations before parsing (see [Table pre-processing](#table-pre-processing)).

**Renderer**: `EmailRenderer(mistune.HTMLRenderer)` overrides every render
method to produce email-specific HTML.

**Post-processor**: strips trailing `<br>` from the final output so the last
block element doesn't produce an extra line break.

The mistune `Markdown` instance is created once at module level and reused
across calls.

### Why subclass HTMLRenderer

`HTMLRenderer` provides `render_token()` dispatch that unpacks token dicts into
method arguments (`text`, `level`, `**attrs`) and pre-renders children. This
gives us method-per-element ergonomics without re-implementing the dispatch.
Class methods on the subclass take priority over the table plugin's registered
functions, so defining `table()`, `table_head()`, etc. on the class is
sufficient.

## Public interface

```python
def markdown_to_html(text: str) -> str:
    """Convert markdown text to HTML for email."""
```

Empty input returns `""`. The function is stateless and safe to call from any
thread (the module-level mistune instance is reentrant for single-threaded use).

## EmailRenderer contracts

### Email-specific HTML choices

These choices ensure consistent rendering across email clients:

- **No `<p>` tags** — paragraphs end with `<br>\n` instead. Email clients handle
  `<p>` margins inconsistently.
- **No `<h1>`–`<h6>` tags** — headings use inline formatting to keep font size
  constant. See heading level mapping below.
- **No `<img>` tags** — images render as links. Email clients handle images
  inconsistently.
- **No raw HTML pass-through** — `inline_html` and `block_html` escape their
  content instead of passing it through, preventing XSS.
- **Inline styles for tables and blockquotes** — `<table style="...">` and
  `<blockquote style="...">` because email clients ignore `<style>` blocks.
- **No `<thead>`/`<tbody>`** — tables use flat `<tr>` rows for compact output.

### Heading level mapping

| Level | Style                 | Tags                                 |
| ----- | --------------------- | ------------------------------------ |
| 1     | bold underline        | `<strong><u>…</u></strong>`          |
| 2     | bold italic underline | `<strong><em><u>…</u></em></strong>` |
| 3     | underline             | `<u>…</u>`                           |
| 4     | italic underline      | `<em><u>…</u></em>`                  |
| 5     | italic                | `<em>…</em>`                         |
| 6     | bold                  | `<strong>…</strong>`                 |

All headings append `<br>\n` for visual separation.

### Block element trailing `<br>` stripping

`paragraph()` appends `<br>\n` for inter-paragraph spacing. Container elements
(`block_quote`, `list_item`) strip trailing `<br>` from their inner content to
avoid double-spacing before closing tags. The top-level post-processor strips
trailing `<br>` from the final document output.

### Inline style constants

- **Table**: `border:1px solid #ccc;border-collapse:collapse;`
- **Table cell**: `border:1px solid #ccc;padding:4px 8px;`
- **Blockquote**:
  `margin:0 0 0 0.8em;border-left:2px solid #ccc;padding:0 0 0 0.6em;color:#666;`

## Table pre-processing

mistune's table plugin has two limitations that cause entire tables to vanish
(falling through to paragraph text) on imperfect input:

1. **Pipes in code spans** — the cell splitter regex splits on all unescaped `|`
   without respecting backtick code spans. A cell like `` `a|b` `` is split into
   two cells instead of one.

2. **Column count mismatches** — if any row has a different cell count than the
   separator, the entire table parse fails. A single extra or missing pipe kills
   the whole table.

Both are common in LLM-generated content. All other malformed markdown degrades
gracefully in mistune — tables are the sole structural failure mode.

### Pipe sentinel approach

Within table lines, pipes inside backtick code spans are replaced with a Unicode
Private Use Area sentinel (`\uf000`) before parsing. The `codespan()` renderer
restores the sentinel to `|` before output.

Why not `\|`? CommonMark treats code span content as literal — backslash escapes
don't apply. `\|` would render as `<code>a\|b</code>` with a visible backslash.

### Column count normalization

After pipe escaping, each table row is normalized to match the separator's
column count: short rows are padded with empty cells, long rows are truncated.
This applies to both header and data rows.

## Robustness properties

mistune never throws exceptions on any input. Malformed markdown degrades
gracefully:

| Input                         | Behavior                                  |
| ----------------------------- | ----------------------------------------- |
| Unclosed inline formatting    | Literal pass-through                      |
| Unclosed fenced code block    | Rest of document treated as code          |
| Malformed links               | Literal pass-through                      |
| Deeply nested structures      | Rendered (blockquotes cap ~6 levels deep) |
| Tables with column mismatches | Handled by pre-processor (see above)      |
| Mixed broken structures       | Each block degrades independently         |
