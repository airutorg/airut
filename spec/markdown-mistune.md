# Markdown to HTML: Migration to mistune

Replace the hand-rolled markdown parser in `airut/markdown.py` with
[mistune](https://github.com/lepture/mistune) v3, a zero-dependency CommonMark
parser with a pluggable renderer architecture.

## Motivation

The current `airut/markdown.py` (~690 lines) is a custom line-by-line markdown
parser supporting a subset of CommonMark. It works, but:

1. **Maintenance cost** — every new markdown feature (strikethrough, task lists,
   nested lists, etc.) requires extending the hand-rolled parser. CommonMark has
   many edge cases that are difficult to handle correctly in ad-hoc code.

2. **Single-purpose** — the parser and renderer are interleaved. Adding a second
   output format (e.g. Slack mrkdwn) would require duplicating large parts of
   the parsing logic.

3. **Spec compliance** — the current parser handles common cases well but
   deviates from CommonMark on various edge cases. A spec-compliant parser
   eliminates these gaps.

mistune addresses all three: it parses CommonMark correctly, separates parsing
from rendering, and lets us define multiple renderers against the same parsed
token stream.

## Why mistune

Selection criteria and how mistune compares to alternatives:

| Criterion            | mistune          | mistletoe        | marko            | markdown-it-py |
| -------------------- | ---------------- | ---------------- | ---------------- | -------------- |
| Runtime dependencies | **0**            | 0                | 0                | 1 (mdurl)      |
| PyPI downloads/month | ~49M             | ~3M              | ~1M              | ~120M          |
| GitHub stars         | ~3k              | ~800             | ~250             | ~700           |
| Actively maintained  | Yes (Dec 2025)   | Yes (2024)       | Yes              | Yes            |
| Custom renderer      | Subclass methods | Subclass methods | Subclass methods | Token stream   |
| CommonMark compliant | Compatible       | Spec-compliant   | v0.31.2          | 100% compliant |
| Table support        | Built-in plugin  | Extension        | GFM extension    | Plugin         |
| License              | BSD-3-Clause     | MIT              | MIT              | MIT            |

**Decision**: mistune wins on supply-chain risk (zero dependencies, single
well-known maintainer, massive adoption — Jupyter ecosystem depends on it) and
on developer ergonomics (method-per-element renderer subclassing). The
`slackstyler` library already demonstrates using mistune as a basis for Slack
mrkdwn output, validating the multi-renderer approach.

Rejected alternatives:

- **commonmark-py** — last release 2021, effectively abandoned.
- **markdown-it-py** — depends on `mdurl`; token-stream renderer is less
  ergonomic than method-per-element.
- **mistletoe** — maintenance gap (2019 hiatus, fork created) raises long-term
  concerns.
- **marko** — lower adoption, 3x slower than Python-Markdown.

## Architecture

### Current design

```
markdown text ──▶ markdown_to_html() ──▶ HTML string
                  (parse + render interleaved, ~690 lines)
```

### New design

```
                    table              ┌─ EmailRenderer ──▶ HTML for email
markdown text ──▶ pre-process ──▶ mistune parser ──┤
                                       └─ (future: SlackRenderer ──▶ mrkdwn)
```

The parser is mistune's built-in CommonMark parser with the `table` plugin. The
`EmailRenderer` is a subclass of `mistune.HTMLRenderer` (~100–150 lines) that
overrides every render method to produce our email-friendly HTML output.

### Key design choice: subclass HTMLRenderer, not BaseRenderer

`HTMLRenderer` includes `render_token()` logic that unpacks token dicts into
method arguments (`text`, `level`, `**attrs`, etc.) — a convenience layer that
pre-renders children and passes the result as the `text` argument. Subclassing
`HTMLRenderer` inherits this unpacking. We then override every render method to
produce our email-specific output. This avoids re-implementing the
token-to-argument dispatch while giving us full control over the HTML output.

Note: `heading()` and other methods receive pre-rendered inline content — the
`text` argument already has emphasis/strong/link/etc. applied by child token
rendering. The renderer methods must not re-escape or re-process this content.

## EmailRenderer specification

The `EmailRenderer` subclass overrides the following `HTMLRenderer` methods.
Each section below specifies the exact output for each token type.

### Inline tokens

#### `text(self, text: str) -> str`

Return `text` with HTML entities escaped. Inherits from `HTMLRenderer` (uses
`mistune.renderers.html.escape_text`, also available as top-level
`mistune.escape`).

#### `emphasis(self, text: str) -> str`

```python
return "<em>" + text + "</em>"
```

#### `strong(self, text: str) -> str`

```python
return "<strong>" + text + "</strong>"
```

#### `codespan(self, text: str) -> str`

```python
# Restore pipe sentinel from _prepare_tables() before rendering.
return "<code>" + escape_text(text.replace("\uf000", "|")) + "</code>"
```

#### `link(self, text: str, url: str, title: str | None = None) -> str`

```python
return '<a href="' + escape_text(url) + '">' + text + "</a>"
```

Titles are ignored (email clients render them inconsistently).

#### `linebreak(self) -> str`

```python
return "<br>"
```

Note: no trailing `\n` or space — matches current output. No self-closing
(`<br>` not `<br />`).

#### `softbreak(self) -> str`

```python
return " "
```

Soft line breaks render as spaces, matching CommonMark paragraph semantics and
current behavior.

#### `image(self, text: str, url: str, title: str | None = None) -> str`

Render as a link (email clients handle images inconsistently):

```python
return '<a href="' + escape_text(url) + '">' + escape_text(text or url) + "</a>"
```

#### `inline_html(self, html: str) -> str`

Escape and return (do not pass raw HTML through):

```python
return escape_text(html)
```

### Block tokens

#### `heading(self, text: str, level: int, **attrs) -> str`

Map heading levels to inline styles (no `<h1>`–`<h6>` tags). Preserves the
current header styling convention:

| Level | Style                 | HTML                                      |
| ----- | --------------------- | ----------------------------------------- |
| 1     | bold underline        | `<strong><u>{text}</u></strong>`          |
| 2     | bold italic underline | `<strong><em><u>{text}</u></em></strong>` |
| 3     | underline             | `<u>{text}</u>`                           |
| 4     | italic underline      | `<em><u>{text}</u></em>`                  |
| 5     | italic                | `<em>{text}</em>`                         |
| 6     | bold                  | `<strong>{text}</strong>`                 |

Append `<br>\n` after the heading for visual separation.

#### `paragraph(self, text: str) -> str`

```python
return text + "<br>\n"
```

No wrapping `<p>` tag — email clients handle `<p>` margins inconsistently.
Trailing `<br>` provides visual paragraph separation matching current behavior.

#### `blank_line(self) -> str`

```python
return "<br>\n"
```

#### `block_code(self, code: str, info: str | None = None) -> str`

```python
return "<pre>" + html.escape(code.rstrip("\n")) + "</pre>\n"
```

Strip trailing newline from code content (mistune includes it). No language
class attribute — not useful for email rendering.

#### `block_quote(self, text: str) -> str`

```python
BLOCKQUOTE_STYLE = (
    "margin:0 0 0 0.8em;border-left:2px solid #ccc;"
    "padding:0 0 0 0.6em;color:#666;"
)
# Strip trailing <br> and whitespace from inner content — paragraph()
# appends <br>\n but we don't want it before </blockquote>.
inner = text.rstrip("\n")
if inner.endswith("<br>"):
    inner = inner[:-4]
return (
    '<blockquote style="' + BLOCKQUOTE_STYLE + '">' + inner + "</blockquote>\n"
)
```

Inline styles for email client compatibility. mistune handles nested blockquotes
recursively. The inner content stripping is needed because `paragraph()` appends
`<br>\n`, but the blockquote wrapper provides its own visual separation.

#### `list(self, text: str, ordered: bool, **attrs) -> str`

```python
tag = "ol" if ordered else "ul"
start = attrs.get("start")
start_attr = f' start="{start}"' if start is not None and start != 1 else ""
return f"<{tag}{start_attr}>{text}</{tag}>\n"
```

Preserves `start` attribute for ordered lists starting at non-1 values.

#### `list_item(self, text: str) -> str`

```python
# Strip trailing <br> from inner content — paragraph() appends <br>\n
# for loose list items but we don't want it before </li>.
inner = text.strip()
if inner.endswith("<br>"):
    inner = inner[:-4]
return "<li>" + inner + "</li>"
```

No newlines between `<li>` tags — produces compact output matching current
behavior. The trailing `<br>` stripping handles loose lists (items separated by
blank lines), where mistune wraps each item's content in `paragraph()`.

#### `thematic_break(self) -> str`

```python
return "<hr>\n"
```

#### `block_html(self, html: str) -> str`

Escape raw HTML blocks (do not pass through):

```python
return escape_text(html)
```

#### `block_text(self, text: str) -> str`

```python
return text
```

#### `block_error(self, text: str) -> str`

```python
return ""
```

### Table tokens (via table plugin)

The table plugin registers these additional render methods. We override them
with email-friendly inline styling matching current output:

```python
TABLE_STYLE = "border:1px solid #ccc;border-collapse:collapse;"
CELL_STYLE = "border:1px solid #ccc;padding:4px 8px;"


def table(self, text: str) -> str:
    return '<table style="' + TABLE_STYLE + '">' + text + "</table>\n"


def table_head(self, text: str) -> str:
    # table_head contains table_cell children directly (no table_row
    # wrapper in mistune's token tree), so we add <tr> here.
    return "<tr>" + text + "</tr>"


def table_body(self, text: str) -> str:
    return text


def table_row(self, text: str) -> str:
    # table_row wraps body rows only (head uses table_head above).
    return "<tr>" + text + "</tr>"


def table_cell(
    self, text: str, align: str | None = None, head: bool = False
) -> str:
    tag = "th" if head else "td"
    return "<" + tag + ' style="' + CELL_STYLE + '">' + text + "</" + tag + ">"
```

No wrapping `<thead>`/`<tbody>` — matches current compact output.

## Table pre-processing

mistune's table plugin has two limitations that cause tables to disappear
entirely (falling through to plain paragraph text) when given imperfect input:

1. **Pipes in code spans** — the `CELL_SPLIT` regex splits on all unescaped `|`
   without respecting backtick code spans. `` | `a|b` | test | `` splits into 3
   cells instead of 2.

2. **Column count mismatches** — if any data row has a different number of cells
   than the header, `_process_row()` returns `None` and the entire table parse
   fails. A single row with an extra or missing pipe kills the whole table.

Both are relevant for LLM-generated content, which commonly includes code spans
with pipes in tables and occasionally produces rows with wrong column counts.

All other malformed markdown (unclosed formatting, broken links, mismatched
delimiters, etc.) degrades gracefully in mistune — unrecognized syntax passes
through as literal text. Tables are the sole structural failure mode requiring
mitigation.

### Pre-processing function: `_prepare_tables(text: str) -> str`

A pre-processing step runs before passing text to mistune. It operates only on
table blocks (contiguous lines matching table syntax) and applies two fixes:

#### Step 1: Replace pipes inside code spans with a sentinel

Within each table line, find backtick-delimited code spans and replace any `|`
inside them with a sentinel character (`\uf000`, a Unicode Private Use Area
character that will never appear in real content). This makes mistune's cell
splitter ignore these pipes during table parsing.

The `codespan()` renderer method then restores the sentinel back to `|` before
rendering, so the final output is correct.

Why not `\|`? CommonMark treats everything inside code spans as literal —
backslash escapes don't work in code spans. Using `\|` would render as
`<code>a\|b</code>` with a visible backslash. The sentinel approach avoids this
by keeping the replacement invisible to the inline parser.

Algorithm:

1. Scan the line character by character.
2. When a backtick run is found (single, double, or triple), look for the
   matching closing backtick run.
3. Within the matched code span, replace `|` with the sentinel `\uf000`.
4. If no closing backtick run is found, leave the opening backticks as-is
   (unmatched backticks should not swallow subsequent pipes).

This is similar to the existing `_remove_code_spans()` logic, adapted to replace
rather than remove.

#### Step 2: Normalize row column counts

After pipe escaping, count the expected column count from the separator line.
For the header row and each data row:

- **Too few cells** — pad with empty cells at the end.
- **Too many cells** — drop trailing cells.

This ensures every row matches the separator's column count, preventing mistune
from rejecting the table. Both header and data rows must be normalized — mistune
requires `len(headers) == len(aligns)` and `len(cells) == len(aligns)`, and
rejects the entire table if either mismatches.

Algorithm:

1. Identify table blocks: a header line with `|`, followed immediately by a
   separator line (`|---|---|` pattern), followed by zero or more data lines
   with `|`. Both pipe-delimited tables (`| A | B |`) and non-pipe tables
   (`A | B`) are handled.
2. Count columns from the separator line.
3. For the header row and each data row, split on `|` (respecting the sentinel
   from Step 1), pad or truncate to match, and rejoin.
4. Non-table lines pass through unchanged.

### Scope and placement

`_prepare_tables()` is a private function in `airut/markdown.py`, called by
`markdown_to_html()` before passing the text to the mistune instance. It does
not modify non-table content.

## Post-render processing

After mistune renders the full document, apply a single post-processing step:

1. **Strip trailing `<br>`** — if the rendered output ends with `<br>` (with
   optional trailing `\n`), remove it. This matches the current behavior where
   the final paragraph/heading does not get a trailing line break.

## Module interface

The public API remains unchanged:

```python
def markdown_to_html(text: str) -> str:
    """Convert markdown text to HTML for email."""
```

Internally, the function pre-processes table blocks, then passes the result to a
`mistune.Markdown` instance configured with `EmailRenderer` and the `table`
plugin, and post-processes the output.

### Module-level instance

Create the mistune `Markdown` instance at module level for reuse:

```python
_email_md = mistune.create_markdown(
    renderer=EmailRenderer(),
    plugins=["table"],
)


def markdown_to_html(text: str) -> str:
    if not text:
        return ""
    prepared = _prepare_tables(text)
    result = _email_md(prepared)
    # Strip trailing whitespace/newlines and trailing <br>
    result = result.rstrip("\n")
    if result.endswith("<br>"):
        result = result[:-4]
    return result
```

## Removed internal functions

The following private functions are removed entirely (their logic is handled by
mistune's parser):

- `_convert_line()` — replaced by mistune block/inline dispatch
- `_convert_inline()` — replaced by mistune inline token rendering
- `_join_paragraph()` — replaced by mistune paragraph + softbreak handling
- `_render_header()` — replaced by `EmailRenderer.heading()`
- `_is_table_line()` — replaced by mistune table plugin parsing
- `_is_separator_line()` — replaced by mistune table plugin parsing
- `_split_table_cells()` — replaced by mistune table plugin parsing
- `_render_table()` — replaced by `EmailRenderer.table*()` methods
- `_get_list_type()` — replaced by mistune list parsing
- `_render_list()` — replaced by `EmailRenderer.list()` / `list_item()`
- `_is_blockquote_line()` — replaced by mistune blockquote parsing
- `_strip_blockquote_marker()` — replaced by mistune blockquote parsing
- `_render_blockquote()` — replaced by `EmailRenderer.block_quote()`
- `_remove_code_spans()` — replaced by mistune inline code parsing

### New internal function

- `_prepare_tables()` — pre-processes table blocks to escape pipes in code spans
  and normalize column counts (see "Table pre-processing" section)

## Known behavioral differences

Migrating from a custom parser to mistune will produce some output differences.
These are intentional improvements or acceptable trade-offs.

### Acceptable differences

1. **Whitespace in output** — mistune may produce slightly different whitespace
   between block elements (e.g. `\n` between list items). The `EmailRenderer`
   methods control this, but minor whitespace differences are acceptable as they
   don't affect email rendering.

2. **Edge case parsing** — mistune follows CommonMark more strictly. Some inputs
   that the current parser handles loosely (e.g. malformed tables, ambiguous
   list markers) may parse differently. This is an improvement.

3. **Paragraph wrapping** — mistune wraps paragraph content through the
   `paragraph()` method. Our renderer appends `<br>\n` instead of wrapping in
   `<p>`. The visual result is equivalent.

4. **Backslash at end of last line** — CommonMark says a trailing `\` on the
   last line of a paragraph is a literal backslash. The current implementation
   preserves this. mistune also preserves this (no `linebreak()` call for
   trailing `\`).

5. **Multiple blank lines** — the current implementation emits one `<br>` per
   blank line, producing `<br>\n<br>\n` for two consecutive blank lines. mistune
   collapses multiple blank lines into a single `blank_line()` call. This is
   acceptable — excessive blank lines in rendered email are not meaningful.

6. **Indented code blocks** — lines with 4+ leading spaces are treated as
   regular text by the current parser. mistune follows CommonMark and treats
   them as indented code blocks (`<pre><code>...</code></pre>`). This is correct
   CommonMark behavior and an improvement.

### Differences requiring test updates

The following differences are expected and require updating the test assertions
to match the new (correct) behavior:

1. **Multiple consecutive blank lines** — current: each blank line produces a
   separate `<br>`. New: mistune may collapse consecutive blank lines. Tests
   asserting exact `<br>` counts for multiple blank lines will need updating.

2. **Table cell pipe handling** — mistune's table plugin does not handle pipes
   inside backtick code spans within table cells (it treats them as cell
   separators). The `_prepare_tables()` pre-processing step escapes these pipes
   before they reach mistune (see "Table pre-processing" section).

3. **Unclosed code blocks** — current: renders content as `<pre>`. mistune: also
   renders as code block but may include a trailing newline in content. The
   `block_code()` method strips trailing `\n` to match.

4. **Hard break tag format** — current: `<br>`. mistune HTMLRenderer default:
   `<br />\n`. Our `linebreak()` override produces `<br>` to match current
   output.

5. **Loose lists (blank lines between items)** — the current implementation
   treats list items separated by blank lines as separate lists (e.g.
   `1. First\n\n2. Second` becomes two `<ol>` elements with `start` attributes).
   mistune follows CommonMark and treats them as a single "loose" list where
   each item's content is wrapped in `paragraph()`. Tests like
   `test_ordered_lists_separated_by_blank_line` will need updating.

6. **Blockquote lazy continuation** — the current implementation ends a
   blockquote when a non-`>` line is encountered. CommonMark allows "lazy
   continuation" where non-`>` lines continue the blockquote's paragraph
   content. For `> Quoted\nAfter text`, the current output is two separate
   blocks; mistune produces a single blockquote containing both lines. Tests
   like `test_blockquote_followed_by_paragraph` will need updating to match
   CommonMark behavior.

## Test migration strategy

The existing test suite (`tests/test_markdown.py`, ~1450 lines) is the primary
validation tool for this migration. The migration follows a structured approach:

### Phase 1: Preserve integration tests

Tests in these classes test `markdown_to_html()` end-to-end and should be
preserved with minimal changes:

- `TestMarkdownToHtml` — basic conversion tests
- `TestParagraphs` — CommonMark paragraph semantics
- `TestHardLineBreaks` — hard/soft break handling
- `TestHeaders` — header level to inline style mapping
- `TestBoldAndItalic` — inline emphasis/strong
- `TestInlineCode` — inline code spans
- `TestCodeBlocks` — fenced code blocks
- `TestLinks` — link conversion
- `TestTables` — table rendering (most tests)
- `TestLists` — list rendering
- `TestHtmlEscaping` — XSS prevention
- `TestComplexContent` — full document rendering
- `TestBlockquotes` — blockquote rendering

**Approach**: Run the existing test suite against the new implementation. For
each failure, evaluate whether the difference is:

- **A bug in the old implementation** — update the test to match correct
  CommonMark behavior.
- **An acceptable rendering difference** — update the test assertion.
- **A regression** — fix the renderer.

### Phase 2: Remove internal function tests

Tests for removed internal functions are deleted entirely:

- `TestRemoveCodeSpans` — tests `_remove_code_spans()` (removed)
- `TestSplitTableCells` — tests `_split_table_cells()` (removed)
- Parts of `TestHelperFunctions` testing removed functions: `_convert_line()`,
  `_convert_inline()`, `_is_table_line()`, `_is_separator_line()`,
  `_render_table()`, `_get_list_type()`, `_render_list()`, `_join_paragraph()`,
  `_is_blockquote_line()`, `_strip_blockquote_marker()`, `_render_blockquote()`

The behavior these tests validated is still covered by the integration tests in
Phase 1 (which test `markdown_to_html()` with the same inputs).

### Phase 3: Add new tests

Add tests for new and changed behavior:

- **`_prepare_tables()` unit tests** — test pipe escaping in code spans (single,
  double, triple backticks), unmatched backtick handling, column count
  normalization (padding short rows, truncating long rows), and pass-through of
  non-table content
- **Robustness tests** — malformed markdown inputs that should degrade
  gracefully: unclosed formatting, broken links, mixed broken structures,
  mismatched table columns (verifying pre-processing fixes them)
- **EmailRenderer method-level tests** — test individual renderer methods
  directly (e.g. `renderer.heading("Title", 1)` returns
  `<strong><u>Title</u></strong><br>\n`)
- **CommonMark edge cases** that the old parser didn't handle (these now work
  correctly for free)

## Robustness to malformed markdown

LLMs may produce imperfect markdown. mistune handles this gracefully in all
cases — it never throws exceptions and never refuses output. Tested behavior:

| Input category                  | Behavior                                       |
| ------------------------------- | ---------------------------------------------- |
| Unclosed inline formatting      | Literal pass-through (e.g. `**` as text)       |
| Unclosed fenced code block      | Treats rest of document as code content        |
| Malformed links                 | Literal pass-through                           |
| Mismatched bold/italic          | Best-effort partial formatting                 |
| Null bytes / control characters | Stripped or passed through                     |
| 10,000+ character lines         | Processed in \<200ms                           |
| 1000 unclosed delimiters        | Processed in \<200ms, no backtracking          |
| Deeply nested structures        | Rendered (quotes cap around 6 levels deep)     |
| Mixed broken structures         | Each block degrades independently              |
| Tables with column mismatches   | **Handled by `_prepare_tables()` — see above** |

The only structural failure mode that required mitigation was tables (column
count mismatches and pipes in code spans). The `_prepare_tables()` pre-processor
resolves this. All other malformed input degrades gracefully to literal text
within paragraphs.

### Collapse of multiple blank lines

mistune collapses consecutive blank lines into fewer `blank_line()` calls than
the current implementation. If preserving multiple `<br>` tags for consecutive
blank lines is important for email formatting, a post-processing step could
count blank lines in the input and insert additional `<br>` tags after
rendering. However, this is likely not worth the complexity — collapsing blank
lines is standard CommonMark behavior.

## Dependency management

Add `mistune>=3.2,<4` to `pyproject.toml` under `[project.dependencies]`.

mistune v3 has been stable since 2023. The `<4` upper bound protects against
breaking API changes while allowing minor/patch updates.

## Implementation plan

1. Add `mistune>=3.2,<4` to `pyproject.toml`
2. Write `_prepare_tables()` pre-processing function with unit tests
3. Write `EmailRenderer(HTMLRenderer)` in `airut/markdown.py`
4. Replace `markdown_to_html()` internals: pre-process → mistune → post-process
5. Delete all removed internal functions
6. Update test suite per migration strategy
7. Run `uv run scripts/ci.py --fix` — verify 100% coverage
8. Update `CLAUDE.md` supported syntax list if the supported feature set changes
