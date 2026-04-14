# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Markdown to HTML conversion for email content using mistune.

This module provides markdown to HTML conversion for email service emails,
using mistune v3 as the CommonMark parser with a custom ``EmailRenderer``
that produces email-friendly HTML output.

The ``EmailRenderer`` subclasses ``mistune.HTMLRenderer`` and overrides
every render method to produce output suitable for email clients:
no ``<p>`` tags (replaced with ``<br>``), inline styles for tables and
blockquotes, and heading levels mapped to inline formatting.

A ``_prepare_tables()`` pre-processing step handles two mistune table
limitations: pipes inside code spans and column count mismatches.

Supported syntax (CommonMark plus GFM tables):
- Paragraphs: consecutive lines joined (soft breaks), blank lines separate
- Hard line breaks: trailing backslash or two+ trailing spaces
- Headers: # (bold underline), ## (bold italic underline), ### (underline),
  #### (italic underline), ##### (italic), ###### (bold)
- Bold: **text** or __text__
- Italic: *text* or _text_
- Preformatted text: ```code blocks``` and `inline code`
- Links: [text](url)
- Images: rendered as links
- Tables: | header | header | (GFM tables via mistune plugin)
- Unordered lists: - item or * item
- Ordered lists: 1. item (with start attribute support)
- Block quotes: > quoted text (nested with >> or > >)
- Thematic breaks: --- or *** or ___
- Inline/block HTML: escaped (not passed through)
"""

import html
import re
from typing import cast

import mistune
import mistune.plugins.table


_PIPE_SENTINEL = "\uf000"

_TABLE_STYLE = "border:1px solid #ccc;border-collapse:collapse;"
_CELL_STYLE = "border:1px solid #ccc;padding:4px 8px;"

_BLOCKQUOTE_STYLE = (
    "margin:0 0 0 0.8em;border-left:2px solid #ccc;"
    "padding:0 0 0 0.6em;color:#666;"
)


class EmailRenderer(mistune.HTMLRenderer):
    """Render mistune tokens as email-friendly HTML."""

    # -- Inline tokens --

    def text(self, text: str) -> str:
        return mistune.escape(text)

    def emphasis(self, text: str) -> str:
        return "<em>" + text + "</em>"

    def strong(self, text: str) -> str:
        return "<strong>" + text + "</strong>"

    def codespan(self, text: str) -> str:
        return (
            "<code>"
            + mistune.escape(text.replace(_PIPE_SENTINEL, "|"))
            + "</code>"
        )

    def link(self, text: str, url: str, title: str | None = None) -> str:
        return '<a href="' + mistune.escape(url) + '">' + text + "</a>"

    def linebreak(self) -> str:
        return "<br>"

    def softbreak(self) -> str:
        return " "

    def image(self, text: str, url: str, title: str | None = None) -> str:
        return (
            '<a href="'
            + mistune.escape(url)
            + '">'
            + mistune.escape(text or url)
            + "</a>"
        )

    def inline_html(self, html: str) -> str:
        return mistune.escape(html)

    # -- Block tokens --

    def heading(self, text: str, level: int, **attrs: object) -> str:
        if level == 1:
            styled = "<strong><u>" + text + "</u></strong>"
        elif level == 2:
            styled = "<strong><em><u>" + text + "</u></em></strong>"
        elif level == 3:
            styled = "<u>" + text + "</u>"
        elif level == 4:
            styled = "<em><u>" + text + "</u></em>"
        elif level == 5:
            styled = "<em>" + text + "</em>"
        else:
            styled = "<strong>" + text + "</strong>"
        return styled + "<br>\n"

    def paragraph(self, text: str) -> str:
        return text + "<br>\n"

    def blank_line(self) -> str:
        return "<br>\n"

    def block_code(self, code: str, info: str | None = None) -> str:
        return "<pre>" + html.escape(code.rstrip("\n")) + "</pre>\n"

    def block_quote(self, text: str) -> str:
        inner = text.rstrip("\n")
        if inner.endswith("<br>"):
            inner = inner[:-4]
        return (
            '<blockquote style="'
            + _BLOCKQUOTE_STYLE
            + '">'
            + inner
            + "</blockquote>\n"
        )

    def list(self, text: str, ordered: bool, **attrs: object) -> str:
        tag = "ol" if ordered else "ul"
        start = attrs.get("start")
        start_attr = (
            f' start="{start}"' if start is not None and start != 1 else ""
        )
        return f"<{tag}{start_attr}>{text}</{tag}>\n"

    def list_item(self, text: str) -> str:
        inner = text.strip()
        if inner.endswith("<br>"):
            inner = inner[:-4]
        return "<li>" + inner + "</li>"

    def thematic_break(self) -> str:
        return "<hr>\n"

    def block_html(self, html: str) -> str:
        return mistune.escape(html)

    def block_text(self, text: str) -> str:
        return text

    def block_error(self, text: str) -> str:
        return ""

    # -- Table tokens (via table plugin) --

    def table(self, text: str) -> str:
        return '<table style="' + _TABLE_STYLE + '">' + text + "</table><br>\n"

    def table_head(self, text: str) -> str:
        return "<tr>" + text + "</tr>"

    def table_body(self, text: str) -> str:
        return text

    def table_row(self, text: str) -> str:
        return "<tr>" + text + "</tr>"

    def table_cell(
        self,
        text: str,
        align: str | None = None,
        head: bool = False,
    ) -> str:
        tag = "th" if head else "td"
        return (
            "<"
            + tag
            + ' style="'
            + _CELL_STYLE
            + '">'
            + text
            + "</"
            + tag
            + ">"
        )


_email_md = mistune.create_markdown(
    renderer=EmailRenderer(),
    plugins=["table", mistune.plugins.table.table_in_quote],
)


def markdown_to_html(text: str) -> str:
    """Convert markdown text to HTML for email.

    Converts markdown syntax to HTML using mistune with a custom
    EmailRenderer that produces email-friendly output. Table blocks
    are pre-processed to handle pipes in code spans and column count
    mismatches.

    Args:
        text: Markdown-formatted text.

    Returns:
        HTML string with converted markdown.
    """
    if not text:
        return ""
    prepared = _prepare_tables(text)
    result = cast(str, _email_md(prepared))
    # Strip trailing whitespace/newlines and trailing <br>
    result = result.rstrip("\n")
    if result.endswith("<br>"):
        result = result[:-4]
    return result


# -- Table pre-processing --

# Pattern to identify a table separator line: only |, -, :, and spaces
_SEPARATOR_RE = re.compile(r"^[ ]{0,3}[|]?[ :]*-[-: |]*$")


def _prepare_tables(text: str) -> str:
    """Pre-process table blocks before passing to mistune.

    Applies two fixes to table blocks:

    1. Replaces pipes inside code spans with a sentinel character so
       mistune's cell splitter doesn't treat them as column separators.
    2. Normalizes row column counts so every row matches the separator's
       column count (padding short rows, truncating long rows).

    Non-table content passes through unchanged.

    Args:
        text: Raw markdown text.

    Returns:
        Text with table blocks pre-processed.
    """
    lines = text.split("\n")
    result: list[str] = []
    i = 0

    while i < len(lines):
        # Look for table start: a line with pipes, followed immediately
        # by a separator line
        if (
            i + 1 < len(lines)
            and "|" in lines[i]
            and _is_sep_line(lines[i + 1])
        ):
            # Found a table block — collect all lines
            table_start = i
            sep_idx = i + 1

            # Count columns from separator line
            sep_line = lines[sep_idx]
            n_cols = _count_columns(sep_line)

            # Process header line
            result.append(
                _normalize_table_row(
                    _escape_code_pipes(lines[table_start]), n_cols
                )
            )
            # Pass separator through as-is
            result.append(lines[sep_idx])
            i = sep_idx + 1

            # Process data rows
            while i < len(lines) and "|" in lines[i]:
                if _is_sep_line(lines[i]):
                    # Another separator — end of table block
                    break
                result.append(
                    _normalize_table_row(_escape_code_pipes(lines[i]), n_cols)
                )
                i += 1
        else:
            result.append(lines[i])
            i += 1

    return "\n".join(result)


def _is_sep_line(line: str) -> bool:
    """Check if a line is a table separator (e.g. |---|---|)."""
    stripped = line.strip()
    if not stripped or "-" not in stripped:
        return False
    return bool(_SEPARATOR_RE.match(stripped))


def _escape_code_pipes(line: str) -> str:
    r"""Replace | inside backtick code spans with sentinel character.

    Scans the line for backtick-delimited code spans (single, double,
    or triple backticks) and replaces any ``|`` inside them with the
    sentinel ``\uf000``. Unmatched opening backticks are left as-is.

    Args:
        line: A single table row string.

    Returns:
        Line with pipes inside code spans replaced by sentinel.
    """
    result: list[str] = []
    i = 0
    while i < len(line):
        if line[i] == "`":
            # Determine backtick run length
            tick_start = i
            while i < len(line) and line[i] == "`":
                i += 1
            opener = line[tick_start:i]
            # Look for matching closing backtick run
            close_pos = line.find(opener, i)
            if close_pos != -1:
                # Replace pipes in the code span content
                content = line[i:close_pos]
                result.append(opener)
                result.append(content.replace("|", _PIPE_SENTINEL))
                result.append(opener)
                i = close_pos + len(opener)
            else:
                # No closing backticks — keep as literal text
                result.append(opener)
        else:
            result.append(line[i])
            i += 1
    return "".join(result)


def _count_columns(sep_line: str) -> int:
    """Count the number of columns in a table separator line."""
    stripped = sep_line.strip()
    # Remove leading/trailing pipes
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return len(stripped.split("|"))


def _normalize_table_row(line: str, n_cols: int) -> str:
    """Normalize a table row to have exactly n_cols columns.

    Pads short rows with empty cells, truncates long rows.

    Args:
        line: A table row string (already pipe-escaped).
        n_cols: Expected number of columns.

    Returns:
        Normalized table row.
    """
    stripped = line.strip()
    has_leading = stripped.startswith("|")
    has_trailing = stripped.endswith("|")

    # Strip outer pipes for splitting
    inner = stripped
    if has_leading:
        inner = inner[1:]
    if has_trailing:
        inner = inner[:-1]

    cells = inner.split("|")

    if len(cells) == n_cols:
        return line  # No change needed

    # Pad or truncate
    if len(cells) < n_cols:
        cells.extend(["  "] * (n_cols - len(cells)))
    else:
        cells = cells[:n_cols]

    # Reconstruct with same pipe style
    joined = "|".join(cells)
    if has_leading:
        joined = "|" + joined
    if has_trailing:
        joined = joined + "|"
    return joined
