# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack message sanitization.

Converts or strips Markdown features not supported by Slack's
``markdown`` block type: tables, syntax-highlighted code fences,
horizontal rules, and bare URLs.
"""

from __future__ import annotations

import re
import unicodedata


#: Regex matching Markdown table blocks (header row + separator + data).
_TABLE_PATTERN = re.compile(
    r"^(\|[^\n]+\|\n)"  # header row
    r"(\|[-| :]+\|\n)"  # separator row
    r"((?:\|[^\n]+\|\n?)*)",  # data rows
    re.MULTILINE,
)

#: Regex matching fenced code block opening with a language hint.
_CODE_FENCE_LANG_PATTERN = re.compile(r"^```\w+", re.MULTILINE)

#: Regex matching Markdown horizontal rules (``---``, ``***``, ``___``).
_HORIZONTAL_RULE_PATTERN = re.compile(
    r"^[ ]{0,3}(?:[-]{3,}|[*]{3,}|[_]{3,})[ \t]*$", re.MULTILINE
)

#: Regex matching bare URLs that are not already inside a Markdown link.
#: Negative lookbehinds exclude URLs that follow ``](`` (link target) or
#: ``[`` (link text start — simplified, handles ``[url](url)`` form).
_BARE_URL_PATTERN = re.compile(
    r"(?<!\]\()(?<!\[)"  # not preceded by ]( or [
    r"(https?://[^\s)\]>]+)"  # URL: scheme + non-whitespace, not ) ] >
)


def _split_table_row(line: str) -> list[str]:
    """Split a table row into cell contents, respecting inline code spans.

    Pipes inside backtick-delimited code (single or double) are not
    treated as column separators.

    Args:
        line: A single table row string (e.g. ``| A | B |``).

    Returns:
        List of cell content strings (untrimmed).
    """
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]

    cells: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(stripped):
        ch = stripped[i]
        if ch == "`":
            # Determine backtick run length (single ` or double ``)
            tick_start = i
            while i < len(stripped) and stripped[i] == "`":
                i += 1
            opener = stripped[tick_start:i]
            current.append(opener)
            # Scan for matching closing backtick run
            close_pos = stripped.find(opener, i)
            if close_pos != -1:
                current.append(stripped[i:close_pos])
                current.append(opener)
                i = close_pos + len(opener)
            # If no closing backticks, treat them as literal text
        elif ch == "|":
            cells.append("".join(current))
            current = []
            i += 1
        else:
            current.append(ch)
            i += 1
    cells.append("".join(current))
    return cells


def _is_separator_cell(cell: str) -> bool:
    """Check whether a cell is a separator cell (e.g. ``---``, ``:--:``)."""
    stripped = cell.strip()
    return bool(stripped) and all(c in "-:" for c in stripped)


def _cell_display_width(text: str) -> int:
    """Compute the monospace display width of *text*.

    East Asian Wide and Fullwidth characters count as 2 columns,
    combining marks (category ``M``) count as 0, and all other
    characters count as 1.  This matches the column-width model
    used by most terminal emulators.

    Args:
        text: Cell content string.

    Returns:
        Display width in monospace columns.
    """
    width = 0
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("M"):  # combining marks
            continue
        eaw = unicodedata.east_asian_width(ch)
        width += 2 if eaw in ("W", "F") else 1
    return width


def _align_table_columns(table: str) -> str:
    """Pad table cells so all columns have equal width.

    Each cell is padded with trailing spaces so that every row has
    identically-positioned pipe characters, producing a visually aligned
    table suitable for monospace rendering inside a code fence.

    Pipes inside inline code spans (backticks) are ignored during column
    splitting.

    Args:
        table: Raw Markdown table string (header + separator + data rows).

    Returns:
        Table string with uniformly-padded columns.
    """
    trailing_newline = table.endswith("\n")
    lines = table.rstrip("\n").split("\n")

    # Parse every row into cells
    parsed_rows: list[list[str]] = []
    for line in lines:
        cells = _split_table_row(line)
        parsed_rows.append([c.strip() for c in cells])

    # Determine number of columns (max across all rows)
    num_cols = max(len(row) for row in parsed_rows)

    # Pad rows with fewer columns
    for row in parsed_rows:
        while len(row) < num_cols:
            row.append("")

    # Compute max display width per column
    col_widths: list[int] = []
    for col_idx in range(num_cols):
        max_width = 0
        for row_idx, row in enumerate(parsed_rows):
            cell = row[col_idx]
            # Separator cells don't constrain column width (they expand)
            if _is_separator_cell(cell):
                # Minimum width for separator is 3 (---)
                max_width = max(max_width, 3)
            else:
                max_width = max(max_width, _cell_display_width(cell))
        col_widths.append(max_width)

    # Rebuild rows with padding
    aligned_lines: list[str] = []
    for row_idx, row in enumerate(parsed_rows):
        cells: list[str] = []
        for col_idx, cell in enumerate(row):
            width = col_widths[col_idx]
            if _is_separator_cell(cell):
                # Preserve alignment colons
                left_colon = cell.startswith(":")
                right_colon = cell.endswith(":")
                dash_count = (
                    width - (1 if left_colon else 0) - (1 if right_colon else 0)
                )
                sep = (
                    (":" if left_colon else "")
                    + "-" * dash_count
                    + (":" if right_colon else "")
                )
                cells.append(f" {sep} ")
            else:
                # Pad with spaces based on display width, not len()
                pad = width - _cell_display_width(cell)
                cells.append(f" {cell}{' ' * pad} ")
        aligned_lines.append("|" + "|".join(cells) + "|")

    result = "\n".join(aligned_lines)
    if trailing_newline:
        result += "\n"
    return result


def _convert_tables(text: str) -> str:
    """Convert Markdown tables to fenced code blocks.

    Slack's ``markdown`` block does not render Markdown tables, so we
    wrap them in code fences to preserve alignment.  Columns are padded
    to uniform width before wrapping.

    Args:
        text: Markdown text potentially containing tables.

    Returns:
        Text with aligned tables wrapped in code fences.
    """

    def _replace_table(match: re.Match[str]) -> str:
        table_text = match.group(0).rstrip("\n")
        aligned = _align_table_columns(table_text)
        return f"```\n{aligned}\n```"

    return _TABLE_PATTERN.sub(_replace_table, text)


def _strip_code_fence_languages(text: str) -> str:
    """Strip language hints from fenced code block openings.

    Slack's ``markdown`` block renders code fences but does not support
    syntax highlighting.  A fence like ````` ```python ````` renders the
    language tag as visible text.  This function strips the tag, leaving
    a plain ````` ``` ````` fence.

    Args:
        text: Markdown text potentially containing fenced code blocks.

    Returns:
        Text with language hints removed from code fences.
    """
    return _CODE_FENCE_LANG_PATTERN.sub("```", text)


def _convert_horizontal_rules(text: str) -> str:
    """Convert Markdown horizontal rules to a plain-text separator.

    Slack's ``markdown`` block does not render horizontal rules
    (``---``, ``***``, ``___``).  We replace them with a Unicode
    em-dash line that provides a visual break.  Only processes lines
    outside fenced code blocks.

    Args:
        text: Markdown text potentially containing horizontal rules.

    Returns:
        Text with horizontal rules replaced by a plain separator.
    """
    lines = text.split("\n")
    result: list[str] = []
    in_fence = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            result.append(line)
        elif not in_fence and _HORIZONTAL_RULE_PATTERN.match(line):
            result.append("\u2014\u2014\u2014")
        else:
            result.append(line)

    return "\n".join(result)


def _linkify_bare_urls(text: str) -> str:
    """Convert bare URLs to explicit Markdown links.

    Wraps bare ``https://…`` and ``http://…`` URLs in Markdown link
    syntax (``[url](url)``) so that Slack's ``markdown`` block renderer
    treats them as explicit links rather than attempting auto-detection,
    which can produce garbled output when URLs appear adjacent to bold
    or other formatting.

    URLs already inside Markdown links (``[text](url)``) and URLs
    inside fenced code blocks or inline code spans are preserved.

    Args:
        text: Markdown text potentially containing bare URLs.

    Returns:
        Text with bare URLs wrapped in Markdown link syntax.
    """
    lines = text.split("\n")
    result: list[str] = []
    in_fence = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            result.append(line)
        elif in_fence:
            result.append(line)
        else:
            result.append(_linkify_line(line))

    return "\n".join(result)


def _linkify_line(line: str) -> str:
    """Linkify bare URLs in a single line, preserving inline code spans.

    Splits the line on inline code (backtick) boundaries so that URLs
    inside code spans are never touched.

    Args:
        line: A single line of Markdown (not inside a fenced block).

    Returns:
        Line with bare URLs converted to ``[url](url)``.
    """
    # Split on inline code spans to avoid touching URLs inside them.
    # Odd-indexed segments are inside backticks.
    parts = line.split("`")
    for i in range(0, len(parts), 2):  # even indices = outside code
        parts[i] = _BARE_URL_PATTERN.sub(r"[\1](\1)", parts[i])
    return "`".join(parts)


def sanitize_for_slack(text: str) -> str:
    """Apply all Slack-specific Markdown sanitization.

    Converts or strips Markdown features not supported by Slack's
    ``markdown`` block type: tables, syntax-highlighted code fences,
    horizontal rules, and bare URLs.

    Args:
        text: Raw Markdown response text.

    Returns:
        Sanitized text suitable for Slack ``markdown`` blocks.
    """
    text = _convert_tables(text)
    text = _strip_code_fence_languages(text)
    text = _convert_horizontal_rules(text)
    text = _linkify_bare_urls(text)
    return text
