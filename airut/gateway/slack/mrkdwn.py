# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""CommonMark to Slack ``mrkdwn`` conversion using mistune.

Claude emits standard Markdown.  Slack's native ``mrkdwn`` syntax differs
from CommonMark (``*bold*`` instead of ``**bold**``, ``<url|text>`` links,
``•`` bullets, no headings).  Rather than rely on Slack's server-side
``markdown``-block translation — historically a source of bugs around bare
URLs, adjacent emphasis, and headings — this module performs an explicit,
source-of-truth conversion.

``SlackMrkdwnRenderer`` subclasses :class:`mistune.BaseRenderer` and mirrors
the structure of the ``EmailRenderer`` in :mod:`airut.markdown`: one render
method per token type, grouped into inline and block sections.  Because the
output is ``mrkdwn`` (not HTML), it uses mistune's token-dict renderer
interface, which also gives correct ordered-list numbering and nested-list
indentation via per-item leading widths.

Mapping rules:

==========================  =========================================
Markdown                    mrkdwn
==========================  =========================================
``**bold**``                ``*bold*``
``*italic*`` / ``_italic_`` ``_italic_``
``~~strike~~``              ``~strike~``
``# H1`` … ``###### H6``    ``*text*`` on its own line (no headings)
``[text](url)``             ``<url|text>``
bare URL                    ``<url>``
`` `code` ``                `` `code` `` (unchanged)
fenced ```` ```lang ````    ```` ``` ```` (language hint dropped)
unordered list              ``• item``, nested with leading spaces
ordered list                ``n. item``
``> quote``                 ``> quote`` (unchanged)
Markdown table              aligned fenced code block
``---`` / ``***`` / ``___`` ``———`` (Unicode em-dash line)
``<``, ``>``, ``&``         escaped to ``&lt;`` / ``&gt;`` / ``&amp;``
``- [ ]`` / ``- [x]``       ``• ☐ …`` / ``• ☑ …``
==========================  =========================================

Escaping of the literal ``<``, ``>``, and ``&`` characters that ``mrkdwn``
reserves happens as a final pass on text nodes only.  Link URLs, code spans,
and code blocks pass through unescaped so that the ``<…>`` link syntax (and
the ``<@U…>`` mention syntax produced by later outbound rewriting) survives.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import Any, cast

import mistune
from mistune.core import BlockState


#: Unordered-list bullet.
_BULLET = "•"  # •

#: Task-list checkbox glyphs.
_UNCHECKED = "☐"  # ☐
_CHECKED = "☑"  # ☑

#: Em-dash line used for thematic breaks.
_EM_DASH_LINE = "———"  # ———

Token = dict[str, Any]


def _escape(text: str) -> str:
    """Escape the three characters reserved by Slack ``mrkdwn``.

    ``&`` must be escaped first so the ``&`` introduced by the ``<`` and
    ``>`` replacements is not double-escaped.

    Args:
        text: Literal text node content.

    Returns:
        Text with ``&``, ``<``, ``>`` replaced by their entities.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SlackMrkdwnRenderer(mistune.BaseRenderer):
    """Render mistune tokens as Slack ``mrkdwn``."""

    NAME = "slack_mrkdwn"

    def render_children(self, token: Token, state: BlockState) -> str:
        return self.render_tokens(token["children"], state)

    # -- Inline tokens --

    def text(self, token: Token, state: BlockState) -> str:
        return _escape(cast(str, token["raw"]))

    def emphasis(self, token: Token, state: BlockState) -> str:
        return "_" + self.render_children(token, state) + "_"

    def strong(self, token: Token, state: BlockState) -> str:
        return "*" + self.render_children(token, state) + "*"

    def strikethrough(self, token: Token, state: BlockState) -> str:
        return "~" + self.render_children(token, state) + "~"

    def codespan(self, token: Token, state: BlockState) -> str:
        return "`" + cast(str, token["raw"]) + "`"

    def link(self, token: Token, state: BlockState) -> str:
        url = cast(str, token["attrs"]["url"])
        text = self.render_children(token, state)
        if not text or text == _escape(url):
            return "<" + url + ">"
        return "<" + url + "|" + text + ">"

    def image(self, token: Token, state: BlockState) -> str:
        # mrkdwn has no inline images; render the alt text as a link.
        return self.link(token, state)

    def linebreak(self, token: Token, state: BlockState) -> str:
        return "\n"

    def softbreak(self, token: Token, state: BlockState) -> str:
        return "\n"

    def inline_html(self, token: Token, state: BlockState) -> str:
        return _escape(cast(str, token["raw"]))

    # -- Block tokens --

    def paragraph(self, token: Token, state: BlockState) -> str:
        return self.render_children(token, state) + "\n\n"

    def heading(self, token: Token, state: BlockState) -> str:
        # Slack has no headings; bold the text on its own line.
        return "*" + self.render_children(token, state) + "*\n\n"

    def blank_line(self, token: Token, state: BlockState) -> str:
        return ""

    def thematic_break(self, token: Token, state: BlockState) -> str:
        return _EM_DASH_LINE + "\n\n"

    def block_text(self, token: Token, state: BlockState) -> str:
        return self.render_children(token, state) + "\n"

    def block_code(self, token: Token, state: BlockState) -> str:
        # Drop the language hint; mrkdwn code fences are unadorned.
        code = cast(str, token["raw"])
        if code and not code.endswith("\n"):
            code += "\n"
        return "```\n" + code + "```\n\n"

    def block_quote(self, token: Token, state: BlockState) -> str:
        text = self.render_children(token, state).rstrip("\n")
        lines = ("> " + line if line else ">" for line in text.split("\n"))
        return "\n".join(lines) + "\n\n"

    def block_html(self, token: Token, state: BlockState) -> str:
        return _escape(cast(str, token["raw"])) + "\n\n"

    def block_error(self, token: Token, state: BlockState) -> str:
        return ""

    def list(self, token: Token, state: BlockState) -> str:
        if token["attrs"]["ordered"]:
            children = self._render_ordered(token, state)
        else:
            children = self._render_unordered(token, state)
        text = "".join(children)
        parent = token.get("parent")
        if parent:
            if parent["tight"]:
                return text
            return text + "\n"
        return text.rstrip("\n") + "\n\n"

    def _render_item(
        self, leading: str, tight: bool, item: Token, state: BlockState
    ) -> str:
        """Render a single list item, indenting wrapped/nested lines.

        Args:
            leading: Bullet or number prefix for the item's first line.
            tight: Whether the parent list is tight (no blank lines).
            item: The ``list_item`` / ``task_list_item`` token.
            state: Current block state.

        Returns:
            The item text, leading-prefixed and indented.
        """
        parent = {"leading": leading, "tight": tight}
        text = ""
        for child in item["children"]:
            if child["type"] == "list":
                child["parent"] = parent
            elif child["type"] == "blank_line":
                continue
            text += self.render_token(child, state)

        lines = text.splitlines()
        out = (lines[0] if lines else "") + "\n"
        prefix = " " * len(leading)
        for line in lines[1:]:
            out += (prefix + line + "\n") if line else "\n"
        return leading + out

    def _render_ordered(self, token: Token, state: BlockState) -> Iterable[str]:
        start = cast(int, token["attrs"].get("start", 1))
        rendered: list[str] = []
        for item in token["children"]:
            leading = f"{start}. "
            rendered.append(
                self._render_item(leading, token["tight"], item, state)
            )
            start += 1
        return rendered

    def _render_unordered(
        self, token: Token, state: BlockState
    ) -> Iterable[str]:
        rendered: list[str] = []
        for item in token["children"]:
            if item["type"] == "task_list_item":
                box = _CHECKED if item["attrs"]["checked"] else _UNCHECKED
                leading = f"{_BULLET} {box} "
            else:
                leading = f"{_BULLET} "
            rendered.append(
                self._render_item(leading, token["tight"], item, state)
            )
        return rendered


_slack_md = mistune.create_markdown(
    renderer=SlackMrkdwnRenderer(),
    plugins=["strikethrough", "url", "task_lists"],
)


def render_mrkdwn(text: str) -> str:
    """Convert Markdown text to Slack ``mrkdwn``.

    Tables are pre-processed into aligned fenced code blocks (Slack does
    not render Markdown tables), then the whole document is parsed by
    mistune and rendered by :class:`SlackMrkdwnRenderer`.

    Args:
        text: Raw Markdown response text.

    Returns:
        ``mrkdwn`` string suitable for the Slack ``text`` parameter.
    """
    if not text:
        return ""
    prepared = _convert_tables(text)
    result = cast(str, _slack_md(prepared))
    return result.rstrip()


# -- Table conversion (moved from the former ``sanitize`` module) --

#: Regex matching Markdown table blocks (header row + separator + data).
_TABLE_PATTERN = re.compile(
    r"^(\|[^\n]+\|\n)"  # header row
    r"(\|[-| :]+\|\n)"  # separator row
    r"((?:\|[^\n]+\|\n?)*)",  # data rows
    re.MULTILINE,
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
        for row in parsed_rows:
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
    for row in parsed_rows:
        cells = []
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
    """Convert Markdown tables to aligned fenced code blocks.

    Slack does not render Markdown tables, so each table is column-aligned
    and wrapped in a code fence.  The fenced block is then parsed by
    mistune as ordinary block code and emitted verbatim.

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
