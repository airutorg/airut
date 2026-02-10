# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Lightweight HTML to text conversion for email content.

Converts HTML email bodies to plain text with markdown-like formatting,
suitable for feeding to an LLM. Handles common HTML elements produced by
email clients like Outlook.

Supported conversions:
- Bold (<b>, <strong>) → **text**
- Italic (<i>, <em>) → *text*
- Links (<a href>) → [text](url)
- Headings (<h1>-<h6>) → # text
- Code (<code>) → `text`
- Preformatted (<pre>) → ```text```
- Unordered lists (<ul>/<li>) → - item
- Ordered lists (<ol>/<li>) → 1. item
- Tables (<table>/<tr>/<td>) → | cell | cell |
- Paragraphs/breaks (<p>, <br>) → newlines
- HTML entities → decoded characters
"""

import re
from html.parser import HTMLParser


def html_to_text(html_content: str) -> str:
    """Convert HTML to plain text with markdown-like formatting.

    Args:
        html_content: HTML string to convert.

    Returns:
        Plain text with markdown formatting.
    """
    if not html_content:
        return ""

    parser = _HTMLToTextParser()
    parser.feed(html_content)
    return parser.get_text()


class _HTMLToTextParser(HTMLParser):
    """HTML parser that produces markdown-like plain text."""

    def __init__(self) -> None:
        super().__init__()
        self._output: list[str] = []
        self._skip_content = False

        # Inline formatting state
        self._in_bold = False
        self._in_italic = False
        self._in_code = False
        self._in_pre = False
        self._pre_content: list[str] = []
        self._link_href: str | None = None

        # List state
        self._list_stack: list[str] = []  # "ul" or "ol"
        self._ol_counters: list[int] = []
        self._in_li = False

        # Table state
        self._in_table = False
        self._table_rows: list[list[str]] = []
        self._current_row: list[str] = []
        self._current_cell: list[str] = []
        self._in_cell = False
        self._is_header_row = False
        self._table_has_header = False

        # Heading state
        self._heading_level = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        """Handle opening HTML tags."""
        tag = tag.lower()
        attr_dict = dict(attrs)

        if tag in ("script", "style"):
            self._skip_content = True
            return

        if tag in ("b", "strong"):
            self._in_bold = True
            self._output.append("**")
        elif tag in ("i", "em"):
            self._in_italic = True
            self._output.append("*")
        elif tag == "code" and not self._in_pre:
            self._in_code = True
            self._output.append("`")
        elif tag == "pre":
            self._in_pre = True
            self._pre_content = []
            self._ensure_newline()
        elif tag == "a":
            self._link_href = attr_dict.get("href")
            if self._link_href:
                self._output.append("[")
        elif tag == "br":
            self._handle_newline()
        elif tag == "p":
            self._ensure_block_break()
        elif tag in ("div", "blockquote", "section", "article"):
            self._ensure_newline()
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._heading_level = int(tag[1])
            self._ensure_block_break()
            self._output.append("#" * self._heading_level + " ")
        elif tag == "ul":
            self._ensure_newline()
            self._list_stack.append("ul")
        elif tag == "ol":
            self._ensure_newline()
            self._list_stack.append("ol")
            self._ol_counters.append(1)
        elif tag == "li":
            self._in_li = True
            self._ensure_newline()
            if self._list_stack:
                if self._list_stack[-1] == "ul":
                    self._output.append("- ")
                else:
                    counter = self._ol_counters[-1] if self._ol_counters else 1
                    self._output.append(f"{counter}. ")
        elif tag == "table":
            self._in_table = True
            self._table_rows = []
            self._table_has_header = False
            self._ensure_newline()
        elif tag == "tr":
            self._current_row = []
            self._is_header_row = False
        elif tag in ("td", "th"):
            self._in_cell = True
            self._current_cell = []
            if tag == "th":
                self._is_header_row = True
        elif tag == "hr":
            self._ensure_newline()
            self._output.append("---")
            self._handle_newline()

    def handle_endtag(self, tag: str) -> None:
        """Handle closing HTML tags."""
        tag = tag.lower()

        if tag in ("script", "style"):
            self._skip_content = False
            return

        if tag in ("b", "strong"):
            self._in_bold = False
            self._output.append("**")
        elif tag in ("i", "em"):
            self._in_italic = False
            self._output.append("*")
        elif tag == "code" and not self._in_pre:
            self._in_code = False
            self._output.append("`")
        elif tag == "pre":
            self._in_pre = False
            content = "".join(self._pre_content)
            self._output.append("```\n")
            self._output.append(content.strip("\n"))
            self._output.append("\n```")
            self._handle_newline()
        elif tag == "a":
            if self._link_href:
                self._output.append(f"]({self._link_href})")
                self._link_href = None
        elif tag == "p":
            self._ensure_block_break()
        elif tag in ("div", "blockquote", "section", "article"):
            self._ensure_newline()
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._heading_level = 0
            self._handle_newline()
        elif tag == "ul":
            if self._list_stack and self._list_stack[-1] == "ul":
                self._list_stack.pop()
            self._ensure_newline()
        elif tag == "ol":
            if self._list_stack and self._list_stack[-1] == "ol":
                self._list_stack.pop()
            if self._ol_counters:
                self._ol_counters.pop()
            self._ensure_newline()
        elif tag == "li":
            self._in_li = False
            if self._list_stack and self._list_stack[-1] == "ol":
                if self._ol_counters:
                    self._ol_counters[-1] += 1
            self._handle_newline()
        elif tag in ("td", "th"):
            self._in_cell = False
            self._current_row.append("".join(self._current_cell).strip())
            self._current_cell = []
        elif tag == "tr":
            if self._current_row:
                self._table_rows.append(self._current_row)
                if self._is_header_row:
                    self._table_has_header = True
            self._current_row = []
        elif tag == "table":
            self._flush_table()
            self._in_table = False

    def handle_data(self, data: str) -> None:
        """Handle text content."""
        if self._skip_content:
            return

        if self._in_pre:
            self._pre_content.append(data)
            return

        if self._in_cell:
            self._current_cell.append(data)
            return

        # Collapse whitespace for non-preformatted text
        if not self._in_code:
            data = re.sub(r"[ \t]+", " ", data)
            # Strip leading whitespace if output is at line start
            if self._at_line_start():
                data = data.lstrip()

        if data:
            self._output.append(data)

    def get_text(self) -> str:
        """Return the accumulated plain text output.

        Returns:
            Converted plain text.
        """
        text = "".join(self._output)
        # Normalize newlines: collapse 3+ into 2
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _handle_newline(self) -> None:
        """Add a newline, avoiding duplicates."""
        if self._output and not self._output[-1].endswith("\n"):
            self._output.append("\n")

    def _ensure_newline(self) -> None:
        """Ensure output ends with at least one newline."""
        if not self._output:
            return
        text = "".join(self._output)
        if text and not text.endswith("\n"):
            self._output.append("\n")

    def _ensure_block_break(self) -> None:
        """Ensure a blank line for block-level elements."""
        if not self._output:
            return
        text = "".join(self._output)
        if text.endswith("\n\n"):
            return
        if text.endswith("\n"):
            self._output.append("\n")
        elif text:
            self._output.append("\n\n")

    def _at_line_start(self) -> bool:
        """Check if output cursor is at the start of a line."""
        if not self._output:
            return True
        text = "".join(self._output)
        return text == "" or text.endswith("\n")

    def _flush_table(self) -> None:
        """Render accumulated table rows as markdown table."""
        if not self._table_rows:
            return

        # Determine column count from widest row
        col_count = max(len(row) for row in self._table_rows)

        # Pad rows to uniform width
        for row in self._table_rows:
            while len(row) < col_count:
                row.append("")

        # Render as markdown table
        for i, row in enumerate(self._table_rows):
            line = "| " + " | ".join(row) + " |"
            self._output.append(line)
            self._handle_newline()

            # Add separator after first row if it's a header
            if i == 0 and self._table_has_header:
                sep = "| " + " | ".join("---" for _ in row) + " |"
                self._output.append(sep)
                self._handle_newline()

        self._table_rows = []
