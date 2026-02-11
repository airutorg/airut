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

When strip_quotes=True, handles quoted reply containers from major email
clients:
- Outlook web/mobile: <div id="mail-editor-reference-message-container">
- Outlook desktop: <div id="divRplyFwdMsg">
- Gmail: <div class="gmail_quote">
- Yahoo: <div class="yahoo_quoted">
- Thunderbird/Apple Mail: <blockquote type="cite">
- Thunderbird: <div class="moz-cite-prefix">

Quote blocks followed by non-quote content (inline replies) are rendered
as markdown blockquotes ("> " prefixed lines) so the LLM sees the context
the user replied to. Trailing quote blocks with no reply after them are
replaced with "[quoted text removed]".
"""

import re
from html.parser import HTMLParser


# Element IDs that mark quoted reply containers
_QUOTE_IDS = frozenset(
    {
        "mail-editor-reference-message-container",
        "divrplyfwdmsg",
    }
)

# CSS class names that mark quoted reply containers
_QUOTE_CLASSES = frozenset(
    {
        "gmail_quote",
        "yahoo_quoted",
        "moz-cite-prefix",
    }
)


def html_to_text(
    html_content: str,
    *,
    strip_quotes: bool = False,
) -> str:
    """Convert HTML to plain text with markdown-like formatting.

    Args:
        html_content: HTML string to convert.
        strip_quotes: If True, handle quoted reply containers from known
            email clients. Quote blocks followed by non-quote content
            (inline replies) are rendered as markdown blockquotes.
            Trailing quote blocks are replaced with
            "[quoted text removed]".

    Returns:
        Plain text with markdown formatting.
    """
    if not html_content:
        return ""

    parser = _HTMLToTextParser(strip_quotes=strip_quotes)
    parser.feed(html_content)
    return parser.get_text()


def _is_quote_element(
    tag: str,
    attrs: dict[str, str | None],
) -> bool:
    """Check if a tag/attrs combination is a known quote container."""
    # Check id attribute
    element_id = attrs.get("id")
    if element_id and element_id.lower() in _QUOTE_IDS:
        return True

    # Check class attribute
    class_attr = attrs.get("class")
    if class_attr:
        classes = set(class_attr.lower().split())
        if classes & _QUOTE_CLASSES:
            return True

    # Check <blockquote type="cite"> (Apple Mail, Thunderbird)
    if tag == "blockquote":
        type_attr = attrs.get("type")
        if type_attr and type_attr.lower() == "cite":
            return True

    return False


class _HTMLToTextParser(HTMLParser):
    """HTML parser that produces markdown-like plain text."""

    def __init__(self, *, strip_quotes: bool = False) -> None:
        super().__init__()
        self._output: list[str] = []
        self._skip_content = False
        self._strip_quotes = strip_quotes

        # Quote handling state. We track a stack of quote containers
        # with nesting depth to match the correct closing tag.
        self._quote_tags: list[str] = []
        self._quote_nesting: list[int] = []

        # Sub-parser that converts quote content to text. When inside
        # a quote, tags and data are forwarded to this parser instead
        # of the main output.
        self._quote_parser: _HTMLToTextParser | None = None

        # Buffered converted text from the most recently closed quote
        # block. If non-quote content follows, this is flushed as
        # markdown "> " lines. Otherwise get_text() replaces it with
        # "[quoted text removed]".
        self._pending_quote: str | None = None

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

    @property
    def _in_quote(self) -> bool:
        return len(self._quote_tags) > 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        """Handle opening HTML tags."""
        tag = tag.lower()
        attr_dict = dict(attrs)

        # Check for quote containers before anything else
        if self._strip_quotes and _is_quote_element(tag, attr_dict):
            if not self._in_quote:
                # Starting a new top-level quote block. Create a
                # sub-parser to convert the quote content. If there's
                # a pending quote from a previous block, merge it into
                # the new sub-parser (consecutive quote containers
                # like Thunderbird's moz-cite-prefix + blockquote
                # should be treated as one logical quote).
                self._quote_parser = _HTMLToTextParser()
                if self._pending_quote:
                    self._quote_parser._output.append(self._pending_quote)
                    self._quote_parser._output.append("\n")
                    self._pending_quote = None
            self._quote_tags.append(tag)
            self._quote_nesting.append(0)
            return

        if self._in_quote:
            # Track nested opens of the same tag as the quote container
            # so we can match the correct closing tag.
            if tag == self._quote_tags[-1]:
                self._quote_nesting[-1] += 1
            # Forward to sub-parser for content conversion
            if self._quote_parser is not None:
                self._quote_parser.handle_starttag(tag, attrs)
            return

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

        # Track closing tags inside quote regions
        if self._in_quote:
            if tag == self._quote_tags[-1]:
                if self._quote_nesting[-1] > 0:
                    # Closing a nested same-tag element, not the
                    # quote container itself.
                    self._quote_nesting[-1] -= 1
                else:
                    # Closing the quote container
                    self._quote_tags.pop()
                    self._quote_nesting.pop()
                    if not self._in_quote:
                        # All quote containers closed — buffer the
                        # converted text for deferred output.
                        if self._quote_parser is not None:
                            self._pending_quote = self._quote_parser.get_text()
                            self._quote_parser = None
            else:
                # Forward non-container close tags to sub-parser
                if self._quote_parser is not None:
                    self._quote_parser.handle_endtag(tag)
            return

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

        if self._in_quote:
            if self._quote_parser is not None:
                self._quote_parser.handle_data(data)
            return

        # Flush any pending quote as markdown blockquote since
        # non-quote content follows it (inline reply pattern).
        # Only flush on substantive text, not whitespace artifacts
        # between closing tags (e.g. "\n</body></html>").
        if self._pending_quote is not None and data.strip():
            self._flush_pending_quote()

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

        Any pending quote buffer that was never followed by non-quote
        content (i.e. trailing quotes) is replaced with a
        "[quoted text removed]" marker.

        Returns:
            Converted plain text.
        """
        # Replace trailing unflushed quote with marker
        if self._pending_quote is not None:
            self._ensure_block_break()
            self._output.append("[quoted text removed]")
            self._handle_newline()
            self._pending_quote = None

        text = "".join(self._output)
        # Normalize newlines: collapse 3+ into 2
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _flush_pending_quote(self) -> None:
        """Emit pending quote buffer as markdown blockquote.

        Called when non-quote content follows a quote block, indicating
        an inline reply pattern where the LLM needs to see the quoted
        context. Callers must check ``_pending_quote is not None``
        before calling.
        """
        quote_text = self._pending_quote
        self._pending_quote = None

        if not quote_text:
            return

        self._ensure_block_break()
        for line in quote_text.splitlines():
            self._output.append(f"> {line}\n")
        self._handle_newline()

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
