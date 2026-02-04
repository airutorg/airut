# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Lightweight markdown to HTML conversion for email content.

This module provides markdown to HTML conversion for email service emails,
supporting a limited subset of markdown syntax that renders well in email
clients. Uses standard HTML tags without custom styling, letting email
clients handle presentation.

Supported syntax:
- Headers: # (bold underline), ## (bold), ### (bold italic)
- Bold: **text** or __text__
- Italic: *text* or _text_
- Preformatted text: ```code blocks``` and `inline code`
- Links: [text](url)
- Tables: | header | header |
- Unordered lists: - item or * item
- Ordered lists: 1. item
"""

import html
import re


def markdown_to_html(text: str) -> str:
    """Convert markdown text to HTML for email.

    Converts a subset of markdown syntax to HTML, using standard HTML tags
    without custom fonts or styling. The resulting HTML is suitable for
    embedding in email messages.

    Args:
        text: Markdown-formatted text.

    Returns:
        HTML string with converted markdown.
    """
    if not text:
        return ""

    lines = text.split("\n")
    result_lines: list[str] = []
    in_code_block = False
    code_block_lines: list[str] = []
    in_table = False
    table_lines: list[str] = []
    in_list = False
    list_lines: list[str] = []
    list_type: str = ""  # "ul" or "ol"

    def flush_list() -> None:
        """Flush pending list lines to result."""
        nonlocal in_list, list_lines, list_type
        if in_list and list_lines:
            result_lines.append(_render_list(list_lines, list_type))
            list_lines = []
            in_list = False
            list_type = ""

    for line in lines:
        # Handle fenced code blocks
        if line.strip().startswith("```"):
            if in_code_block:
                # End code block
                code_content = "\n".join(code_block_lines)
                result_lines.append(f"<pre>{html.escape(code_content)}</pre>")
                code_block_lines = []
                in_code_block = False
            else:
                # Start code block - flush any pending structures
                if in_table:
                    result_lines.append(_render_table(table_lines))
                    table_lines = []
                    in_table = False
                flush_list()
                in_code_block = True
            continue

        if in_code_block:
            code_block_lines.append(line)
            continue

        # Handle tables
        if _is_table_line(line):
            flush_list()
            if not in_table:
                in_table = True
            table_lines.append(line)
            continue
        elif in_table:
            # End of table
            result_lines.append(_render_table(table_lines))
            table_lines = []
            in_table = False

        # Handle lists
        line_list_type = _get_list_type(line)
        if line_list_type:
            if not in_list:
                in_list = True
                list_type = line_list_type
            elif line_list_type != list_type:
                # Switching list type - flush current list
                flush_list()
                in_list = True
                list_type = line_list_type
            list_lines.append(line)
            continue
        elif in_list:
            # End of list
            flush_list()

        # Process regular line - add <br> to all lines for proper HTML rendering
        # Empty lines become standalone <br>, content lines end with <br>
        converted = _convert_line(line)
        if converted == "<br>":
            result_lines.append(converted)
        else:
            result_lines.append(converted + "<br>")

    # Handle unclosed code block
    if in_code_block and code_block_lines:
        code_content = "\n".join(code_block_lines)
        result_lines.append(f"<pre>{html.escape(code_content)}</pre>")

    # Handle unclosed table
    if in_table and table_lines:
        result_lines.append(_render_table(table_lines))

    # Handle unclosed list
    flush_list()

    result = "\n".join(result_lines)

    # Strip trailing <br> from the final output
    if result.endswith("<br>"):
        result = result[:-4]

    return result


def _convert_line(line: str) -> str:
    """Convert a single line of markdown to HTML.

    Args:
        line: Single line of markdown text.

    Returns:
        HTML-converted line.
    """
    # Handle headers (must be done before escaping)
    # Convert to inline styles to keep font size constant:
    # # => bold underline, ## => bold, ### => bold italic
    header_match = re.match(r"^(#{1,3})\s+(.+)$", line)
    if header_match:
        level = len(header_match.group(1))
        content = header_match.group(2)
        escaped_content = _convert_inline(html.escape(content))
        if level == 1:
            return f"<strong><u>{escaped_content}</u></strong>"
        elif level == 2:
            return f"<strong>{escaped_content}</strong>"
        else:  # level == 3
            return f"<strong><em>{escaped_content}</em></strong>"

    # Handle empty lines
    if not line.strip():
        return "<br>"

    # Escape HTML and convert inline elements
    escaped = html.escape(line)
    converted = _convert_inline(escaped)

    return converted


def _convert_inline(text: str) -> str:
    """Convert inline markdown elements to HTML.

    Handles bold, italic, inline code, and links.

    Args:
        text: HTML-escaped text with markdown inline elements.

    Returns:
        Text with inline elements converted to HTML.
    """
    # Inline code (must be done first to prevent other conversions inside code)
    # Match backticks but handle escaped HTML entities
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)

    # Links: [text](url) - url was HTML-escaped, so unescape for href
    def replace_link(match: re.Match[str]) -> str:
        link_text = match.group(1)
        url = html.unescape(match.group(2))
        return f'<a href="{html.escape(url)}">{link_text}</a>'

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", replace_link, text)

    # Bold: **text** or __text__ (must be done before italic)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"__([^_]+)__", r"<strong>\1</strong>", text)

    # Italic: *text* or _text_
    # Use negative lookbehind/lookahead to avoid matching inside words for _
    text = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", text)
    underscore_pattern = r"(?<![a-zA-Z0-9])_([^_]+)_(?![a-zA-Z0-9])"
    text = re.sub(underscore_pattern, r"<em>\1</em>", text)

    return text


def _is_table_line(line: str) -> bool:
    """Check if a line is part of a markdown table.

    Pipes inside inline code (backticks) are ignored when detecting tables.

    Args:
        line: Line to check.

    Returns:
        True if line appears to be a table row.
    """
    stripped = line.strip()
    if not stripped:
        return False

    # Replace inline code segments with placeholder before checking for pipes.
    # This prevents pipes inside `code` from triggering table detection
    # while preserving cell content so code-only cells remain non-empty.
    line_without_code = re.sub(r"`[^`]*`", "X", stripped)

    # Table lines start and/or contain pipes
    # Separator lines look like |---|---|
    if "|" in line_without_code:
        # Must have at least two cells or be a separator
        parts = line_without_code.split("|")
        # Filter out empty parts from leading/trailing pipes
        non_empty = [p for p in parts if p.strip()]
        return len(non_empty) >= 1

    return False


def _is_separator_line(line: str) -> bool:
    """Check if a line is a table separator (|---|---|).

    Args:
        line: Line to check.

    Returns:
        True if line is a separator row.
    """
    stripped = line.strip()
    # Separator contains only |, -, :, and spaces
    return bool(re.match(r"^[\|\-:\s]+$", stripped)) and "-" in stripped


def _render_table(lines: list[str]) -> str:
    """Render markdown table lines as HTML table.

    Args:
        lines: List of table lines (including header and separator).

    Returns:
        HTML table string.
    """
    if not lines:
        return ""

    rows: list[list[str]] = []
    has_header = False

    for i, line in enumerate(lines):
        if _is_separator_line(line):
            # Mark that we have a header (rows before separator)
            if i > 0:
                has_header = True
            continue

        # Parse cells
        stripped = line.strip()
        # Remove leading/trailing pipes and split
        if stripped.startswith("|"):
            stripped = stripped[1:]
        if stripped.endswith("|"):
            stripped = stripped[:-1]

        cells = [cell.strip() for cell in stripped.split("|")]
        rows.append(cells)

    if not rows:
        return ""

    # Build HTML table with minimal inline border styling
    # Using inline styles for email client compatibility
    border_style = "border:1px solid #ccc;border-collapse:collapse;"
    cell_style = "border:1px solid #ccc;padding:4px 8px;"
    html_parts = [f'<table style="{border_style}">']

    for i, row in enumerate(rows):
        html_parts.append("<tr>")
        # First row is header if we found a separator after it
        tag = "th" if has_header and i == 0 else "td"
        for cell in row:
            escaped_cell = html.escape(cell)
            converted_cell = _convert_inline(escaped_cell)
            cell_html = f'<{tag} style="{cell_style}">{converted_cell}</{tag}>'
            html_parts.append(cell_html)
        html_parts.append("</tr>")

    html_parts.append("</table>")

    return "".join(html_parts)


def _get_list_type(line: str) -> str:
    """Determine if a line is a list item and what type.

    Args:
        line: Line to check.

    Returns:
        "ul" for unordered list, "ol" for ordered list, "" if not a list item.
    """
    stripped = line.strip()
    if not stripped:
        return ""

    # Unordered list: starts with - or * followed by space
    if re.match(r"^[-*]\s+", stripped):
        return "ul"

    # Ordered list: starts with number followed by . and space
    if re.match(r"^\d+\.\s+", stripped):
        return "ol"

    return ""


def _render_list(lines: list[str], list_type: str) -> str:
    """Render markdown list lines as HTML list.

    Args:
        lines: List of list item lines.
        list_type: "ul" for unordered or "ol" for ordered.

    Returns:
        HTML list string.
    """
    if not lines or not list_type:
        return ""

    # For ordered lists, parse the start number from the first item
    start_attr = ""
    if list_type == "ol" and lines:
        first_line = lines[0].strip()
        match = re.match(r"^(\d+)\.\s+", first_line)
        if match:
            start_num = int(match.group(1))
            if start_num != 1:
                start_attr = f' start="{start_num}"'

    html_parts = [f"<{list_type}{start_attr}>"]

    for line in lines:
        stripped = line.strip()
        # Extract content after list marker
        if list_type == "ul":
            # Remove - or * and following space
            content = re.sub(r"^[-*]\s+", "", stripped)
        else:
            # Remove number, dot, and following space
            content = re.sub(r"^\d+\.\s+", "", stripped)

        escaped_content = html.escape(content)
        converted_content = _convert_inline(escaped_content)
        html_parts.append(f"<li>{converted_content}</li>")

    html_parts.append(f"</{list_type}>")

    return "".join(html_parts)
