# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for markdown to HTML conversion."""

from airut.markdown import (
    _convert_inline,
    _convert_line,
    _get_list_type,
    _is_separator_line,
    _is_table_line,
    _render_list,
    _render_table,
    markdown_to_html,
)


class TestMarkdownToHtml:
    """Tests for markdown_to_html function."""

    def test_empty_string(self):
        """Test converting empty string."""
        assert markdown_to_html("") == ""

    def test_plain_text(self):
        """Test plain text without markdown - no trailing br."""
        text = "Hello, this is plain text."
        result = markdown_to_html(text)
        assert result == "Hello, this is plain text."

    def test_multiple_lines(self):
        """Test multiple lines - each ends with br except last."""
        text = "Line 1\nLine 2\nLine 3"
        result = markdown_to_html(text)
        assert result == "Line 1<br>\nLine 2<br>\nLine 3"

    def test_empty_line_becomes_standalone_br(self):
        """Test empty line becomes standalone br tag."""
        text = "Line 1\n\nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>\n<br>\nLine 2"

    def test_multiple_empty_lines(self):
        """Test multiple consecutive empty lines produce multiple br tags."""
        text = "Line 1\n\n\nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>\n<br>\n<br>\nLine 2"

    def test_empty_line_at_start(self):
        """Test empty line at start of text."""
        text = "\nLine 1"
        result = markdown_to_html(text)
        assert result == "<br>\nLine 1"


class TestHeaders:
    """Tests for header conversion.

    Headers are converted to inline styles to keep font size constant:
    - # => bold underline
    - ## => bold
    - ### => bold italic
    """

    def test_h1_header(self):
        """Test h1 header conversion to bold underline."""
        result = markdown_to_html("# Header 1")
        assert result == "<strong><u>Header 1</u></strong>"

    def test_h2_header(self):
        """Test h2 header conversion to bold."""
        result = markdown_to_html("## Header 2")
        assert result == "<strong>Header 2</strong>"

    def test_h3_header(self):
        """Test h3 header conversion to bold italic."""
        result = markdown_to_html("### Header 3")
        assert result == "<strong><em>Header 3</em></strong>"

    def test_header_with_inline_formatting(self):
        """Test header with bold and italic."""
        result = markdown_to_html("## **Bold** and *italic* header")
        expected = "<strong>"
        expected += "<strong>Bold</strong> and <em>italic</em> header"
        expected += "</strong>"
        assert result == expected

    def test_header_without_space(self):
        """Test that header without space is not converted."""
        result = markdown_to_html("#NoSpace")
        # Should not be converted (no space after #)
        assert result == "#NoSpace"


class TestBoldAndItalic:
    """Tests for bold and italic conversion."""

    def test_bold_asterisks(self):
        """Test bold with double asterisks."""
        result = markdown_to_html("This is **bold** text.")
        assert result == "This is <strong>bold</strong> text."

    def test_bold_underscores(self):
        """Test bold with double underscores."""
        result = markdown_to_html("This is __bold__ text.")
        assert result == "This is <strong>bold</strong> text."

    def test_italic_asterisks(self):
        """Test italic with single asterisks."""
        result = markdown_to_html("This is *italic* text.")
        assert result == "This is <em>italic</em> text."

    def test_italic_underscores(self):
        """Test italic with single underscores."""
        result = markdown_to_html("This is _italic_ text.")
        assert result == "This is <em>italic</em> text."

    def test_bold_and_italic(self):
        """Test bold and italic together."""
        result = markdown_to_html("**Bold** and *italic* together.")
        expected = "<strong>Bold</strong> and <em>italic</em> together."
        assert result == expected

    def test_underscore_in_word_not_italic(self):
        """Test that underscores in words are not converted."""
        result = markdown_to_html("variable_name_here")
        # Should not be converted - underscores are part of word
        assert result == "variable_name_here"


class TestInlineCode:
    """Tests for inline code conversion."""

    def test_inline_code(self):
        """Test inline code with backticks."""
        result = markdown_to_html("Use `code` here.")
        assert result == "Use <code>code</code> here."

    def test_inline_code_with_special_chars(self):
        """Test inline code preserves special characters."""
        result = markdown_to_html("Use `<html>` tag.")
        assert result == "Use <code>&lt;html&gt;</code> tag."

    def test_multiple_inline_code(self):
        """Test multiple inline code segments."""
        result = markdown_to_html("`foo` and `bar`")
        assert result == "<code>foo</code> and <code>bar</code>"


class TestCodeBlocks:
    """Tests for fenced code block conversion."""

    def test_simple_code_block(self):
        """Test simple fenced code block."""
        text = "```\nprint(x)\n```"
        result = markdown_to_html(text)
        assert result == "<pre>print(x)</pre>"

    def test_code_block_with_language(self):
        """Test code block with language specifier."""
        text = "```python\ndef foo():\n    pass\n```"
        result = markdown_to_html(text)
        assert result == "<pre>def foo():\n    pass</pre>"

    def test_code_block_escapes_html(self):
        """Test code block escapes HTML characters."""
        text = "```\n<html>&amp;</html>\n```"
        result = markdown_to_html(text)
        assert result == "<pre>&lt;html&gt;&amp;amp;&lt;/html&gt;</pre>"

    def test_code_block_with_text_before_after(self):
        """Test code block with surrounding text."""
        text = "Before\n```\ncode\n```\nAfter"
        result = markdown_to_html(text)
        assert result == "Before<br>\n<pre>code</pre>\nAfter"

    def test_unclosed_code_block(self):
        """Test unclosed code block is still rendered."""
        text = "```\ncode without closing"
        result = markdown_to_html(text)
        assert result == "<pre>code without closing</pre>"


class TestLinks:
    """Tests for link conversion."""

    def test_simple_link(self):
        """Test simple markdown link."""
        result = markdown_to_html("[text](https://example.com)")
        assert result == '<a href="https://example.com">text</a>'

    def test_link_with_special_chars(self):
        """Test link with special characters in URL."""
        result = markdown_to_html("[search](https://example.com?q=a&b=c)")
        assert result == '<a href="https://example.com?q=a&amp;b=c">search</a>'

    def test_link_with_formatted_text(self):
        """Test link with bold text."""
        result = markdown_to_html("[**bold link**](https://example.com)")
        expected = '<a href="https://example.com">'
        expected += "<strong>bold link</strong></a>"
        assert result == expected

    def test_multiple_links(self):
        """Test multiple links in same line."""
        result = markdown_to_html(
            "[one](https://one.com) and [two](https://two.com)"
        )
        assert (
            result == '<a href="https://one.com">one</a> and '
            '<a href="https://two.com">two</a>'
        )


class TestTables:
    """Tests for table conversion."""

    def test_simple_table(self):
        """Test simple markdown table."""
        text = "| A | B |\n|---|---|\n| 1 | 2 |"
        result = markdown_to_html(text)
        # Table has inline border styling
        assert "<table style=" in result
        assert ">A</th>" in result
        assert ">B</th>" in result
        assert ">1</td>" in result
        assert ">2</td>" in result
        assert "</table>" in result

    def test_table_without_leading_pipe(self):
        """Test table without leading pipe."""
        text = "A | B\n---|---\n1 | 2"
        result = markdown_to_html(text)
        assert "<table style=" in result
        assert ">A</th>" in result
        assert ">B</th>" in result
        assert ">1</td>" in result
        assert ">2</td>" in result

    def test_table_with_inline_formatting(self):
        """Test table with inline formatting in cells."""
        text = "| **Bold** | *Italic* |\n|---|---|\n| `code` | text |"
        result = markdown_to_html(text)
        assert "<strong>Bold</strong>" in result
        assert "<em>Italic</em>" in result
        assert "<code>code</code>" in result

    def test_table_escapes_html(self):
        """Test table escapes HTML in cells."""
        text = "| <script> | test |\n|---|---|\n| x | y |"
        result = markdown_to_html(text)
        assert "&lt;script&gt;" in result
        assert "<script>" not in result

    def test_table_followed_by_text(self):
        """Test table followed by regular text."""
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n\nRegular text"
        result = markdown_to_html(text)
        assert "<table style=" in result
        assert "</table>" in result
        assert result.endswith("Regular text")

    def test_table_followed_by_code_block(self):
        """Test table immediately followed by code block."""
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n```\ncode\n```"
        result = markdown_to_html(text)
        assert "<table style=" in result
        assert "</table>" in result
        assert "<pre>code</pre>" in result

    def test_table_only_separator(self):
        """Test table with only separator line produces empty string."""
        # This edge case: table lines containing only a separator
        lines = ["|---|---|"]
        result = _render_table(lines)
        assert result == ""

    def test_middle_dot_not_table(self):
        """Test that middle dot separator is not interpreted as table."""
        # Middle dot should be treated as regular text, not table delimiter
        text = "Cost: $0.1000 · Web searches: 2"
        result = markdown_to_html(text)
        # Should not contain table markup
        assert "<table" not in result
        assert "<td>" not in result
        # Should contain the middle dot character
        assert "·" in result

    def test_pipe_in_inline_code_not_table(self):
        """Test that pipes inside inline code are not treated as tables."""
        text = "Use the `|` operator to combine filters."
        result = markdown_to_html(text)
        # Should not contain table markup
        assert "<table" not in result
        assert "<td>" not in result
        # Should contain the inline code with pipe
        assert "<code>|</code>" in result

    def test_multiple_pipes_in_code_not_table(self):
        """Test that multiple pipes in code don't trigger table detection."""
        text = "Pattern: `| A | B |` is a table syntax"
        result = markdown_to_html(text)
        # Should not contain table markup
        assert "<table" not in result
        assert "<td>" not in result
        # Should contain the inline code
        assert "<code>" in result

    def test_table_with_code_only_cells(self):
        """Test table where all cell content is inside backticks."""
        text = (
            "| Old | New |\n"
            "|---|---|\n"
            "| `a` | `b` |\n"
            "| `c` | `d` |\n"
            "| `e` | `f` |"
        )
        result = markdown_to_html(text)
        # Should be a single table, not split
        assert result.count("<table") == 1
        assert result.count("</table>") == 1
        assert "<code>a</code>" in result
        assert "<code>f</code>" in result

    def test_pipe_outside_code_is_table(self):
        """Test that actual table syntax still works with code present."""
        text = "| Column `A` | Column B |\n|---|---|\n| `value` | data |"
        result = markdown_to_html(text)
        # Should contain table markup
        assert "<table" in result
        # Should also preserve inline code in cells
        assert "<code>A</code>" in result
        assert "<code>value</code>" in result


class TestLists:
    """Tests for list conversion."""

    def test_unordered_list_dash(self):
        """Test unordered list with dash marker."""
        text = "- Item 1\n- Item 2\n- Item 3"
        result = markdown_to_html(text)
        expected = "<ul><li>Item 1</li><li>Item 2</li><li>Item 3</li></ul>"
        assert result == expected

    def test_unordered_list_asterisk(self):
        """Test unordered list with asterisk marker."""
        text = "* Item A\n* Item B"
        result = markdown_to_html(text)
        assert result == "<ul><li>Item A</li><li>Item B</li></ul>"

    def test_ordered_list(self):
        """Test ordered list."""
        text = "1. First\n2. Second\n3. Third"
        result = markdown_to_html(text)
        assert result == "<ol><li>First</li><li>Second</li><li>Third</li></ol>"

    def test_ordered_list_any_numbers(self):
        """Test ordered list ignores actual numbers."""
        text = "1. First\n1. Second\n5. Third"
        result = markdown_to_html(text)
        assert result == "<ol><li>First</li><li>Second</li><li>Third</li></ol>"

    def test_list_with_inline_formatting(self):
        """Test list items with inline formatting."""
        text = "- **Bold** item\n- *Italic* item\n- `code` item"
        result = markdown_to_html(text)
        assert "<li><strong>Bold</strong> item</li>" in result
        assert "<li><em>Italic</em> item</li>" in result
        assert "<li><code>code</code> item</li>" in result

    def test_list_escapes_html(self):
        """Test list items escape HTML."""
        text = "- <script>alert()</script>"
        result = markdown_to_html(text)
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_list_followed_by_text(self):
        """Test list followed by regular text."""
        text = "- Item 1\n- Item 2\n\nRegular text"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "</ul>" in result
        assert result.endswith("Regular text")

    def test_list_followed_by_code_block(self):
        """Test list followed by code block."""
        text = "- Item 1\n```\ncode\n```"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "</ul>" in result
        assert "<pre>code</pre>" in result

    def test_list_followed_by_table(self):
        """Test list followed by table."""
        text = "- Item\n| A | B |\n|---|---|\n| 1 | 2 |"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "</ul>" in result
        assert "<table style=" in result

    def test_switching_list_types(self):
        """Test switching from unordered to ordered list."""
        text = "- Unordered\n1. Ordered"
        result = markdown_to_html(text)
        assert "<ul><li>Unordered</li></ul>" in result
        assert "<ol><li>Ordered</li></ol>" in result

    def test_dash_not_list_without_space(self):
        """Test that dash without space is not a list."""
        text = "-NoSpace"
        result = markdown_to_html(text)
        assert "<ul>" not in result
        assert result == "-NoSpace"

    def test_ordered_list_with_custom_start(self):
        """Test ordered list starting at number other than 1."""
        text = "5. Fifth\n6. Sixth\n7. Seventh"
        result = markdown_to_html(text)
        expected = '<ol start="5">'
        expected += "<li>Fifth</li><li>Sixth</li><li>Seventh</li></ol>"
        assert result == expected

    def test_ordered_list_starting_at_one_no_start_attr(self):
        """Test ordered list starting at 1 has no start attribute."""
        text = "1. First\n2. Second"
        result = markdown_to_html(text)
        assert result == "<ol><li>First</li><li>Second</li></ol>"
        assert "start=" not in result

    def test_ordered_lists_separated_by_blank_line(self):
        """Test ordered lists separated by blank lines preserve numbering."""
        text = "1. First\n\n2. Second\n\n3. Third"
        result = markdown_to_html(text)
        assert "<ol><li>First</li></ol>" in result
        assert '<ol start="2"><li>Second</li></ol>' in result
        assert '<ol start="3"><li>Third</li></ol>' in result


class TestHtmlEscaping:
    """Tests for HTML escaping."""

    def test_html_tags_escaped(self):
        """Test HTML tags are escaped."""
        result = markdown_to_html("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_ampersand_escaped(self):
        """Test ampersand is escaped."""
        result = markdown_to_html("Tom & Jerry")
        assert result == "Tom &amp; Jerry"

    def test_quotes_escaped(self):
        """Test quotes are escaped in regular text."""
        result = markdown_to_html('Say "hello"')
        assert result == "Say &quot;hello&quot;"


class TestComplexContent:
    """Tests for complex markdown content."""

    def test_full_document(self):
        """Test converting a full document with various elements."""
        text = """# Title

This is a **paragraph** with *formatting*.

## Code Example

```
def hello():
    print("world")
```

See [docs](https://docs.example.com) for more.

| Col A | Col B |
|-------|-------|
| 1     | 2     |
"""
        result = markdown_to_html(text)

        # Check all elements are present
        assert "<strong><u>Title</u></strong>" in result
        assert "<strong>paragraph</strong>" in result
        assert "<em>formatting</em>" in result
        assert "<strong>Code Example</strong>" in result
        assert "<pre>" in result
        assert "</pre>" in result
        assert '<a href="https://docs.example.com">docs</a>' in result
        assert "<table style=" in result


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_convert_line_empty(self):
        """Test _convert_line with empty line."""
        assert _convert_line("") == "<br>"
        assert _convert_line("   ") == "<br>"

    def test_convert_line_header(self):
        """Test _convert_line with header."""
        assert _convert_line("# Header") == "<strong><u>Header</u></strong>"

    def test_convert_inline_all_formats(self):
        """Test _convert_inline with all formats."""
        text = "**bold** *italic* `code` [link](url)"
        result = _convert_inline(text)
        assert "<strong>bold</strong>" in result
        assert "<em>italic</em>" in result
        assert "<code>code</code>" in result
        assert '<a href="url">link</a>' in result

    def test_is_table_line(self):
        """Test _is_table_line function."""
        assert _is_table_line("| A | B |") is True
        assert _is_table_line("A | B") is True
        assert _is_table_line("|---|---|") is True
        assert _is_table_line("No pipes here") is False
        assert _is_table_line("") is False
        assert _is_table_line("   ") is False
        # Pipes in inline code should not trigger table detection
        assert _is_table_line("Use the `|` operator") is False
        assert _is_table_line("Pattern: `| A | B |` syntax") is False
        # But actual tables with code in cells should still be detected
        assert _is_table_line("| `code` | value |") is True

    def test_is_separator_line(self):
        """Test _is_separator_line function."""
        assert _is_separator_line("|---|---|") is True
        assert _is_separator_line("---|---") is True
        assert _is_separator_line("|:---:|:---:|") is True
        assert _is_separator_line("| A | B |") is False
        assert _is_separator_line("") is False

    def test_render_table_empty(self):
        """Test _render_table with empty list."""
        assert _render_table([]) == ""

    def test_render_table_no_separator(self):
        """Test _render_table without separator line."""
        lines = ["| A | B |", "| 1 | 2 |"]
        result = _render_table(lines)
        # Without separator, all rows are td
        assert "<th>" not in result
        assert ">A</td>" in result

    def test_get_list_type(self):
        """Test _get_list_type function."""
        assert _get_list_type("- Item") == "ul"
        assert _get_list_type("* Item") == "ul"
        assert _get_list_type("1. Item") == "ol"
        assert _get_list_type("99. Item") == "ol"
        assert _get_list_type("-NoSpace") == ""
        assert _get_list_type("Regular text") == ""
        assert _get_list_type("") == ""
        assert _get_list_type("   ") == ""

    def test_render_list_empty(self):
        """Test _render_list with empty list."""
        assert _render_list([], "ul") == ""
        assert _render_list(["- Item"], "") == ""

    def test_render_list_unordered(self):
        """Test _render_list for unordered list."""
        lines = ["- Item 1", "- Item 2"]
        result = _render_list(lines, "ul")
        assert result == "<ul><li>Item 1</li><li>Item 2</li></ul>"

    def test_render_list_ordered(self):
        """Test _render_list for ordered list."""
        lines = ["1. First", "2. Second"]
        result = _render_list(lines, "ol")
        assert result == "<ol><li>First</li><li>Second</li></ol>"
