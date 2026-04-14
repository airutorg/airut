# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for markdown to HTML conversion."""

from airut.markdown import (
    EmailRenderer,
    _count_columns,
    _escape_code_pipes,
    _is_sep_line,
    _normalize_table_row,
    _prepare_tables,
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

    def test_empty_line_becomes_standalone_br(self):
        """Test empty line becomes standalone br tag."""
        text = "Line 1\n\nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>\n<br>\nLine 2"

    def test_multiple_empty_lines(self):
        """Multiple consecutive blank lines collapse to single blank_line.

        mistune follows CommonMark and collapses multiple blank lines into
        a single blank_line token.
        """
        text = "Line 1\n\n\nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>\n<br>\nLine 2"

    def test_empty_line_at_start(self):
        """Test empty line at start of text."""
        text = "\nLine 1"
        result = markdown_to_html(text)
        assert result == "<br>\nLine 1"


class TestParagraphs:
    """Tests for CommonMark paragraph behavior (section 4.8).

    Consecutive non-blank lines form a paragraph. Soft line breaks
    within a paragraph are rendered as spaces. Blank lines separate
    paragraphs.
    """

    def test_multiline_paragraph_joins_with_space(self):
        """Consecutive non-blank lines join with spaces (soft breaks)."""
        text = "Line 1\nLine 2\nLine 3"
        result = markdown_to_html(text)
        assert result == "Line 1 Line 2 Line 3"

    def test_two_paragraphs_separated_by_blank_line(self):
        """Blank line separates two paragraphs."""
        text = "Paragraph one.\n\nParagraph two."
        result = markdown_to_html(text)
        assert result == "Paragraph one.<br>\n<br>\nParagraph two."

    def test_three_paragraphs(self):
        """Multiple paragraphs separated by blank lines."""
        text = "First.\n\nSecond.\n\nThird."
        result = markdown_to_html(text)
        assert result == "First.<br>\n<br>\nSecond.<br>\n<br>\nThird."

    def test_multiline_paragraphs_with_blank_separator(self):
        """Multi-line paragraphs join internally, separate at blank lines."""
        text = "Line A1\nLine A2\n\nLine B1\nLine B2"
        result = markdown_to_html(text)
        assert result == "Line A1 Line A2<br>\n<br>\nLine B1 Line B2"

    def test_multiple_blank_lines_between_paragraphs(self):
        """Multiple blank lines collapse to single break (CommonMark)."""
        text = "First.\n\n\nSecond."
        result = markdown_to_html(text)
        assert result == "First.<br>\n<br>\nSecond."

    def test_paragraph_with_inline_formatting_across_lines(self):
        """Inline formatting works within joined paragraph lines."""
        text = "This is **bold**\nand *italic* text."
        result = markdown_to_html(text)
        assert (
            result == "This is <strong>bold</strong> and <em>italic</em> text."
        )

    def test_paragraph_before_code_block(self):
        """Paragraph flushes before code block."""
        text = "Some text\n```\ncode\n```"
        result = markdown_to_html(text)
        assert result == "Some text<br>\n<pre>code</pre>"

    def test_paragraph_after_code_block(self):
        """Paragraph starts after code block."""
        text = "```\ncode\n```\nSome text"
        result = markdown_to_html(text)
        assert result == "<pre>code</pre>\nSome text"

    def test_multiline_paragraph_between_code_blocks(self):
        """Multi-line paragraph between code blocks joins correctly."""
        text = "```\ncode1\n```\nMiddle text\nmore text\n```\ncode2\n```"
        result = markdown_to_html(text)
        assert (
            result
            == "<pre>code1</pre>\nMiddle text more text<br>\n<pre>code2</pre>"
        )

    def test_paragraph_before_list(self):
        """Paragraph flushes before list starts."""
        text = "Some text\n\n- item 1\n- item 2"
        result = markdown_to_html(text)
        assert (
            result
            == "Some text<br>\n<br>\n<ul><li>item 1</li><li>item 2</li></ul>"
        )

    def test_paragraph_before_header(self):
        """Paragraph flushes before header."""
        text = "Some text\n\n# Header"
        result = markdown_to_html(text)
        assert result == "Some text<br>\n<br>\n<strong><u>Header</u></strong>"

    def test_paragraph_after_header(self):
        """Paragraph starts after header."""
        text = "# Header\nSome text"
        result = markdown_to_html(text)
        assert result == "<strong><u>Header</u></strong><br>\nSome text"

    def test_paragraph_strips_trailing_spaces(self):
        """Three trailing spaces is 2+ so triggers hard break."""
        text = "Hello   \nworld"
        result = markdown_to_html(text)
        assert result == "Hello<br>world"

    def test_paragraph_single_trailing_space_soft_break(self):
        """Single trailing space is a soft break, not a hard break."""
        text = "Hello \nworld"
        result = markdown_to_html(text)
        assert result == "Hello world"


class TestHardLineBreaks:
    """Tests for hard line breaks per CommonMark spec (section 6.7).

    A line ending preceded by two or more spaces or a backslash
    is rendered as <br> (hard line break).
    """

    def test_backslash_hard_break(self):
        """Trailing backslash creates hard line break."""
        text = "Line 1\\\nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>Line 2"

    def test_two_trailing_spaces_hard_break(self):
        """Two trailing spaces create hard line break."""
        text = "Line 1  \nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>Line 2"

    def test_multiple_trailing_spaces_hard_break(self):
        """More than two trailing spaces also create hard break."""
        text = "Line 1     \nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>Line 2"

    def test_backslash_last_line_literal(self):
        """Trailing backslash on last line of paragraph is kept as literal."""
        result = markdown_to_html("Hello\\")
        assert result == "Hello\\"

    def test_trailing_spaces_last_line_stripped(self):
        """Trailing spaces on last line of paragraph are stripped."""
        result = markdown_to_html("Hello  ")
        assert result == "Hello"

    def test_backslash_end_of_paragraph_literal(self):
        """Backslash at end of paragraph (before blank line) is literal."""
        text = "Line 1\\\n\nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1\\<br>\n<br>\nLine 2"

    def test_trailing_spaces_end_of_paragraph_stripped(self):
        """Trailing spaces at end of paragraph are stripped."""
        text = "Line 1  \n\nLine 2"
        result = markdown_to_html(text)
        assert result == "Line 1<br>\n<br>\nLine 2"

    def test_mixed_hard_and_soft_breaks(self):
        """Mix of hard and soft breaks in one paragraph."""
        text = "Line 1\\\nLine 2\nLine 3"
        result = markdown_to_html(text)
        assert result == "Line 1<br>Line 2 Line 3"

    def test_multiple_hard_breaks(self):
        """Multiple consecutive hard breaks."""
        text = "Line 1\\\nLine 2\\\nLine 3"
        result = markdown_to_html(text)
        assert result == "Line 1<br>Line 2<br>Line 3"

    def test_hard_break_with_inline_formatting(self):
        """Hard break works with inline formatting."""
        text = "**Bold**\\\n*italic*"
        result = markdown_to_html(text)
        assert result == "<strong>Bold</strong><br><em>italic</em>"

    def test_hard_break_spaces_with_formatting(self):
        """Hard break via spaces works with inline formatting."""
        text = "**Bold**  \n*italic*"
        result = markdown_to_html(text)
        assert result == "<strong>Bold</strong><br><em>italic</em>"


class TestHeaders:
    """Tests for header conversion.

    Headers are converted to inline styles to keep font size constant:
    - # => bold underline
    - ## => bold italic underline
    - ### => underline
    - #### => italic underline
    - ##### => italic
    - ###### => bold
    """

    def test_h1_header(self):
        """Test h1 header conversion to bold underline."""
        result = markdown_to_html("# Header 1")
        assert result == "<strong><u>Header 1</u></strong>"

    def test_h2_header(self):
        """Test h2 header conversion to bold italic underline."""
        result = markdown_to_html("## Header 2")
        assert result == "<strong><em><u>Header 2</u></em></strong>"

    def test_h3_header(self):
        """Test h3 header conversion to underline."""
        result = markdown_to_html("### Header 3")
        assert result == "<u>Header 3</u>"

    def test_h4_header(self):
        """Test h4 header conversion to italic underline."""
        result = markdown_to_html("#### Header 4")
        assert result == "<em><u>Header 4</u></em>"

    def test_h5_header(self):
        """Test h5 header conversion to italic."""
        result = markdown_to_html("##### Header 5")
        assert result == "<em>Header 5</em>"

    def test_h6_header(self):
        """Test h6 header conversion to bold."""
        result = markdown_to_html("###### Header 6")
        assert result == "<strong>Header 6</strong>"

    def test_header_with_inline_formatting(self):
        """Test header with bold and italic."""
        result = markdown_to_html("## **Bold** and *italic* header")
        expected = "<strong><em><u>"
        expected += "<strong>Bold</strong> and <em>italic</em> header"
        expected += "</u></em></strong>"
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
        text = "Before\n\n```\ncode\n```\n\nAfter"
        result = markdown_to_html(text)
        assert result == "Before<br>\n<br>\n<pre>code</pre>\n<br>\nAfter"

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

    def test_table_has_trailing_br_for_spacing(self):
        """Table output ends with <br> for visual separation."""
        text = "| A | B |\n|---|---|\n| 1 | 2 |"
        result = markdown_to_html(text)
        assert result.endswith("</table>")
        # When followed by text, the <br> provides spacing
        text2 = "| A | B |\n|---|---|\n| 1 | 2 |\n\nAfter"
        result2 = markdown_to_html(text2)
        assert "</table><br>" in result2

    def test_table_followed_by_code_block(self):
        """Test table immediately followed by code block."""
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n\n```\ncode\n```"
        result = markdown_to_html(text)
        assert "<table style=" in result
        assert "</table>" in result
        assert "<pre>code</pre>" in result

    def test_middle_dot_not_table(self):
        """Test that middle dot separator is not interpreted as table."""
        text = "Cost: $0.1000 \u00b7 Web searches: 2"
        result = markdown_to_html(text)
        assert "<table" not in result
        assert "<td>" not in result
        assert "\u00b7" in result

    def test_pipe_in_inline_code_not_table(self):
        """Test that pipes inside inline code are not treated as tables."""
        text = "Use the `|` operator to combine filters."
        result = markdown_to_html(text)
        assert "<table" not in result
        assert "<td>" not in result
        assert "<code>|</code>" in result

    def test_multiple_pipes_in_code_not_table(self):
        """Test that multiple pipes in code don't trigger table detection."""
        text = "Pattern: `| A | B |` is a table syntax"
        result = markdown_to_html(text)
        assert "<table" not in result
        assert "<td>" not in result
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
        assert result.count("<table") == 1
        assert result.count("</table>") == 1
        assert "<code>a</code>" in result
        assert "<code>f</code>" in result

    def test_pipe_outside_code_is_table(self):
        """Test that actual table syntax still works with code present."""
        text = "| Column `A` | Column B |\n|---|---|\n| `value` | data |"
        result = markdown_to_html(text)
        assert "<table" in result
        assert "<code>A</code>" in result
        assert "<code>value</code>" in result

    def test_pipe_in_backtick_cell_not_split(self):
        """Pipe inside backtick code in a table cell must not split the cell."""
        text = "| Code | Desc |\n|---|---|\n| `a|b` | test |"
        result = markdown_to_html(text)
        assert "<table" in result
        assert "<code>a|b</code>" in result
        assert result.count("<td") == 2

    def test_double_backtick_pipe_in_cell(self):
        """Double-backtick code span with pipe must not split the cell."""
        text = "| Code | Desc |\n|---|---|\n| ``a|b`` | test |"
        result = markdown_to_html(text)
        assert "<table" in result
        assert "<code>a|b</code>" in result
        assert result.count("<td") == 2

    def test_multiple_pipes_in_code_cell(self):
        """Multiple pipes inside backtick code in a table cell."""
        text = "| Expr | Desc |\n|---|---|\n| `a|b|c` | union |"
        result = markdown_to_html(text)
        assert "<table" in result
        assert "<code>a|b|c</code>" in result
        assert result.count("<td") == 2

    def test_multiple_code_spans_with_pipes_in_row(self):
        """Multiple code spans with pipes in different cells of same row."""
        text = "| A | B |\n|---|---|\n| `x|y` | `a|b|c` |"
        result = markdown_to_html(text)
        assert "<code>x|y</code>" in result
        assert "<code>a|b|c</code>" in result
        assert result.count("<td") == 2

    def test_unclosed_backtick_does_not_swallow_pipe(self):
        """Unclosed backtick should not hide subsequent pipes."""
        text = "| A | B |\n|---|---|\n| `unclosed | val |"
        result = markdown_to_html(text)
        assert "<table" in result
        assert result.count("<td") == 2

    def test_double_backtick_pipe_not_table_line(self):
        """Line with pipe only inside double-backtick code is not a table."""
        text = "Use ``a|b`` in your code"
        result = markdown_to_html(text)
        assert "<table" not in result
        assert "<code>a|b</code>" in result

    def test_table_with_mixed_code_and_text_pipes(self):
        """Table cell mixing code-with-pipe and regular text."""
        text = "| Expr | Note |\n|---|---|\n| `a|b` or c | info |"
        result = markdown_to_html(text)
        assert "<code>a|b</code>" in result
        assert result.count("<td") == 2

    def test_triple_backtick_code_span_with_pipe(self):
        """Triple-backtick code span with pipe in a table cell."""
        text = "| Code | Desc |\n|---|---|\n| ```a|b``` | test |"
        result = markdown_to_html(text)
        assert "<table" in result

    def test_pipe_text_without_separator_not_table(self):
        """Lines with pipes but no separator row are not tables."""
        text = "Option A | Option B | Option C"
        result = markdown_to_html(text)
        assert "<table" not in result
        assert "<td>" not in result
        assert "Option A" in result
        assert "Option B" in result

    def test_source_line_with_pipes_not_table(self):
        """Source attribution lines with pipe separators are not tables."""
        text = (
            "**Source:** Anthropic"
            " | [Announcement](https://example.com)"
            " | [Blog](https://example.com/blog)"
            " | [HN Discussion (425 pts)](https://news.example.com)"
        )
        result = markdown_to_html(text)
        assert "<table" not in result
        assert "<td>" not in result
        assert "<strong>Source:</strong>" in result
        assert '<a href="https://example.com">Announcement</a>' in result

    def test_multiple_pipe_lines_without_separator_not_table(self):
        """Multiple consecutive pipe lines without separator are not tables."""
        text = "A | B | C\nD | E | F\nG | H | I"
        result = markdown_to_html(text)
        assert "<table" not in result
        assert "<td>" not in result
        assert "A" in result
        assert "D" in result

    def test_pipe_line_at_end_not_table(self):
        """Pipe line at end of input (no following separator) is not a table."""
        text = "Some text\nA | B | C"
        result = markdown_to_html(text)
        assert "<table" not in result

    def test_separator_without_header_not_table(self):
        """Separator line without a preceding header is not a table."""
        text = "|---|---|\n| 1 | 2 |"
        result = markdown_to_html(text)
        assert "<table" not in result

    def test_table_still_works_with_separator(self):
        """Valid table with header + separator + data still works."""
        text = "| Name | Value |\n|---|---|\n| foo | bar |\n| baz | qux |"
        result = markdown_to_html(text)
        assert "<table" in result
        assert ">Name</th>" in result
        assert ">Value</th>" in result
        assert ">foo</td>" in result
        assert ">bar</td>" in result
        assert ">baz</td>" in result
        assert ">qux</td>" in result

    def test_document_with_pipes_and_tables(self):
        """Document mixing pipe text and real tables renders correctly."""
        text = (
            "# Title\n"
            "\n"
            "**Source:** X"
            " | [Link](https://example.com)"
            " | [HN](https://hn.com)\n"
            "\n"
            "Some paragraph.\n"
            "\n"
            "| Col A | Col B |\n"
            "|-------|-------|\n"
            "| 1     | 2     |\n"
            "\n"
            "More text | with pipes | in it"
        )
        result = markdown_to_html(text)
        # Only one table (the real one with separator)
        assert result.count("<table") == 1
        # The source line should be plain text with links
        assert '<a href="https://example.com">Link</a>' in result
        # The "More text" line should be plain text
        assert "More text" in result
        assert result.count("</table>") == 1


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
        text = "- Item 1\n\n```\ncode\n```"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "</ul>" in result
        assert "<pre>code</pre>" in result

    def test_list_followed_by_table(self):
        """Test list followed by table."""
        text = "- Item\n\n| A | B |\n|---|---|\n| 1 | 2 |"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "</ul>" in result
        assert "<table style=" in result

    def test_switching_list_types(self):
        """Test switching from unordered to ordered list."""
        text = "- Unordered\n\n1. Ordered"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "<li>Unordered</li>" in result
        assert "<ol>" in result
        assert "<li>Ordered</li>" in result

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
        """Blank lines between items form a loose list in CommonMark.

        mistune follows CommonMark: blank lines between items make a
        "loose" list (single list with paragraph-wrapped items), not
        separate lists.
        """
        text = "1. First\n\n2. Second\n\n3. Third"
        result = markdown_to_html(text)
        # Should be a single list
        assert result.count("<ol") == 1
        assert result.count("</ol>") == 1
        assert "First" in result
        assert "Second" in result
        assert "Third" in result

    def test_multiline_list_item_continuation(self):
        """Continuation lines without marker join the current list item."""
        text = "- First line\n  second line\n  third line"
        result = markdown_to_html(text)
        assert result == "<ul><li>First line second line third line</li></ul>"

    def test_multiline_list_multiple_items(self):
        """Multiple multiline list items each join their continuations."""
        text = (
            "- Item one first\n  item one second\n"
            "- Item two first\n  item two second"
        )
        result = markdown_to_html(text)
        assert "<li>Item one first item one second</li>" in result
        assert "<li>Item two first item two second</li>" in result

    def test_multiline_list_item_with_inline_formatting(self):
        """Inline formatting works across continuation lines."""
        text = (
            "- **Bold title** \u2014 description\n"
            "  continues with *italic* here"
        )
        result = markdown_to_html(text)
        assert "<strong>Bold title</strong>" in result
        assert "<em>italic</em>" in result
        # Should be a single list item
        assert result.count("<li>") == 1

    def test_multiline_ordered_list_continuation(self):
        """Ordered list items support continuation lines."""
        text = "1. First item\n   continues here\n2. Second item"
        result = markdown_to_html(text)
        assert "First item" in result
        assert "continues here" in result
        assert "<li>Second item</li>" in result

    def test_multiline_list_item_blank_line_ends_list(self):
        """Blank line after continuation creates loose list."""
        text = "- Item one\n  continued\n\nParagraph"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "Item one" in result
        assert "continued" in result
        assert result.endswith("Paragraph")

    def test_multiline_list_item_code_fence_after_blank(self):
        """Code fence after blank line following list item."""
        text = "- Item\n\n```\ncode\n```"
        result = markdown_to_html(text)
        assert "<ul>" in result
        assert "</ul>" in result
        assert "<pre>code</pre>" in result

    def test_multiline_list_real_world_newsletter(self):
        """Real-world newsletter-style bullet with links and continuations."""
        text = (
            "- **Meta building AI clone** \u2014 FT reports Meta is"
            " developing\n"
            "  photorealistic AI characters starting with Mark Zuckerberg\n"
            "  ([FT](https://example.com/ft) |\n"
            "  [Ars](https://example.com/ars))."
        )
        result = markdown_to_html(text)
        # Should be a single list item
        assert result.count("<li>") == 1
        assert result.count("</li>") == 1
        assert "<strong>Meta building AI clone</strong>" in result
        assert "photorealistic AI characters" in result
        assert '<a href="https://example.com/ft">FT</a>' in result
        assert '<a href="https://example.com/ars">Ars</a>' in result

    def test_multiline_list_item_hard_break_in_continuation(self):
        """Hard break (trailing backslash) works within list continuation."""
        text = "- Line one\\\n  Line two"
        result = markdown_to_html(text)
        assert "Line one<br>Line two" in result


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
        assert "<strong><em><u>Code Example</u></em></strong>" in result
        assert "<pre>" in result
        assert "</pre>" in result
        assert '<a href="https://docs.example.com">docs</a>' in result
        assert "<table style=" in result


class TestBlockquotes:
    """Tests for blockquote conversion per CommonMark spec (section 5.1).

    A block quote marker consists of 0-3 spaces of initial indent, plus
    the ``>`` character, plus an optional single space. The content after
    stripping the marker is processed recursively as markdown.
    """

    def test_simple_blockquote(self):
        """Single-line blockquote renders as <blockquote>."""
        result = markdown_to_html("> Hello")
        assert "<blockquote" in result
        assert "Hello" in result
        assert "</blockquote>" in result

    def test_blockquote_no_space_after_marker(self):
        """Blockquote without space after > is still valid per CommonMark."""
        result = markdown_to_html(">Hello")
        assert "<blockquote" in result
        assert "Hello" in result
        assert "</blockquote>" in result

    def test_multiline_blockquote_soft_breaks(self):
        """Consecutive > lines form single blockquote with soft breaks."""
        text = "> Line 1\n> Line 2\n> Line 3"
        result = markdown_to_html(text)
        assert result.count("<blockquote") == 1
        assert result.count("</blockquote>") == 1
        assert "Line 1 Line 2 Line 3" in result

    def test_blockquote_paragraph_separation(self):
        """Blank > line creates paragraph break within blockquote."""
        text = "> Para 1\n>\n> Para 2"
        result = markdown_to_html(text)
        assert result.count("<blockquote") == 1
        assert "Para 1" in result
        assert "Para 2" in result

    def test_nested_blockquote(self):
        """Nested blockquote with > > marker."""
        text = "> > Nested"
        result = markdown_to_html(text)
        assert result.count("<blockquote") == 2
        assert result.count("</blockquote>") == 2
        assert "Nested" in result

    def test_nested_blockquote_no_space(self):
        """Nested blockquote with >> (no space between markers)."""
        text = ">> Nested"
        result = markdown_to_html(text)
        assert result.count("<blockquote") == 2
        assert result.count("</blockquote>") == 2
        assert "Nested" in result

    def test_deeply_nested_blockquote(self):
        """Three levels of nesting."""
        text = "> > > Deep"
        result = markdown_to_html(text)
        assert result.count("<blockquote") == 3
        assert result.count("</blockquote>") == 3
        assert "Deep" in result

    def test_blockquote_with_inline_formatting(self):
        """Blockquote content supports inline formatting."""
        text = "> **Bold** and *italic* and `code`"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "<strong>Bold</strong>" in result
        assert "<em>italic</em>" in result
        assert "<code>code</code>" in result

    def test_blockquote_with_link(self):
        """Blockquote content supports links."""
        text = "> See [docs](https://example.com)"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert '<a href="https://example.com">docs</a>' in result

    def test_blockquote_with_header(self):
        """Blockquote containing a header."""
        text = "> # Title\n> Some text"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "<strong><u>Title</u></strong>" in result
        assert "Some text" in result

    def test_blockquote_with_list(self):
        """Blockquote containing a list."""
        text = "> - Item 1\n> - Item 2"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "<ul>" in result
        assert "<li>Item 1</li>" in result
        assert "<li>Item 2</li>" in result

    def test_blockquote_with_code_block(self):
        """Blockquote containing a fenced code block."""
        text = "> ```\n> code here\n> ```"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "<pre>code here</pre>" in result

    def test_blockquote_preceded_by_paragraph(self):
        """Paragraph text before a blockquote flushes correctly."""
        text = "Some text\n\n> Quoted"
        result = markdown_to_html(text)
        assert "Some text" in result
        assert "<blockquote" in result
        assert "Quoted" in result
        assert result.index("Some text") < result.index("<blockquote")

    def test_blockquote_followed_by_paragraph(self):
        r"""Text after blockquote renders correctly.

        CommonMark allows lazy continuation — non-``>`` lines continue
        the blockquote paragraph. So ``> Quoted\nAfter text`` becomes
        a single blockquote with both lines.
        """
        text = "> Quoted\n\nAfter text"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "Quoted" in result
        assert "After text" in result
        assert result.index("</blockquote>") < result.index("After text")

    def test_two_separate_blockquotes(self):
        """Blank line without > separates into two blockquotes."""
        text = "> First\n\n> Second"
        result = markdown_to_html(text)
        assert result.count("<blockquote") == 2
        assert result.count("</blockquote>") == 2
        assert "First" in result
        assert "Second" in result

    def test_blockquote_html_escaping(self):
        """HTML in blockquote is properly escaped."""
        text = "> <script>alert('xss')</script>"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_empty_blockquote_marker(self):
        """Bare > marker produces blockquote with empty content."""
        result = markdown_to_html(">")
        assert "<blockquote" in result
        assert "</blockquote>" in result

    def test_blockquote_at_end_of_document(self):
        """Blockquote at end of document flushes correctly."""
        text = "Text before\n\n> Final quote"
        result = markdown_to_html(text)
        assert "Text before" in result
        assert "<blockquote" in result
        assert "Final quote" in result
        assert result.endswith("</blockquote>")

    def test_blockquote_between_paragraphs(self):
        """Blockquote between two paragraphs."""
        text = "Before\n\n> Quoted\n\nAfter"
        result = markdown_to_html(text)
        assert result.index("Before") < result.index("<blockquote")
        assert result.index("</blockquote>") < result.index("After")

    def test_blockquote_leading_spaces(self):
        """Up to 3 leading spaces before > are allowed."""
        for spaces in range(4):
            prefix = " " * spaces
            result = markdown_to_html(f"{prefix}> Hello")
            assert "<blockquote" in result, (
                f"Failed with {spaces} leading spaces"
            )
            assert "Hello" in result

    def test_four_spaces_before_marker_not_blockquote(self):
        """Four leading spaces before > is indented code block."""
        result = markdown_to_html("    > Not a quote")
        assert "<blockquote" not in result

    def test_blockquote_preserves_extra_content_spaces(self):
        """Only one space after > is stripped; extra spaces are content."""
        text = ">  Two spaces"
        result = markdown_to_html(text)
        assert "<blockquote" in result

    def test_blockquote_with_hard_break(self):
        """Hard line break inside blockquote via trailing backslash."""
        text = "> Line 1\\\n> Line 2"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "Line 1<br>Line 2" in result

    def test_blockquote_with_table(self):
        """Blockquote containing a table."""
        text = "> | A | B |\n> |---|---|\n> | 1 | 2 |"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "<table" in result
        assert ">A</th>" in result
        assert ">1</td>" in result

    def test_blockquote_interrupts_paragraph(self):
        """Per CommonMark, blockquote can interrupt a paragraph."""
        text = "Paragraph\n\n> Quote"
        result = markdown_to_html(text)
        assert "Paragraph" in result
        assert "<blockquote" in result
        assert "Quote" in result

    def test_blockquote_mixed_with_other_blocks(self):
        """Document with blockquote mixed among other block elements."""
        text = "# Title\n\n> Quoted text\n\n- List item\n\n> Another quote"
        result = markdown_to_html(text)
        assert "<strong><u>Title</u></strong>" in result
        assert result.count("<blockquote") == 2
        assert "<li>List item</li>" in result

    def test_blockquote_only_marker_between_content(self):
        """Bare > between content lines keeps single blockquote."""
        text = "> Line 1\n>\n> Line 2"
        result = markdown_to_html(text)
        assert result.count("<blockquote") == 1
        assert "Line 1" in result
        assert "Line 2" in result

    def test_blockquote_with_ordered_list(self):
        """Blockquote containing an ordered list."""
        text = "> 1. First\n> 2. Second"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "<ol>" in result
        assert "<li>First</li>" in result
        assert "<li>Second</li>" in result

    def test_blockquote_immediately_after_table(self):
        """Blockquote right after a table flushes the table first."""
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n\n> Quoted"
        result = markdown_to_html(text)
        assert "<table" in result
        assert "</table>" in result
        assert "<blockquote" in result
        assert "Quoted" in result
        assert result.index("</table>") < result.index("<blockquote")


class TestPrepareTables:
    """Tests for _prepare_tables pre-processing function."""

    def test_non_table_passthrough(self):
        """Non-table content passes through unchanged."""
        text = "Hello world\n\nAnother paragraph"
        assert _prepare_tables(text) == text

    def test_pipe_in_code_span_escaped(self):
        """Pipe inside code span is replaced with sentinel."""
        text = "| A | B |\n|---|---|\n| `a|b` | test |"
        result = _prepare_tables(text)
        assert "\uf000" in result
        assert "`a\uf000b`" in result

    def test_double_backtick_pipe_escaped(self):
        """Pipe inside double-backtick code span is escaped."""
        text = "| A | B |\n|---|---|\n| ``a|b`` | test |"
        result = _prepare_tables(text)
        assert "\uf000" in result

    def test_unmatched_backtick_not_escaped(self):
        """Unmatched backtick does not escape subsequent pipes."""
        text = "| A | B |\n|---|---|\n| `unclosed | val |"
        result = _prepare_tables(text)
        # The pipe after `unclosed should remain a pipe
        lines = result.split("\n")
        assert lines[2].count("|") >= 3  # At least the cell separators

    def test_short_row_padded(self):
        """Row with fewer columns than separator is padded."""
        text = "| A | B | C |\n|---|---|---|\n| 1 |"
        result = _prepare_tables(text)
        lines = result.split("\n")
        # Data row should have 3 cells
        data_cells = lines[2].strip().strip("|").split("|")
        assert len(data_cells) == 3

    def test_long_row_truncated(self):
        """Row with more columns than separator is truncated."""
        text = "| A | B |\n|---|---|\n| 1 | 2 | 3 | 4 |"
        result = _prepare_tables(text)
        lines = result.split("\n")
        data_cells = lines[2].strip().strip("|").split("|")
        assert len(data_cells) == 2

    def test_matching_columns_unchanged(self):
        """Row with correct column count is unchanged."""
        text = "| A | B |\n|---|---|\n| 1 | 2 |"
        assert _prepare_tables(text) == text

    def test_header_row_normalized(self):
        """Header row with wrong column count is normalized."""
        text = "| A |\n|---|---|\n| 1 | 2 |"
        result = _prepare_tables(text)
        lines = result.split("\n")
        header_cells = lines[0].strip().strip("|").split("|")
        assert len(header_cells) == 2

    def test_separator_like_data_row_stops_table(self):
        """A separator-like line in data rows stops table processing."""
        # Two tables back-to-back without blank line: the second
        # table's separator appears within the first table's data rows
        text = (
            "| A | B |\n|---|---|\n| 1 | 2 |\n| C | D |\n|---|---|\n| 3 | 4 |"
        )
        result = _prepare_tables(text)
        # Should process both tables
        assert result.count("|---|---|") == 2


class TestEscapeCodePipes:
    """Tests for _escape_code_pipes helper."""

    def test_single_backtick(self):
        """Pipe in single-backtick code is replaced."""
        result = _escape_code_pipes("| `a|b` | test |")
        assert "|" not in result.split("`")[1]
        assert "\uf000" in result

    def test_double_backtick(self):
        """Pipe in double-backtick code is replaced."""
        result = _escape_code_pipes("| ``a|b`` | test |")
        assert "\uf000" in result

    def test_triple_backtick(self):
        """Pipe in triple-backtick code is replaced."""
        result = _escape_code_pipes("| ```a|b``` | test |")
        assert "\uf000" in result

    def test_no_code_span(self):
        """Text without backticks is unchanged."""
        text = "| A | B |"
        assert _escape_code_pipes(text) == text

    def test_unmatched_backtick(self):
        """Unmatched backtick leaves text as-is."""
        text = "| `unclosed | val |"
        result = _escape_code_pipes(text)
        assert result == text

    def test_multiple_code_spans(self):
        """Multiple code spans with pipes are all escaped."""
        text = "| `a|b` | `c|d` |"
        result = _escape_code_pipes(text)
        assert result.count("\uf000") == 2


class TestIsSepLine:
    """Tests for _is_sep_line helper."""

    def test_simple_separator(self):
        assert _is_sep_line("|---|---|") is True

    def test_separator_no_pipes(self):
        assert _is_sep_line("---|---") is True

    def test_separator_with_alignment(self):
        assert _is_sep_line("|:---:|:---:|") is True
        assert _is_sep_line("|:---|---:|") is True

    def test_not_separator(self):
        assert _is_sep_line("| A | B |") is False

    def test_empty(self):
        assert _is_sep_line("") is False

    def test_whitespace(self):
        assert _is_sep_line("   ") is False


class TestCountColumns:
    """Tests for _count_columns helper."""

    def test_two_columns(self):
        assert _count_columns("|---|---|") == 2

    def test_three_columns(self):
        assert _count_columns("|---|---|---|") == 3

    def test_no_outer_pipes(self):
        assert _count_columns("---|---") == 2


class TestNormalizeTableRow:
    """Tests for _normalize_table_row helper."""

    def test_matching_count(self):
        """Row with correct count is unchanged."""
        row = "| A | B |"
        assert _normalize_table_row(row, 2) == row

    def test_padding(self):
        """Short row is padded."""
        result = _normalize_table_row("| A |", 3)
        cells = result.strip().strip("|").split("|")
        assert len(cells) == 3

    def test_truncation(self):
        """Long row is truncated."""
        result = _normalize_table_row("| A | B | C | D |", 2)
        cells = result.strip().strip("|").split("|")
        assert len(cells) == 2


class TestEmailRendererMethods:
    """Tests for individual EmailRenderer methods."""

    def setup_method(self):
        self.renderer = EmailRenderer()

    def test_heading_levels(self):
        """Each heading level produces correct inline styling."""
        assert (
            self.renderer.heading("T", 1) == "<strong><u>T</u></strong><br>\n"
        )
        assert (
            self.renderer.heading("T", 2)
            == "<strong><em><u>T</u></em></strong><br>\n"
        )
        assert self.renderer.heading("T", 3) == "<u>T</u><br>\n"
        assert self.renderer.heading("T", 4) == "<em><u>T</u></em><br>\n"
        assert self.renderer.heading("T", 5) == "<em>T</em><br>\n"
        assert self.renderer.heading("T", 6) == "<strong>T</strong><br>\n"

    def test_paragraph(self):
        assert self.renderer.paragraph("text") == "text<br>\n"

    def test_blank_line(self):
        assert self.renderer.blank_line() == "<br>\n"

    def test_linebreak(self):
        assert self.renderer.linebreak() == "<br>"

    def test_softbreak(self):
        assert self.renderer.softbreak() == " "

    def test_emphasis(self):
        assert self.renderer.emphasis("x") == "<em>x</em>"

    def test_strong(self):
        assert self.renderer.strong("x") == "<strong>x</strong>"

    def test_codespan_restores_sentinel(self):
        """Codespan restores pipe sentinel to actual pipe."""
        assert self.renderer.codespan("a\uf000b") == "<code>a|b</code>"

    def test_link(self):
        assert (
            self.renderer.link("text", "http://x.com")
            == '<a href="http://x.com">text</a>'
        )

    def test_image_as_link(self):
        assert (
            self.renderer.image("alt", "http://img.com")
            == '<a href="http://img.com">alt</a>'
        )

    def test_image_no_alt(self):
        assert (
            self.renderer.image("", "http://img.com")
            == '<a href="http://img.com">http://img.com</a>'
        )

    def test_inline_html_escaped(self):
        assert self.renderer.inline_html("<b>") == "&lt;b&gt;"

    def test_block_html_escaped(self):
        assert self.renderer.block_html("<div>") == "&lt;div&gt;"

    def test_block_code(self):
        assert self.renderer.block_code("x\n") == "<pre>x</pre>\n"

    def test_block_error(self):
        assert self.renderer.block_error("err") == ""

    def test_thematic_break(self):
        assert self.renderer.thematic_break() == "<hr>\n"

    def test_table_styling(self):
        assert 'style="' in self.renderer.table("content")

    def test_table_cell_th(self):
        result = self.renderer.table_cell("x", head=True)
        assert result.startswith("<th")
        assert result.endswith("</th>")

    def test_table_cell_td(self):
        result = self.renderer.table_cell("x", head=False)
        assert result.startswith("<td")
        assert result.endswith("</td>")


class TestRobustness:
    """Tests for robustness with malformed markdown input."""

    def test_unclosed_bold(self):
        """Unclosed bold passes through as literal."""
        result = markdown_to_html("**unclosed bold")
        assert "**unclosed bold" in result

    def test_unclosed_link(self):
        """Unclosed link passes through as literal."""
        result = markdown_to_html("[unclosed link(url")
        assert "[unclosed link(url" in result

    def test_mixed_broken_structures(self):
        """Multiple broken structures degrade independently."""
        text = "**bold\n\n> quote\n\n*italic"
        result = markdown_to_html(text)
        assert "<blockquote" in result
        assert "quote" in result

    def test_table_column_mismatch_handled(self):
        """Table with column mismatch is normalized by pre-processing."""
        text = "| A | B | C |\n|---|---|---|\n| 1 |"
        result = markdown_to_html(text)
        # Pre-processing pads the short row, so table renders
        assert "<table" in result
        assert ">A</th>" in result

    def test_long_line(self):
        """Very long line is handled without issues."""
        text = "x" * 10000
        result = markdown_to_html(text)
        assert len(result) == 10000

    def test_null_bytes(self):
        """Null bytes in input don't crash."""
        result = markdown_to_html("hello\x00world")
        assert "hello" in result
        assert "world" in result
