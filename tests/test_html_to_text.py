# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for HTML to text conversion."""

from lib.html_to_text import html_to_text


def test_empty_input() -> None:
    """Test that empty input returns empty output."""
    assert html_to_text("") == ""


def test_plain_text_passthrough() -> None:
    """Test that plain text without HTML is passed through."""
    assert html_to_text("Hello world") == "Hello world"


def test_paragraph_tags() -> None:
    """Test paragraph tag conversion to double newlines."""
    result = html_to_text("<p>First paragraph.</p><p>Second paragraph.</p>")
    assert "First paragraph." in result
    assert "Second paragraph." in result
    assert "\n\n" in result


def test_br_tags() -> None:
    """Test line break conversion."""
    result = html_to_text("Line one<br>Line two<br/>Line three")
    assert "Line one\n" in result
    assert "Line two\n" in result
    assert "Line three" in result


def test_bold_strong() -> None:
    """Test <strong> conversion to markdown bold."""
    result = html_to_text("This is <strong>important</strong> text.")
    assert result == "This is **important** text."


def test_bold_b() -> None:
    """Test <b> conversion to markdown bold."""
    result = html_to_text("This is <b>bold</b> text.")
    assert result == "This is **bold** text."


def test_italic_em() -> None:
    """Test <em> conversion to markdown italic."""
    result = html_to_text("This is <em>emphasized</em> text.")
    assert result == "This is *emphasized* text."


def test_italic_i() -> None:
    """Test <i> conversion to markdown italic."""
    result = html_to_text("This is <i>italic</i> text.")
    assert result == "This is *italic* text."


def test_inline_code() -> None:
    """Test <code> conversion to backtick."""
    result = html_to_text("Use the <code>print()</code> function.")
    assert result == "Use the `print()` function."


def test_preformatted_block() -> None:
    """Test <pre> conversion to fenced code block."""
    result = html_to_text("<pre>def hello():\n    print('hi')</pre>")
    assert "```" in result
    assert "def hello():" in result
    assert "    print('hi')" in result


def test_preformatted_with_code_tag() -> None:
    """Test <pre><code> combination."""
    result = html_to_text("<pre><code>x = 1\ny = 2</code></pre>")
    assert "```" in result
    assert "x = 1" in result
    assert "y = 2" in result


def test_link() -> None:
    """Test <a> conversion to markdown link."""
    result = html_to_text('Click <a href="https://example.com">here</a>.')
    assert result == "Click [here](https://example.com)."


def test_link_no_href() -> None:
    """Test <a> without href is treated as plain text."""
    result = html_to_text("An <a>anchor</a> without link.")
    assert result == "An anchor without link."


def test_heading_h1() -> None:
    """Test h1 heading conversion."""
    result = html_to_text("<h1>Title</h1>")
    assert "# Title" in result


def test_heading_h2() -> None:
    """Test h2 heading conversion."""
    result = html_to_text("<h2>Subtitle</h2>")
    assert "## Subtitle" in result


def test_heading_h3() -> None:
    """Test h3 heading conversion."""
    result = html_to_text("<h3>Section</h3>")
    assert "### Section" in result


def test_unordered_list() -> None:
    """Test <ul>/<li> conversion."""
    html = "<ul><li>First</li><li>Second</li><li>Third</li></ul>"
    result = html_to_text(html)
    assert "- First" in result
    assert "- Second" in result
    assert "- Third" in result


def test_ordered_list() -> None:
    """Test <ol>/<li> conversion."""
    html = "<ol><li>First</li><li>Second</li><li>Third</li></ol>"
    result = html_to_text(html)
    assert "1. First" in result
    assert "2. Second" in result
    assert "3. Third" in result


def test_simple_table() -> None:
    """Test basic table conversion."""
    html = """
    <table>
        <tr><th>Name</th><th>Value</th></tr>
        <tr><td>foo</td><td>1</td></tr>
        <tr><td>bar</td><td>2</td></tr>
    </table>
    """
    result = html_to_text(html)
    assert "| Name | Value |" in result
    assert "| --- | --- |" in result
    assert "| foo | 1 |" in result
    assert "| bar | 2 |" in result


def test_table_without_header() -> None:
    """Test table with only td cells (no th)."""
    html = """
    <table>
        <tr><td>a</td><td>b</td></tr>
        <tr><td>c</td><td>d</td></tr>
    </table>
    """
    result = html_to_text(html)
    assert "| a | b |" in result
    assert "| c | d |" in result
    # No separator line when there's no header
    assert "---" not in result


def test_html_entities() -> None:
    """Test HTML entity decoding."""
    result = html_to_text("&amp; &lt; &gt; &quot; &#39;")
    assert "& < > \" '" == result


def test_nbsp_entity() -> None:
    """Test non-breaking space entity."""
    result = html_to_text("hello&nbsp;world")
    assert "hello" in result
    assert "world" in result


def test_script_and_style_stripped() -> None:
    """Test that script and style content is excluded."""
    html = """
    <p>Visible text</p>
    <script>alert('hidden')</script>
    <style>.hidden { display: none; }</style>
    <p>More visible text</p>
    """
    result = html_to_text(html)
    assert "Visible text" in result
    assert "More visible text" in result
    assert "alert" not in result
    assert "display" not in result


def test_whitespace_collapsing() -> None:
    """Test that excessive whitespace is collapsed."""
    result = html_to_text("Hello    world    test")
    assert result == "Hello world test"


def test_div_newlines() -> None:
    """Test that div elements create newlines."""
    result = html_to_text("<div>First</div><div>Second</div>")
    assert "First\n" in result
    assert "Second" in result


def test_hr_tag() -> None:
    """Test horizontal rule conversion."""
    result = html_to_text("<p>Above</p><hr><p>Below</p>")
    assert "---" in result
    assert "Above" in result
    assert "Below" in result


def test_nested_formatting() -> None:
    """Test nested bold and italic."""
    result = html_to_text("<b><i>bold italic</i></b>")
    assert result == "***bold italic***"


def test_outlook_style_html() -> None:
    """Test realistic Outlook-style HTML email body."""
    html = """
    <html>
    <head><style>body { font-family: Calibri; }</style></head>
    <body>
    <p>Hi there,</p>
    <p>Please take a look at the <b>attached report</b> and let me know
    if you have any questions.</p>
    <p>Key findings:</p>
    <ul>
    <li>Revenue increased by <em>15%</em></li>
    <li>Costs decreased by <em>3%</em></li>
    </ul>
    <p>Thanks,<br>John</p>
    </body>
    </html>
    """
    result = html_to_text(html)
    assert "Hi there," in result
    assert "**attached report**" in result
    assert "- Revenue increased by *15%*" in result
    assert "- Costs decreased by *3%*" in result
    assert "Thanks," in result
    assert "John" in result
    # Style content should not appear
    assert "Calibri" not in result


def test_multiple_newlines_collapsed() -> None:
    """Test that excessive newlines are collapsed to at most two."""
    html = "<p>First</p><p></p><p></p><p></p><p>Last</p>"
    result = html_to_text(html)
    assert "\n\n\n" not in result
    assert "First" in result
    assert "Last" in result


def test_table_uneven_rows() -> None:
    """Test table with rows of different cell counts."""
    html = """
    <table>
        <tr><th>A</th><th>B</th><th>C</th></tr>
        <tr><td>1</td><td>2</td></tr>
    </table>
    """
    result = html_to_text(html)
    assert "| A | B | C |" in result
    # Short row should be padded
    assert "| 1 | 2 |" in result


def test_empty_table() -> None:
    """Test empty table produces no output."""
    result = html_to_text("<table></table>")
    assert result == ""


def test_link_with_entities_in_url() -> None:
    """Test link with HTML entities in URL."""
    html = '<a href="https://example.com?a=1&amp;b=2">link</a>'
    result = html_to_text(html)
    assert "[link](https://example.com?a=1&b=2)" == result


def test_blockquote() -> None:
    """Test blockquote creates newlines."""
    result = html_to_text(
        "<p>Before</p><blockquote>Quoted text</blockquote><p>After</p>"
    )
    assert "Before" in result
    assert "Quoted text" in result
    assert "After" in result
