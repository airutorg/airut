# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for HTML to text conversion and HTML quote stripping."""

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


# --- strip_quotes=True tests ---


def test_strip_quotes_no_quotes() -> None:
    """Test that HTML without quote markers passes through unchanged."""
    html = "<html><body><p>Hello world</p></body></html>"
    result = html_to_text(html, strip_quotes=True)
    assert "Hello world" in result
    assert "[quoted text removed]" not in result


def test_strip_quotes_disabled_by_default() -> None:
    """Test that quotes are preserved when strip_quotes is False."""
    html = (
        "<html><body>"
        "<div>My reply</div>"
        '<div id="mail-editor-reference-message-container">'
        "<div>Quoted content</div>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html)
    assert "My reply" in result
    assert "Quoted content" in result
    assert "[quoted text removed]" not in result


def test_strip_quotes_outlook_mobile() -> None:
    """Test stripping Outlook web/mobile reply container."""
    html = (
        "<html><body>"
        "<div>My reply</div>"
        '<div id="mail-editor-reference-message-container">'
        "<div>Quoted content</div>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "My reply" in result
    assert "Quoted content" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_outlook_desktop() -> None:
    """Test stripping Outlook desktop reply divider."""
    html = (
        "<html><body>"
        "<p>My reply text</p>"
        '<div id="divRplyFwdMsg" style="color: black;">'
        "<b>From:</b> Someone<br>"
        "<b>Sent:</b> Yesterday<br>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "My reply text" in result
    assert "Someone" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_gmail() -> None:
    """Test stripping Gmail quote container."""
    html = (
        "<html><body>"
        "<div>My reply to your message</div>"
        '<div class="gmail_quote">'
        '<div class="gmail_attr">'
        "On Mon, Jan 1, 2026, Bob wrote:"
        "</div>"
        "<blockquote>Original message</blockquote>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "My reply to your message" in result
    assert "Original message" not in result
    assert "Bob wrote" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_gmail_extra_classes() -> None:
    """Test Gmail quote with additional CSS classes."""
    html = (
        "<html><body>"
        "<div>Reply</div>"
        '<div class="gmail_extra gmail_quote">'
        "<p>Quoted text</p>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "Reply" in result
    assert "Quoted text" not in result


def test_strip_quotes_yahoo() -> None:
    """Test stripping Yahoo Mail quote container."""
    html = (
        "<html><body>"
        "<div>My response</div>"
        '<div class="yahoo_quoted">'
        "<p>Previous message</p>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "My response" in result
    assert "Previous message" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_thunderbird() -> None:
    """Test stripping Thunderbird moz-cite-prefix and blockquote cite."""
    html = (
        "<html><body>"
        "<p>Here is my reply.</p>"
        '<div class="moz-cite-prefix">'
        "On 2026-01-01, Alice wrote:"
        "</div>"
        '<blockquote type="cite">'
        "<p>Original message from Alice</p>"
        "</blockquote>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "Here is my reply." in result
    assert "Alice wrote" not in result
    assert "Original message from Alice" not in result


def test_strip_quotes_apple_mail() -> None:
    """Test stripping Apple Mail blockquote type=cite."""
    html = (
        "<html><body>"
        "<div>Thanks for the update.</div>"
        '<blockquote type="cite">'
        "<div>The original email content here</div>"
        "</blockquote>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "Thanks for the update." in result
    assert "The original email content here" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_inline_reply() -> None:
    """Test inline reply preserves quote content as markdown blockquotes.

    When non-quote content follows a quote block (inline reply pattern),
    the quote is rendered as "> " prefixed lines so the LLM sees what
    the user replied to.
    """
    html = (
        "<html><body>"
        "<p>I agree with point 1.</p>"
        '<blockquote type="cite">'
        "<p>Point 1: We should refactor.</p>"
        "</blockquote>"
        "<p>But point 2 needs more thought.</p>"
        '<blockquote type="cite">'
        "<p>Point 2: We should rewrite.</p>"
        "</blockquote>"
        "<p>Let's discuss tomorrow.</p>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "I agree with point 1." in result
    assert "But point 2 needs more thought." in result
    assert "Let's discuss tomorrow." in result
    # Quotes followed by non-quote content are rendered as blockquotes
    assert "> Point 1: We should refactor." in result
    assert "> Point 2: We should rewrite." in result
    assert "[quoted text removed]" not in result


def test_strip_quotes_bottom_posting() -> None:
    """Test bottom-posting: quote at top, reply at bottom.

    The quote is followed by non-quote content (the reply), so it
    should be rendered as a markdown blockquote.
    """
    html = (
        "<html><body>"
        '<div class="gmail_quote">'
        "<p>Original question from the sender</p>"
        "</div>"
        "<p>Here is my answer at the bottom.</p>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "> Original question from the sender" in result
    assert "Here is my answer at the bottom." in result
    assert "[quoted text removed]" not in result


def test_strip_quotes_trailing_only() -> None:
    """Test top-posting: reply at top, trailing quote at bottom.

    The trailing quote has no non-quote content after it, so it
    should be replaced with "[quoted text removed]".
    """
    html = (
        "<html><body>"
        "<p>Sounds good, let's proceed.</p>"
        '<blockquote type="cite">'
        "<p>Should we go ahead with the plan?</p>"
        "</blockquote>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "Sounds good, let's proceed." in result
    assert "Should we go ahead" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_inline_then_trailing() -> None:
    """Test mix of inline reply and trailing quote.

    First quote is followed by a reply (rendered as blockquote),
    second quote is trailing (replaced with marker).
    """
    html = (
        "<html><body>"
        '<blockquote type="cite">'
        "<p>What about feature X?</p>"
        "</blockquote>"
        "<p>Feature X is done.</p>"
        '<blockquote type="cite">'
        "<p>And feature Y?</p>"
        "</blockquote>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    # First quote is followed by reply → blockquote
    assert "> What about feature X?" in result
    assert "Feature X is done." in result
    # Second quote is trailing → marker
    assert "And feature Y" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_inline_reply_bare_text() -> None:
    """Test inline reply where bare text follows a quote block.

    When text content directly follows a quote block without an
    enclosing tag, the pending quote is flushed from handle_data.
    """
    html = (
        '<blockquote type="cite">'
        "<p>Original question</p>"
        "</blockquote>"
        "My bare text reply"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "> Original question" in result
    assert "My bare text reply" in result
    assert "[quoted text removed]" not in result


def test_strip_quotes_empty_quote_block() -> None:
    """Test that an empty quote block followed by content is handled."""
    html = '<blockquote type="cite"></blockquote><p>Reply after empty quote</p>'
    result = html_to_text(html, strip_quotes=True)
    assert "Reply after empty quote" in result
    assert "[quoted text removed]" not in result


def test_strip_quotes_case_insensitive() -> None:
    """Test that quote detection is case-insensitive."""
    html = (
        "<HTML><BODY>"
        "<P>Reply</P>"
        '<DIV ID="mail-editor-reference-message-container">'
        "<P>Quoted</P>"
        "</DIV>"
        "</BODY></HTML>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "Reply" in result
    assert "Quoted" not in result


def test_strip_quotes_single_quotes_attr() -> None:
    """Test that single-quoted attribute values are handled."""
    html = (
        "<html><body>"
        "<p>Reply</p>"
        "<div id='mail-editor-reference-message-container'>"
        "<p>Quoted</p>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "Reply" in result
    assert "Quoted" not in result


def test_strip_quotes_realistic_outlook() -> None:
    """Test with realistic Outlook web/mobile HTML structure."""
    html = (
        "<html><head>"
        '<meta http-equiv="Content-Type"'
        ' content="text/html; charset=utf-8">'
        "</head><body>"
        '<div style="direction: ltr; font-family: Aptos;">'
        "<span>Can you run the analysis?</span>"
        "</div>"
        '<div id="mail-editor-reference-message-container" '
        'style="color: inherit;">'
        '<div class="ms-outlook-mobile-reference-message">'
        "</div>"
        '<div class="ms-outlook-mobile-reference-message" '
        'style="border-top: 1pt solid;">'
        "<b>From: </b>Bot &lt;bot@example.com&gt;<br>"
        "<b>Date: </b>Tuesday, 10. February 2026<br>"
        "</div>"
        '<div class="ms-outlook-mobile-reference-message">'
        "All done. Here is a summary."
        "</div>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "Can you run the analysis?" in result
    assert "All done" not in result
    assert "bot@example.com" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_regular_blockquote_preserved() -> None:
    """Test that a plain blockquote (no type=cite) is not stripped."""
    html = (
        "<html><body>"
        "<p>As Einstein said:</p>"
        "<blockquote>Imagination is more important.</blockquote>"
        "<p>I agree.</p>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)
    assert "As Einstein said:" in result
    assert "Imagination is more important." in result
    assert "I agree." in result
    assert "[quoted text removed]" not in result


def test_strip_quotes_outlook_with_list_siblings() -> None:
    """Test Outlook quote container with <ul> siblings of inner <div>s.

    Real Outlook emails place <ul>/<li> elements as direct children of
    the quote container alongside <div> children. The nesting tracker
    must not be confused by non-div elements or close the quote
    container prematurely when an inner </div> brings the depth to 0.
    """
    html = (
        "<html><head>"
        '<meta http-equiv="Content-Type"'
        ' content="text/html; charset=us-ascii">'
        "</head><body>"
        '<div style="font-family: Aptos; font-size: 12pt;">'
        "How long is our README file?</div>"
        '<div style="font-family: Aptos; font-size: 12pt;"><br></div>'
        '<div id="mail-editor-reference-message-container">'
        '<div class="ms-outlook-mobile-reference-message">'
        "</div>"
        '<div class="ms-outlook-mobile-reference-message"'
        ' style="border-top: 1pt solid;">'
        "<b>From: </b>Bot &lt;bot@example.com&gt;<br>"
        "<b>Date: </b>Wednesday, 11. February 2026 at 9.18<br>"
        "<b>To: </b>User &lt;user@example.com&gt;<br>"
        "<b>Subject: </b>Re: [ID:abc123] Hello<br><br>"
        "</div>"
        '<div class="ms-outlook-mobile-reference-message">'
        "Hello! I'm the assistant. I can help with:<br><br>"
        "</div>"
        "<ul>"
        "<li><b>Bug fixes</b> in the codebase</li>"
        "<li><b>Code review</b> and analysis</li>"
        "<li><b>Running checks</b> and CI</li>"
        "</ul>"
        '<div class="ms-outlook-mobile-reference-message"><br>'
        "What can I help you with?<br><br>"
        "<i>Cost: $0.04</i></div>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)

    assert "How long is our README file?" in result
    # All quoted content must be stripped
    assert "Bot" not in result
    assert "bot@example.com" not in result
    assert "assistant" not in result
    assert "Bug fixes" not in result
    assert "Code review" not in result
    assert "What can I help you with" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_gmail_real_structure() -> None:
    """Test Gmail quote with nested gmail_quote containers and rich content.

    Real Gmail replies use a two-level structure:
    - Outer: <div class="gmail_quote gmail_quote_container">
    - Attribution: <div class="gmail_attr">On ... wrote:</div>
    - Inner: <blockquote class="gmail_quote">content</blockquote>

    The outer div is the quote container. The inner blockquote is a
    child element with the same class name. The parser must consume
    the entire tree including tables, lists, and formatting inside
    the inner blockquote.
    """
    html = (
        '<div dir="ltr">What is the size of our README file?</div>'
        "<br>"
        '<div class="gmail_quote gmail_quote_container">'
        '<div dir="ltr" class="gmail_attr">'
        "On Wed, Feb 11, 2026 at 9:18 AM Bot"
        " &lt;bot@example.com&gt; wrote:<br>"
        "</div>"
        '<blockquote class="gmail_quote"'
        ' style="margin:0px 0px 0px 0.8ex;'
        "border-left:1px solid rgb(204,204,204);"
        'padding-left:1ex">'
        "<strong><u>ProjectName</u></strong><br><br>"
        "This is <strong>ProjectName</strong> — a diagnostic"
        " log analyzer, built as both a <strong>web app</strong>"
        " and a <strong>desktop app</strong>.<br><br>"
        "<strong>Project structure</strong><br><br>"
        "It&#39;s a monorepo with npm workspaces:<br><br>"
        "<table><tbody>"
        "<tr><th>Package</th><th>Purpose</th></tr>"
        "<tr><td><code>/app</code></td>"
        "<td>React frontend</td></tr>"
        "<tr><td><code>/parser</code></td>"
        "<td>Log parsing library</td></tr>"
        "<tr><td><code>/api</code></td>"
        "<td>API backend</td></tr>"
        "</tbody></table><br>"
        "<strong>Key capabilities</strong><br><br>"
        "<ul>"
        "<li><strong>Log parsing</strong> — Extracts data</li>"
        "<li><strong>Issue detection</strong> — Finds problems</li>"
        "<li><strong>AI analysis</strong> — Deep diagnostics</li>"
        "</ul><br>"
        "<strong>Tech stack</strong><br><br>"
        "<ul>"
        "<li>TypeScript throughout</li>"
        "<li>React + Vite for the frontend</li>"
        "<li>Vitest for testing</li>"
        "</ul><br>"
        "Let me know if you&#39;d like to dive deeper.<br><br>"
        "<em>Cost: $0.05</em>"
        "</blockquote>"
        "</div>"
    )
    result = html_to_text(html, strip_quotes=True)

    assert "What is the size of our README file?" in result
    # All quoted content must be stripped
    assert "bot@example.com" not in result
    assert "ProjectName" not in result
    assert "monorepo" not in result
    assert "Log parsing" not in result
    assert "TypeScript" not in result
    assert "Cost" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_outlook_complex_quoted_reply() -> None:
    """Test Outlook quote with rich formatting, code, and lists.

    Real Outlook quoted messages often contain complex formatting
    including <code>, <b>, <i>, and <ul>/<li> elements mixed with
    <div> siblings inside the quote container.
    """
    html = (
        "<html><head>"
        '<meta http-equiv="Content-Type"'
        ' content="text/html; charset=us-ascii">'
        "</head><body>"
        '<div style="font-family: Aptos; font-size: 12pt;">'
        '<span style="color: rgb(0, 0, 0);">'
        "Can you run the tests to verify the fix?</span>"
        "<span><br><br></span></div>"
        '<div style="font-family: Aptos; font-size: 12pt;"><br></div>'
        '<div id="mail-editor-reference-message-container"'
        ' style="color: inherit;">'
        '<div class="ms-outlook-mobile-reference-message">'
        "</div>"
        '<div class="ms-outlook-mobile-reference-message"'
        ' style="border-top: 1pt solid;">'
        "<b>From: </b>Bot &lt;bot@example.com&gt;<br>"
        "<b>Date: </b>Tuesday, 10. February 2026 at 20.41<br>"
        "<b>To: </b>User &lt;user@example.com&gt;<br>"
        "<b>Subject: </b>Re: [ID:def456] Analysis report<br><br>"
        "</div>"
        '<div class="ms-outlook-mobile-reference-message">'
        "All done. Here is a summary:<br><br>"
        "<b>Changes Made</b><br><br>"
        "<b>Review:</b>&nbsp;https://review.example.com/+/12345<br>"
        "<b>CI:</b>&nbsp;Passed (Verified: +1)<br><br>"
        "<b><i>Problem</i></b><br><br>"
        "The analyzer had a blind spot: it detected resets only via the "
        "<code>SystemController::requestPower</code>&nbsp;path. "
        "When the daemon triggered a reset through the "
        "<b>recovery path</b>&nbsp;"
        "(<code>health check failure</code>), "
        "the command went through "
        "<code>StackAccess::sendResetRequest</code>&nbsp;instead.<br><br>"
        "<b><i>Fix</i></b><br><br>"
        "<b><code>parser/src/analyzers/restartAnalyzer.ts</code>:</b>"
        "</div>"
        "<ul>"
        "<li>Added a new regex matching reset log entries</li>"
        "<li>Extended <code>hasIntentionalReset()</code>&nbsp;to check "
        "both log sources</li>"
        "<li>Updated the finding description</li>"
        "</ul>"
        '<div class="ms-outlook-mobile-reference-message"><br>'
        "<b><code>parser/src/analyzers/restartAnalyzer.test.ts</code>:"
        "</b></div>"
        "<ul>"
        "<li>Added test: daemon-initiated reset detected as intentional</li>"
        "<li>Added test: daemon reset takes priority over error codes</li>"
        "<li>Updated existing assertion to match refined wording</li>"
        "</ul>"
        '<div class="ms-outlook-mobile-reference-message"><br>'
        "<b><i>Validation</i></b><br><br>"
        "Ran against the original diagnostics file. The session is now "
        "correctly classified as intentional (Warning) instead of "
        "error (Error).<br><br>"
        "<i>Cost: $4.41</i></div>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)

    assert "Can you run the tests to verify the fix?" in result
    # All quoted content must be stripped
    assert "bot@example.com" not in result
    assert "All done" not in result
    assert "blind spot" not in result
    assert "SystemController" not in result
    assert "restartAnalyzer" not in result
    assert "daemon-initiated" not in result
    assert "Validation" not in result
    assert "Cost" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_mixed_client_nesting() -> None:
    """Test deep nesting of different client containers.

    Scenario:
    1. Gmail wrapper (outermost)
    2. Outlook wrapper (inside Gmail)
    3. Thunderbird wrapper (inside Outlook)

    Expected: The entire tree is stripped because it is all contained
    within the top-level Gmail quote block.
    """
    html = (
        "<html><body>"
        "<p>Top level reply.</p>"
        '<div class="gmail_quote">'
        '<div class="gmail_attr">On Jan 1, Outlook User wrote:</div>'
        '<div id="divRplyFwdMsg">'
        "<p>Forwarded message:</p>"
        '<div class="moz-cite-prefix">On Dec 31, TB User wrote:</div>'
        '<blockquote type="cite">'
        "<p>Original content.</p>"
        "</blockquote>"
        "</div>"
        "</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)

    assert "Top level reply." in result
    # Ensure inner content is NOT leaked
    assert "Outlook User" not in result
    assert "Forwarded message" not in result
    assert "Original content" not in result
    # Should only see one removal marker for the whole block
    assert result.count("[quoted text removed]") == 1


def test_strip_quotes_trailing_whitespace_not_flushed() -> None:
    """Test that trailing breaks/whitespace do NOT trigger quote flushing.

    A quote block followed only by <br> tags or whitespace should be
    treated as a trailing quote (replaced with marker), not flushed as
    a markdown blockquote. This is important because real email clients
    often insert whitespace or <br> between the quote container and
    the closing </body> tag.
    """
    html = (
        "<html><body>"
        "<p>My Reply.</p>"
        '<div class="gmail_quote">'
        "<p>Old history.</p>"
        "</div>"
        "<br>"
        "   "
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)

    assert "My Reply." in result
    # Whitespace-only content does not trigger inline reply detection
    assert "Old history" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_interleaved_conversation() -> None:
    """Test multiple distinct quote blocks separated by replies.

    Scenario:
    - Quote 1 (Point A)
    - Reply 1 (Answer to A)
    - Quote 2 (Point B)
    - Reply 2 (Answer to B)
    - Quote 3 (Signature/History - Trailing)
    """
    html = (
        "<html><body>"
        '<blockquote type="cite">Is the server up?</blockquote>'
        "<p>Yes, it is.</p>"
        '<blockquote type="cite">Did you check the logs?</blockquote>'
        "<p>Checking now.</p>"
        '<blockquote type="cite">Original Footer info...</blockquote>'
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)

    # First quote -> Flushed because Reply 1 follows
    assert "> Is the server up?" in result
    assert "Yes, it is." in result

    # Second quote -> Flushed because Reply 2 follows
    assert "> Did you check the logs?" in result
    assert "Checking now." in result

    # Third quote -> Stripped because nothing follows
    assert "Original Footer info" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_outlook_desktop_sibling_body() -> None:
    """Test Outlook desktop divRplyFwdMsg with quoted body in sibling elements.

    Outlook desktop puts the From/Sent/To/Subject header inside
    <div id="divRplyFwdMsg">, but the actual quoted message body is in
    a separate sibling <div> after it. The quote boundary detection must
    suppress both the header div and all subsequent sibling content.
    """
    html = (
        "<html><body>"
        "<div><p>Sounds good, let's proceed.</p></div>"
        "<hr>"
        '<div id="divRplyFwdMsg" dir="ltr">'
        '<font face="Calibri, sans-serif" style="font-size:11pt">'
        "<b>From:</b> Bot &lt;bot@example.com&gt;<br>"
        "<b>Sent:</b> Monday, January 5, 2026 3:00 PM<br>"
        "<b>To:</b> User &lt;user@example.com&gt;<br>"
        "<b>Subject:</b> Re: Analysis report</font>"
        "<div>&nbsp;</div>"
        "</div>"
        "<div>The analysis is complete. Here are the results:<br><br>"
        "<strong>Summary</strong><br><br>"
        "Found 5 issues across 3 modules.<br><br>"
        "<ol>"
        "<li><strong>Module A</strong> has a memory leak</li>"
        "<li><strong>Module B</strong> has a race condition</li>"
        "<li><strong>Module C</strong> needs refactoring</li>"
        "</ol><br>"
        "Reply to approve the fix plan.<br><br>"
        "<em>Cost: $1.50</em></div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)

    assert "Sounds good, let's proceed." in result
    # All quoted content (both header and body sibling) must be stripped
    assert "bot@example.com" not in result
    assert "Analysis report" not in result
    assert "analysis is complete" not in result
    assert "memory leak" not in result
    assert "race condition" not in result
    assert "Module C" not in result
    assert "Cost" not in result
    assert "[quoted text removed]" in result


def test_strip_quotes_outlook_desktop_boundary_with_signature() -> None:
    """Test Outlook desktop with signature div before the quote boundary.

    Outlook mobile inserts a body-separator div and a signature div
    between the user's reply and the quoted content. These should be
    preserved while everything from divRplyFwdMsg onward is stripped.
    """
    html = (
        "<html><body>"
        '<div style="font-family: Aptos; font-size: 12pt;">'
        "Please go ahead.</div>"
        '<div id="body-separator"><br></div>'
        '<div id="signature"><div></div></div>'
        "<hr>"
        '<div id="divRplyFwdMsg" dir="ltr">'
        "<b>From:</b> Assistant &lt;assistant@example.com&gt;<br>"
        "<b>Sent:</b> Tuesday, February 3, 2026 10:00 AM<br>"
        "</div>"
        "<div>Here is the detailed report with findings.</div>"
        "</body></html>"
    )
    result = html_to_text(html, strip_quotes=True)

    assert "Please go ahead." in result
    assert "assistant@example.com" not in result
    assert "detailed report" not in result
    assert "[quoted text removed]" in result
