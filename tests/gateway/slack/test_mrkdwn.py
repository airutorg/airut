# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the CommonMark to Slack ``mrkdwn`` renderer."""

from mistune.core import BlockState

from airut.gateway.slack.mrkdwn import (
    SlackMrkdwnRenderer,
    _align_table_columns,
    _cell_display_width,
    _convert_tables,
    _escape,
    _is_separator_cell,
    _split_table_row,
    render_mrkdwn,
)


class TestInlineFormatting:
    def test_bold(self) -> None:
        assert render_mrkdwn("**bold**") == "*bold*"

    def test_italic_asterisk(self) -> None:
        assert render_mrkdwn("*italic*") == "_italic_"

    def test_italic_underscore(self) -> None:
        assert render_mrkdwn("_italic_") == "_italic_"

    def test_strikethrough(self) -> None:
        assert render_mrkdwn("~~strike~~") == "~strike~"

    def test_codespan_unchanged(self) -> None:
        # Code span content (including ``<`` ``>`` ``&``) passes through.
        assert render_mrkdwn("`a < b & c`") == "`a < b & c`"

    def test_bold_italic_nested(self) -> None:
        assert render_mrkdwn("**_x_**") == "*_x_*"


class TestHeadings:
    def test_h1(self) -> None:
        assert render_mrkdwn("# Title") == "*Title*"

    def test_h6(self) -> None:
        assert render_mrkdwn("###### Sub") == "*Sub*"

    def test_heading_then_paragraph(self) -> None:
        assert render_mrkdwn("# Title\n\nBody text.") == "*Title*\n\nBody text."


class TestLinks:
    def test_inline_link(self) -> None:
        assert (
            render_mrkdwn("[text](http://example.com)")
            == "<http://example.com|text>"
        )

    def test_bare_url(self) -> None:
        assert (
            render_mrkdwn("see https://example.com now")
            == "see <https://example.com> now"
        )

    def test_autolink(self) -> None:
        assert render_mrkdwn("<http://auto.test>") == "<http://auto.test>"

    def test_empty_link_text(self) -> None:
        assert render_mrkdwn("[](http://x.test)") == "<http://x.test>"

    def test_url_with_ampersand_not_escaped(self) -> None:
        # The URL passes through unescaped; only the label is escaped.
        assert (
            render_mrkdwn("[q](http://x.test?a=1&b=2)")
            == "<http://x.test?a=1&b=2|q>"
        )

    def test_image_rendered_as_link(self) -> None:
        assert (
            render_mrkdwn("![alt](http://img.test/p.png)")
            == "<http://img.test/p.png|alt>"
        )

    def test_image_without_alt(self) -> None:
        assert (
            render_mrkdwn("![](http://img.test/p.png)")
            == "<http://img.test/p.png>"
        )


class TestCodeBlocks:
    def test_fenced_drops_language(self) -> None:
        assert render_mrkdwn("```python\nx = 1\n```") == "```\nx = 1\n```"

    def test_empty_fence(self) -> None:
        assert render_mrkdwn("```\n```") == "```\n```"

    def test_indented_code_block(self) -> None:
        # Indented-code raw lacks a trailing newline; the renderer adds one.
        assert render_mrkdwn("    code line") == "```\ncode line\n```"


class TestLists:
    def test_unordered(self) -> None:
        assert render_mrkdwn("- a\n- b") == "• a\n• b"

    def test_ordered(self) -> None:
        assert render_mrkdwn("1. one\n2. two") == "1. one\n2. two"

    def test_ordered_custom_start(self) -> None:
        assert render_mrkdwn("3. three\n4. four") == "3. three\n4. four"

    def test_nested_unordered(self) -> None:
        assert (
            render_mrkdwn("- a\n- b\n  - nested\n- c")
            == "• a\n• b\n  • nested\n• c"
        )

    def test_nested_in_ordered(self) -> None:
        assert (
            render_mrkdwn("1. one\n   - sub a\n   - sub b\n2. two")
            == "1. one\n   • sub a\n   • sub b\n2. two"
        )

    def test_empty_item(self) -> None:
        assert render_mrkdwn("-\n- b") == "• \n• b"

    def test_loose_list(self) -> None:
        assert render_mrkdwn("- a\n\n- b") == "• a\n\n• b"

    def test_loose_multi_paragraph_item(self) -> None:
        assert (
            render_mrkdwn("- first\n\n  second\n\n- next")
            == "• first\n\n  second\n\n• next"
        )

    def test_loose_nested_list(self) -> None:
        assert (
            render_mrkdwn("- outer\n\n  - nested\n  - nested2\n\n- after")
            == "• outer\n\n  • nested\n  • nested2\n\n• after"
        )

    def test_task_list(self) -> None:
        assert render_mrkdwn("- [ ] todo\n- [x] done") == "• ☐ todo\n• ☑ done"


class TestBlockQuotes:
    def test_simple_quote(self) -> None:
        assert render_mrkdwn("> quote line\n> second") == (
            "> quote line\n> second"
        )

    def test_quote_with_empty_line(self) -> None:
        assert render_mrkdwn("> a\n>\n> b") == "> a\n>\n> b"


class TestThematicBreak:
    def test_dashes(self) -> None:
        assert render_mrkdwn("a\n\n---\n\nb") == "a\n\n———\n\nb"

    def test_asterisks(self) -> None:
        assert render_mrkdwn("a\n\n***\n\nb") == "a\n\n———\n\nb"


class TestEscaping:
    def test_escapes_reserved_chars(self) -> None:
        assert render_mrkdwn("a < b > c & d") == "a &lt; b &gt; c &amp; d"

    def test_inline_html_escaped(self) -> None:
        assert (
            render_mrkdwn("x <span>y</span> z")
            == "x &lt;span&gt;y&lt;/span&gt; z"
        )

    def test_block_html_escaped(self) -> None:
        assert (
            render_mrkdwn("<div>\nhi\n</div>")
            == "&lt;div&gt;\nhi\n&lt;/div&gt;"
        )

    def test_escape_helper_order(self) -> None:
        # ``&`` must be escaped first so entities are not double-escaped.
        assert _escape("<&>") == "&lt;&amp;&gt;"


class TestBreaks:
    def test_softbreak_becomes_newline(self) -> None:
        assert render_mrkdwn("line one\nline two") == "line one\nline two"

    def test_hard_linebreak(self) -> None:
        assert render_mrkdwn("line one  \nline two") == "line one\nline two"


class TestTables:
    def test_table_becomes_aligned_code_block(self) -> None:
        src = "| Name | Age |\n| --- | --- |\n| Alice | 30 |\n| Bob | 5 |"
        expected = (
            "```\n"
            "| Name  | Age |\n"
            "| ----- | --- |\n"
            "| Alice | 30  |\n"
            "| Bob   | 5   |\n"
            "```"
        )
        assert render_mrkdwn(src) == expected


class TestMisc:
    def test_empty_string(self) -> None:
        assert render_mrkdwn("") == ""

    def test_blank_lines_between_paragraphs(self) -> None:
        assert render_mrkdwn("one\n\n\ntwo") == "one\n\ntwo"

    def test_block_error_renders_empty(self) -> None:
        # ``block_error`` ignores its arguments and yields nothing.
        assert SlackMrkdwnRenderer().block_error({}, BlockState()) == ""


class TestSplitTableRow:
    def test_strips_outer_pipes(self) -> None:
        assert _split_table_row("| a | b |") == [" a ", " b "]

    def test_no_outer_pipes(self) -> None:
        assert _split_table_row("a | b") == ["a ", " b"]

    def test_pipe_in_code_span_preserved(self) -> None:
        assert _split_table_row("| `a | b` | c |") == [" `a | b` ", " c "]

    def test_double_backtick_code_span(self) -> None:
        assert _split_table_row("| ``a | b`` | c |") == [" ``a | b`` ", " c "]

    def test_unmatched_backtick(self) -> None:
        # An unclosed backtick has no closing run, so it stays literal.
        assert _split_table_row("| a`b | c |") == [" a`b ", " c "]


class TestIsSeparatorCell:
    def test_dashes(self) -> None:
        assert _is_separator_cell("---") is True

    def test_colons(self) -> None:
        assert _is_separator_cell(":-:") is True

    def test_text(self) -> None:
        assert _is_separator_cell("abc") is False

    def test_empty(self) -> None:
        assert _is_separator_cell("   ") is False


class TestCellDisplayWidth:
    def test_ascii(self) -> None:
        assert _cell_display_width("abc") == 3

    def test_wide_characters(self) -> None:
        # CJK characters occupy two columns each.
        assert _cell_display_width("中文") == 4

    def test_combining_marks_ignored(self) -> None:
        # ``e`` + combining acute accent renders as one column.
        assert _cell_display_width("é") == 1


class TestAlignTableColumns:
    def test_aligns_and_preserves_trailing_newline(self) -> None:
        table = "| a | bb |\n| --- | --- |\n| ccc | d |\n"
        result = _align_table_columns(table)
        assert result.endswith("\n")
        lines = result.split("\n")
        # Separator cells force a minimum column width of three.
        assert lines[0] == "| a   | bb  |"
        assert lines[1] == "| --- | --- |"
        assert lines[2] == "| ccc | d   |"

    def test_no_trailing_newline(self) -> None:
        table = "| a | b |\n| - | - |"
        result = _align_table_columns(table)
        assert not result.endswith("\n")

    def test_preserves_alignment_colons(self) -> None:
        table = "| a | b | c |\n| :-- | --: | :-: |\n| 1 | 2 | 3 |"
        result = _align_table_columns(table)
        sep = result.split("\n")[1]
        assert ":--" in sep
        assert "--:" in sep
        assert ":-:" in sep

    def test_pads_short_rows(self) -> None:
        # A data row with fewer columns than the header is padded.
        table = "| a | b |\n| - | - |\n| only |"
        result = _align_table_columns(table)
        # Three columns positions kept consistent across rows.
        assert all(line.count("|") == 3 for line in result.split("\n"))


class TestConvertTables:
    def test_wraps_table_in_code_fence(self) -> None:
        src = "| a | b |\n| - | - |\n| 1 | 2 |\n"
        result = _convert_tables(src)
        assert result.startswith("```\n")
        assert result.rstrip().endswith("```")

    def test_non_table_text_unchanged(self) -> None:
        src = "just a paragraph\n\nanother one"
        assert _convert_tables(src) == src
