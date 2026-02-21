# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for Slack message sanitization."""

from airut.gateway.slack.sanitize import (
    _align_table_columns,
    _convert_horizontal_rules,
    _convert_tables,
    _linkify_bare_urls,
    _strip_code_fence_languages,
    sanitize_for_slack,
)


def _display_width(text: str) -> int:
    """Compute the monospace display width of *text*.

    Test-only helper that mirrors the production ``_cell_display_width``
    logic: East Asian Wide/Fullwidth characters count as 2, combining
    marks as 0, everything else as 1.
    """
    import unicodedata

    width = 0
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("M"):  # combining marks
            continue
        eaw = unicodedata.east_asian_width(ch)
        width += 2 if eaw in ("W", "F") else 1
    return width


def _split_row_for_test(line: str) -> list[str]:
    """Split a table row into cells, respecting inline code spans.

    Helper for tests only — mirrors the production cell-splitting logic.
    """
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]

    cells: list[str] = []
    current: list[str] = []
    in_code = False
    i = 0
    while i < len(stripped):
        ch = stripped[i]
        if ch == "`" and not in_code:
            in_code = True
            current.append(ch)
        elif ch == "`" and in_code:
            in_code = False
            current.append(ch)
        elif ch == "|" and not in_code:
            cells.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    cells.append("".join(current))
    return cells


class TestAlignTableColumns:
    def test_simple_alignment(self) -> None:
        table = "| A | B |\n|---|---|\n| 1 | 2 |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # All lines should have equal length
        assert len(set(len(line) for line in lines)) == 1

    def test_uneven_columns_padded(self) -> None:
        table = "| Name | Value |\n|---|---|\n| x | long content here |"
        result = _align_table_columns(table)
        # Column widths should be uniform across rows
        assert "| Name | Value             |" in result
        assert "| x    | long content here |" in result

    def test_separator_row_aligned(self) -> None:
        table = "| Name | Value |\n|---|---|\n| foo | bar |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # Separator row should use dashes to fill
        sep_line = lines[1]
        assert sep_line.startswith("|")
        assert sep_line.endswith("|")
        # Each separator cell should be filled with dashes
        cells = sep_line.strip("|").split("|")
        for cell in cells:
            stripped = cell.strip()
            assert all(c in "-:" for c in stripped)

    def test_already_aligned_unchanged(self) -> None:
        table = "| Foo | Bar |\n| --- | --- |\n| aaa | bbb |"
        result = _align_table_columns(table)
        assert result == table

    def test_three_columns(self) -> None:
        table = "| A | Bee | Cee |\n|---|---|---|\n| long | xxx | yyy |"
        result = _align_table_columns(table)
        assert "| A    | Bee | Cee |" in result
        assert "| long | xxx | yyy |" in result

    def test_many_rows(self) -> None:
        table = "| Col |\n|---|\n| short |\n| very long content |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # All rows should have same width
        lengths = [len(line) for line in lines]
        assert len(set(lengths)) == 1

    def test_empty_cells(self) -> None:
        table = "| A | B |\n|---|---|\n| x |  |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        assert len(set(len(line) for line in lines)) == 1

    def test_pipe_in_inline_code_ignored(self) -> None:
        """Pipes inside backticks should not be treated as column separators."""
        table = "| Code | Desc |\n|---|---|\n| `a|b` | test |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # The `a|b` should remain intact
        assert "`a|b`" in result
        # Should still have exactly 2 columns
        header_cells = _split_row_for_test(lines[0])
        assert len(header_cells) == 2

    def test_pipe_in_inline_code_column_width(self) -> None:
        """Column width should use display width, counting `a|b` as 5 chars."""
        table = "| Code | Desc |\n|---|---|\n| `a|b` | test |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # All lines should have the same width
        assert len(set(len(line) for line in lines)) == 1

    def test_multiple_inline_code_with_pipes(self) -> None:
        """Multiple inline code spans with pipes in same row."""
        table = "| A | B |\n|---|---|\n| `x|y` | `a|b|c` |"
        result = _align_table_columns(table)
        assert "`x|y`" in result
        assert "`a|b|c`" in result
        lines = result.split("\n")
        assert len(set(len(line) for line in lines)) == 1

    def test_separator_with_alignment_colons(self) -> None:
        """Separator colons (left/right/center align) should be preserved."""
        table = "| Left | Center | Right |\n|:---|:---:|---:|\n| a | b | c |"
        result = _align_table_columns(table)
        sep_line = result.split("\n")[1]
        cells = sep_line.strip("|").split("|")
        # Left-aligned: starts with :
        assert cells[0].strip().startswith(":")
        assert not cells[0].strip().endswith(":")
        # Center-aligned: starts and ends with :
        assert cells[1].strip().startswith(":")
        assert cells[1].strip().endswith(":")
        # Right-aligned: ends with :
        assert not cells[2].strip().startswith(":")
        assert cells[2].strip().endswith(":")

    def test_single_column(self) -> None:
        table = "| Header |\n|---|\n| data |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        assert len(set(len(line) for line in lines)) == 1

    def test_wide_header_narrow_data(self) -> None:
        table = "| Very Long Header | Another Long One |\n|---|---|\n| a | b |"
        result = _align_table_columns(table)
        assert "| a                | b                |" in result

    def test_wide_data_narrow_header(self) -> None:
        table = "| H | I |\n|---|---|\n| wide content | another wide cell |"
        result = _align_table_columns(table)
        assert "| H            | I                 |" in result

    def test_trailing_newline_preserved(self) -> None:
        """If the input has a trailing newline, it should be preserved."""
        table = "| A | B |\n|---|---|\n| 1 | 2 |\n"
        result = _align_table_columns(table)
        assert result.endswith("\n")

    def test_no_trailing_newline(self) -> None:
        table = "| A | B |\n|---|---|\n| 1 | 2 |"
        result = _align_table_columns(table)
        assert not result.endswith("\n")

    def test_mismatched_column_counts(self) -> None:
        """Rows with fewer columns should be padded with empty cells."""
        table = "| A | B | C |\n|---|---|---|\n| 1 | 2 |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # All lines should have equal width
        assert len(set(len(line) for line in lines)) == 1

    def test_extra_columns_in_data(self) -> None:
        """Rows with extra columns beyond header should keep them."""
        table = "| A | B |\n|---|---|\n| 1 | 2 | 3 |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        assert len(set(len(line) for line in lines)) == 1

    def test_whitespace_in_cells_normalized(self) -> None:
        """Extra whitespace in cells is trimmed to single space padding."""
        table = "|  A  |    B    |\n|---|---|\n|1|2|"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # All lines same width
        assert len(set(len(line) for line in lines)) == 1

    def test_escaped_backtick_in_code(self) -> None:
        """Double backtick code spans with pipes."""
        table = "| Code | Desc |\n|---|---|\n| ``a|b`` | test |"
        result = _align_table_columns(table)
        assert "``a|b``" in result
        lines = result.split("\n")
        assert len(set(len(line) for line in lines)) == 1

    def test_backtick_not_closed(self) -> None:
        """Unclosed backtick should not consume rest of line."""
        table = "| A | B |\n|---|---|\n| `unclosed | val |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # Should still parse as 2 columns (unclosed backtick doesn't hide pipe)
        assert len(set(len(line) for line in lines)) == 1

    def test_emoji_in_cell(self) -> None:
        """Emoji occupy 2 columns in monospace but are 1 code point."""
        table = "| Icon | Name |\n|---|---|\n| \U0001f389 | party |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # Pipes should visually align in a monospace terminal.
        # \U0001f389 (party popper) is display-width 2, "party" is 5,
        # "Icon" is 4, "Name" is 4.  Column 1 max display width =
        # max(4, 2) = 4, Column 2 max display width = max(4, 5) = 5.
        # Header: "| Icon | Name  |"   (Icon=4, Name padded to 5)
        # Data:   "| party popper   | party |"  (dw2 + 2 trailing spaces = 4)
        assert "| Name  |" in result
        # All lines must have the same *display* width
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"

    def test_multiple_emoji_in_cell(self) -> None:
        """Multiple emoji in one cell."""
        table = (
            "| Status | Text |\n|---|---|\n| \U0001f44d\U0001f44e | thumbs |"
        )
        result = _align_table_columns(table)
        lines = result.split("\n")
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"
        assert "\U0001f44d\U0001f44e" in result

    def test_east_asian_wide_characters(self) -> None:
        """CJK characters are display-width 2."""
        table = "| Key | Value |\n|---|---|\n| \u4e2d\u6587 | text |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"
        assert "\u4e2d\u6587" in result

    def test_mixed_ascii_and_emoji(self) -> None:
        """Row mixing ASCII and emoji in different cells."""
        table = "| Desc | Icon |\n|---|---|\n| hello world | \u2764\ufe0f |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"

    def test_emoji_in_header(self) -> None:
        """Emoji in header cell expands column for narrow data rows."""
        table = "| \U0001f680 Launch | Status |\n|---|---|\n| abc | ok |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"
        assert "\U0001f680 Launch" in result

    def test_emoji_next_to_pipe_in_code(self) -> None:
        """Emoji inside inline code with pipe."""
        table = "| Code | Desc |\n|---|---|\n| `\U0001f4a5|boom` | test |"
        result = _align_table_columns(table)
        assert "`\U0001f4a5|boom`" in result
        lines = result.split("\n")
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"

    def test_zero_width_joiner_sequence(self) -> None:
        """ZWJ emoji sequences (e.g. family) are complex multi-codepoint."""
        # family emoji: man ZWJ woman ZWJ girl
        family = "\U0001f468\u200d\U0001f469\u200d\U0001f467"
        table = f"| Who | Note |\n|---|---|\n| {family} | fam |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        # We don't require perfect emoji rendering — just that the
        # function doesn't crash and produces consistent display widths.
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"
        assert family in result

    def test_combining_characters(self) -> None:
        """Combining diacritical marks are zero-width."""
        # "e with acute" as e + combining acute accent (2 code points,
        # 1 display col)
        e_accent = "e\u0301"
        table = f"| Char | Name |\n|---|---|\n| {e_accent} | acute |"
        result = _align_table_columns(table)
        lines = result.split("\n")
        dw = [_display_width(line) for line in lines]
        assert len(set(dw)) == 1, f"display widths differ: {dw}"
        assert e_accent in result

    def test_integration_with_convert_tables(self) -> None:
        """Tables should be aligned before wrapping in code fences."""
        md = "| Name | Value |\n|---|---|\n| x | long content here |"
        result = _convert_tables(md)
        assert "```" in result
        # Check alignment happened
        assert "| Name | Value             |" in result
        assert "| x    | long content here |" in result

    def test_integration_sanitize_for_slack(self) -> None:
        """Full sanitization pipeline should align tables."""
        text = "Hello\n\n| A | B |\n|---|---|\n| x | long |"
        result = sanitize_for_slack(text)
        # Table should be aligned and wrapped in code fence
        assert "| A   | B    |" in result
        assert "| x   | long |" in result
        assert result.startswith("Hello\n\n```\n")


class TestConvertTables:
    def test_converts_simple_table(self) -> None:
        md = "| Name | Value |\n|------|-------|\n| foo  | bar   |\n"
        result = _convert_tables(md)
        assert "```" in result
        assert "| Name | Value |" in result

    def test_leaves_non_table_text(self) -> None:
        text = "Just regular text\n\nWith paragraphs"
        assert _convert_tables(text) == text

    def test_mixed_content(self) -> None:
        text = "Before table\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\nAfter table"
        result = _convert_tables(text)
        assert "```" in result
        assert "Before table" in result
        assert "After table" in result


class TestStripCodeFenceLanguages:
    def test_strips_language_tag(self) -> None:
        text = "```python\nprint('hi')\n```"
        result = _strip_code_fence_languages(text)
        assert result == "```\nprint('hi')\n```"

    def test_strips_multiple_languages(self) -> None:
        text = "```javascript\nconst x = 1;\n```\n\n```rust\nfn main() {}\n```"
        result = _strip_code_fence_languages(text)
        assert "```javascript" not in result
        assert "```rust" not in result
        assert result == "```\nconst x = 1;\n```\n\n```\nfn main() {}\n```"

    def test_leaves_plain_code_fence(self) -> None:
        text = "```\nplain code\n```"
        assert _strip_code_fence_languages(text) == text

    def test_leaves_inline_backticks(self) -> None:
        text = "Use `code` here"
        assert _strip_code_fence_languages(text) == text

    def test_leaves_non_code_text(self) -> None:
        text = "No code blocks here"
        assert _strip_code_fence_languages(text) == text


class TestConvertHorizontalRules:
    def test_converts_dashes(self) -> None:
        text = "Before\n\n---\n\nAfter"
        result = _convert_horizontal_rules(text)
        assert "\u2014\u2014\u2014" in result
        assert "---" not in result

    def test_converts_asterisks(self) -> None:
        text = "Before\n\n***\n\nAfter"
        result = _convert_horizontal_rules(text)
        assert "\u2014\u2014\u2014" in result
        assert "***" not in result

    def test_converts_underscores(self) -> None:
        text = "Before\n\n___\n\nAfter"
        result = _convert_horizontal_rules(text)
        assert "\u2014\u2014\u2014" in result
        assert "___" not in result

    def test_converts_long_rule(self) -> None:
        text = "Before\n\n----------\n\nAfter"
        result = _convert_horizontal_rules(text)
        assert "\u2014\u2014\u2014" in result

    def test_preserves_hr_inside_code_block(self) -> None:
        text = "```\n---\n```"
        result = _convert_horizontal_rules(text)
        assert "---" in result
        assert "\u2014\u2014\u2014" not in result

    def test_preserves_dashes_in_text(self) -> None:
        text = "This is a normal -- dash in text"
        assert _convert_horizontal_rules(text) == text

    def test_leaves_regular_text(self) -> None:
        text = "Just text\n\nMore text"
        assert _convert_horizontal_rules(text) == text

    def test_leading_spaces_allowed(self) -> None:
        text = "Before\n\n   ---\n\nAfter"
        result = _convert_horizontal_rules(text)
        assert "\u2014\u2014\u2014" in result


class TestLinkifyBareUrls:
    def test_linkifies_bare_https_url(self) -> None:
        text = "Visit https://example.com for details"
        result = _linkify_bare_urls(text)
        assert (
            result
            == "Visit [https://example.com](https://example.com) for details"
        )

    def test_linkifies_bare_http_url(self) -> None:
        text = "See http://example.com here"
        result = _linkify_bare_urls(text)
        assert result == "See [http://example.com](http://example.com) here"

    def test_linkifies_url_with_path(self) -> None:
        text = "PR: https://github.com/org/repo/pull/29"
        result = _linkify_bare_urls(text)
        assert (
            result
            == "PR: [https://github.com/org/repo/pull/29](https://github.com/org/repo/pull/29)"
        )

    def test_preserves_existing_markdown_link(self) -> None:
        text = "See [my link](https://example.com) here"
        result = _linkify_bare_urls(text)
        assert result == text

    def test_preserves_url_as_link_text(self) -> None:
        """Do not double-wrap ``[url](url)`` style links."""
        text = "[https://example.com](https://example.com)"
        result = _linkify_bare_urls(text)
        assert result == text

    def test_preserves_url_inside_code_fence(self) -> None:
        text = "```\nhttps://example.com\n```"
        result = _linkify_bare_urls(text)
        assert result == text

    def test_preserves_url_inside_inline_code(self) -> None:
        text = "Use `https://example.com` for testing"
        result = _linkify_bare_urls(text)
        assert result == text

    def test_linkifies_multiple_urls(self) -> None:
        text = "See https://a.com and https://b.com"
        result = _linkify_bare_urls(text)
        assert result == (
            "See [https://a.com](https://a.com)"
            " and [https://b.com](https://b.com)"
        )

    def test_linkifies_url_after_bold(self) -> None:
        """Reproduce the exact Slack mangling scenario."""
        text = "**PR:** https://github.com/org/repo/pull/29"
        result = _linkify_bare_urls(text)
        assert result == (
            "**PR:** [https://github.com/org/repo/pull/29]"
            "(https://github.com/org/repo/pull/29)"
        )

    def test_real_world_slack_mangling_case(self) -> None:
        """Full reproduction of the reported Slack rendering bug."""
        text = (
            "Done. Here's what was added:\n\n"
            "**PR:** https://github.com/airutorg/website/pull/29\n"
            "**Preview:** https://888abf88.airut-website.pages.dev"
        )
        result = _linkify_bare_urls(text)
        assert result == (
            "Done. Here's what was added:\n\n"
            "**PR:** [https://github.com/airutorg/website/pull/29]"
            "(https://github.com/airutorg/website/pull/29)\n"
            "**Preview:** [https://888abf88.airut-website.pages.dev]"
            "(https://888abf88.airut-website.pages.dev)"
        )

    def test_leaves_plain_text_unchanged(self) -> None:
        text = "No URLs here, just plain text"
        assert _linkify_bare_urls(text) == text

    def test_url_with_query_string(self) -> None:
        text = "Check https://example.com/search?q=hello&page=1 now"
        result = _linkify_bare_urls(text)
        assert result == (
            "Check [https://example.com/search?q=hello&page=1]"
            "(https://example.com/search?q=hello&page=1) now"
        )

    def test_url_with_fragment(self) -> None:
        text = "See https://example.com/page#section for info"
        result = _linkify_bare_urls(text)
        assert result == (
            "See [https://example.com/page#section]"
            "(https://example.com/page#section) for info"
        )

    def test_url_at_end_of_line(self) -> None:
        text = "Link: https://example.com"
        result = _linkify_bare_urls(text)
        assert result == "Link: [https://example.com](https://example.com)"

    def test_url_at_start_of_line(self) -> None:
        text = "https://example.com is the site"
        result = _linkify_bare_urls(text)
        assert (
            result == "[https://example.com](https://example.com) is the site"
        )


class TestSanitizeForSlack:
    def test_applies_all_sanitizations(self) -> None:
        text = (
            "# Title\n\n"
            "```python\nprint('hi')\n```\n\n"
            "---\n\n"
            "| A | B |\n|---|---|\n| 1 | 2 |\n"
        )
        result = sanitize_for_slack(text)
        # Tables wrapped in code fences and aligned
        assert "```\n| A   | B   |" in result
        # Language tag stripped
        assert "```python" not in result
        # Horizontal rule converted
        assert "\u2014\u2014\u2014" in result

    def test_no_changes_for_supported_markdown(self) -> None:
        text = "**bold** and *italic* and `code`"
        assert sanitize_for_slack(text) == text

    def test_hr_not_converted_inside_table_code_block(self) -> None:
        """HR inside table code fence is preserved after sanitization.

        After table conversion, the --- separator row is inside a
        code fence and should not be treated as a horizontal rule.
        """
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n"
        result = sanitize_for_slack(text)
        # The table is in a code fence, so the --- row stays (now aligned)
        assert "| --- | --- |" in result
        assert "\u2014\u2014\u2014" not in result

    def test_linkifies_bare_urls(self) -> None:
        text = "Visit https://example.com for info"
        result = sanitize_for_slack(text)
        assert (
            result
            == "Visit [https://example.com](https://example.com) for info"
        )
