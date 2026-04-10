# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/check_xrefs.py."""

from pathlib import Path
from unittest.mock import patch

import pytest
from scripts.check_xrefs import (
    _collect_md_files,
    _extract_headings,
    _extract_links,
    _heading_to_anchor,
    _strip_inline_code,
    _validate_link,
    check_xrefs,
    main,
)


class TestHeadingToAnchor:
    """Tests for _heading_to_anchor."""

    def test_simple(self) -> None:
        assert _heading_to_anchor("Getting Started") == "getting-started"

    def test_punctuation_removed(self) -> None:
        assert (
            _heading_to_anchor("Step 1: Choose a Provider")
            == "step-1-choose-a-provider"
        )

    def test_apostrophe_removed(self) -> None:
        assert _heading_to_anchor("What's New?") == "whats-new"

    def test_em_dash_double_hyphen(self) -> None:
        """Em dash flanked by spaces produces double hyphen."""
        assert (
            _heading_to_anchor("ci.py — Local CI Runner")
            == "cipy--local-ci-runner"
        )

    def test_plus_sign_double_hyphen(self) -> None:
        """Plus sign flanked by spaces produces double hyphen."""
        assert (
            _heading_to_anchor("Socket Mode + Authorization Rules")
            == "socket-mode--authorization-rules"
        )

    def test_underscores_preserved(self) -> None:
        assert _heading_to_anchor("my_function") == "my_function"

    def test_whitespace_stripped(self) -> None:
        assert _heading_to_anchor("  hello  ") == "hello"


class TestExtractHeadings:
    """Tests for _extract_headings."""

    def test_single_heading(self) -> None:
        content = "# Getting Started\n\nSome text.\n"
        assert _extract_headings(content) == {"getting-started"}

    def test_multiple_levels(self) -> None:
        content = "# Top\n## Second\n### Third\n"
        assert _extract_headings(content) == {"top", "second", "third"}

    def test_duplicate_headings(self) -> None:
        content = "## Example\n\ntext\n\n## Example\n\ntext\n\n## Example\n"
        anchors = _extract_headings(content)
        assert "example" in anchors
        assert "example-1" in anchors
        assert "example-2" in anchors

    def test_non_heading_lines_ignored(self) -> None:
        content = "Not a heading\n#Also not\n\n## Real Heading\n"
        assert _extract_headings(content) == {"real-heading"}

    def test_closing_hashes(self) -> None:
        """Headings with trailing hashes are parsed correctly."""
        content = "## My Heading ##\n"
        assert _extract_headings(content) == {"my-heading"}


class TestStripInlineCode:
    """Tests for _strip_inline_code."""

    def test_single_backtick(self) -> None:
        line = "Use `[url](url)` syntax"
        result = _strip_inline_code(line)
        assert "[url](url)" not in result

    def test_double_backtick(self) -> None:
        line = "Use ``[url](url)`` syntax"
        result = _strip_inline_code(line)
        assert "[url](url)" not in result

    def test_preserves_length(self) -> None:
        line = "a `bc` d"
        result = _strip_inline_code(line)
        assert len(result) == len(line)

    def test_no_backtick(self) -> None:
        line = "no code here"
        assert _strip_inline_code(line) == line


class TestExtractLinks:
    """Tests for _extract_links."""

    def test_regular_link(self) -> None:
        content = "See [other](other.md) for details.\n"
        links = _extract_links(content)
        assert links == [(1, "other.md")]

    def test_anchor_link(self) -> None:
        content = "See [section](#my-section).\n"
        links = _extract_links(content)
        assert links == [(1, "#my-section")]

    def test_file_with_anchor(self) -> None:
        content = "See [it](other.md#section).\n"
        links = _extract_links(content)
        assert links == [(1, "other.md#section")]

    def test_image_link_skipped(self) -> None:
        content = "![alt](image.png)\n"
        assert _extract_links(content) == []

    def test_http_skipped(self) -> None:
        content = "[Google](https://google.com)\n"
        assert _extract_links(content) == []

    def test_mailto_skipped(self) -> None:
        content = "[Email](mailto:a@b.com)\n"
        assert _extract_links(content) == []

    def test_fenced_code_block_skipped(self) -> None:
        content = "```\n[link](file.md)\n```\n"
        assert _extract_links(content) == []

    def test_tilde_code_block_skipped(self) -> None:
        content = "~~~\n[link](file.md)\n~~~\n"
        assert _extract_links(content) == []

    def test_inline_code_skipped(self) -> None:
        content = "Use `[url](url)` syntax.\n"
        assert _extract_links(content) == []

    def test_multiple_links_per_line(self) -> None:
        content = "[a](a.md) and [b](b.md)\n"
        links = _extract_links(content)
        assert links == [(1, "a.md"), (1, "b.md")]

    def test_line_numbers(self) -> None:
        content = "text\n[link](file.md)\ntext\n"
        links = _extract_links(content)
        assert links == [(2, "file.md")]


class TestCollectMdFiles:
    """Tests for _collect_md_files."""

    def test_collects_all_md(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("")
        (tmp_path / "b.md").write_text("")
        (tmp_path / "c.txt").write_text("")
        files = _collect_md_files(tmp_path, None)
        names = {f.name for f in files}
        assert names == {"a.md", "b.md"}

    def test_specific_file(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("")
        (tmp_path / "b.md").write_text("")
        files = _collect_md_files(tmp_path, [Path("a.md")])
        assert len(files) == 1
        assert files[0].name == "a.md"

    def test_specific_dir(self, tmp_path: Path) -> None:
        sub = tmp_path / "docs"
        sub.mkdir()
        (sub / "a.md").write_text("")
        (tmp_path / "b.md").write_text("")
        files = _collect_md_files(tmp_path, [Path("docs")])
        assert len(files) == 1
        assert files[0].name == "a.md"

    def test_excludes_hidden(self, tmp_path: Path) -> None:
        hidden = tmp_path / ".git"
        hidden.mkdir()
        (hidden / "x.md").write_text("")
        (tmp_path / "a.md").write_text("")
        files = _collect_md_files(tmp_path, None)
        assert len(files) == 1

    def test_includes_airut(self, tmp_path: Path) -> None:
        airut = tmp_path / ".airut"
        airut.mkdir()
        (airut / "x.md").write_text("")
        files = _collect_md_files(tmp_path, None)
        assert len(files) == 1


class TestValidateLink:
    """Tests for _validate_link."""

    def test_valid_file(self, tmp_path: Path) -> None:
        (tmp_path / "target.md").write_text("# Heading\n")
        cache: dict[Path, set[str]] = {}
        result = _validate_link("target.md", tmp_path, tmp_path / "a.md", cache)
        assert result is None

    def test_missing_file(self, tmp_path: Path) -> None:
        cache: dict[Path, set[str]] = {}
        result = _validate_link(
            "missing.md", tmp_path, tmp_path / "a.md", cache
        )
        assert result is not None
        assert "file not found" in result

    def test_valid_anchor(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("# Intro\n")
        cache: dict[Path, set[str]] = {}
        result = _validate_link("#intro", tmp_path, tmp_path / "a.md", cache)
        assert result is None

    def test_broken_anchor(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("# Intro\n")
        cache: dict[Path, set[str]] = {}
        result = _validate_link("#nope", tmp_path, tmp_path / "a.md", cache)
        assert result is not None
        assert "anchor #nope not found" in result

    def test_directory_target(self, tmp_path: Path) -> None:
        (tmp_path / "subdir").mkdir()
        cache: dict[Path, set[str]] = {}
        result = _validate_link("subdir", tmp_path, tmp_path / "a.md", cache)
        assert result is None

    def test_populates_cache(self, tmp_path: Path) -> None:
        (tmp_path / "target.md").write_text("# One\n## Two\n")
        cache: dict[Path, set[str]] = {}
        _validate_link("target.md#one", tmp_path, tmp_path / "a.md", cache)
        assert (tmp_path / "target.md").resolve() in cache


class TestCheckXrefs:
    """Tests for check_xrefs."""

    def test_all_valid(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 0 when all links are valid."""
        (tmp_path / "a.md").write_text("# Heading\n\n[b](b.md)\n")
        (tmp_path / "b.md").write_text("# Other\n\n[a](a.md)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0
        captured = capsys.readouterr()
        assert "cross-reference(s) valid" in captured.out

    def test_broken_file_link(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 when a file link target doesn't exist."""
        (tmp_path / "a.md").write_text("[missing](missing.md)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 1
        captured = capsys.readouterr()
        assert "file not found" in captured.out

    def test_broken_anchor(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 when an anchor doesn't exist in target file."""
        (tmp_path / "a.md").write_text("# Real\n\n[x](#missing)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 1
        captured = capsys.readouterr()
        assert "anchor #missing not found" in captured.out

    def test_valid_same_file_anchor(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.md").write_text("# My Section\n\n[x](#my-section)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_valid_cross_file_anchor(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.md").write_text("[x](b.md#intro)\n")
        (tmp_path / "b.md").write_text("# Intro\n\nHello.\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_directory_link(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "a.md").write_text("[dir](subdir)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_directory_link_verbose(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "a.md").write_text("[dir](subdir)\n")

        result = check_xrefs(verbose=True, root=tmp_path)
        assert result == 0
        captured = capsys.readouterr()
        assert "OK (directory)" in captured.out

    def test_verbose_shows_valid(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.md").write_text("[b](b.md)\n")
        (tmp_path / "b.md").write_text("# B\n")

        result = check_xrefs(verbose=True, root=tmp_path)
        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_verbose_shows_valid_anchor(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Verbose mode shows OK for links with anchors."""
        (tmp_path / "a.md").write_text("# Intro\n\n[x](#intro)\n")

        result = check_xrefs(verbose=True, root=tmp_path)
        assert result == 0
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_url_encoded_anchor(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """URL-encoded anchors are decoded before matching."""
        # %2D decodes to hyphen
        (tmp_path / "a.md").write_text("# Hello World\n\n[x](#hello%2Dworld)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_url_encoded_em_dash_anchor(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """URL-encoded em dash in anchor matches stripped heading."""
        # mdformat encodes em dash as %E2%80%94, but the heading anchor
        # strips it. Normalization should make them match.
        (tmp_path / "a.md").write_text(
            "# ci.py \u2014 Runner\n\n[x](#cipy-%E2%80%94-runner)\n"
        )

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_hidden_dirs_excluded(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Files in hidden directories (except .airut) are skipped."""
        hidden = tmp_path / ".hidden"
        hidden.mkdir()
        (hidden / "bad.md").write_text("[missing](nonexistent.md)\n")
        (tmp_path / "ok.md").write_text("# OK\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_airut_dir_included(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """.airut directory is not excluded."""
        airut = tmp_path / ".airut"
        airut.mkdir()
        (airut / "readme.md").write_text("[missing](nonexistent.md)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 1

    def test_specific_file_path(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Scanning a specific file works."""
        (tmp_path / "a.md").write_text("[b](b.md)\n")
        (tmp_path / "b.md").write_text("# B\n")

        result = check_xrefs(paths=[Path("a.md")], root=tmp_path)
        assert result == 0

    def test_specific_dir_path(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Scanning a specific directory works."""
        sub = tmp_path / "docs"
        sub.mkdir()
        (sub / "a.md").write_text("[b](b.md)\n")
        (sub / "b.md").write_text("# B\n")

        result = check_xrefs(paths=[Path("docs")], root=tmp_path)
        assert result == 0

    def test_parent_relative_link(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Parent-relative links (../) resolve correctly."""
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "root.md").write_text("# Root\n")
        (sub / "child.md").write_text("[root](../root.md#root)\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_error_summary_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Error output includes count summary."""
        (tmp_path / "a.md").write_text(
            "# OK\n\n[good](#ok)\n[bad](missing.md)\n"
        )

        result = check_xrefs(root=tmp_path)
        assert result == 1
        captured = capsys.readouterr()
        assert "1 broken, 1 valid" in captured.out

    def test_heading_cache_reused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Multiple links to same file only read it once."""
        (tmp_path / "target.md").write_text("# One\n\n## Two\n")
        (tmp_path / "source.md").write_text(
            "[a](target.md#one)\n[b](target.md#two)\n"
        )

        result = check_xrefs(root=tmp_path)
        assert result == 0

    def test_no_links(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """File with no links counts as 0 valid."""
        (tmp_path / "a.md").write_text("Just text, no links.\n")

        result = check_xrefs(root=tmp_path)
        assert result == 0
        captured = capsys.readouterr()
        assert "All 0 cross-reference(s) valid." in captured.out


class TestMain:
    """Tests for main CLI entry point."""

    def test_default_args(self, tmp_path: Path) -> None:
        """Main with no args scans current directory."""
        (tmp_path / "a.md").write_text("# Test\n")
        with patch(
            "sys.argv",
            ["check_xrefs.py", "--root", str(tmp_path)],
        ):
            result = main()
        assert result == 0

    def test_verbose_flag(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("[b](b.md)\n")
        (tmp_path / "b.md").write_text("# B\n")
        with patch(
            "sys.argv",
            ["check_xrefs.py", "--verbose", "--root", str(tmp_path)],
        ):
            result = main()
        assert result == 0

    def test_path_args(self, tmp_path: Path) -> None:
        sub = tmp_path / "docs"
        sub.mkdir()
        (sub / "a.md").write_text("# A\n")
        with patch(
            "sys.argv",
            [
                "check_xrefs.py",
                "--root",
                str(tmp_path),
                "docs",
            ],
        ):
            result = main()
        assert result == 0

    def test_failure_exit_code(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("[missing](gone.md)\n")
        with patch(
            "sys.argv",
            ["check_xrefs.py", "--root", str(tmp_path)],
        ):
            result = main()
        assert result == 1
