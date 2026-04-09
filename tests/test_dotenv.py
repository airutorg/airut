# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut.dotenv — minimal .env file parser."""

import os
from pathlib import Path

import pytest

from airut.dotenv import load_dotenv, parse_dotenv


# ---------------------------------------------------------------------------
# parse_dotenv — basic key=value
# ---------------------------------------------------------------------------


class TestParseDotenvBasic:
    """Basic key=value parsing."""

    def test_empty_string(self) -> None:
        assert parse_dotenv("") == {}

    def test_simple_pair(self) -> None:
        assert parse_dotenv("A=b") == {"A": "b"}

    def test_multiple_pairs(self) -> None:
        assert parse_dotenv("A=1\nB=2\nC=3") == {
            "A": "1",
            "B": "2",
            "C": "3",
        }

    def test_empty_value(self) -> None:
        assert parse_dotenv("KEY=") == {"KEY": ""}

    def test_empty_value_with_newline(self) -> None:
        assert parse_dotenv("A=\nB=2") == {"A": "", "B": "2"}

    def test_equals_in_value(self) -> None:
        assert parse_dotenv("URL=postgres://h:5432/db?opt=1") == {
            "URL": "postgres://h:5432/db?opt=1"
        }

    def test_numeric_value(self) -> None:
        assert parse_dotenv("PORT=8080") == {"PORT": "8080"}

    def test_last_value_wins(self) -> None:
        assert parse_dotenv("A=1\nA=2") == {"A": "2"}


# ---------------------------------------------------------------------------
# parse_dotenv — whitespace handling
# ---------------------------------------------------------------------------


class TestParseDotenvWhitespace:
    """Whitespace around keys, values, and equals sign."""

    def test_spaces_around_equals(self) -> None:
        assert parse_dotenv(" A = b ") == {"A": "b"}

    def test_tabs_around_equals(self) -> None:
        assert parse_dotenv("\tA\t=\tb\t") == {"A": "b"}

    def test_trailing_space_in_unquoted_value(self) -> None:
        assert parse_dotenv("A=hello world   ") == {"A": "hello world"}

    def test_internal_spaces_preserved(self) -> None:
        assert parse_dotenv("A=hello   world") == {"A": "hello   world"}

    def test_internal_tabs_preserved(self) -> None:
        assert parse_dotenv("A=b\tc") == {"A": "b\tc"}

    def test_nbsp_preserved_in_value(self) -> None:
        """Non-breaking space is not stripped (not ASCII whitespace)."""
        assert parse_dotenv("A=b\u00a0 c") == {"A": "b\u00a0 c"}


# ---------------------------------------------------------------------------
# parse_dotenv — comments
# ---------------------------------------------------------------------------


class TestParseDotenvComments:
    """Comment lines and inline comments."""

    def test_full_line_comment(self) -> None:
        assert parse_dotenv("# this is a comment") == {}

    def test_comment_with_leading_space(self) -> None:
        assert parse_dotenv("  # indented comment") == {}

    def test_inline_comment_space_hash(self) -> None:
        """Space + # starts an inline comment for unquoted values."""
        assert parse_dotenv("A=value #comment") == {"A": "value"}

    def test_inline_comment_tab_hash(self) -> None:
        """Tab + # starts an inline comment for unquoted values."""
        assert parse_dotenv("A=value\t#comment") == {"A": "value"}

    def test_hash_without_space_is_value(self) -> None:
        """# without preceding whitespace is part of the value."""
        assert parse_dotenv("A=value#notcomment") == {"A": "value#notcomment"}

    def test_comments_between_values(self) -> None:
        result = parse_dotenv("A=1\n# comment\nB=2")
        assert result == {"A": "1", "B": "2"}

    def test_only_comments(self) -> None:
        assert parse_dotenv("# one\n# two\n# three") == {}


# ---------------------------------------------------------------------------
# parse_dotenv — blank lines
# ---------------------------------------------------------------------------


class TestParseDotenvBlankLines:
    """Blank and whitespace-only lines."""

    def test_blank_lines_ignored(self) -> None:
        assert parse_dotenv("\n\n") == {}

    def test_blank_lines_between_pairs(self) -> None:
        assert parse_dotenv("A=1\n\nB=2") == {"A": "1", "B": "2"}

    def test_whitespace_only_lines(self) -> None:
        assert parse_dotenv("  \n\t\n") == {}

    def test_trailing_newline(self) -> None:
        assert parse_dotenv("A=1\n") == {"A": "1"}

    def test_crlf_line_endings(self) -> None:
        assert parse_dotenv("A=1\r\nB=2\r\n") == {"A": "1", "B": "2"}

    def test_cr_line_endings(self) -> None:
        assert parse_dotenv("A=1\rB=2\r") == {"A": "1", "B": "2"}


# ---------------------------------------------------------------------------
# parse_dotenv — export prefix
# ---------------------------------------------------------------------------


class TestParseDotenvExport:
    """Lines starting with ``export``."""

    def test_export_prefix(self) -> None:
        assert parse_dotenv("export A=b") == {"A": "b"}

    def test_export_with_leading_whitespace(self) -> None:
        assert parse_dotenv("  export A=b") == {"A": "b"}

    def test_export_key_starting_with_export(self) -> None:
        """Key starting with 'export_' is not confused with the prefix."""
        assert parse_dotenv("export export_a=1") == {"export_a": "1"}

    def test_export_key_named_port(self) -> None:
        """Key starting with 'port' after export prefix."""
        assert parse_dotenv("export port=8000") == {"port": "8000"}


# ---------------------------------------------------------------------------
# parse_dotenv — single-quoted values
# ---------------------------------------------------------------------------


class TestParseDotenvSingleQuoted:
    """Single-quoted values."""

    def test_basic_single_quoted(self) -> None:
        assert parse_dotenv("A='hello world'") == {"A": "hello world"}

    def test_preserves_trailing_space(self) -> None:
        assert parse_dotenv("A='hello '") == {"A": "hello "}

    def test_no_escape_processing(self) -> None:
        r"""Backslash-n stays literal in single quotes."""
        assert parse_dotenv(r"A='hello\nworld'") == {"A": r"hello\nworld"}

    def test_escaped_single_quote(self) -> None:
        assert parse_dotenv(r"A='it\'s'") == {"A": "it's"}

    def test_hash_inside_single_quotes(self) -> None:
        """Hash inside quotes is not a comment."""
        assert parse_dotenv("A='val #not a comment'") == {
            "A": "val #not a comment"
        }

    def test_double_quote_inside_single_quotes(self) -> None:
        assert parse_dotenv("""A='"hello"'""") == {"A": '"hello"'}

    def test_empty_single_quoted(self) -> None:
        assert parse_dotenv("A=''") == {"A": ""}

    def test_multiline_single_quoted(self) -> None:
        assert parse_dotenv("A='line1\nline2'") == {"A": "line1\nline2"}

    def test_single_quoted_with_spaces_around(self) -> None:
        """Spaces outside quotes are stripped."""
        assert parse_dotenv("A = 'hello' ") == {"A": "hello"}


# ---------------------------------------------------------------------------
# parse_dotenv — double-quoted values
# ---------------------------------------------------------------------------


class TestParseDotenvDoubleQuoted:
    """Double-quoted values."""

    def test_basic_double_quoted(self) -> None:
        assert parse_dotenv('A="hello world"') == {"A": "hello world"}

    def test_preserves_trailing_space(self) -> None:
        assert parse_dotenv('A="hello "') == {"A": "hello "}

    def test_escape_newline(self) -> None:
        r"""``\n`` becomes a real newline."""
        assert parse_dotenv(r'A="hello\nworld"') == {"A": "hello\nworld"}

    def test_escape_tab(self) -> None:
        r"""``\t`` becomes a real tab."""
        assert parse_dotenv(r'A="col1\tcol2"') == {"A": "col1\tcol2"}

    def test_escape_backslash(self) -> None:
        r"""``\\`` becomes a single backslash."""
        assert parse_dotenv(r'A="path\\to"') == {"A": "path\\to"}

    def test_escape_double_quote(self) -> None:
        r"""``\"`` becomes a literal double quote."""
        assert parse_dotenv(r'A="say \"hi\""') == {"A": 'say "hi"'}

    def test_escape_dollar(self) -> None:
        r"""``\$`` becomes a literal dollar sign."""
        assert parse_dotenv(r'A="\$HOME"') == {"A": "$HOME"}

    def test_unknown_escape_keeps_backslash(self) -> None:
        r"""Unknown escape sequences preserve the backslash."""
        assert parse_dotenv(r'A="hello\xworld"') == {"A": r"hello\xworld"}

    def test_hash_inside_double_quotes(self) -> None:
        assert parse_dotenv('A="val #not a comment"') == {
            "A": "val #not a comment"
        }

    def test_single_quote_inside_double_quotes(self) -> None:
        assert parse_dotenv("""A="it's"  """) == {"A": "it's"}

    def test_empty_double_quoted(self) -> None:
        assert parse_dotenv('A=""') == {"A": ""}

    def test_multiline_double_quoted(self) -> None:
        assert parse_dotenv('A="line1\nline2"') == {"A": "line1\nline2"}

    def test_multiline_with_escape_n(self) -> None:
        r"""Literal newline AND ``\n`` escape in double quotes."""
        assert parse_dotenv('A="line1\\nline2\nline3"') == {
            "A": "line1\nline2\nline3"
        }

    def test_double_quoted_with_spaces_around(self) -> None:
        """Spaces outside quotes are stripped."""
        assert parse_dotenv('A = "hello" ') == {"A": "hello"}


# ---------------------------------------------------------------------------
# parse_dotenv — quoted keys
# ---------------------------------------------------------------------------


class TestParseDotenvQuotedKeys:
    """Keys may be quoted (single or double)."""

    def test_single_quoted_key(self) -> None:
        assert parse_dotenv("'MY_KEY'=value") == {"MY_KEY": "value"}

    def test_double_quoted_key(self) -> None:
        assert parse_dotenv('"MY_KEY"=value') == {"MY_KEY": "value"}


# ---------------------------------------------------------------------------
# parse_dotenv — no-value keys
# ---------------------------------------------------------------------------


class TestParseDotenvNoValue:
    """Keys without an ``=`` sign."""

    def test_no_value_key_excluded(self) -> None:
        """Keys without = are skipped (cannot be set in os.environ)."""
        assert parse_dotenv("NO_VALUE_KEY") == {}

    def test_no_value_mixed(self) -> None:
        assert parse_dotenv("SKIP_ME\nA=1") == {"A": "1"}


# ---------------------------------------------------------------------------
# parse_dotenv — error recovery
# ---------------------------------------------------------------------------


class TestParseDotenvErrors:
    """Malformed lines are silently skipped."""

    def test_unclosed_double_quote(self) -> None:
        """Unclosed double-quote line is skipped, next line parses OK."""
        assert parse_dotenv('A="unterminated\nB=2') == {"B": "2"}

    def test_unclosed_single_quote(self) -> None:
        assert parse_dotenv("A='unterminated\nB=2") == {"B": "2"}

    def test_trailing_whitespace_only(self) -> None:
        """File ending with whitespace (no trailing newline)."""
        assert parse_dotenv("A=1\n   ") == {"A": "1"}

    def test_unterminated_quoted_key(self) -> None:
        """Quoted key without closing quote is skipped."""
        assert parse_dotenv("'unterminated") == {}

    def test_escaped_char_in_quoted_key(self) -> None:
        r"""Backslash in a quoted key is preserved (no escape processing)."""
        assert parse_dotenv("'a\\'b'=1") == {"a\\'b": "1"}

    def test_export_with_no_key(self) -> None:
        """Bare ``export`` with nothing after it is skipped."""
        assert parse_dotenv("export \nA=1") == {"A": "1"}

    def test_bare_export_at_eof(self) -> None:
        """Bare ``export`` at end of file."""
        assert parse_dotenv("export") == {}


# ---------------------------------------------------------------------------
# parse_dotenv — unicode and special characters
# ---------------------------------------------------------------------------


class TestParseDotenvUnicode:
    """Unicode and special characters in keys and values."""

    def test_unicode_value(self) -> None:
        assert parse_dotenv("A=café") == {"A": "café"}

    def test_unicode_quoted(self) -> None:
        assert parse_dotenv('A="à"') == {"A": "à"}

    def test_special_chars_in_key(self) -> None:
        assert parse_dotenv("ugly[%$=secret") == {"ugly[%$": "secret"}

    def test_special_chars_quoted_value(self) -> None:
        assert parse_dotenv('KEY="S3cr3t_P4ssw#rD"') == {
            "KEY": "S3cr3t_P4ssw#rD"
        }


# ---------------------------------------------------------------------------
# parse_dotenv — realistic .env files
# ---------------------------------------------------------------------------


class TestParseDotenvRealistic:
    """Full .env file scenarios."""

    def test_typical_env_file(self) -> None:
        content = """\
# Application settings
APP_NAME=myapp
APP_ENV=production
DEBUG=false

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mydb
DB_USER=admin
DB_PASS="s3cr3t p@ss"

# API keys
export API_KEY=abc123
export API_SECRET='def456'
"""
        result = parse_dotenv(content)
        assert result == {
            "APP_NAME": "myapp",
            "APP_ENV": "production",
            "DEBUG": "false",
            "DB_HOST": "localhost",
            "DB_PORT": "5432",
            "DB_NAME": "mydb",
            "DB_USER": "admin",
            "DB_PASS": "s3cr3t p@ss",
            "API_KEY": "abc123",
            "API_SECRET": "def456",
        }

    def test_multiline_certificates(self) -> None:
        content = 'CERT="-----BEGIN CERT-----\nMIIBxT...\n-----END CERT-----"'
        result = parse_dotenv(content)
        assert result["CERT"] == (
            "-----BEGIN CERT-----\nMIIBxT...\n-----END CERT-----"
        )

    def test_connection_string(self) -> None:
        content = (
            "DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require"
        )
        result = parse_dotenv(content)
        assert result["DATABASE_URL"] == (
            "postgres://user:pass@host:5432/db?sslmode=require"
        )


# ---------------------------------------------------------------------------
# load_dotenv — file loading and os.environ integration
# ---------------------------------------------------------------------------


class TestLoadDotenv:
    """Loading .env files into os.environ."""

    def test_sets_env_vars(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOTENV_TEST_A=hello\nDOTENV_TEST_B=world\n")
        monkeypatch.delenv("DOTENV_TEST_A", raising=False)
        monkeypatch.delenv("DOTENV_TEST_B", raising=False)
        result = load_dotenv(env_file)
        assert os.environ["DOTENV_TEST_A"] == "hello"
        assert os.environ["DOTENV_TEST_B"] == "world"
        assert result == {
            "DOTENV_TEST_A": "hello",
            "DOTENV_TEST_B": "world",
        }

    def test_does_not_overwrite_existing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOTENV_TEST_X=new")
        monkeypatch.setenv("DOTENV_TEST_X", "existing")
        load_dotenv(env_file)
        assert os.environ["DOTENV_TEST_X"] == "existing"

    def test_override_overwrites_existing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOTENV_TEST_Y=new")
        monkeypatch.setenv("DOTENV_TEST_Y", "existing")
        load_dotenv(env_file, override=True)
        assert os.environ["DOTENV_TEST_Y"] == "new"

    def test_returns_parsed_dict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("K1=v1\nK2=v2\n")
        monkeypatch.delenv("K1", raising=False)
        monkeypatch.delenv("K2", raising=False)
        result = load_dotenv(env_file)
        assert result == {"K1": "v1", "K2": "v2"}

    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_dotenv(tmp_path / "nonexistent.env")
        assert result == {}

    def test_empty_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("")
        result = load_dotenv(env_file)
        assert result == {}

    def test_utf8_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("GREETING=héllo", encoding="utf-8")
        monkeypatch.delenv("GREETING", raising=False)
        result = load_dotenv(env_file)
        assert result == {"GREETING": "héllo"}
        assert os.environ["GREETING"] == "héllo"
