# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

r"""Minimal ``.env`` file parser.

Replaces the ``python-dotenv`` dependency with a focused implementation
that covers the subset of ``.env`` syntax actually used in practice:

- ``KEY=value`` pairs (unquoted, single-quoted, double-quoted)
- ``export`` prefix
- Comments (``#`` full-line and inline after whitespace)
- Escape sequences in double-quoted values (``\\n \\t \\\\ \\" \\$``)
- Multiline values inside quotes
- Graceful skip of malformed lines
"""

import os
from pathlib import Path


# Double-quoted escape map: only these sequences are transformed.
_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "\\": "\\",
    '"': '"',
    "$": "$",
}


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse ``.env`` file content into a dictionary.

    Args:
        text: The contents of a ``.env`` file.

    Returns:
        Mapping of variable names to their string values.  Keys that
        appear without an ``=`` sign are silently skipped.  When a key
        appears more than once the last value wins.
    """
    result: dict[str, str] = {}
    pos = 0
    length = len(text)

    while pos < length:
        # Skip blank lines and whitespace-only lines.
        pos = _skip_whitespace_no_newline(text, pos, length)
        if pos >= length:
            break
        if text[pos] in "\r\n":
            pos = _skip_newline(text, pos, length)
            continue

        # Full-line comment.
        if text[pos] == "#":
            pos = _skip_to_next_line(text, pos, length)
            continue

        # Optional ``export`` prefix.
        pos = _skip_export(text, pos, length)

        # Key.
        key, pos = _read_key(text, pos, length)
        if key is None:
            pos = _skip_to_next_line(text, pos, length)
            continue

        # Equals sign.
        pos = _skip_whitespace_no_newline(text, pos, length)
        if pos >= length or text[pos] != "=":
            # No ``=`` → skip this entry.
            pos = _skip_to_next_line(text, pos, length)
            continue

        pos += 1  # consume ``=``

        # Value.
        value_start = pos
        value, pos = _read_value(text, pos, length)
        if value is None:
            # Malformed (e.g. unclosed quote) — skip this line only.
            pos = _skip_to_next_line(text, value_start, length)
            continue

        result[key] = value

        # Consume remainder of the line (inline comment, trailing space).
        pos = _skip_to_next_line(text, pos, length)

    return result


def load_dotenv(path: Path, *, override: bool = False) -> dict[str, str]:
    """Load a ``.env`` file into :data:`os.environ`.

    Args:
        path: Path to the ``.env`` file.  If the file does not exist an
            empty dict is returned and nothing is modified.
        override: When *True*, overwrite environment variables that
            already exist.  The default (*False*) matches the
            ``python-dotenv`` convention.

    Returns:
        The parsed key/value pairs (regardless of whether they were
        actually written to the environment).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}

    values = parse_dotenv(text)
    for key, value in values.items():
        if override or key not in os.environ:
            os.environ[key] = value
    return values


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _skip_whitespace_no_newline(text: str, pos: int, length: int) -> int:
    """Advance past spaces and tabs (not newlines)."""
    while pos < length and text[pos] in " \t":
        pos += 1
    return pos


def _skip_newline(text: str, pos: int, length: int) -> int:
    r"""Consume one newline (``\\n``, ``\\r``, or ``\\r\\n``)."""
    if pos < length:
        if text[pos] == "\r":
            pos += 1
            if pos < length and text[pos] == "\n":
                pos += 1
        elif text[pos] == "\n":
            pos += 1
    return pos


def _skip_to_next_line(text: str, pos: int, length: int) -> int:
    """Skip to the start of the next line."""
    while pos < length and text[pos] not in "\r\n":
        pos += 1
    return _skip_newline(text, pos, length)


def _skip_export(text: str, pos: int, length: int) -> int:
    """Consume an optional ``export`` keyword followed by whitespace."""
    if text[pos : pos + 6] == "export" and (
        pos + 6 >= length or text[pos + 6] in " \t"
    ):
        pos += 6
        pos = _skip_whitespace_no_newline(text, pos, length)
    return pos


def _read_key(text: str, pos: int, length: int) -> tuple[str | None, int]:
    """Read a key (optionally quoted)."""
    if pos >= length:
        return None, pos

    if text[pos] in ("'", '"'):
        quote = text[pos]
        pos += 1
        start = pos
        while pos < length and text[pos] != quote:
            if text[pos] == "\\" and pos + 1 < length:
                pos += 2
            else:
                pos += 1
        if pos >= length:
            return None, pos
        key = text[start:pos]
        pos += 1  # closing quote
        return key, pos

    # Unquoted key: read until ``=``, whitespace, or end-of-line.
    start = pos
    while pos < length and text[pos] not in "= \t\r\n":
        pos += 1
    if pos == start:
        return None, pos
    return text[start:pos], pos


def _read_value(text: str, pos: int, length: int) -> tuple[str | None, int]:
    """Read a value (unquoted, single-quoted, or double-quoted)."""
    pos = _skip_whitespace_no_newline(text, pos, length)

    if pos >= length or text[pos] in "\r\n":
        # ``KEY=`` with nothing after ``=``.
        return "", pos

    if text[pos] == "'":
        return _read_single_quoted(text, pos + 1, length)
    if text[pos] == '"':
        return _read_double_quoted(text, pos + 1, length)
    return _read_unquoted(text, pos, length)


def _read_single_quoted(
    text: str, pos: int, length: int
) -> tuple[str | None, int]:
    r"""Read a single-quoted value. No escape processing except ``\\'``."""
    parts: list[str] = []
    while pos < length:
        ch = text[pos]
        if ch == "\\" and pos + 1 < length and text[pos + 1] == "'":
            parts.append("'")
            pos += 2
        elif ch == "'":
            return "".join(parts), pos + 1
        else:
            parts.append(ch)
            pos += 1
    # Unterminated.
    return None, pos


def _read_double_quoted(
    text: str, pos: int, length: int
) -> tuple[str | None, int]:
    """Read a double-quoted value with escape processing."""
    parts: list[str] = []
    while pos < length:
        ch = text[pos]
        if ch == "\\" and pos + 1 < length:
            nxt = text[pos + 1]
            replacement = _ESCAPES.get(nxt)
            if replacement is not None:
                parts.append(replacement)
                pos += 2
            else:
                # Unknown escape — keep backslash and character.
                parts.append(ch)
                parts.append(nxt)
                pos += 2
        elif ch == '"':
            return "".join(parts), pos + 1
        else:
            parts.append(ch)
            pos += 1
    # Unterminated.
    return None, pos


def _read_unquoted(text: str, pos: int, length: int) -> tuple[str, int]:
    """Read an unquoted value.

    Stops at a newline.  Inline comments (``<space>#`` or ``<tab>#``)
    end the value.  Trailing whitespace is stripped.
    """
    start = pos
    comment_start: int | None = None

    while pos < length and text[pos] not in "\r\n":
        if text[pos] == "#" and pos > start and text[pos - 1] in " \t":
            comment_start = pos - 1
            break
        pos += 1

    if comment_start is not None:
        value = text[start:comment_start].rstrip(" \t")
    else:
        value = text[start:pos].rstrip(" \t")
    return value, pos
