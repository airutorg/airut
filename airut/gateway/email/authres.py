# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Parser for the ``Authentication-Results`` header field (RFC 8601).

The receiving mail server writes this header, but many of the values in
it come from the sender: the identity in a DKIM signature, the envelope
sender, the From domain.  The server quotes such values, so a quoted
value may hold any text — including ``dmarc=pass``.  A result can only
be trusted when it is read from the header's structure, never when it
is found by searching the header's text.

The grammar (RFC 8601 §2.2), simplified::

    header   = authserv-id [version] ( ";" "none" / 1*( ";" resinfo ) )
    resinfo  = method ["/" version] "=" result [reason] *propspec
    reason   = "reason" "=" value
    propspec = ptype "." property "=" pvalue

Whitespace and comments (which nest) may appear between any two tokens.
A value is a token or a quoted string; a pvalue may also be a quoted
local part joined to ``@domain``.

Microsoft 365 omits the authserv-id, so a header whose first segment is
itself a ``method=result`` entry is read as having none.

Input this module cannot read raises ``AuthResultsParseError``; the
caller treats the header as unusable rather than guessing at it.  So
does a header longer than ``MAX_LENGTH``: real ones are a few hundred
characters, and a bound keeps parsing cheap whatever the input.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass


#: Longest header value parsed.
MAX_LENGTH = 16 * 1024

#: Characters that end an unquoted word.
_SPECIALS = frozenset(' \t\r\n();="')

#: Whitespace, including the CR and LF left over from folding.
_WHITESPACE = frozenset(" \t\r\n")

#: A key in a ``key=value`` pair: a method (optionally with a
#: ``/version``), ``reason``, a ``ptype.property``, or an extension
#: keyword such as Microsoft's ``action``.
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[0-9]+)?$")

#: An authres-version, which may follow the authserv-id.
_VERSION_RE = re.compile(r"^[0-9]+$")


class AuthResultsParseError(ValueError):
    """Raised when an ``Authentication-Results`` value cannot be read."""


@dataclass(frozen=True)
class AuthResult:
    """One ``method=result`` entry of an ``Authentication-Results`` header.

    Attributes:
        method: Authentication method (``dmarc``, ``dkim``, ``spf``, ...),
            lowercase and without a version.
        result: The method's result (``pass``, ``fail``, ...), lowercase.
        properties: Every ``key=value`` pair after the result, in order:
            ``ptype.property`` pairs such as ``header.from``, the
            ``reason``, and extensions such as Microsoft's ``action``.
            Keys are lowercase; values are unquoted and otherwise as
            written.
    """

    method: str
    result: str
    properties: tuple[tuple[str, str], ...] = ()

    def values(self, key: str) -> list[str]:
        """Return every value of *key* (e.g. ``header.from``), in order."""
        key = key.lower()
        return [value for k, value in self.properties if k == key]


@dataclass(frozen=True)
class AuthResults:
    """A parsed ``Authentication-Results`` header.

    Attributes:
        authserv_id: The authserv-id, unquoted, or None when the header
            has none (Microsoft 365).
        results: The header's entries, in order.  Empty for ``none``.
    """

    authserv_id: str | None
    results: tuple[AuthResult, ...]


class _Kind(enum.Enum):
    WORD = enum.auto()
    SEMICOLON = enum.auto()
    EQUALS = enum.auto()


@dataclass
class _Token:
    """A lexical token.

    Attributes:
        kind: Token kind.
        text: The word, with quoted parts unquoted.
        spaced: Whether whitespace or a comment precedes the token.
        quoted: Whether any part of a word was a quoted string.
    """

    kind: _Kind
    text: str
    spaced: bool
    quoted: bool = False


def _skip_comment(value: str, start: int) -> int:
    """Return the index just after the comment opening at *start*."""
    depth = 0
    i = start
    while i < len(value):
        c = value[i]
        if c == "\\":
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AuthResultsParseError("unterminated comment")


def _read_quoted(value: str, start: int) -> tuple[str, int]:
    """Read the quoted string opening at *start*.

    Returns:
        The unquoted text, and the index just after the closing quote.
    """
    text: list[str] = []
    i = start + 1
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            text.append(value[i + 1])
            i += 2
        elif c == '"':
            return "".join(text), i + 1
        else:
            text.append(c)
            i += 1
    raise AuthResultsParseError("unterminated quoted string")


def _add_word(
    tokens: list[_Token], text: str, spaced: bool, quoted: bool
) -> None:
    """Append a word, joining it to a word it directly follows.

    A quoted local part and the ``@domain`` after it form one value.
    """
    last = tokens[-1] if tokens else None
    if not spaced and last is not None and last.kind is _Kind.WORD:
        last.text += text
        last.quoted = last.quoted or quoted
    else:
        tokens.append(_Token(_Kind.WORD, text, spaced, quoted))


def _tokenize(value: str) -> list[_Token]:
    """Split *value* into words, ``;`` and ``=``, dropping comments."""
    tokens: list[_Token] = []
    spaced = True
    i = 0
    while i < len(value):
        c = value[i]
        if c in _WHITESPACE:
            spaced = True
            i += 1
        elif c == "(":
            i = _skip_comment(value, i)
            spaced = True
        elif c == ")":
            raise AuthResultsParseError("unbalanced ')'")
        elif c in ";=":
            kind = _Kind.SEMICOLON if c == ";" else _Kind.EQUALS
            tokens.append(_Token(kind, c, spaced))
            spaced = False
            i += 1
        elif c == '"':
            text, i = _read_quoted(value, i)
            _add_word(tokens, text, spaced, quoted=True)
            spaced = False
        else:
            end = i
            while end < len(value) and value[end] not in _SPECIALS:
                end += 1
            _add_word(tokens, value[i:end], spaced, quoted=False)
            spaced = False
            i = end
    return tokens


def ascii_lower(value: str) -> str:
    """Lowercase *value* if it is ASCII; leave it unchanged otherwise.

    For comparing the hostnames in a header: they are case-insensitive,
    but ``str.lower`` also folds some non-ASCII characters onto ASCII
    ones (the Kelvin sign becomes ``k``), so such a value must never
    match an ASCII one.
    """
    return value.lower() if value.isascii() else value


def _split_segments(tokens: list[_Token]) -> list[list[_Token]]:
    """Split *tokens* at each ``;``."""
    segments: list[list[_Token]] = [[]]
    for token in tokens:
        if token.kind is _Kind.SEMICOLON:
            segments.append([])
        else:
            segments[-1].append(token)
    return segments


@dataclass(frozen=True)
class _Pair:
    """A ``key=value`` pair; *quoted* if any part of the value was."""

    key: str
    value: str
    quoted: bool


def _parse_pairs(tokens: list[_Token]) -> list[_Pair]:
    """Read a segment as a sequence of ``key=value`` pairs.

    A value continues through any ``=`` and words written directly
    after it, so base64 padding such as ``header.b=abc=`` stays whole.
    """
    pairs: list[_Pair] = []
    i = 0
    while i < len(tokens):
        key = tokens[i]
        if (
            key.kind is not _Kind.WORD
            or key.quoted
            or not _KEY_RE.match(key.text)
        ):
            raise AuthResultsParseError(f"expected a key, got {key.text!r}")
        if i + 1 >= len(tokens) or tokens[i + 1].kind is not _Kind.EQUALS:
            raise AuthResultsParseError(f"expected '=' after {key.text!r}")
        if i + 2 >= len(tokens) or tokens[i + 2].kind is not _Kind.WORD:
            raise AuthResultsParseError(f"missing value for {key.text!r}")
        value = tokens[i + 2].text
        quoted = tokens[i + 2].quoted
        i += 3
        while i < len(tokens) and not tokens[i].spaced:
            value += tokens[i].text
            quoted = quoted or tokens[i].quoted
            i += 1
        pairs.append(_Pair(key.text.lower(), value, quoted))
    return pairs


def _parse_entry(tokens: list[_Token]) -> AuthResult:
    """Read one resinfo: ``method=result`` and the pairs after it.

    The result is a keyword, never a quoted string.  Beyond that it is
    not checked: Amazon SES writes segments such as
    ``envelope-from=user@example.com`` beside its entries, which read
    as entries of methods no caller looks for.
    """
    first, *rest = _parse_pairs(tokens)
    if "." in first.key:
        raise AuthResultsParseError(f"expected a method, got {first.key!r}")
    if first.quoted:
        raise AuthResultsParseError(f"quoted result {first.value!r}")
    return AuthResult(
        method=first.key.partition("/")[0],
        result=first.value.lower(),
        properties=tuple((pair.key, pair.value) for pair in rest),
    )


def _parse_authserv_id(tokens: list[_Token]) -> str:
    """Read the authserv-id and the optional version after it."""
    if not tokens or len(tokens) > 2:
        raise AuthResultsParseError("malformed authserv-id")
    if len(tokens) == 2 and (
        tokens[1].quoted or not _VERSION_RE.match(tokens[1].text)
    ):
        raise AuthResultsParseError("malformed authserv-id")
    return tokens[0].text


def _is_no_result(entries: list[list[_Token]]) -> bool:
    """Whether *entries* is the lone ``none`` that stands for no results."""
    if len(entries) != 1 or len(entries[0]) != 1:
        return False
    token = entries[0][0]
    return not token.quoted and token.text.lower() == "none"


def parse_authentication_results(value: str) -> AuthResults:
    """Parse an ``Authentication-Results`` header value.

    Args:
        value: The header value, folded or not.

    Returns:
        The authserv-id and the entries.

    Raises:
        AuthResultsParseError: If *value* does not follow the grammar,
            or is longer than ``MAX_LENGTH``.
    """
    if len(value) > MAX_LENGTH:
        raise AuthResultsParseError(f"longer than {MAX_LENGTH} characters")
    segments = _split_segments(_tokenize(value))
    first = segments[0]
    if any(token.kind is _Kind.EQUALS for token in first):
        authserv_id = None
        entries = segments
    else:
        authserv_id = _parse_authserv_id(first)
        entries = segments[1:]

    # Tolerate empty segments, such as after a trailing ";".
    entries = [entry for entry in entries if entry]
    if _is_no_result(entries):
        return AuthResults(authserv_id, ())
    return AuthResults(
        authserv_id, tuple(_parse_entry(entry) for entry in entries)
    )
