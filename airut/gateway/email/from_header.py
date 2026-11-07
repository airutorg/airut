# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Strict reading of an incoming email's ``From`` header.

The From address decides whether a sender is authorized and where the
reply goes, so the header is read strictly.  ``parse_from_mailbox``
returns an address only when the header:

- is at most ``MAX_LENGTH`` characters once unfolded — a bound taken
  from RFC 5322's limit on a line — and nests parentheses at most
  ``MAX_COMMENT_DEPTH`` deep.
  Both are checked before parsing: the standard library's address
  parser slows down quadratically with the length of its input and
  recurses into nested comments.  Nesting the raw text does not show
  (an encoded word can decode to parentheses) is still bounded by the
  length, and the parser's ``RecursionError`` is a rejection;
- holds exactly one mailbox, outside any group, as RFC 5322 reads it,
  with no parse error other than obsolete syntax (such as an unquoted
  ``.`` in a display name);
- writes the address plainly: as the whole header, or as the one
  ``<address>`` that ends it, after a display name.  Comments,
  whitespace or a route inside the address, anything after it, and any
  other ``<`` or ``>`` are rejected.  So is a display name that holds
  specials outside quoted strings and comments when read raw (an
  encoded word, which the standard library decodes first, may hide
  them), or that holds an encoded word and decodes, as lenient mail
  clients decode it, to text with ``<``, ``>`` or ``@``.  RFC 5322
  allows some of these, but another parser may read such a header as
  naming a different address;
- has an address of a strict form: an unquoted local part, ``@``, and a
  domain of letters, digits, dots and hyphens.
"""

import re
from email import policy
from email.errors import HeaderParseError, ObsoleteHeaderDefect
from email.header import decode_header, make_header


#: Longest From header accepted, unfolded: RFC 5322 §2.1.1's limit on
#: a line.  One mailbox fits easily (a folded header may be longer).
MAX_LENGTH = 998

#: Deepest nesting of parentheses accepted.
MAX_COMMENT_DEPTH = 3

#: Strict addr-spec: rejects local parts that need quoting, domain
#: literals, and other tricks.
_ADDRESS_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+$")

#: RFC 5322 specials that a display name may hold only inside a quoted
#: string or a comment.  ``.`` is left out: obsolete syntax allows it.
_PHRASE_SPECIALS = frozenset(")<>[]:;@\\,")

#: Line breaks that fold a header onto continuation lines.
_FOLDING_RE = re.compile(r"\r?\n(?=[ \t])")


def _paren_depth(value: str) -> int:
    """Return how deeply parentheses nest in *value*.

    Counts every ``(``, quoted or escaped ones too, and only an
    unescaped ``)`` as closing: a comment is never shallower than this,
    and counting more only rejects more.
    """
    depth = deepest = 0
    escaped = False
    for c in value:
        if c == "(":
            depth += 1
            deepest = max(deepest, depth)
        elif c == ")" and depth > 0 and not escaped:
            depth -= 1
        escaped = c == "\\" and not escaped
    return deepest


def _plain_display_name(text: str) -> bool:
    """Whether *text*, read raw, is a display name and nothing more.

    Read as a parser that does not decode encoded words reads it: the
    specials that would give it structure may appear only inside a
    quoted string or a comment, and both must be closed.
    """
    depth = 0
    quoted = False
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and (quoted or depth > 0):
            i += 2
            continue
        if quoted:
            quoted = c != '"'
        elif c == "(":
            depth += 1
        elif depth > 0:
            if c == ")":
                depth -= 1
        elif c == '"':
            quoted = True
        elif c in _PHRASE_SPECIALS:
            return False
        i += 1
    return not quoted and depth == 0


def _decodes_plainly(text: str) -> bool:
    """Whether *text*, decoded leniently, shows no address it hides raw.

    Lenient decoders, as in many mail clients, also decode encoded words
    that the standard library's parser leaves alone (inside comments, or
    not set apart by whitespace), and decoded text can move what was
    quoted or commented out.  So a display name holding any encoded word
    may not decode to text with ``<``, ``>`` or ``@`` in it.
    """
    try:
        parts = decode_header(text)
        decoded = str(make_header(parts))
    except (HeaderParseError, LookupError, ValueError):
        return False
    if all(charset is None for _, charset in parts):
        return True
    return not any(c in decoded for c in "<>@")


def _written_plainly(value: str, address: str) -> bool:
    """Whether *value* is *address*, or a display name and ``<address>``.

    The ``<address>`` must end the header and be its only ``<`` and
    ``>``.
    """
    stripped = value.strip(" \t")
    if stripped == address:
        return True
    suffix = f"<{address}>"
    if not (
        stripped.count("<") == 1
        and stripped.count(">") == 1
        and stripped.endswith(suffix)
    ):
        return False
    name = stripped[: -len(suffix)]
    return _plain_display_name(name) and _decodes_plainly(name)


def parse_from_mailbox(from_header: str) -> str | None:
    """Return the single mailbox in a From header value, or None.

    Args:
        from_header: Raw From header value, folded or not.

    Returns:
        The lowercase address, or None if the header is rejected (see
        the module docstring for the rules).
    """
    value = _FOLDING_RE.sub("", from_header)
    if len(value) > MAX_LENGTH or _paren_depth(value) > MAX_COMMENT_DEPTH:
        return None

    try:
        header = policy.default.header_factory("from", value)
    except (ValueError, IndexError, RecursionError):
        # ValueError: a bare CR or LF left in an address.  IndexError:
        # the parser fails on some malformed groups, such as "(c):".
        # RecursionError: comments nested in decoded text.
        return None

    if any(not isinstance(d, ObsoleteHeaderDefect) for d in header.defects):
        return None
    if len(header.groups) != 1:
        return None
    group = header.groups[0]
    if group.display_name is not None or len(group.addresses) != 1:
        return None

    address = group.addresses[0].addr_spec
    if (
        not _ADDRESS_RE.match(address)
        or "=?" in address
        or not _written_plainly(value, address)
    ):
        return None
    return address.lower()
