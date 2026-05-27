# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack mention resolution.

Converts Slack mention tokens in inbound message bodies into
human-readable strings (:meth:`MentionResolver.resolve_in`) and rewrites
unambiguous ``@name`` / ``#name`` / ``@group`` tokens in outbound bodies
back into Slack reference syntax (:meth:`MentionResolver.rewrite_out`).

The resolver reuses the user, user-group, and channel caches owned by
:class:`~airut.gateway.slack.authorizer.SlackAuthorizer` so it issues no
duplicate API traffic.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

from airut.gateway.slack.authorizer import SlackAuthorizer, UserInfo


#: Broadcast tokens that are kept literal and never rewritten outbound.
_BROADCAST_TOKENS = frozenset({"channel", "here", "everyone"})

#: Matches a single Slack reference token ``<...>`` (content has no ``>``).
_INBOUND_TOKEN_RE = re.compile(r"<([^>]+)>")

#: Matches an outbound ``@name`` / ``#name`` token at a word boundary.  The
#: leading sigil must not follow a word character or URL/email punctuation
#: (so ``user@host`` and ``path#frag`` are not rewritten); the name body is
#: greedy, so the trailing boundary is implicit.
_OUTBOUND_TOKEN_RE = re.compile(r"(?<![\w./@#-])([@#])([A-Za-z0-9._-]+)")


def _match_user(
    name: str, candidates: Sequence[UserInfo]
) -> tuple[UserInfo | None, bool]:
    """Match a bare name against a candidate user set.

    Matches case-insensitively on ``display_name``, then ``real_name``,
    then ``name`` (Slack handle), in that order.  Bot users are excluded.

    Args:
        name: The token name without its sigil.
        candidates: Per-thread candidate users.

    Returns:
        ``(user, ambiguous)``.  ``user`` is the sole match for the
        highest-priority field that matched, or None.  ``ambiguous`` is
        True when a field matched more than one distinct user, in which
        case the token must be left alone.
    """
    name_lower = name.lower()
    for field in ("display_name", "real_name", "name"):
        matches = [
            c
            for c in candidates
            if not c.is_bot
            and getattr(c, field)
            and getattr(c, field).lower() == name_lower
        ]
        unique_ids = {c.user_id for c in matches}
        if len(unique_ids) == 1:
            return matches[0], False
        if len(unique_ids) > 1:
            return None, True
    return None, False


class MentionResolver:
    """Resolves Slack mention tokens in both directions.

    Args:
        authorizer: The :class:`SlackAuthorizer` whose caches back user,
            user-group, and channel lookups.
        bot_user_id: The Airut bot's own user ID, used to strip the bot's
            mention from invocation messages.  When None the bot mention is
            resolved like any other user.
    """

    def __init__(
        self, authorizer: SlackAuthorizer, bot_user_id: str | None = None
    ) -> None:
        self._authorizer = authorizer
        self._bot_user_id = bot_user_id
        self._bot_strip_re: re.Pattern[str] | None = None
        if bot_user_id:
            self._bot_strip_re = re.compile(
                rf"\s*<@{re.escape(bot_user_id)}(?:\|[^>]*)?>"
            )

    def resolve_in(self, text: str, *, strip_bot_mention: bool = False) -> str:
        """Convert Slack mention tokens into human-readable strings.

        Args:
            text: An inbound message or replayed thread-history body.
            strip_bot_mention: When True, the bot's own mention is removed
                entirely (used for the invocation message, where it is
                redundant context).  When False it is resolved to the bot's
                display name (used for replayed history, where it records
                that the bot was addressed).

        Returns:
            The body with mention tokens rendered as ``@name`` / ``#name``
            and angle-bracketed links unwrapped.
        """
        if strip_bot_mention and self._bot_strip_re is not None:
            text = self._bot_strip_re.sub("", text).strip()
        return _INBOUND_TOKEN_RE.sub(self._resolve_token, text)

    def rewrite_out(
        self, text: str, candidates: Sequence[UserInfo] = ()
    ) -> str:
        """Rewrite unambiguous name tokens into Slack reference syntax.

        Scans for ``@name`` / ``#name`` tokens outside code spans and
        fenced code blocks.  ``@name`` resolves against the per-thread
        candidate users first, then user groups; ``#name`` resolves against
        the workspace channel list.  Tokens that match exactly one referent
        are rewritten; zero or multiple matches are left as literal text.

        Args:
            text: Outbound body, already rendered to Slack ``mrkdwn``.
            candidates: Per-thread candidate users for ``@name`` resolution.

        Returns:
            The body with resolvable tokens rewritten to Slack syntax.
        """

        def _transform(segment: str) -> str:
            return _OUTBOUND_TOKEN_RE.sub(
                lambda m: self._rewrite_token(
                    m.group(1), m.group(2), candidates
                ),
                segment,
            )

        return _apply_outside_code(text, _transform)

    def _resolve_token(self, match: re.Match[str]) -> str:
        """Render a single inbound ``<...>`` token as readable text."""
        content = match.group(1)
        kind = content[0]

        if kind == "@":
            user_id, _, _ = content[1:].partition("|")
            info = self._authorizer.get_user_info(user_id)
            display = info.display_name if info and info.display_name else None
            return f"@{display or user_id}"

        if kind == "#":
            channel_id, sep, label = content[1:].partition("|")
            return f"#{label if sep else channel_id}"

        if kind == "!":
            body = content[1:]
            if body.startswith("subteam^"):
                subteam_id, sep, handle = body[len("subteam^") :].partition("|")
                return f"@{handle if sep else subteam_id}"
            if body in _BROADCAST_TOKENS:
                return f"@{body}"
            return match.group(0)

        # Angle-bracketed auto-link: ``<url>`` or ``<url|text>``.
        url, sep, label = content.partition("|")
        if sep:
            return f"{label} ({url})"
        return url

    def _rewrite_token(
        self, sigil: str, name: str, candidates: Sequence[UserInfo]
    ) -> str:
        """Resolve a single outbound ``@name`` / ``#name`` token."""
        literal = f"{sigil}{name}"

        if sigil == "#":
            channel_id = self._authorizer.resolve_channel_id(name)
            if channel_id:
                return f"<#{channel_id}|{name}>"
            return literal

        if name.lower() in _BROADCAST_TOKENS:
            return literal

        user, ambiguous = _match_user(name, candidates)
        if ambiguous:
            return literal
        if user is not None:
            return f"<@{user.user_id}>"

        group_id = self._authorizer.lookup_group_id(name)
        if group_id is not None:
            return f"<!subteam^{group_id}|{name}>"
        return literal


def _apply_outside_code(text: str, transform: Callable[[str], str]) -> str:
    """Apply *transform* to text outside code spans and fenced blocks.

    Lines inside ``` fences are passed through untouched; on other lines
    the content between backticks (inline code spans) is skipped by
    transforming only the even-indexed segments of a backtick split.

    Args:
        text: The text to process.
        transform: Callback applied to each non-code text segment.

    Returns:
        The text with *transform* applied outside all code regions.
    """
    result: list[str] = []
    in_fence = False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            result.append(line)
        elif in_fence:
            result.append(line)
        else:
            parts = line.split("`")
            for i in range(0, len(parts), 2):
                parts[i] = transform(parts[i])
            result.append("`".join(parts))
    return "\n".join(result)
