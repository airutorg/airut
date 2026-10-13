# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack channel thread history replay.

Reads a channel thread via ``conversations.replies`` and renders the
messages Claude has not seen as a prompt preamble, so Claude has the same
context a human reading the thread would.  Two windows are supported: the
whole prior thread on mid-thread engagement, and — with ``sticky_threads``
off — the messages posted since the previous mention (catch-up).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import cast

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from airut._json_types import JsonDict, JsonValue
from airut.gateway.slack.authorizer import SlackAuthorizer
from airut.gateway.slack.listener import CONTENT_SUBTYPES, mentions_bot
from airut.gateway.slack.mention_resolver import MentionResolver


logger = logging.getLogger(__name__)

#: Most recent thread messages folded into the prompt per replay; older
#: messages are summarized as an omitted-count line.
_HISTORY_REPLAY_LIMIT = 200

#: Hard cap on messages fetched while paginating ``conversations.replies``,
#: bounding work for pathologically long threads before trimming to
#: :data:`_HISTORY_REPLAY_LIMIT`.
_HISTORY_FETCH_CAP = 1000

#: Preamble intro for the first mention inside a thread the bot has not
#: joined: the replayed messages are everything that preceded it.
_INVITED_INTRO = (
    "The user invited you into an existing Slack thread.  The messages "
    "below are the conversation that preceded the invocation, in order.  "
    "Use them as background; the invocation that triggered you is the "
    "attributed message that follows this preamble."
)

#: Preamble intro for a later mention in an engaged thread when
#: ``sticky_threads`` is off: the replayed messages are the ones posted
#: since the previous mention, which were not delivered to Claude.
_CATCH_UP_INTRO = (
    "In this Slack thread you only receive messages that mention you.  "
    "The messages below were posted in the thread since you were last "
    "mentioned and were not addressed to you, in order.  Use them as "
    "background; the attributed message(s) that follow this preamble are "
    "the ones that mentioned you."
)


@dataclass
class ThreadReplay:
    """Thread messages rendered for a prompt preamble.

    The default instance is the empty replay (nothing to fold in).
    """

    lines: list[str] = field(default_factory=list)
    """One ``[<name>]: <body>`` line per replayed message, preceded by an
    ``[N earlier messages omitted]`` line when the window was trimmed."""

    author_ids: list[str] = field(default_factory=list)
    """Authors of the replayed messages, for the outbound mention set."""

    file_urls: list[tuple[str, str]] = field(default_factory=list)
    """``(name, url)`` of the replayed messages' attachments, in order."""

    catch_up: bool = False
    """Whether this is a catch-up (vs mid-thread engagement) replay."""

    @property
    def preamble(self) -> str:
        """The intro and lines joined, or empty when nothing was replayed."""
        if not self.lines:
            return ""
        intro = _CATCH_UP_INTRO if self.catch_up else _INVITED_INTRO
        return "\n".join([intro, *self.lines])


class ThreadHistory:
    """Fetches and renders Slack channel thread history for replay.

    Args:
        client: Slack ``WebClient`` for ``conversations.replies``.
        authorizer: Authorizer providing display names, the bot user ID,
            and authorization of earlier mentions (catch-up boundary).
    """

    def __init__(self, client: WebClient, authorizer: SlackAuthorizer) -> None:
        self._client = client
        self._authorizer = authorizer

    def replay(
        self,
        channel_id: str,
        thread_ts: str,
        triggering_ts: str,
        resolver: MentionResolver,
        *,
        catch_up: bool,
    ) -> ThreadReplay:
        """Fetch a thread and render the messages Claude has not seen.

        Reads the thread via ``conversations.replies`` (paginated, bounded
        by :data:`_HISTORY_FETCH_CAP`), drops the triggering message and
        non-human messages, keeps the most recent
        :data:`_HISTORY_REPLAY_LIMIT`, and renders each as
        ``[<display name>]: <resolved body>``.  The invocation itself is
        delivered separately via the attributed message body, so it is not
        repeated here.

        Files attached to the replayed messages are collected for deferred
        download so they land in the inbox alongside the triggering
        message's own attachments, and each line notes the filenames it
        carried.

        Args:
            channel_id: Channel the thread lives in.
            thread_ts: Root timestamp of the thread.
            triggering_ts: ts of the invocation message (excluded).
            resolver: Mention resolver for inbound token resolution.
            catch_up: Replay only the messages posted since the previous
                mention (``sticky_threads`` off) instead of the whole
                thread.

        Returns:
            The rendered replay; empty when there is nothing to replay.
        """
        messages = self._fetch_thread_messages(channel_id, thread_ts)
        if catch_up:
            messages = self._since_previous_mention(messages, triggering_ts)

        replay = ThreadReplay(catch_up=catch_up)
        history = [
            m
            for m in messages
            if m.get("ts") != triggering_ts and _is_replayable(m)
        ]
        if not history:
            return replay

        omitted = len(history) - _HISTORY_REPLAY_LIMIT
        if omitted > 0:
            history = history[-_HISTORY_REPLAY_LIMIT:]
            replay.lines.append(f"[{omitted} earlier messages omitted]")

        for message in history:
            author = cast(str, message.get("user", ""))
            replay.author_ids.append(author)
            # Warm the user cache (fetching on a miss, as inbound mention
            # tokens do) so authors who never addressed the bot render by
            # name rather than as a raw user ID.
            self._authorizer.get_user_info(author)
            display = self._authorizer.get_display_name(author)
            resolved = resolver.resolve_in(
                cast(str, message.get("text", "")), strip_bot_mention=False
            )
            message_files = extract_file_urls(message.get("files"))
            replay.file_urls.extend(message_files)
            rendered = resolved
            if message_files:
                names = ", ".join(name for name, _ in message_files)
                suffix = f"[attached: {names}]"
                # A file_share message may have no comment text; avoid the
                # double space that ``{resolved} {suffix}`` would leave then.
                rendered = f"{resolved} {suffix}" if resolved else suffix
            replay.lines.append(f"[{display}]: {rendered}")

        return replay

    def _since_previous_mention(
        self, messages: list[JsonDict], triggering_ts: str
    ) -> list[JsonDict]:
        """Slice thread *messages* to those posted since the previous mention.

        With ``sticky_threads`` off the listener delivers only messages that
        ``@``-mention the bot, so the messages Claude has not seen are the
        ones between the previous delivered mention and the trigger.
        Messages from the trigger onwards are excluded: a later mention is
        delivered on its own and a later non-mention belongs to the next
        catch-up.  When no earlier delivered mention is found (e.g. it was
        deleted), the window starts at the root.

        Returns no messages when the trigger is not among the fetched ones
        (thread past the fetch cap, or the fetch failed): the window cannot
        be placed, and guessing would replay messages Claude already saw.
        """
        end = next(
            (i for i, m in enumerate(messages) if m.get("ts") == triggering_ts),
            None,
        )
        if end is None:
            if messages:
                logger.warning(
                    "Skipping Slack catch-up replay: message %s not in the "
                    "%d fetched thread messages",
                    triggering_ts,
                    len(messages),
                )
            return []
        bot_user_id = self._authorizer.get_bot_user_id()
        for i in range(end - 1, -1, -1):
            if self._is_delivered_mention(messages[i], bot_user_id):
                return messages[i + 1 : end]
        return messages[:end]

    def _is_delivered_mention(
        self, message: JsonDict, bot_user_id: str | None
    ) -> bool:
        """Return whether *message* is a mention the bot acted on.

        Only a human-authored mention from an authorized user was delivered
        to Claude; bot-authored mentions are dropped by the listener and an
        unauthorized user's mention is rejected, so neither marks what
        Claude last saw.
        """
        if not _is_replayable(message) or not mentions_bot(
            cast(str, message.get("text", "")), bot_user_id
        ):
            return False
        authorized, _ = self._authorizer.authorize(
            cast(str, message.get("user", ""))
        )
        return authorized

    def _fetch_thread_messages(
        self, channel_id: str, thread_ts: str
    ) -> list[JsonDict]:
        """Page through ``conversations.replies`` up to the fetch cap.

        Messages are deduplicated by ``ts``, keeping the first occurrence:
        Slack may repeat the parent message at the top of each page, which
        would otherwise appear out of order (and more than once).
        """
        messages: list[JsonDict] = []
        seen_ts: set[str] = set()
        cursor: str | None = None
        try:
            while True:
                resp = self._client.conversations_replies(
                    channel=channel_id,
                    ts=thread_ts,
                    limit=200,
                    cursor=cursor,
                )
                for message in cast(list[JsonDict], resp.get("messages", [])):
                    ts = cast(str, message.get("ts", ""))
                    if ts not in seen_ts:
                        seen_ts.add(ts)
                        messages.append(message)
                cursor = resp.get("response_metadata", {}).get("next_cursor")
                if not cursor or len(messages) >= _HISTORY_FETCH_CAP:
                    break
        except SlackApiError as e:
            logger.warning(
                "Failed to fetch Slack thread history for %s: %s",
                thread_ts,
                e,
            )
        return messages


def _is_replayable(message: JsonDict) -> bool:
    """Return whether a thread message is human content worth replaying.

    Keeps human messages, including file uploads (Slack tags those
    ``file_share``); drops bot posts and system/edit subtypes.  The
    content-subtype carve-out matches the listener so a file shared before
    the invocation is replayed and downloaded.
    """
    subtype = message.get("subtype")
    return (
        bool(message.get("user"))
        and not message.get("bot_id")
        and (not subtype or subtype in CONTENT_SUBTYPES)
    )


def extract_file_urls(raw_files: JsonValue) -> list[tuple[str, str]]:
    """Pull ``(filename, download_url)`` tuples from a message's ``files``.

    Shared by the triggering-message parse and the thread-history replay so
    attachments are queued for deferred download identically wherever they
    appear.  Files lacking a usable URL are skipped.

    Args:
        raw_files: The ``files`` field of a Slack message payload
            (non-lists, including an absent field, yield no files).

    Returns:
        List of ``(name, url)`` pairs, in payload order.
    """
    if not isinstance(raw_files, list):
        return []
    result: list[tuple[str, str]] = []
    for entry in raw_files:
        if not isinstance(entry, dict):
            continue
        name = cast(str, entry.get("name", "unnamed"))
        url = cast(
            str,
            entry.get("url_private_download") or entry.get("url_private", ""),
        )
        if url:
            result.append((name, url))
    return result
