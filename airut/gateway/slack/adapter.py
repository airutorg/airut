# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack channel adapter.

Implements the ``ChannelAdapter`` protocol for Slack, wrapping
authorization, thread mapping, and Slack API message delivery.
"""

from __future__ import annotations

import logging
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from airut._json_types import JsonDict
from airut.gateway.channel import (
    AuthenticationError,
    ChannelAdapter,
    ChannelSendError,
    ParsedMessage,
    PlanStreamer,
    RawMessage,
    TaskPhase,
)
from airut.gateway.slack.authorizer import SlackAuthorizer
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.listener import SlackChannelListener
from airut.gateway.slack.mention_resolver import MentionResolver
from airut.gateway.slack.mrkdwn import render_mrkdwn
from airut.gateway.slack.plan_streamer import SlackPlanStreamer
from airut.gateway.slack.thread_store import SlackThreadStore


logger = logging.getLogger(__name__)

#: Maximum characters in a single ``mrkdwn`` ``text`` message.
_MAX_TEXT_CHARS = 40000

#: Maximum number of split messages before falling back to a file upload.
_MAX_SPLIT_MESSAGES = 5

#: Maximum length for thread title.
_MAX_TITLE_LENGTH = 60

#: Most recent thread messages folded into the prompt on mid-thread
#: engagement; older messages are summarized as an omitted-count line.
_HISTORY_REPLAY_LIMIT = 200

#: Hard cap on messages fetched while paginating ``conversations.replies``,
#: bounding work for pathologically long threads before trimming to
#: :data:`_HISTORY_REPLAY_LIMIT`.
_HISTORY_FETCH_CAP = 1000

#: Maximum attachment download size (100 MB).
_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024

#: Allowed hostnames for Slack file download URLs.  Only URLs on these
#: hosts will be fetched during attachment download.  This prevents the
#: bot token from being sent to non-Slack hosts if the event payload
#: were ever to contain unexpected URLs.
#:
#: ``files.slack.com`` — current ``url_private`` / ``url_private_download``
#: ``slack.com``       — legacy ``url_private`` format (``/files-pri/``)
_SLACK_FILE_HOSTS: frozenset[str] = frozenset({"files.slack.com", "slack.com"})


@dataclass
class SlackParsedMessage(ParsedMessage):
    """Slack-specific parsed message.

    Carries Slack threading info and deferred file download state
    alongside the channel-agnostic ``ParsedMessage`` fields.  The core
    sees a plain ``ParsedMessage``; the adapter downcasts to access
    Slack-specific fields when sending replies.
    """

    slack_channel_id: str = ""
    """DM channel ID (``D``-prefixed) or channel ID (``C``/``G``-prefixed)."""

    slack_thread_ts: str = ""
    """Thread timestamp for reply threading (the engaged thread root)."""

    slack_file_urls: list[tuple[str, str]] = field(default_factory=list)
    """List of ``(filename, download_url)`` for deferred download."""

    triggering_message_ts: str = ""
    """ts of the message that arrived, used for the ``:eyes:`` reaction."""

    is_channel: bool = False
    """Whether this arrived in a channel (vs a DM).

    Gates the DM-only ``assistant.threads`` status and title APIs."""

    mention_candidate_ids: list[str] = field(default_factory=list)
    """User IDs eligible for outbound ``@``-mention rewriting in the reply.

    The triggering sender, any authors seen in replayed thread history, and
    members of user groups named in the authorization rules."""


class SlackChannelAdapter(ChannelAdapter):
    """``ChannelAdapter`` implementation for Slack (Socket Mode).

    Wraps ``SlackAuthorizer``, ``SlackThreadStore``, and the Slack
    ``WebClient`` behind the ``ChannelAdapter`` interface.
    """

    def __init__(
        self,
        config: SlackChannelConfig,
        client: WebClient,
        authorizer: SlackAuthorizer,
        thread_store: SlackThreadStore,
        slack_listener: SlackChannelListener | None = None,
        *,
        repo_id: str,
    ) -> None:
        self._config = config
        self._client = client
        self._authorizer = authorizer
        self._thread_store = thread_store
        self._listener = slack_listener
        self._repo_id = repo_id
        self._resolver: MentionResolver | None = None

    @classmethod
    def from_config(
        cls, config: SlackChannelConfig, *, repo_id: str
    ) -> SlackChannelAdapter:
        """Create an adapter with all Slack components from config.

        Args:
            config: Slack channel configuration.
            repo_id: Repository identifier.

        Returns:
            Fully configured ``SlackChannelAdapter``.
        """
        from airut.gateway.config import get_storage_dir

        client = WebClient(token=config.bot_token)
        authorizer = SlackAuthorizer(client=client, rules=config.authorized)
        state_dir = get_storage_dir(repo_id)
        thread_store = SlackThreadStore(state_dir)
        listener = SlackChannelListener(config, thread_store, authorizer)

        return cls(
            config=config,
            client=client,
            authorizer=authorizer,
            thread_store=thread_store,
            slack_listener=listener,
            repo_id=repo_id,
        )

    @property
    def listener(self) -> SlackChannelListener:
        """Slack channel listener for message lifecycle management.

        Raises:
            RuntimeError: If adapter was created without a listener.
        """
        if self._listener is None:
            raise RuntimeError("SlackChannelAdapter created without a listener")
        return self._listener

    def channel_context(self) -> str:
        """Return the base system prompt for the Slack channel.

        This is the standard set of instructions about the Slack
        interface, formatting, tool limitations, and directory layout
        that applies to every Slack-delivered task — both interactive
        messages and scheduled tasks.
        """
        return (
            "User is interacting with this session via Slack "
            "and will receive your last reply as a Slack message. "
            "After the reply, everything not in /workspace, /inbox, "
            "and /storage is reset. "
            "Markdown formatting (except tables) is supported "
            "in your responses. "
            "To send files back to the user, place them in the "
            "/outbox directory root (no subdirectories). "
            "Use /storage to persist files across messages.\n\n"
            "IMPORTANT: AskUserQuestion and plan mode tools "
            "(EnterPlanMode/ExitPlanMode) do not work over Slack. "
            "If you need clarification, include questions in "
            "your response text and the user will reply via Slack."
        )

    def authenticate_and_parse(
        self, raw_message: RawMessage[JsonDict]
    ) -> SlackParsedMessage:
        """Authenticate sender and parse the Slack message.

        Args:
            raw_message: ``RawMessage`` wrapping a Slack event payload.

        Returns:
            ``SlackParsedMessage`` if authenticated and authorized.

        Raises:
            AuthenticationError: If authorization fails.
        """
        payload = raw_message.content
        user_id = cast(str, payload.get("user", ""))
        text = cast(str, payload.get("text", ""))
        channel_id = cast(str, payload.get("channel", ""))
        message_ts = cast(str, payload.get("ts", ""))
        raw_thread_ts = cast(str, payload.get("thread_ts", ""))

        # A channel arrives either as an ``app_mention`` event (no
        # channel_type) or a ``message`` event with channel_type
        # channel/group; DMs are message.im (channel_type "im").
        event_type = cast(str, payload.get("type", ""))
        channel_type = cast(str, payload.get("channel_type", ""))
        is_channel = event_type == "app_mention" or channel_type in (
            "channel",
            "group",
        )

        # The engaged thread root: a top-level channel mention has no
        # thread_ts, so its own ts roots the thread.
        thread_ts = raw_thread_ts or message_ts

        # Authorize via rules
        authorized, reason = self._authorizer.authorize(user_id)
        if not authorized:
            logger.warning(
                "Repo '%s': rejecting Slack message from %s: %s",
                self._repo_id,
                user_id,
                reason,
            )
            raise AuthenticationError(sender=user_id, reason=reason)

        # Instant acknowledgement for channels: a :eyes: reaction on the
        # triggering message.  Added here (post-authorization, per arriving
        # message) so coalesced follow-ups are acknowledged too and an
        # unauthorized mention never gets a reaction.
        if is_channel:
            self._add_reaction(channel_id, message_ts)

        # Look up existing conversation from thread mapping
        conversation_id = self._thread_store.get_conversation_id(
            channel_id, thread_ts
        )

        resolver = self._get_resolver()

        # Mid-thread engagement: the bot was mentioned inside an existing
        # thread it has not joined.  Replay the prior messages so Claude
        # has the same context a human reading the thread would.
        channel_context = self.channel_context()
        candidate_ids: list[str] = [user_id]
        if is_channel and conversation_id is None and raw_thread_ts:
            preamble, history_authors = self._replay_history(
                channel_id, thread_ts, message_ts, resolver
            )
            if preamble:
                channel_context = f"{channel_context}\n\n{preamble}"
            candidate_ids.extend(history_authors)
        candidate_ids.extend(self._authorizer.candidate_group_member_ids())

        # Resolve inbound mention tokens so Claude sees human-readable names.
        # The bot's own mention is stripped from the invocation (redundant).
        body = resolver.resolve_in(text, strip_bot_mention=True)

        # Extract file metadata for deferred download
        slack_file_urls: list[tuple[str, str]] = []
        for raw_file in cast(list[JsonDict], payload.get("files", [])):
            name = cast(str, raw_file.get("name", "unnamed"))
            url = cast(
                str,
                raw_file.get("url_private_download")
                or raw_file.get("url_private", ""),
            )
            if url:
                slack_file_urls.append((name, url))

        # Build display title
        display_title = body[:_MAX_TITLE_LENGTH].split("\n")[0] if body else ""

        # Resolve the user ID to a readable name for prompt attribution.
        # The authorize() call above warmed the user cache, so this is a
        # cache hit (no extra Slack API request).  The ID is rendered as a
        # bare ``<U123>`` rather than ``<@U123>`` so the resolved ID is never
        # itself live-mention syntax.  The name half is user-controlled and
        # not sanitized here (consistent with the message body); the outbound
        # mrkdwn renderer escapes ``<``/``>`` so anything Claude echoes is
        # inert regardless.
        name = self._authorizer.get_display_name(user_id)
        sender_display = f"{name} <{user_id}>" if name != user_id else user_id

        # A bare channel mention can strip to an empty body; mark it so the
        # gateway's empty-body guard lets the engagement proceed (the thread
        # context, if any, carries the intent).  ``subject`` is otherwise
        # unused by the Slack path.
        subject = "Slack channel message" if is_channel and not body else ""

        return SlackParsedMessage(
            sender=user_id,
            sender_display=sender_display,
            body=body,
            conversation_id=conversation_id,
            model_hint=None,
            display_title=display_title or "(no message)",
            channel_context=channel_context,
            subject=subject,
            slack_channel_id=channel_id,
            slack_thread_ts=thread_ts,
            slack_file_urls=slack_file_urls,
            triggering_message_ts=message_ts,
            is_channel=is_channel,
            mention_candidate_ids=_dedup_preserving_order(candidate_ids),
        )

    def _get_resolver(self) -> MentionResolver:
        """Return the mention resolver, building it once lazily.

        Deferred until first use so the bot user ID (resolved via
        ``auth.test``) is available — by the time a message is parsed,
        ``authorize()`` has warmed that cache.
        """
        if self._resolver is None:
            self._resolver = MentionResolver(
                self._authorizer,
                bot_user_id=self._authorizer.get_bot_user_id(),
            )
        return self._resolver

    def _add_reaction(self, channel_id: str, message_ts: str) -> None:
        """Add the ``:eyes:`` acknowledgement reaction (non-fatal)."""
        try:
            self._client.reactions_add(
                channel=channel_id, timestamp=message_ts, name="eyes"
            )
        except SlackApiError as e:
            logger.warning("Failed to add Slack reaction (non-fatal): %s", e)

    def _replay_history(
        self,
        channel_id: str,
        thread_ts: str,
        triggering_ts: str,
        resolver: MentionResolver,
    ) -> tuple[str, list[str]]:
        """Fetch prior thread messages and render them as a prompt preamble.

        Reads the thread via ``conversations.replies`` (paginated, bounded
        by :data:`_HISTORY_FETCH_CAP`), drops the triggering message and
        non-human messages, keeps the most recent
        :data:`_HISTORY_REPLAY_LIMIT`, and renders each as
        ``[<display name>]: <resolved body>``.  The invocation itself is
        delivered separately via the attributed message body, so it is not
        repeated here.

        Args:
            channel_id: Channel the thread lives in.
            thread_ts: Root timestamp of the thread.
            triggering_ts: ts of the invocation message (excluded).
            resolver: Mention resolver for inbound token resolution.

        Returns:
            ``(preamble, author_ids)`` — the preamble is empty when no
            prior messages exist; ``author_ids`` lists the distinct human
            authors for the outbound mention candidate set.
        """
        messages = self._fetch_thread_messages(channel_id, thread_ts)

        history = [
            m
            for m in messages
            if m.get("ts") != triggering_ts
            and m.get("user")
            and not m.get("subtype")
            and not m.get("bot_id")
        ]
        if not history:
            return "", []

        omitted = len(history) - _HISTORY_REPLAY_LIMIT
        if omitted > 0:
            history = history[-_HISTORY_REPLAY_LIMIT:]

        lines: list[str] = [
            "The user invited you into an existing Slack thread.  The "
            "messages below are the conversation that preceded the "
            "invocation, in order.  Use them as background; the invocation "
            "that triggered you is the attributed message that follows this "
            "preamble."
        ]
        if omitted > 0:
            lines.append(f"[{omitted} earlier messages omitted]")

        author_ids: list[str] = []
        for message in history:
            author = cast(str, message.get("user", ""))
            author_ids.append(author)
            display = self._authorizer.get_display_name(author)
            resolved = resolver.resolve_in(
                cast(str, message.get("text", "")), strip_bot_mention=False
            )
            lines.append(f"[{display}]: {resolved}")

        return "\n".join(lines), author_ids

    def _fetch_thread_messages(
        self, channel_id: str, thread_ts: str
    ) -> list[JsonDict]:
        """Page through ``conversations.replies`` up to the fetch cap."""
        messages: list[JsonDict] = []
        cursor: str | None = None
        try:
            while True:
                resp = self._client.conversations_replies(
                    channel=channel_id,
                    ts=thread_ts,
                    limit=200,
                    cursor=cursor,
                )
                messages.extend(cast(list[JsonDict], resp.get("messages", [])))
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

    def save_attachments(
        self, parsed: ParsedMessage, inbox_dir: Path
    ) -> list[str]:
        """Download Slack files and save to the inbox directory.

        Uses ``urllib.request`` for downloads because the Slack SDK's
        ``WebClient`` does not expose a file download method.  The SDK
        itself uses ``urllib`` internally (not ``httpx`` or ``requests``),
        so this is consistent.  Auth comes from ``WebClient.token`` to
        stay in sync with the client's credential management.

        Args:
            parsed: Parsed message (must be a ``SlackParsedMessage``).
            inbox_dir: Path to save attachments to.

        Returns:
            List of saved filenames.
        """
        if not isinstance(parsed, SlackParsedMessage):
            raise TypeError(
                f"Expected SlackParsedMessage, got {type(parsed).__name__}"
            )
        saved: list[str] = []

        for filename, url in parsed.slack_file_urls:
            try:
                if not _is_slack_file_url(url):
                    logger.warning(
                        "Skipping Slack attachment %s: URL host not in "
                        "allowed set %s",
                        filename,
                        _SLACK_FILE_HOSTS,
                    )
                    continue

                req = urllib.request.Request(
                    url,
                    headers={"Authorization": f"Bearer {self._client.token}"},
                )
                with urllib.request.urlopen(req) as resp:
                    data = resp.read(_MAX_DOWNLOAD_BYTES + 1)
                    if len(data) > _MAX_DOWNLOAD_BYTES:
                        logger.warning(
                            "Slack attachment %s exceeds %d bytes, skipping",
                            filename,
                            _MAX_DOWNLOAD_BYTES,
                        )
                        continue

                safe_name = Path(filename).name
                if not safe_name:
                    safe_name = "unnamed"
                filepath = inbox_dir / safe_name
                filepath.write_bytes(data)
                saved.append(safe_name)
                logger.info("Saved Slack attachment: %s", safe_name)

            except Exception as e:
                logger.warning(
                    "Failed to download Slack file %s: %s", filename, e
                )

        return saved

    def send_acknowledgment(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        model: str,
        dashboard_url: str | None,
    ) -> None:
        """Send acknowledgment and register thread mapping."""
        if not isinstance(parsed, SlackParsedMessage):
            raise TypeError(
                f"Expected SlackParsedMessage, got {type(parsed).__name__}"
            )

        # Register thread mapping for conversation resumption
        self._thread_store.register(
            parsed.slack_channel_id,
            parsed.slack_thread_ts,
            conversation_id,
        )

        # Build acknowledgment text (aligned with email channel)
        if dashboard_url:
            task_url = f"{dashboard_url}/conversation/{conversation_id}"
            text = (
                f"I've started working on this and will reply shortly. "
                f"See progress at {task_url}"
            )
        else:
            text = "I've started working on this and will reply shortly."

        try:
            self._client.chat_postMessage(
                channel=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                text=text,
            )
        except SlackApiError as e:
            logger.warning(
                "Failed to send Slack acknowledgment (non-fatal): %s", e
            )

    def report_phase(self, parsed: ParsedMessage, phase: TaskPhase) -> None:
        """Surface the lifecycle phase via the thread loading status.

        Slack locks the thread composer while a status is active, so we
        show it only during ``PREPARING`` and clear it on ``RUNNING`` —
        keeping the composer free for follow-ups during the run.
        """
        if not isinstance(parsed, SlackParsedMessage):
            raise TypeError(
                f"Expected SlackParsedMessage, got {type(parsed).__name__}"
            )
        # assistant.threads.setStatus is a DM-only (Agents & AI Apps) API.
        # In channels the :eyes: reaction is the acknowledgement instead.
        if parsed.is_channel:
            return
        if phase is TaskPhase.PREPARING:
            self._set_status(parsed, "is working on this...")
        elif phase is TaskPhase.RUNNING:
            self._set_status(parsed, "")

    def _set_status(self, parsed: SlackParsedMessage, status: str) -> None:
        """Set (or clear, when empty) the assistant thread status."""
        try:
            self._client.assistant_threads_setStatus(
                channel_id=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                status=status,
            )
        except SlackApiError as e:
            logger.warning("Failed to set Slack status (non-fatal): %s", e)

    def send_reply(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        response_text: str,
        usage_footer: str,
        outbox_files: list[Path],
    ) -> None:
        """Send reply with response text, optional files, and thread title."""
        if not isinstance(parsed, SlackParsedMessage):
            raise TypeError(
                f"Expected SlackParsedMessage, got {type(parsed).__name__}"
            )

        # Append usage footer
        body = response_text
        if usage_footer:
            body = f"{response_text}\n\n_{usage_footer}_"

        # Convert Markdown to Slack mrkdwn for rendering
        body = render_mrkdwn(body)

        # Rewrite unambiguous @name / #name / @group tokens into Slack
        # reference syntax against this thread's candidate set so they
        # render as real mentions.
        candidates = [
            info
            for cid in parsed.mention_candidate_ids
            if (info := self._authorizer.get_user_info(cid)) is not None
        ]
        body = self._get_resolver().rewrite_out(body, candidates)

        # Send message(s)
        try:
            _send_long_message(
                client=self._client,
                channel=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                text=body,
            )
        except SlackApiError as e:
            logger.error("Failed to send Slack reply: %s", e)
            raise ChannelSendError(str(e)) from e

        # Upload outbox files
        for filepath in outbox_files:
            if filepath.exists():
                try:
                    _upload_file(
                        self._client,
                        parsed.slack_channel_id,
                        parsed.slack_thread_ts,
                        filepath,
                    )
                except SlackApiError as e:
                    logger.warning(
                        "Failed to upload file %s: %s", filepath.name, e
                    )

        # Set thread title from first message.  assistant.threads.setTitle
        # is a DM-only (Agents & AI Apps) API; channel threads are
        # discovered by their root message, so it is skipped there.
        title = parsed.display_title[:_MAX_TITLE_LENGTH]
        if title and not parsed.is_channel:
            try:
                self._client.assistant_threads_setTitle(
                    channel_id=parsed.slack_channel_id,
                    thread_ts=parsed.slack_thread_ts,
                    title=title,
                )
            except SlackApiError as e:
                logger.debug("Failed to set thread title: %s", e)

    def send_error(
        self,
        parsed: ParsedMessage,
        conversation_id: str | None,
        error_message: str,
    ) -> None:
        """Send error notification to the Slack thread."""
        if not isinstance(parsed, SlackParsedMessage):
            raise TypeError(
                f"Expected SlackParsedMessage, got {type(parsed).__name__}"
            )

        try:
            self._client.chat_postMessage(
                channel=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                text=f"An error occurred: {error_message}",
            )
        except SlackApiError as e:
            logger.error("Failed to send Slack error message: %s", e)

    def create_plan_streamer(
        self, parsed: ParsedMessage
    ) -> PlanStreamer | None:
        """Create a plan streamer for real-time task progress.

        Returns a ``SlackPlanStreamer`` that displays ``TodoWrite``
        progress in the Slack thread via message updates.

        Args:
            parsed: Parsed message (must be a ``SlackParsedMessage``).

        Returns:
            A ``SlackPlanStreamer``, or ``None`` if the parsed message
            is not a ``SlackParsedMessage``.
        """
        if not isinstance(parsed, SlackParsedMessage):
            return None
        return SlackPlanStreamer(
            client=self._client,
            channel=parsed.slack_channel_id,
            thread_ts=parsed.slack_thread_ts,
        )

    def cleanup_conversations(self, active_conversation_ids: set[str]) -> None:
        """Remove thread mappings for conversations no longer active."""
        removed = self._thread_store.retain_only(active_conversation_ids)
        if removed:
            logger.info(
                "Repo '%s': pruned %d stale thread mappings",
                self._repo_id,
                removed,
            )


def _dedup_preserving_order(ids: list[str]) -> list[str]:
    """Return *ids* with duplicates removed, keeping first-seen order."""
    return list(dict.fromkeys(ids))


def _is_slack_file_url(url: str) -> bool:
    """Check whether a URL points to a known Slack file-hosting domain.

    Only HTTPS URLs on :data:`_SLACK_FILE_HOSTS` are accepted.  This
    prevents the bot token from being sent to arbitrary hosts if the
    event payload contains unexpected URLs.

    Args:
        url: URL to validate.

    Returns:
        True if the URL is a valid Slack file URL.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.hostname in _SLACK_FILE_HOSTS


def _split_message(text: str) -> list[str]:
    """Split ``mrkdwn`` text into chunks within the ``text`` ceiling.

    Splits at paragraph boundaries first, then at line boundaries when a
    single paragraph exceeds :data:`_MAX_TEXT_CHARS`, and finally hard-slices
    a single line that is itself longer than the ceiling so no chunk ever
    exceeds it (avoiding silent truncation by Slack).

    Args:
        text: Full ``mrkdwn`` body, longer than :data:`_MAX_TEXT_CHARS`.

    Returns:
        List of chunks, each at most :data:`_MAX_TEXT_CHARS` characters.
    """
    chunks: list[str] = []
    current = ""

    for paragraph in text.split("\n\n"):
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if len(candidate) <= _MAX_TEXT_CHARS:
            current = candidate
            continue
        if current:
            chunks.append(current)
            current = ""
        if len(paragraph) <= _MAX_TEXT_CHARS:
            current = paragraph
            continue
        # Single paragraph exceeds the ceiling: split at line boundaries.
        for line in paragraph.split("\n"):
            candidate = f"{current}\n{line}" if current else line
            if len(candidate) <= _MAX_TEXT_CHARS:
                current = candidate
                continue
            if current:
                chunks.append(current)
                current = ""
            # Single line exceeds the ceiling: hard-slice it.
            while len(line) > _MAX_TEXT_CHARS:
                chunks.append(line[:_MAX_TEXT_CHARS])
                line = line[_MAX_TEXT_CHARS:]
            current = line

    if current:
        chunks.append(current)

    return chunks


def _send_long_message(
    client: WebClient,
    channel: str,
    thread_ts: str,
    text: str,
) -> None:
    """Send a ``mrkdwn`` reply, splitting or uploading as needed.

    Strategy:
    1. Bodies within :data:`_MAX_TEXT_CHARS` ship as a single
       ``chat.postMessage`` via the ``text`` parameter.
    2. Larger bodies split at paragraph (then line) boundaries into
       multiple in-thread messages.
    3. Bodies that split into more than :data:`_MAX_SPLIT_MESSAGES` chunks
       fall back to an uploaded ``response.md`` file.

    Args:
        client: Slack ``WebClient``.
        channel: Channel ID.
        thread_ts: Thread timestamp.
        text: Full ``mrkdwn`` body.
    """
    chunks = [text] if len(text) <= _MAX_TEXT_CHARS else _split_message(text)

    if len(chunks) <= _MAX_SPLIT_MESSAGES:
        for chunk in chunks:
            client.chat_postMessage(
                channel=channel, thread_ts=thread_ts, text=chunk
            )
    else:
        client.files_upload_v2(
            channel=channel,
            thread_ts=thread_ts,
            content=text,
            filename="response.md",
            title="Response",
        )


def _upload_file(
    client: WebClient,
    channel: str,
    thread_ts: str,
    filepath: Path,
) -> None:
    """Upload a file to a Slack thread.

    Args:
        client: Slack ``WebClient``.
        channel: Channel ID.
        thread_ts: Thread timestamp.
        filepath: Path to the file to upload.
    """
    client.files_upload_v2(
        channel=channel,
        thread_ts=thread_ts,
        file=str(filepath),
        filename=filepath.name,
    )
