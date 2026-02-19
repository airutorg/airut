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
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from airut.gateway.channel import (
    AuthenticationError,
    ChannelAdapter,
    ParsedMessage,
    RawMessage,
)
from airut.gateway.slack.authorizer import SlackAuthorizer
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.listener import SlackChannelListener
from airut.gateway.slack.thread_store import SlackThreadStore


logger = logging.getLogger(__name__)

#: Maximum characters in a single Slack ``markdown`` block.
_MAX_BLOCK_CHARS = 12000

#: Maximum total characters before splitting into multiple messages.
_MAX_MESSAGE_CHARS = 13000

#: Maximum length for thread title.
_MAX_TITLE_LENGTH = 60

#: Maximum attachment download size (100 MB).
_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024

#: Regex matching Markdown table blocks (header row + separator + data).
_TABLE_PATTERN = re.compile(
    r"^(\|[^\n]+\|\n)"  # header row
    r"(\|[-| :]+\|\n)"  # separator row
    r"((?:\|[^\n]+\|\n?)*)",  # data rows
    re.MULTILINE,
)


@dataclass
class SlackParsedMessage(ParsedMessage):
    """Slack-specific parsed message.

    Carries Slack threading info and deferred file download state
    alongside the channel-agnostic ``ParsedMessage`` fields.  The core
    sees a plain ``ParsedMessage``; the adapter downcasts to access
    Slack-specific fields when sending replies.
    """

    slack_channel_id: str = ""
    """DM channel ID (``D``-prefixed)."""

    slack_thread_ts: str = ""
    """Thread timestamp for reply threading."""

    slack_file_urls: list[tuple[str, str]] = field(default_factory=list)
    """List of ``(filename, download_url)`` for deferred download."""


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
        listener = SlackChannelListener(config)

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

    def authenticate_and_parse(
        self, raw_message: RawMessage[dict[str, Any]]
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
        user_id = payload.get("user", "")
        text = payload.get("text", "")
        channel_id = payload.get("channel", "")
        thread_ts = payload.get("thread_ts", "")

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

        # Look up existing conversation from thread mapping
        conversation_id = self._thread_store.get_conversation_id(
            channel_id, thread_ts
        )

        # Extract file metadata for deferred download
        slack_file_urls: list[tuple[str, str]] = []
        for file_info in payload.get("files", []):
            name = file_info.get("name", "unnamed")
            url = file_info.get("url_private_download") or file_info.get(
                "url_private", ""
            )
            if url:
                slack_file_urls.append((name, url))

        # Build display title
        display_title = text[:_MAX_TITLE_LENGTH].split("\n")[0] if text else ""

        # Build channel context
        channel_context = (
            "User is interacting with this session via Slack and will "
            "receive your reply as a Slack message. "
            "After the reply, everything not in /workspace, /inbox, "
            "and /storage is reset. "
            "Markdown formatting is supported in your responses. "
            "To send files back to the user, place them in the "
            "/outbox directory root (no subdirectories). "
            "Use /storage to persist files across messages.\n\n"
            "IMPORTANT: The user cannot see intermediate output during "
            "execution. They will only see your final reply. Do not "
            "assume the user can respond to clarifying questions "
            "quickly -- if you need to make a judgment call, proceed "
            "with your best assessment and explain your reasoning in "
            "the reply."
        )

        return SlackParsedMessage(
            sender=user_id,
            body=text,
            conversation_id=conversation_id,
            model_hint=None,
            display_title=display_title or "(no message)",
            channel_context=channel_context,
            slack_channel_id=channel_id,
            slack_thread_ts=thread_ts,
            slack_file_urls=slack_file_urls,
        )

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

        # Build acknowledgment text
        text = (
            f"Your request has been received and is now being "
            f"processed by {model}."
        )
        if dashboard_url:
            task_url = f"{dashboard_url}/conversation/{conversation_id}"
            text += f" {task_url}"

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

        # Convert tables to code blocks
        body = _convert_tables(body)

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
            raise

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

        # Set thread title from first message
        title = parsed.display_title[:_MAX_TITLE_LENGTH]
        if title:
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

    def send_rejection(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        reason: str,
        dashboard_url: str | None,
    ) -> None:
        """Send rejection notification to the Slack thread."""
        if not isinstance(parsed, SlackParsedMessage):
            raise TypeError(
                f"Expected SlackParsedMessage, got {type(parsed).__name__}"
            )

        text = f"Your message could not be processed.\n\nReason: {reason}"
        if dashboard_url:
            task_url = f"{dashboard_url}/conversation/{conversation_id}"
            text += f"\n\nConversation: {task_url}"
        else:
            text += f"\n\nConversation ID: {conversation_id}"

        try:
            self._client.chat_postMessage(
                channel=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                text=text,
            )
        except SlackApiError as e:
            logger.warning("Failed to send Slack rejection (non-fatal): %s", e)

    def cleanup_conversations(self, active_conversation_ids: set[str]) -> None:
        """Remove thread mappings for conversations no longer active."""
        removed = self._thread_store.retain_only(active_conversation_ids)
        if removed:
            logger.info(
                "Repo '%s': pruned %d stale thread mappings",
                self._repo_id,
                removed,
            )


def _convert_tables(text: str) -> str:
    """Convert Markdown tables to fenced code blocks.

    Slack's ``markdown`` block does not render Markdown tables, so we
    wrap them in code fences to preserve alignment.

    Args:
        text: Markdown text potentially containing tables.

    Returns:
        Text with tables wrapped in code fences.
    """

    def _replace_table(match: re.Match[str]) -> str:
        table_text = match.group(0).rstrip("\n")
        return f"```\n{table_text}\n```"

    return _TABLE_PATTERN.sub(_replace_table, text)


def _split_blocks(text: str) -> list[str]:
    """Split text into chunks suitable for ``markdown`` blocks.

    Splits at paragraph boundaries first, then at line boundaries
    if a paragraph exceeds the block limit.

    Args:
        text: Full response text.

    Returns:
        List of text chunks, each within ``_MAX_BLOCK_CHARS``.
    """
    if len(text) <= _MAX_BLOCK_CHARS:
        return [text]

    blocks: list[str] = []
    current = ""

    for paragraph in text.split("\n\n"):
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if len(candidate) <= _MAX_BLOCK_CHARS:
            current = candidate
        else:
            if current:
                blocks.append(current)
            # If single paragraph exceeds limit, split by lines
            if len(paragraph) > _MAX_BLOCK_CHARS:
                lines = paragraph.split("\n")
                current = ""
                for line in lines:
                    candidate = f"{current}\n{line}" if current else line
                    if len(candidate) <= _MAX_BLOCK_CHARS:
                        current = candidate
                    else:
                        if current:
                            blocks.append(current)
                        current = line[:_MAX_BLOCK_CHARS] + "\n[truncated]"
            else:
                current = paragraph

    if current:
        blocks.append(current)

    return blocks


def _send_long_message(
    client: WebClient,
    channel: str,
    thread_ts: str,
    text: str,
) -> None:
    """Send a potentially long message, splitting as needed.

    Strategy:
    1. Split into multiple ``markdown`` blocks within one message.
    2. If total exceeds ~13K chars, split into multiple messages.
    3. If extremely long, upload as file attachment.

    Args:
        client: Slack ``WebClient``.
        channel: Channel ID.
        thread_ts: Thread timestamp.
        text: Full response text.
    """
    blocks = _split_blocks(text)

    if len(text) <= _MAX_MESSAGE_CHARS:
        # Single message with multiple blocks
        block_kit = [{"type": "markdown", "text": block} for block in blocks]
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            blocks=block_kit,
            text=text[:200],  # fallback text for notifications
        )
    elif len(text) <= _MAX_MESSAGE_CHARS * 5:
        # Multiple messages
        message_blocks: list[list[dict[str, str]]] = []
        current_message: list[dict[str, str]] = []
        current_length = 0

        for block in blocks:
            if current_length + len(block) > _MAX_MESSAGE_CHARS:
                if current_message:
                    message_blocks.append(current_message)
                current_message = []
                current_length = 0
            current_message.append({"type": "markdown", "text": block})
            current_length += len(block)

        if current_message:
            message_blocks.append(current_message)

        for msg_blocks in message_blocks:
            client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                blocks=msg_blocks,
                text="(continued)",
            )
    else:
        # Fallback: upload as file
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
