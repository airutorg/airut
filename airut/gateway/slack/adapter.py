# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack channel adapter.

Implements the ChannelAdapter protocol for Slack, using Slack's
Agents & AI Apps platform with Socket Mode.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airut.gateway.channel import AuthenticationError, ParsedMessage
from airut.gateway.slack.authorizer import (
    AuthorizationError,
    SlackAuthorizer,
)
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.thread_store import SlackThreadStore


logger = logging.getLogger(__name__)

#: Maximum characters per Slack markdown_text message.
_MAX_MESSAGE_LENGTH = 12000

#: Channel context system prompt for Slack interactions.
_CHANNEL_CONTEXT = (
    "User is interacting with this session via Slack and will receive your "
    "reply as a Slack message. After the reply, everything not in /workspace, "
    "/inbox, and /storage is reset. Markdown formatting is supported in your "
    "responses. To send files back to the user, place them in the /outbox "
    "directory root (no subdirectories). Use /storage to persist files across "
    "messages.\n\n"
    "IMPORTANT: The user cannot see intermediate output during "
    "execution. They will only see your final reply. Do not assume "
    "the user can respond to clarifying questions quickly \u2014 if you "
    "need to make a judgment call, proceed with your best assessment "
    "and explain your reasoning in the reply."
)

#: Regex matching a Markdown table (header row, separator, data rows).
_TABLE_PATTERN = re.compile(
    r"(\|[^\n]+\|\n\|[\s:|-]+\|\n(?:\|[^\n]+\|\n?)*)",
    re.MULTILINE,
)


@dataclass
class SlackParsedMessage(ParsedMessage):
    """Slack-specific parsed message.

    Carries Slack-specific state for reply threading and deferred
    file download.
    """

    slack_channel_id: str = ""
    """DM channel ID (D-prefixed)."""

    slack_thread_ts: str = ""
    """Thread timestamp for reply threading."""

    slack_file_urls: list[tuple[str, str]] = field(default_factory=list)
    """List of (filename, download_url) for deferred download."""


def convert_tables_to_code_blocks(text: str) -> str:
    """Convert Markdown tables to fenced code blocks.

    Slack's ``markdown_text`` does not render tables. This preserves
    alignment by wrapping tables in code fences.

    Args:
        text: Response text potentially containing Markdown tables.

    Returns:
        Text with tables wrapped in code blocks.
    """

    def _replace(match: re.Match[str]) -> str:
        table = match.group(1).rstrip("\n")
        return f"```\n{table}\n```"

    return _TABLE_PATTERN.sub(_replace, text)


def split_message(text: str) -> list[str]:
    """Split a message that exceeds the Slack character limit.

    Splits at paragraph breaks first, then at line breaks, to produce
    chunks within the 12K character limit.

    Args:
        text: Full response text.

    Returns:
        List of message chunks, each within the character limit.
    """
    if len(text) <= _MAX_MESSAGE_LENGTH:
        return [text]

    chunks: list[str] = []
    remaining = text

    while remaining:
        if len(remaining) <= _MAX_MESSAGE_LENGTH:
            chunks.append(remaining)
            break

        # Try to split at a paragraph break
        split_point = remaining.rfind("\n\n", 0, _MAX_MESSAGE_LENGTH)
        if split_point == -1:
            # Fall back to line break
            split_point = remaining.rfind("\n", 0, _MAX_MESSAGE_LENGTH)
        if split_point == -1:
            # Last resort: hard cut
            split_point = _MAX_MESSAGE_LENGTH

        chunks.append(remaining[:split_point].rstrip())
        remaining = remaining[split_point:].lstrip("\n")

    return chunks


class SlackChannelAdapter:
    """ChannelAdapter implementation for Slack (Socket Mode).

    Wraps SlackAuthorizer, SlackThreadStore, and Slack Web API behind
    the ChannelAdapter interface.
    """

    def __init__(
        self,
        config: SlackChannelConfig,
        authorizer: SlackAuthorizer,
        thread_store: SlackThreadStore,
        bot_client: Any,
        *,
        repo_id: str = "",
    ) -> None:
        self._config = config
        self._authorizer = authorizer
        self._thread_store = thread_store
        self._client = bot_client
        self._repo_id = repo_id

    @classmethod
    def from_config(
        cls,
        config: SlackChannelConfig,
        *,
        repo_id: str = "",
        storage_dir: Path | None = None,
    ) -> SlackChannelAdapter:
        """Create an adapter with all Slack components from config.

        Args:
            config: Slack channel configuration.
            repo_id: Repository identifier.
            storage_dir: State directory for thread store persistence.

        Returns:
            Fully configured SlackChannelAdapter.
        """
        from slack_sdk import WebClient

        client = WebClient(token=config.bot_token)

        authorizer = SlackAuthorizer(
            rules=config.authorized,
            bot_client=client,
        )

        store_dir = storage_dir or Path(".")
        thread_store = SlackThreadStore(store_dir)

        return cls(
            config=config,
            authorizer=authorizer,
            thread_store=thread_store,
            bot_client=client,
            repo_id=repo_id,
        )

    def authenticate_and_parse(self, raw_message: Any) -> SlackParsedMessage:
        """Authenticate the Slack user and parse the event payload.

        Args:
            raw_message: Slack event payload dict from the Socket Mode
                event handler. Expected keys: ``user``, ``text``,
                ``channel``, ``thread_ts``, and optionally ``files``.

        Returns:
            SlackParsedMessage if authorized.

        Raises:
            AuthenticationError: If authorization fails.
        """
        user_id = raw_message.get("user", "")
        text = raw_message.get("text", "")
        channel_id = raw_message.get("channel", "")
        thread_ts = raw_message.get("thread_ts", "")

        # Authorize user
        try:
            user_info = self._authorizer.authorize(user_id)
        except AuthorizationError as e:
            logger.warning(
                "Repo '%s': rejecting Slack message from %s: %s",
                self._repo_id,
                user_id,
                e.reason,
            )
            raise AuthenticationError(
                sender=user_id,
                reason=e.reason,
            ) from e

        # Resolve conversation ID from thread mapping
        conv_id = self._thread_store.get_conversation_id(channel_id, thread_ts)

        # Extract file metadata for deferred download
        file_urls: list[tuple[str, str]] = []
        for file_info in raw_message.get("files", []):
            name = file_info.get("name", "untitled")
            url = file_info.get("url_private_download", "")
            if url:
                file_urls.append((name, url))

        # Build subject from first ~60 chars of text
        subject = text[:60].strip()
        if len(text) > 60:
            subject += "..."
        subject = subject or "(no text)"

        sender_label = f"{user_info.display_name} ({user_id})"

        return SlackParsedMessage(
            sender=sender_label,
            body=text,
            conversation_id=conv_id,
            model_hint=None,
            subject=subject,
            channel_context=_CHANNEL_CONTEXT,
            slack_channel_id=channel_id,
            slack_thread_ts=thread_ts,
            slack_file_urls=file_urls,
        )

    def save_attachments(
        self, parsed: ParsedMessage, inbox_dir: Path
    ) -> list[str]:
        """Download Slack file attachments to the inbox directory.

        Args:
            parsed: Parsed message (must be a SlackParsedMessage).
            inbox_dir: Path to save attachments to.

        Returns:
            List of saved filenames.
        """
        assert isinstance(parsed, SlackParsedMessage)
        if not parsed.slack_file_urls:
            return []

        saved: list[str] = []
        for filename, url in parsed.slack_file_urls:
            try:
                import httpx

                with httpx.Client() as http:
                    response = http.get(
                        url,
                        headers={
                            "Authorization": (
                                f"Bearer {self._config.bot_token}"
                            ),
                        },
                        follow_redirects=True,
                    )
                    response.raise_for_status()

                dest = inbox_dir / filename
                dest.write_bytes(response.content)
                saved.append(filename)
                logger.debug("Downloaded Slack file: %s", filename)
            except Exception as e:
                logger.warning(
                    "Failed to download Slack file '%s': %s", filename, e
                )

        return saved

    def send_acknowledgment(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        model: str,
        dashboard_url: str | None,
    ) -> None:
        """Send acknowledgment message and set thread status."""
        assert isinstance(parsed, SlackParsedMessage)

        # Register thread mapping for new conversations
        self._thread_store.register(
            parsed.slack_channel_id,
            parsed.slack_thread_ts,
            conversation_id,
        )

        # Set assistant status indicator
        try:
            self._client.assistant_threads_setStatus(
                channel_id=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                status="is working on this...",
            )
        except Exception as e:
            logger.debug("Failed to set thread status: %s", e)

        # Build acknowledgment text
        text = (
            f"Your request has been received and is now being "
            f"processed by {model}."
        )
        if dashboard_url:
            task_url = f"{dashboard_url}/conversation/{conversation_id}"
            text += f" [Track progress]({task_url})"

        try:
            self._client.chat_postMessage(
                channel=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                markdown_text=text,
                unfurl_links=False,
                unfurl_media=False,
            )
        except Exception as e:
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
        """Send final response in Slack thread."""
        assert isinstance(parsed, SlackParsedMessage)

        # Convert tables to code blocks for Slack rendering
        text = convert_tables_to_code_blocks(response_text)

        # Append usage footer
        if usage_footer:
            text = f"{text}\n\n_{usage_footer}_"

        # Split and send
        chunks = split_message(text)
        for chunk in chunks:
            try:
                self._client.chat_postMessage(
                    channel=parsed.slack_channel_id,
                    thread_ts=parsed.slack_thread_ts,
                    markdown_text=chunk,
                    unfurl_links=False,
                    unfurl_media=False,
                )
            except Exception as e:
                logger.error("Failed to send Slack reply chunk: %s", e)

        # Upload outbox files
        if outbox_files:
            self._upload_files(
                parsed.slack_channel_id,
                parsed.slack_thread_ts,
                outbox_files,
            )

        # Set thread title from subject
        try:
            title = parsed.subject or conversation_id
            self._client.assistant_threads_setTitle(
                channel_id=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                title=title,
            )
        except Exception as e:
            logger.debug("Failed to set thread title: %s", e)

    def send_error(
        self,
        parsed: ParsedMessage,
        conversation_id: str | None,
        error_message: str,
    ) -> None:
        """Send error notification in Slack thread."""
        assert isinstance(parsed, SlackParsedMessage)

        try:
            self._client.chat_postMessage(
                channel=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                markdown_text=error_message,
                unfurl_links=False,
                unfurl_media=False,
            )
        except Exception as e:
            logger.error("Failed to send Slack error message: %s", e)

    def send_rejection(
        self,
        parsed: ParsedMessage,
        conversation_id: str,
        reason: str,
        dashboard_url: str | None,
    ) -> None:
        """Send rejection notification in Slack thread."""
        assert isinstance(parsed, SlackParsedMessage)

        text = f"Your message could not be processed.\n\nReason: {reason}"
        if dashboard_url:
            task_url = f"{dashboard_url}/conversation/{conversation_id}"
            text += f"\n\n[Conversation {conversation_id}]({task_url})"
        else:
            text += f"\n\nConversation ID: {conversation_id}"

        try:
            self._client.chat_postMessage(
                channel=parsed.slack_channel_id,
                thread_ts=parsed.slack_thread_ts,
                markdown_text=text,
                unfurl_links=False,
                unfurl_media=False,
            )
        except Exception as e:
            logger.warning("Failed to send Slack rejection (non-fatal): %s", e)

    def _upload_files(
        self,
        channel_id: str,
        thread_ts: str,
        files: list[Path],
    ) -> None:
        """Upload files to a Slack thread.

        Uses ``files.getUploadURLExternal`` +
        ``files.completeUploadExternal`` flow.

        Args:
            channel_id: Slack channel ID.
            thread_ts: Thread timestamp.
            files: List of file paths to upload.
        """
        for filepath in files:
            if not filepath.is_file():
                continue
            try:
                data = filepath.read_bytes()
                filename = filepath.name
                length = len(data)

                # Step 1: Get upload URL
                url_response = self._client.files_getUploadURLExternal(
                    filename=filename,
                    length=length,
                )
                upload_url = url_response["upload_url"]
                file_id = url_response["file_id"]

                # Step 2: Upload file content
                import httpx

                with httpx.Client() as http:
                    http.post(
                        upload_url,
                        content=data,
                        headers={"Content-Type": "application/octet-stream"},
                    )

                # Step 3: Complete the upload
                self._client.files_completeUploadExternal(
                    files=[{"id": file_id, "title": filename}],
                    channel_id=channel_id,
                    thread_ts=thread_ts,
                )
                logger.debug("Uploaded file to Slack: %s", filename)
            except Exception as e:
                logger.warning(
                    "Failed to upload file '%s' to Slack: %s",
                    filepath.name,
                    e,
                )
