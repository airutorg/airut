# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackChannelAdapter."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from airut.gateway.channel import AuthenticationError, RawMessage
from airut.gateway.slack.adapter import (
    SlackChannelAdapter,
    SlackParsedMessage,
    _convert_autolinks,
    _convert_tables,
    _send_long_message,
    _split_blocks,
    _upload_file,
)
from airut.gateway.slack.authorizer import SlackAuthorizer
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.thread_store import SlackThreadStore


def _make_config() -> SlackChannelConfig:
    return SlackChannelConfig(
        bot_token="xoxb-test-token",
        app_token="xapp-test-token",
        authorized=({"workspace_members": True},),
    )


def _make_adapter(
    tmp_path: Path,
) -> tuple[
    SlackChannelAdapter,
    MagicMock,
    MagicMock,
    SlackThreadStore,
]:
    config = _make_config()
    client = MagicMock(spec=WebClient)
    client.token = config.bot_token
    authorizer = MagicMock(spec=SlackAuthorizer)
    thread_store = SlackThreadStore(tmp_path)
    adapter = SlackChannelAdapter(
        config=config,
        client=client,
        authorizer=authorizer,
        thread_store=thread_store,
        repo_id="test",
    )
    return adapter, client, authorizer, thread_store


def _make_raw_message(
    *,
    user: str = "U123",
    text: str = "Hello bot",
    channel: str = "D456",
    thread_ts: str = "1234567890.123456",
    files: list | None = None,
) -> RawMessage:
    payload: dict = {
        "user": user,
        "text": text,
        "channel": channel,
        "thread_ts": thread_ts,
    }
    if files:
        payload["files"] = files
    return RawMessage(
        sender=user,
        content=payload,
        display_title=text[:60] if text else "",
    )


class TestAuthenticateAndParse:
    def test_successful_parse(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        msg = _make_raw_message(text="Do something")

        result = adapter.authenticate_and_parse(msg)

        assert isinstance(result, SlackParsedMessage)
        assert result.sender == "U123"
        assert result.body == "Do something"
        assert result.conversation_id is None
        assert result.slack_channel_id == "D456"
        assert result.slack_thread_ts == "1234567890.123456"

    def test_unauthorized_raises(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (
            False,
            "sender not authorized",
        )
        msg = _make_raw_message()

        with pytest.raises(AuthenticationError) as exc_info:
            adapter.authenticate_and_parse(msg)
        assert exc_info.value.sender == "U123"
        assert "not authorized" in exc_info.value.reason

    def test_resumes_existing_conversation(self, tmp_path: Path) -> None:
        adapter, _, authorizer, thread_store = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        thread_store.register("D456", "1234567890.123456", "conv1")
        msg = _make_raw_message()

        result = adapter.authenticate_and_parse(msg)
        assert result.conversation_id == "conv1"

    def test_channel_context_set(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        msg = _make_raw_message()

        result = adapter.authenticate_and_parse(msg)
        assert "Slack" in result.channel_context
        assert "intermediate output" in result.channel_context

    def test_display_title_truncated(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        long_text = "A" * 100
        msg = _make_raw_message(text=long_text)

        result = adapter.authenticate_and_parse(msg)
        assert len(result.display_title) == 60

    def test_display_title_fallback(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        msg = _make_raw_message(text="")

        result = adapter.authenticate_and_parse(msg)
        assert result.display_title == "(no message)"

    def test_extracts_file_metadata(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        msg = _make_raw_message(
            files=[
                {
                    "name": "report.txt",
                    "url_private_download": "https://files.slack.com/report.txt",
                }
            ]
        )

        result = adapter.authenticate_and_parse(msg)
        assert len(result.slack_file_urls) == 1
        assert result.slack_file_urls[0] == (
            "report.txt",
            "https://files.slack.com/report.txt",
        )

    def test_model_hint_is_none(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        msg = _make_raw_message()

        result = adapter.authenticate_and_parse(msg)
        assert result.model_hint is None


class TestSaveAttachments:
    def test_downloads_and_saves(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="see attached",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            slack_file_urls=[("report.txt", "https://example.com/f")],
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"file data"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            return_value=mock_resp,
        ) as mock_urlopen:
            result = adapter.save_attachments(parsed, inbox)

        assert result == ["report.txt"]
        assert (inbox / "report.txt").read_bytes() == b"file data"

        # Auth header should use client.token, not config.bot_token
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == f"Bearer {client.token}"

    def test_handles_download_error(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="see attached",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            slack_file_urls=[("report.txt", "https://example.com/f")],
        )

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            side_effect=Exception("network error"),
        ):
            result = adapter.save_attachments(parsed, inbox)

        assert result == []

    def test_no_files(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="no files",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        result = adapter.save_attachments(parsed, inbox)
        assert result == []


class TestSendAcknowledgment:
    def test_sends_ack_and_registers_thread(self, tmp_path: Path) -> None:
        adapter, client, _, thread_store = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)

        # Thread registered
        assert thread_store.get_conversation_id("D456", "ts1") == "conv1"
        # Message sent
        client.chat_postMessage.assert_called_once()
        call_kw = client.chat_postMessage.call_args[1]
        assert "received" in call_kw["text"]
        assert "sonnet" in call_kw["text"]

    def test_sends_ack_with_dashboard_url(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        adapter.send_acknowledgment(
            parsed, "conv1", "opus", "https://dash.example.com"
        )
        call_kw = client.chat_postMessage.call_args[1]
        assert "dash.example.com/conversation/conv1" in call_kw["text"]

    def test_api_failure_non_fatal(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.chat_postMessage.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        # Should not raise
        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)


class TestSendReply:
    def test_sends_reply_text(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test task",
        )

        adapter.send_reply(parsed, "conv1", "Response text", "", [])

        client.chat_postMessage.assert_called_once()

    def test_appends_usage_footer(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test",
        )

        adapter.send_reply(parsed, "conv1", "Done", "Cost: $0.01", [])

        call_kw = client.chat_postMessage.call_args[1]
        blocks = call_kw["blocks"]
        text = blocks[0]["text"]
        assert "Cost: $0.01" in text

    def test_uploads_outbox_files(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test",
        )

        outfile = tmp_path / "report.txt"
        outfile.write_text("report data")

        adapter.send_reply(parsed, "conv1", "Done", "", [outfile])

        client.files_upload_v2.assert_called_once()

    def test_sets_thread_title(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Fix the login bug",
        )

        adapter.send_reply(parsed, "conv1", "Done", "", [])

        client.assistant_threads_setTitle.assert_called_once()
        call_kw = client.assistant_threads_setTitle.call_args[1]
        assert call_kw["title"] == "Fix the login bug"

    def test_converts_autolinks_in_reply(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test",
        )

        adapter.send_reply(
            parsed,
            "conv1",
            "**PR:** <https://github.com/org/repo/pull/1>",
            "",
            [],
        )

        call_kw = client.chat_postMessage.call_args[1]
        block_text = call_kw["blocks"][0]["text"]
        assert "<https://" not in block_text
        assert "https://github.com/org/repo/pull/1" in block_text

    def test_api_failure_raises(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.chat_postMessage.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test",
        )

        with pytest.raises(SlackApiError):
            adapter.send_reply(parsed, "conv1", "Done", "", [])


class TestSendError:
    def test_sends_error_message(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        adapter.send_error(parsed, "conv1", "Something broke")

        client.chat_postMessage.assert_called_once()
        call_kw = client.chat_postMessage.call_args[1]
        assert "Something broke" in call_kw["text"]

    def test_api_failure_logged(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.chat_postMessage.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        # Should not raise
        adapter.send_error(parsed, "conv1", "error msg")


class TestSendRejection:
    def test_sends_rejection(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        adapter.send_rejection(parsed, "conv1", "queue full", None)

        client.chat_postMessage.assert_called_once()
        call_kw = client.chat_postMessage.call_args[1]
        assert "queue full" in call_kw["text"]
        assert "conv1" in call_kw["text"]

    def test_sends_rejection_with_dashboard(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        adapter.send_rejection(
            parsed, "conv1", "busy", "https://dash.example.com"
        )
        call_kw = client.chat_postMessage.call_args[1]
        assert "dash.example.com/conversation/conv1" in call_kw["text"]

    def test_api_failure_non_fatal(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.chat_postMessage.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        # Should not raise
        adapter.send_rejection(parsed, "conv1", "reason", None)


class TestListenerProperty:
    def test_exposes_listener(self, tmp_path: Path) -> None:
        listener = MagicMock()
        adapter = SlackChannelAdapter(
            config=_make_config(),
            client=MagicMock(spec=WebClient),
            authorizer=MagicMock(spec=SlackAuthorizer),
            thread_store=SlackThreadStore(tmp_path),
            slack_listener=listener,
            repo_id="test",
        )
        assert adapter.listener is listener

    def test_raises_when_no_listener(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        with pytest.raises(RuntimeError, match="created without a listener"):
            _ = adapter.listener


class TestFromConfig:
    def test_creates_all_components(self, tmp_path: Path) -> None:
        config = _make_config()
        with (
            patch("airut.gateway.slack.adapter.WebClient") as mock_client,
            patch("airut.gateway.slack.adapter.SlackAuthorizer") as mock_auth,
            patch("airut.gateway.slack.adapter.SlackThreadStore") as mock_store,
            patch(
                "airut.gateway.slack.adapter.SlackChannelListener"
            ) as mock_listener,
            patch(
                "airut.gateway.config.get_storage_dir",
                return_value=tmp_path,
            ),
        ):
            adapter = SlackChannelAdapter.from_config(config, repo_id="test")

        mock_client.assert_called_once_with(token=config.bot_token)
        mock_auth.assert_called_once()
        mock_store.assert_called_once()
        mock_listener.assert_called_once_with(config)
        assert adapter.listener is mock_listener.return_value


class TestConvertTables:
    def test_converts_simple_table(self) -> None:
        md = "| Name | Value |\n|------|-------|\n| foo  | bar   |\n"
        result = _convert_tables(md)
        assert "```" in result
        assert "| Name | Value |" in result

    def test_leaves_non_table_text(self) -> None:
        text = "Just regular text\n\nWith paragraphs"
        assert _convert_tables(text) == text

    def test_mixed_content(self) -> None:
        text = "Before table\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\nAfter table"
        result = _convert_tables(text)
        assert "```" in result
        assert "Before table" in result
        assert "After table" in result


class TestConvertAutolinks:
    def test_converts_https_autolink(self) -> None:
        text = "**PR:** <https://github.com/org/repo/pull/27>"
        result = _convert_autolinks(text)
        assert result == "**PR:** https://github.com/org/repo/pull/27"

    def test_converts_http_autolink(self) -> None:
        text = "See <http://example.com/path>"
        result = _convert_autolinks(text)
        assert result == "See http://example.com/path"

    def test_converts_multiple_autolinks(self) -> None:
        text = (
            "**PR:** <https://github.com/org/repo/pull/27>\n"
            "**Preview:** <https://abc123.pages.dev>"
        )
        result = _convert_autolinks(text)
        assert result == (
            "**PR:** https://github.com/org/repo/pull/27\n"
            "**Preview:** https://abc123.pages.dev"
        )

    def test_leaves_bare_urls_unchanged(self) -> None:
        text = "Visit https://example.com for details"
        assert _convert_autolinks(text) == text

    def test_leaves_non_url_angle_brackets(self) -> None:
        text = "Use `<div>` in HTML and x < y > z"
        assert _convert_autolinks(text) == text

    def test_leaves_empty_text(self) -> None:
        assert _convert_autolinks("") == ""

    def test_preserves_surrounding_formatting(self) -> None:
        text = "Check _<https://example.com>_ for details"
        result = _convert_autolinks(text)
        assert result == "Check _https://example.com_ for details"


class TestSplitBlocks:
    def test_short_text_single_block(self) -> None:
        text = "Short text"
        blocks = _split_blocks(text)
        assert blocks == ["Short text"]

    def test_splits_at_paragraph_boundary(self) -> None:
        p1 = "A" * 6000
        p2 = "B" * 6000
        text = f"{p1}\n\n{p2}"
        blocks = _split_blocks(text)
        assert len(blocks) == 2
        assert blocks[0] == p1
        assert blocks[1] == p2

    def test_single_large_paragraph_splits_at_lines(self) -> None:
        lines = ["A" * 100 for _ in range(200)]
        text = "\n".join(lines)
        blocks = _split_blocks(text)
        assert len(blocks) > 1
        for block in blocks:
            assert len(block) <= 12000


class TestSendLongMessage:
    def test_medium_text_multiple_messages(self) -> None:
        """Text between 13K and 65K chars splits into multiple messages."""
        client = MagicMock(spec=WebClient)
        # Build text with paragraphs that exceeds 13K total
        paragraphs = [f"Para {i}: " + "X" * 5000 for i in range(6)]
        text = "\n\n".join(paragraphs)
        _send_long_message(client, "C123", "ts1", text)
        assert client.chat_postMessage.call_count > 1

    def test_very_long_text_uploaded_as_file(self) -> None:
        """Text exceeding 65K chars is uploaded as a file."""
        client = MagicMock(spec=WebClient)
        text = "A" * 70000
        _send_long_message(client, "C123", "ts1", text)
        client.files_upload_v2.assert_called_once()
        client.chat_postMessage.assert_not_called()


class TestUploadFile:
    def test_uploads_file(self, tmp_path: Path) -> None:
        client = MagicMock(spec=WebClient)
        filepath = tmp_path / "test.txt"
        filepath.write_text("hello")
        _upload_file(client, "C123", "ts1", filepath)
        client.files_upload_v2.assert_called_once()
        call_kw = client.files_upload_v2.call_args[1]
        assert call_kw["filename"] == "test.txt"


class TestSendReplyEdgeCases:
    def test_file_upload_failure_non_fatal(self, tmp_path: Path) -> None:
        """File upload errors don't prevent the reply from sending."""
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.files_upload_v2.side_effect = SlackApiError(
            message="upload_failed",
            response=MagicMock(status_code=500, data={}),
        )
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test",
        )
        outfile = tmp_path / "report.txt"
        outfile.write_text("data")

        # Should not raise
        adapter.send_reply(parsed, "conv1", "Done", "", [outfile])
        client.chat_postMessage.assert_called_once()

    def test_title_set_failure_non_fatal(self, tmp_path: Path) -> None:
        """Thread title set errors don't affect the reply."""
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.assistant_threads_setTitle.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test title",
        )

        # Should not raise
        adapter.send_reply(parsed, "conv1", "Done", "", [])


class TestPathTraversal:
    def test_path_traversal_sanitized(self, tmp_path: Path) -> None:
        """Filenames with path separators are sanitized."""
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="file",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            slack_file_urls=[("../../etc/evil.sh", "https://example.com/f")],
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"safe data"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            result = adapter.save_attachments(parsed, inbox)

        # The file should be saved with just the basename
        assert result == ["evil.sh"]
        assert (inbox / "evil.sh").exists()
        # No file should escape inbox
        assert not (tmp_path / "etc").exists()

    def test_empty_basename_uses_unnamed(self, tmp_path: Path) -> None:
        """Filenames that resolve to empty basename use 'unnamed'."""
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="file",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            slack_file_urls=[("", "https://example.com/f")],
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"data"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            result = adapter.save_attachments(parsed, inbox)

        assert result == ["unnamed"]
        assert (inbox / "unnamed").exists()


class TestDownloadSizeLimit:
    def test_oversized_download_skipped(self, tmp_path: Path) -> None:
        """Files exceeding the size limit are skipped."""
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="big file",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            slack_file_urls=[("big.bin", "https://example.com/big")],
        )

        # Simulate a response larger than _MAX_DOWNLOAD_BYTES
        from airut.gateway.slack.adapter import _MAX_DOWNLOAD_BYTES

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"x" * (_MAX_DOWNLOAD_BYTES + 1)
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            result = adapter.save_attachments(parsed, inbox)

        assert result == []
        assert not (inbox / "big.bin").exists()


class TestTypeCheckErrors:
    def test_save_attachments_type_error(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        from airut.gateway.channel import ParsedMessage

        wrong = ParsedMessage(
            sender="U123",
            body="text",
            conversation_id=None,
            model_hint=None,
        )
        with pytest.raises(TypeError, match="SlackParsedMessage"):
            adapter.save_attachments(wrong, inbox)

    def test_send_acknowledgment_type_error(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        from airut.gateway.channel import ParsedMessage

        wrong = ParsedMessage(
            sender="U123",
            body="t",
            conversation_id=None,
            model_hint=None,
        )
        with pytest.raises(TypeError, match="SlackParsedMessage"):
            adapter.send_acknowledgment(wrong, "c1", "model", None)

    def test_send_reply_type_error(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        from airut.gateway.channel import ParsedMessage

        wrong = ParsedMessage(
            sender="U123",
            body="t",
            conversation_id=None,
            model_hint=None,
        )
        with pytest.raises(TypeError, match="SlackParsedMessage"):
            adapter.send_reply(wrong, "c1", "text", "", [])

    def test_send_error_type_error(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        from airut.gateway.channel import ParsedMessage

        wrong = ParsedMessage(
            sender="U123",
            body="t",
            conversation_id=None,
            model_hint=None,
        )
        with pytest.raises(TypeError, match="SlackParsedMessage"):
            adapter.send_error(wrong, "c1", "err")

    def test_send_rejection_type_error(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        from airut.gateway.channel import ParsedMessage

        wrong = ParsedMessage(
            sender="U123",
            body="t",
            conversation_id=None,
            model_hint=None,
        )
        with pytest.raises(TypeError, match="SlackParsedMessage"):
            adapter.send_rejection(wrong, "c1", "reason", None)


class TestSplitBlocksTruncation:
    def test_long_line_truncated_with_marker(self) -> None:
        """Lines exceeding block limit get [truncated] marker."""
        from airut.gateway.slack.adapter import _MAX_BLOCK_CHARS

        # Single line exceeding block limit (no paragraph/line breaks)
        text = "X" * (_MAX_BLOCK_CHARS + 5000)
        blocks = _split_blocks(text)
        assert len(blocks) >= 1
        assert "[truncated]" in blocks[0]
