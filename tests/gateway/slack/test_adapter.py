# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackChannelAdapter."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.channel import AuthenticationError
from airut.gateway.slack.adapter import (
    _CHANNEL_CONTEXT,
    _MAX_MESSAGE_LENGTH,
    SlackChannelAdapter,
    SlackParsedMessage,
    convert_tables_to_code_blocks,
    split_message,
)
from airut.gateway.slack.authorizer import AuthorizationError, UserInfo
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.thread_store import SlackThreadStore


def _make_config() -> SlackChannelConfig:
    return SlackChannelConfig(
        bot_token="xoxb-test-token",
        app_token="xapp-test-token",
        authorized=[{"workspace_members": True}],
    )


def _make_user_info(
    user_id: str = "U12345678",
    display_name: str = "Test User",
) -> UserInfo:
    return UserInfo(
        user_id=user_id,
        display_name=display_name,
        is_bot=False,
        is_restricted=False,
        is_ultra_restricted=False,
        team_id="T000001",
        deleted=False,
        fetched_at=0,
    )


def _make_adapter(
    config: SlackChannelConfig | None = None,
    tmp_path: Path | None = None,
) -> tuple[SlackChannelAdapter, MagicMock, MagicMock, SlackThreadStore]:
    cfg = config or _make_config()
    authorizer = MagicMock()
    client = MagicMock()
    store_dir = tmp_path or Path("/tmp/test-slack-store")  # noqa: S108
    thread_store = SlackThreadStore(store_dir)
    adapter = SlackChannelAdapter(
        config=cfg,
        authorizer=authorizer,
        thread_store=thread_store,
        bot_client=client,
    )
    return adapter, authorizer, client, thread_store


def _make_payload(
    *,
    user: str = "U12345678",
    text: str = "Hello, do something",
    channel: str = "D001",
    thread_ts: str = "1700000000.000001",
    files: list[dict] | None = None,
) -> dict:
    payload: dict = {
        "user": user,
        "text": text,
        "channel": channel,
        "thread_ts": thread_ts,
    }
    if files:
        payload["files"] = files
    return payload


class TestAuthenticateAndParse:
    def test_successful_parse(self, tmp_path: Path) -> None:
        adapter, authorizer, _, _ = _make_adapter(tmp_path=tmp_path)
        authorizer.authorize.return_value = _make_user_info()
        payload = _make_payload()

        result = adapter.authenticate_and_parse(payload)

        assert isinstance(result, SlackParsedMessage)
        assert "Test User" in result.sender
        assert "U12345678" in result.sender
        assert result.body == "Hello, do something"
        assert result.conversation_id is None
        assert result.model_hint is None
        assert result.slack_channel_id == "D001"
        assert result.slack_thread_ts == "1700000000.000001"
        assert result.channel_context == _CHANNEL_CONTEXT

    def test_extracts_file_metadata(self, tmp_path: Path) -> None:
        adapter, authorizer, _, _ = _make_adapter(tmp_path=tmp_path)
        authorizer.authorize.return_value = _make_user_info()
        payload = _make_payload(
            files=[
                {
                    "name": "report.pdf",
                    "url_private_download": "https://files.slack.com/dl/T01/F01/report.pdf",
                },
                {
                    "name": "data.csv",
                    "url_private_download": "https://files.slack.com/dl/T01/F02/data.csv",
                },
            ]
        )

        result = adapter.authenticate_and_parse(payload)
        assert len(result.slack_file_urls) == 2
        assert result.slack_file_urls[0] == (
            "report.pdf",
            "https://files.slack.com/dl/T01/F01/report.pdf",
        )

    def test_unauthorized_raises(self, tmp_path: Path) -> None:
        adapter, authorizer, _, _ = _make_adapter(tmp_path=tmp_path)
        authorizer.authorize.side_effect = AuthorizationError(
            user_id="U12345678",
            reason="bot users are not allowed",
        )
        payload = _make_payload()

        with pytest.raises(AuthenticationError) as exc_info:
            adapter.authenticate_and_parse(payload)
        assert exc_info.value.sender == "U12345678"
        assert "bot users" in exc_info.value.reason

    def test_resolves_existing_conversation(self, tmp_path: Path) -> None:
        adapter, authorizer, _, thread_store = _make_adapter(tmp_path=tmp_path)
        authorizer.authorize.return_value = _make_user_info()
        thread_store.register("D001", "1700000000.000001", "existing_conv")

        payload = _make_payload()
        result = adapter.authenticate_and_parse(payload)
        assert result.conversation_id == "existing_conv"

    def test_subject_truncated(self, tmp_path: Path) -> None:
        adapter, authorizer, _, _ = _make_adapter(tmp_path=tmp_path)
        authorizer.authorize.return_value = _make_user_info()
        long_text = "A" * 100
        payload = _make_payload(text=long_text)

        result = adapter.authenticate_and_parse(payload)
        assert result.subject == "A" * 60 + "..."

    def test_empty_text_subject(self, tmp_path: Path) -> None:
        adapter, authorizer, _, _ = _make_adapter(tmp_path=tmp_path)
        authorizer.authorize.return_value = _make_user_info()
        payload = _make_payload(text="")

        result = adapter.authenticate_and_parse(payload)
        assert result.subject == "(no text)"


class TestSaveAttachments:
    def test_downloads_files(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="see attached",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="1700000000.000001",
            slack_file_urls=[
                ("file.txt", "https://files.slack.com/dl/file.txt"),
            ],
        )

        inbox = tmp_path / "inbox"
        inbox.mkdir()

        mock_response = MagicMock()
        mock_response.content = b"file content"
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        import httpx as httpx_mod

        with patch.object(httpx_mod, "Client", return_value=mock_client):
            result = adapter.save_attachments(parsed, inbox)

        assert result == ["file.txt"]
        assert (inbox / "file.txt").read_bytes() == b"file content"

    def test_returns_empty_when_no_files(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="no files",
            conversation_id=None,
            model_hint=None,
        )

        result = adapter.save_attachments(parsed, tmp_path)
        assert result == []


class TestSendAcknowledgment:
    def test_sends_ack_without_dashboard(self, tmp_path: Path) -> None:
        adapter, _, client, thread_store = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="1700000000.000001",
        )

        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)

        client.assistant_threads_setStatus.assert_called_once()
        client.chat_postMessage.assert_called_once()
        call_kw = client.chat_postMessage.call_args[1]
        assert "sonnet" in call_kw["markdown_text"]
        assert call_kw["channel"] == "D001"
        assert call_kw["thread_ts"] == "1700000000.000001"

    def test_sends_ack_with_dashboard(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="1700000000.000001",
        )

        adapter.send_acknowledgment(
            parsed, "conv1", "sonnet", "https://dash.example.com"
        )

        call_kw = client.chat_postMessage.call_args[1]
        assert "dash.example.com/conversation/conv1" in call_kw["markdown_text"]

    def test_registers_thread_mapping(self, tmp_path: Path) -> None:
        adapter, _, _, thread_store = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="1700000000.000001",
        )

        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)

        assert (
            thread_store.get_conversation_id("D001", "1700000000.000001")
            == "conv1"
        )

    def test_status_failure_non_fatal(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        client.assistant_threads_setStatus.side_effect = Exception("API error")
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        # Should not raise
        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)
        # Message should still be sent
        client.chat_postMessage.assert_called_once()


class TestSendReply:
    def test_sends_reply_text(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            subject="Test request",
            slack_channel_id="D001",
            slack_thread_ts="1700000000.000001",
        )

        adapter.send_reply(parsed, "conv1", "Response text", "", [])

        client.chat_postMessage.assert_called_once()
        call_kw = client.chat_postMessage.call_args[1]
        assert call_kw["markdown_text"] == "Response text"

    def test_appends_usage_footer(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        adapter.send_reply(parsed, "conv1", "Done", "Cost: $0.01", [])
        call_kw = client.chat_postMessage.call_args[1]
        assert "Cost: $0.01" in call_kw["markdown_text"]

    def test_converts_tables(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        table_text = "| A | B |\n|---|---|\n| 1 | 2 |"
        adapter.send_reply(parsed, "conv1", table_text, "", [])

        call_kw = client.chat_postMessage.call_args[1]
        assert "```" in call_kw["markdown_text"]

    def test_sets_thread_title(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            subject="Fix the login bug",
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        adapter.send_reply(parsed, "conv1", "Done", "", [])

        client.assistant_threads_setTitle.assert_called_once()
        call_kw = client.assistant_threads_setTitle.call_args[1]
        assert call_kw["title"] == "Fix the login bug"


class TestSendError:
    def test_sends_error_message(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        adapter.send_error(parsed, "conv1", "Something broke")
        call_kw = client.chat_postMessage.call_args[1]
        assert call_kw["markdown_text"] == "Something broke"

    def test_api_failure_logged(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        client.chat_postMessage.side_effect = Exception("API error")
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        # Should not raise
        adapter.send_error(parsed, "conv1", "error msg")


class TestSendRejection:
    def test_sends_rejection_without_dashboard(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        adapter.send_rejection(parsed, "conv1", "duplicate", None)
        call_kw = client.chat_postMessage.call_args[1]
        assert "duplicate" in call_kw["markdown_text"]
        assert "conv1" in call_kw["markdown_text"]

    def test_sends_rejection_with_dashboard(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        adapter.send_rejection(
            parsed, "conv1", "busy", "https://dash.example.com"
        )
        call_kw = client.chat_postMessage.call_args[1]
        assert "dash.example.com/conversation/conv1" in call_kw["markdown_text"]

    def test_api_failure_non_fatal(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        client.chat_postMessage.side_effect = Exception("API error")
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        # Should not raise
        adapter.send_rejection(parsed, "conv1", "reason", None)


class TestConvertTablesToCodeBlocks:
    def test_converts_simple_table(self) -> None:
        text = "Before\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\nAfter"
        result = convert_tables_to_code_blocks(text)
        assert "```\n| A | B |\n|---|---|\n| 1 | 2 |\n```" in result
        assert "Before" in result
        assert "After" in result

    def test_no_tables_unchanged(self) -> None:
        text = "No tables here"
        assert convert_tables_to_code_blocks(text) == text

    def test_multiple_tables(self) -> None:
        text = "| A |\n|---|\n| 1 |\n\n| B |\n|---|\n| 2 |"
        result = convert_tables_to_code_blocks(text)
        assert result.count("```") == 4  # 2 tables × 2 fences


class TestSplitMessage:
    def test_short_message_not_split(self) -> None:
        text = "Short message"
        assert split_message(text) == ["Short message"]

    def test_splits_at_paragraph_break(self) -> None:
        text = "A" * _MAX_MESSAGE_LENGTH + "\n\n" + "B" * 500
        chunks = split_message(text)
        assert len(chunks) == 2
        assert chunks[0] == "A" * _MAX_MESSAGE_LENGTH
        assert chunks[1] == "B" * 500

    def test_splits_at_line_break(self) -> None:
        text = "A" * _MAX_MESSAGE_LENGTH + "\n" + "B" * 500
        chunks = split_message(text)
        assert len(chunks) == 2

    def test_hard_cut_when_no_breaks(self) -> None:
        text = "A" * 15000
        chunks = split_message(text)
        assert len(chunks) == 2
        assert len(chunks[0]) == _MAX_MESSAGE_LENGTH
        assert len(chunks[1]) == 3000

    def test_exact_limit_not_split(self) -> None:
        text = "A" * _MAX_MESSAGE_LENGTH
        assert len(split_message(text)) == 1


class TestFromConfig:
    def test_creates_adapter_from_config(self) -> None:
        config = _make_config()
        mock_sdk = MagicMock()
        with patch.dict("sys.modules", {"slack_sdk": mock_sdk}):
            adapter = SlackChannelAdapter.from_config(
                config, repo_id="test-repo"
            )
        mock_sdk.WebClient.assert_called_once_with(token="xoxb-test-token")
        assert adapter._repo_id == "test-repo"

    def test_from_config_with_storage_dir(self, tmp_path: Path) -> None:
        config = _make_config()
        mock_sdk = MagicMock()
        with patch.dict("sys.modules", {"slack_sdk": mock_sdk}):
            adapter = SlackChannelAdapter.from_config(
                config, repo_id="test", storage_dir=tmp_path
            )
        assert adapter._thread_store is not None


class TestSaveAttachmentsEdgeCases:
    def test_download_failure_logged(self, tmp_path: Path) -> None:
        """Failed downloads are logged and skipped."""
        adapter, _, _, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="see attached",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
            slack_file_urls=[
                ("bad.txt", "https://files.slack.com/dl/bad.txt"),
            ],
        )

        inbox = tmp_path / "inbox"
        inbox.mkdir()

        mock_client = MagicMock()
        mock_client.get.side_effect = Exception("Network error")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        import httpx as httpx_mod

        with patch.object(httpx_mod, "Client", return_value=mock_client):
            result = adapter.save_attachments(parsed, inbox)

        assert result == []


class TestSendAcknowledgmentEdgeCases:
    def test_post_message_failure_non_fatal(self, tmp_path: Path) -> None:
        """Failed ack post is non-fatal."""
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        client.chat_postMessage.side_effect = Exception("API error")
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        # Should not raise
        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)


class TestSendReplyEdgeCases:
    def test_post_message_failure_logged(self, tmp_path: Path) -> None:
        """Failed reply chunk is logged, not raised."""
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        client.chat_postMessage.side_effect = Exception("API error")
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        # Should not raise
        adapter.send_reply(parsed, "conv1", "text", "", [])

    def test_uploads_outbox_files(self, tmp_path: Path) -> None:
        """Outbox files are uploaded via _upload_files."""
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            subject="subj",
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        # Create a file to upload
        outbox_file = tmp_path / "result.txt"
        outbox_file.write_text("result content")

        client.files_getUploadURLExternal.return_value = {
            "upload_url": "https://upload.slack.com/...",
            "file_id": "F001",
        }

        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)

        import httpx as httpx_mod

        with patch.object(httpx_mod, "Client", return_value=mock_http):
            adapter.send_reply(parsed, "conv1", "text", "", [outbox_file])

        client.files_getUploadURLExternal.assert_called_once()
        client.files_completeUploadExternal.assert_called_once()

    def test_title_set_failure_non_fatal(self, tmp_path: Path) -> None:
        """Failed thread title set is non-fatal."""
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        client.assistant_threads_setTitle.side_effect = Exception("error")
        parsed = SlackParsedMessage(
            sender="Test User (U123)",
            body="body",
            conversation_id=None,
            model_hint=None,
            subject="subj",
            slack_channel_id="D001",
            slack_thread_ts="ts",
        )

        # Should not raise
        adapter.send_reply(parsed, "conv1", "text", "", [])


class TestUploadFiles:
    def test_upload_success(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)

        # Create file
        f = tmp_path / "output.txt"
        f.write_bytes(b"data")

        client.files_getUploadURLExternal.return_value = {
            "upload_url": "https://upload.slack.com/...",
            "file_id": "F001",
        }

        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)

        import httpx as httpx_mod

        with patch.object(httpx_mod, "Client", return_value=mock_http):
            adapter._upload_files("D001", "ts", [f])

        client.files_getUploadURLExternal.assert_called_once_with(
            filename="output.txt", length=4
        )
        mock_http.post.assert_called_once()
        client.files_completeUploadExternal.assert_called_once()

    def test_upload_skips_missing_files(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)
        missing = tmp_path / "nonexistent.txt"

        adapter._upload_files("D001", "ts", [missing])

        client.files_getUploadURLExternal.assert_not_called()

    def test_upload_failure_logged(self, tmp_path: Path) -> None:
        adapter, _, client, _ = _make_adapter(tmp_path=tmp_path)

        f = tmp_path / "output.txt"
        f.write_bytes(b"data")

        client.files_getUploadURLExternal.side_effect = Exception("API fail")

        # Should not raise
        adapter._upload_files("D001", "ts", [f])
