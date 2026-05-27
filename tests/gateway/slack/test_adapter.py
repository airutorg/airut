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

from airut.gateway.channel import (
    AuthenticationError,
    ChannelSendError,
    RawMessage,
)
from airut.gateway.slack.adapter import (
    SlackChannelAdapter,
    SlackParsedMessage,
    _is_slack_file_url,
    _send_long_message,
    _split_message,
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
        assert "AskUserQuestion" in result.channel_context

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
            slack_file_urls=[
                (
                    "report.txt",
                    "https://files.slack.com/files-pri/T1-F1/report.txt",
                )
            ],
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
            slack_file_urls=[
                (
                    "report.txt",
                    "https://files.slack.com/files-pri/T1-F1/report.txt",
                )
            ],
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
        assert "started working" in call_kw["text"]
        assert "reply shortly" in call_kw["text"]

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
        text = call_kw["text"]
        assert "https://dash.example.com/conversation/conv1" in text
        # Bare URL, no mrkdwn link syntax (Slack auto-links bare URLs)
        assert "<" not in text
        assert ">" not in text

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
        call_kw = client.chat_postMessage.call_args[1]
        assert call_kw["text"] == "Response text"
        assert "blocks" not in call_kw

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
        # Footer is rendered as italic mrkdwn (``_…_``).
        assert call_kw["text"] == "Done\n\n_Cost: $0.01_"

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

        with pytest.raises(ChannelSendError):
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
        text = call_kw["text"]
        assert "https://dash.example.com/conversation/conv1" in text
        # Bare URL, no mrkdwn link syntax (Slack auto-links bare URLs)
        assert "<" not in text
        assert ">" not in text

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


class TestSplitMessage:
    def test_splits_at_paragraph_boundary(self) -> None:
        p1 = "A" * 30000
        p2 = "B" * 30000
        text = f"{p1}\n\n{p2}"
        chunks = _split_message(text)
        assert chunks == [p1, p2]

    def test_accumulates_paragraphs_under_limit(self) -> None:
        # Two small paragraphs plus one that forces a flush, so the first
        # chunk holds both accumulated paragraphs.
        p1 = "A" * 100
        p2 = "B" * 100
        p3 = "C" * 39999
        text = f"{p1}\n\n{p2}\n\n{p3}"
        chunks = _split_message(text)
        assert chunks[0] == f"{p1}\n\n{p2}"
        assert chunks[1] == p3

    def test_single_large_paragraph_splits_at_lines(self) -> None:
        lines = ["X" * 1000 for _ in range(60)]
        text = "\n".join(lines)
        chunks = _split_message(text)
        assert len(chunks) > 1
        for chunk in chunks:
            assert len(chunk) <= 40000


class TestSendLongMessage:
    def test_short_text_single_message(self) -> None:
        """Text within the ceiling ships as a single ``text`` message."""
        client = MagicMock(spec=WebClient)
        _send_long_message(client, "C123", "ts1", "short reply")
        client.chat_postMessage.assert_called_once_with(
            channel="C123", thread_ts="ts1", text="short reply"
        )

    def test_medium_text_multiple_messages(self) -> None:
        """Text between 40K and 200K chars splits into multiple messages."""
        client = MagicMock(spec=WebClient)
        paragraphs = [f"Para {i}: " + "X" * 30000 for i in range(4)]
        text = "\n\n".join(paragraphs)
        _send_long_message(client, "C123", "ts1", text)
        assert client.chat_postMessage.call_count > 1
        for call in client.chat_postMessage.call_args_list:
            assert "blocks" not in call[1]

    def test_very_long_text_uploaded_as_file(self) -> None:
        """Text beyond five messages' worth is uploaded as a file."""
        client = MagicMock(spec=WebClient)
        text = "A" * 200001
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
            slack_file_urls=[
                (
                    "../../etc/evil.sh",
                    "https://files.slack.com/files-pri/T1-F1/evil.sh",
                )
            ],
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
            slack_file_urls=[
                ("", "https://files.slack.com/files-pri/T1-F1/file")
            ],
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
            slack_file_urls=[
                ("big.bin", "https://files.slack.com/files-pri/T1-F1/big.bin")
            ],
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


class TestChannelContext:
    def test_returns_slack_instructions(self, tmp_path: Path) -> None:
        """channel_context() returns the Slack system prompt."""
        adapter, _, _, _ = _make_adapter(tmp_path)
        ctx = adapter.channel_context()
        assert "Slack" in ctx
        assert "AskUserQuestion" in ctx
        assert "/outbox" in ctx
        assert "/storage" in ctx

    def test_consistent_with_authenticate_and_parse(
        self, tmp_path: Path
    ) -> None:
        """channel_context() matches authenticate_and_parse."""
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        msg = _make_raw_message()

        parsed = adapter.authenticate_and_parse(msg)
        ctx = adapter.channel_context()
        assert parsed.channel_context == ctx


class TestCleanupConversations:
    def test_removes_stale_thread_mappings(self, tmp_path: Path) -> None:
        adapter, _, _, thread_store = _make_adapter(tmp_path)
        thread_store.register("D123", "ts1", "conv1")
        thread_store.register("D123", "ts2", "conv2")
        thread_store.register("D456", "ts3", "conv3")

        adapter.cleanup_conversations({"conv1", "conv3"})

        assert thread_store.get_conversation_id("D123", "ts1") == "conv1"
        assert thread_store.get_conversation_id("D123", "ts2") is None
        assert thread_store.get_conversation_id("D456", "ts3") == "conv3"

    def test_noop_when_all_active(self, tmp_path: Path) -> None:
        adapter, _, _, thread_store = _make_adapter(tmp_path)
        thread_store.register("D123", "ts1", "conv1")

        adapter.cleanup_conversations({"conv1"})

        assert thread_store.get_conversation_id("D123", "ts1") == "conv1"

    def test_noop_on_empty_store(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)

        # Should not raise
        adapter.cleanup_conversations({"conv1"})


class TestCreatePlanStreamer:
    def test_returns_streamer_for_slack_message(self, tmp_path: Path) -> None:
        from airut.gateway.slack.plan_streamer import SlackPlanStreamer

        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        streamer = adapter.create_plan_streamer(parsed)
        assert isinstance(streamer, SlackPlanStreamer)

    def test_returns_none_for_non_slack_message(self, tmp_path: Path) -> None:
        from airut.gateway.channel import ParsedMessage

        adapter, _, _, _ = _make_adapter(tmp_path)
        wrong = ParsedMessage(
            sender="U123",
            body="text",
            conversation_id=None,
            model_hint=None,
        )

        result = adapter.create_plan_streamer(wrong)
        assert result is None


class TestIsSlackFileUrl:
    """Tests for URL validation of Slack file downloads."""

    def test_accepts_files_slack_com(self) -> None:
        url = "https://files.slack.com/files-pri/T024-F024/report.txt"
        assert _is_slack_file_url(url) is True

    def test_accepts_files_slack_com_download(self) -> None:
        url = "https://files.slack.com/files-pri/T024-F024/download/report.txt"
        assert _is_slack_file_url(url) is True

    def test_accepts_legacy_slack_com(self) -> None:
        url = "https://slack.com/files-pri/T024-F024/1.png"
        assert _is_slack_file_url(url) is True

    def test_rejects_http(self) -> None:
        url = "http://files.slack.com/files-pri/T024-F024/report.txt"
        assert _is_slack_file_url(url) is False

    def test_rejects_arbitrary_host(self) -> None:
        assert _is_slack_file_url("https://evil.com/file") is False

    def test_rejects_internal_metadata(self) -> None:
        assert _is_slack_file_url("http://169.254.169.254/metadata") is False

    def test_rejects_localhost(self) -> None:
        assert _is_slack_file_url("http://localhost:8080/secret") is False

    def test_rejects_subdomain_impersonation(self) -> None:
        assert _is_slack_file_url("https://files.slack.com.evil.com/f") is False

    def test_rejects_empty_string(self) -> None:
        assert _is_slack_file_url("") is False

    def test_rejects_non_url(self) -> None:
        assert _is_slack_file_url("not a url") is False

    def test_rejects_ftp_scheme(self) -> None:
        assert _is_slack_file_url("ftp://files.slack.com/file") is False

    def test_rejects_slack_files_com(self) -> None:
        """slack-files.com is for thumbnails, not private file downloads."""
        assert _is_slack_file_url("https://slack-files.com/file") is False

    def test_rejects_malformed_ipv6(self) -> None:
        """Malformed URLs that cause urlparse ValueError are rejected."""
        assert _is_slack_file_url("https://[invalid/file") is False


class TestSaveAttachmentsUrlValidation:
    """Tests that save_attachments rejects non-Slack URLs."""

    def test_rejects_non_slack_url(self, tmp_path: Path) -> None:
        """Files from non-Slack hosts are skipped (no download attempt)."""
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="see attached",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            slack_file_urls=[("evil.txt", "https://evil.com/steal-token")],
        )

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
        ) as mock_urlopen:
            result = adapter.save_attachments(parsed, inbox)

        assert result == []
        mock_urlopen.assert_not_called()

    def test_rejects_internal_ip(self, tmp_path: Path) -> None:
        """URLs targeting internal IPs are rejected."""
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
            slack_file_urls=[
                ("meta.json", "http://169.254.169.254/latest/meta-data/")
            ],
        )

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
        ) as mock_urlopen:
            result = adapter.save_attachments(parsed, inbox)

        assert result == []
        mock_urlopen.assert_not_called()

    def test_mixed_valid_and_invalid_urls(self, tmp_path: Path) -> None:
        """Valid Slack URLs download; non-Slack URLs are skipped."""
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()

        parsed = SlackParsedMessage(
            sender="U123",
            body="files",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            slack_file_urls=[
                ("evil.txt", "https://evil.com/steal"),
                (
                    "good.txt",
                    "https://files.slack.com/files-pri/T1-F1/good.txt",
                ),
            ],
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"good data"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            return_value=mock_resp,
        ) as mock_urlopen:
            result = adapter.save_attachments(parsed, inbox)

        # Only the valid Slack URL was downloaded
        assert result == ["good.txt"]
        mock_urlopen.assert_called_once()
        assert (inbox / "good.txt").read_bytes() == b"good data"
        assert not (inbox / "evil.txt").exists()
