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
    TaskPhase,
    UndeliveredFile,
)
from airut.gateway.slack.adapter import (
    _MAX_SPLIT_MESSAGES,
    _MAX_TEXT_CHARS,
    SlackChannelAdapter,
    SlackParsedMessage,
    _is_slack_file_url,
    _send_long_message,
    _split_message,
    _upload_file,
)
from airut.gateway.slack.authorizer import SlackAuthorizer, UserInfo
from airut.gateway.slack.config import SlackChannelConfig
from airut.gateway.slack.thread_store import SlackThreadStore


def _make_config(*, sticky_threads: bool = True) -> SlackChannelConfig:
    return SlackChannelConfig(
        bot_token="xoxb-test-token",
        app_token="xapp-test-token",
        authorized=({"workspace_members": True},),
        sticky_threads=sticky_threads,
    )


def _make_adapter(
    tmp_path: Path,
    *,
    sticky_threads: bool = True,
) -> tuple[
    SlackChannelAdapter,
    MagicMock,
    MagicMock,
    SlackThreadStore,
]:
    config = _make_config(sticky_threads=sticky_threads)
    client = MagicMock(spec=WebClient)
    client.token = config.bot_token
    authorizer = MagicMock(spec=SlackAuthorizer)
    authorizer.get_bot_user_id.return_value = "UBOT"
    authorizer.candidate_group_member_ids.return_value = set()
    authorizer.get_user_info.return_value = None
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
        authorizer.get_display_name.return_value = "Alice Anderson"
        msg = _make_raw_message(text="Do something")

        result = adapter.authenticate_and_parse(msg)

        assert isinstance(result, SlackParsedMessage)
        assert result.sender == "U123"
        # Resolved name plus the bare user ID (inert, not a live mention).
        assert result.sender_display == "Alice Anderson <U123>"
        assert result.body == "Do something"
        assert result.conversation_id is None
        assert result.slack_channel_id == "D456"
        assert result.slack_thread_ts == "1234567890.123456"

    def test_sender_display_falls_back_to_user_id(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        # No cached profile: get_display_name returns the raw user ID.
        authorizer.get_display_name.return_value = "U123"
        msg = _make_raw_message(text="Do something")

        result = adapter.authenticate_and_parse(msg)

        assert result.sender_display == "U123"

    def test_unauthorized_raises(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (
            False,
            "sender not authorized",
        )
        # authorize() warmed the cache, so the rejected sender resolves to
        # a readable name for the dashboard (same form as authorized).
        authorizer.get_display_name.return_value = "Alice Anderson"
        msg = _make_raw_message()

        with pytest.raises(AuthenticationError) as exc_info:
            adapter.authenticate_and_parse(msg)
        assert exc_info.value.sender == "Alice Anderson <U123>"
        assert "not authorized" in exc_info.value.reason

    def test_unauthorized_falls_back_to_user_id(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (False, "failed to fetch user info")
        # No cached profile (e.g. user-info fetch failed): falls back to ID.
        authorizer.get_display_name.return_value = "U123"
        msg = _make_raw_message()

        with pytest.raises(AuthenticationError) as exc_info:
            adapter.authenticate_and_parse(msg)
        assert exc_info.value.sender == "U123"

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

    def test_does_not_follow_planted_link(self, tmp_path: Path) -> None:
        """A link the task left in the inbox is not written through.

        It could name any host path; the attachment is saved beside it.
        """
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()
        target = tmp_path / "host" / "planted.txt"
        target.parent.mkdir()
        (inbox / "report.txt").symlink_to(target)

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
        ):
            result = adapter.save_attachments(parsed, inbox)

        assert result == ["report-1.txt"]
        assert (inbox / "report-1.txt").read_bytes() == b"file data"
        assert not target.exists()

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

    def test_duplicate_names_are_uniquified(self, tmp_path: Path) -> None:
        """Two attachments sharing a name are both saved, not clobbered."""
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
            slack_file_urls=[
                (
                    "data.csv",
                    "https://files.slack.com/files-pri/T1-F1/data.csv",
                ),
                (
                    "data.csv",
                    "https://files.slack.com/files-pri/T1-F2/data.csv",
                ),
            ],
        )

        contents = [b"first", b"second"]

        def fake_urlopen(req: object) -> MagicMock:
            resp = MagicMock()
            resp.read.return_value = contents.pop(0)
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            side_effect=fake_urlopen,
        ):
            result = adapter.save_attachments(parsed, inbox)

        # Both files saved under distinct names; neither overwrites the other.
        assert result == ["data.csv", "data-1.csv"]
        assert (inbox / "data.csv").read_bytes() == b"first"
        assert (inbox / "data-1.csv").read_bytes() == b"second"

    def test_duplicate_of_existing_inbox_file(self, tmp_path: Path) -> None:
        """A new attachment colliding with a prior turn's file is preserved."""
        adapter, _, _, _ = _make_adapter(tmp_path)
        inbox = tmp_path / "inbox"
        inbox.mkdir()
        (inbox / "report.txt").write_bytes(b"old turn")

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
                ),
            ],
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"new turn"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch(
            "airut.gateway.slack.adapter.urllib.request.urlopen",
            return_value=mock_resp,
        ):
            result = adapter.save_attachments(parsed, inbox)

        assert result == ["report-1.txt"]
        assert (inbox / "report.txt").read_bytes() == b"old turn"
        assert (inbox / "report-1.txt").read_bytes() == b"new turn"


class TestCoalesce:
    def test_coalesce_merges_file_urls(self) -> None:
        """A coalesced follow-up's attachments join the survivor's list."""
        survivor = SlackParsedMessage(
            sender="U1",
            body="first",
            conversation_id="c1",
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            slack_file_urls=[("a.txt", "https://files.slack.com/a")],
            acknowledged_message_ts=["T1"],
            is_channel=True,
        )
        follow_up = SlackParsedMessage(
            sender="U2",
            body="second",
            conversation_id="c1",
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            slack_file_urls=[("b.txt", "https://files.slack.com/b")],
            acknowledged_message_ts=["T2"],
            is_channel=True,
        )

        survivor.coalesce(follow_up)

        # Both messages' attachments are downloaded when the survivor runs.
        assert survivor.slack_file_urls == [
            ("a.txt", "https://files.slack.com/a"),
            ("b.txt", "https://files.slack.com/b"),
        ]
        # Reaction targets and burst entries still accumulate as before.
        assert survivor.acknowledged_message_ts == ["T1", "T2"]
        assert [body for _, _, body in survivor.coalesced_entries] == [
            "first",
            "second",
        ]

    def test_coalesce_with_plain_parsed_message(self) -> None:
        """Coalescing a non-Slack message does not touch Slack-only state."""
        from airut.gateway.channel import ParsedMessage

        survivor = SlackParsedMessage(
            sender="U1",
            body="first",
            conversation_id="c1",
            model_hint=None,
            slack_file_urls=[("a.txt", "https://files.slack.com/a")],
        )
        other = ParsedMessage(
            sender="U2", body="second", conversation_id="c1", model_hint=None
        )

        survivor.coalesce(other)

        assert survivor.slack_file_urls == [
            ("a.txt", "https://files.slack.com/a")
        ]


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


class TestReportPhase:
    def test_preparing_sets_loading_indicator(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        adapter.report_phase(parsed, TaskPhase.PREPARING)

        client.assistant_threads_setStatus.assert_called_once_with(
            channel_id="D456",
            thread_ts="ts1",
            status="is working on this...",
        )

    def test_running_clears_status(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
        )

        adapter.report_phase(parsed, TaskPhase.RUNNING)

        client.assistant_threads_setStatus.assert_called_once_with(
            channel_id="D456",
            thread_ts="ts1",
            status="",
        )

    def test_api_failure_non_fatal(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.assistant_threads_setStatus.side_effect = SlackApiError(
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
        adapter.report_phase(parsed, TaskPhase.PREPARING)
        adapter.report_phase(parsed, TaskPhase.RUNNING)

    def test_type_error(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        from airut.gateway.channel import ParsedMessage

        wrong = ParsedMessage(
            sender="U123",
            body="t",
            conversation_id=None,
            model_hint=None,
        )
        with pytest.raises(TypeError, match="SlackParsedMessage"):
            adapter.report_phase(wrong, TaskPhase.PREPARING)


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

        undelivered = adapter.send_reply(parsed, "conv1", "Done", "", [outfile])

        client.files_upload_v2.assert_called_once()
        assert undelivered == []

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
        mock_listener.assert_called_once_with(
            config, mock_store.return_value, mock_auth.return_value
        )
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

    def test_single_long_line_hard_sliced(self) -> None:
        # A single line longer than the ceiling is sliced without loss.
        text = "X" * 90000
        chunks = _split_message(text)
        assert len(chunks) == 3
        for chunk in chunks:
            assert len(chunk) <= 40000
        assert "".join(chunks) == text


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

    def test_medium_text_at_most_five_messages(self) -> None:
        """A sub-200K body needing >5 chunks uploads rather than posting."""
        client = MagicMock(spec=WebClient)
        # Six ~30K paragraphs (total ~180K) each flush into their own chunk.
        paragraphs = ["X" * 30001 for _ in range(6)]
        text = "\n\n".join(paragraphs)
        assert len(text) < _MAX_TEXT_CHARS * _MAX_SPLIT_MESSAGES
        _send_long_message(client, "C123", "ts1", text)
        client.files_upload_v2.assert_called_once()
        client.chat_postMessage.assert_not_called()

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
        """File upload errors don't prevent the reply from sending.

        The undelivered file is named in the thread for the user, and
        returned so the core sets it aside for the agent.
        """
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
        undelivered = adapter.send_reply(parsed, "conv1", "Done", "", [outfile])

        texts = [
            c.kwargs["text"] for c in client.chat_postMessage.call_args_list
        ]
        assert texts[0] == "Done"
        assert "report.txt" in texts[1]
        assert undelivered == [
            UndeliveredFile(outfile, "upload to Slack failed")
        ]

    def test_upload_failure_report_failure_non_fatal(
        self, tmp_path: Path
    ) -> None:
        """Failing to report a failed upload does not raise."""
        adapter, client, _, _ = _make_adapter(tmp_path)
        error = SlackApiError(
            message="upload_failed",
            response=MagicMock(status_code=500, data={}),
        )
        client.files_upload_v2.side_effect = error
        client.chat_postMessage.side_effect = [MagicMock(), error]
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

        # The reply, then the (also failing) failure report.
        assert client.chat_postMessage.call_count == 2

    def test_unreadable_file_reported(self, tmp_path: Path) -> None:
        """A file that vanished before upload is reported, not raised.

        ``files_upload_v2`` opens the path itself, so a file removed
        between listing and upload surfaces as an ``OSError`` rather than
        a Slack error — it must stay on the reported path.
        """
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.files_upload_v2.side_effect = FileNotFoundError("gone.txt")
        parsed = SlackParsedMessage(
            sender="U123",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D456",
            slack_thread_ts="ts1",
            display_title="Test",
        )

        # Should not raise even though the path does not exist
        adapter.send_reply(parsed, "conv1", "Done", "", [tmp_path / "gone.txt"])

        texts = [
            c.kwargs["text"] for c in client.chat_postMessage.call_args_list
        ]
        assert "gone.txt" in texts[1]

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


def _channel_raw(
    *,
    user: str = "U1",
    text: str = "<@UBOT> do the thing",
    channel: str = "C1",
    ts: str = "T1",
    thread_ts: str | None = None,
    event_type: str = "app_mention",
    channel_type: str | None = None,
    files: list | None = None,
) -> RawMessage:
    payload: dict = {
        "type": event_type,
        "user": user,
        "text": text,
        "channel": channel,
        "ts": ts,
    }
    if thread_ts is not None:
        payload["thread_ts"] = thread_ts
    if channel_type is not None:
        payload["channel_type"] = channel_type
    if files is not None:
        payload["files"] = files
    return RawMessage(sender=user, content=payload, display_title=text[:60])


class TestChannelEngagement:
    def test_top_level_mention_parse(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"

        result = adapter.authenticate_and_parse(_channel_raw())

        assert result.is_channel is True
        assert result.slack_channel_id == "C1"
        # Top-level mention: the message ts roots the thread.
        assert result.slack_thread_ts == "T1"
        # Bot mention stripped from the invocation body.
        assert result.body == "do the thing"
        assert result.mention_candidate_ids == ["U1"]
        # :eyes: reaction acknowledges the triggering message.
        client.reactions_add.assert_called_once_with(
            channel="C1", timestamp="T1", name="eyes"
        )
        # The acked ts is recorded for the later terminal-reaction swap.
        assert result.acknowledged_message_ts == ["T1"]
        # No replay for a brand-new top-level thread.
        client.conversations_replies.assert_not_called()

    def test_message_event_is_channel(self, tmp_path: Path) -> None:
        adapter, client, authorizer, store = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"
        store.register("C1", "T1", "conv1")

        result = adapter.authenticate_and_parse(
            _channel_raw(
                event_type="message",
                channel_type="channel",
                text="follow up",
                ts="T2",
                thread_ts="T1",
            )
        )

        assert result.is_channel is True
        assert result.conversation_id == "conv1"
        assert result.slack_thread_ts == "T1"
        # Sticky threads: every follow-up was delivered, so no replay.
        client.conversations_replies.assert_not_called()
        assert result.catch_up_history == []

    def test_followup_by_other_user_acknowledged_with_eyes(
        self, tmp_path: Path
    ) -> None:
        """A different user's non-mention follow-up still gets ``:eyes:``.

        Regression guard for the reported scenario: user A starts a thread
        by mentioning the bot; user B later replies in the same engaged
        thread *without* mentioning the bot.  B's ``message`` event must be
        acknowledged with an ``:eyes:`` reaction on its own ts (not A's),
        and that ts must be recorded for the terminal swap — exactly as a
        mention is.  The acknowledgement is sender-independent: it is gated
        only by ``is_channel``, the same flag that later drives the
        completion checkmark, so a checkmark can never appear without a
        preceding ``:eyes:``.
        """
        adapter, client, authorizer, store = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Bob"
        # User A's conversation is already mapped to the thread root T1.
        store.register("C1", "T1", "conv1")

        parsed = adapter.authenticate_and_parse(
            _channel_raw(
                user="UB",
                event_type="message",
                channel_type="channel",
                text="continuing the conversation",
                ts="T2",
                thread_ts="T1",
            )
        )

        # B's follow-up is acknowledged on B's own message (T2), not T1.
        client.reactions_add.assert_called_once_with(
            channel="C1", timestamp="T2", name="eyes"
        )
        assert parsed.acknowledged_message_ts == ["T2"]
        assert parsed.conversation_id == "conv1"

        # On completion the ack swaps to a checkmark on the same message,
        # so the in-flight :eyes: and the terminal mark stay coupled.
        client.reactions_add.reset_mock()
        adapter.report_phase(parsed, TaskPhase.COMPLETED)
        client.reactions_remove.assert_called_once_with(
            channel="C1", timestamp="T2", name="eyes"
        )
        client.reactions_add.assert_called_once_with(
            channel="C1", timestamp="T2", name="white_check_mark"
        )

    def test_dm_is_not_channel(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"

        result = adapter.authenticate_and_parse(
            _channel_raw(
                event_type="message",
                channel_type="im",
                channel="D1",
                text="hi",
                thread_ts="T1",
            )
        )

        assert result.is_channel is False
        client.reactions_add.assert_not_called()
        # DMs acknowledge via the thread status, so no reaction to track.
        assert result.acknowledged_message_ts == []

    def test_reaction_failure_non_fatal(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"
        client.reactions_add.side_effect = SlackApiError(
            message="no", response=MagicMock(status_code=500, data={})
        )

        # Should not raise.
        result = adapter.authenticate_and_parse(_channel_raw())
        assert result.is_channel is True

    def test_bare_mention_sets_subject_sentinel(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"

        result = adapter.authenticate_and_parse(_channel_raw(text="<@UBOT>"))

        assert result.body == ""
        assert result.subject == "Slack channel message"

    def test_group_members_in_candidates(self, tmp_path: Path) -> None:
        adapter, _, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"
        authorizer.candidate_group_member_ids.return_value = {"U2", "U3"}

        result = adapter.authenticate_and_parse(_channel_raw())

        assert result.mention_candidate_ids[0] == "U1"
        assert set(result.mention_candidate_ids) == {"U1", "U2", "U3"}


class TestMidThreadReplay:
    def test_replay_folds_history(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: {
            "U1": "Alice",
            "U2": "Bob",
        }.get(uid, uid)
        client.conversations_replies.return_value = {
            "messages": [
                {"ts": "T0", "user": "U2", "text": "the earlier question"},
                {"ts": "T1", "user": "U1", "text": "<@UBOT> please help"},
            ],
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> please help", ts="T1", thread_ts="T0")
        )

        # Mid-thread: the engaged thread is the existing root.
        assert result.slack_thread_ts == "T0"
        assert "existing Slack thread" in result.channel_context
        assert "[Bob]: the earlier question" in result.channel_context
        assert result.body == "please help"
        # Replay author joins the outbound candidate set.
        assert "U2" in result.mention_candidate_ids
        # The invocation message itself is not repeated in the preamble.
        assert result.channel_context.count("please help") == 0

    def test_replay_collects_history_attachments(self, tmp_path: Path) -> None:
        """Files posted earlier in the thread are queued for inbox download."""
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: {
            "U1": "Alice",
            "U2": "Bob",
        }.get(uid, uid)
        # Slack tags an uploaded file with subtype "file_share"; the replay
        # must keep such messages rather than drop them as a system subtype.
        client.conversations_replies.return_value = {
            "messages": [
                {
                    "ts": "T0",
                    "user": "U2",
                    "subtype": "file_share",
                    "text": "here is the spec",
                    "files": [
                        {
                            "name": "spec.pdf",
                            "url_private_download": (
                                "https://files.slack.com/spec.pdf"
                            ),
                        }
                    ],
                },
                {"ts": "T1", "user": "U1", "text": "<@UBOT> please help"},
            ],
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> please help", ts="T1", thread_ts="T0")
        )

        # The earlier attachment is queued for download to /inbox.
        assert (
            "spec.pdf",
            "https://files.slack.com/spec.pdf",
        ) in result.slack_file_urls
        # The preamble renders the file_share message and flags attachments.
        assert (
            "[Bob]: here is the spec [attached: spec.pdf]"
            in result.channel_context
        )

    def test_replay_file_share_without_comment(self, tmp_path: Path) -> None:
        """A file_share with no comment renders the attachment cleanly."""
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: {"U2": "Bob"}.get(
            uid, uid
        )
        client.conversations_replies.return_value = {
            "messages": [
                {
                    "ts": "T0",
                    "user": "U2",
                    "subtype": "file_share",
                    "text": "",
                    "files": [
                        {
                            "name": "spec.pdf",
                            "url_private_download": (
                                "https://files.slack.com/spec.pdf"
                            ),
                        }
                    ],
                },
                {"ts": "T1", "user": "U1", "text": "<@UBOT> help"},
            ],
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        # No double space between the colon and the attachment marker.
        assert "[Bob]: [attached: spec.pdf]" in result.channel_context
        assert "[Bob]:  [attached" not in result.channel_context

    def test_replay_history_attachments_precede_trigger(
        self, tmp_path: Path
    ) -> None:
        """History files are ordered before the triggering message's files."""
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: uid
        client.conversations_replies.return_value = {
            "messages": [
                {
                    "ts": "T0",
                    "user": "U2",
                    "text": "earlier",
                    "files": [
                        {
                            "name": "old.txt",
                            "url_private_download": (
                                "https://files.slack.com/old.txt"
                            ),
                        }
                    ],
                },
                {"ts": "T1", "user": "U1", "text": "<@UBOT> help"},
            ],
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(
                text="<@UBOT> help",
                ts="T1",
                thread_ts="T0",
                files=[
                    {
                        "name": "new.txt",
                        "url_private_download": (
                            "https://files.slack.com/new.txt"
                        ),
                    }
                ],
            )
        )

        assert result.slack_file_urls == [
            ("old.txt", "https://files.slack.com/old.txt"),
            ("new.txt", "https://files.slack.com/new.txt"),
        ]

    def test_replay_excludes_bots_and_subtypes(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: uid
        client.conversations_replies.return_value = {
            "messages": [
                {"ts": "T0", "user": "U2", "text": "human msg"},
                {"ts": "Tb", "bot_id": "B1", "text": "bot noise"},
                {"ts": "Tj", "user": "U9", "subtype": "channel_join"},
                {"ts": "T1", "user": "U1", "text": "<@UBOT> help"},
            ],
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        assert "[U2]: human msg" in result.channel_context
        assert "bot noise" not in result.channel_context
        assert result.mention_candidate_ids == ["U1", "U2"]

    def test_replay_no_prior_messages(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"
        # Thread contains only the invocation message.
        client.conversations_replies.return_value = {
            "messages": [{"ts": "T1", "user": "U1", "text": "<@UBOT> help"}],
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        # No preamble appended when there is no prior history.
        assert "existing Slack thread" not in result.channel_context

    def test_replay_trims_to_limit(self, tmp_path: Path) -> None:
        from airut.gateway.slack.thread_history import _HISTORY_REPLAY_LIMIT

        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: uid
        history = [
            {"ts": f"T{i}", "user": "U2", "text": f"msg{i}"}
            for i in range(_HISTORY_REPLAY_LIMIT + 50)
        ]
        history.append({"ts": "TX", "user": "U1", "text": "<@UBOT> help"})
        client.conversations_replies.return_value = {
            "messages": history,
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="TX", thread_ts="T0")
        )

        assert "[50 earlier messages omitted]" in result.channel_context
        # Oldest 50 are dropped from the rendered preamble.
        assert "msg0" not in result.channel_context
        assert "msg49" not in result.channel_context
        assert "msg50" in result.channel_context

    def test_replay_paginates(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: uid
        client.conversations_replies.side_effect = [
            {
                "messages": [{"ts": "T0", "user": "U2", "text": "first"}],
                "response_metadata": {"next_cursor": "c1"},
            },
            {
                "messages": [
                    {"ts": "T0b", "user": "U2", "text": "second"},
                    {"ts": "T1", "user": "U1", "text": "<@UBOT> help"},
                ],
                "response_metadata": {},
            },
        ]

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        assert client.conversations_replies.call_count == 2
        assert "[U2]: first" in result.channel_context
        assert "[U2]: second" in result.channel_context

    def test_replay_dedups_parent_repeated_per_page(
        self, tmp_path: Path
    ) -> None:
        """A parent repeated at the top of each page is replayed once."""
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: uid
        root = {"ts": "T0", "user": "U2", "text": "root"}
        client.conversations_replies.side_effect = [
            {
                "messages": [root, {"ts": "Ta", "user": "U3", "text": "a"}],
                "response_metadata": {"next_cursor": "c1"},
            },
            {
                "messages": [
                    root,
                    {"ts": "Tb", "user": "U3", "text": "b"},
                    {"ts": "T1", "user": "U1", "text": "<@UBOT> help"},
                ],
                "response_metadata": {},
            },
        ]

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        assert result.channel_context.endswith("\n[U2]: root\n[U3]: a\n[U3]: b")

    def test_replay_fetches_uncached_author_names(self, tmp_path: Path) -> None:
        """Authors who never addressed the bot are looked up, not raw IDs."""
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: uid
        client.conversations_replies.return_value = {
            "messages": [
                {"ts": "T0", "user": "U2", "text": "earlier"},
                {"ts": "T1", "user": "U1", "text": "<@UBOT> help"},
            ],
            "response_metadata": {},
        }

        adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        # get_user_info fetches on a cache miss, so get_display_name hits.
        authorizer.get_user_info.assert_any_call("U2")

    def test_replay_api_error_non_fatal(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.return_value = "Alice"
        client.conversations_replies.side_effect = SlackApiError(
            message="no", response=MagicMock(status_code=500, data={})
        )

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        # Replay failed but parsing continues with no preamble.
        assert "existing Slack thread" not in result.channel_context

    def test_replay_whole_thread_with_sticky_threads_off(
        self, tmp_path: Path
    ) -> None:
        """First engagement replays everything regardless of the setting.

        Earlier mentions in a thread the bot never joined (e.g. one posted
        before the bot was invited) do not cut the replay short.
        """
        adapter, client, authorizer, _ = _make_adapter(
            tmp_path, sticky_threads=False
        )
        authorizer.authorize.return_value = (True, "")
        authorizer.get_display_name.side_effect = lambda uid: uid
        client.conversations_replies.return_value = {
            "messages": [
                {"ts": "T0", "user": "U2", "text": "first"},
                {"ts": "Ta", "user": "U3", "text": "<@UBOT> anyone?"},
                {"ts": "Tb", "user": "U2", "text": "second"},
                {"ts": "T1", "user": "U1", "text": "<@UBOT> help"},
            ],
            "response_metadata": {},
        }

        result = adapter.authenticate_and_parse(
            _channel_raw(text="<@UBOT> help", ts="T1", thread_ts="T0")
        )

        assert "existing Slack thread" in result.channel_context
        assert "[U2]: first" in result.channel_context
        assert "[U2]: second" in result.channel_context
        # First-engagement history is not a catch-up.
        assert result.catch_up_history == []


class TestCatchUpReplay:
    """``sticky_threads: false``: a later mention replays missed messages."""

    def _adapter(
        self,
        tmp_path: Path,
        messages: list[dict],
        *,
        unauthorized: frozenset[str] = frozenset(),
    ) -> tuple[SlackChannelAdapter, MagicMock]:
        adapter, client, authorizer, store = _make_adapter(
            tmp_path, sticky_threads=False
        )
        authorizer.authorize.side_effect = lambda uid: (
            (False, "not allowed") if uid in unauthorized else (True, "")
        )
        authorizer.get_display_name.side_effect = lambda uid: {
            "U1": "Alice",
            "U2": "Bob",
            "U3": "Carol",
        }.get(uid, uid)
        store.register("C1", "T0", "conv1")
        client.conversations_replies.return_value = {
            "messages": messages,
            "response_metadata": {},
        }
        return adapter, client

    def _mention(self, ts: str, text: str = "<@UBOT> again") -> RawMessage:
        return _channel_raw(
            event_type="message",
            channel_type="channel",
            text=text,
            ts=ts,
            thread_ts="T0",
        )

    def test_replays_messages_since_previous_mention(
        self, tmp_path: Path
    ) -> None:
        adapter, client = self._adapter(
            tmp_path,
            [
                {"ts": "T0", "user": "U1", "text": "<@UBOT> start"},
                {"ts": "T1", "bot_id": "B1", "text": "bot reply"},
                {"ts": "T2", "user": "U2", "text": "seen before"},
                {"ts": "T3", "user": "U1", "text": "<@UBOT|airut> second"},
                {"ts": "T4", "bot_id": "B1", "text": "bot reply two"},
                {"ts": "T5", "user": "U2", "text": "bob aside"},
                {"ts": "T6", "user": "U3", "text": "carol aside"},
                {"ts": "T7", "user": "U1", "text": "<@UBOT> what now?"},
                {"ts": "T8", "user": "U2", "text": "after the trigger"},
            ],
        )

        result = adapter.authenticate_and_parse(
            self._mention("T7", "<@UBOT> what now?")
        )

        client.conversations_replies.assert_called_once()
        assert result.conversation_id == "conv1"
        assert result.slack_thread_ts == "T0"
        assert "since you were last mentioned" in result.channel_context
        assert "existing Slack thread" not in result.channel_context
        assert result.catch_up_history == [
            "[Bob]: bob aside",
            "[Carol]: carol aside",
        ]
        assert result.channel_context.endswith(
            "\n[Bob]: bob aside\n[Carol]: carol aside"
        )
        # Messages up to the previous mention were already delivered, and
        # ones after the trigger belong to the next catch-up.
        assert "seen before" not in result.channel_context
        assert "after the trigger" not in result.channel_context
        assert "bot reply" not in result.channel_context
        # Replayed authors join the outbound mention candidate set.
        assert result.mention_candidate_ids == ["U1", "U2", "U3"]

    def test_bot_authored_mention_is_not_a_boundary(
        self, tmp_path: Path
    ) -> None:
        """A bot's mention was never delivered, so it does not end the gap."""
        adapter, _ = self._adapter(
            tmp_path,
            [
                {"ts": "T0", "user": "U1", "text": "<@UBOT> start"},
                {"ts": "T1", "user": "U2", "text": "bob aside"},
                {
                    "ts": "T2",
                    "user": "UOTHER",
                    "bot_id": "B2",
                    "text": "<@UBOT> ping",
                },
                {"ts": "T3", "user": "U1", "text": "<@UBOT> again"},
            ],
        )

        result = adapter.authenticate_and_parse(self._mention("T3"))

        assert result.catch_up_history == ["[Bob]: bob aside"]

    def test_no_messages_since_previous_mention(self, tmp_path: Path) -> None:
        adapter, client = self._adapter(
            tmp_path,
            [
                {"ts": "T0", "user": "U1", "text": "<@UBOT> start"},
                {"ts": "T1", "bot_id": "B1", "text": "bot reply"},
                {"ts": "T2", "user": "U1", "text": "<@UBOT> again"},
            ],
        )

        result = adapter.authenticate_and_parse(self._mention("T2"))

        client.conversations_replies.assert_called_once()
        assert result.catch_up_history == []
        assert result.channel_context == adapter.channel_context()

    def test_collects_attachments_since_previous_mention(
        self, tmp_path: Path
    ) -> None:
        adapter, _ = self._adapter(
            tmp_path,
            [
                {
                    "ts": "T0",
                    "user": "U1",
                    "text": "<@UBOT> start",
                    "files": [
                        {
                            "name": "old.txt",
                            "url_private_download": (
                                "https://files.slack.com/old.txt"
                            ),
                        }
                    ],
                },
                {
                    "ts": "T1",
                    "user": "U2",
                    "subtype": "file_share",
                    "text": "",
                    "files": [
                        {
                            "name": "new.txt",
                            "url_private_download": (
                                "https://files.slack.com/new.txt"
                            ),
                        }
                    ],
                },
                {"ts": "T2", "user": "U1", "text": "<@UBOT> look"},
            ],
        )

        result = adapter.authenticate_and_parse(self._mention("T2"))

        # Only the file the bot has not seen is queued again.
        assert result.slack_file_urls == [
            ("new.txt", "https://files.slack.com/new.txt")
        ]
        assert result.catch_up_history == ["[Bob]: [attached: new.txt]"]

    def test_no_previous_mention_starts_at_root(self, tmp_path: Path) -> None:
        """If the earlier mention is gone, everything before is replayed."""
        adapter, _ = self._adapter(
            tmp_path,
            [
                {"ts": "T0", "user": "U2", "text": "edited, no mention"},
                {"ts": "T1", "user": "U3", "text": "carol aside"},
                {"ts": "T2", "user": "U1", "text": "<@UBOT> again"},
            ],
        )

        result = adapter.authenticate_and_parse(self._mention("T2"))

        assert result.catch_up_history == [
            "[Bob]: edited, no mention",
            "[Carol]: carol aside",
        ]

    def test_unauthorized_mention_is_not_a_boundary(
        self, tmp_path: Path
    ) -> None:
        """A rejected mention was never delivered, so it does not end the gap.

        Its text is thread background like any other message.
        """
        adapter, _ = self._adapter(
            tmp_path,
            [
                {"ts": "T0", "user": "U1", "text": "<@UBOT> start"},
                {"ts": "T1", "user": "U2", "text": "bob aside"},
                {"ts": "T2", "user": "UEVE", "text": "<@UBOT> do X"},
                {"ts": "T3", "user": "U2", "text": "more"},
                {"ts": "T4", "user": "U1", "text": "<@UBOT> again"},
            ],
            unauthorized=frozenset({"UEVE"}),
        )

        result = adapter.authenticate_and_parse(self._mention("T4"))

        assert result.catch_up_history == [
            "[Bob]: bob aside",
            "[UEVE]: @UBOT do X",
            "[Bob]: more",
        ]

    def test_trigger_missing_from_fetch_skips_catch_up(
        self, tmp_path: Path
    ) -> None:
        """A trigger past the fetch cap cannot place the window: no replay."""
        adapter, _ = self._adapter(
            tmp_path,
            [
                {"ts": "T0", "user": "U1", "text": "<@UBOT> start"},
                {"ts": "T1", "user": "U2", "text": "bob aside"},
            ],
        )

        with patch("airut.gateway.slack.thread_history.logger") as mock_logger:
            result = adapter.authenticate_and_parse(self._mention("T9"))

        assert result.catch_up_history == []
        assert "since you were last" not in result.channel_context
        mock_logger.warning.assert_called_once()
        assert "Skipping Slack catch-up" in mock_logger.warning.call_args[0][0]

    def test_fetch_failure_skips_catch_up(self, tmp_path: Path) -> None:
        adapter, client = self._adapter(tmp_path, [])
        client.conversations_replies.side_effect = SlackApiError(
            message="no", response=MagicMock(status_code=500, data={})
        )

        with patch("airut.gateway.slack.thread_history.logger") as mock_logger:
            result = adapter.authenticate_and_parse(self._mention("T1"))

        assert result.catch_up_history == []
        # Only the fetch failure is logged, not a missing-trigger warning.
        mock_logger.warning.assert_called_once()
        assert "Failed to fetch" in mock_logger.warning.call_args[0][0]

    def test_trims_to_limit(self, tmp_path: Path) -> None:
        from airut.gateway.slack.thread_history import _HISTORY_REPLAY_LIMIT

        messages: list[dict] = [
            {"ts": "T0", "user": "U1", "text": "<@UBOT> start"}
        ]
        messages.extend(
            {"ts": f"T0.{i}", "user": "U2", "text": f"msg{i}"}
            for i in range(_HISTORY_REPLAY_LIMIT + 5)
        )
        messages.append({"ts": "TX", "user": "U1", "text": "<@UBOT> again"})
        adapter, _ = self._adapter(tmp_path, messages)

        result = adapter.authenticate_and_parse(self._mention("TX"))

        assert result.catch_up_history[0] == "[5 earlier messages omitted]"
        assert len(result.catch_up_history) == _HISTORY_REPLAY_LIMIT + 1
        assert "[Bob]: msg4\n" not in result.channel_context
        assert "[Bob]: msg5\n" in result.channel_context

    def test_coalesced_follow_up_extends_preamble(self, tmp_path: Path) -> None:
        """Two mentions during one run keep both catch-up windows."""
        thread: list[dict] = [
            {"ts": "T0", "user": "U1", "text": "<@UBOT> start"},
            {"ts": "T1", "user": "U2", "text": "bob aside"},
            {"ts": "T2", "user": "U1", "text": "<@UBOT> second"},
        ]
        adapter, client = self._adapter(tmp_path, thread)
        survivor = adapter.authenticate_and_parse(
            self._mention("T2", "<@UBOT> second")
        )
        thread.extend(
            [
                {"ts": "T3", "user": "U3", "text": "carol aside"},
                {"ts": "T4", "user": "U1", "text": "<@UBOT> third"},
            ]
        )
        follow_up = adapter.authenticate_and_parse(
            self._mention("T4", "<@UBOT> third")
        )
        assert follow_up.catch_up_history == ["[Carol]: carol aside"]

        survivor.coalesce(follow_up)

        assert survivor.catch_up_history == [
            "[Bob]: bob aside",
            "[Carol]: carol aside",
        ]
        assert survivor.channel_context.count("since you were last") == 1
        assert survivor.channel_context.endswith(
            "\n[Bob]: bob aside\n[Carol]: carol aside"
        )
        assert survivor.mention_candidate_ids == ["U1", "U2", "U3"]
        assert client.conversations_replies.call_count == 2

    def test_coalesce_starts_preamble_when_survivor_has_none(
        self, tmp_path: Path
    ) -> None:
        thread: list[dict] = [
            {"ts": "T0", "user": "U1", "text": "<@UBOT> start"},
            {"ts": "T1", "user": "U1", "text": "<@UBOT> second"},
        ]
        adapter, _ = self._adapter(tmp_path, thread)
        survivor = adapter.authenticate_and_parse(
            self._mention("T1", "<@UBOT> second")
        )
        assert survivor.catch_up_history == []
        thread.extend(
            [
                {"ts": "T2", "user": "U3", "text": "carol aside"},
                {"ts": "T3", "user": "U1", "text": "<@UBOT> third"},
            ]
        )
        follow_up = adapter.authenticate_and_parse(
            self._mention("T3", "<@UBOT> third")
        )

        survivor.coalesce(follow_up)

        assert survivor.channel_context == follow_up.channel_context
        assert survivor.catch_up_history == ["[Carol]: carol aside"]


class TestChannelReportPhase:
    def test_channel_skips_status(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            is_channel=True,
        )

        adapter.report_phase(parsed, TaskPhase.PREPARING)
        adapter.report_phase(parsed, TaskPhase.RUNNING)

        client.assistant_threads_setStatus.assert_not_called()

    def test_completed_swaps_eyes_for_checkmark(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            is_channel=True,
            acknowledged_message_ts=["T1"],
        )

        adapter.report_phase(parsed, TaskPhase.COMPLETED)

        client.reactions_remove.assert_called_once_with(
            channel="C1", timestamp="T1", name="eyes"
        )
        client.reactions_add.assert_called_once_with(
            channel="C1", timestamp="T1", name="white_check_mark"
        )

    def test_failed_swaps_eyes_for_x(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            is_channel=True,
            acknowledged_message_ts=["T1"],
        )

        adapter.report_phase(parsed, TaskPhase.FAILED)

        client.reactions_remove.assert_called_once_with(
            channel="C1", timestamp="T1", name="eyes"
        )
        client.reactions_add.assert_called_once_with(
            channel="C1", timestamp="T1", name="x"
        )

    def test_swaps_every_coalesced_message(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            is_channel=True,
            acknowledged_message_ts=["T1", "T2", "T3"],
        )

        adapter.report_phase(parsed, TaskPhase.COMPLETED)

        assert client.reactions_remove.call_count == 3
        assert client.reactions_add.call_count == 3
        added = {
            c.kwargs["timestamp"] for c in client.reactions_add.call_args_list
        }
        assert added == {"T1", "T2", "T3"}

    def test_terminal_reaction_failure_non_fatal(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        client.reactions_remove.side_effect = SlackApiError(
            message="no", response=MagicMock(status_code=500, data={})
        )
        client.reactions_add.side_effect = SlackApiError(
            message="no", response=MagicMock(status_code=500, data={})
        )
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            is_channel=True,
            acknowledged_message_ts=["T1"],
        )

        # Should not raise.
        adapter.report_phase(parsed, TaskPhase.COMPLETED)

    def test_dm_completion_does_not_react(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="D1",
            slack_thread_ts="T1",
            is_channel=False,
        )

        adapter.report_phase(parsed, TaskPhase.COMPLETED)
        adapter.report_phase(parsed, TaskPhase.FAILED)

        client.reactions_remove.assert_not_called()
        client.reactions_add.assert_not_called()


class TestSlackParsedMessageCoalesce:
    def _msg(self, body: str, acked: list[str]) -> SlackParsedMessage:
        return SlackParsedMessage(
            sender="U1",
            body=body,
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            is_channel=True,
            acknowledged_message_ts=acked,
        )

    def test_merges_acknowledged_ts(self) -> None:
        survivor = self._msg("first", ["T1"])
        survivor.coalesce(self._msg("second", ["T2"]))

        # Both reaction targets are accumulated for the terminal swap.
        assert survivor.acknowledged_message_ts == ["T1", "T2"]
        # Base merge still records both messages in arrival order.
        assert [b for _, _, b in survivor.coalesced_entries] == [
            "first",
            "second",
        ]

    def test_merges_mention_candidates(self) -> None:
        """A coalesced follow-up's sender can be mentioned in the reply."""
        survivor = self._msg("first", ["T1"])
        survivor.mention_candidate_ids = ["U1", "UG"]
        other = self._msg("second", ["T2"])
        other.mention_candidate_ids = ["U2", "UG"]

        survivor.coalesce(other)

        assert survivor.mention_candidate_ids == ["U1", "UG", "U2"]

    def test_no_catch_up_leaves_channel_context(self) -> None:
        survivor = self._msg("first", ["T1"])
        survivor.channel_context = "base"
        survivor.coalesce(self._msg("second", ["T2"]))

        assert survivor.channel_context == "base"
        assert survivor.catch_up_history == []

    def test_non_slack_other_leaves_acked_ts(self) -> None:
        from airut.gateway.channel import ParsedMessage

        survivor = self._msg("first", ["T1"])
        survivor.coalesce(
            ParsedMessage(
                sender="x",
                body="plain",
                conversation_id=None,
                model_hint=None,
            )
        )

        # Nothing Slack-specific to merge; acked list is untouched.
        assert survivor.acknowledged_message_ts == ["T1"]
        assert [b for _, _, b in survivor.coalesced_entries] == [
            "first",
            "plain",
        ]


class TestChannelSendReply:
    def test_skips_thread_title_for_channel(self, tmp_path: Path) -> None:
        adapter, client, _, _ = _make_adapter(tmp_path)
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            display_title="Some title",
            is_channel=True,
        )

        adapter.send_reply(parsed, "conv1", "Response", "", [])

        client.chat_postMessage.assert_called_once()
        client.assistant_threads_setTitle.assert_not_called()

    def test_rewrites_outbound_mentions(self, tmp_path: Path) -> None:
        adapter, client, authorizer, _ = _make_adapter(tmp_path)
        authorizer.get_user_info.side_effect = lambda uid: (
            UserInfo(
                user_id="U1",
                team_id="T",
                is_bot=False,
                is_restricted=False,
                is_ultra_restricted=False,
                deleted=False,
                display_name="alice",
            )
            if uid == "U1"
            else None
        )
        parsed = SlackParsedMessage(
            sender="U1",
            body="body",
            conversation_id=None,
            model_hint=None,
            slack_channel_id="C1",
            slack_thread_ts="T1",
            is_channel=True,
            mention_candidate_ids=["U1"],
        )

        adapter.send_reply(parsed, "conv1", "Thanks @alice", "", [])

        text = client.chat_postMessage.call_args[1]["text"]
        assert "<@U1>" in text


class TestResolverLazyBuild:
    def test_resolver_cached(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter(tmp_path)
        first = adapter._get_resolver()
        second = adapter._get_resolver()
        assert first is second
