# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for EmailChannelAdapter."""

from email.parser import BytesParser
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.channel import RawMessage
from airut.gateway.config import EmailChannelConfig
from airut.gateway.email.adapter import (
    EmailChannelAdapter,
    EmailParsedMessage,
    _clean_outbox,
)
from airut.gateway.email.responder import SMTPSendError


def _make_config() -> EmailChannelConfig:
    return EmailChannelConfig(
        imap_server="imap.example.com",
        imap_port=993,
        smtp_server="smtp.example.com",
        smtp_port=587,
        username="test@example.com",
        password="pass",
        from_address="Bot <bot@example.com>",
        authorized_senders=["user@example.com"],
        trusted_authserv_id="mx.example.com",
    )


def _make_email(
    *,
    sender: str = "user@example.com",
    to: str = "bot@example.com",
    subject: str = "Hello",
    body: str = "Test body",
    message_id: str = "<msg1@example.com>",
    references: str = "",
    auth_results: str = ("mx.example.com; dmarc=pass; spf=pass"),
):
    raw = (
        f"From: {sender}\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: {message_id}\r\n"
    )
    if references:
        raw += f"References: {references}\r\n"
    if auth_results:
        raw += f"Authentication-Results: {auth_results}\r\n"
    raw += f"\r\n{body}"
    return BytesParser().parsebytes(raw.encode())


def _make_raw_message(**kwargs: object) -> RawMessage:
    """Build a RawMessage wrapping an email for authenticate_and_parse tests."""
    sender = str(kwargs.get("sender", "user@example.com"))
    subject = str(kwargs.get("subject", "Hello"))
    email_msg = _make_email(**kwargs)  # type: ignore[arg-type]
    return RawMessage(sender=sender, content=email_msg, display_title=subject)


def _make_adapter(
    config: EmailChannelConfig | None = None,
) -> tuple[
    EmailChannelAdapter,
    MagicMock,
    MagicMock,
    MagicMock,
]:
    """Create adapter with mocked auth/responder components."""
    cfg = config or _make_config()
    authenticator = MagicMock()
    authorizer = MagicMock()
    responder = MagicMock()
    adapter = EmailChannelAdapter(
        config=cfg,
        authenticator=authenticator,
        authorizer=authorizer,
        responder=responder,
        repo_id="test",
    )
    return adapter, authenticator, authorizer, responder


class TestAuthenticateAndParse:
    def test_successful_parse(self) -> None:
        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = True
        msg = _make_raw_message(body="Do something")

        result = adapter.authenticate_and_parse(msg)

        assert result is not None
        assert isinstance(result, EmailParsedMessage)
        assert result.sender == "user@example.com"
        assert result.body == "Do something"
        assert result.conversation_id is None
        assert result.original_message_id == "<msg1@example.com>"
        assert result._raw_message is msg.content

    def test_unauthenticated_raises(self) -> None:
        from airut.gateway.channel import AuthenticationError

        adapter, auth, _, _ = _make_adapter()
        auth.authenticate.return_value = None
        msg = _make_raw_message()

        with pytest.raises(AuthenticationError) as exc_info:
            adapter.authenticate_and_parse(msg)
        assert exc_info.value.sender == "user@example.com"
        assert "DMARC" in exc_info.value.reason

    def test_unauthorized_raises(self) -> None:
        from airut.gateway.channel import AuthenticationError

        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = False
        msg = _make_raw_message()

        with pytest.raises(AuthenticationError) as exc_info:
            adapter.authenticate_and_parse(msg)
        assert exc_info.value.sender == "user@example.com"
        assert "not authorized" in exc_info.value.reason

    def test_extracts_conversation_id_from_subject(self) -> None:
        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = True
        msg = _make_raw_message(subject="Re: [ID:aabb1122] Follow-up")

        result = adapter.authenticate_and_parse(msg)
        assert result is not None
        assert result.conversation_id == "aabb1122"

    def test_extracts_model_from_address(self) -> None:
        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = True
        msg = _make_raw_message(to="bot+opus@example.com")

        result = adapter.authenticate_and_parse(msg)
        assert result is not None
        assert result.model_hint == "opus"

    def test_channel_context_set(self) -> None:
        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = True
        msg = _make_raw_message()

        result = adapter.authenticate_and_parse(msg)
        assert result is not None
        assert "email interface" in result.channel_context

    def test_display_title_set_from_email(self) -> None:
        """Parsed message includes decoded email subject for task tracker."""
        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = True
        msg = _make_raw_message(subject="Fix the login bug")

        result = adapter.authenticate_and_parse(msg)
        assert result is not None
        assert result.display_title == "Fix the login bug"

    def test_display_title_fallback_no_subject(self) -> None:
        """Empty email subject falls back to '(no subject)'."""
        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = True
        msg = _make_raw_message(subject="")

        result = adapter.authenticate_and_parse(msg)
        assert result is not None
        assert result.display_title == "(no subject)"

    def test_references_parsed(self) -> None:
        adapter, auth, authz, _ = _make_adapter()
        auth.authenticate.return_value = "user@example.com"
        authz.is_authorized.return_value = True
        msg = _make_raw_message(references="<ref1@ex.com> <ref2@ex.com>")

        result = adapter.authenticate_and_parse(msg)
        assert result is not None
        assert result.original_references == [
            "<ref1@ex.com>",
            "<ref2@ex.com>",
        ]


class TestSaveAttachments:
    def test_extracts_attachments_from_raw_message(
        self, tmp_path: Path
    ) -> None:
        adapter, _, _, _ = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="see attached",
            conversation_id=None,
            model_hint=None,
        )
        parsed._raw_message = _make_email()

        with patch(
            "airut.gateway.email.adapter.extract_attachments",
            return_value=["file.txt"],
        ) as mock_extract:
            result = adapter.save_attachments(parsed, tmp_path)

        assert result == ["file.txt"]
        mock_extract.assert_called_once_with(parsed._raw_message, tmp_path)

    def test_returns_empty_when_no_raw_message(self, tmp_path: Path) -> None:
        adapter, _, _, _ = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="no attach",
            conversation_id=None,
            model_hint=None,
        )

        result = adapter.save_attachments(parsed, tmp_path)
        assert result == []


class TestSendAcknowledgment:
    def test_sends_ack_without_dashboard(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)
        responder.send_reply.assert_called_once()
        call_kw = responder.send_reply.call_args[1]
        assert "started working" in call_kw["body"]
        assert call_kw["to"] == "user@example.com"

    def test_sends_ack_with_dashboard(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_acknowledgment(
            parsed,
            "conv1",
            "sonnet",
            "https://dash.example.com",
        )
        call_kw = responder.send_reply.call_args[1]
        assert "dash.example.com/conversation/conv1" in call_kw["body"]
        assert "dash.example.com/conversation/conv1" in call_kw["html_body"]

    def test_smtp_failure_non_fatal(self) -> None:
        adapter, _, _, responder = _make_adapter()
        responder.send_reply.side_effect = SMTPSendError("fail")
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            decoded_subject="Test",
        )

        # Should not raise
        adapter.send_acknowledgment(parsed, "conv1", "sonnet", None)


class TestSendReply:
    def test_sends_reply_text(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_reply(parsed, "conv1", "Response text", "", [])
        responder.send_reply.assert_called_once()
        call_kw = responder.send_reply.call_args[1]
        assert call_kw["body"] == "Response text"

    def test_appends_usage_footer(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_reply(parsed, "conv1", "Done", "Cost: $0.01", [])
        call_kw = responder.send_reply.call_args[1]
        assert "Cost: $0.01" in call_kw["body"]

    def test_sends_attachments_from_outbox(self, tmp_path: Path) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        outbox = tmp_path / "outbox"
        outbox.mkdir()
        outfile = outbox / "report.txt"
        outfile.write_text("report content")

        with patch(
            "airut.gateway.email.adapter.collect_outbox_files",
            return_value=[("report.txt", b"report content")],
        ):
            adapter.send_reply(
                parsed,
                "conv1",
                "Done",
                "",
                [outfile],
            )

        call_kw = responder.send_reply.call_args[1]
        assert call_kw["attachments"] == [("report.txt", b"report content")]

    def test_retry_cleans_outbox_on_success(self, tmp_path: Path) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        outbox = tmp_path / "outbox"
        outbox.mkdir()
        outfile = outbox / "report.txt"
        outfile.write_text("data")

        # First call fails, second succeeds
        responder.send_reply.side_effect = [
            SMTPSendError("temp"),
            None,
        ]

        with patch(
            "airut.gateway.email.adapter.collect_outbox_files",
            return_value=[("report.txt", b"data")],
        ):
            adapter.send_reply(
                parsed,
                "conv1",
                "Done",
                "",
                [outfile],
            )

        # Outbox should be cleaned after retry success
        assert not outfile.exists()

    def test_retry_on_smtp_failure(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        # First call fails, second succeeds
        responder.send_reply.side_effect = [
            SMTPSendError("temp fail"),
            None,
        ]

        adapter.send_reply(parsed, "conv1", "Done", "", [])
        assert responder.send_reply.call_count == 2

    def test_retry_failure_raises(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        # Both calls fail
        responder.send_reply.side_effect = SMTPSendError("permanent fail")

        with pytest.raises(SMTPSendError):
            adapter.send_reply(parsed, "conv1", "Done", "", [])


class TestSendError:
    def test_sends_error_reply(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test Subject",
        )

        adapter.send_error(parsed, "conv1", "Something broke")
        responder.send_reply.assert_called_once()
        call_kw = responder.send_reply.call_args[1]
        assert call_kw["body"] == "Something broke"
        assert call_kw["subject"] == "Re: Test Subject"

    def test_smtp_failure_logged(self) -> None:
        adapter, _, _, responder = _make_adapter()
        responder.send_reply.side_effect = SMTPSendError("fail")
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            decoded_subject="Test",
        )

        # Should not raise
        adapter.send_error(parsed, "conv1", "error msg")


class TestSendRejection:
    def test_sends_rejection_without_dashboard(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_rejection(parsed, "conv1", "duplicate", None)
        responder.send_reply.assert_called_once()
        call_kw = responder.send_reply.call_args[1]
        assert "duplicate" in call_kw["body"]
        assert "conv1" in call_kw["body"]

    def test_sends_rejection_with_dashboard(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_rejection(
            parsed,
            "conv1",
            "busy",
            "https://dash.example.com",
        )
        call_kw = responder.send_reply.call_args[1]
        assert "dash.example.com/conversation/conv1" in call_kw["body"]
        assert "dash.example.com/conversation/conv1" in call_kw["html_body"]

    def test_smtp_failure_non_fatal(self) -> None:
        adapter, _, _, responder = _make_adapter()
        responder.send_reply.side_effect = SMTPSendError("fail")
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            decoded_subject="Test",
        )

        # Should not raise
        adapter.send_rejection(parsed, "conv1", "reason", None)

    def test_html_escapes_reason(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_rejection(
            parsed,
            "conv1",
            "<script>alert('xss')</script>",
            None,
        )
        call_kw = responder.send_reply.call_args[1]
        assert "<script>" not in call_kw["html_body"]
        assert "&lt;script&gt;" in call_kw["html_body"]


class TestStructuredMessageId:
    """Tests for structured Message-ID generation on all reply types."""

    def test_acknowledgment_has_structured_id(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_acknowledgment(parsed, "aabb1122", "sonnet", None)
        call_kw = responder.send_reply.call_args[1]
        mid = call_kw["message_id"]
        assert mid.startswith("<airut.aabb1122.")
        assert "@example.com>" in mid

    def test_rejection_has_structured_id(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_rejection(parsed, "aabb1122", "Busy", None)
        call_kw = responder.send_reply.call_args[1]
        mid = call_kw["message_id"]
        assert mid.startswith("<airut.aabb1122.")
        assert "@example.com>" in mid

    def test_reply_has_structured_id(self) -> None:
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        adapter.send_reply(parsed, "aabb1122", "Done", "", [])
        call_kw = responder.send_reply.call_args[1]
        mid = call_kw["message_id"]
        assert mid.startswith("<airut.aabb1122.")
        assert "@example.com>" in mid

    def test_retry_preserves_message_id(self) -> None:
        """SMTP retry uses the same Message-ID."""
        adapter, _, _, responder = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            decoded_subject="Test",
        )

        # First call fails, second succeeds
        responder.send_reply.side_effect = [
            SMTPSendError("fail"),
            None,
        ]
        adapter.send_reply(parsed, "aabb1122", "body", "", [])
        assert responder.send_reply.call_count == 2
        first_mid = responder.send_reply.call_args_list[0][1]["message_id"]
        second_mid = responder.send_reply.call_args_list[1][1]["message_id"]
        assert first_mid == second_mid
        assert first_mid.startswith("<airut.aabb1122.")


class TestBuildReplyHeaders:
    def test_adds_conversation_id_to_subject(self) -> None:
        adapter, _, _, _ = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            original_references=[],
            decoded_subject="Hello World",
        )

        subject, refs = adapter._build_reply_headers(parsed, "conv1")
        assert subject == "Re: [ID:conv1] Hello World"
        assert refs == ["<msg1@ex.com>"]

    def test_strips_re_prefix(self) -> None:
        adapter, _, _, _ = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            original_references=[],
            decoded_subject="Re: Re: Hello",
        )

        subject, _ = adapter._build_reply_headers(parsed, "conv1")
        assert subject == "Re: [ID:conv1] Hello"

    def test_preserves_existing_conv_id(self) -> None:
        adapter, _, _, _ = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg1@ex.com>",
            original_references=[],
            decoded_subject="Re: [ID:conv1] Hello",
        )

        subject, _ = adapter._build_reply_headers(parsed, "conv1")
        assert subject == "Re: [ID:conv1] Hello"

    def test_builds_references_list(self) -> None:
        adapter, _, _, _ = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id="<msg2@ex.com>",
            original_references=["<msg1@ex.com>"],
            decoded_subject="Test",
        )

        _, refs = adapter._build_reply_headers(parsed, "conv1")
        assert refs == ["<msg1@ex.com>", "<msg2@ex.com>"]

    def test_empty_references_and_message_id(self) -> None:
        adapter, _, _, _ = _make_adapter()
        parsed = EmailParsedMessage(
            sender="user@example.com",
            body="body",
            conversation_id=None,
            model_hint=None,
            original_message_id=None,
            original_references=[],
            decoded_subject="Test",
        )

        _, refs = adapter._build_reply_headers(parsed, "conv1")
        assert refs == []


class TestCleanOutbox:
    def test_removes_files(self, tmp_path: Path) -> None:
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "file1.txt").write_text("a")
        (outbox / "file2.txt").write_text("b")

        _clean_outbox(
            [("file1.txt", b"a"), ("file2.txt", b"b")],
            outbox,
        )

        remaining = list(outbox.iterdir())
        assert len(remaining) == 0

    def test_noop_for_empty_attachments(self, tmp_path: Path) -> None:
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "file.txt").write_text("keep me")

        _clean_outbox([], outbox)

        # File should still exist
        assert (outbox / "file.txt").exists()

    def test_noop_for_missing_outbox(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "nonexistent"

        # Should not raise
        _clean_outbox([("file.txt", b"data")], nonexistent)

    def test_handles_unlink_error(self, tmp_path: Path) -> None:
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        f = outbox / "file.txt"
        f.write_text("data")

        with patch.object(Path, "unlink", side_effect=OSError("perm denied")):
            # Should not raise
            _clean_outbox([("file.txt", b"data")], outbox)


class TestResponderProperty:
    def test_exposes_responder(self) -> None:
        adapter, _, _, responder = _make_adapter()
        assert adapter.responder is responder


class TestListenerProperty:
    def test_exposes_listener(self) -> None:
        listener = MagicMock()
        adapter = EmailChannelAdapter(
            config=_make_config(),
            authenticator=MagicMock(),
            authorizer=MagicMock(),
            responder=MagicMock(),
            listener=listener,
            repo_id="test",
        )
        assert adapter.listener is listener

    def test_raises_when_no_listener(self) -> None:
        adapter, _, _, _ = _make_adapter()
        with pytest.raises(RuntimeError, match="created without a listener"):
            _ = adapter.listener


class TestCreatePlanStreamer:
    def test_returns_none(self) -> None:
        """Email does not support plan streaming."""
        from airut.gateway.channel import ParsedMessage

        adapter, _, _, _ = _make_adapter()
        parsed = ParsedMessage(
            sender="user@example.com",
            body="text",
            conversation_id=None,
            model_hint=None,
        )
        assert adapter.create_plan_streamer(parsed) is None


class TestCleanupConversations:
    def test_noop(self) -> None:
        """Email adapter has no per-conversation state to clean up."""
        adapter, _, _, _ = _make_adapter()
        # Should not raise or have any side effects
        adapter.cleanup_conversations({"conv1", "conv2"})

    def test_noop_empty_set(self) -> None:
        adapter, _, _, _ = _make_adapter()
        adapter.cleanup_conversations(set())


class TestFromConfig:
    def test_creates_all_components(self) -> None:
        with (
            patch(
                "airut.gateway.email.adapter.SenderAuthenticator"
            ) as mock_auth,
            patch("airut.gateway.email.adapter.SenderAuthorizer") as mock_authz,
            patch("airut.gateway.email.adapter.EmailResponder") as mock_resp,
            patch(
                "airut.gateway.email.adapter.EmailChannelListener"
            ) as mock_listener,
        ):
            config = _make_config()
            adapter = EmailChannelAdapter.from_config(config, repo_id="test")

        mock_auth.assert_called_once()
        mock_authz.assert_called_once()
        mock_resp.assert_called_once_with(config)
        mock_listener.assert_called_once_with(config, repo_id="test")
        assert adapter.listener is mock_listener.return_value
        assert adapter.responder is mock_resp.return_value
