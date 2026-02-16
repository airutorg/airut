# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for email_replies module."""

from pathlib import Path

import pytest

from airut.gateway.service.email_replies import (
    send_acknowledgment,
    send_error_reply,
    send_rejection_reply,
    send_reply,
)

from .conftest import make_message, make_service, update_global


class TestSendErrorReply:
    def test_sends_error(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        msg = make_message(subject="Help", message_id="<m1@ex.com>")
        send_error_reply(handler, msg, "Something went wrong")
        handler.responder.send_reply.assert_called_once()
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["subject"] == "Re: Help"
        assert call_kwargs["body"] == "Something went wrong"
        assert call_kwargs["references"] == ["<m1@ex.com>"]

    def test_smtp_error_logged(self, email_config, tmp_path: Path) -> None:
        from airut.gateway import SMTPSendError

        svc, handler = make_service(email_config, tmp_path)
        handler.responder.send_reply.side_effect = SMTPSendError("fail")
        msg = make_message()
        # Should not raise
        send_error_reply(handler, msg, "err")

    def test_no_message_id(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        msg = make_message()
        # Remove Message-ID
        del msg["Message-ID"]
        send_error_reply(handler, msg, "err")
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["references"] == []


class TestSendAcknowledgment:
    def test_new_conversation_with_dashboard(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url="https://dash.example.com")
        msg = make_message(subject="Do stuff")
        send_acknowledgment(
            handler, msg, "conv123", "sonnet", svc.global_config
        )
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert "[ID:conv123]" in call_kwargs["subject"]
        assert "started working" in call_kwargs["body"]
        assert (
            "https://dash.example.com/conversation/conv123"
            in call_kwargs["body"]
        )
        assert "html_body" in call_kwargs
        assert (
            "https://dash.example.com/conversation/conv123"
            in call_kwargs["html_body"]
        )

    def test_no_dashboard_url(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message(subject="Do stuff")
        send_acknowledgment(handler, msg, "conv123", "opus", svc.global_config)
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert "started working" in call_kwargs["body"]
        assert "reply shortly" in call_kwargs["body"]

    def test_existing_conv_id_in_subject(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message(subject="[ID:conv123] Do stuff")
        send_acknowledgment(
            handler, msg, "conv123", "sonnet", svc.global_config
        )
        call_kwargs = handler.responder.send_reply.call_args[1]
        # Should not duplicate [ID:conv123]
        assert call_kwargs["subject"].count("[ID:conv123]") == 1

    def test_strips_re_prefix(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message(subject="Re: Re: Hello")
        send_acknowledgment(handler, msg, "conv1", "sonnet", svc.global_config)
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["subject"] == "Re: [ID:conv1] Hello"

    def test_smtp_error_non_fatal(self, email_config, tmp_path: Path) -> None:
        from airut.gateway import SMTPSendError

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        handler.responder.send_reply.side_effect = SMTPSendError("fail")
        msg = make_message()
        # Should not raise
        send_acknowledgment(handler, msg, "c1", "sonnet", svc.global_config)

    def test_references_threading(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message(
            message_id="<m2@ex.com>",
            references="<m1@ex.com>",
        )
        send_acknowledgment(handler, msg, "c1", "sonnet", svc.global_config)
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["references"] == ["<m1@ex.com>", "<m2@ex.com>"]

    def test_no_references_no_message_id(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message()
        del msg["Message-ID"]
        del msg["References"]
        send_acknowledgment(handler, msg, "c1", "sonnet", svc.global_config)
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["references"] == []


class TestSendRejectionReply:
    def test_with_dashboard(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url="https://dash.example.com")
        msg = make_message(subject="[ID:conv1] Help")
        send_rejection_reply(
            handler, msg, "conv1", "Still processing", svc.global_config
        )
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert "Still processing" in call_kwargs["body"]
        assert (
            "https://dash.example.com/conversation/conv1" in call_kwargs["body"]
        )
        assert call_kwargs["subject"].count("[ID:conv1]") == 1

    def test_without_dashboard(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message(subject="Test")
        send_rejection_reply(handler, msg, "conv1", "Busy", svc.global_config)
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert "Busy" in call_kwargs["body"]
        assert "conv1" in call_kwargs["body"]

    def test_html_escapes_reason(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message()
        send_rejection_reply(
            handler,
            msg,
            "c1",
            "<script>alert('xss')</script>",
            svc.global_config,
        )
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert "<script>" not in call_kwargs["html_body"]
        assert "&lt;script&gt;" in call_kwargs["html_body"]

    def test_strips_re_prefix(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message(subject="Re: Re: Hello")
        send_rejection_reply(
            handler, msg, "aabb1122", "Busy", svc.global_config
        )
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["subject"] == "Re: [ID:aabb1122] Hello"

    def test_smtp_error_non_fatal(self, email_config, tmp_path: Path) -> None:
        from airut.gateway import SMTPSendError

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        handler.responder.send_reply.side_effect = SMTPSendError("fail")
        msg = make_message()
        send_rejection_reply(handler, msg, "c1", "reason", svc.global_config)


class TestSendReply:
    def test_basic_reply(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path
        msg = make_message(subject="Do stuff")
        send_reply(handler, msg, "conv1", "Done!")
        handler.responder.send_reply.assert_called_once()
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert "[ID:conv1]" in call_kwargs["subject"]
        assert call_kwargs["body"] == "Done!"

    def test_outbox_files_attached(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        conversation_dir = tmp_path / "conversations" / "conv1"
        conversation_dir.mkdir(parents=True)
        outbox = conversation_dir / "outbox"
        outbox.mkdir()
        (outbox / "report.pdf").write_bytes(b"pdf content")
        handler.conversation_manager.get_conversation_dir.return_value = (
            conversation_dir
        )

        msg = make_message()
        send_reply(handler, msg, "conv1", "Here's the report")
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["attachments"] is not None
        # Outbox should be cleaned up after send
        assert not (outbox / "report.pdf").exists()

    def test_outbox_cleanup_on_retry(
        self, email_config, tmp_path: Path
    ) -> None:
        from airut.gateway import SMTPSendError

        svc, handler = make_service(email_config, tmp_path)
        conversation_dir = tmp_path / "conversations" / "conv1"
        conversation_dir.mkdir(parents=True)
        outbox = conversation_dir / "outbox"
        outbox.mkdir()
        (outbox / "file.txt").write_bytes(b"data")
        handler.conversation_manager.get_conversation_dir.return_value = (
            conversation_dir
        )

        # First call fails, second succeeds
        handler.responder.send_reply.side_effect = [
            SMTPSendError("fail"),
            None,
        ]
        msg = make_message()
        send_reply(handler, msg, "conv1", "body")
        assert handler.responder.send_reply.call_count == 2
        # Outbox cleaned up after successful retry
        assert not (outbox / "file.txt").exists()

    def test_retry_failure_raises(self, email_config, tmp_path: Path) -> None:
        from airut.gateway import SMTPSendError

        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path
        handler.responder.send_reply.side_effect = SMTPSendError("fail")
        msg = make_message()
        with pytest.raises(SMTPSendError):
            send_reply(handler, msg, "conv1", "body")

    def test_existing_conv_id_not_duplicated(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path
        msg = make_message(subject="[ID:aabb1122] Test")
        send_reply(handler, msg, "conv1", "body")
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["subject"].count("[ID:conv1]") == 1

    def test_strips_re_prefix(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path
        msg = make_message(subject="Re: Re: Hello")
        send_reply(handler, msg, "conv1", "body")
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["subject"] == "Re: [ID:conv1] Hello"

    def test_references_with_existing(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path
        msg = make_message(
            message_id="<m2@ex.com>",
            references="<m1@ex.com>",
        )
        send_reply(handler, msg, "conv1", "body")
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["references"] == ["<m1@ex.com>", "<m2@ex.com>"]

    def test_no_outbox_dir(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path
        msg = make_message()
        send_reply(handler, msg, "conv1", "body")
        call_kwargs = handler.responder.send_reply.call_args[1]
        assert call_kwargs["attachments"] is None

    def test_structured_message_id(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path
        msg = make_message()
        send_reply(handler, msg, "aabb1122", "body")
        call_kwargs = handler.responder.send_reply.call_args[1]
        mid = call_kwargs["message_id"]
        assert mid.startswith("<airut.aabb1122.")
        assert mid.endswith("@example.com>")


class TestStructuredMessageId:
    """Tests for structured Message-ID generation on all reply types."""

    def test_acknowledgment_has_structured_id(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message()
        send_acknowledgment(
            handler, msg, "aabb1122", "sonnet", svc.global_config
        )
        call_kwargs = handler.responder.send_reply.call_args[1]
        mid = call_kwargs["message_id"]
        assert mid.startswith("<airut.aabb1122.")
        assert "@example.com>" in mid

    def test_rejection_has_structured_id(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        msg = make_message()
        send_rejection_reply(
            handler, msg, "aabb1122", "Busy", svc.global_config
        )
        call_kwargs = handler.responder.send_reply.call_args[1]
        mid = call_kwargs["message_id"]
        assert mid.startswith("<airut.aabb1122.")
        assert "@example.com>" in mid

    def test_retry_preserves_message_id(
        self, email_config, tmp_path: Path
    ) -> None:
        """Test that SMTP retry uses the same Message-ID."""
        from airut.gateway import SMTPSendError

        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.get_workspace_path.return_value = tmp_path

        # First call fails, second succeeds
        handler.responder.send_reply.side_effect = [
            SMTPSendError("fail"),
            None,
        ]
        msg = make_message()
        send_reply(handler, msg, "aabb1122", "body")
        assert handler.responder.send_reply.call_count == 2
        # Both calls should use the same message_id
        first_mid = handler.responder.send_reply.call_args_list[0][1][
            "message_id"
        ]
        second_mid = handler.responder.send_reply.call_args_list[1][1][
            "message_id"
        ]
        assert first_mid == second_mid
        assert first_mid.startswith("<airut.aabb1122.")
