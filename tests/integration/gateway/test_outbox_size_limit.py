# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for outbox files too large for email.

Files that would push a reply over the size limit — configured,
advertised by the SMTP server, or found when the server refuses the
message — are left out and named in the reply, and the outbox is still
cleared so later replies are not refused too.
"""

import threading
from dataclasses import replace

import pytest

from airut.gateway.config import EmailChannelConfig

from .conftest import get_message_attachments, get_message_text
from .environment import IntegrationEnvironment


def _with_max_message_size(
    env: IntegrationEnvironment, max_message_size_mb: int
) -> None:
    """Set the email channel's ``max_message_size_mb`` in *env*."""
    repo = env.config.repos["test"]
    channel = repo.channels["email"]
    assert isinstance(channel, EmailChannelConfig)
    smtp = replace(channel.smtp, max_message_size_mb=max_message_size_mb)
    channels = {"email": replace(channel, smtp=smtp)}
    env.config = replace(
        env.config, repos={"test": replace(repo, channels=channels)}
    )


#: Mock code writing a small and a 1MB file to the outbox.
_SUMMARY_AND_DUMP = """
(outbox / 'summary.txt').write_text('Small summary')
(outbox / 'dump.bin').write_bytes(bytes(range(256)) * 4096)

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created summary and dump"),
    generate_result_event(session_id, "Files ready"),
]
"""


def _assert_follow_up_clean(
    env: IntegrationEnvironment, create_email, conv_id: str
) -> None:
    """Check the next reply carries neither the files nor the note.

    The outbox must have been cleared: had the oversized file stayed,
    every later reply would be refused as well.
    """
    follow_up = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Follow-up answered"),
    generate_result_event(session_id, "Done"),
]
"""
    env.email_server.inject_message(
        create_email(subject=f"Re: [ID:{conv_id}] Follow-up", body=follow_up)
    )
    reply = env.email_server.wait_for_sent(
        lambda m: "follow-up answered" in get_message_text(m).lower(),
        timeout=30.0,
    )
    assert reply is not None
    assert get_message_attachments(reply) == []
    assert "Could not attach" not in get_message_text(reply)


class TestOutboxSizeLimit:
    """Test outbox files too large for email."""

    def test_oversized_file_left_out_and_named(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """A file over the size limit is named instead of failing the reply.

        The text and the files that fit still arrive, and the outbox is
        cleared, so the next reply in the conversation is not stuck
        trying to send the oversized file again.
        """
        _with_max_message_size(integration_env, 1)
        mock_code = """
(outbox / 'summary.txt').write_text('Small summary')
(outbox / 'dump.bin').write_bytes(bytes(range(256)) * 8192)

events = [
    generate_system_event(session_id),
    generate_assistant_event("Created summary and dump"),
    generate_result_event(session_id, "Files ready"),
]
"""
        integration_env.email_server.inject_message(
            create_email(subject="Generate a dump", body=mock_code)
        )

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])

            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    m != ack
                    and "created summary and dump"
                    in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response is not None

            assert get_message_attachments(response) == [
                ("summary.txt", b"Small summary")
            ]
            assert (
                "Could not attach 1 file(s) without exceeding the 1.0MB "
                "email size limit: dump.bin (2.0MB)"
            ) in get_message_text(response)

            _assert_follow_up_clean(integration_env, create_email, conv_id)

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_server_size_limit_honoured(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
    ) -> None:
        """The limit the SMTP server advertises is honoured as well.

        Without this, the server refuses the whole reply and the user
        hears nothing at all.
        """
        integration_env.email_server.set_smtp_size_limit(512 * 1024)
        integration_env.email_server.inject_message(
            create_email(subject="Generate a dump", body=_SUMMARY_AND_DUMP)
        )

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "created summary and dump" in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response is not None

            assert get_message_attachments(response) == [
                ("summary.txt", b"Small summary")
            ]
            assert (
                "Could not attach 1 file(s) without exceeding the 512KB "
                "email size limit: dump.bin (1.0MB)"
            ) in get_message_text(response)

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    @pytest.mark.parametrize("hang_up", [False, True])
    def test_server_rejection_resends_without_attachments(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
        hang_up: bool,
    ) -> None:
        """A server refusing more than it advertised still gets the text.

        The reply goes out again without attachments, naming them, on a
        new connection in case the server hung up after refusing.
        """
        integration_env.email_server.reject_messages_over(
            256 * 1024, hang_up=hang_up
        )
        integration_env.email_server.inject_message(
            create_email(subject="Generate a dump", body=_SUMMARY_AND_DUMP)
        )

        service = integration_env.create_service()
        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])

            response = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "created summary and dump" in get_message_text(m).lower()
                ),
                timeout=30.0,
            )
            assert response is not None

            assert get_message_attachments(response) == []
            assert (
                "Could not attach 2 file(s) because the mail server rejected "
                "the email as too large: dump.bin (1.0MB), summary.txt (13B)"
            ) in get_message_text(response)

            _assert_follow_up_clean(integration_env, create_email, conv_id)

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
