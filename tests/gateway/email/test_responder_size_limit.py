# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for keeping outgoing email under the message size limit."""

import smtplib
from dataclasses import replace
from email.message import Message
from unittest.mock import MagicMock

import pytest

from airut.gateway.email.responder import EmailResponder, SMTPSendError
from tests.gateway.email.conftest import attachment_names, plain_text


def _responder(email_config, max_message_size_mb: int = 25) -> EmailResponder:
    channel = email_config.channels["email"]
    smtp = replace(channel.smtp, max_message_size_mb=max_message_size_mb)
    return EmailResponder(replace(channel, smtp=smtp))


def _sent(server: MagicMock, index: int = 0) -> Message:
    return server.send_message.call_args_list[index][0][0]


def test_send_reply_footer_follows_body(email_config, smtp_server):
    left_out = _responder(email_config).send_reply(
        to="user@example.com",
        subject="Test",
        body="Done.",
        footer="Cost: $1",
    )
    assert plain_text(_sent(smtp_server)) == "Done.\n\n*Cost: $1*"
    assert left_out == {}


def test_send_reply_leaves_out_files_over_configured_limit(
    email_config, smtp_server
):
    """The largest file goes; the rest and the text still arrive."""
    left_out = _responder(email_config, max_message_size_mb=1).send_reply(
        to="user@example.com",
        subject="Test",
        body="Here are the files.",
        attachments=[
            ("notes.txt", b"short notes"),
            ("dump.bin", b"\x00" * (2 * 1024 * 1024)),
        ],
        footer="Cost: $1",
    )

    smtp_server.send_message.assert_called_once()
    msg = _sent(smtp_server)
    assert attachment_names(msg) == ["notes.txt"]
    assert plain_text(msg) == (
        "Here are the files.\n\n"
        "Could not attach 1 file(s) without exceeding the 1.0MB email "
        "size limit: dump.bin (2.0MB)\n\n"
        "*Cost: $1*"
    )
    assert left_out == {"dump.bin": "did not fit in the 1.0MB email size limit"}


def test_send_reply_honours_lower_server_size(email_config, smtp_server):
    """A SIZE below the configured limit is the one that counts."""
    smtp_server.esmtp_features = {"size": "50000"}

    _responder(email_config).send_reply(
        to="user@example.com",
        subject="Test",
        body="Files.",
        attachments=[
            ("small.txt", b"a" * 1000),
            ("large.bin", b"b" * 60_000),
        ],
    )

    msg = _sent(smtp_server)
    assert attachment_names(msg) == ["small.txt"]
    assert "49KB email size limit: large.bin (59KB)" in plain_text(msg)


def test_send_reply_keeps_configured_limit_below_server_size(
    email_config, smtp_server
):
    smtp_server.esmtp_features = {"size": str(100 * 1024 * 1024)}

    _responder(email_config, max_message_size_mb=1).send_reply(
        to="user@example.com",
        subject="Test",
        body="Files.",
        attachments=[("large.bin", b"b" * (1024 * 1024))],
    )

    assert attachment_names(_sent(smtp_server)) == []


@pytest.mark.parametrize("advertised", ["0", "", "unlimited"])
def test_send_reply_ignores_unusable_server_size(
    email_config, smtp_server, advertised
):
    """SIZE 0 means no limit (RFC 1870); junk is ignored."""
    smtp_server.esmtp_features = {"size": advertised}

    _responder(email_config).send_reply(
        to="user@example.com",
        subject="Test",
        body="Files.",
        attachments=[("data.bin", b"d" * 100_000)],
    )

    assert attachment_names(_sent(smtp_server)) == ["data.bin"]


def test_send_reply_resends_without_attachments_on_size_rejection(
    email_config, smtp_connect, smtp_server
):
    """A server whose limit is below what it advertised still gets the text.

    Resending the same message would fail the same way, and the core
    keeps the outbox after a failed send, so every later reply in the
    conversation would fail too.
    """
    smtp_server.send_message.side_effect = [
        smtplib.SMTPSenderRefused(
            552, b"5.3.4 Message size exceeds fixed limit", "bot@x"
        ),
        None,
    ]

    left_out = _responder(email_config).send_reply(
        to="user@example.com",
        subject="Test",
        body="Files.",
        attachments=[("a.txt", b"aaa"), ("b.txt", b"bbbb")],
        footer="Cost: $1",
    )

    assert smtp_server.send_message.call_count == 2
    # Some servers hang up after refusing, so the resend reconnects.
    assert smtp_connect.call_count == 2
    assert attachment_names(_sent(smtp_server, 0)) == ["a.txt", "b.txt"]
    fallback = _sent(smtp_server, 1)
    assert attachment_names(fallback) == []
    assert plain_text(fallback) == (
        "Files.\n\n"
        "Could not attach 2 file(s) because the mail server rejected the "
        "email as too large: a.txt (3B), b.txt (4B)\n\n"
        "*Cost: $1*"
    )
    reason = "the mail server rejected the email as too large"
    assert left_out == {"a.txt": reason, "b.txt": reason}


def test_send_reply_size_rejection_without_attachments_fails(
    email_config, smtp_server
):
    smtp_server.send_message.side_effect = smtplib.SMTPDataError(
        552, b"Too much mail data"
    )

    with pytest.raises(SMTPSendError):
        _responder(email_config).send_reply(
            to="user@example.com", subject="Test", body="Text only."
        )
    smtp_server.send_message.assert_called_once()


def test_send_reply_size_rejection_after_all_left_out_fails(
    email_config, smtp_server
):
    """With every file already left out there is nothing more to drop."""
    smtp_server.esmtp_features = {"size": "10000"}
    smtp_server.send_message.side_effect = smtplib.SMTPDataError(
        552, b"Too much mail data"
    )

    with pytest.raises(SMTPSendError):
        _responder(email_config).send_reply(
            to="user@example.com",
            subject="Test",
            body="Files.",
            attachments=[("big.bin", b"b" * 50_000)],
        )
    smtp_server.send_message.assert_called_once()


def test_send_reply_other_rejection_keeps_attachments(
    email_config, smtp_server
):
    """Only a size rejection drops attachments; others fail the send."""
    smtp_server.send_message.side_effect = smtplib.SMTPDataError(
        550, b"5.7.1 Rejected"
    )

    with pytest.raises(SMTPSendError):
        _responder(email_config).send_reply(
            to="user@example.com",
            subject="Test",
            body="Files.",
            attachments=[("a.txt", b"aaa")],
        )
    smtp_server.send_message.assert_called_once()


def test_send_reply_fallback_failure_raises(email_config, smtp_server):
    smtp_server.send_message.side_effect = [
        smtplib.SMTPSenderRefused(552, b"Message too big", "bot@x"),
        smtplib.SMTPServerDisconnected("gone"),
    ]

    with pytest.raises(SMTPSendError):
        _responder(email_config).send_reply(
            to="user@example.com",
            subject="Test",
            body="Files.",
            attachments=[("a.txt", b"aaa")],
        )
    assert smtp_server.send_message.call_count == 2
