# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared fixtures for email channel tests.

Re-exports service test helpers needed by test_replies.py, and helpers
for inspecting outgoing emails.
"""

from collections.abc import Iterator
from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from tests.gateway.service.conftest import (
    make_message,
    make_service,
    update_global,
)


__all__ = [
    "attachment_names",
    "make_message",
    "make_service",
    "plain_text",
    "update_global",
]


def plain_text(msg: Message) -> str:
    """Return the decoded plain-text body of an outgoing email."""
    for part in msg.walk():
        if part.get_content_type() == "text/plain" and not part.get_filename():
            payload = part.get_payload(decode=True)
            assert isinstance(payload, bytes)
            return payload.decode()
    raise AssertionError("no text/plain body")


def attachment_names(msg: Message) -> list[str]:
    """Return the file names attached to an outgoing email."""
    return [
        part.get_filename() or ""
        for part in msg.walk()
        if part.get_content_disposition() == "attachment"
    ]


@pytest.fixture
def smtp_connect() -> Iterator[MagicMock]:
    """Patch ``smtplib.SMTP``, which the responder connects with."""
    with patch("smtplib.SMTP") as smtp_class:
        yield smtp_class


@pytest.fixture
def smtp_server(smtp_connect: MagicMock) -> MagicMock:
    """Return the SMTP session every ``smtp_connect`` call opens.

    The session advertises no ESMTP extensions; tests set ``SIZE`` in
    ``esmtp_features`` as needed.
    """
    server = MagicMock()
    server.esmtp_features = {}
    smtp_connect.return_value.__enter__.return_value = server
    return server
