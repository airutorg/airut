# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the channel recipient check."""

from email.message import Message

import pytest

from airut.gateway.config import EmailAccountConfig
from airut.gateway.email.incoming import IncomingEmail
from airut.gateway.email.recipient import addressed_to, channel_addresses


def _headers(**fields: str) -> Message:
    headers = Message()
    for name, value in fields.items():
        headers[name] = value
    return headers


CHANNEL = frozenset({"bot@example.com"})


class TestChannelAddresses:
    def test_from_address_and_username(self):
        account = EmailAccountConfig(
            username="Mailbox@Example.com",
            from_address="Bot <Bot@Example.com>",
        )
        assert channel_addresses(account) == {
            "bot@example.com",
            "mailbox@example.com",
        }

    def test_username_that_is_not_an_address_left_out(self):
        account = EmailAccountConfig(
            username="bot-login", from_address="bot@example.com"
        )
        assert channel_addresses(account) == {"bot@example.com"}

    def test_non_ascii_address_left_out(self):
        account = EmailAccountConfig(
            username="\u212abot@example.com",
            from_address="Bot <\u212abot@example.com>",
        )
        assert channel_addresses(account) == frozenset()

    def test_plus_tag_stripped(self):
        account = EmailAccountConfig(
            username="bot", from_address="bot+replies@example.com"
        )
        assert channel_addresses(account) == {"bot@example.com"}


class TestAddressedTo:
    @pytest.mark.parametrize(
        "fields",
        [
            {"To": "bot@example.com"},
            {"To": "Bot <BOT@example.COM>"},
            {"To": "other@example.org, Bot <bot@example.com>"},
            {"To": "other@example.org", "Cc": "bot@example.com"},
            {"Cc": "bot@example.com"},
            {"To": "bot+opus@example.com"},
            {"To": "team: bot@example.com, other@example.org;"},
            {"To": "bot@example.com", "Cc": "Bot [AI] <x@example.org>"},
            {"To": "Bot [AI] <x@example.org>", "Cc": "bot@example.com"},
        ],
    )
    def test_addressed(self, fields: dict[str, str]):
        assert addressed_to(_headers(**fields), CHANNEL) is True

    @pytest.mark.parametrize(
        "fields",
        [
            {},
            {"To": "other@example.org"},
            {"To": "other@example.org", "Cc": "third@example.org"},
            {"To": '"bot@example.com" <other@example.org>'},
            {"To": "other@example.org (bot@example.com)"},
            {"To": "bot@example.com.example.org"},
            {"To": "undisclosed-recipients:;"},
            {"Bcc": "bot@example.com"},
        ],
    )
    def test_not_addressed(self, fields: dict[str, str]):
        assert addressed_to(_headers(**fields), CHANNEL) is False

    def test_non_ascii_address_not_compared(self):
        """``str.lower`` folds the Kelvin sign onto ``k``."""
        headers = _headers(To="\u212abot@example.com")
        assert addressed_to(headers, frozenset({"kbot@example.com"})) is False

    def test_undecodable_display_name(self):
        raw = b"To: \xff <bot@example.com>\r\n\r\n"
        headers = IncomingEmail.parse(raw).headers()
        assert addressed_to(headers, CHANNEL) is True

    def test_no_channel_addresses(self):
        assert addressed_to(_headers(To="bot@example.com"), frozenset()) is (
            False
        )
