# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Whether an incoming email was addressed to the channel.

A message is acted on only if its ``To`` or ``Cc`` names the channel's
own address, so that a message its sender addressed to someone else is
not taken as a request (``email.auth.require_channel_recipient``).
The fields are read from those the authenticator verified (see
``SenderAuthenticator.verified_headers``): with Airut's own DKIM
verification, they are the ones the sender signed.

Addresses are compared case-insensitively, ignoring a ``+tag`` in the
local part, so ``bot+opus@example.com`` names ``bot@example.com``.
Only ASCII addresses are compared: ``str.lower`` folds some non-ASCII
characters onto ASCII ones.
"""

from email.message import Message
from email.utils import getaddresses, parseaddr

from airut.gateway.config import EmailAccountConfig


def _mailbox(address: str) -> str:
    """Return *address* lowercase, without a ``+tag`` in its local part."""
    local, _, domain = address.lower().rpartition("@")
    return f"{local.partition('+')[0]}@{domain}"


def _comparable(address: str) -> bool:
    """Whether *address* can be compared with a channel address."""
    return "@" in address and address.isascii()


def channel_addresses(account: EmailAccountConfig) -> frozenset[str]:
    """Return the addresses that name the channel of *account*.

    Its ``from_address``, and its ``username`` when that is an address
    (as it is for most mailboxes).
    """
    candidates = (parseaddr(account.from_address)[1], account.username)
    return frozenset(_mailbox(a) for a in candidates if _comparable(a))


def addressed_to(headers: Message, addresses: frozenset[str]) -> bool:
    """Whether the ``To`` or ``Cc`` of *headers* names one of *addresses*.

    Each field is parsed on its own, so that one the standard library
    cannot read does not hide an address in another.

    Args:
        headers: The header fields to read.
        addresses: The channel's addresses, from ``channel_addresses``.
    """
    return any(
        _comparable(address) and _mailbox(address) in addresses
        for name in ("To", "Cc")
        for value in headers.get_all(name, [])
        # str(): an undecodable 8-bit header is a Header object.
        for _, address in getaddresses([str(value)])
    )
