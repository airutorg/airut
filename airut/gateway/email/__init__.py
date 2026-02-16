# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email channel implementation for the gateway.

Provides email-specific protocol handling:
- EmailChannelAdapter: ChannelAdapter implementation for email
- EmailListener: IMAP polling/IDLE listener
- EmailResponder: SMTP reply construction
- SenderAuthenticator: DMARC verification
- SenderAuthorizer: Sender allowlist checking
- Email MIME parsing and attachment extraction
"""

from airut.gateway.email.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)
from airut.gateway.email.parsing import (
    ParseError,
    collect_outbox_files,
    decode_subject,
    extract_attachments,
    extract_body,
    extract_conversation_id,
    extract_conversation_id_from_headers,
    extract_model_from_address,
)
from airut.gateway.email.responder import (
    EmailResponder,
    SMTPSendError,
    generate_message_id,
)
from airut.gateway.email.security import (
    SecurityValidationError,
    SenderAuthenticator,
    SenderAuthorizer,
)


__all__ = [
    # listener
    "EmailListener",
    "IMAPConnectionError",
    "IMAPIdleError",
    # parsing
    "ParseError",
    "collect_outbox_files",
    "decode_subject",
    "extract_attachments",
    "extract_body",
    "extract_conversation_id",
    "extract_conversation_id_from_headers",
    "extract_model_from_address",
    # responder
    "EmailResponder",
    "SMTPSendError",
    "generate_message_id",
    # security
    "SecurityValidationError",
    "SenderAuthenticator",
    "SenderAuthorizer",
]
