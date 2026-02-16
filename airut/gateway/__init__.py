# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Email gateway subsystem.

Provides headless email integration with Claude Code via:
- Git-based conversation state management (ConversationManager)
- Email I/O with IMAP/SMTP (EmailListener, EmailResponder)
- Authentication and authorization (SenderAuthenticator, SenderAuthorizer)
- Message parsing utilities
- Configuration loading
"""

from airut.gateway.config import (
    ConfigError,
    GlobalConfig,
    RepoConfig,
    RepoServerConfig,
    ServerConfig,
)
from airut.gateway.conversation import (
    ConversationError,
    ConversationManager,
    GitCloneError,
)
from airut.gateway.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)
from airut.gateway.parsing import (
    ParseError,
    decode_subject,
    extract_attachments,
    extract_body,
    extract_conversation_id,
    extract_conversation_id_from_headers,
)
from airut.gateway.responder import (
    EmailResponder,
    SMTPSendError,
    generate_message_id,
)
from airut.gateway.security import (
    SecurityValidationError,
    SenderAuthenticator,
    SenderAuthorizer,
)


__all__ = [
    # config
    "ConfigError",
    "GlobalConfig",
    "RepoConfig",
    "RepoServerConfig",
    "ServerConfig",
    # conversation
    "ConversationError",
    "ConversationManager",
    "GitCloneError",
    # listener
    "EmailListener",
    "IMAPConnectionError",
    "IMAPIdleError",
    # parsing
    "ParseError",
    "decode_subject",
    "extract_attachments",
    "extract_body",
    "extract_conversation_id",
    "extract_conversation_id_from_headers",
    # responder
    "EmailResponder",
    "SMTPSendError",
    "generate_message_id",
    # security
    "SecurityValidationError",
    "SenderAuthenticator",
    "SenderAuthorizer",
]
