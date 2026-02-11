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

from lib.gateway.config import (
    ConfigError,
    GlobalConfig,
    RepoConfig,
    RepoServerConfig,
    ServerConfig,
)
from lib.gateway.conversation import (
    ConversationError,
    ConversationManager,
    GitCloneError,
)
from lib.gateway.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)
from lib.gateway.parsing import (
    ParseError,
    decode_subject,
    extract_attachments,
    extract_body,
    extract_conversation_id,
)
from lib.gateway.responder import (
    EmailResponder,
    SMTPSendError,
)
from lib.gateway.security import (
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
    # responder
    "EmailResponder",
    "SMTPSendError",
    # security
    "SecurityValidationError",
    "SenderAuthenticator",
    "SenderAuthorizer",
]
