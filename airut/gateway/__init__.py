# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Gateway subsystem.

Provides headless interaction with Claude Code via messaging channels:
- Channel adapter abstraction (ChannelAdapter, ParsedMessage)
- Git-based conversation state management (ConversationManager)
- Email channel implementation (gateway/email/)
- Configuration loading
"""

from airut.gateway.channel import (
    ChannelAdapter,
    ParsedMessage,
)
from airut.gateway.config import (
    ConfigError,
    EmailChannelConfig,
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
from airut.gateway.email.listener import (
    EmailListener,
    IMAPConnectionError,
    IMAPIdleError,
)
from airut.gateway.email.parsing import (
    ParseError,
    decode_subject,
    extract_attachments,
    extract_body,
    extract_conversation_id,
    extract_conversation_id_from_headers,
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
    # channel
    "ChannelAdapter",
    "ParsedMessage",
    # config
    "ConfigError",
    "EmailChannelConfig",
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
