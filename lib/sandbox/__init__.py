# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Sandbox library for safe containerized execution of Claude Code.

The sandbox owns container lifecycle, network isolation, session
persistence, and error detection. Protocol layers (email, Slack,
automation) define what Claude sees (prompts, repos, files, mounts);
the sandbox handles how it runs safely.
"""

from lib.sandbox._image import ImageBuildError
from lib.sandbox._output import extract_error_summary
from lib.sandbox._proxy import ProxyError
from lib.sandbox.network_log import NETWORK_LOG_FILENAME, NetworkLog
from lib.sandbox.sandbox import Sandbox, SandboxConfig
from lib.sandbox.secrets import (
    MaskedSecret,
    PreparedSecrets,
    SecretReplacements,
    SigningCredential,
    generate_session_token_surrogate,
    generate_surrogate,
    prepare_secrets,
)
from lib.sandbox.session import (
    SESSION_FILE_NAME,
    SessionMetadata,
    SessionReply,
    SessionStore,
)
from lib.sandbox.task import (
    EventCallback,
    NetworkSandboxConfig,
    SandboxError,
    Task,
)
from lib.sandbox.types import ContainerEnv, ExecutionResult, Mount, Outcome


__all__ = [
    # sandbox
    "Sandbox",
    "SandboxConfig",
    # task
    "Task",
    "EventCallback",
    "NetworkSandboxConfig",
    "SandboxError",
    # types
    "ContainerEnv",
    "ExecutionResult",
    "Mount",
    "Outcome",
    # secrets
    "MaskedSecret",
    "PreparedSecrets",
    "SecretReplacements",
    "SigningCredential",
    "generate_session_token_surrogate",
    "generate_surrogate",
    "prepare_secrets",
    # session
    "SESSION_FILE_NAME",
    "SessionMetadata",
    "SessionReply",
    "SessionStore",
    # network_log
    "NETWORK_LOG_FILENAME",
    "NetworkLog",
    # errors
    "ImageBuildError",
    "ProxyError",
    # output
    "extract_error_summary",
]
