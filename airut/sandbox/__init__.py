# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Sandbox library for safe containerized execution.

The sandbox owns container lifecycle, network isolation, event logging,
and error detection. Protocol layers (email, Slack, automation) define
what Claude sees (prompts, repos, files, mounts); the sandbox handles
how it runs safely.

Two task types are provided:

- ``AgentTask`` -- runs Claude Code in the sandbox.
- ``CommandTask`` -- runs arbitrary commands in the sandbox.
"""

from airut.sandbox._image_cache import (
    ImageBuildError,
    ImageBuildSpec,
    content_hash,
)
from airut.sandbox._proxy import ProxyError, build_proxy_spec
from airut.sandbox.event_log import EVENTS_FILE_NAME, EventLog
from airut.sandbox.network_log import NETWORK_LOG_FILENAME, NetworkLog
from airut.sandbox.sandbox import Sandbox, SandboxConfig, default_proxy_dir
from airut.sandbox.secrets import (
    MaskedSecret,
    PreparedSecrets,
    SecretReplacements,
    SigningCredential,
    generate_session_token_surrogate,
    generate_surrogate,
    prepare_secrets,
)
from airut.sandbox.task import (
    AgentTask,
    CommandTask,
    EventCallback,
    NetworkSandboxConfig,
    SandboxError,
)
from airut.sandbox.types import (
    CommandResult,
    ContainerEnv,
    ExecutionResult,
    Mount,
    Outcome,
    ResourceLimits,
)


__all__ = [
    # sandbox
    "Sandbox",
    "SandboxConfig",
    "default_proxy_dir",
    # task
    "AgentTask",
    "CommandTask",
    "EventCallback",
    "NetworkSandboxConfig",
    "SandboxError",
    # types
    "CommandResult",
    "ContainerEnv",
    "ExecutionResult",
    "Mount",
    "Outcome",
    "ResourceLimits",
    # secrets
    "MaskedSecret",
    "PreparedSecrets",
    "SecretReplacements",
    "SigningCredential",
    "generate_session_token_surrogate",
    "generate_surrogate",
    "prepare_secrets",
    # event_log
    "EVENTS_FILE_NAME",
    "EventLog",
    # network_log
    "NETWORK_LOG_FILENAME",
    "NetworkLog",
    # image
    "ImageBuildSpec",
    "content_hash",
    "build_proxy_spec",
    # errors
    "ImageBuildError",
    "ProxyError",
]
