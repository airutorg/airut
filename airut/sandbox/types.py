# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Type definitions for the sandbox library.

Provides the core types used throughout the sandbox: Mount, ContainerEnv,
Outcome, and ExecutionResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from airut.claude_output import StreamEvent
from airut.claude_output.types import Usage


@dataclass(frozen=True)
class Mount:
    """A volume mount for the container.

    Attributes:
        host_path: Absolute path on the host.
        container_path: Path inside the container.
        read_only: Whether the mount is read-only.
    """

    host_path: Path
    container_path: str
    read_only: bool = False


@dataclass(frozen=True)
class ContainerEnv:
    """Container environment variables.

    All values are redacted in log output (command-line logging).
    Container env vars are assumed to be secrets or secret-derived.

    Attributes:
        variables: Mapping of environment variable names to values.
    """

    variables: dict[str, str] = field(default_factory=dict)


class Outcome(Enum):
    """Classifies execution result to guide caller behavior.

    The caller matches on Outcome to decide how to handle the result.
    """

    SUCCESS = "success"
    TIMEOUT = "timeout"
    PROMPT_TOO_LONG = "prompt_too_long"
    SESSION_CORRUPTED = "session_corrupted"
    CONTAINER_FAILED = "container_failed"


@dataclass(frozen=True)
class ExecutionResult:
    """Result of a sandbox task execution.

    Always returned -- the sandbox does not raise for expected failures
    (timeout, prompt too long, session corrupted). Only raises
    SandboxError for truly unexpected infrastructure failures.

    Attributes:
        outcome: Classification of the execution result.
        session_id: Claude session ID (from result or init event).
        response_text: Extracted response text from Claude output.
        events: Parsed streaming events from Claude.
        duration_ms: Execution duration in milliseconds.
        total_cost_usd: Total cost in USD.
        num_turns: Number of agentic turns.
        usage: Token usage breakdown.
        stdout: Raw stdout from the container.
        stderr: Raw stderr from the container.
        exit_code: Container process exit code.
    """

    outcome: Outcome
    session_id: str
    response_text: str
    events: list[StreamEvent]
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    usage: Usage
    stdout: str
    stderr: str
    exit_code: int
