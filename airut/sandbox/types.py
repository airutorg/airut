# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Type definitions for the sandbox library.

Provides the core types used throughout the sandbox: Mount, ContainerEnv,
Outcome, and ExecutionResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from airut.claude_output.types import Usage
from airut.config.schema import Scope, meta


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
        duration_ms: Execution duration in milliseconds.
        total_cost_usd: Total cost in USD.
        num_turns: Number of agentic turns.
        is_error: Whether Claude reported an error in the result event.
        usage: Token usage breakdown.
        web_search_count: Number of WebSearch tool uses.
        web_fetch_count: Number of WebFetch tool uses.
        error_summary: Human-readable error summary, or None.
    """

    outcome: Outcome
    session_id: str
    response_text: str
    duration_ms: int
    total_cost_usd: float
    num_turns: int
    is_error: bool
    usage: Usage
    web_search_count: int
    web_fetch_count: int
    error_summary: str | None


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

#: Regex for validating memory limit strings (e.g. "512m", "2g", "1024k").
_MEMORY_PATTERN = re.compile(r"^\d+[bkmgBKMG]$")


def _validate_memory(value: str) -> None:
    """Validate a memory limit string.

    Accepts podman ``--memory`` format: a number followed by a unit
    suffix (``b``, ``k``, ``m``, ``g``, case-insensitive).

    Args:
        value: Memory limit string.

    Raises:
        ValueError: If the format is invalid.
    """
    if not _MEMORY_PATTERN.match(value):
        raise ValueError(
            f"Invalid memory limit '{value}': "
            f"expected format like '512m', '2g', '1024k'"
        )
    if int(value[:-1]) == 0:
        raise ValueError(
            f"Invalid memory limit '{value}': value must be greater than zero"
        )


@dataclass(frozen=True)
class ResourceLimits:
    """Container resource limits.

    All fields are optional.  When ``None``, the corresponding
    podman flag is not passed and no limit is enforced.

    Used in two contexts:

    - **Server config** — defines defaults for all repos.
    - **Repo config** — overrides server defaults per repo.

    Attributes:
        timeout: Max container execution time in seconds.
        memory: Memory limit for ``--memory`` (e.g. ``"2g"``).
        cpus: CPU limit for ``--cpus`` (supports fractional cores,
            e.g. ``1.5``).
        pids_limit: Process limit for ``--pids-limit``.
    """

    timeout: int | None = field(
        default=None,
        metadata=meta(
            "Max execution time in seconds (minimum 10)",
            Scope.TASK,
        ),
    )
    memory: str | None = field(
        default=None,
        metadata=meta(
            "Memory limit (e.g. 512m, 2g)",
            Scope.TASK,
        ),
    )
    cpus: float | None = field(
        default=None,
        metadata=meta(
            "CPU limit (e.g. 1.5 for one and a half cores)",
            Scope.TASK,
        ),
    )
    pids_limit: int | None = field(
        default=None,
        metadata=meta(
            "Max number of processes in the container",
            Scope.TASK,
        ),
    )

    def __post_init__(self) -> None:
        """Validate resource limit values.

        Raises:
            ValueError: If any field has an invalid value.
        """
        if self.timeout is not None and self.timeout < 10:
            raise ValueError(f"Timeout must be >= 10s: {self.timeout}")
        if self.cpus is not None and self.cpus < 0.01:
            raise ValueError(f"CPUs must be >= 0.01: {self.cpus}")
        if self.pids_limit is not None and self.pids_limit < 1:
            raise ValueError(f"PIDs limit must be >= 1: {self.pids_limit}")
        if self.memory is not None:
            _validate_memory(self.memory)

    def with_defaults(self, defaults: ResourceLimits | None) -> ResourceLimits:
        """Return a copy with ``None`` fields filled from *defaults*.

        For each field, uses ``self``'s value if set, otherwise falls
        back to the corresponding value in *defaults*.

        Args:
            defaults: Server-wide default limits.  ``None`` means no
                defaults (return ``self`` unchanged).

        Returns:
            New ResourceLimits with defaults applied.
        """
        if defaults is None:
            return self

        return ResourceLimits(
            timeout=self.timeout
            if self.timeout is not None
            else defaults.timeout,
            memory=self.memory if self.memory is not None else defaults.memory,
            cpus=self.cpus if self.cpus is not None else defaults.cpus,
            pids_limit=(
                self.pids_limit
                if self.pids_limit is not None
                else defaults.pids_limit
            ),
        )


@dataclass(frozen=True)
class CommandResult:
    """Result of a generic command execution in the sandbox.

    Returned by ``CommandTask.execute()`` for non-Claude container commands.

    Attributes:
        exit_code: Container process exit code.
        stdout: Raw stdout from the container.
        stderr: Raw stderr from the container.
        duration_ms: Execution duration in milliseconds.
        timed_out: Whether the command timed out.
    """

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
