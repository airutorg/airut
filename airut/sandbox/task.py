# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-execution tasks for the sandbox.

An AgentTask represents a single sandboxed Claude Code execution within an
execution context. It manages the container process lifecycle, proxy
start/stop, streaming output parsing, and event logging.

A CommandTask represents a single sandboxed command execution (arbitrary
command, no Claude-specific logic).
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from airut.allowlist import Allowlist, serialize_allowlist_json
from airut.claude_output import StreamEvent, parse_event
from airut.sandbox._output import build_execution_result
from airut.sandbox._proxy import ProxyManager, _ContextProxy
from airut.sandbox._run_container import (
    _ProcessTracker,
    build_network_args,
    run_container,
)
from airut.sandbox.event_log import EventLog
from airut.sandbox.network_log import NETWORK_LOG_FILENAME, NetworkLog
from airut.sandbox.secrets import SecretReplacements
from airut.sandbox.types import (
    CommandResult,
    ContainerEnv,
    ExecutionResult,
    Mount,
    ResourceLimits,
)


logger = logging.getLogger(__name__)


class EventCallback(Protocol):
    """Protocol for streaming event callbacks."""

    def __call__(self, event: StreamEvent) -> None: ...


class SandboxError(Exception):
    """Base exception for sandbox infrastructure failures.

    Raised only for unexpected errors -- not for expected execution
    failures like timeout or prompt-too-long (those are returned as
    Outcome variants in ExecutionResult).
    """


class NetworkSandboxConfig:
    """Everything needed to set up network isolation for a task.

    Combines the allowlist (what hosts are reachable) with secret
    replacement rules (how credentials are protected at the proxy level).
    """

    def __init__(
        self,
        allowlist: Allowlist,
        replacements: SecretReplacements,
    ) -> None:
        self.allowlist = allowlist
        self.replacements = replacements


def _start_proxy(
    execution_context_id: str,
    network_sandbox: NetworkSandboxConfig,
    proxy_manager: ProxyManager,
    network_log_dir: Path | None,
) -> _ContextProxy:
    """Start the network proxy for a task.

    Args:
        execution_context_id: Task identifier for proxy scoping.
        network_sandbox: Network sandbox configuration.
        proxy_manager: Shared proxy manager.
        network_log_dir: Directory for network activity log.

    Returns:
        Active proxy context.
    """
    allowlist_json = serialize_allowlist_json(network_sandbox.allowlist)
    replacements_json = json.dumps(
        network_sandbox.replacements.to_dict()
    ).encode()

    return proxy_manager.start_proxy(
        execution_context_id,
        allowlist_json=allowlist_json,
        replacements_json=replacements_json,
        network_log_dir=network_log_dir,
    )


class AgentTask:
    """A single sandboxed Claude Code execution.

    Lifecycle::

        task = sandbox.create_task(...)
        result = task.execute(prompt, session_id=session_id, model=model)

        # Events are appended to events.jsonl during execution
        # Conversation metadata is managed by the caller (gateway)

        # From another thread:
        task.stop()

    Thread Safety:
        execute() is not reentrant -- only one execution at a time per
        AgentTask. stop() is safe to call from another thread during
        execute().
    """

    def __init__(
        self,
        execution_context_id: str,
        *,
        image_tag: str,
        mounts: list[Mount],
        env: ContainerEnv,
        execution_context_dir: Path,
        network_log_dir: Path | None,
        network_sandbox: NetworkSandboxConfig | None,
        resource_limits: ResourceLimits,
        container_command: str,
        proxy_manager: ProxyManager | None,
    ) -> None:
        self._execution_context_id = execution_context_id
        self._image_tag = image_tag
        self._mounts = mounts
        self._env = env
        self._execution_context_dir = execution_context_dir
        self._network_log_dir = network_log_dir
        self._network_sandbox = network_sandbox
        self._resource_limits = resource_limits
        self._container_command = container_command
        self._proxy_manager = proxy_manager

        # Event log (append-only)
        self._event_log = EventLog(execution_context_dir)

        # Network log
        self._network_log: NetworkLog | None = None
        if network_log_dir is not None:
            self._network_log = NetworkLog(
                network_log_dir / NETWORK_LOG_FILENAME
            )

        # Claude session state directory
        self._claude_dir = execution_context_dir / "claude"
        self._claude_dir.mkdir(parents=True, exist_ok=True)

        # Process tracking for stop()
        self._process_tracker = _ProcessTracker()

    @property
    def execution_context_id(self) -> str:
        """Execution context identifier."""
        return self._execution_context_id

    @property
    def event_log(self) -> EventLog:
        """Access the append-only event log."""
        return self._event_log

    @property
    def network_log(self) -> NetworkLog | None:
        """Access network activity log (None if sandbox disabled)."""
        return self._network_log

    def execute(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        model: str = "sonnet",
        on_event: EventCallback | Callable[[StreamEvent], None] | None = None,
    ) -> ExecutionResult:
        """Execute Claude Code in the sandbox.

        1. Start proxy (if network sandbox configured)
        2. Build podman command with mounts, env, network args
        3. Run container with prompt on stdin
        4. Stream events to event log and invoke callback
        5. Stop proxy
        6. Classify result and return

        Args:
            prompt: User prompt to pass to Claude via stdin.
            session_id: Optional session ID for --resume.
            model: Claude model name (e.g., "opus", "sonnet").
            on_event: Optional callback for real-time streaming events.

        Returns:
            ExecutionResult -- always returned, never raises for expected
            failures.

        Raises:
            SandboxError: Only for unexpected infrastructure failures.
        """
        logger.info(
            "Executing Claude Code (model=%s) for context %s",
            model,
            self._execution_context_id,
        )

        task_proxy: _ContextProxy | None = None

        try:
            # Start proxy if network sandbox configured
            if (
                self._network_sandbox is not None
                and self._proxy_manager is not None
            ):
                task_proxy = _start_proxy(
                    self._execution_context_id,
                    self._network_sandbox,
                    self._proxy_manager,
                    self._network_log_dir,
                )

            try:
                result = self._run_container(
                    prompt,
                    session_id=session_id,
                    model=model,
                    on_event=on_event,
                    task_proxy=task_proxy,
                )
            finally:
                # Always stop proxy, even on failure
                if task_proxy is not None and self._proxy_manager is not None:
                    self._proxy_manager.stop_proxy(self._execution_context_id)

            return result

        except Exception as e:
            if isinstance(e, SandboxError):
                raise
            logger.error(
                "Unexpected error during context %s: %s",
                self._execution_context_id,
                e,
            )
            raise SandboxError(f"Execution failed: {e}") from e

    def stop(self) -> bool:
        """Stop execution from another thread.

        Sends SIGTERM, waits 5 seconds, then SIGKILL.

        Returns:
            True if a running process was stopped, False if nothing running.
        """
        result = self._process_tracker.stop()
        if not result:
            logger.warning(
                "No running process found for context %s",
                self._execution_context_id,
            )
        else:
            logger.info(
                "Stopping execution for context %s",
                self._execution_context_id,
            )
        return result

    def _run_container(
        self,
        prompt: str,
        *,
        session_id: str | None,
        model: str,
        on_event: Callable[[StreamEvent], None] | None,
        task_proxy: _ContextProxy | None,
    ) -> ExecutionResult:
        """Run the container with the given configuration."""
        # Build claude command
        claude_cmd = ["claude"]
        if session_id:
            claude_cmd.extend(["--resume", session_id])
            logger.info("Resuming Claude session: %s", session_id)
        claude_cmd.extend(["--model", model])
        claude_cmd.extend(
            [
                "-p",
                "-",  # Read prompt from stdin
                "--dangerously-skip-permissions",
                "--output-format",
                "stream-json",
                "--verbose",
            ]
        )

        logger.info(
            "Executing Claude Code with prompt (length=%d): %s",
            len(prompt),
            prompt,
        )

        # Build mounts list with claude/ directory
        all_mounts = list(self._mounts)
        all_mounts.append(
            Mount(
                host_path=self._claude_dir,
                container_path="/root/.claude",
                read_only=False,
            )
        )

        # Build network args
        network_args = build_network_args(task_proxy)

        # Stdout callback: parse events and forward
        def on_stdout_line(line: str) -> None:
            event = parse_event(line)
            if event is not None:
                self._event_log.append_event(event)
                if on_event:
                    on_event(event)

        try:
            raw_result = run_container(
                container_command=self._container_command,
                image_tag=self._image_tag,
                mounts=all_mounts,
                env=self._env,
                resource_limits=self._resource_limits,
                network_args=network_args,
                command=claude_cmd,
                stdin_data=prompt,
                on_stdout_line=on_stdout_line,
                timeout=self._resource_limits.timeout,
                process_tracker=self._process_tracker,
                stderr_passthrough=False,
            )
        except Exception as e:
            logger.error("Unexpected container execution error: %s", e)
            raise SandboxError(f"Container execution failed: {e}") from e

        return build_execution_result(
            stdout=raw_result.stdout,
            stderr=raw_result.stderr,
            exit_code=raw_result.exit_code,
            timed_out=raw_result.timed_out,
            duration_ms=raw_result.duration_ms,
        )


class CommandTask:
    """A single sandboxed command execution.

    Unlike AgentTask, this runs an arbitrary command (not Claude Code).
    There is no event log, no Claude session directory, and stderr
    passes through to the parent process.

    Lifecycle::

        task = sandbox.create_command_task(...)
        result = task.execute(["make", "test"])

        # From another thread:
        task.stop()

    Thread Safety:
        execute() is not reentrant -- only one execution at a time per
        CommandTask. stop() is safe to call from another thread during
        execute().
    """

    def __init__(
        self,
        execution_context_id: str,
        *,
        image_tag: str,
        mounts: list[Mount],
        env: ContainerEnv,
        execution_context_dir: Path,
        network_log_dir: Path | None,
        network_sandbox: NetworkSandboxConfig | None,
        resource_limits: ResourceLimits,
        container_command: str,
        proxy_manager: ProxyManager | None,
    ) -> None:
        self._execution_context_id = execution_context_id
        self._image_tag = image_tag
        self._mounts = mounts
        self._env = env
        self._execution_context_dir = execution_context_dir
        self._network_log_dir = network_log_dir
        self._network_sandbox = network_sandbox
        self._resource_limits = resource_limits
        self._container_command = container_command
        self._proxy_manager = proxy_manager

        # Network log
        self._network_log: NetworkLog | None = None
        if network_log_dir is not None:
            self._network_log = NetworkLog(
                network_log_dir / NETWORK_LOG_FILENAME
            )

        # Process tracking for stop()
        self._process_tracker = _ProcessTracker()

    @property
    def execution_context_id(self) -> str:
        """Execution context identifier."""
        return self._execution_context_id

    @property
    def network_log(self) -> NetworkLog | None:
        """Access network activity log (None if sandbox disabled)."""
        return self._network_log

    def execute(
        self,
        command: list[str],
        *,
        on_output: Callable[[str], None] | None = None,
    ) -> CommandResult:
        """Execute a command in the sandbox.

        1. Start proxy (if network sandbox configured)
        2. Run container with command
        3. Stream stdout to callback and sys.stdout
        4. Stop proxy
        5. Return CommandResult

        Args:
            command: Command and arguments to run inside the container.
            on_output: Optional callback for each stdout line.

        Returns:
            CommandResult with exit code, stdout, timing, and timeout
            status.

        Raises:
            SandboxError: Only for unexpected infrastructure failures.
        """
        logger.info(
            "Executing command for context %s: %s",
            self._execution_context_id,
            command,
        )

        task_proxy: _ContextProxy | None = None

        try:
            # Start proxy if network sandbox configured
            if (
                self._network_sandbox is not None
                and self._proxy_manager is not None
            ):
                task_proxy = _start_proxy(
                    self._execution_context_id,
                    self._network_sandbox,
                    self._proxy_manager,
                    self._network_log_dir,
                )

            try:
                # Build network args
                network_args = build_network_args(task_proxy)

                # Stdout callback: collect and stream
                def on_stdout_line(line: str) -> None:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    if on_output is not None:
                        on_output(line)

                raw_result = run_container(
                    container_command=self._container_command,
                    image_tag=self._image_tag,
                    mounts=self._mounts,
                    env=self._env,
                    resource_limits=self._resource_limits,
                    network_args=network_args,
                    command=command,
                    stdin_data=None,
                    on_stdout_line=on_stdout_line,
                    timeout=self._resource_limits.timeout,
                    process_tracker=self._process_tracker,
                    stderr_passthrough=True,
                )
            finally:
                # Always stop proxy, even on failure
                if task_proxy is not None and self._proxy_manager is not None:
                    self._proxy_manager.stop_proxy(self._execution_context_id)

            return CommandResult(
                exit_code=raw_result.exit_code,
                stdout=raw_result.stdout,
                stderr=raw_result.stderr,
                duration_ms=raw_result.duration_ms,
                timed_out=raw_result.timed_out,
            )

        except Exception as e:
            if isinstance(e, SandboxError):
                raise
            logger.error(
                "Unexpected error during context %s: %s",
                self._execution_context_id,
                e,
            )
            raise SandboxError(f"Execution failed: {e}") from e

    def stop(self) -> bool:
        """Stop execution from another thread.

        Returns:
            True if a running process was stopped, False if nothing running.
        """
        return self._process_tracker.stop()
