# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-execution tasks for the sandbox.

An AgentTask represents a single sandboxed Claude Code execution within
an execution context. A CommandTask represents an arbitrary command
execution in the same container environment.

Both task types share proxy lifecycle management and container execution
via the ``_run_container`` module. Task execution is async -- callers
use ``asyncio.run()`` or ``await`` depending on their concurrency model.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from airut.allowlist import Allowlist, serialize_allowlist_json
from airut.claude_output import StreamEvent, parse_event
from airut.sandbox._network import get_network_args
from airut.sandbox._output import build_execution_result
from airut.sandbox._proxy import ProxyManager, _ContextProxy
from airut.sandbox._run_container import (
    _ProcessTracker,
    run_container,
)
from airut.sandbox.event_log import EventLog
from airut.sandbox.network_log import NetworkLog
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
    network_sandbox: NetworkSandboxConfig | None,
    proxy_manager: ProxyManager | None,
    network_log_path: Path | None,
) -> _ContextProxy | None:
    """Start a proxy for the given execution context if sandbox is configured.

    Args:
        execution_context_id: Execution context identifier.
        network_sandbox: Network sandbox configuration.
        proxy_manager: Proxy manager instance.
        network_log_path: File path for network activity log.

    Returns:
        Started context proxy, or None if no sandbox configured.
    """
    if network_sandbox is None or proxy_manager is None:
        return None

    allowlist_json = serialize_allowlist_json(network_sandbox.allowlist)
    replacements_json = json.dumps(
        network_sandbox.replacements.to_dict()
    ).encode()

    return proxy_manager.start_proxy(
        execution_context_id,
        allowlist_json=allowlist_json,
        replacements_json=replacements_json,
        network_log_path=network_log_path,
    )


async def _tail_network_log(
    network_log: NetworkLog,
    callback: Callable[[str], None],
    stop_event: asyncio.Event,
    poll_interval: float = 0.5,
) -> None:
    """Tail a network log file and invoke callback for each new line.

    Polls the network log at ``poll_interval`` until ``stop_event``
    is set, then performs a final drain.

    Args:
        network_log: NetworkLog instance to tail.
        callback: Called for each new log line.
        stop_event: Set to signal tailing should stop.
        poll_interval: Seconds between polls.
    """
    offset = 0
    while not stop_event.is_set():
        lines, offset = network_log.tail(offset)
        for line in lines:
            callback(line)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=poll_interval)
        except TimeoutError:
            pass
    # Final drain after stop
    lines, _ = network_log.tail(offset)
    for line in lines:
        callback(line)


class AgentTask:
    """A single sandboxed Claude Code execution.

    Lifecycle::

        task = sandbox.create_task(...)
        result = await task.execute(prompt, session_id=session_id, model=model)

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
        network_log_path: Path | None,
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
        self._network_log_path = network_log_path
        self._network_sandbox = network_sandbox
        self._resource_limits = resource_limits
        self._container_command = container_command
        self._proxy_manager = proxy_manager

        # Event log (append-only)
        self._event_log = EventLog(execution_context_dir)

        # Network log
        self._network_log: NetworkLog | None = None
        if network_log_path is not None:
            self._network_log = NetworkLog(network_log_path)

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

    async def execute(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        model: str = "sonnet",
        effort: str | None = None,
        on_event: EventCallback | Callable[[StreamEvent], None] | None = None,
        on_stderr_line: Callable[[str], None] | None = None,
        on_network_line: Callable[[str], None] | None = None,
    ) -> ExecutionResult:
        """Execute Claude Code in the sandbox.

        1. Start proxy (if network sandbox configured)
        2. Optionally start network log tailing
        3. Build podman command with mounts, env, network args
        4. Run container with prompt on stdin
        5. Stream events to event log and invoke callback
        6. Stop network log tailing
        7. Stop proxy
        8. Classify result and return

        Args:
            prompt: User prompt to pass to Claude via stdin.
            session_id: Optional session ID for --resume.
            model: Claude model name (e.g., "opus", "sonnet").
            effort: Optional effort level (e.g., "medium", "high",
                "max").  Passed as ``--effort`` to the CLI.  ``None``
                means the flag is omitted.
            on_event: Optional callback for real-time streaming events.
            on_stderr_line: Optional callback for each stderr line.
            on_network_line: Optional callback for network log lines
                during execution. Silently skipped if no network sandbox.

        Returns:
            ExecutionResult -- always returned, never raises for expected
            failures.

        Raises:
            SandboxError: Only for unexpected infrastructure failures.
        """
        logger.info(
            "Executing Claude Code (model=%s, effort=%s) for context %s",
            model,
            effort,
            self._execution_context_id,
        )

        task_proxy: _ContextProxy | None = None

        try:
            # Start proxy if network sandbox configured
            task_proxy = _start_proxy(
                self._execution_context_id,
                self._network_sandbox,
                self._proxy_manager,
                self._network_log_path,
            )

            try:
                result = await self._run_container(
                    prompt,
                    session_id=session_id,
                    model=model,
                    effort=effort,
                    on_event=on_event,
                    on_stderr_line=on_stderr_line,
                    on_network_line=on_network_line,
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

        Sends SIGTERM and returns immediately. A background timer
        sends SIGKILL after 5 seconds if the process has not exited.

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
                "Stopped execution for context %s",
                self._execution_context_id,
            )
        return result

    async def _run_container(
        self,
        prompt: str,
        *,
        session_id: str | None,
        model: str,
        effort: str | None,
        on_event: Callable[[StreamEvent], None] | None,
        on_stderr_line: Callable[[str], None] | None,
        on_network_line: Callable[[str], None] | None,
        task_proxy: _ContextProxy | None,
    ) -> ExecutionResult:
        """Run the container with the given configuration."""
        # Build claude command
        claude_cmd = ["claude"]
        if session_id:
            claude_cmd.extend(["--resume", session_id])
            logger.info("Resuming Claude session: %s", session_id)
        claude_cmd.extend(["--model", model])
        if effort is not None:
            claude_cmd.extend(["--effort", effort])
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

        # Build mounts list (caller mounts + claude dir)
        all_mounts = list(self._mounts) + [
            Mount(
                host_path=self._claude_dir,
                container_path="/root/.claude",
                read_only=False,
            ),
        ]

        # Build network args
        network_args: list[str] = []
        if task_proxy is not None:
            network_args = get_network_args(
                task_proxy.network_name, task_proxy.proxy_ip
            )

        def on_stdout_line(line: str) -> None:
            event = parse_event(line)
            if event is not None:
                self._event_log.append_event(event)
                if on_event:
                    on_event(event)

        # Start network log tailing if requested
        tail_task: asyncio.Task[None] | None = None
        stop_tailing: asyncio.Event | None = None
        if on_network_line is not None and self._network_log is not None:
            stop_tailing = asyncio.Event()
            tail_task = asyncio.create_task(
                _tail_network_log(
                    self._network_log,
                    on_network_line,
                    stop_tailing,
                )
            )

        try:
            raw = await run_container(
                container_command=self._container_command,
                image_tag=self._image_tag,
                mounts=all_mounts,
                env=self._env,
                resource_limits=self._resource_limits,
                network_args=network_args,
                command=claude_cmd,
                stdin_data=prompt,
                on_stdout_line=on_stdout_line,
                on_stderr_line=on_stderr_line,
                timeout=self._resource_limits.timeout,
                process_tracker=self._process_tracker,
            )
        except Exception as e:
            logger.error("Unexpected container execution error: %s", e)
            raise SandboxError(f"Container execution failed: {e}") from e
        finally:
            if stop_tailing is not None:
                stop_tailing.set()
            if tail_task is not None:
                try:
                    await tail_task
                except BaseException:
                    logger.warning("Network log tailing failed", exc_info=True)

        logger.debug(
            "Full stdout (length=%d):\n%s",
            len(raw.stdout),
            raw.stdout,
        )
        if raw.stderr:
            logger.debug(
                "Full stderr (length=%d):\n%s",
                len(raw.stderr),
                raw.stderr,
            )

        return build_execution_result(
            stdout=raw.stdout,
            stderr=raw.stderr,
            exit_code=raw.exit_code,
            timed_out=raw.timed_out,
            duration_ms=raw.duration_ms,
        )


class CommandTask:
    """A generic command execution in the sandbox container.

    Unlike ``AgentTask``, ``CommandTask`` does not create a Claude
    session directory, event log, or parse streaming events. It runs
    an arbitrary command in the same sandboxed container environment.

    Lifecycle::

        task = sandbox.create_command_task(...)
        result = await task.execute(["ls", "-la"])

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
        network_log_path: Path | None,
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
        self._network_log_path = network_log_path
        self._network_sandbox = network_sandbox
        self._resource_limits = resource_limits
        self._container_command = container_command
        self._proxy_manager = proxy_manager

        # Network log
        self._network_log: NetworkLog | None = None
        if network_log_path is not None:
            self._network_log = NetworkLog(network_log_path)

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

    async def execute(
        self,
        command: list[str],
        *,
        on_output: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
        on_network_line: Callable[[str], None] | None = None,
    ) -> CommandResult:
        """Execute a command in the sandbox container.

        Args:
            command: Command and arguments to run in the container.
            on_output: Optional callback invoked for each stdout line.
            on_stderr: Optional callback invoked for each stderr line.
            on_network_line: Optional callback for network log lines
                during execution. Silently skipped if no network sandbox.

        Returns:
            CommandResult with exit code, stdout, stderr, duration, and
            timeout flag.

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
            task_proxy = _start_proxy(
                self._execution_context_id,
                self._network_sandbox,
                self._proxy_manager,
                self._network_log_path,
            )

            try:
                # Build network args
                network_args: list[str] = []
                if task_proxy is not None:
                    network_args = get_network_args(
                        task_proxy.network_name, task_proxy.proxy_ip
                    )

                # Start network log tailing if requested
                tail_task: asyncio.Task[None] | None = None
                stop_tailing: asyncio.Event | None = None
                if (
                    on_network_line is not None
                    and self._network_log is not None
                ):
                    stop_tailing = asyncio.Event()
                    tail_task = asyncio.create_task(
                        _tail_network_log(
                            self._network_log,
                            on_network_line,
                            stop_tailing,
                        )
                    )

                try:
                    raw = await run_container(
                        container_command=self._container_command,
                        image_tag=self._image_tag,
                        mounts=self._mounts,
                        env=self._env,
                        resource_limits=self._resource_limits,
                        network_args=network_args,
                        command=command,
                        stdin_data=None,
                        on_stdout_line=on_output,
                        on_stderr_line=on_stderr,
                        timeout=self._resource_limits.timeout,
                        process_tracker=self._process_tracker,
                    )
                finally:
                    if stop_tailing is not None:
                        stop_tailing.set()
                    if tail_task is not None:
                        try:
                            await tail_task
                        except BaseException:
                            logger.warning(
                                "Network log tailing failed",
                                exc_info=True,
                            )
            finally:
                # Always stop proxy, even on failure
                if task_proxy is not None and self._proxy_manager is not None:
                    self._proxy_manager.stop_proxy(self._execution_context_id)

            return CommandResult(
                exit_code=raw.exit_code,
                stdout=raw.stdout,
                stderr=raw.stderr,
                duration_ms=raw.duration_ms,
                timed_out=raw.timed_out,
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
