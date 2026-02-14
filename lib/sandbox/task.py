# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Per-execution task for the sandbox.

A Task represents a single sandboxed Claude Code execution within an
execution context. It manages the container process lifecycle, proxy
start/stop, streaming output parsing, and event logging.
"""

from __future__ import annotations

import json
import logging
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from lib.allowlist import Allowlist, serialize_allowlist_json
from lib.claude_output import StreamEvent, parse_event
from lib.sandbox._network import get_network_args
from lib.sandbox._output import build_execution_result
from lib.sandbox._proxy import ProxyManager, _ContextProxy
from lib.sandbox.event_log import EventLog
from lib.sandbox.network_log import NETWORK_LOG_FILENAME, NetworkLog
from lib.sandbox.secrets import SecretReplacements
from lib.sandbox.types import ContainerEnv, ExecutionResult, Mount


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


class Task:
    """A single sandboxed Claude Code execution.

    Lifecycle::

        task = sandbox.create_task(...)
        result = task.execute(prompt, session_id=session_id, model=model)

        # Events are appended to events.jsonl during execution
        # Conversation metadata is managed by the caller (gateway)

        # From another thread:
        task.stop()

    Thread Safety:
        execute() is not reentrant -- only one execution at a time per Task.
        stop() is safe to call from another thread during execute().
    """

    def __init__(
        self,
        execution_context_id: str,
        *,
        image_tag: str,
        mounts: list[Mount],
        env: ContainerEnv,
        session_dir: Path,
        network_log_dir: Path | None,
        network_sandbox: NetworkSandboxConfig | None,
        timeout_seconds: int,
        container_command: str,
        proxy_manager: ProxyManager | None,
    ) -> None:
        self._execution_context_id = execution_context_id
        self._image_tag = image_tag
        self._mounts = mounts
        self._env = env
        self._session_dir = session_dir
        self._network_log_dir = network_log_dir
        self._network_sandbox = network_sandbox
        self._timeout_seconds = timeout_seconds
        self._container_command = container_command
        self._proxy_manager = proxy_manager

        # Event log (append-only)
        self._event_log = EventLog(session_dir)

        # Network log
        self._network_log: NetworkLog | None = None
        if network_log_dir is not None:
            self._network_log = NetworkLog(
                network_log_dir / NETWORK_LOG_FILENAME
            )

        # Claude session state directory
        self._claude_dir = session_dir / "claude"
        self._claude_dir.mkdir(parents=True, exist_ok=True)

        # Process tracking for stop()
        self._process: subprocess.Popen[str] | None = None
        self._process_lock = threading.Lock()

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
                allowlist_json = serialize_allowlist_json(
                    self._network_sandbox.allowlist
                )
                replacements_json = json.dumps(
                    self._network_sandbox.replacements.to_dict()
                ).encode()

                task_proxy = self._proxy_manager.start_proxy(
                    self._execution_context_id,
                    allowlist_json=allowlist_json,
                    replacements_json=replacements_json,
                    network_log_dir=self._network_log_dir,
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
        with self._process_lock:
            process = self._process
            if process is None:
                logger.warning(
                    "No running process found for context %s",
                    self._execution_context_id,
                )
                return False

            logger.info(
                "Stopping execution for context %s",
                self._execution_context_id,
            )
            try:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(
                        "Process did not terminate gracefully, sending SIGKILL"
                    )
                    process.kill()
                    process.wait()
                return True
            except Exception as e:
                logger.error("Failed to stop process: %s", e)
                return False

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
        # Build command
        cmd = [
            self._container_command,
            "run",
            "--rm",
            "-i",
            "--log-driver=none",
        ]

        # Pass environment variables to container
        for env_var, value in self._env.variables.items():
            cmd.extend(["-e", f"{env_var}={value}"])

        # Add caller mounts
        for mount in self._mounts:
            ro = ":ro" if mount.read_only else ":rw"
            cmd.extend(["-v", f"{mount.host_path}:{mount.container_path}{ro}"])

        # Add claude session state mount (sandbox-managed)
        cmd.extend(["-v", f"{self._claude_dir}:/root/.claude:rw"])

        # Network sandbox args
        if task_proxy is not None:
            cmd.extend(
                get_network_args(task_proxy.network_name, task_proxy.proxy_ip)
            )

        cmd.append(self._image_tag)

        # Build claude command
        claude_cmd = ["claude"]
        if session_id:
            claude_cmd.extend(["--resume", session_id])
            logger.info("Resuming session: %s", session_id)
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
        cmd.extend(claude_cmd)

        logger.info(
            "Executing Claude Code with prompt (length=%d): %s",
            len(prompt),
            prompt,
        )

        # Redact secrets from logged command
        redacted_cmd = []
        skip_next = False
        for i, arg in enumerate(cmd):
            if skip_next:
                skip_next = False
                continue
            if arg == "-e" and i + 1 < len(cmd):
                next_arg = cmd[i + 1]
                if "=" in next_arg:
                    var_name = next_arg.split("=")[0]
                    redacted_cmd.extend(["-e", f"{var_name}=***"])
                    skip_next = True
                    continue
            redacted_cmd.append(arg)
        logger.debug("Full command: %s", " ".join(redacted_cmd))

        start_time = time.time()
        timed_out = False

        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Track process for stop()
            with self._process_lock:
                self._process = process

            try:
                # Send prompt to stdin and close it
                if process.stdin:
                    process.stdin.write(prompt)
                    process.stdin.close()

                # Read stdout line-by-line
                stdout_lines: list[str] = []
                if process.stdout:
                    for line in process.stdout:
                        stdout_lines.append(line)
                        event = parse_event(line)
                        if event is not None:
                            # Append to event log (O(1) append)
                            self._event_log.append_event(event)
                            if on_event:
                                on_event(event)

                # Wait for process to complete with timeout
                try:
                    process.wait(timeout=self._timeout_seconds)
                except subprocess.TimeoutExpired:
                    logger.error(
                        "Container execution timed out, killing process"
                    )
                    process.kill()
                    process.wait()
                    timed_out = True

                # Read stderr
                stderr_lines: list[str] = []
                if process.stderr:
                    stderr_lines = process.stderr.readlines()

                stdout = "".join(stdout_lines)
                stderr = "".join(stderr_lines)
                exit_code = process.returncode

            finally:
                with self._process_lock:
                    self._process = None

            elapsed = time.time() - start_time
            duration_ms = int(elapsed * 1000)

            logger.info(
                "Execution completed in %.2fs (exit_code=%d)",
                elapsed,
                exit_code,
            )
            logger.debug(
                "Full stdout (length=%d):\n%s",
                len(stdout),
                stdout,
            )
            if stderr:
                logger.debug(
                    "Full stderr (length=%d):\n%s",
                    len(stderr),
                    stderr,
                )

            return build_execution_result(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=timed_out,
                duration_ms=duration_ms,
            )

        except Exception as e:
            logger.error("Unexpected container execution error: %s", e)
            raise SandboxError(f"Container execution failed: {e}") from e
