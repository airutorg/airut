# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Generic container execution for the sandbox.

Extracts the container subprocess lifecycle from task-specific logic so
that both ``AgentTask`` (Claude Code) and ``CommandTask`` (arbitrary
commands) can share the same execution engine.
"""

from __future__ import annotations

import logging
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from airut.sandbox.types import ContainerEnv, Mount, ResourceLimits


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _RawResult:
    """Raw result from a container execution.

    Attributes:
        stdout: Raw stdout text.
        stderr: Raw stderr text (empty when ``stderr_passthrough`` is True).
        exit_code: Container process exit code.
        duration_ms: Execution duration in milliseconds.
        timed_out: Whether the command timed out.
    """

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    timed_out: bool


class _ProcessTracker:
    """Thread-safe process reference for stop() support.

    Holds a reference to the currently running subprocess and provides
    a ``stop()`` method that can be called from another thread to
    gracefully terminate the process.
    """

    def __init__(self) -> None:
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

    def set(self, process: subprocess.Popen[str]) -> None:
        """Set the active process reference.

        Args:
            process: The running subprocess.
        """
        with self._lock:
            self._process = process

    def clear(self) -> None:
        """Clear the process reference after completion."""
        with self._lock:
            self._process = None

    def stop(self) -> bool:
        """Stop the tracked process from another thread.

        Sends SIGTERM, waits 5 seconds, then SIGKILL. The lock is
        released before the blocking wait to avoid holding it during
        I/O.

        Returns:
            True if a running process was stopped, False if nothing running.
        """
        with self._lock:
            process = self._process
        if process is None:
            return False

        logger.info("Stopping tracked process")
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


def _redact_env_args(cmd: list[str]) -> list[str]:
    """Redact environment variable values from a command for logging.

    Replaces ``-e VAR=value`` pairs with ``-e VAR=***``.

    Args:
        cmd: Full command-line argument list.

    Returns:
        Redacted copy of the command.
    """
    redacted: list[str] = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        if arg == "-e" and i + 1 < len(cmd):
            next_arg = cmd[i + 1]
            if "=" in next_arg:
                var_name = next_arg.split("=")[0]
                redacted.extend(["-e", f"{var_name}=***"])
                skip_next = True
                continue
        redacted.append(arg)
    return redacted


def run_container(
    container_command: str,
    image_tag: str,
    mounts: list[Mount],
    env: ContainerEnv,
    resource_limits: ResourceLimits,
    network_args: list[str],
    command: list[str],
    stdin_data: str | None,
    on_stdout_line: Callable[[str], None] | None,
    timeout: int | None,
    process_tracker: _ProcessTracker,
    stderr_passthrough: bool = False,
) -> _RawResult:
    """Run a container and return the raw result.

    Builds the podman command with security flags, environment variables,
    mounts, resource limits, and network arguments, then executes it.

    Args:
        container_command: Container runtime (e.g. "podman").
        image_tag: Container image tag.
        mounts: Volume mounts for the container.
        env: Container environment variables.
        resource_limits: Resource limits (memory, cpus, pids).
        network_args: Network sandbox arguments (empty list if no sandbox).
        command: Command to run inside the container.
        stdin_data: Data to write to stdin, or None.
        on_stdout_line: Callback for each stdout line, or None.
        timeout: Timeout in seconds, or None for no timeout.
        process_tracker: Process tracker for stop() support.
        stderr_passthrough: If True, pass stderr to the parent process
            instead of capturing it.

    Returns:
        _RawResult with stdout, stderr, exit code, duration, and timeout flag.

    Raises:
        subprocess.SubprocessError: On unexpected subprocess failures.
    """
    cmd = [
        container_command,
        "run",
        "--rm",
        "-i",
        "--log-driver=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
    ]

    # Pass environment variables to container
    for env_var, value in env.variables.items():
        cmd.extend(["-e", f"{env_var}={value}"])

    # Add caller mounts
    for mount in mounts:
        ro = ":ro" if mount.read_only else ":rw"
        cmd.extend(["-v", f"{mount.host_path}:{mount.container_path}{ro}"])

    # Resource limits
    if resource_limits.memory is not None:
        cmd.extend(["--memory", resource_limits.memory])
        cmd.extend(["--memory-swap", resource_limits.memory])
    if resource_limits.cpus is not None:
        cmd.extend(["--cpus", str(resource_limits.cpus)])
    if resource_limits.pids_limit is not None:
        cmd.extend(["--pids-limit", str(resource_limits.pids_limit)])

    # Network sandbox args
    cmd.extend(network_args)

    cmd.append(image_tag)
    cmd.extend(command)

    # Log redacted command
    redacted_cmd = _redact_env_args(cmd)
    logger.debug("Full command: %s", " ".join(redacted_cmd))

    start_time = time.time()
    timed_out = False

    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None if stderr_passthrough else subprocess.PIPE,
        text=True,
    )

    # Track process for stop()
    process_tracker.set(process)

    try:
        # Write stdin data and close
        if process.stdin:
            if stdin_data is not None:
                process.stdin.write(stdin_data)
            process.stdin.close()

        # Read stdout line-by-line
        stdout_lines: list[str] = []
        if process.stdout:
            for line in process.stdout:
                stdout_lines.append(line)
                if on_stdout_line is not None:
                    on_stdout_line(line)

        # Wait for process to complete with timeout
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.error("Container execution timed out, killing process")
            process.kill()
            process.wait()
            timed_out = True

        # Read stderr if captured
        stderr_lines: list[str] = []
        if not stderr_passthrough and process.stderr:
            stderr_lines = process.stderr.readlines()

        stdout = "".join(stdout_lines)
        stderr = "".join(stderr_lines)
        exit_code = process.returncode

    finally:
        process_tracker.clear()

    elapsed = time.time() - start_time
    duration_ms = int(elapsed * 1000)

    logger.info(
        "Container execution completed in %.2fs (exit_code=%d)",
        elapsed,
        exit_code,
    )

    return _RawResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=duration_ms,
        timed_out=timed_out,
    )
