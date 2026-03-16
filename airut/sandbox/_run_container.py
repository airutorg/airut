# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Generic container execution for the sandbox.

Extracts the container subprocess lifecycle from task-specific logic so
that both ``AgentTask`` (Claude Code) and ``CommandTask`` (arbitrary
commands) can share the same execution engine.

Uses ``asyncio.create_subprocess_exec`` for concurrent stdout/stderr
reading, eliminating the deadlock risk of sequential pipe reads.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
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
        stderr: Raw stderr text.
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
    """Thread-safe PID reference for stop() support.

    Holds the raw PID of the currently running subprocess and provides
    a ``stop()`` method that can be called from another thread to
    terminate the process via ``os.kill()``.
    """

    def __init__(self) -> None:
        self._pid: int | None = None
        self._lock = threading.Lock()

    def set(self, pid: int) -> None:
        """Set the active process PID.

        Args:
            pid: The running subprocess PID.
        """
        with self._lock:
            self._pid = pid

    def clear(self) -> None:
        """Clear the PID reference after completion."""
        with self._lock:
            self._pid = None

    def stop(self) -> bool:
        """Stop the tracked process from another thread.

        Sends SIGTERM and returns immediately. A background timer sends
        SIGKILL after 5 seconds if the process has not exited.

        Returns:
            True if a signal was sent, False if nothing running.
        """
        with self._lock:
            pid = self._pid
        if pid is None:
            return False

        logger.info("Stopping tracked process (pid=%d)", pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return False

        threading.Timer(5.0, self._force_kill).start()
        return True

    def _force_kill(self) -> None:
        """Send SIGKILL if the process is still tracked."""
        with self._lock:
            pid = self._pid
        if pid is None:
            return  # clear() was called -- process already reaped
        logger.warning(
            "Process did not terminate gracefully, sending SIGKILL (pid=%d)",
            pid,
        )
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # already exited


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


async def run_container(
    container_command: str,
    image_tag: str,
    mounts: list[Mount],
    env: ContainerEnv,
    resource_limits: ResourceLimits,
    network_args: list[str],
    command: list[str],
    stdin_data: str | None,
    on_stdout_line: Callable[[str], None] | None,
    on_stderr_line: Callable[[str], None] | None,
    timeout: int | None,
    process_tracker: _ProcessTracker,
) -> _RawResult:
    """Run a container and return the raw result.

    Builds the podman command with security flags, environment variables,
    mounts, resource limits, and network arguments, then executes it
    with concurrent stdout/stderr reading via asyncio.

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
        on_stderr_line: Callback for each stderr line, or None.
        timeout: Timeout in seconds, or None for no timeout.
        process_tracker: Process tracker for stop() support.

    Returns:
        _RawResult with stdout, stderr, exit code, duration, and
        timeout flag.
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

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Track process PID for stop()
    process_tracker.set(process.pid)

    try:
        # Write stdin and close
        if process.stdin:
            if stdin_data is not None:
                process.stdin.write(stdin_data.encode())
                await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()

        # Mutable accumulators that survive cancellation
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        async def read_lines(
            stream: asyncio.StreamReader,
            lines: list[str],
            callback: Callable[[str], None] | None,
        ) -> None:
            # Use fixed-size read() instead of readline() so that
            # individual lines are not constrained by the asyncio
            # StreamReader buffer limit.  Complete lines (including the
            # trailing newline) are delivered as they arrive; any
            # remaining data after EOF is flushed as a final
            # unterminated line.
            buf = bytearray()
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    if buf:
                        line = buf.decode("utf-8", errors="replace")
                        lines.append(line)
                        if callback is not None:
                            callback(line)
                    break
                buf.extend(chunk)
                while True:
                    pos = buf.find(b"\n")
                    if pos == -1:
                        break
                    raw_line = bytes(buf[: pos + 1])
                    del buf[: pos + 1]
                    line = raw_line.decode("utf-8", errors="replace")
                    lines.append(line)
                    if callback is not None:
                        callback(line)

        async def _run() -> None:
            # stdout/stderr are always set because we pass PIPE above
            assert process.stdout is not None
            assert process.stderr is not None
            await asyncio.gather(
                read_lines(process.stdout, stdout_lines, on_stdout_line),
                read_lines(process.stderr, stderr_lines, on_stderr_line),
            )
            await process.wait()

        try:
            await asyncio.wait_for(_run(), timeout=timeout)
            timed_out = False
        except TimeoutError:
            logger.error("Container execution timed out, killing process")
            process.kill()
            await process.wait()
            timed_out = True

        stdout = "".join(stdout_lines)
        stderr = "".join(stderr_lines)
        exit_code = process.returncode or 0

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
