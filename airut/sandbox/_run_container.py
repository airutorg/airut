# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Generic container execution for the sandbox.

Extracts the container process lifecycle (command construction, process
management, stdin/stdout streaming, timeout handling) from the task layer.
Both AgentTask and CommandTask delegate to :func:`run_container`.
"""

from __future__ import annotations

import logging
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from airut.sandbox._network import get_network_args
from airut.sandbox._proxy import _ContextProxy
from airut.sandbox.types import ContainerEnv, Mount, ResourceLimits


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _RawResult:
    """Raw output from a container execution.

    Contains the unprocessed stdout/stderr, exit code, timing, and
    timeout status.  Callers convert this into domain-specific result
    types (ExecutionResult, CommandResult).

    Attributes:
        stdout: Raw stdout from the container.
        stderr: Raw stderr from the container (empty when passthrough).
        exit_code: Container process exit code.
        duration_ms: Execution duration in milliseconds.
        timed_out: Whether the container was killed by timeout.
    """

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    timed_out: bool


class _ProcessTracker:
    """Thread-safe process tracking for stop().

    Holds a reference to the running container process so that
    another thread can send SIGTERM/SIGKILL via :meth:`stop`.
    """

    def __init__(self) -> None:
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

    def set(self, process: subprocess.Popen[str]) -> None:
        """Register the active process."""
        with self._lock:
            self._process = process

    def clear(self) -> None:
        """Clear the process reference after completion."""
        with self._lock:
            self._process = None

    def stop(self) -> bool:
        """Stop the tracked process. Returns True if stopped."""
        with self._lock:
            process = self._process
            if process is None:
                return False
            try:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                return True
            except Exception:
                return False


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
    """Run a command inside a container.

    Constructs the full podman/docker command, starts the process,
    handles stdin/stdout streaming, enforces timeouts, and collects
    results.

    Args:
        container_command: Container runtime (``podman`` or ``docker``).
        image_tag: Container image tag.
        mounts: Volume mounts for the container.
        env: Container environment variables.
        resource_limits: CPU, memory, PID limits.
        network_args: Pre-built network arguments (from proxy setup).
        command: The command to run inside the container.
        stdin_data: Data to write to stdin.  ``None`` closes stdin
            immediately.
        on_stdout_line: Callback invoked for each stdout line.
        timeout: Maximum execution time in seconds.  ``None`` means
            no timeout.
        process_tracker: Thread-safe tracker for stop() support.
        stderr_passthrough: When True, stderr goes directly to the
            parent process (``stderr=None``).  When False, stderr is
            captured (``stderr=PIPE``).

    Returns:
        _RawResult with stdout, stderr, exit code, timing, and
        timeout status.

    Raises:
        Exception: Propagated from subprocess.Popen on infrastructure
            failures.
    """
    # Build command
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
    limits = resource_limits
    if limits.memory is not None:
        cmd.extend(["--memory", limits.memory])
        cmd.extend(["--memory-swap", limits.memory])
    if limits.cpus is not None:
        cmd.extend(["--cpus", str(limits.cpus)])
    if limits.pids_limit is not None:
        cmd.extend(["--pids-limit", str(limits.pids_limit)])

    # Network sandbox args
    cmd.extend(network_args)

    cmd.append(image_tag)

    # Append the command to run inside the container
    cmd.extend(command)

    # Redact secrets from logged command
    redacted_cmd = _redact_env_args(cmd)
    logger.debug("Full command: %s", " ".join(redacted_cmd))

    start_time = time.time()
    timed_out = False

    stderr_arg = None if stderr_passthrough else subprocess.PIPE

    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr_arg,
        text=True,
    )

    # Track process for stop()
    process_tracker.set(process)

    try:
        # Send stdin data and close
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

        # Read stderr (only when captured)
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

    return _RawResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=duration_ms,
        timed_out=timed_out,
    )


def build_network_args(task_proxy: _ContextProxy | None) -> list[str]:
    """Build network arguments from a task proxy.

    Args:
        task_proxy: Active proxy context, or None if no proxy.

    Returns:
        List of podman command-line arguments for network setup.
    """
    if task_proxy is None:
        return []
    return get_network_args(task_proxy.network_name, task_proxy.proxy_ip)


def _redact_env_args(cmd: list[str]) -> list[str]:
    """Redact environment variable values from a command list.

    Args:
        cmd: Full podman command list.

    Returns:
        Copy with ``-e VAR=value`` redacted to ``-e VAR=***``.
    """
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
    return redacted_cmd
