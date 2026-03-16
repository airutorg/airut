# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_run_container.py -- generic container execution."""

from __future__ import annotations

import asyncio
import signal
from unittest.mock import AsyncMock, MagicMock, patch

from airut.sandbox._run_container import (
    _ProcessTracker,
    _redact_env_args,
    run_container,
)
from airut.sandbox.types import ContainerEnv, Mount, ResourceLimits


def _make_mock_process(
    *,
    returncode: int = 0,
    stdout_data: bytes = b"",
    stderr_data: bytes = b"",
    pid: int = 12345,
) -> MagicMock:
    """Create a mock asyncio.subprocess.Process.

    Returns a mock that behaves like the result of
    ``asyncio.create_subprocess_exec()``.
    """
    mock = MagicMock()
    mock.pid = pid
    mock.returncode = returncode

    # stdin
    mock.stdin = MagicMock()
    mock.stdin.write = MagicMock()
    mock.stdin.drain = AsyncMock()
    mock.stdin.close = MagicMock()
    mock.stdin.wait_closed = AsyncMock()

    # Async iterator for binary stream lines
    class _MockStream:
        def __init__(self, data_lines):
            self._lines = data_lines
            self._index = 0

        def __aiter__(self):
            return self

        async def __anext__(self):
            if self._index >= len(self._lines):
                raise StopAsyncIteration
            line = self._lines[self._index]
            self._index += 1
            return line

    # stdout as async iterator yielding lines
    stdout_lines = stdout_data.split(b"\n") if stdout_data else []
    stdout_lines = [line + b"\n" for line in stdout_lines if line]
    mock.stdout = _MockStream(stdout_lines)

    # stderr as async iterator
    stderr_lines = stderr_data.split(b"\n") if stderr_data else []
    stderr_lines = [line + b"\n" for line in stderr_lines if line]
    mock.stderr = _MockStream(stderr_lines)

    # wait
    mock.wait = AsyncMock(return_value=returncode)

    # kill
    mock.kill = MagicMock()

    return mock


class TestProcessTracker:
    """Tests for _ProcessTracker thread-safe PID-based process reference."""

    def test_initial_state(self) -> None:
        """Tracker starts with no PID."""
        tracker = _ProcessTracker()
        assert tracker._pid is None

    def test_set_and_clear(self) -> None:
        """set() stores PID, clear() removes it."""
        tracker = _ProcessTracker()
        tracker.set(12345)
        assert tracker._pid == 12345
        tracker.clear()
        assert tracker._pid is None

    def test_stop_no_process(self) -> None:
        """stop() returns False when no PID is tracked."""
        tracker = _ProcessTracker()
        assert tracker.stop() is False

    @patch("airut.sandbox._run_container.os.kill")
    @patch("airut.sandbox._run_container.threading.Timer")
    def test_stop_sends_sigterm(
        self, mock_timer: MagicMock, mock_kill: MagicMock
    ) -> None:
        """stop() sends SIGTERM and starts force-kill timer."""
        tracker = _ProcessTracker()
        tracker.set(12345)

        result = tracker.stop()

        assert result is True
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)
        mock_timer.assert_called_once()
        mock_timer.return_value.start.assert_called_once()

    @patch("airut.sandbox._run_container.os.kill")
    def test_stop_process_already_exited(self, mock_kill: MagicMock) -> None:
        """stop() returns False if process already exited."""
        tracker = _ProcessTracker()
        tracker.set(12345)
        mock_kill.side_effect = ProcessLookupError()

        result = tracker.stop()

        assert result is False

    @patch("airut.sandbox._run_container.os.kill")
    def test_force_kill_when_still_tracked(self, mock_kill: MagicMock) -> None:
        """_force_kill sends SIGKILL when PID is still tracked."""
        tracker = _ProcessTracker()
        tracker.set(12345)

        tracker._force_kill()

        mock_kill.assert_called_once_with(12345, signal.SIGKILL)

    @patch("airut.sandbox._run_container.os.kill")
    def test_force_kill_skipped_after_clear(self, mock_kill: MagicMock) -> None:
        """_force_kill is skipped if clear() was called."""
        tracker = _ProcessTracker()
        tracker.set(12345)
        tracker.clear()

        tracker._force_kill()

        mock_kill.assert_not_called()

    @patch("airut.sandbox._run_container.os.kill")
    def test_force_kill_handles_already_exited(
        self, mock_kill: MagicMock
    ) -> None:
        """_force_kill tolerates ProcessLookupError."""
        tracker = _ProcessTracker()
        tracker.set(12345)
        mock_kill.side_effect = ProcessLookupError()

        # Should not raise
        tracker._force_kill()


class TestRedactEnvArgs:
    """Tests for _redact_env_args helper."""

    def test_no_env_args(self) -> None:
        """Command without env args passes through unchanged."""
        cmd = ["podman", "run", "--rm", "image"]
        assert _redact_env_args(cmd) == cmd

    def test_redacts_env_values(self) -> None:
        """Env var values are replaced with ***."""
        cmd = [
            "podman",
            "run",
            "-e",
            "API_KEY=secret123",
            "-e",
            "TOKEN=abc",
            "image",
        ]
        result = _redact_env_args(cmd)
        assert result == [
            "podman",
            "run",
            "-e",
            "API_KEY=***",
            "-e",
            "TOKEN=***",
            "image",
        ]

    def test_preserves_other_flags(self) -> None:
        """Non-env flags are preserved."""
        cmd = ["podman", "run", "--memory", "2g", "-e", "KEY=val", "image"]
        result = _redact_env_args(cmd)
        assert "--memory" in result
        assert "2g" in result

    def test_no_equals_not_redacted(self) -> None:
        """Env args without = are passed through unchanged."""
        cmd = ["podman", "run", "-e", "KEY_ONLY", "image"]
        result = _redact_env_args(cmd)
        assert result == ["podman", "run", "-e", "KEY_ONLY", "image"]


class TestRunContainer:
    """Tests for async run_container function."""

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_builds_correct_command(self, mock_create: MagicMock) -> None:
        """run_container builds podman command with correct flags."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test123",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo", "hello"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert call_args[0] == "podman"
        assert call_args[1] == "run"
        assert "--rm" in call_args
        assert "-i" in call_args
        assert "airut:test123" in call_args
        assert "echo" in call_args
        assert "hello" in call_args

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_security_flags(self, mock_create: MagicMock) -> None:
        """run_container includes security hardening flags."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert "--cap-drop=ALL" in call_args
        assert "--security-opt=no-new-privileges:true" in call_args
        assert "--log-driver=none" in call_args

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_env_vars(self, mock_create: MagicMock) -> None:
        """run_container passes environment variables."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        env = ContainerEnv(variables={"API_KEY": "secret", "TOKEN": "abc123"})
        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=env,
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert "-e" in call_args
        assert "API_KEY=secret" in call_args
        assert "TOKEN=abc123" in call_args

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_mounts(self, mock_create: MagicMock) -> None:
        """run_container passes mount configurations."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        from pathlib import Path

        mounts = [
            Mount(
                host_path=Path("/host/workspace"),
                container_path="/workspace",
                read_only=False,
            ),
            Mount(
                host_path=Path("/host/config"),
                container_path="/config",
                read_only=True,
            ),
        ]
        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=mounts,
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        cmd_str = " ".join(str(a) for a in call_args)
        assert "/host/workspace:/workspace:rw" in cmd_str
        assert "/host/config:/config:ro" in cmd_str

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_resource_limits_memory(self, mock_create: MagicMock) -> None:
        """run_container adds --memory and --memory-swap flags."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(memory="2g"),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert "--memory" in call_args
        idx = call_args.index("--memory")
        assert call_args[idx + 1] == "2g"
        assert "--memory-swap" in call_args
        swap_idx = call_args.index("--memory-swap")
        assert call_args[swap_idx + 1] == "2g"

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_resource_limits_cpus(self, mock_create: MagicMock) -> None:
        """run_container adds --cpus flag."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(cpus=1.5),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert "--cpus" in call_args
        idx = call_args.index("--cpus")
        assert call_args[idx + 1] == "1.5"

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_resource_limits_pids(self, mock_create: MagicMock) -> None:
        """run_container adds --pids-limit flag."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(pids_limit=256),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert "--pids-limit" in call_args
        idx = call_args.index("--pids-limit")
        assert call_args[idx + 1] == "256"

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_no_resource_limit_flags_when_none(
        self, mock_create: MagicMock
    ) -> None:
        """run_container omits resource flags when all None."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert "--memory" not in call_args
        assert "--cpus" not in call_args
        assert "--pids-limit" not in call_args

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_network_args(self, mock_create: MagicMock) -> None:
        """run_container includes network args in command."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=["--network", "my-net", "--dns", "10.0.0.1"],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert "--network" in call_args
        assert "my-net" in call_args
        assert "--dns" in call_args

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_stdin_data(self, mock_create: MagicMock) -> None:
        """run_container writes stdin_data and closes stdin."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data="hello world",
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        mock_process.stdin.write.assert_called_once_with(b"hello world")
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_stdin_closed_when_no_data(
        self, mock_create: MagicMock
    ) -> None:
        """run_container closes stdin even without data."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        mock_process.stdin.write.assert_not_called()
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_on_stdout_line_callback(
        self, mock_create: MagicMock
    ) -> None:
        """run_container calls on_stdout_line for each line."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process(stdout_data=b"line1\nline2\nline3")
        mock_create.return_value = mock_process

        lines: list[str] = []

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=lines.append,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        assert len(lines) == 3
        assert lines[0] == "line1\n"
        assert lines[1] == "line2\n"
        assert lines[2] == "line3\n"

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_on_stderr_line_callback(
        self, mock_create: MagicMock
    ) -> None:
        """run_container calls on_stderr_line for each stderr line."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process(stderr_data=b"err1\nerr2")
        mock_create.return_value = mock_process

        lines: list[str] = []

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=lines.append,
            timeout=None,
            process_tracker=tracker,
        )

        assert len(lines) == 2
        assert lines[0] == "err1\n"
        assert lines[1] == "err2\n"

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_timeout(self, mock_create: MagicMock) -> None:
        """run_container sets timed_out flag on timeout."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        # Make _run() hang to trigger timeout
        mock_process.wait = AsyncMock(side_effect=lambda: asyncio.sleep(10))

        result = await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=0,
            process_tracker=tracker,
        )

        assert result.timed_out is True
        mock_process.kill.assert_called_once()

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_result_fields(self, mock_create: MagicMock) -> None:
        """run_container returns _RawResult with correct fields."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process(
            returncode=42,
            stdout_data=b"output",
            stderr_data=b"errors",
        )
        mock_create.return_value = mock_process

        result = await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        assert result.exit_code == 42
        assert "output" in result.stdout
        assert "errors" in result.stderr
        assert result.timed_out is False
        assert result.duration_ms >= 0

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_clears_process_tracker(self, mock_create: MagicMock) -> None:
        """run_container clears process tracker after completion."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        assert tracker._pid is None

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_custom_container_command(
        self, mock_create: MagicMock
    ) -> None:
        """run_container uses specified container command."""
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="docker",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_create.call_args[0]
        assert call_args[0] == "docker"

    @patch("airut.sandbox._run_container.asyncio.create_subprocess_exec")
    async def test_stream_buffer_limit_raised(
        self, mock_create: MagicMock
    ) -> None:
        """run_container sets a large stream buffer limit for long lines.

        Claude Code can emit single JSON lines exceeding the default 64 KiB
        asyncio StreamReader limit.  Verify that create_subprocess_exec is
        called with a limit well above the default.
        """
        tracker = _ProcessTracker()
        mock_process = _make_mock_process()
        mock_create.return_value = mock_process

        await run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            on_stderr_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_kwargs = mock_create.call_args[1]
        # Default asyncio limit is 2**16 = 64 KiB -- must be much larger
        assert "limit" in call_kwargs
        assert call_kwargs["limit"] > 2**16
