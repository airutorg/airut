# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_run_container.py -- generic container execution."""

from __future__ import annotations

import signal
import subprocess
from unittest.mock import MagicMock, patch

from airut.sandbox._run_container import (
    _ProcessTracker,
    _redact_env_args,
    run_container,
)
from airut.sandbox.types import ContainerEnv, Mount, ResourceLimits
from tests.sandbox.conftest import create_mock_popen


class TestProcessTracker:
    """Tests for _ProcessTracker thread-safe process reference."""

    def test_initial_state(self) -> None:
        """Tracker starts with no process."""
        tracker = _ProcessTracker()
        assert tracker._process is None

    def test_set_and_clear(self) -> None:
        """set() stores process, clear() removes it."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()
        tracker.set(mock_process)
        assert tracker._process is mock_process
        tracker.clear()
        assert tracker._process is None

    def test_stop_no_process(self) -> None:
        """stop() returns False when no process is tracked."""
        tracker = _ProcessTracker()
        assert tracker.stop() is False

    def test_stop_success(self) -> None:
        """stop() sends SIGTERM and returns True."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()
        mock_process.wait.return_value = None
        tracker.set(mock_process)

        result = tracker.stop()

        assert result is True
        mock_process.send_signal.assert_called_once_with(signal.SIGTERM)
        mock_process.wait.assert_called_once_with(timeout=5)

    def test_stop_force_kill_on_timeout(self) -> None:
        """stop() kills process if SIGTERM times out."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()
        mock_process.wait.side_effect = [
            subprocess.TimeoutExpired("cmd", 5),
            None,
        ]
        tracker.set(mock_process)

        result = tracker.stop()

        assert result is True
        mock_process.send_signal.assert_called_once_with(signal.SIGTERM)
        mock_process.kill.assert_called_once()
        assert mock_process.wait.call_count == 2

    def test_stop_handles_exception(self) -> None:
        """stop() returns False on exception."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()
        mock_process.send_signal.side_effect = OSError("Process error")
        tracker.set(mock_process)

        result = tracker.stop()

        assert result is False

    def test_stop_does_not_hold_lock_during_wait(self) -> None:
        """stop() releases lock before blocking wait."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()

        # Track whether lock is held during wait
        lock_held_during_wait = False

        def check_lock_during_wait(**kwargs: object) -> None:
            nonlocal lock_held_during_wait
            # Try to acquire the lock; if we can, it's not held
            acquired = tracker._lock.acquire(blocking=False)
            if not acquired:
                lock_held_during_wait = True
            else:
                tracker._lock.release()

        mock_process.wait.side_effect = check_lock_during_wait
        tracker.set(mock_process)

        tracker.stop()

        assert not lock_held_during_wait


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
    """Tests for run_container function."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_builds_correct_command(self, mock_popen: MagicMock) -> None:
        """run_container builds podman command with correct flags."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test123",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo", "hello"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "podman"
        assert call_args[1] == "run"
        assert "--rm" in call_args
        assert "-i" in call_args
        assert "airut:test123" in call_args
        assert "echo" in call_args
        assert "hello" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_security_flags(self, mock_popen: MagicMock) -> None:
        """run_container includes security hardening flags."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert "--cap-drop=ALL" in call_args
        assert "--security-opt=no-new-privileges:true" in call_args
        assert "--log-driver=none" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_env_vars(self, mock_popen: MagicMock) -> None:
        """run_container passes environment variables."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        env = ContainerEnv(variables={"API_KEY": "secret", "TOKEN": "abc123"})
        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=env,
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert "-e" in call_args
        assert "API_KEY=secret" in call_args
        assert "TOKEN=abc123" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_mounts(self, mock_popen: MagicMock) -> None:
        """run_container passes mount configurations."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

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
        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=mounts,
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        cmd_str = " ".join(str(a) for a in call_args)
        assert "/host/workspace:/workspace:rw" in cmd_str
        assert "/host/config:/config:ro" in cmd_str

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_resource_limits_memory(self, mock_popen: MagicMock) -> None:
        """run_container adds --memory and --memory-swap flags."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(memory="2g"),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert "--memory" in call_args
        idx = call_args.index("--memory")
        assert call_args[idx + 1] == "2g"
        assert "--memory-swap" in call_args
        swap_idx = call_args.index("--memory-swap")
        assert call_args[swap_idx + 1] == "2g"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_resource_limits_cpus(self, mock_popen: MagicMock) -> None:
        """run_container adds --cpus flag."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(cpus=1.5),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert "--cpus" in call_args
        idx = call_args.index("--cpus")
        assert call_args[idx + 1] == "1.5"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_resource_limits_pids(self, mock_popen: MagicMock) -> None:
        """run_container adds --pids-limit flag."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(pids_limit=256),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert "--pids-limit" in call_args
        idx = call_args.index("--pids-limit")
        assert call_args[idx + 1] == "256"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_no_resource_limit_flags_when_none(
        self, mock_popen: MagicMock
    ) -> None:
        """run_container omits resource flags when all None."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert "--memory" not in call_args
        assert "--cpus" not in call_args
        assert "--pids-limit" not in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_network_args(self, mock_popen: MagicMock) -> None:
        """run_container includes network args in command."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=["--network", "my-net", "--dns", "10.0.0.1"],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert "--network" in call_args
        assert "my-net" in call_args
        assert "--dns" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stdin_data(self, mock_popen: MagicMock) -> None:
        """run_container writes stdin_data and closes stdin."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data="hello world",
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        mock_process.stdin.write.assert_called_once_with("hello world")
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stdin_closed_when_no_data(self, mock_popen: MagicMock) -> None:
        """run_container closes stdin even without data."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        mock_process.stdin.write.assert_not_called()
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_on_stdout_line_callback(self, mock_popen: MagicMock) -> None:
        """run_container calls on_stdout_line for each line."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(
            returncode=0, stdout="line1\nline2\nline3\n", stderr=""
        )
        mock_popen.return_value = mock_process

        lines: list[str] = []

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=lines.append,
            timeout=None,
            process_tracker=tracker,
        )

        assert len(lines) == 3
        assert lines[0] == "line1\n"
        assert lines[1] == "line2\n"
        assert lines[2] == "line3\n"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_timeout(self, mock_popen: MagicMock) -> None:
        """run_container sets timed_out flag on timeout."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(raise_timeout=True)
        mock_popen.return_value = mock_process

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=10,
            process_tracker=tracker,
        )

        assert result.timed_out is True
        mock_process.kill.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stderr_passthrough(self, mock_popen: MagicMock) -> None:
        """stderr_passthrough=True passes stderr=None to Popen."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        # For passthrough, stderr should be None
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
            stderr_passthrough=True,
        )

        # When passthrough=True, stderr=None is passed to Popen
        popen_kwargs = mock_popen.call_args.kwargs
        assert popen_kwargs["stderr"] is None
        # stderr in result should be empty (not captured)
        assert result.stderr == ""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_result_fields(self, mock_popen: MagicMock) -> None:
        """run_container returns _RawResult with correct fields."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(
            returncode=42, stdout="output", stderr="errors"
        )
        mock_popen.return_value = mock_process

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        assert result.exit_code == 42
        # create_mock_popen adds newline to each line
        assert "output" in result.stdout
        assert "errors" in result.stderr
        assert result.timed_out is False
        assert result.duration_ms >= 0

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_clears_process_tracker(self, mock_popen: MagicMock) -> None:
        """run_container clears process tracker after completion."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        assert tracker._process is None

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_custom_container_command(self, mock_popen: MagicMock) -> None:
        """run_container uses specified container command."""
        tracker = _ProcessTracker()
        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_popen.return_value = mock_process

        run_container(
            container_command="docker",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cmd"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "docker"
