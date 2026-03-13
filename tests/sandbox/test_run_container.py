# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_run_container.py -- generic container execution."""

import signal
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from airut.sandbox._run_container import (
    _ProcessTracker,
    _RawResult,
    _redact_env_args,
    run_container,
)
from airut.sandbox.types import ContainerEnv, Mount, ResourceLimits
from tests.sandbox.conftest import create_mock_popen


class TestRawResult:
    """Tests for _RawResult dataclass."""

    def test_fields(self) -> None:
        """_RawResult stores all fields correctly."""
        result = _RawResult(
            stdout="output",
            stderr="errors",
            exit_code=0,
            duration_ms=1234,
            timed_out=False,
        )
        assert result.stdout == "output"
        assert result.stderr == "errors"
        assert result.exit_code == 0
        assert result.duration_ms == 1234
        assert result.timed_out is False

    def test_frozen(self) -> None:
        """_RawResult is frozen (immutable)."""
        result = _RawResult(
            stdout="", stderr="", exit_code=0, duration_ms=0, timed_out=False
        )
        with pytest.raises(AttributeError):
            result.exit_code = 1  # type: ignore[misc]


class TestProcessTracker:
    """Tests for _ProcessTracker."""

    def test_stop_returns_false_when_no_process(self) -> None:
        """stop() returns False when no process is tracked."""
        tracker = _ProcessTracker()
        assert tracker.stop() is False

    def test_stop_sends_sigterm(self) -> None:
        """stop() sends SIGTERM to tracked process."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()
        mock_process.wait.return_value = None

        tracker.set(mock_process)
        result = tracker.stop()

        assert result is True
        mock_process.send_signal.assert_called_once_with(signal.SIGTERM)
        mock_process.wait.assert_called_once_with(timeout=5)

    def test_stop_force_kills_on_timeout(self) -> None:
        """stop() force kills if SIGTERM doesn't work within timeout."""
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

    def test_stop_returns_false_on_exception(self) -> None:
        """stop() returns False on exception."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()
        mock_process.send_signal.side_effect = OSError("gone")

        tracker.set(mock_process)
        result = tracker.stop()

        assert result is False

    def test_clear_removes_process(self) -> None:
        """clear() removes process reference."""
        tracker = _ProcessTracker()
        mock_process = MagicMock()
        tracker.set(mock_process)
        tracker.clear()

        assert tracker.stop() is False

    def test_set_replaces_process(self) -> None:
        """set() replaces previous process reference."""
        tracker = _ProcessTracker()
        process1 = MagicMock()
        process2 = MagicMock()
        process2.wait.return_value = None

        tracker.set(process1)
        tracker.set(process2)
        tracker.stop()

        process1.send_signal.assert_not_called()
        process2.send_signal.assert_called_once()


class TestRunContainer:
    """Tests for run_container function."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_builds_command_with_security_flags(
        self, mock_popen: MagicMock
    ) -> None:
        """run_container builds command with security flags."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
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

        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "run"
        assert "--rm" in cmd
        assert "-i" in cmd
        assert "--log-driver=none" in cmd
        assert "--cap-drop=ALL" in cmd
        assert "--security-opt=no-new-privileges:true" in cmd

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_env_vars_in_command(self, mock_popen: MagicMock) -> None:
        """run_container includes environment variables."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(variables={"KEY": "val", "KEY2": "val2"}),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        cmd = mock_popen.call_args[0][0]
        assert "KEY=val" in cmd
        assert "KEY2=val2" in cmd

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_mounts_in_command(self, mock_popen: MagicMock) -> None:
        """run_container includes volume mounts."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()
        from pathlib import Path

        mounts = [
            Mount(
                host_path=Path("/host/work"),
                container_path="/container/work",
                read_only=False,
            ),
            Mount(
                host_path=Path("/host/config"),
                container_path="/container/config",
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
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        cmd = mock_popen.call_args[0][0]
        cmd_str = " ".join(cmd)
        assert "/host/work:/container/work:rw" in cmd_str
        assert "/host/config:/container/config:ro" in cmd_str

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_resource_limits_in_command(self, mock_popen: MagicMock) -> None:
        """run_container includes resource limit flags."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(
                memory="2g", cpus=1.5, pids_limit=256
            ),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        cmd = mock_popen.call_args[0][0]
        assert "--memory" in cmd
        mem_idx = cmd.index("--memory")
        assert cmd[mem_idx + 1] == "2g"
        assert "--memory-swap" in cmd
        swap_idx = cmd.index("--memory-swap")
        assert cmd[swap_idx + 1] == "2g"
        assert "--cpus" in cmd
        cpu_idx = cmd.index("--cpus")
        assert cmd[cpu_idx + 1] == "1.5"
        assert "--pids-limit" in cmd
        pids_idx = cmd.index("--pids-limit")
        assert cmd[pids_idx + 1] == "256"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stdin_data_written_and_closed(self, mock_popen: MagicMock) -> None:
        """run_container writes stdin_data and closes stdin."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["cat"],
            stdin_data="hello world",
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        mock_process.stdin.write.assert_called_once_with("hello world")
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stdin_data_none_closes_immediately(
        self, mock_popen: MagicMock
    ) -> None:
        """run_container with stdin_data=None closes stdin immediately."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        mock_process.stdin.write.assert_not_called()
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_on_stdout_line_callback(self, mock_popen: MagicMock) -> None:
        """run_container invokes callback for each stdout line."""
        mock_process = create_mock_popen(
            returncode=0, stdout="line1\nline2\nline3"
        )
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        lines_received: list[str] = []

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=lambda line: lines_received.append(line),
            timeout=None,
            process_tracker=tracker,
        )

        assert len(lines_received) == 3
        assert result.stdout != ""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_timeout_handling(self, mock_popen: MagicMock) -> None:
        """run_container handles timeout correctly."""
        mock_process = create_mock_popen(raise_timeout=True)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["sleep", "999"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=10,
            process_tracker=tracker,
        )

        assert result.timed_out is True
        mock_process.kill.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stderr_passthrough_true(self, mock_popen: MagicMock) -> None:
        """stderr_passthrough=True uses stderr=None."""
        mock_process = create_mock_popen(returncode=0)
        # With passthrough, stderr won't be set to PIPE
        mock_process.stderr = None
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
            stderr_passthrough=True,
        )

        # Verify stderr=None was passed (passthrough)
        popen_kwargs = mock_popen.call_args[1]
        assert popen_kwargs["stderr"] is None
        assert result.stderr == ""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stderr_passthrough_false(self, mock_popen: MagicMock) -> None:
        """stderr_passthrough=False uses stderr=PIPE."""
        mock_process = create_mock_popen(
            returncode=0, stderr="some error output"
        )
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
            stderr_passthrough=False,
        )

        popen_kwargs = mock_popen.call_args[1]
        assert popen_kwargs["stderr"] == subprocess.PIPE
        assert "some error output" in result.stderr

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_network_args_passed(self, mock_popen: MagicMock) -> None:
        """run_container includes network args in command."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=["--network", "test-net", "--dns", "10.0.0.1"],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        cmd = mock_popen.call_args[0][0]
        assert "--network" in cmd
        net_idx = cmd.index("--network")
        assert cmd[net_idx + 1] == "test-net"
        assert "--dns" in cmd

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_command_appended_at_end(self, mock_popen: MagicMock) -> None:
        """run_container appends command after image tag."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["make", "test"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        cmd = mock_popen.call_args[0][0]
        img_idx = cmd.index("airut:test")
        assert cmd[img_idx + 1] == "make"
        assert cmd[img_idx + 2] == "test"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_clears_tracker_after_completion(
        self, mock_popen: MagicMock
    ) -> None:
        """run_container clears process tracker after completion."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        assert tracker._process is None

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_returns_raw_result(self, mock_popen: MagicMock) -> None:
        """run_container returns _RawResult with correct fields."""
        mock_process = create_mock_popen(
            returncode=42, stdout="out", stderr="err"
        )
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        result = run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        assert isinstance(result, _RawResult)
        assert result.exit_code == 42
        assert "out" in result.stdout
        assert "err" in result.stderr
        assert result.timed_out is False
        assert result.duration_ms >= 0

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_no_resource_limit_flags_when_none(
        self, mock_popen: MagicMock
    ) -> None:
        """run_container omits resource flags when all None."""
        mock_process = create_mock_popen(returncode=0)
        mock_popen.return_value = mock_process
        tracker = _ProcessTracker()

        run_container(
            container_command="podman",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            resource_limits=ResourceLimits(),
            network_args=[],
            command=["echo"],
            stdin_data=None,
            on_stdout_line=None,
            timeout=None,
            process_tracker=tracker,
        )

        cmd = mock_popen.call_args[0][0]
        assert "--memory" not in cmd
        assert "--cpus" not in cmd
        assert "--pids-limit" not in cmd


class TestRedactEnvArgs:
    """Tests for _redact_env_args helper."""

    def test_redacts_env_values(self) -> None:
        """Redacts -e VAR=value pairs."""
        cmd = ["podman", "run", "-e", "SECRET=s3cr3t", "image:tag"]
        redacted = _redact_env_args(cmd)
        assert "-e" in redacted
        assert "SECRET=***" in redacted
        assert "s3cr3t" not in " ".join(redacted)

    def test_preserves_non_env_args(self) -> None:
        """Preserves non-env arguments."""
        cmd = ["podman", "run", "--rm", "-i", "image:tag"]
        redacted = _redact_env_args(cmd)
        assert redacted == cmd

    def test_handles_multiple_env_vars(self) -> None:
        """Handles multiple -e flags."""
        cmd = [
            "podman",
            "run",
            "-e",
            "A=1",
            "-e",
            "B=2",
            "image:tag",
        ]
        redacted = _redact_env_args(cmd)
        assert "A=***" in redacted
        assert "B=***" in redacted
