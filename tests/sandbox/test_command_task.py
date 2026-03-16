# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for CommandTask in lib/sandbox/task.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.sandbox._proxy import ProxyManager
from airut.sandbox.network_log import NetworkLog
from airut.sandbox.task import CommandTask, NetworkSandboxConfig, SandboxError
from airut.sandbox.types import (
    CommandResult,
    ContainerEnv,
    Mount,
    ResourceLimits,
)
from tests.sandbox.conftest import create_mock_popen


def _make_command_task(
    tmp_path: Path,
    *,
    image_tag: str = "airut:test123",
    mounts: list[Mount] | None = None,
    env: ContainerEnv | None = None,
    network_log_path: Path | None = None,
    network_sandbox: NetworkSandboxConfig | None = None,
    resource_limits: ResourceLimits | None = None,
    container_command: str = "podman",
    proxy_manager: ProxyManager | None = None,
) -> CommandTask:
    """Create a CommandTask with standard test params."""
    context_dir = tmp_path / "context"
    context_dir.mkdir(parents=True, exist_ok=True)

    return CommandTask(
        "test-cmd-id",
        image_tag=image_tag,
        mounts=mounts or [],
        env=env or ContainerEnv(),
        execution_context_dir=context_dir,
        network_log_path=network_log_path,
        network_sandbox=network_sandbox,
        resource_limits=resource_limits or ResourceLimits(),
        container_command=container_command,
        proxy_manager=proxy_manager,
    )


class TestCommandTaskInit:
    """Tests for CommandTask initialization."""

    def test_no_claude_dir(self, tmp_path: Path) -> None:
        """CommandTask does not create claude/ subdirectory."""
        _make_command_task(tmp_path)
        claude_dir = tmp_path / "context" / "claude"
        assert not claude_dir.exists()

    def test_no_event_log(self, tmp_path: Path) -> None:
        """CommandTask does not have event_log attribute."""
        task = _make_command_task(tmp_path)
        assert not hasattr(task, "event_log")
        assert not hasattr(task, "_event_log")

    def test_execution_context_id(self, tmp_path: Path) -> None:
        """execution_context_id property returns the context ID."""
        task = _make_command_task(tmp_path)
        assert task.execution_context_id == "test-cmd-id"

    def test_network_log_none(self, tmp_path: Path) -> None:
        """network_log is None when network_log_path not provided."""
        task = _make_command_task(tmp_path)
        assert task.network_log is None

    def test_network_log_created(self, tmp_path: Path) -> None:
        """network_log is created when network_log_path is provided."""
        log_path = tmp_path / "logs" / "network-sandbox.log"
        log_path.parent.mkdir()
        task = _make_command_task(tmp_path, network_log_path=log_path)
        assert isinstance(task.network_log, NetworkLog)


class TestCommandTaskExecute:
    """Tests for CommandTask.execute() method."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_returns_command_result(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() returns a CommandResult instance."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0, stdout="output\n", stderr=""
        )
        mock_process.stderr = None  # stderr_passthrough=True
        mock_popen.return_value = mock_process

        result = task.execute(["ls", "-la"])

        assert isinstance(result, CommandResult)
        assert result.exit_code == 0
        assert result.stdout == "output\n"
        assert result.timed_out is False
        assert result.duration_ms >= 0

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_exit_code_passthrough(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() passes through non-zero exit codes."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=42, stdout="", stderr="")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        result = task.execute(["false"])

        assert result.exit_code == 42

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_on_output_callback(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() calls on_output for each stdout line."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0, stdout="line1\nline2\n", stderr=""
        )
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        received: list[str] = []
        result = task.execute(["cmd"], on_output=received.append)

        assert result.exit_code == 0
        assert len(received) == 2
        assert received[0] == "line1\n"
        assert received[1] == "line2\n"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stderr_passthrough(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() uses stderr_passthrough=True."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["cmd"])

        popen_kwargs = mock_popen.call_args.kwargs
        assert popen_kwargs["stderr"] is None

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stdin_closed_immediately(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() does not write stdin data (stdin_data=None)."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["cmd"])

        mock_process.stdin.write.assert_not_called()
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_command_passed_to_container(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() passes command to container."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["echo", "hello", "world"])

        call_args = mock_popen.call_args[0][0]
        assert "echo" in call_args
        assert "hello" in call_args
        assert "world" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    @patch("airut.sandbox.task.sys")
    def test_stdout_written_to_sys_stdout(
        self, mock_sys: MagicMock, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() writes stdout lines to sys.stdout and flushes."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0, stdout="output\n", stderr=""
        )
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["cmd"])

        mock_sys.stdout.write.assert_called()
        mock_sys.stdout.flush.assert_called()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_unexpected_error_wrapped(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() wraps unexpected errors as SandboxError."""
        task = _make_command_task(tmp_path)
        mock_popen.side_effect = RuntimeError("Unexpected error")

        with pytest.raises(SandboxError, match="Execution failed"):
            task.execute(["cmd"])

    def test_sandbox_error_not_wrapped(self, tmp_path: Path) -> None:
        """execute() re-raises SandboxError without wrapping."""
        from airut.allowlist import Allowlist
        from airut.sandbox.secrets import SecretReplacements

        mock_proxy_manager = MagicMock()
        mock_proxy_manager.start_proxy.side_effect = SandboxError("Proxy error")

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        task = _make_command_task(
            tmp_path,
            network_sandbox=sandbox_config,
            proxy_manager=mock_proxy_manager,
        )

        with pytest.raises(SandboxError, match="Proxy error"):
            task.execute(["cmd"])


class TestCommandTaskStop:
    """Tests for CommandTask.stop() method."""

    def test_stop_no_running_process(self, tmp_path: Path) -> None:
        """stop() returns False when no process is running."""
        task = _make_command_task(tmp_path)
        assert task.stop() is False

    def test_stop_success(self, tmp_path: Path) -> None:
        """stop() terminates a running process."""
        task = _make_command_task(tmp_path)

        mock_process = MagicMock()
        mock_process.wait.return_value = None
        task._process_tracker._process = mock_process

        result = task.stop()

        assert result is True


class TestCommandTaskWithProxy:
    """Tests for CommandTask with network sandbox."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_proxy_start_and_stop(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() starts and stops proxy when network sandbox configured."""
        from airut.allowlist import Allowlist
        from airut.sandbox._proxy import _ContextProxy
        from airut.sandbox.secrets import SecretReplacements

        mock_proxy_manager = MagicMock()
        mock_context_proxy = _ContextProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_ip="10.199.1.100",
            subnet_octet=1,
        )
        mock_proxy_manager.start_proxy.return_value = mock_context_proxy

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        with patch(
            "airut.sandbox.task.get_network_args",
            return_value=["--network", "test-net", "--dns", "10.199.1.100"],
        ):
            task = _make_command_task(
                tmp_path,
                network_sandbox=sandbox_config,
                proxy_manager=mock_proxy_manager,
            )

            mock_process = create_mock_popen(returncode=0, stdout="", stderr="")
            mock_process.stderr = None
            mock_popen.return_value = mock_process

            task.execute(["cmd"])

        mock_proxy_manager.start_proxy.assert_called_once()
        mock_proxy_manager.stop_proxy.assert_called_once_with("test-cmd-id")
