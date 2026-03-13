# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for CommandTask in lib/sandbox/task.py."""

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
    network_log_dir: Path | None = None,
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
        network_log_dir=network_log_dir,
        network_sandbox=network_sandbox,
        resource_limits=resource_limits or ResourceLimits(),
        container_command=container_command,
        proxy_manager=proxy_manager,
    )


class TestCommandTaskInit:
    """Tests for CommandTask initialization."""

    def test_no_claude_dir_created(self, tmp_path: Path) -> None:
        """CommandTask does NOT create claude/ subdirectory."""
        _make_command_task(tmp_path)
        claude_dir = tmp_path / "context" / "claude"
        assert not claude_dir.exists()

    def test_no_event_log(self, tmp_path: Path) -> None:
        """CommandTask has no event_log attribute."""
        task = _make_command_task(tmp_path)
        assert not hasattr(task, "event_log")
        assert not hasattr(task, "_event_log")

    def test_network_log_none_when_no_dir(self, tmp_path: Path) -> None:
        """network_log is None when network_log_dir not provided."""
        task = _make_command_task(tmp_path)
        assert task.network_log is None

    def test_network_log_created_when_dir_provided(
        self, tmp_path: Path
    ) -> None:
        """network_log is created when network_log_dir is provided."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        task = _make_command_task(tmp_path, network_log_dir=log_dir)
        assert isinstance(task.network_log, NetworkLog)

    def test_execution_context_id_property(self, tmp_path: Path) -> None:
        """execution_context_id property returns the context ID."""
        task = _make_command_task(tmp_path)
        assert task.execution_context_id == "test-cmd-id"


class TestCommandTaskExecute:
    """Tests for CommandTask.execute() method."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_returns_command_result(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() returns CommandResult."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0, stdout="output")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        result = task.execute(["echo", "hello"])

        assert isinstance(result, CommandResult)
        assert result.exit_code == 0
        assert result.timed_out is False

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_exit_code_passthrough(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() returns the container's exit code."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=42, stdout="")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        result = task.execute(["false"])

        assert result.exit_code == 42

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_on_output_callback(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() invokes on_output callback for each stdout line."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0, stdout="line1\nline2\n")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        lines: list[str] = []
        result = task.execute(["make", "test"], on_output=lines.append)

        assert len(lines) == 2
        assert result.exit_code == 0

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stderr_passthrough(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() uses stderr passthrough (stderr=None in Popen)."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0)
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["echo", "hello"])

        popen_kwargs = mock_popen.call_args[1]
        assert popen_kwargs["stderr"] is None

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_stdin_closed_immediately(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() closes stdin immediately (no data sent)."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0)
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["echo", "hello"])

        mock_process.stdin.write.assert_not_called()
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    @patch("sys.stdout")
    def test_stdout_streamed_to_sys_stdout(
        self, mock_sys_stdout: MagicMock, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() streams stdout lines to sys.stdout."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0, stdout="line1\nline2\n")
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["make", "test"])

        # sys.stdout.write should have been called for each line
        write_calls = [
            call[0][0] for call in mock_sys_stdout.write.call_args_list
        ]
        assert "line1\n" in write_calls
        assert "line2\n" in write_calls

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_command_in_podman_args(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() passes command to container."""
        task = _make_command_task(tmp_path)

        mock_process = create_mock_popen(returncode=0)
        mock_process.stderr = None
        mock_popen.return_value = mock_process

        task.execute(["make", "-j4", "test"])

        cmd = mock_popen.call_args[0][0]
        img_idx = cmd.index("airut:test123")
        assert cmd[img_idx + 1] == "make"
        assert cmd[img_idx + 2] == "-j4"
        assert cmd[img_idx + 3] == "test"


class TestCommandTaskStop:
    """Tests for CommandTask.stop() method."""

    def test_stop_no_running_process(self, tmp_path: Path) -> None:
        """stop() returns False when no process is running."""
        task = _make_command_task(tmp_path)
        assert task.stop() is False

    def test_stop_success(self, tmp_path: Path) -> None:
        """stop() terminates a running process successfully."""
        task = _make_command_task(tmp_path)

        mock_process = MagicMock()
        mock_process.wait.return_value = None
        task._process_tracker._process = mock_process

        assert task.stop() is True


class TestCommandTaskErrors:
    """Tests for CommandTask error handling."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_sandbox_error_propagated(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """SandboxError is re-raised without wrapping."""
        task = _make_command_task(tmp_path)

        # Simulate SandboxError from inside run_container
        mock_popen.side_effect = SandboxError("Direct sandbox error")

        with pytest.raises(SandboxError, match="Direct sandbox error"):
            task.execute(["echo", "hello"])


class TestCommandTaskWithProxy:
    """Tests for CommandTask execution with network sandbox."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_proxy_start_and_stop(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() starts proxy before and stops after container run."""
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
            "airut.sandbox._run_container.get_network_args",
            return_value=["--network", "test-net"],
        ):
            task = _make_command_task(
                tmp_path,
                network_sandbox=sandbox_config,
                proxy_manager=mock_proxy_manager,
            )

            mock_process = create_mock_popen(returncode=0)
            mock_process.stderr = None
            mock_popen.return_value = mock_process

            task.execute(["echo", "hello"])

        mock_proxy_manager.start_proxy.assert_called_once()
        mock_proxy_manager.stop_proxy.assert_called_once_with("test-cmd-id")

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_proxy_stopped_on_failure(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """Proxy is stopped even when execution fails."""
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
            "airut.sandbox._run_container.get_network_args",
            return_value=["--network", "test-net"],
        ):
            task = _make_command_task(
                tmp_path,
                network_sandbox=sandbox_config,
                proxy_manager=mock_proxy_manager,
            )

            mock_popen.side_effect = RuntimeError("Container exploded")

            with pytest.raises(SandboxError):
                task.execute(["echo", "hello"])

        mock_proxy_manager.stop_proxy.assert_called_once_with("test-cmd-id")

    def test_non_sandbox_error_wrapped(self, tmp_path: Path) -> None:
        """Non-SandboxError during proxy setup is wrapped."""
        from airut.allowlist import Allowlist
        from airut.sandbox.secrets import SecretReplacements

        mock_proxy_manager = MagicMock()
        mock_proxy_manager.start_proxy.side_effect = RuntimeError("Boom")

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        task = _make_command_task(
            tmp_path,
            network_sandbox=sandbox_config,
            proxy_manager=mock_proxy_manager,
        )

        with pytest.raises(SandboxError, match="Execution failed"):
            task.execute(["echo"])
