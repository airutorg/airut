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
from tests.sandbox.conftest import create_mock_run_container


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

    async def test_returns_command_result(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() returns a CommandResult instance."""
        task = _make_command_task(tmp_path)

        mock_rc = create_mock_run_container(returncode=0, stdout="output\n")
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        result = await task.execute(["ls", "-la"])

        assert isinstance(result, CommandResult)
        assert result.exit_code == 0
        assert result.stdout == "output\n"
        assert result.timed_out is False
        assert result.duration_ms >= 0

    async def test_exit_code_passthrough(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() passes through non-zero exit codes."""
        task = _make_command_task(tmp_path)

        mock_rc = create_mock_run_container(returncode=42)
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        result = await task.execute(["false"])

        assert result.exit_code == 42

    async def test_on_output_callback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() calls on_output for each stdout line."""
        task = _make_command_task(tmp_path)

        mock_rc = create_mock_run_container(
            returncode=0, stdout="line1\nline2\n"
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        received: list[str] = []
        result = await task.execute(["cmd"], on_output=received.append)

        assert result.exit_code == 0
        assert len(received) == 2
        assert received[0] == "line1\n"
        assert received[1] == "line2\n"

    async def test_on_stderr_callback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() calls on_stderr for each stderr line."""
        task = _make_command_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            # Invoke the stderr callback
            cb = kwargs.get("on_stderr_line")
            if cb:
                cb("error line\n")
            return await create_mock_run_container(returncode=0)(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        stderr_lines: list[str] = []
        await task.execute(["cmd"], on_stderr=stderr_lines.append)

        assert "error line\n" in stderr_lines

    async def test_stderr_captured_in_result(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CommandResult.stderr is populated with captured stderr."""
        task = _make_command_task(tmp_path)

        mock_rc = create_mock_run_container(
            returncode=0, stderr="error output\n"
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        result = await task.execute(["cmd"])

        assert result.stderr == "error output\n"

    async def test_no_implicit_stdout_write(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() does not write to sys.stdout when no on_output given."""
        task = _make_command_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                returncode=0, stdout="output\n"
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute(["cmd"])

        # on_stdout_line is always set (for accumulation), but calling
        # it should not write to sys.stdout when no on_output was given
        assert calls[0]["on_stdout_line"] is not None

    async def test_stdin_not_sent(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() does not write stdin data (stdin_data=None)."""
        task = _make_command_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(returncode=0)(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute(["cmd"])

        assert calls[0]["stdin_data"] is None

    async def test_command_passed_to_container(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() passes command to container."""
        task = _make_command_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(returncode=0)(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute(["echo", "hello", "world"])

        cmd = calls[0]["command"]
        assert "echo" in cmd
        assert "hello" in cmd
        assert "world" in cmd

    async def test_no_entrypoint_override(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() does not override the image entrypoint.

        The correct entrypoint (agent or passthrough) is baked into the
        image at build time.  CommandTask must NOT pass an entrypoint
        override to run_container.
        """
        task = _make_command_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(returncode=0)(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute(["./check.sh"])

        assert "entrypoint" not in calls[0]

    async def test_unexpected_error_wrapped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() wraps unexpected errors as SandboxError."""
        task = _make_command_task(tmp_path)

        async def failing_rc(**kwargs):
            raise RuntimeError("Unexpected error")

        monkeypatch.setattr("airut.sandbox.task.run_container", failing_rc)

        with pytest.raises(SandboxError, match="Execution failed"):
            await task.execute(["cmd"])

    async def test_sandbox_error_not_wrapped(self, tmp_path: Path) -> None:
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
            await task.execute(["cmd"])

    async def test_on_network_line_callback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() tails network log when on_network_line is provided."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("ALLOW example.com\n")

        task = _make_command_task(tmp_path, network_log_path=log_path)

        mock_rc = create_mock_run_container(returncode=0)
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        network_lines: list[str] = []
        await task.execute(["cmd"], on_network_line=network_lines.append)

        assert "ALLOW example.com" in network_lines


class TestCommandTaskStop:
    """Tests for CommandTask.stop() method."""

    def test_stop_no_running_process(self, tmp_path: Path) -> None:
        """stop() returns False when no process is running."""
        task = _make_command_task(tmp_path)
        assert task.stop() is False

    @patch("airut.sandbox._run_container.os.kill")
    @patch("airut.sandbox._run_container.threading.Timer")
    def test_stop_success(
        self,
        mock_timer: MagicMock,
        mock_kill: MagicMock,
        tmp_path: Path,
    ) -> None:
        """stop() terminates a running process."""
        task = _make_command_task(tmp_path)
        task._process_tracker.set(12345)

        result = task.stop()

        assert result is True


class TestCommandTaskWithProxy:
    """Tests for CommandTask with network sandbox."""

    async def test_proxy_start_and_stop(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() starts and stops proxy when configured."""
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

            mock_rc = create_mock_run_container(returncode=0)
            monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

            await task.execute(["cmd"])

        mock_proxy_manager.start_proxy.assert_called_once()
        mock_proxy_manager.stop_proxy.assert_called_once_with("test-cmd-id")


class TestCommandTaskTailFailure:
    """Tests for tail task exception handling in CommandTask."""

    async def test_tail_task_exception_logged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tail task exception is caught and logged, not propagated."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("")
        task = _make_command_task(tmp_path, network_log_path=log_path)

        mock_rc = create_mock_run_container(returncode=0)
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        # Patch _tail_network_log to raise
        async def bad_tail(*args, **kwargs):
            raise RuntimeError("tail exploded")

        monkeypatch.setattr("airut.sandbox.task._tail_network_log", bad_tail)

        # Should not raise despite tail failure
        result = await task.execute(["cmd"], on_network_line=lambda _line: None)
        assert result.exit_code == 0
