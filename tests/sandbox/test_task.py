# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/task.py -- per-execution AgentTask class."""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.claude_output import StreamEvent
from airut.claude_output.types import EventType
from airut.sandbox._proxy import ProxyManager
from airut.sandbox.event_log import EventLog
from airut.sandbox.network_log import NetworkLog
from airut.sandbox.task import (
    AgentTask,
    NetworkSandboxConfig,
    SandboxError,
    _tail_network_log,
)
from airut.sandbox.types import ContainerEnv, Mount, Outcome, ResourceLimits
from tests.sandbox.conftest import create_mock_run_container


def _make_task(
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
    claude_binary_path: Path | None = None,
) -> AgentTask:
    """Create an AgentTask with standard test params."""
    context_dir = tmp_path / "context"
    context_dir.mkdir(parents=True, exist_ok=True)

    return AgentTask(
        "test-task-id",
        image_tag=image_tag,
        mounts=mounts or [],
        env=env or ContainerEnv(),
        execution_context_dir=context_dir,
        network_log_path=network_log_path,
        network_sandbox=network_sandbox,
        resource_limits=resource_limits or ResourceLimits(),
        container_command=container_command,
        proxy_manager=proxy_manager,
        claude_binary_path=claude_binary_path,
    )


class TestAgentTaskInit:
    """Tests for AgentTask initialization."""

    def test_creates_claude_dir(self, tmp_path: Path) -> None:
        """Init creates claude/ subdirectory in execution_context_dir."""
        _make_task(tmp_path)
        claude_dir = tmp_path / "context" / "claude"
        assert claude_dir.exists()

    def test_event_log_property(self, tmp_path: Path) -> None:
        """event_log property returns EventLog."""
        task = _make_task(tmp_path)
        assert isinstance(task.event_log, EventLog)

    def test_network_log_none_when_no_path(self, tmp_path: Path) -> None:
        """network_log is None when network_log_path not provided."""
        task = _make_task(tmp_path)
        assert task.network_log is None

    def test_network_log_created_when_path_provided(
        self, tmp_path: Path
    ) -> None:
        """network_log is created when network_log_path is provided."""
        log_path = tmp_path / "logs" / "network-sandbox.log"
        log_path.parent.mkdir()
        task = _make_task(tmp_path, network_log_path=log_path)
        assert isinstance(task.network_log, NetworkLog)

    def test_execution_context_id_property(self, tmp_path: Path) -> None:
        """execution_context_id property returns the context ID."""
        task = _make_task(tmp_path)
        assert task.execution_context_id == "test-task-id"


class TestAgentTaskExecute:
    """Tests for AgentTask.execute() method."""

    async def test_execute_success(
        self,
        tmp_path: Path,
        sample_streaming_output: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() returns ExecutionResult with parsed output."""
        task = _make_task(tmp_path)

        mock_rc = create_mock_run_container(
            returncode=0, stdout=sample_streaming_output
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        result = await task.execute("Test prompt")

        assert result.outcome == Outcome.SUCCESS
        assert result.session_id == "test-session-123"
        assert result.response_text == "I've completed the task."

    async def test_execute_timeout(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() returns TIMEOUT outcome when container times out."""
        task = _make_task(tmp_path, resource_limits=ResourceLimits(timeout=10))

        mock_rc = create_mock_run_container(timed_out=True)
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        result = await task.execute("Test prompt")

        assert result.outcome == Outcome.TIMEOUT

    async def test_execute_nonzero_exit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() returns CONTAINER_FAILED on non-zero exit code."""
        task = _make_task(tmp_path)

        mock_rc = create_mock_run_container(
            returncode=1, stderr="Error occurred"
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        result = await task.execute("Test prompt")

        assert result.outcome == Outcome.CONTAINER_FAILED

    async def test_execute_without_session_id(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() without session_id does not include --resume."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt")

        cmd = calls[0]["command"]
        assert "--resume" not in cmd

    async def test_execute_with_session_id(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() with session_id includes --resume flag."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute(
            "Test prompt",
            session_id="c7886694-f2cb-4861-ad3c-fbe0964eb4df",
        )

        cmd = calls[0]["command"]
        assert "--resume" in cmd
        resume_index = cmd.index("--resume")
        assert cmd[resume_index + 1] == "c7886694-f2cb-4861-ad3c-fbe0964eb4df"

    async def test_execute_model_parameter(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() passes model via --model CLI parameter."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt", model="opus")

        cmd = calls[0]["command"]
        assert "--model" in cmd
        model_index = cmd.index("--model")
        assert cmd[model_index + 1] == "opus"

    async def test_execute_default_model(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() uses sonnet as default model."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt")

        cmd = calls[0]["command"]
        assert "--model" in cmd
        model_index = cmd.index("--model")
        assert cmd[model_index + 1] == "sonnet"

    async def test_execute_effort_parameter(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() passes effort via --effort CLI parameter."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt", effort="max")

        cmd = calls[0]["command"]
        assert "--effort" in cmd
        effort_index = cmd.index("--effort")
        assert cmd[effort_index + 1] == "max"

    async def test_execute_effort_omitted_by_default(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() omits --effort when not specified."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt")

        cmd = calls[0]["command"]
        assert "--effort" not in cmd

    async def test_execute_with_callback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() invokes callback for each parsed event."""
        task = _make_task(tmp_path)

        streaming_output = (
            '{"type": "system", "subtype": "init", "session_id": "s1"}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "test"}]}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "done"}\n'
        )
        mock_rc = create_mock_run_container(
            returncode=0, stdout=streaming_output
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        events_received: list[StreamEvent] = []

        def callback(event: StreamEvent) -> None:
            events_received.append(event)

        await task.execute("Test prompt", on_event=callback)

        assert len(events_received) == 3
        assert events_received[0].event_type == EventType.SYSTEM
        assert events_received[1].event_type == EventType.ASSISTANT
        assert events_received[2].event_type == EventType.RESULT

    async def test_execute_callback_non_json_lines_skipped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Callback is not invoked for non-JSON lines."""
        task = _make_task(tmp_path)

        streaming_output = (
            "Non-JSON line\n"
            '{"type": "system", "session_id": "s1"}\n'
            "Another non-JSON\n"
            '{"type": "result", "session_id": "s1", "result": "done"}\n'
        )
        mock_rc = create_mock_run_container(
            returncode=0, stdout=streaming_output
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        events_received: list[StreamEvent] = []

        def callback(event: StreamEvent) -> None:
            events_received.append(event)

        await task.execute("Test prompt", on_event=callback)

        # Only 2 valid JSON events should be received
        assert len(events_received) == 2

    async def test_execute_sends_prompt_on_stdin(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() writes prompt to stdin_data."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("My test prompt")

        assert calls[0]["stdin_data"] == "My test prompt"

    async def test_execute_mounts_claude_dir(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() mounts claude/ directory at /root/.claude."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt")

        mounts = calls[0]["mounts"]
        claude_mount = [
            m for m in mounts if m.container_path == "/root/.claude"
        ]
        assert len(claude_mount) == 1
        assert not claude_mount[0].read_only

    async def test_execute_mounts_claude_binary(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() mounts claude binary when path provided."""
        binary = tmp_path / "claude"
        binary.write_bytes(b"binary")
        task = _make_task(tmp_path, claude_binary_path=binary)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt")

        mounts = calls[0]["mounts"]
        binary_mount = [
            m for m in mounts if m.container_path == "/opt/claude/claude"
        ]
        assert len(binary_mount) == 1
        assert binary_mount[0].host_path == binary
        assert binary_mount[0].read_only

    async def test_execute_unexpected_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() raises SandboxError on unexpected exception."""
        task = _make_task(tmp_path)

        async def failing_rc(**kwargs):
            raise RuntimeError("Unexpected error")

        monkeypatch.setattr("airut.sandbox.task.run_container", failing_rc)

        with pytest.raises(SandboxError, match="execution failed"):
            await task.execute("Test prompt")

    async def test_execute_on_stderr_line_callback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() passes on_stderr_line through to run_container."""
        task = _make_task(tmp_path)

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            # Invoke the stderr callback
            cb = kwargs.get("on_stderr_line")
            if cb:
                cb("stderr line\n")
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        stderr_lines: list[str] = []
        await task.execute("Test prompt", on_stderr_line=stderr_lines.append)

        assert "stderr line\n" in stderr_lines

    async def test_execute_on_network_line_callback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() tails network log when on_network_line is provided."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("ALLOW example.com\nBLOCK evil.com\n")

        task = _make_task(tmp_path, network_log_path=log_path)

        mock_rc = create_mock_run_container(
            stdout='{"type": "result", "result": "test"}\n'
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        network_lines: list[str] = []
        await task.execute("Test prompt", on_network_line=network_lines.append)

        assert "ALLOW example.com" in network_lines
        assert "BLOCK evil.com" in network_lines

    async def test_execute_on_network_line_no_crash_without_sandbox(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Passing on_network_line when network_log is None does not crash."""
        task = _make_task(tmp_path)  # no network_log_path

        mock_rc = create_mock_run_container(
            stdout='{"type": "result", "result": "test"}\n'
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        # Should not raise
        await task.execute("Test prompt", on_network_line=lambda line: None)

    async def test_execute_resource_limits_passed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() passes resource limits to run_container."""
        task = _make_task(
            tmp_path,
            resource_limits=ResourceLimits(
                timeout=600, memory="4g", cpus=2.5, pids_limit=512
            ),
        )

        calls: list[dict] = []

        async def capture_rc(**kwargs):
            calls.append(kwargs)
            return await create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )(**kwargs)

        monkeypatch.setattr("airut.sandbox.task.run_container", capture_rc)

        await task.execute("Test prompt")

        assert calls[0]["resource_limits"].memory == "4g"
        assert calls[0]["resource_limits"].cpus == 2.5
        assert calls[0]["resource_limits"].pids_limit == 512


class TestTailNetworkLog:
    """Tests for _tail_network_log helper."""

    async def test_polls_and_delivers_lines(self, tmp_path: Path) -> None:
        """Loop body runs, poll times out, then stop delivers lines."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("LINE1\n")
        net_log = NetworkLog(log_path)

        received: list[str] = []
        stop = asyncio.Event()

        async def set_stop_after_poll():
            # Wait long enough for at least one poll timeout
            await asyncio.sleep(0.05)
            stop.set()

        asyncio.create_task(set_stop_after_poll())
        await _tail_network_log(
            net_log, received.append, stop, poll_interval=0.01
        )

        assert "LINE1" in received


class TestAgentTaskTailFailure:
    """Tests for tail task exception handling in AgentTask."""

    async def test_tail_task_exception_logged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tail task exception is caught and logged, not propagated."""
        log_path = tmp_path / "network-sandbox.log"
        log_path.write_text("")
        task = _make_task(tmp_path, network_log_path=log_path)

        mock_rc = create_mock_run_container(
            stdout='{"type": "result", "result": "test"}\n'
        )
        monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

        # Patch _tail_network_log to raise
        async def bad_tail(*args, **kwargs):
            raise RuntimeError("tail exploded")

        monkeypatch.setattr("airut.sandbox.task._tail_network_log", bad_tail)

        # Should not raise despite tail failure
        result = await task.execute(
            "Test prompt", on_network_line=lambda _line: None
        )
        assert result.outcome == Outcome.SUCCESS


class TestAgentTaskStop:
    """Tests for AgentTask.stop() method."""

    def test_stop_no_running_process(self, tmp_path: Path) -> None:
        """stop() returns False when no process is running."""
        task = _make_task(tmp_path)
        result = task.stop()
        assert result is False

    @patch("airut.sandbox._run_container.os.kill")
    @patch("airut.sandbox._run_container.threading.Timer")
    def test_stop_success(
        self,
        mock_timer: MagicMock,
        mock_kill: MagicMock,
        tmp_path: Path,
    ) -> None:
        """stop() sends SIGTERM via os.kill."""
        task = _make_task(tmp_path)
        task._process_tracker.set(12345)

        result = task.stop()

        assert result is True
        mock_kill.assert_called_once_with(12345, 15)  # SIGTERM

    def test_stop_no_pid(self, tmp_path: Path) -> None:
        """stop() returns False when no PID is tracked."""
        task = _make_task(tmp_path)

        result = task.stop()

        assert result is False


class TestAgentTaskWithProxy:
    """Tests for AgentTask execution with network sandbox."""

    async def test_execute_starts_and_stops_proxy(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """execute() starts proxy before and stops after container run."""
        from airut.allowlist import Allowlist
        from airut.sandbox._proxy import _ContextProxy
        from airut.sandbox.secrets import SecretReplacements
        from airut.sandbox.task import NetworkSandboxConfig

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
            task = _make_task(
                tmp_path,
                network_sandbox=sandbox_config,
                proxy_manager=mock_proxy_manager,
            )

            mock_rc = create_mock_run_container(
                stdout='{"type": "result", "result": "test"}\n'
            )
            monkeypatch.setattr("airut.sandbox.task.run_container", mock_rc)

            await task.execute("Test prompt")

        mock_proxy_manager.start_proxy.assert_called_once()
        mock_proxy_manager.stop_proxy.assert_called_once_with("test-task-id")

    async def test_proxy_stopped_on_execution_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Proxy is stopped even when container execution fails."""
        from airut.allowlist import Allowlist
        from airut.sandbox._proxy import _ContextProxy
        from airut.sandbox.secrets import SecretReplacements
        from airut.sandbox.task import NetworkSandboxConfig

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
            return_value=["--network", "test-net"],
        ):
            task = _make_task(
                tmp_path,
                network_sandbox=sandbox_config,
                proxy_manager=mock_proxy_manager,
            )

            async def failing_rc(**kwargs):
                raise RuntimeError("Container exploded")

            monkeypatch.setattr("airut.sandbox.task.run_container", failing_rc)

            with pytest.raises(SandboxError):
                await task.execute("Test prompt")

        mock_proxy_manager.stop_proxy.assert_called_once_with("test-task-id")

    async def test_non_sandbox_error_in_execute_outer_scope(
        self, tmp_path: Path
    ) -> None:
        """Non-SandboxError during proxy setup is wrapped."""
        from airut.allowlist import Allowlist
        from airut.sandbox.secrets import SecretReplacements
        from airut.sandbox.task import NetworkSandboxConfig

        mock_proxy_manager = MagicMock()
        mock_proxy_manager.start_proxy.side_effect = RuntimeError(
            "DNS resolution failed"
        )

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        task = _make_task(
            tmp_path,
            network_sandbox=sandbox_config,
            proxy_manager=mock_proxy_manager,
        )

        with pytest.raises(SandboxError, match="Execution failed"):
            await task.execute("Test prompt")
