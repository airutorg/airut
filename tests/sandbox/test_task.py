# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/task.py -- per-execution AgentTask class."""

import signal
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.claude_output import StreamEvent
from airut.claude_output.types import EventType
from airut.sandbox._proxy import ProxyManager
from airut.sandbox.event_log import EventLog
from airut.sandbox.network_log import NetworkLog
from airut.sandbox.task import AgentTask, NetworkSandboxConfig, SandboxError
from airut.sandbox.types import ContainerEnv, Mount, Outcome, ResourceLimits
from tests.sandbox.conftest import create_mock_popen


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

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_success(
        self,
        mock_popen: MagicMock,
        tmp_path: Path,
        sample_streaming_output: str,
    ) -> None:
        """execute() returns ExecutionResult with parsed output."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0, stdout=sample_streaming_output, stderr=""
        )
        mock_popen.return_value = mock_process

        result = task.execute("Test prompt")

        assert result.outcome == Outcome.SUCCESS
        assert len(result.events) == 3
        assert result.events[0].event_type == EventType.SYSTEM
        assert result.events[1].event_type == EventType.ASSISTANT
        assert result.events[2].event_type == EventType.RESULT
        assert result.exit_code == 0
        assert result.session_id == "test-session-123"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_timeout(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() returns TIMEOUT outcome when container times out."""
        task = _make_task(tmp_path, resource_limits=ResourceLimits(timeout=10))

        mock_process = create_mock_popen(raise_timeout=True)
        mock_popen.return_value = mock_process

        result = task.execute("Test prompt")

        assert result.outcome == Outcome.TIMEOUT

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_nonzero_exit(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() returns CONTAINER_FAILED on non-zero exit code."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=1, stdout="", stderr="Error occurred"
        )
        mock_popen.return_value = mock_process

        result = task.execute("Test prompt")

        assert result.outcome == Outcome.CONTAINER_FAILED
        assert result.exit_code == 1

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_without_session_id(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() without session_id does not include --resume."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--resume" not in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_with_session_id(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() with session_id includes --resume flag."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute(
            "Test prompt",
            session_id="c7886694-f2cb-4861-ad3c-fbe0964eb4df",
        )

        call_args = mock_popen.call_args[0][0]
        assert "--resume" in call_args
        resume_index = call_args.index("--resume")
        assert (
            call_args[resume_index + 1]
            == "c7886694-f2cb-4861-ad3c-fbe0964eb4df"
        )

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_model_parameter(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() passes model via --model CLI parameter."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt", model="opus")

        call_args = mock_popen.call_args[0][0]
        assert "--model" in call_args
        model_index = call_args.index("--model")
        assert call_args[model_index + 1] == "opus"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_default_model(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() uses sonnet as default model."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--model" in call_args
        model_index = call_args.index("--model")
        assert call_args[model_index + 1] == "sonnet"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_effort_parameter(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() passes effort via --effort CLI parameter."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt", effort="max")

        call_args = mock_popen.call_args[0][0]
        assert "--effort" in call_args
        effort_index = call_args.index("--effort")
        assert call_args[effort_index + 1] == "max"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_effort_omitted_by_default(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() omits --effort when not specified."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--effort" not in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_container_env(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() passes container environment variables."""
        env = ContainerEnv(
            variables={
                "ANTHROPIC_API_KEY": "sk-test-key-12345",
                "GH_TOKEN": "ghp_testtoken",
            }
        )
        task = _make_task(tmp_path, env=env)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "-e" in call_args
        assert "ANTHROPIC_API_KEY=sk-test-key-12345" in call_args
        assert "GH_TOKEN=ghp_testtoken" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_empty_container_env(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() with empty env does not add env var flags."""
        task = _make_task(tmp_path, env=ContainerEnv())

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        # Find all -e flags and their values
        env_pairs = [
            call_args[i + 1]
            for i in range(len(call_args) - 1)
            if call_args[i] == "-e"
        ]
        env_names = [p.split("=")[0] for p in env_pairs]
        for name in ["ANTHROPIC_API_KEY", "GH_TOKEN"]:
            assert name not in env_names

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_mounts(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() passes mount configurations to container."""
        mounts = [
            Mount(
                host_path=tmp_path / "workspace",
                container_path="/workspace",
                read_only=False,
            ),
            Mount(
                host_path=tmp_path / "config",
                container_path="/config",
                read_only=True,
            ),
        ]
        task = _make_task(tmp_path, mounts=mounts)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        command_str = " ".join(call_args)
        assert f"{tmp_path / 'workspace'}:/workspace:rw" in command_str
        assert f"{tmp_path / 'config'}:/config:ro" in command_str

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_with_callback(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() invokes callback for each parsed event."""
        task = _make_task(tmp_path)

        streaming_output = (
            '{"type": "system", "subtype": "init", "session_id": "s1"}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "test"}]}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "done"}'
        )
        mock_process = create_mock_popen(
            returncode=0, stdout=streaming_output, stderr=""
        )
        mock_popen.return_value = mock_process

        events_received: list[StreamEvent] = []

        def callback(event: StreamEvent) -> None:
            events_received.append(event)

        task.execute("Test prompt", on_event=callback)

        assert len(events_received) == 3
        assert events_received[0].event_type == EventType.SYSTEM
        assert events_received[1].event_type == EventType.ASSISTANT
        assert events_received[2].event_type == EventType.RESULT

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_callback_non_json_lines_skipped(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """Callback is not invoked for non-JSON lines."""
        task = _make_task(tmp_path)

        streaming_output = (
            "Non-JSON line\n"
            '{"type": "system", "session_id": "s1"}\n'
            "Another non-JSON\n"
            '{"type": "result", "session_id": "s1", "result": "done"}'
        )
        mock_process = create_mock_popen(
            returncode=0, stdout=streaming_output, stderr=""
        )
        mock_popen.return_value = mock_process

        events_received: list[StreamEvent] = []

        def callback(event: StreamEvent) -> None:
            events_received.append(event)

        task.execute("Test prompt", on_event=callback)

        # Only 2 valid JSON events should be received
        assert len(events_received) == 2

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_uses_image_tag(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() uses the configured image_tag in the command."""
        task = _make_task(tmp_path, image_tag="airut:custom123")

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "airut:custom123" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_custom_container_command(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() uses custom container command."""
        task = _make_task(tmp_path, container_command="docker")

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "docker"
        assert call_args[1] == "run"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_container_security_options(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() includes --cap-drop=ALL and --security-opt flags."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--cap-drop=ALL" in call_args
        assert "--security-opt=no-new-privileges:true" in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_unexpected_error(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() raises SandboxError on unexpected exception."""
        task = _make_task(tmp_path)

        mock_popen.side_effect = RuntimeError("Unexpected error")

        with pytest.raises(SandboxError, match="execution failed"):
            task.execute("Test prompt")

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_mounts_claude_dir(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() mounts claude/ directory at /root/.claude."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        command_str = " ".join(str(a) for a in call_args)
        assert "/root/.claude:rw" in command_str

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_sends_prompt_on_stdin(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() writes prompt to stdin and closes it."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("My test prompt")

        mock_process.stdin.write.assert_called_once_with("My test prompt")
        mock_process.stdin.close.assert_called_once()

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_resume_flag_before_prompt(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() places --resume before -p flag in command."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt", session_id="test-session-id")

        call_args = mock_popen.call_args[0][0]
        resume_index = call_args.index("--resume")
        prompt_index = call_args.index("-p")
        assert resume_index < prompt_index

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_clears_process_after_completion(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() clears process tracker after completion."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        assert task._process_tracker._process is None

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_resource_limits_memory(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() adds --memory and --memory-swap flags."""
        task = _make_task(tmp_path, resource_limits=ResourceLimits(memory="2g"))

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--memory" in call_args
        memory_index = call_args.index("--memory")
        assert call_args[memory_index + 1] == "2g"
        assert "--memory-swap" in call_args
        swap_index = call_args.index("--memory-swap")
        assert call_args[swap_index + 1] == "2g"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_resource_limits_cpus(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() adds --cpus flag (supports fractional values)."""
        task = _make_task(tmp_path, resource_limits=ResourceLimits(cpus=1.5))

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--cpus" in call_args
        cpus_index = call_args.index("--cpus")
        assert call_args[cpus_index + 1] == "1.5"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_resource_limits_pids(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() adds --pids-limit flag."""
        task = _make_task(
            tmp_path, resource_limits=ResourceLimits(pids_limit=256)
        )

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--pids-limit" in call_args
        pids_index = call_args.index("--pids-limit")
        assert call_args[pids_index + 1] == "256"

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_no_resource_limit_flags_when_none(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() omits resource limit flags when all limits are None."""
        task = _make_task(tmp_path, resource_limits=ResourceLimits())

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--memory" not in call_args
        assert "--memory-swap" not in call_args
        assert "--cpus" not in call_args
        assert "--pids-limit" not in call_args

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_all_resource_limits(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() adds all resource limit flags when all are set."""
        task = _make_task(
            tmp_path,
            resource_limits=ResourceLimits(
                timeout=600, memory="4g", cpus=2.5, pids_limit=512
            ),
        )

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        call_args = mock_popen.call_args[0][0]
        assert "--memory" in call_args
        assert "--memory-swap" in call_args
        assert "--cpus" in call_args
        assert "--pids-limit" in call_args


class TestAgentTaskStop:
    """Tests for AgentTask.stop() method."""

    def test_stop_no_running_process(self, tmp_path: Path) -> None:
        """stop() returns False when no process is running."""
        task = _make_task(tmp_path)
        result = task.stop()
        assert result is False

    def test_stop_success(self, tmp_path: Path) -> None:
        """stop() terminates a running process successfully."""
        task = _make_task(tmp_path)

        mock_process = MagicMock()
        mock_process.send_signal = MagicMock()
        mock_process.wait = MagicMock(return_value=None)

        task._process_tracker._process = mock_process

        result = task.stop()

        assert result is True
        mock_process.send_signal.assert_called_once_with(signal.SIGTERM)
        mock_process.wait.assert_called_once_with(timeout=5)

    def test_stop_force_kill(self, tmp_path: Path) -> None:
        """stop() force kills if graceful termination fails."""
        task = _make_task(tmp_path)

        mock_process = MagicMock()
        mock_process.send_signal = MagicMock()
        mock_process.wait = MagicMock(
            side_effect=[
                subprocess.TimeoutExpired("cmd", 5),
                None,
            ]
        )
        mock_process.kill = MagicMock()

        task._process_tracker._process = mock_process

        result = task.stop()

        assert result is True
        mock_process.send_signal.assert_called_once_with(signal.SIGTERM)
        assert mock_process.wait.call_count == 2
        mock_process.kill.assert_called_once()

    def test_stop_handles_errors(self, tmp_path: Path) -> None:
        """stop() handles exceptions gracefully."""
        task = _make_task(tmp_path)

        mock_process = MagicMock()
        mock_process.send_signal.side_effect = OSError("Process error")

        task._process_tracker._process = mock_process

        result = task.stop()

        assert result is False


class TestAgentTaskWithProxy:
    """Tests for AgentTask execution with network sandbox."""

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_execute_starts_and_stops_proxy(
        self, mock_popen: MagicMock, tmp_path: Path
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

        # Need to mock get_network_args since it checks for CA cert
        with patch(
            "airut.sandbox.task.get_network_args",
            return_value=["--network", "test-net", "--dns", "10.199.1.100"],
        ):
            task = _make_task(
                tmp_path,
                network_sandbox=sandbox_config,
                proxy_manager=mock_proxy_manager,
            )

            mock_process = create_mock_popen(
                returncode=0,
                stdout='{"type": "result", "result": "test"}',
                stderr="",
            )
            mock_popen.return_value = mock_process

            task.execute("Test prompt")

        mock_proxy_manager.start_proxy.assert_called_once()
        mock_proxy_manager.stop_proxy.assert_called_once_with("test-task-id")

    @patch("airut.sandbox._run_container.subprocess.Popen")
    def test_proxy_stopped_on_execution_failure(
        self, mock_popen: MagicMock, tmp_path: Path
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

            mock_popen.side_effect = RuntimeError("Container exploded")

            with pytest.raises(SandboxError):
                task.execute("Test prompt")

        mock_proxy_manager.stop_proxy.assert_called_once_with("test-task-id")

    def test_non_sandbox_error_in_execute_outer_scope(
        self, tmp_path: Path
    ) -> None:
        """Non-SandboxError during proxy setup is wrapped as SandboxError."""
        from airut.allowlist import Allowlist
        from airut.sandbox.secrets import SecretReplacements
        from airut.sandbox.task import NetworkSandboxConfig

        mock_proxy_manager = MagicMock()
        # Proxy startup fails with a non-SandboxError
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
            task.execute("Test prompt")
