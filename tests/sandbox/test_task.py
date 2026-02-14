# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/task.py -- per-execution Task class."""

import signal
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lib.claude_output import StreamEvent
from lib.claude_output.types import EventType
from lib.sandbox._proxy import ProxyManager
from lib.sandbox.event_log import EventLog
from lib.sandbox.network_log import NetworkLog
from lib.sandbox.task import NetworkSandboxConfig, SandboxError, Task
from lib.sandbox.types import ContainerEnv, Mount, Outcome
from tests.sandbox.conftest import create_mock_popen


def _make_task(
    tmp_path: Path,
    *,
    image_tag: str = "airut:test123",
    mounts: list[Mount] | None = None,
    env: ContainerEnv | None = None,
    network_log_dir: Path | None = None,
    network_sandbox: NetworkSandboxConfig | None = None,
    timeout_seconds: int = 300,
    container_command: str = "podman",
    proxy_manager: ProxyManager | None = None,
) -> Task:
    """Create a Task with standard test params."""
    session_dir = tmp_path / "session"
    session_dir.mkdir(parents=True, exist_ok=True)

    return Task(
        "test-task-id",
        image_tag=image_tag,
        mounts=mounts or [],
        env=env or ContainerEnv(),
        session_dir=session_dir,
        network_log_dir=network_log_dir,
        network_sandbox=network_sandbox,
        timeout_seconds=timeout_seconds,
        container_command=container_command,
        proxy_manager=proxy_manager,
    )


class TestTaskInit:
    """Tests for Task initialization."""

    def test_creates_claude_dir(self, tmp_path: Path) -> None:
        """Init creates claude/ subdirectory in session_dir."""
        _make_task(tmp_path)
        claude_dir = tmp_path / "session" / "claude"
        assert claude_dir.exists()

    def test_event_log_property(self, tmp_path: Path) -> None:
        """event_log property returns EventLog."""
        task = _make_task(tmp_path)
        assert isinstance(task.event_log, EventLog)

    def test_network_log_none_when_no_dir(self, tmp_path: Path) -> None:
        """network_log is None when network_log_dir not provided."""
        task = _make_task(tmp_path)
        assert task.network_log is None

    def test_network_log_created_when_dir_provided(
        self, tmp_path: Path
    ) -> None:
        """network_log is created when network_log_dir is provided."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        task = _make_task(tmp_path, network_log_dir=log_dir)
        assert isinstance(task.network_log, NetworkLog)

    def test_execution_context_id_property(self, tmp_path: Path) -> None:
        """execution_context_id property returns the context ID."""
        task = _make_task(tmp_path)
        assert task.execution_context_id == "test-task-id"


class TestTaskExecute:
    """Tests for Task.execute() method."""

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
    def test_execute_timeout(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() returns TIMEOUT outcome when container times out."""
        task = _make_task(tmp_path, timeout_seconds=1)

        mock_process = create_mock_popen(raise_timeout=True)
        mock_popen.return_value = mock_process

        result = task.execute("Test prompt")

        assert result.outcome == Outcome.TIMEOUT

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
    def test_execute_unexpected_error(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() raises SandboxError on unexpected exception."""
        task = _make_task(tmp_path)

        mock_popen.side_effect = RuntimeError("Unexpected error")

        with pytest.raises(SandboxError, match="execution failed"):
            task.execute("Test prompt")

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
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

    @patch("lib.sandbox.task.subprocess.Popen")
    def test_execute_clears_process_after_completion(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() clears _process reference after completion."""
        task = _make_task(tmp_path)

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"type": "result", "result": "test"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        task.execute("Test prompt")

        assert task._process is None


class TestTaskStop:
    """Tests for Task.stop() method."""

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

        task._process = mock_process

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

        task._process = mock_process

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

        task._process = mock_process

        result = task.stop()

        assert result is False


class TestTaskWithProxy:
    """Tests for Task execution with network sandbox."""

    @patch("lib.sandbox.task.subprocess.Popen")
    def test_execute_starts_and_stops_proxy(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """execute() starts proxy before and stops after container run."""
        from lib.allowlist import Allowlist
        from lib.sandbox._proxy import _ContextProxy
        from lib.sandbox.secrets import SecretReplacements
        from lib.sandbox.task import NetworkSandboxConfig

        mock_proxy_manager = MagicMock()
        mock_context_proxy = _ContextProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_ip="10.199.1.100",
        )
        mock_proxy_manager.start_proxy.return_value = mock_context_proxy

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        # Need to mock get_network_args since it checks for CA cert
        with patch(
            "lib.sandbox.task.get_network_args",
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

    @patch("lib.sandbox.task.subprocess.Popen")
    def test_proxy_stopped_on_execution_failure(
        self, mock_popen: MagicMock, tmp_path: Path
    ) -> None:
        """Proxy is stopped even when container execution fails."""
        from lib.allowlist import Allowlist
        from lib.sandbox._proxy import _ContextProxy
        from lib.sandbox.secrets import SecretReplacements
        from lib.sandbox.task import NetworkSandboxConfig

        mock_proxy_manager = MagicMock()
        mock_context_proxy = _ContextProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_ip="10.199.1.100",
        )
        mock_proxy_manager.start_proxy.return_value = mock_context_proxy

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        with patch(
            "lib.sandbox.task.get_network_args",
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
        from lib.allowlist import Allowlist
        from lib.sandbox.secrets import SecretReplacements
        from lib.sandbox.task import NetworkSandboxConfig

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
