# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scheduled task execution."""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.conversation import ConversationLayout
from airut.dashboard.tracker import CompletionReason
from airut.gateway.config import (
    ScheduleConfig,
    ScheduleDelivery,
)
from airut.gateway.scheduler.execution import (
    _build_prompt,
    _build_script_error_prompt,
    _format_size,
    _truncate_output,
    execute_scheduled_task,
)
from airut.gateway.service.message_processing import SandboxTaskResult
from airut.sandbox import Outcome


def _make_schedule_config(
    prompt: str | None = "Do the thing",
    trigger_command: str | None = None,
    trigger_timeout: int | None = None,
    model: str | None = None,
    effort: str | None = None,
    output_limit: int = 102400,
) -> ScheduleConfig:
    return ScheduleConfig(
        cron="0 9 * * *",
        deliver=ScheduleDelivery(channel="email", to="user@example.com"),
        prompt=prompt,
        trigger_command=trigger_command,
        trigger_timeout=trigger_timeout,
        model=model,
        effort=effort,
        output_limit=output_limit,
    )


def _make_sandbox_result(
    outcome: Outcome = Outcome.SUCCESS,
    conversation_id: str = "abc12345",
    response_text: str = "Done!",
    is_error: bool = False,
) -> SandboxTaskResult:
    layout = MagicMock(spec=ConversationLayout)
    layout.outbox = Path("/tmp/outbox")
    return SandboxTaskResult(
        outcome=outcome,
        conversation_id=conversation_id,
        response_text=response_text,
        usage_stats=None,
        layout=layout,
        is_error=is_error,
    )


def _make_service() -> MagicMock:
    svc = MagicMock()
    svc.tracker = MagicMock()
    svc._executor_pool = MagicMock()
    svc._futures_lock = threading.Lock()
    svc._pending_futures = set()
    return svc


def _make_handler(model: str = "opus", effort: str | None = None) -> MagicMock:
    handler = MagicMock()
    handler.config.repo_id = "test-repo"
    handler.config.model = model
    handler.config.effort = effort
    handler.conversation_manager = MagicMock()
    handler.conversation_manager.initialize_new.return_value = (
        "conv123",
        Path("/tmp/conv"),
    )
    adapter = MagicMock()
    adapter.channel_context.return_value = "Email context instructions"
    handler.adapters = {"email": adapter}
    return handler


class TestExecuteScheduledTaskPromptMode:
    """Test prompt mode execution."""

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    def test_prompt_mode_success(
        self, mock_sandbox: MagicMock, mock_deliver: MagicMock
    ) -> None:
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(prompt="Review PRs")
        result = _make_sandbox_result()
        mock_sandbox.return_value = result

        execute_scheduled_task(svc, handler, "daily-review", config, "task-1")

        mock_sandbox.assert_called_once()
        call_kwargs = mock_sandbox.call_args
        assert "Review PRs" in call_kwargs.kwargs["prompt"]
        assert call_kwargs.kwargs["model"] == "opus"
        mock_deliver.assert_called_once_with(
            handler, "daily-review", config, result
        )
        svc.tracker.complete_task.assert_called_once_with(
            "task-1", CompletionReason.SUCCESS
        )

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    def test_prompt_mode_uses_schedule_model(
        self, mock_sandbox: MagicMock, mock_deliver: MagicMock
    ) -> None:
        svc = _make_service()
        handler = _make_handler(model="opus")
        config = _make_schedule_config(prompt="Test", model="sonnet")
        mock_sandbox.return_value = _make_sandbox_result()

        execute_scheduled_task(svc, handler, "test", config, "task-1")

        assert mock_sandbox.call_args.kwargs["model"] == "sonnet"

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    def test_prompt_mode_exception(
        self, mock_sandbox: MagicMock, mock_deliver: MagicMock
    ) -> None:
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config()
        mock_sandbox.side_effect = RuntimeError("boom")

        execute_scheduled_task(svc, handler, "test", config, "task-1")

        svc.tracker.complete_task.assert_called_once_with(
            "task-1", CompletionReason.INTERNAL_ERROR
        )
        mock_deliver.assert_not_called()


class TestExecuteScheduledTaskScriptMode:
    """Test script mode execution."""

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    @patch("airut.gateway.scheduler.execution._run_command_task")
    def test_script_exit0_empty_output(
        self,
        mock_cmd: MagicMock,
        mock_sandbox: MagicMock,
        mock_deliver: MagicMock,
    ) -> None:
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None, trigger_command="./check.sh"
        )

        mock_cmd.return_value = MagicMock(exit_code=0, stdout="", stderr="")

        execute_scheduled_task(svc, handler, "nightly", config, "task-1")

        mock_sandbox.assert_not_called()
        mock_deliver.assert_not_called()
        handler.conversation_manager.delete.assert_called_once()
        svc.tracker.complete_task.assert_called_once_with(
            "task-1", CompletionReason.SUCCESS
        )

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    @patch("airut.gateway.scheduler.execution._run_command_task")
    def test_script_exit0_with_output(
        self,
        mock_cmd: MagicMock,
        mock_sandbox: MagicMock,
        mock_deliver: MagicMock,
    ) -> None:
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None, trigger_command="./check.sh"
        )

        mock_cmd.return_value = MagicMock(
            exit_code=0, stdout="Fix this bug", stderr=""
        )
        result = _make_sandbox_result()
        mock_sandbox.return_value = result

        execute_scheduled_task(svc, handler, "nightly", config, "task-1")

        mock_sandbox.assert_called_once()
        prompt = mock_sandbox.call_args.kwargs["prompt"]
        assert "Fix this bug" in prompt
        mock_deliver.assert_called_once()

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    @patch("airut.gateway.scheduler.execution._run_command_task")
    def test_script_nonzero_exit(
        self,
        mock_cmd: MagicMock,
        mock_sandbox: MagicMock,
        mock_deliver: MagicMock,
    ) -> None:
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None, trigger_command="./check.sh"
        )

        mock_cmd.return_value = MagicMock(
            exit_code=1, stdout="error output", stderr="stderr output"
        )
        result = _make_sandbox_result()
        mock_sandbox.return_value = result

        execute_scheduled_task(svc, handler, "nightly", config, "task-1")

        mock_sandbox.assert_called_once()
        prompt = mock_sandbox.call_args.kwargs["prompt"]
        assert "failed unexpectedly" in prompt
        assert "Exit code: 1" in prompt
        assert "error output" in prompt


class TestBuildPrompt:
    """Test prompt construction."""

    def test_with_channel_context(self) -> None:
        handler = _make_handler()
        config = _make_schedule_config()
        prompt = _build_prompt(handler, "daily", config, "Do stuff")
        assert "Email context instructions" in prompt
        assert 'scheduled task "daily"' in prompt
        assert "user@example.com" in prompt
        assert "Do stuff" in prompt

    def test_no_adapter(self) -> None:
        handler = _make_handler()
        handler.adapters = {}
        config = _make_schedule_config()
        prompt = _build_prompt(handler, "daily", config, "Do stuff")
        assert prompt == "Do stuff"


class TestTruncateOutput:
    """Test output truncation."""

    def test_no_truncation(self) -> None:
        assert _truncate_output("hello", 100) == "hello"

    def test_truncation(self) -> None:
        output = "x" * 200
        result = _truncate_output(output, 50)
        assert len(result) < 200
        assert "truncated" in result

    def test_truncation_size_labels(self) -> None:
        output = "x" * 200000
        result = _truncate_output(output, 1024)
        assert "KB" in result or "MB" in result


class TestFormatSize:
    """Test size formatting."""

    def test_bytes(self) -> None:
        assert _format_size(500) == "500B"

    def test_kb(self) -> None:
        assert _format_size(2048) == "2KB"

    def test_mb(self) -> None:
        assert _format_size(2 * 1024 * 1024) == "2.0MB"


class TestBuildScriptErrorPrompt:
    """Test script error prompt construction."""

    def test_basic(self) -> None:
        prompt = _build_script_error_prompt(["./check.sh"], 1, "error!", 102400)
        assert "failed unexpectedly" in prompt
        assert "./check.sh" in prompt
        assert "Exit code: 1" in prompt
        assert "error!" in prompt


class TestInlineBashCommand:
    """Test that inline bash commands (bash -c '...') are parsed correctly."""

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    @patch("airut.gateway.scheduler.execution._run_command_task")
    def test_bash_c_with_shell_operators(
        self,
        mock_cmd: MagicMock,
        mock_sandbox: MagicMock,
        mock_deliver: MagicMock,
    ) -> None:
        """Bash -c 'cmd1 && cmd2' is split correctly by shlex."""
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None,
            trigger_command="bash -c 'echo hello && echo world'",
        )

        mock_cmd.return_value = MagicMock(
            exit_code=0, stdout="hello\nworld\n", stderr=""
        )
        mock_sandbox.return_value = _make_sandbox_result()

        execute_scheduled_task(svc, handler, "inline-bash", config, "task-1")

        # Verify the command was parsed into the correct list
        cmd_arg = mock_cmd.call_args.args[3]
        assert cmd_arg == ["bash", "-c", "echo hello && echo world"]

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    @patch("airut.gateway.scheduler.execution._run_command_task")
    def test_bash_c_with_pipes_and_semicolons(
        self,
        mock_cmd: MagicMock,
        mock_sandbox: MagicMock,
        mock_deliver: MagicMock,
    ) -> None:
        """Bash -c with pipes and semicolons preserves the full expression."""
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None,
            trigger_command="bash -c 'cat /tmp/data | grep error; echo done'",
        )

        mock_cmd.return_value = MagicMock(
            exit_code=0, stdout="done\n", stderr=""
        )
        mock_sandbox.return_value = _make_sandbox_result()

        execute_scheduled_task(svc, handler, "pipe-test", config, "task-1")

        cmd_arg = mock_cmd.call_args.args[3]
        assert cmd_arg == [
            "bash",
            "-c",
            "cat /tmp/data | grep error; echo done",
        ]

    @patch("airut.gateway.scheduler.execution.deliver_result")
    @patch("airut.gateway.scheduler.execution.run_in_sandbox")
    @patch("airut.gateway.scheduler.execution._run_command_task")
    def test_bash_c_failed_produces_error_prompt_with_full_command(
        self,
        mock_cmd: MagicMock,
        mock_sandbox: MagicMock,
        mock_deliver: MagicMock,
    ) -> None:
        """Failed inline bash command appears correctly in error prompt."""
        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None,
            trigger_command="bash -c 'test -f /missing && echo ok'",
        )

        mock_cmd.return_value = MagicMock(
            exit_code=1, stdout="", stderr="test failed"
        )
        mock_sandbox.return_value = _make_sandbox_result()

        execute_scheduled_task(svc, handler, "fail-test", config, "task-1")

        prompt = mock_sandbox.call_args.kwargs["prompt"]
        assert "failed unexpectedly" in prompt
        assert "Exit code: 1" in prompt
        # The reconstructed command should be quoted properly
        assert "bash -c" in prompt

    def test_shlex_split_preserves_inner_operators(self) -> None:
        """Direct unit test: shlex.split keeps && inside single quotes."""
        import shlex

        result = shlex.split("bash -c 'cd /tmp && ls -la'")
        assert result == ["bash", "-c", "cd /tmp && ls -la"]

    def test_shlex_split_preserves_double_quoted_operators(self) -> None:
        """Double-quoted expressions also preserve shell operators."""
        import shlex

        result = shlex.split('bash -c "echo a || echo b"')
        assert result == ["bash", "-c", "echo a || echo b"]


class TestRunCommandTask:
    """Test _run_command_task sandbox setup."""

    def test_basic_command_execution(self) -> None:
        """Test the full command task setup and execution."""
        from airut.gateway.scheduler.execution import _run_command_task

        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None,
            trigger_command="./check.sh",
        )

        conv_dir = Path("/tmp/test-conv")
        handler.conversation_manager.get_conversation_dir.return_value = (
            conv_dir
        )
        handler.config.build_task_env.return_value = ({"VAR": "val"}, {})
        handler.config.network_sandbox_enabled = False
        handler.config.container_path = ".airut/container"

        mock_result = MagicMock()
        mock_result.exit_code = 0
        mock_result.stdout = "output"

        mock_task = MagicMock()
        mock_task.execute = MagicMock(return_value=mock_result)
        svc.sandbox.create_command_task.return_value = mock_task

        with (
            patch(
                "airut.conversation.create_conversation_layout"
            ) as mock_layout,
            patch("airut.conversation.prepare_conversation"),
            patch(
                "airut.gateway.service.message_processing.build_image",
                return_value="test:latest",
            ) as mock_build,
            patch("asyncio.run", return_value=mock_result),
        ):
            layout = MagicMock()
            layout.workspace = Path("/tmp/workspace")
            layout.inbox = Path("/tmp/inbox")
            layout.outbox = Path("/tmp/outbox")
            layout.storage = Path("/tmp/storage")
            mock_layout.return_value = layout

            result = _run_command_task(
                svc, handler, "conv123", ["./check.sh"], config
            )

        assert result is mock_result
        svc.sandbox.create_command_task.assert_called_once()
        # CommandTask must use passthrough entrypoint image
        mock_build.assert_called_once()
        assert mock_build.call_args.kwargs.get("passthrough_entrypoint"), (
            "CommandTask must use passthrough entrypoint image"
        )

    def test_command_with_trigger_timeout(self) -> None:
        """Trigger timeout overrides resource_limits."""
        from airut.gateway.scheduler.execution import _run_command_task
        from airut.sandbox.types import ResourceLimits

        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None,
            trigger_command="./check.sh",
            trigger_timeout=300,
        )

        conv_dir = Path("/tmp/test-conv")
        handler.conversation_manager.get_conversation_dir.return_value = (
            conv_dir
        )
        handler.config.build_task_env.return_value = ({"VAR": "val"}, {})
        handler.config.network_sandbox_enabled = False
        handler.config.container_path = ".airut/container"
        handler.config.resource_limits = ResourceLimits(
            timeout=3600, memory="8g", cpus=4, pids_limit=1024
        )

        mock_result = MagicMock()
        mock_task = MagicMock()
        mock_task.execute = MagicMock(return_value=mock_result)
        svc.sandbox.create_command_task.return_value = mock_task

        with (
            patch(
                "airut.conversation.create_conversation_layout"
            ) as mock_layout,
            patch("airut.conversation.prepare_conversation"),
            patch(
                "airut.gateway.service.message_processing.build_image",
                return_value="test:latest",
            ),
            patch("asyncio.run", return_value=mock_result),
        ):
            layout = MagicMock()
            layout.workspace = Path("/tmp/workspace")
            layout.inbox = Path("/tmp/inbox")
            layout.outbox = Path("/tmp/outbox")
            layout.storage = Path("/tmp/storage")
            mock_layout.return_value = layout

            _run_command_task(svc, handler, "conv123", ["./check.sh"], config)

        call_kwargs = svc.sandbox.create_command_task.call_args.kwargs
        assert call_kwargs["resource_limits"].timeout == 300

    def test_command_with_network_sandbox(self) -> None:
        """Network sandbox is configured when enabled."""
        from airut.gateway.scheduler.execution import _run_command_task

        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None,
            trigger_command="./check.sh",
        )

        conv_dir = Path("/tmp/test-conv")
        handler.conversation_manager.get_conversation_dir.return_value = (
            conv_dir
        )
        handler.config.build_task_env.return_value = ({"VAR": "val"}, {})
        handler.config.network_sandbox_enabled = True
        handler.config.container_path = ".airut/container"

        mock_result = MagicMock()
        mock_task = MagicMock()
        mock_task.execute = MagicMock(return_value=mock_result)
        svc.sandbox.create_command_task.return_value = mock_task

        with (
            patch(
                "airut.conversation.create_conversation_layout"
            ) as mock_layout,
            patch("airut.conversation.prepare_conversation"),
            patch(
                "airut.gateway.service.message_processing.build_image",
                return_value="test:latest",
            ),
            patch(
                "airut.allowlist.parse_allowlist_yaml",
                return_value=[],
            ),
            patch(
                "airut.gateway.service.message_processing.convert_replacement_map",
                return_value={},
            ),
            patch("asyncio.run", return_value=mock_result),
        ):
            handler.conversation_manager.mirror.read_file.return_value = (
                "rules: []"
            )
            layout = MagicMock()
            layout.workspace = Path("/tmp/workspace")
            layout.inbox = Path("/tmp/inbox")
            layout.outbox = Path("/tmp/outbox")
            layout.storage = Path("/tmp/storage")
            mock_layout.return_value = layout

            _run_command_task(svc, handler, "conv123", ["./check.sh"], config)

        call_kwargs = svc.sandbox.create_command_task.call_args.kwargs
        assert call_kwargs["network_sandbox"] is not None
        assert call_kwargs["network_log_path"] is not None

    def test_command_network_sandbox_read_error(self) -> None:
        """Network sandbox raises ProxyError when allowlist read fails."""
        from airut.gateway.scheduler.execution import _run_command_task
        from airut.sandbox import ProxyError

        svc = _make_service()
        handler = _make_handler()
        config = _make_schedule_config(
            prompt=None,
            trigger_command="./check.sh",
        )

        conv_dir = Path("/tmp/test-conv")
        handler.conversation_manager.get_conversation_dir.return_value = (
            conv_dir
        )
        handler.config.build_task_env.return_value = ({}, {})
        handler.config.network_sandbox_enabled = True
        handler.config.container_path = ".airut/container"

        with (
            patch(
                "airut.conversation.create_conversation_layout"
            ) as mock_layout,
            patch("airut.conversation.prepare_conversation"),
            patch(
                "airut.gateway.service.message_processing.build_image",
                return_value="test:latest",
            ),
        ):
            handler.conversation_manager.mirror.read_file.side_effect = (
                FileNotFoundError("not found")
            )
            layout = MagicMock()
            layout.workspace = Path("/tmp/workspace")
            layout.inbox = Path("/tmp/inbox")
            layout.outbox = Path("/tmp/outbox")
            layout.storage = Path("/tmp/storage")
            mock_layout.return_value = layout

            with pytest.raises(ProxyError, match="Failed to read/parse"):
                _run_command_task(
                    svc, handler, "conv123", ["./check.sh"], config
                )
