# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for ClaudeExecutor class."""

import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from lib.container.executor import (
    ClaudeExecutor,
    ContainerTimeoutError,
    ExecutionResult,
    ImageBuildError,
    _ImageInfo,
)


def create_mock_popen(returncode=0, stdout="", stderr="", raise_timeout=False):
    """Create a mock Popen object."""
    import subprocess
    from unittest.mock import MagicMock

    mock = MagicMock()
    mock.returncode = returncode
    # stdout should be an iterator that yields lines WITH newlines
    if stdout:
        lines = stdout.split("\n")
        # Add newlines back and filter empty lines at the end
        mock.stdout = iter(line + "\n" for line in lines if line.strip())
    else:
        mock.stdout = iter([])
    mock.stderr = MagicMock()
    # stderr.readlines() should return list of lines
    if stderr:
        stderr_lines = stderr.split("\n")
        mock.stderr.readlines.return_value = [
            line + "\n" for line in stderr_lines if line.strip()
        ]
    else:
        mock.stderr.readlines.return_value = []
    mock.stdin = MagicMock()

    if raise_timeout:
        # First call to wait() raises TimeoutExpired, subsequent calls
        # return None
        mock.wait.side_effect = [
            subprocess.TimeoutExpired(cmd=["podman"], timeout=1),
            None,  # After kill(), wait() should succeed
        ]
    else:
        mock.wait.return_value = None

    mock.kill.return_value = None
    return mock


SAMPLE_MOUNTS = [
    "/tmp/workspace:/workspace:rw",
    "/tmp/claude:/root/.claude:rw",
    "/tmp/gitconfig:/root/.gitconfig:ro",
    "/tmp/inbox:/inbox:rw",
    "/tmp/outbox:/outbox:rw",
]


def _make_executor(
    mock_mirror: MagicMock,
    docker_dir: Path,
    **kwargs: Any,
) -> ClaudeExecutor:
    """Helper to create an executor with standard test params."""
    entrypoint = docker_dir / "airut-entrypoint.sh"
    return ClaudeExecutor(
        mirror=mock_mirror,
        entrypoint_path=entrypoint,
        **kwargs,
    )


class TestClaudeExecutor:
    """Tests for ClaudeExecutor class."""

    def test_init_valid_entrypoint(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """Initialize with valid entrypoint path."""
        executor = _make_executor(mock_mirror, docker_dir)

        assert executor.entrypoint_path == docker_dir / "airut-entrypoint.sh"

    def test_init_nonexistent_entrypoint(
        self, mock_mirror: MagicMock, tmp_path: Path
    ) -> None:
        """Raise ValueError if entrypoint doesn't exist."""
        nonexistent = tmp_path / "nonexistent.sh"

        with pytest.raises(ValueError, match="Entrypoint does not exist"):
            ClaudeExecutor(
                mirror=mock_mirror,
                entrypoint_path=nonexistent,
            )

    def test_init_custom_parameters(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """Initialize with custom parameters."""
        executor = _make_executor(mock_mirror, docker_dir, max_age_hours=48)

        assert executor._max_age_hours == 48

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_success(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
        sample_streaming_output: str,
        sample_claude_output: dict[str, Any],
    ) -> None:
        """execute() returns ExecutionResult with parsed output."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout=sample_streaming_output, stderr=""
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test123",
        )

        assert result.success is True
        assert result.output == sample_claude_output
        assert result.error_message == ""
        assert result.exit_code == 0

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_uses_image_tag(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() uses the provided image_tag in the command."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout='{"result": "test"}', stderr=""
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:abc123",
        )

        call_args = mock_popen.call_args[0][0]
        assert "airut:abc123" in call_args

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_timeout(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Raise ContainerTimeoutError on timeout."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(raise_timeout=True)
        mock_popen.return_value = mock_process

        with pytest.raises(
            ContainerTimeoutError, match="Execution timed out after 1 seconds"
        ):
            executor.execute(
                session_git_repo,
                "Test prompt",
                mounts=SAMPLE_MOUNTS,
                image_tag="airut:test",
                timeout_seconds=1,
            )

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_unexpected_error(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Raise ExecutorError on unexpected exception."""
        from lib.container.executor import ExecutorError

        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_popen.side_effect = RuntimeError("Unexpected error")

        with pytest.raises(ExecutorError, match="Container execution failed"):
            executor.execute(
                session_git_repo,
                "Test prompt",
                mounts=SAMPLE_MOUNTS,
                image_tag="airut:test",
            )

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_nonzero_exit(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Return ExecutionResult with error on non-zero exit."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        error_output = "Error: Something went wrong\n" * 25
        mock_process = create_mock_popen(
            returncode=1, stdout="", stderr=error_output
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        assert result.success is False
        assert result.output is None
        assert "Container execution failed" in result.error_message
        assert "exit code 1" in result.error_message
        assert result.exit_code == 1
        assert result.error_message.count("\n") >= 19

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_json_parse_failure(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Return ExecutionResult with parse error on invalid JSON."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout="Not valid JSON", stderr=""
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        assert result.success is False
        assert result.output is None
        assert "Failed to parse Claude JSON output" in result.error_message
        assert result.exit_code == 0

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_json_parse_failure_with_invalid_brace_line(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Parse error when line starts with { but is invalid JSON."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout="Some output\n{not valid json\nMore output",
            stderr="",
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        assert result.success is False
        assert result.output is None
        assert "Failed to parse Claude JSON output" in result.error_message
        assert result.exit_code == 0

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_json_parse_from_line(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Success when valid JSON events found after non-JSON lines."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        streaming_output = (
            "Syncing dependencies...\n"
            '{"type": "system", "subtype": "init", "session_id": "s1"}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Done"}]}}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Done", "duration_ms": 100, "total_cost_usd": 0.01, '
            '"num_turns": 1, "is_error": false, "usage": {}}'
        )
        mock_process = create_mock_popen(
            returncode=0, stdout=streaming_output, stderr=""
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        assert result.success is True
        assert result.output is not None
        assert result.output["result"] == "Done"
        assert result.exit_code == 0

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_json_parse_non_dict_output(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Return ExecutionResult with parse error when JSON is not a dict."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout='"some string"', stderr=""
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        assert result.success is False
        assert result.output is None
        assert "Failed to parse Claude JSON output" in result.error_message
        assert result.exit_code == 0

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_json_parse_non_dict_line(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Parse error when JSON line is not a dict."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout="Some output\n[1, 2, 3]\nMore output",
            stderr="",
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        assert result.success is False
        assert result.output is None
        assert "Failed to parse Claude JSON output" in result.error_message
        assert result.exit_code == 0

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_parser_returns_non_dict(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Handle case where parser returns non-dict (defensive check)."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout='{"result": "something"}', stderr=""
        )
        mock_popen.return_value = mock_process

        with patch.object(
            executor, "_parse_claude_output", return_value="not a dict"
        ):
            result = executor.execute(
                session_git_repo,
                "Test prompt",
                mounts=SAMPLE_MOUNTS,
                image_tag="airut:test",
            )

        assert result.success is False
        assert result.output is None
        assert "Parser error: got str instead of dict" in result.error_message
        assert result.exit_code == 0

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_passes_mounts_to_container(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Verify mounts are passed to podman command."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mounts = [
            f"{tmp_path}/workspace:/workspace:rw",
            f"{tmp_path}/claude:/root/.claude:rw",
            f"{tmp_path}/gitconfig:/root/.gitconfig:ro",
            f"{tmp_path}/inbox:/inbox:rw",
            f"{tmp_path}/outbox:/outbox:rw",
        ]

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"result": {"content": []}, "status": "success"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=mounts,
            image_tag="airut:test",
        )

        call_args = mock_popen.call_args[0][0]
        command_str = " ".join(call_args)
        for mount in mounts:
            assert mount in command_str

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_without_session_id(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() without session_id doesn't include --resume."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"result": "test", "session_id": "new-session"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        call_args = mock_popen.call_args[0][0]
        assert "--resume" not in call_args

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_with_session_id(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() with session_id includes --resume flag."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"result": "test", "session_id": "existing-session"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
            session_id="c7886694-f2cb-4861-ad3c-fbe0964eb4df",
        )

        call_args = mock_popen.call_args[0][0]
        assert "--resume" in call_args
        resume_index = call_args.index("--resume")
        assert (
            call_args[resume_index + 1]
            == "c7886694-f2cb-4861-ad3c-fbe0964eb4df"
        )

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_with_model(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() passes model via --model CLI parameter."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout='{"result": "test"}', stderr=""
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
            model="opus",
        )

        call_args = mock_popen.call_args[0][0]
        assert "--model" in call_args
        model_index = call_args.index("--model")
        assert call_args[model_index + 1] == "opus"

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_default_model(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() uses sonnet as default model when not specified."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout='{"result": "test"}', stderr=""
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        call_args = mock_popen.call_args[0][0]
        assert "--model" in call_args
        model_index = call_args.index("--model")
        assert call_args[model_index + 1] == "sonnet"

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_resume_flag_before_prompt(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() places --resume before -p flag in command."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0, stdout='{"result": "test"}', stderr=""
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
            session_id="test-session-id",
        )

        call_args = mock_popen.call_args[0][0]
        resume_index = call_args.index("--resume")
        prompt_index = call_args.index("-p")
        assert resume_index < prompt_index

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_passes_container_env(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Verify container_env values are passed to container."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"result": {"content": []}, "status": "success"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
            container_env={
                "R2_ACCOUNT_ID": "test-account",
                "R2_ACCESS_KEY_ID": "test-key",
                "ANTHROPIC_API_KEY": "sk-test-key-12345",
                "CF_ACCESS_CLIENT_ID": "test-client-id",
                "CF_ACCESS_CLIENT_SECRET": "test-client-secret",
                "GEMINI_API_KEY": "test-gemini-key",
            },
        )

        call_args = mock_popen.call_args[0][0]
        assert "-e" in call_args
        assert "R2_ACCOUNT_ID=test-account" in call_args
        assert "R2_ACCESS_KEY_ID=test-key" in call_args
        assert "ANTHROPIC_API_KEY=sk-test-key-12345" in call_args
        assert "CF_ACCESS_CLIENT_ID=test-client-id" in call_args
        assert "CF_ACCESS_CLIENT_SECRET=test-client-secret" in call_args
        assert "GEMINI_API_KEY=test-gemini-key" in call_args

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_passes_oauth_token(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Verify CLAUDE_CODE_OAUTH_TOKEN is passed to container."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"result": {"content": []}, "status": "success"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
            container_env={"CLAUDE_CODE_OAUTH_TOKEN": "oauth-test-token"},
        )

        call_args = mock_popen.call_args[0][0]
        assert "CLAUDE_CODE_OAUTH_TOKEN=oauth-test-token" in call_args

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_empty_container_env(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Verify no -e flags for env when container_env is empty."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"result": {"content": []}, "status": "success"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        call_args = mock_popen.call_args[0][0]
        env_pairs = [
            call_args[i + 1]
            for i in range(len(call_args) - 1)
            if call_args[i] == "-e"
        ]
        env_names = [p.split("=")[0] for p in env_pairs]
        for name in [
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "GH_TOKEN",
            "R2_ACCOUNT_ID",
        ]:
            assert name not in env_names

    def test_parse_claude_output_valid_json(
        self,
        mock_mirror: MagicMock,
        docker_dir: Path,
        sample_streaming_output: str,
        sample_claude_output: dict[str, Any],
    ) -> None:
        """_parse_claude_output() parses valid streaming JSON."""
        executor = _make_executor(mock_mirror, docker_dir)

        result = executor._parse_claude_output(sample_streaming_output)

        assert result == sample_claude_output

    def test_parse_claude_output_invalid_json(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """_parse_claude_output() returns None on invalid JSON."""
        executor = _make_executor(mock_mirror, docker_dir)

        result = executor._parse_claude_output("Not valid JSON")

        assert result is None

    def test_parse_claude_output_with_empty_lines(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """_parse_claude_output() handles empty lines in streaming output."""
        executor = _make_executor(mock_mirror, docker_dir)

        streaming_with_blanks = (
            '{"type": "system", "subtype": "init"}\n'
            "\n"
            '{"type": "result", "subtype": "success", "session_id": "s1"}\n'
            "   \n"
        )
        result = executor._parse_claude_output(streaming_with_blanks)

        assert result is not None
        assert len(result["events"]) == 2
        assert result["events"][0]["type"] == "system"
        assert result["events"][1]["type"] == "result"

    def test_execution_result_dataclass(self) -> None:
        """Test ExecutionResult dataclass creation."""
        result = ExecutionResult(
            success=True,
            output={"test": "data"},
            error_message="",
            stdout="output",
            stderr="",
            exit_code=0,
        )

        assert result.success is True
        assert result.output == {"test": "data"}
        assert result.error_message == ""
        assert result.stdout == "output"
        assert result.stderr == ""
        assert result.exit_code == 0


class TestImageBuild:
    """Tests for two-layer image build functionality."""

    @patch("subprocess.run")
    def test_build_repo_image_copies_context_files(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """_build_repo_image copies context files to build directory.

        When the Dockerfile uses COPY to include additional files (like
        gitconfig), those files must be present in the build context.
        """
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        dockerfile = b"FROM ubuntu:24.04\nCOPY gitconfig /root/.gitconfig\n"
        context_files = {
            "gitconfig": b"[user]\n\tname = Test\n",
        }

        tag = executor._build_repo_image(dockerfile, context_files)

        assert tag.startswith("airut-repo:")
        mock_run.assert_called_once()

        # Verify the build command
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "build"

    @patch("subprocess.run")
    def test_ensure_image_reads_all_container_files(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image reads all files from .airut/container/ directory."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        # Configure mock_mirror to return multiple files
        mock_mirror.list_directory.return_value = ["Dockerfile", "gitconfig"]
        dockerfile = b"FROM ubuntu:24.04\nCOPY gitconfig /root/.gitconfig\n"
        gitconfig = b"[user]\n\tname = Test\n"
        mock_mirror.read_file.side_effect = lambda path: {
            ".airut/container/Dockerfile": dockerfile,
            ".airut/container/gitconfig": gitconfig,
        }[path]

        tag = executor.ensure_image()

        assert tag.startswith("airut:")
        # Verify list_directory was called
        mock_mirror.list_directory.assert_called_once_with(".airut/container")
        # Verify both files were read
        assert mock_mirror.read_file.call_count == 2

    @patch("subprocess.run")
    def test_ensure_image_list_directory_failure(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image raises error when list_directory fails."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_mirror.list_directory.side_effect = RuntimeError("mirror down")

        with pytest.raises(ImageBuildError, match="Failed to list"):
            executor.ensure_image()

    @patch("subprocess.run")
    def test_ensure_image_no_dockerfile(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image raises error when no Dockerfile found."""
        executor = _make_executor(mock_mirror, docker_dir)
        # Return files but no Dockerfile
        mock_mirror.list_directory.return_value = ["gitconfig", "other.txt"]
        mock_mirror.read_file.return_value = b"some content"

        with pytest.raises(ImageBuildError, match="No Dockerfile found"):
            executor.ensure_image()

    def test_content_hash(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """_content_hash returns consistent hex digest."""
        executor = _make_executor(mock_mirror, docker_dir)

        h1 = executor._content_hash(b"hello")
        h2 = executor._content_hash(b"hello")
        h3 = executor._content_hash(b"world")

        assert h1 == h2
        assert h1 != h3
        assert len(h1) == 64

    def test_content_hash_accepts_str(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """_content_hash accepts string input."""
        executor = _make_executor(mock_mirror, docker_dir)

        h1 = executor._content_hash("hello")
        h2 = executor._content_hash(b"hello")

        assert h1 == h2

    def test_is_image_fresh_true(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """_is_image_fresh returns True for recently built images."""
        executor = _make_executor(mock_mirror, docker_dir)

        info = _ImageInfo(tag="test:123", built_at=datetime.now())
        assert executor._is_image_fresh(info) is True

    def test_is_image_fresh_false(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """_is_image_fresh returns False for old images."""
        executor = _make_executor(mock_mirror, docker_dir)

        info = _ImageInfo(
            tag="test:123",
            built_at=datetime.now() - timedelta(hours=25),
        )
        assert executor._is_image_fresh(info) is False

    def test_is_image_fresh_custom_max_age(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """_is_image_fresh respects max_age_hours."""
        executor = _make_executor(mock_mirror, docker_dir, max_age_hours=1)

        info = _ImageInfo(
            tag="test:123",
            built_at=datetime.now() - timedelta(hours=2),
        )
        assert executor._is_image_fresh(info) is False

    @patch("subprocess.run")
    def test_build_repo_image(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_build_repo_image builds and returns tagged image."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        dockerfile = b"FROM ubuntu:24.04\nRUN echo hello\n"
        tag = executor._build_repo_image(dockerfile)

        assert tag.startswith("airut-repo:")
        assert len(tag.split(":")[1]) == 64

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "build"
        assert "-t" in cmd
        assert tag in cmd

    @patch("subprocess.run")
    def test_build_repo_image_caches(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_build_repo_image reuses cached image."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        dockerfile = b"FROM ubuntu:24.04\n"

        tag1 = executor._build_repo_image(dockerfile)
        tag2 = executor._build_repo_image(dockerfile)

        assert tag1 == tag2
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_build_repo_image_rebuilds_when_stale(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_build_repo_image rebuilds stale images."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        dockerfile = b"FROM ubuntu:24.04\n"
        content_hash = executor._content_hash(dockerfile)

        executor._repo_images[content_hash] = _ImageInfo(
            tag=f"airut-repo:{content_hash}",
            built_at=datetime.now() - timedelta(hours=25),
        )

        executor._build_repo_image(dockerfile)

        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_build_repo_image_failure(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_build_repo_image raises ImageBuildError on failure."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["podman", "build"], stderr="build error"
        )

        with pytest.raises(ImageBuildError, match="Repo image build failed"):
            executor._build_repo_image(b"FROM ubuntu:24.04\n")

    @patch("subprocess.run")
    def test_build_overlay_image(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_build_overlay_image builds overlay with entrypoint."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        tag = executor._build_overlay_image(
            "airut-repo:abc123", b"#!/bin/bash\nexec claude\n"
        )

        assert tag.startswith("airut:")
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_build_overlay_image_failure(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_build_overlay_image raises ImageBuildError on failure."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["podman", "build"], stderr="overlay error"
        )

        with pytest.raises(ImageBuildError, match="Overlay image build failed"):
            executor._build_overlay_image("airut-repo:abc123", b"#!/bin/bash\n")

    @patch("subprocess.run")
    def test_ensure_image(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image builds both layers and returns overlay tag."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        tag = executor.ensure_image()

        assert tag.startswith("airut:")
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    def test_ensure_image_mirror_failure(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image raises ImageBuildError on mirror read failure."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_mirror.read_file.side_effect = RuntimeError("mirror down")

        with pytest.raises(ImageBuildError, match="Failed to read"):
            executor.ensure_image()

    @patch("subprocess.run")
    def test_ensure_image_caches_both_layers(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image reuses cached images on second call."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        tag1 = executor.ensure_image()
        tag2 = executor.ensure_image()

        assert tag1 == tag2
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    def test_ensure_image_different_dockerfile(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image builds new images when Dockerfile changes."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        tag1 = executor.ensure_image()

        mock_mirror.read_file.return_value = b"FROM ubuntu:22.04\n"
        tag2 = executor.ensure_image()

        assert tag1 != tag2
        assert mock_run.call_count == 4

    @patch("subprocess.run")
    def test_image_exists(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_image_exists returns True when image exists."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.return_value = MagicMock(returncode=0)

        assert executor._image_exists("airut:test") is True
        mock_run.assert_called_once_with(
            ["podman", "image", "inspect", "airut:test"],
            check=True,
            capture_output=True,
            text=True,
        )

    @patch("subprocess.run")
    def test_image_exists_false(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """_image_exists returns False when image doesn't exist."""
        executor = _make_executor(mock_mirror, docker_dir)
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["podman", "image", "inspect"]
        )

        assert executor._image_exists("airut:test") is False


class TestContainerCommandOverride:
    """Tests for container_command configuration."""

    def test_container_command_defaults_to_podman(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """container_command defaults to 'podman'."""
        executor = _make_executor(mock_mirror, docker_dir)

        assert executor.container_command == "podman"

    def test_container_command_from_constructor(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """container_command uses constructor argument."""
        executor = _make_executor(
            mock_mirror, docker_dir, container_command="docker"
        )

        assert executor.container_command == "docker"

    @patch("subprocess.run")
    def test_custom_container_command_used_in_build(
        self,
        mock_run: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
    ) -> None:
        """ensure_image() uses container_command for build."""
        executor = _make_executor(
            mock_mirror, docker_dir, container_command="custom-container"
        )
        mock_run.return_value = MagicMock(returncode=0)

        executor.ensure_image()

        for call in mock_run.call_args_list:
            assert call[0][0][0] == "custom-container"

    @patch("lib.container.executor.subprocess.Popen")
    def test_custom_container_command_used_in_execute(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() uses container_command for run."""
        executor = _make_executor(
            mock_mirror, docker_dir, container_command="custom-container"
        )

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        streaming_output = (
            '{"type": "system", "subtype": "init", "session_id": "s1"}\n'
            '{"type": "result", "subtype": "success", "session_id": "s1", '
            '"result": "Done"}'
        )
        mock_process = create_mock_popen(
            returncode=0, stdout=streaming_output, stderr=""
        )
        mock_popen.return_value = mock_process

        result = executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
        )

        assert result.success is True
        call_args = mock_popen.call_args[0][0]
        assert call_args[0] == "custom-container"
        assert call_args[1] == "run"


class TestExtractErrorSummary:
    """Tests for extract_error_summary function."""

    def test_empty_input_returns_none(self) -> None:
        """Returns None for empty or whitespace input."""
        from lib.container.executor import extract_error_summary

        assert extract_error_summary("") is None
        assert extract_error_summary("   ") is None
        assert extract_error_summary("\n\n") is None

    def test_extracts_result_text(self) -> None:
        """Extracts text from result event."""
        from lib.container.executor import extract_error_summary

        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            '{"type": "result", "result": "Error: Something failed"}'
        )

        result = extract_error_summary(stdout)

        assert result == "Error: Something failed"

    def test_extracts_assistant_text_blocks(self) -> None:
        """Extracts text from assistant messages when no result."""
        from lib.container.executor import extract_error_summary

        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "I encountered an error"}]}}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "The file was not found"}]}}'
        )

        result = extract_error_summary(stdout)

        assert result is not None
        assert "I encountered an error" in result
        assert "The file was not found" in result

    def test_prefers_result_over_assistant_text(self) -> None:
        """Prefers result text over assistant text blocks."""
        from lib.container.executor import extract_error_summary

        stdout = (
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Some assistant text"}]}}\n'
            '{"type": "result", "result": "Final error message"}'
        )

        result = extract_error_summary(stdout)

        assert result == "Final error message"

    def test_truncates_to_max_lines(self) -> None:
        """Truncates output to max_lines, keeping last lines."""
        from lib.container.executor import extract_error_summary

        lines = [f"Line {i}" for i in range(20)]
        result_text = "\n".join(lines)
        stdout = f'{{"type": "result", "result": {json.dumps(result_text)}}}'

        result = extract_error_summary(stdout, max_lines=5)

        assert result is not None
        result_lines = result.split("\n")
        assert len(result_lines) == 5
        assert "Line 15" in result
        assert "Line 19" in result

    def test_handles_non_json_lines(self) -> None:
        """Skips non-JSON lines gracefully."""
        from lib.container.executor import extract_error_summary

        stdout = (
            "Some random text\n"
            '{"type": "result", "result": "Actual error"}\n'
            "More non-json\n"
        )

        result = extract_error_summary(stdout)

        assert result == "Actual error"

    def test_handles_non_dict_json(self) -> None:
        """Skips JSON lines that are not dicts."""
        from lib.container.executor import extract_error_summary

        stdout = (
            "[1, 2, 3]\n"
            '"just a string"\n'
            '{"type": "result", "result": "Real error"}'
        )

        result = extract_error_summary(stdout)

        assert result == "Real error"

    def test_returns_none_if_no_useful_content(self) -> None:
        """Returns None when no text or result found."""
        from lib.container.executor import extract_error_summary

        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            '{"type": "user", "message": "some user message"}'
        )

        result = extract_error_summary(stdout)

        assert result is None

    def test_handles_empty_result(self) -> None:
        """Returns None when result is empty string."""
        from lib.container.executor import extract_error_summary

        stdout = '{"type": "result", "result": ""}'

        result = extract_error_summary(stdout)

        assert result is None

    def test_handles_tool_use_blocks(self) -> None:
        """Ignores tool_use blocks in assistant messages."""
        from lib.container.executor import extract_error_summary

        stdout = (
            '{"type": "assistant", "message": {"content": '
            '[{"type": "tool_use", "name": "some_tool", "input": {}}]}}\n'
            '{"type": "assistant", "message": {"content": '
            '[{"type": "text", "text": "Error occurred"}]}}'
        )

        result = extract_error_summary(stdout)

        assert result == "Error occurred"

    def test_skips_empty_lines_in_output(self) -> None:
        """Skips empty lines between JSON events."""
        from lib.container.executor import extract_error_summary

        stdout = (
            '{"type": "system", "subtype": "init"}\n'
            "\n"
            "   \n"
            '{"type": "result", "result": "Error message"}\n'
            "\n"
        )

        result = extract_error_summary(stdout)

        assert result == "Error message"

    def test_truncates_text_blocks_to_max_lines(self) -> None:
        """Truncates text blocks output to max_lines, keeping last lines."""
        from lib.container.executor import extract_error_summary

        stdout = ""
        for i in range(15):
            stdout += (
                f'{{"type": "assistant", "message": {{"content": '
                f'[{{"type": "text", "text": "Line {i}"}}]}}}}\n'
            )

        result = extract_error_summary(stdout, max_lines=5)

        assert result is not None
        result_lines = result.split("\n")
        assert len(result_lines) == 5
        assert "Line 10" in result
        assert "Line 14" in result
        assert "Line 0" not in result


class TestStopExecution:
    """Tests for stop_execution functionality."""

    def test_stop_execution_success(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """stop_execution() terminates a running process successfully."""
        executor = _make_executor(mock_mirror, docker_dir)

        mock_process = MagicMock()
        mock_process.send_signal = MagicMock()
        mock_process.wait = MagicMock(return_value=None)

        executor._running_processes["test-conv-id"] = mock_process

        result = executor.stop_execution("test-conv-id")

        assert result is True
        mock_process.send_signal.assert_called_once()
        mock_process.wait.assert_called_once()
        assert "test-conv-id" not in executor._running_processes

    def test_stop_execution_not_found(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """stop_execution() returns False when process not found."""
        executor = _make_executor(mock_mirror, docker_dir)

        result = executor.stop_execution("nonexistent-id")

        assert result is False

    def test_stop_execution_force_kill(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """stop_execution() force kills if graceful termination fails."""
        from subprocess import TimeoutExpired

        executor = _make_executor(mock_mirror, docker_dir)

        mock_process = MagicMock()
        mock_process.send_signal = MagicMock()
        mock_process.wait = MagicMock(
            side_effect=[TimeoutExpired("cmd", 5), None]
        )
        mock_process.kill = MagicMock()

        executor._running_processes["test-conv-id"] = mock_process

        result = executor.stop_execution("test-conv-id")

        assert result is True
        mock_process.send_signal.assert_called_once()
        assert mock_process.wait.call_count == 2
        mock_process.kill.assert_called_once()

    def test_stop_execution_handles_errors(
        self, mock_mirror: MagicMock, docker_dir: Path
    ) -> None:
        """stop_execution() handles exceptions gracefully."""
        executor = _make_executor(mock_mirror, docker_dir)

        mock_process = MagicMock()
        mock_process.send_signal.side_effect = OSError("Process error")

        executor._running_processes["test-conv-id"] = mock_process

        result = executor.stop_execution("test-conv-id")

        assert result is False

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_tracks_process(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() tracks running process when conversation_id provided."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        mock_process = create_mock_popen(
            returncode=0,
            stdout='{"result": "test", "session_id": "s1"}',
            stderr="",
        )
        mock_popen.return_value = mock_process

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
            conversation_id="test-conv-id",
        )

        assert "test-conv-id" not in executor._running_processes

    @patch("lib.container.executor.subprocess.Popen")
    def test_execute_with_callback(
        self,
        mock_popen: MagicMock,
        mock_mirror: MagicMock,
        docker_dir: Path,
        tmp_path: Path,
    ) -> None:
        """execute() invokes callback for each event when provided."""
        executor = _make_executor(mock_mirror, docker_dir)

        session_git_repo = tmp_path / "workspace"
        session_git_repo.mkdir()

        streaming_output = (
            "Non-JSON line\n"
            '{"type": "system", "session_id": "s1"}\n'
            "Another non-JSON line\n"
            '{"type": "assistant", "message": "test"}\n'
            '{"type": "result", "session_id": "s1", "result": "done"}'
        )
        mock_process = create_mock_popen(
            returncode=0,
            stdout=streaming_output,
            stderr="",
        )
        mock_popen.return_value = mock_process

        events_received = []

        def callback(event: dict) -> None:
            events_received.append(event)

        executor.execute(
            session_git_repo,
            "Test prompt",
            mounts=SAMPLE_MOUNTS,
            image_tag="airut:test",
            on_event=callback,
        )

        assert len(events_received) == 3
        assert events_received[0]["type"] == "system"
        assert events_received[1]["type"] == "assistant"
        assert events_received[2]["type"] == "result"
