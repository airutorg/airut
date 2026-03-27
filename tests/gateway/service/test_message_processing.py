# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for message_processing module."""

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from airut.claude_output.types import Usage
from airut.dashboard.tracker import CompletionReason
from airut.gateway.channel import ChannelSendError, ParsedMessage
from airut.gateway.config import RepoServerConfig
from airut.gateway.service import build_recovery_prompt
from airut.gateway.service.message_processing import process_message
from airut.sandbox import ExecutionResult, Outcome
from airut.sandbox.claude_binary import ClaudeBinaryError
from airut.sandbox.types import ResourceLimits

from .conftest import make_service, update_global, update_repo


def _make_parsed_message(
    *,
    sender: str = "user@example.com",
    body: str = "Hello",
    conversation_id: str | None = None,
    model_hint: str | None = None,
    channel_context: str = "Email context",
    subject: str = "",
) -> ParsedMessage:
    """Build a ParsedMessage for testing."""
    return ParsedMessage(
        sender=sender,
        body=body,
        conversation_id=conversation_id,
        model_hint=model_hint,
        channel_context=channel_context,
        subject=subject,
    )


def _make_success_result(
    response_text: str = "Done!",
    total_cost_usd: float = 0.01,
) -> ExecutionResult:
    """Create a successful ExecutionResult for testing."""
    return ExecutionResult(
        outcome=Outcome.SUCCESS,
        session_id="test-session",
        response_text=response_text,
        duration_ms=100,
        total_cost_usd=total_cost_usd,
        num_turns=1,
        is_error=False,
        usage=Usage(),
        web_search_count=0,
        web_fetch_count=0,
        error_summary=None,
    )


def _make_failure_result(
    outcome: Outcome = Outcome.CONTAINER_FAILED,
    error_summary: str | None = None,
    session_id: str = "",
) -> ExecutionResult:
    """Create a failed ExecutionResult for testing."""
    return ExecutionResult(
        outcome=outcome,
        session_id=session_id,
        response_text="",
        duration_ms=100,
        total_cost_usd=0.0,
        num_turns=0,
        is_error=True,
        usage=Usage(),
        web_search_count=0,
        web_fetch_count=0,
        error_summary=error_summary,
    )


class TestMakeTodoCallback:
    """Tests for _make_todo_callback."""

    def test_captures_todowrite_event(self) -> None:
        """Callback extracts todos from TodoWrite tool use events."""
        from airut.claude_output.types import (
            EventType,
            StreamEvent,
            ToolUseBlock,
        )
        from airut.dashboard.tracker import (
            TaskTracker,
            TodoItem,
            TodoStatus,
        )
        from airut.gateway.service.message_processing import (
            _make_todo_callback,
        )

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        callback = _make_todo_callback(tracker, "abc12345")

        todos_raw = [
            {"content": "Run tests", "status": "in_progress"},
            {"content": "Fix bugs", "status": "pending"},
        ]
        event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="s1",
            content_blocks=(
                ToolUseBlock(
                    tool_id="t1",
                    tool_name="TodoWrite",
                    tool_input={"todos": todos_raw},
                ),
            ),
            raw="{}",
        )
        callback(event)

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is not None
        assert len(task.todos) == 2
        assert isinstance(task.todos[0], TodoItem)
        assert task.todos[0].content == "Run tests"
        assert task.todos[0].status == TodoStatus.IN_PROGRESS
        assert task.todos[1].content == "Fix bugs"
        assert task.todos[1].status == TodoStatus.PENDING

    def test_ignores_non_todowrite_events(self) -> None:
        """Callback ignores tool uses that aren't TodoWrite."""
        from airut.claude_output.types import (
            EventType,
            StreamEvent,
            TextBlock,
            ToolUseBlock,
        )
        from airut.dashboard.tracker import TaskTracker
        from airut.gateway.service.message_processing import (
            _make_todo_callback,
        )

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        callback = _make_todo_callback(tracker, "abc12345")

        # Text block — should be ignored
        text_event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="s1",
            content_blocks=(TextBlock(text="hello"),),
            raw="{}",
        )
        callback(text_event)

        # Other tool — should be ignored
        other_event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="s1",
            content_blocks=(
                ToolUseBlock(
                    tool_id="t1",
                    tool_name="Bash",
                    tool_input={"command": "ls"},
                ),
            ),
            raw="{}",
        )
        callback(other_event)

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is None

    def test_forwards_to_plan_streamer(self) -> None:
        """Callback forwards TodoWrite items to the plan streamer."""
        from unittest.mock import MagicMock

        from airut.claude_output.types import (
            EventType,
            StreamEvent,
            ToolUseBlock,
        )
        from airut.dashboard.tracker import TaskTracker
        from airut.gateway.service.message_processing import (
            _make_todo_callback,
        )

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        mock_streamer = MagicMock()

        callback = _make_todo_callback(
            tracker, "abc12345", plan_streamer=mock_streamer
        )

        todos_raw = [
            {"content": "Run tests", "status": "in_progress"},
        ]
        event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="s1",
            content_blocks=(
                ToolUseBlock(
                    tool_id="t1",
                    tool_name="TodoWrite",
                    tool_input={"todos": todos_raw},
                ),
            ),
            raw="{}",
        )
        callback(event)

        mock_streamer.update.assert_called_once()
        items = mock_streamer.update.call_args[0][0]
        assert len(items) == 1
        assert items[0].content == "Run tests"

    def test_no_plan_streamer_no_error(self) -> None:
        """Callback works with plan_streamer=None (default)."""
        from airut.claude_output.types import (
            EventType,
            StreamEvent,
            ToolUseBlock,
        )
        from airut.dashboard.tracker import TaskTracker
        from airut.gateway.service.message_processing import (
            _make_todo_callback,
        )

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        callback = _make_todo_callback(tracker, "abc12345")

        todos_raw = [{"content": "Run tests", "status": "pending"}]
        event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="s1",
            content_blocks=(
                ToolUseBlock(
                    tool_id="t1",
                    tool_name="TodoWrite",
                    tool_input={"todos": todos_raw},
                ),
            ),
            raw="{}",
        )
        # Should not raise
        callback(event)

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is not None

    def test_non_todowrite_ignored_by_callback(self) -> None:
        """Non-TodoWrite tool use is ignored (no action forwarding)."""
        from unittest.mock import MagicMock

        from airut.claude_output.types import (
            EventType,
            StreamEvent,
            ToolUseBlock,
        )
        from airut.dashboard.tracker import TaskTracker
        from airut.gateway.service.message_processing import (
            _make_todo_callback,
        )

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")
        mock_streamer = MagicMock()

        callback = _make_todo_callback(
            tracker, "abc12345", plan_streamer=mock_streamer
        )

        event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="s1",
            content_blocks=(
                ToolUseBlock(
                    tool_id="t1",
                    tool_name="Bash",
                    tool_input={"command": "ls"},
                ),
            ),
            raw="{}",
        )
        callback(event)

        mock_streamer.update.assert_not_called()

    def test_ignores_invalid_todos_value(self) -> None:
        """Callback ignores TodoWrite with non-list todos."""
        from airut.claude_output.types import (
            EventType,
            StreamEvent,
            ToolUseBlock,
        )
        from airut.dashboard.tracker import TaskTracker
        from airut.gateway.service.message_processing import (
            _make_todo_callback,
        )

        tracker = TaskTracker()
        tracker.add_task("abc12345", "Test")

        callback = _make_todo_callback(tracker, "abc12345")

        # todos is a string, not a list
        event = StreamEvent(
            event_type=EventType.ASSISTANT,
            subtype="",
            session_id="s1",
            content_blocks=(
                ToolUseBlock(
                    tool_id="t1",
                    tool_name="TodoWrite",
                    tool_input={"todos": "not a list"},
                ),
            ),
            raw="{}",
        )
        callback(event)

        task = tracker.get_task("abc12345")
        assert task is not None
        assert task.todos is None


class TestProcessMessage:
    @pytest.fixture(autouse=True)
    def _patch_build_task_env(self):
        """Patch build_task_env for all process message tests."""
        with patch.object(
            RepoServerConfig,
            "build_task_env",
            return_value=({}, {}),
        ) as mock_bte:
            self._mock_build_task_env = mock_bte
            yield

    def _setup_svc(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> tuple[Any, Any, MagicMock, MagicMock]:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        update_repo(handler, resource_limits=ResourceLimits(timeout=300))

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        (repo_path / "inbox").mkdir()
        (repo_path / "outbox").mkdir()

        handler.conversation_manager.exists.return_value = False
        handler.conversation_manager.initialize_new.return_value = (
            "conv1",
            repo_path,
        )
        handler.conversation_manager.get_conversation_dir.return_value = (
            tmp_path / "conversations"
        )
        handler.conversation_manager.get_workspace_path.return_value = repo_path
        mock_mirror = MagicMock()
        mock_mirror.list_directory.return_value = ["Dockerfile"]

        def _read_file(path: str) -> bytes:
            if "Dockerfile" in path:
                return b"FROM python:3.13-slim\n"
            if "network-allowlist" in path:
                return b"domains: []\nurl_prefixes: []\n"
            return b""

        mock_mirror.read_file.side_effect = _read_file
        handler.conversation_manager.mirror = mock_mirror

        mock_conv_store = MagicMock()
        mock_conv_store.get_session_id_for_resume.return_value = None
        mock_conv_store.get_model.return_value = None
        mock_conv_store.get_effort.return_value = None

        # Configure sandbox mock: ensure_image returns tag,
        # create_task returns a mock Task whose execute returns success
        mock_task = MagicMock()
        mock_task.execute = AsyncMock(return_value=_make_success_result())
        mock_task.event_log = MagicMock()
        svc.sandbox.ensure_image.return_value = "airut:test"
        svc.sandbox.create_task.return_value = mock_task
        svc._mock_task = mock_task  # Store for test access

        # Create mock adapter
        adapter = MagicMock()
        adapter.save_attachments.return_value = []

        return svc, handler, mock_conv_store, adapter

    def test_new_conversation_success(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.SUCCESS
        assert conv_id == "conv1"
        adapter.send_reply.assert_called_once()

    def test_empty_body_rejected_for_resumed_conversation(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Empty body rejected when resuming a conversation."""
        svc, handler, _, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="", conversation_id="aabb1122")

        reason, conv_id = process_message(
            svc, parsed, "task1", handler, adapter
        )
        assert reason != CompletionReason.SUCCESS
        adapter.send_error.assert_called_once()

    def test_empty_body_rejected_without_subject(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Empty body rejected when no subject."""
        svc, handler, _, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="")

        reason, conv_id = process_message(
            svc, parsed, "task1", handler, adapter
        )
        assert reason != CompletionReason.SUCCESS
        adapter.send_error.assert_called_once()

    def test_empty_body_allowed_with_subject(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Empty body allowed when subject is present."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="", subject="Fix the bug")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.SUCCESS
        assert conv_id == "conv1"
        adapter.send_reply.assert_called_once()

    def test_execution_failure(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                error_summary="FATAL: OOM",
            )
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )
        assert reason == CompletionReason.EXECUTION_FAILED
        assert conv_id == "conv1"

    def test_container_timeout(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                outcome=Outcome.TIMEOUT,
            )
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )
        assert reason == CompletionReason.TIMEOUT
        error_msg = adapter.send_error.call_args[0][2]
        assert "after 300 seconds" in error_msg

    def test_container_timeout_no_timeout_value(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Timeout message is clean when no timeout value is configured."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, resource_limits=ResourceLimits(timeout=None))
        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                outcome=Outcome.TIMEOUT,
            )
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )
        assert reason == CompletionReason.TIMEOUT
        error_msg = adapter.send_error.call_args[0][2]
        assert "The task was interrupted." in error_msg
        assert "interrupted ." not in error_msg

    def test_git_clone_error(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        from airut.gateway import GitCloneError

        svc, handler, _, adapter = self._setup_svc(email_config, tmp_path)
        handler.conversation_manager.initialize_new.side_effect = GitCloneError(
            "clone failed"
        )
        parsed = _make_parsed_message(body="Do something")
        reason, conv_id = process_message(
            svc, parsed, "task1", handler, adapter
        )
        assert reason != CompletionReason.SUCCESS
        assert conv_id is None

    def test_unexpected_error(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        svc._mock_task.execute = AsyncMock(
            side_effect=RuntimeError("unexpected")
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )
        assert reason == CompletionReason.INTERNAL_ERROR

    def test_channel_send_error(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        adapter.send_reply.side_effect = ChannelSendError("SMTP rate limit")
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )
        assert reason == CompletionReason.CHANNEL_ERROR
        assert conv_id == "conv1"

    def test_resume_existing_conversation(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_cs.get_model.return_value = "opus"
        mock_cs.get_session_id_for_resume.return_value = "session-abc"

        parsed = _make_parsed_message(
            body="Continue", conversation_id="aabb1122"
        )

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "conv1", handler, adapter
            )
        assert reason == CompletionReason.SUCCESS
        # Mirror should be updated before resuming
        handler.conversation_manager.mirror.update_mirror.assert_called_once()
        # Should not send acknowledgment for resumed conversations
        adapter.send_acknowledgment.assert_not_called()
        # Only the reply
        adapter.send_reply.assert_called_once()

    def test_model_hint_used_for_new_conversation(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do stuff", model_hint="opus")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        # task.execute should be called with opus model
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["model"] == "opus"

    def test_default_effort_passed_to_execute(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, effort="max")

        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["effort"] == "max"

    def test_effort_none_by_default(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["effort"] is None

    def test_effort_persisted_for_resumed_conversation(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_cs.get_model.return_value = "opus"
        mock_cs.get_effort.return_value = "high"
        mock_cs.get_session_id_for_resume.return_value = None
        mock_cs.load.return_value = MagicMock(replies=[])

        parsed = _make_parsed_message(
            body="Continue",
            conversation_id="aabb1122",
        )

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "conv1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["effort"] == "high"

    def test_server_model_used_as_sole_source(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, model="haiku")

        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["model"] == "haiku"

    def test_server_effort_used_as_sole_source(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, effort="low")

        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["effort"] == "low"

    def test_channel_hint_overrides_server_model(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, model="opus", effort="max")

        parsed = _make_parsed_message(body="Do stuff", model_hint="sonnet")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        # Channel hint overrides server model
        assert call_kwargs["model"] == "sonnet"
        assert call_kwargs["effort"] == "max"

    def test_channel_hint_overrides_server_model_preference(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, model="haiku")

        parsed = _make_parsed_message(body="Do stuff", model_hint="opus")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        # Channel hint takes priority over server model
        assert call_kwargs["model"] == "opus"

    def test_server_model_used_when_no_channel_hint(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, model="haiku")

        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["model"] == "haiku"

    def test_server_effort_used_directly(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, effort="low")

        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["effort"] == "low"

    def test_server_override_not_used_for_resumed_conversation(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, model="haiku", effort="low")
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_cs.get_model.return_value = "opus"
        mock_cs.get_effort.return_value = "max"
        mock_cs.get_session_id_for_resume.return_value = None
        mock_cs.load.return_value = MagicMock(replies=[])

        parsed = _make_parsed_message(
            body="Continue",
            conversation_id="aabb1122",
        )

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "conv1", handler, adapter)
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["model"] == "opus"
        assert call_kwargs["effort"] == "max"

    def test_attachments_saved(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        # Adapter returns attachment filenames
        adapter.save_attachments.return_value = ["report.pdf"]
        parsed = _make_parsed_message(body="See attached")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        # Prompt should mention inbox
        call_args = svc._mock_task.execute.call_args
        assert "report.pdf" in call_args[0][0]  # positional prompt arg

    def test_usage_stats_footer(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Check")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        # Reply should contain cost footer via adapter
        adapter.send_reply.assert_called_once()
        # Check the usage_footer arg (5th positional)
        assert "Cost:" in str(adapter.send_reply.call_args)

    def test_success_calls_add_reply(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Successful execution records reply via add_reply."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)

        mock_cs.add_reply.assert_called_once()
        call_args = mock_cs.add_reply.call_args
        assert call_args[0][0] == "conv1"  # conversation_id

    def test_event_log_start_new_reply_called(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """task.event_log.start_new_reply() is called before execution."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)

        svc._mock_task.event_log.start_new_reply.assert_called_once()

    def test_resumed_conversation_ignores_model_request(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_cs.get_model.return_value = "sonnet"
        mock_cs.get_session_id_for_resume.return_value = None

        parsed = _make_parsed_message(
            body="Continue",
            conversation_id="aabb1122",
            model_hint="opus",
        )

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "conv1", handler, adapter)
        # Should use stored model, not requested
        call_kwargs = svc._mock_task.execute.call_args[1]
        assert call_kwargs["model"] == "sonnet"

    def test_task_id_updated_for_new_conversation(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "temp-123", handler, adapter)
        svc.tracker.set_conversation_id.assert_called_once_with(
            "temp-123", "conv1"
        )

    def test_long_subject_truncated_in_log(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Long messages don't crash processing."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        # Just verify it doesn't crash

    def test_no_usage_stats_no_footer(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        # Result with no cost → no usage stats footer
        svc._mock_task.execute = AsyncMock(
            return_value=_make_success_result(total_cost_usd=0.0)
        )
        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        # Check that usage_footer is empty
        call_args = adapter.send_reply.call_args
        usage_footer = call_args[0][3]  # 4th positional arg
        assert usage_footer == ""

    def test_cost_shown_with_api_key_only(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Cost shown when only ANTHROPIC_API_KEY is set."""
        self._mock_build_task_env.return_value = (
            {"ANTHROPIC_API_KEY": "sk-test"},
            {},
        )
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Check")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        assert "Cost:" in str(adapter.send_reply.call_args)

    def test_cost_hidden_with_oauth_only(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Cost hidden when only OAuth token is set."""
        self._mock_build_task_env.return_value = (
            {"CLAUDE_CODE_OAUTH_TOKEN": "tok"},
            {},
        )
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Check")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        assert "Cost:" not in str(adapter.send_reply.call_args)

    def test_cost_shown_with_both_api_key_and_oauth(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Cost shown when both are set (API key takes priority)."""
        self._mock_build_task_env.return_value = (
            {
                "ANTHROPIC_API_KEY": "sk-test",
                "CLAUDE_CODE_OAUTH_TOKEN": "tok",
            },
            {},
        )
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Check")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            process_message(svc, parsed, "task1", handler, adapter)
        assert "Cost:" in str(adapter.send_reply.call_args)

    def test_failure_with_no_error_summary(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        svc._mock_task.execute = AsyncMock(return_value=_make_failure_result())
        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, _ = process_message(svc, parsed, "task1", handler, adapter)
        assert reason == CompletionReason.EXECUTION_FAILED
        # Check that reply uses the short error format via adapter
        call_args = adapter.send_reply.call_args
        response_text = call_args[0][2]  # 3rd positional arg
        assert "An error occurred" in response_text

    def test_failure_with_error_summary(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                error_summary="Error summary text",
            )
        )
        parsed = _make_parsed_message(body="Do stuff")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, _ = process_message(svc, parsed, "task1", handler, adapter)
        assert reason == CompletionReason.EXECUTION_FAILED
        # Claude output is included when error_summary exists
        call_args = adapter.send_reply.call_args
        response_text = call_args[0][2]  # 3rd positional arg
        assert "Claude output:" in response_text
        assert "Error summary text" in response_text

    def test_execution_failure_persists_session(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Conversation store must be updated even when execution fails."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                session_id="err-session-1",
            )
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.EXECUTION_FAILED
        mock_cs.add_reply.assert_called_once()
        call_args = mock_cs.add_reply.call_args
        assert call_args[0][0] == "conv1"  # conversation_id

    def test_container_timeout_persists_session(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Store must be updated on container timeout."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                outcome=Outcome.TIMEOUT,
            )
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        mock_cs.add_reply.assert_called_once()
        call_args = mock_cs.add_reply.call_args
        assert call_args[0][0] == "conv1"  # conversation_id

    def test_unexpected_error_persists_session(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Conversation store must be updated on unexpected exceptions."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        svc._mock_task.execute = AsyncMock(
            side_effect=RuntimeError("unexpected")
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        mock_cs.add_reply.assert_called_once()
        call_args = mock_cs.add_reply.call_args
        assert call_args[0][0] == "conv1"  # conversation_id

    def test_unexpected_error_persist_failure_handled(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Persist failure in catch-all handler is logged, not raised."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        svc._mock_task.execute = AsyncMock(
            side_effect=RuntimeError("unexpected")
        )
        mock_cs.add_reply.side_effect = OSError("disk full")
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        assert conv_id == "conv1"

    def test_prompt_too_long_retries_with_new_session(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Prompt-too-long error triggers retry with fresh session."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        # Simulate resuming an existing conversation
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_cs.get_session_id_for_resume.return_value = "old-session-id"
        mock_cs.get_last_successful_response.return_value = "I created the PR."

        # First call: prompt too long; second call: success
        prompt_too_long_result = _make_failure_result(
            outcome=Outcome.PROMPT_TOO_LONG,
        )
        success_result = _make_success_result(
            response_text="Recovered!",
        )

        mock_task1 = MagicMock()
        mock_task1.execute = AsyncMock(return_value=prompt_too_long_result)
        mock_task1.event_log = MagicMock()

        mock_task2 = MagicMock()
        mock_task2.execute = AsyncMock(return_value=success_result)
        mock_task2.event_log = MagicMock()

        svc.sandbox.create_task.side_effect = [mock_task1, mock_task2]

        parsed = _make_parsed_message(
            body="Continue please", conversation_id="aabb1122"
        )

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.SUCCESS
        # Should have created two tasks: first attempt + retry
        assert svc.sandbox.create_task.call_count == 2
        # First task: called with session_id
        first_call = mock_task1.execute.call_args
        assert first_call[1]["session_id"] == "old-session-id"
        # Second task: called without session_id
        second_call = mock_task2.execute.call_args
        assert second_call[1]["session_id"] is None
        # Recovery prompt should mention context loss
        assert "context length limits" in second_call[0][0]
        # Should include last response
        assert "I created the PR." in second_call[0][0]

    def test_prompt_too_long_no_retry_without_session_id(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Prompt-too-long without session_id does not retry (new conv)."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        mock_cs.get_session_id_for_resume.return_value = None

        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                outcome=Outcome.PROMPT_TOO_LONG,
            )
        )

        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        # Should only create one task (no retry)
        assert svc.sandbox.create_task.call_count == 1

    def test_session_corrupted_retries_with_new_session(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """API 4xx error triggers retry with fresh session."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        # Simulate resuming an existing conversation
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_cs.get_session_id_for_resume.return_value = "old-session-id"
        mock_cs.get_last_successful_response.return_value = "Previous work."

        # First call: session corrupted; second call: success
        corrupted_result = _make_failure_result(
            outcome=Outcome.SESSION_CORRUPTED,
        )
        success_result = _make_success_result(
            response_text="Recovered!",
        )

        mock_task1 = MagicMock()
        mock_task1.execute = AsyncMock(return_value=corrupted_result)
        mock_task1.event_log = MagicMock()

        mock_task2 = MagicMock()
        mock_task2.execute = AsyncMock(return_value=success_result)
        mock_task2.event_log = MagicMock()

        svc.sandbox.create_task.side_effect = [mock_task1, mock_task2]

        parsed = _make_parsed_message(
            body="Continue please", conversation_id="aabb1122"
        )

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.SUCCESS
        assert svc.sandbox.create_task.call_count == 2
        first_call = mock_task1.execute.call_args
        assert first_call[1]["session_id"] == "old-session-id"
        second_call = mock_task2.execute.call_args
        assert second_call[1]["session_id"] is None
        assert "context length limits" in second_call[0][0]

    def test_session_corrupted_no_retry_without_session_id(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """API 4xx without session_id does not retry (new conversation)."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        mock_cs.get_session_id_for_resume.return_value = None

        svc._mock_task.execute = AsyncMock(
            return_value=_make_failure_result(
                outcome=Outcome.SESSION_CORRUPTED,
            )
        )

        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        # Should only create one task (no retry)
        assert svc.sandbox.create_task.call_count == 1


class TestClaudeBinaryError:
    """Tests for ClaudeBinaryError handling in process_message."""

    @pytest.fixture(autouse=True)
    def _patch_build_task_env(self):
        """Patch build_task_env for all tests."""
        with patch.object(
            RepoServerConfig,
            "build_task_env",
            return_value=({}, {}),
        ) as mock_bte:
            self._mock_build_task_env = mock_bte
            yield

    def _setup_svc(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> tuple[Any, Any, MagicMock, MagicMock]:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        update_repo(handler, resource_limits=ResourceLimits(timeout=300))

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        (repo_path / "inbox").mkdir()
        (repo_path / "outbox").mkdir()

        handler.conversation_manager.exists.return_value = False
        handler.conversation_manager.initialize_new.return_value = (
            "conv1",
            repo_path,
        )
        handler.conversation_manager.get_conversation_dir.return_value = (
            tmp_path / "conversations"
        )
        handler.conversation_manager.get_workspace_path.return_value = repo_path
        mock_mirror = MagicMock()
        mock_mirror.list_directory.return_value = ["Dockerfile"]

        def _read_file(path: str) -> bytes:
            if "Dockerfile" in path:
                return b"FROM python:3.13-slim\n"
            if "network-allowlist" in path:
                return b"domains: []\nurl_prefixes: []\n"
            return b""

        mock_mirror.read_file.side_effect = _read_file
        handler.conversation_manager.mirror = mock_mirror

        mock_conv_store = MagicMock()
        mock_conv_store.get_session_id_for_resume.return_value = None
        mock_conv_store.get_model.return_value = None
        mock_conv_store.get_effort.return_value = None

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(return_value=_make_success_result())
        mock_task.event_log = MagicMock()
        svc.sandbox.ensure_image.return_value = "airut:test"
        svc.sandbox.create_task.return_value = mock_task

        adapter = MagicMock()
        adapter.save_attachments.return_value = []

        return svc, handler, mock_conv_store, adapter

    def test_binary_fetch_error_sends_error_reply(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """ClaudeBinaryError during binary fetch sends error to user."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        svc.claude_binary_cache.ensure.side_effect = ClaudeBinaryError(
            "download failed"
        )

        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_cs,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.EXECUTION_FAILED
        adapter.send_error.assert_called_once()


class TestSandboxDisabledWarning:
    """Tests for sandbox-disabled warning log messages."""

    def _setup_svc(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> tuple[Any, Any, MagicMock, MagicMock]:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)
        update_repo(
            handler,
            network_sandbox_enabled=False,
            resource_limits=ResourceLimits(timeout=300),
        )

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        (repo_path / "inbox").mkdir()
        (repo_path / "outbox").mkdir()

        handler.conversation_manager.exists.return_value = False
        handler.conversation_manager.initialize_new.return_value = (
            "conv1",
            repo_path,
        )
        handler.conversation_manager.get_workspace_path.return_value = repo_path
        mock_mirror = MagicMock()
        mock_mirror.list_directory.return_value = ["Dockerfile"]
        mock_mirror.read_file.return_value = b"FROM python:3.13-slim\n"
        handler.conversation_manager.mirror = mock_mirror

        mock_cs = MagicMock()
        mock_cs.get_session_id_for_resume.return_value = None
        mock_cs.get_model.return_value = None
        mock_cs.get_effort.return_value = None

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(return_value=_make_success_result())
        mock_task.event_log = MagicMock()
        svc.sandbox.ensure_image.return_value = "airut:test"
        svc.sandbox.create_task.return_value = mock_task

        adapter = MagicMock()
        adapter.save_attachments.return_value = []

        return svc, handler, mock_cs, adapter

    def test_sandbox_disabled_logs_warning(
        self,
        email_config: RepoServerConfig,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Disabling sandbox logs a warning."""
        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Hello")

        import logging

        with (
            caplog.at_level(logging.WARNING),
            patch(
                "airut.gateway.service.message_processing.ConversationStore",
                return_value=mock_cs,
            ),
        ):
            process_message(svc, parsed, "task1", handler, adapter)

        assert any(
            "network sandbox disabled" in r.message for r in caplog.records
        )

    def test_sandbox_disabled_with_masked_secrets_logs_extra_warning(
        self,
        email_config: RepoServerConfig,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Disabled sandbox with masked secrets logs additional warning."""
        from airut.gateway.config import MaskedSecret

        svc, handler, mock_cs, adapter = self._setup_svc(email_config, tmp_path)

        # Add masked secret to trigger the extra warning
        object.__setattr__(
            handler.config,
            "masked_secrets",
            {
                "GH_TOKEN": MaskedSecret(
                    value="ghp_test",
                    scopes=frozenset(["api.github.com"]),
                    headers=("Authorization",),
                )
            },
        )

        parsed = _make_parsed_message(body="Hello")

        import logging

        with (
            caplog.at_level(logging.WARNING),
            patch(
                "airut.gateway.service.message_processing.ConversationStore",
                return_value=mock_cs,
            ),
        ):
            process_message(svc, parsed, "task1", handler, adapter)

        assert any(
            "masked secrets" in r.message.lower() for r in caplog.records
        )


class TestBuildImageErrors:
    """Tests for _build_image error paths exercised through process_message."""

    @pytest.fixture(autouse=True)
    def _patch_build_task_env(self):
        """Patch build_task_env for all build image error tests."""
        with patch.object(
            RepoServerConfig,
            "build_task_env",
            return_value=({}, {}),
        ):
            yield

    def _setup_svc(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> tuple[Any, Any, MagicMock, MagicMock]:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        (repo_path / "inbox").mkdir()
        (repo_path / "outbox").mkdir()

        handler.conversation_manager.exists.return_value = False
        handler.conversation_manager.initialize_new.return_value = (
            "conv1",
            repo_path,
        )
        handler.conversation_manager.get_conversation_dir.return_value = (
            tmp_path / "conversations"
        )
        handler.conversation_manager.get_workspace_path.return_value = repo_path
        mock_mirror = MagicMock()
        mock_mirror.list_directory.return_value = ["Dockerfile"]

        def _read_file(path: str) -> bytes:
            if "Dockerfile" in path:
                return b"FROM python:3.13-slim\n"
            if "network-allowlist" in path:
                return b"domains: []\nurl_prefixes: []\n"
            return b""

        mock_mirror.read_file.side_effect = _read_file
        handler.conversation_manager.mirror = mock_mirror

        mock_conv_store = MagicMock()
        mock_conv_store.get_session_id_for_resume.return_value = None
        mock_conv_store.get_model.return_value = None
        mock_conv_store.get_effort.return_value = None

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(return_value=_make_success_result())
        mock_task.event_log = MagicMock()
        svc.sandbox.ensure_image.return_value = "airut:test"
        svc.sandbox.create_task.return_value = mock_task
        svc._mock_task = mock_task

        adapter = MagicMock()
        adapter.save_attachments.return_value = []

        return svc, handler, mock_conv_store, adapter

    def test_list_directory_error_raises_image_build_error(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """mirror.list_directory failure is caught and sent as error."""
        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)
        handler.conversation_manager.mirror.list_directory.side_effect = (
            RuntimeError("mirror error")
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_ss,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        assert conv_id == "conv1"
        # Error reply should be sent via adapter
        adapter.send_error.assert_called_once()
        error_msg = adapter.send_error.call_args[0][2]
        assert "ImageBuildError" in error_msg

    def test_read_file_error_raises_image_build_error(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """mirror.read_file failure is caught and sent as error."""
        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)

        handler.conversation_manager.mirror.list_directory.return_value = [
            "Dockerfile"
        ]
        handler.conversation_manager.mirror.read_file.side_effect = (
            RuntimeError("read error")
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_ss,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        assert conv_id == "conv1"
        adapter.send_error.assert_called_once()
        error_msg = adapter.send_error.call_args[0][2]
        assert "ImageBuildError" in error_msg

    def test_no_dockerfile_raises_image_build_error(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Missing Dockerfile in directory listing raises ImageBuildError."""
        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)

        handler.conversation_manager.mirror.list_directory.return_value = [
            "requirements.txt",
            "setup.py",
        ]
        handler.conversation_manager.mirror.read_file.side_effect = (
            lambda path: b"content"
        )
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_ss,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        assert conv_id == "conv1"
        adapter.send_error.assert_called_once()
        error_msg = adapter.send_error.call_args[0][2]
        assert "ImageBuildError" in error_msg
        assert "No Dockerfile" in error_msg

    def test_custom_container_path_used(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """container_path from repo config is passed to mirror."""
        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)
        update_repo(handler, container_path=".devcontainer")

        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_ss,
        ):
            process_message(svc, parsed, "task1", handler, adapter)

        # Verify the mirror was queried with the custom path
        handler.conversation_manager.mirror.list_directory.assert_called_with(
            ".devcontainer"
        )


class TestAllowlistParseError:
    """Tests for network allowlist read/parse failure path."""

    @pytest.fixture(autouse=True)
    def _patch_build_task_env(self):
        """Patch build_task_env for allowlist error tests."""
        with patch.object(
            RepoServerConfig,
            "build_task_env",
            return_value=({}, {}),
        ):
            yield

    def _setup_svc(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> tuple[Any, Any, MagicMock, MagicMock]:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        (repo_path / "inbox").mkdir()
        (repo_path / "outbox").mkdir()

        handler.conversation_manager.exists.return_value = False
        handler.conversation_manager.initialize_new.return_value = (
            "conv1",
            repo_path,
        )
        handler.conversation_manager.get_conversation_dir.return_value = (
            tmp_path / "conversations"
        )
        handler.conversation_manager.get_workspace_path.return_value = repo_path
        mock_mirror = MagicMock()
        mock_mirror.list_directory.return_value = ["Dockerfile"]

        def _read_file(path: str) -> bytes:
            if "Dockerfile" in path:
                return b"FROM python:3.13-slim\n"
            if "network-allowlist" in path:
                raise RuntimeError("allowlist read error")
            return b""

        mock_mirror.read_file.side_effect = _read_file
        handler.conversation_manager.mirror = mock_mirror

        mock_conv_store = MagicMock()
        mock_conv_store.get_session_id_for_resume.return_value = None
        mock_conv_store.get_model.return_value = None
        mock_conv_store.get_effort.return_value = None

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(return_value=_make_success_result())
        mock_task.event_log = MagicMock()
        svc.sandbox.ensure_image.return_value = "airut:test"
        svc.sandbox.create_task.return_value = mock_task

        adapter = MagicMock()
        adapter.save_attachments.return_value = []

        return svc, handler, mock_conv_store, adapter

    def test_allowlist_read_error_raises_proxy_error(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """Failure reading/parsing allowlist raises ProxyError."""
        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)
        parsed = _make_parsed_message(body="Do something")

        with patch(
            "airut.gateway.service.message_processing.ConversationStore",
            return_value=mock_ss,
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason != CompletionReason.SUCCESS
        assert conv_id == "conv1"
        adapter.send_error.assert_called_once()
        error_msg = adapter.send_error.call_args[0][2]
        assert "ProxyError" in error_msg


class TestConvertReplacementMap:
    """Tests for _convert_replacement_map exercised through process_message."""

    def _setup_svc(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> tuple[Any, Any, MagicMock, MagicMock]:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)

        repo_path = tmp_path / "repo"
        repo_path.mkdir()
        (repo_path / "inbox").mkdir()
        (repo_path / "outbox").mkdir()

        handler.conversation_manager.exists.return_value = False
        handler.conversation_manager.initialize_new.return_value = (
            "conv1",
            repo_path,
        )
        handler.conversation_manager.get_conversation_dir.return_value = (
            tmp_path / "conversations"
        )
        handler.conversation_manager.get_workspace_path.return_value = repo_path
        mock_mirror = MagicMock()
        mock_mirror.list_directory.return_value = ["Dockerfile"]

        def _read_file(path: str) -> bytes:
            if "Dockerfile" in path:
                return b"FROM python:3.13-slim\n"
            if "network-allowlist" in path:
                return b"domains: []\nurl_prefixes: []\n"
            return b""

        mock_mirror.read_file.side_effect = _read_file
        handler.conversation_manager.mirror = mock_mirror

        mock_conv_store = MagicMock()
        mock_conv_store.get_session_id_for_resume.return_value = None
        mock_conv_store.get_model.return_value = None
        mock_conv_store.get_effort.return_value = None

        mock_task = MagicMock()
        mock_task.execute = AsyncMock(return_value=_make_success_result())
        mock_task.event_log = MagicMock()
        svc.sandbox.ensure_image.return_value = "airut:test"
        svc.sandbox.create_task.return_value = mock_task
        svc._mock_task = mock_task

        adapter = MagicMock()
        adapter.save_attachments.return_value = []

        return svc, handler, mock_conv_store, adapter

    def test_replacement_and_signing_entries_converted(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """ReplacementEntry and SigningCredentialEntry are converted."""
        from airut.gateway.config import (
            ReplacementEntry,
            SigningCredentialEntry,
        )

        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)

        replacement_map = {
            "surrogate-token-1": ReplacementEntry(
                real_value="real-secret-value",
                scopes=("api.github.com",),
                headers=("Authorization",),
            ),
            "surrogate-key-id": SigningCredentialEntry(
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key=("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
                session_token="FwoGZXIvYXdzEBY",
                surrogate_session_token="surr-session-token",
                scopes=("bedrock.us-east-1.amazonaws.com",),
            ),
        }

        parsed = _make_parsed_message(body="Do something")

        with (
            patch.object(
                RepoServerConfig,
                "build_task_env",
                return_value=({}, replacement_map),
            ),
            patch(
                "airut.gateway.service.message_processing.ConversationStore",
                return_value=mock_ss,
            ),
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.SUCCESS
        assert conv_id == "conv1"

        # Verify NetworkSandboxConfig was passed to create_task
        create_task_call = svc.sandbox.create_task.call_args
        network_sandbox = create_task_call[1]["network_sandbox"]
        assert network_sandbox is not None
        assert network_sandbox.replacements is not None

        # Verify the replacement map was properly converted
        replacements_dict = network_sandbox.replacements.to_dict()
        assert "surrogate-token-1" in replacements_dict
        assert replacements_dict["surrogate-token-1"]["value"] == (
            "real-secret-value"
        )
        assert "surrogate-key-id" in replacements_dict
        assert replacements_dict["surrogate-key-id"]["access_key_id"] == (
            "AKIAIOSFODNN7EXAMPLE"
        )
        assert replacements_dict["surrogate-key-id"]["type"] == "aws-sigv4"

    def test_allow_foreign_credentials_converted(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """allow_foreign_credentials is threaded through conversion."""
        from airut.gateway.config import ReplacementEntry

        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)

        replacement_map = {
            "surrogate-token-1": ReplacementEntry(
                real_value="real-secret-value",
                scopes=("api.github.com",),
                headers=("Authorization",),
                allow_foreign_credentials=True,
            ),
        }

        parsed = _make_parsed_message(body="Do something")

        with (
            patch.object(
                RepoServerConfig,
                "build_task_env",
                return_value=({}, replacement_map),
            ),
            patch(
                "airut.gateway.service.message_processing.ConversationStore",
                return_value=mock_ss,
            ),
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.SUCCESS

        create_task_call = svc.sandbox.create_task.call_args
        network_sandbox = create_task_call[1]["network_sandbox"]
        replacements_dict = network_sandbox.replacements.to_dict()
        assert (
            replacements_dict["surrogate-token-1"]["allow_foreign_credentials"]
            is True
        )

    def test_github_app_entries_converted(
        self, email_config: RepoServerConfig, tmp_path: Path
    ) -> None:
        """GitHubAppEntry entries are properly converted."""
        from airut.gateway.config import GitHubAppEntry

        svc, handler, mock_ss, adapter = self._setup_svc(email_config, tmp_path)

        replacement_map = {
            "ghs_SurrogateToken1234567890abcdefgh": GitHubAppEntry(
                app_id="Iv23liXyz",
                private_key="test-key",
                installation_id=12345,
                base_url="https://api.github.com",
                scopes=("api.github.com",),
                permissions={"contents": "write"},
                repositories=("my-repo",),
            ),
        }

        parsed = _make_parsed_message(body="Do something")

        with (
            patch.object(
                RepoServerConfig,
                "build_task_env",
                return_value=({}, replacement_map),
            ),
            patch(
                "airut.gateway.service.message_processing.ConversationStore",
                return_value=mock_ss,
            ),
        ):
            reason, conv_id = process_message(
                svc, parsed, "task1", handler, adapter
            )

        assert reason == CompletionReason.SUCCESS

        create_task_call = svc.sandbox.create_task.call_args
        network_sandbox = create_task_call[1]["network_sandbox"]
        replacements_dict = network_sandbox.replacements.to_dict()
        key = "ghs_SurrogateToken1234567890abcdefgh"
        assert key in replacements_dict
        assert replacements_dict[key]["type"] == "github-app"
        assert replacements_dict[key]["app_id"] == "Iv23liXyz"
        assert replacements_dict[key]["private_key"] == "test-key"
        assert replacements_dict[key]["installation_id"] == 12345
        assert replacements_dict[key]["permissions"] == {"contents": "write"}
        assert replacements_dict[key]["repositories"] == ["my-repo"]


class TestBuildRecoveryPrompt:
    """Tests for build_recovery_prompt."""

    def test_includes_user_message(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            channel_context="Channel context header",
            user_message="Please fix the bug",
        )
        assert "Please fix the bug" in result

    def test_includes_channel_context(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            channel_context="Channel context header",
            user_message="hello",
        )
        assert "Channel context header" in result

    def test_includes_context_loss_notice(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            channel_context="ctx",
            user_message="hello",
        )
        assert "context length limits" in result
        assert "fresh session" in result

    def test_includes_last_response(self) -> None:
        result = build_recovery_prompt(
            last_response="I created a PR at https://example.com",
            channel_context="ctx",
            user_message="hello",
        )
        assert "I created a PR at https://example.com" in result
        assert "Your last reply" in result

    def test_omits_last_response_when_none(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            channel_context="ctx",
            user_message="hello",
        )
        assert "Your last reply" not in result

    def test_truncates_long_response(self) -> None:
        long_response = "x" * 5000
        result = build_recovery_prompt(
            last_response=long_response,
            channel_context="ctx",
            user_message="hello",
        )
        assert "[...truncated]" in result
        # Should contain first 3000 chars
        assert "x" * 3000 in result
