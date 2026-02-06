# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for message_processing module."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from lib.container.executor import ExecutionResult
from lib.gateway.config import RepoConfig
from lib.gateway.service import build_recovery_prompt, is_prompt_too_long_error
from lib.gateway.service.message_processing import process_message

from .conftest import make_message, make_service, update_global


def _make_repo_config(
    *,
    default_model: str = "sonnet",
    timeout: int = 300,
    network_sandbox_enabled: bool = True,
    container_env: dict[str, str] | None = None,
) -> RepoConfig:
    """Create a RepoConfig for testing."""
    return RepoConfig(
        default_model=default_model,
        timeout=timeout,
        network_sandbox_enabled=network_sandbox_enabled,
        container_env=container_env or {},
    )


class TestProcessMessage:
    @pytest.fixture(autouse=True)
    def _patch_repo_config(self):
        """Patch RepoConfig.from_mirror for all process message tests."""
        rc = _make_repo_config()
        # from_mirror now returns (RepoConfig, ReplacementMap) tuple
        with patch(
            "lib.gateway.service.message_processing.RepoConfig.from_mirror",
            return_value=(rc, {}),
        ) as mock_rc:
            self._mock_repo_config = mock_rc
            self._repo_config = rc
            yield

    def _setup_svc(
        self, email_config: Any, tmp_path: Path
    ) -> tuple[Any, Any, Any]:
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
        handler.conversation_manager.get_session_dir.return_value = (
            tmp_path / "sessions"
        )
        handler.conversation_manager.get_workspace_path.return_value = repo_path
        handler.conversation_manager.mirror = MagicMock()

        handler.authenticator.authenticate.return_value = (
            "authorized@example.com"
        )

        mock_session_store = MagicMock()
        mock_session_store.get_session_id_for_resume.return_value = None
        mock_session_store.get_model.return_value = None

        handler.executor.execute.return_value = ExecutionResult(
            success=True,
            output={
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [{"type": "text", "text": "Done!"}]
                        },
                    }
                ],
                "total_cost_usd": 0.01,
            },
            error_message="",
            stdout="",
            stderr="",
            exit_code=0,
        )
        handler.executor.ensure_image = MagicMock(return_value="airut:test")

        return svc, handler, mock_session_store

    def test_new_conversation_success(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)

        assert success is True
        assert conv_id == "conv1"
        handler.responder.send_reply.assert_called()  # ack + reply

    def test_unauthenticated_rejected(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, _ = self._setup_svc(email_config, tmp_path)
        handler.authenticator.authenticate.return_value = None
        msg = make_message()
        success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False
        assert conv_id is None

    def test_unauthorized_rejected(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, _ = self._setup_svc(email_config, tmp_path)
        handler.authenticator.authenticate.return_value = "other@example.com"
        handler.authorizer.is_authorized.return_value = False
        msg = make_message()
        success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False
        assert conv_id is None

    def test_unauthorized_sender_rejected_before_conversation_lookup(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Authorization rejects before conversation ID is ever examined.

        Even when the email subject contains a valid conversation ID,
        an unauthorized sender must be rejected without any call to
        conversation_manager.exists() or resume_existing().
        """
        svc, handler, _ = self._setup_svc(email_config, tmp_path)
        handler.authenticator.authenticate.return_value = "intruder@evil.com"
        handler.authorizer.is_authorized.return_value = False
        msg = make_message(
            subject="[ID:aabb1122] Continue task",
            body="I want to hijack this conversation",
        )
        success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False
        assert conv_id is None
        # Conversation manager must never be consulted
        handler.conversation_manager.exists.assert_not_called()
        handler.conversation_manager.resume_existing.assert_not_called()

    def test_conversation_id_from_other_repo_treated_as_new(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """A conversation ID that doesn't exist in this repo starts a new one.

        When an email arrives with a conversation ID that belongs to a
        different repo (not found in this repo's ConversationManager),
        the system must treat it as a new conversation rather than
        erroring or leaking state.
        """
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        # The conversation ID exists in the subject but NOT in this repo
        handler.conversation_manager.exists.return_value = False
        msg = make_message(
            subject="[ID:deadbeef] Continue task",
            body="Work on this",
        )

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is True
        # Should create a new conversation, not resume
        handler.conversation_manager.initialize_new.assert_called_once()
        handler.conversation_manager.resume_existing.assert_not_called()

    def test_empty_body_rejected(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, _ = self._setup_svc(email_config, tmp_path)
        msg = make_message(body="> quoted only\n> more quotes")

        with patch(
            "lib.gateway.service.message_processing.strip_quoted_text",
            return_value="",
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False

    def test_execution_failure(self, email_config: Any, tmp_path: Path) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)

        handler.executor.execute.return_value = ExecutionResult(
            success=False,
            output=None,
            error_message="Container crashed",
            stdout='{"type":"result","is_error":true}',
            stderr="FATAL: OOM\nline2\nline3",
            exit_code=1,
        )
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False
        assert conv_id == "conv1"

    def test_container_timeout(self, email_config: Any, tmp_path: Path) -> None:
        from lib.container.executor import ContainerTimeoutError

        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        handler.executor.execute.side_effect = ContainerTimeoutError("timeout")
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False

    def test_git_clone_error(self, email_config: Any, tmp_path: Path) -> None:
        from lib.gateway import GitCloneError

        svc, handler, _ = self._setup_svc(email_config, tmp_path)
        handler.conversation_manager.initialize_new.side_effect = GitCloneError(
            "clone failed"
        )
        msg = make_message(body="Do something")
        success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False
        assert conv_id is None

    def test_unexpected_error(self, email_config: Any, tmp_path: Path) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        handler.executor.execute.side_effect = RuntimeError("unexpected")
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)
        assert success is False

    def test_resume_existing_conversation(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_ss.get_model.return_value = "opus"
        mock_ss.get_session_id_for_resume.return_value = "session-abc"

        msg = make_message(subject="[ID:aabb1122] Test", body="Continue")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "conv1", handler)
        assert success is True
        # Mirror should be updated before resuming
        handler.conversation_manager.mirror.update_mirror.assert_called_once()
        # Should not send acknowledgment for resumed conversations
        # (only send_reply for the response)
        calls = handler.responder.send_reply.call_args_list
        assert len(calls) == 1  # only the reply, no ack

    def test_model_from_address(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        msg = make_message(to="airut+opus@example.com", body="Do stuff")

        with (
            patch(
                "lib.gateway.service.message_processing.SessionStore",
                return_value=mock_ss,
            ),
            patch(
                "lib.gateway.service.message_processing.extract_model_from_address",
                return_value="opus",
            ),
        ):
            process_message(svc, msg, "task1", handler)
        # executor should be called with opus model
        call_kwargs = handler.executor.execute.call_args[1]
        assert call_kwargs["model"] == "opus"

    def test_attachments_saved(self, email_config: Any, tmp_path: Path) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        msg = make_message(body="See attached")

        with (
            patch(
                "lib.gateway.service.message_processing.SessionStore",
                return_value=mock_ss,
            ),
            patch(
                "lib.gateway.service.message_processing.extract_attachments",
                return_value=["report.pdf"],
            ),
        ):
            process_message(svc, msg, "task1", handler)
        # Prompt should mention inbox
        call_kwargs = handler.executor.execute.call_args[1]
        assert "report.pdf" in call_kwargs["prompt"]

    def test_usage_stats_footer(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        msg = make_message(body="Check")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            process_message(svc, msg, "task1", handler)
        # Reply should contain cost footer
        reply_call = handler.responder.send_reply.call_args_list[-1]
        body = reply_call[1]["body"]
        assert "Cost:" in body

    def test_on_event_callback(self, email_config: Any, tmp_path: Path) -> None:
        """Test that on_event callback is passed and works."""
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        msg = make_message(body="Do stuff")

        # Capture the on_event callback
        captured_callback = None

        def capture_execute(**kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("on_event")

            return ExecutionResult(
                success=True,
                output={
                    "events": [
                        {
                            "type": "assistant",
                            "message": {
                                "content": [{"type": "text", "text": "Ok"}]
                            },
                        }
                    ]
                },
                error_message="",
                stdout="",
                stderr="",
                exit_code=0,
            )

        handler.executor.execute.side_effect = capture_execute

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            process_message(svc, msg, "task1", handler)

        assert captured_callback is not None
        # Call the callback with a regular event
        captured_callback({"type": "assistant", "message": {"content": []}})
        mock_ss.update_or_add_reply.assert_called()

    def test_on_event_callback_result_event(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Test on_event with a result-type event extracts fields."""
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        msg = make_message(body="Do stuff")

        captured_callback = None

        def capture_execute(**kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("on_event")

            return ExecutionResult(
                success=True,
                output={"events": [], "result": "ok"},
                error_message="",
                stdout="",
                stderr="",
                exit_code=0,
            )

        handler.executor.execute.side_effect = capture_execute

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            process_message(svc, msg, "task1", handler)

        # Call with result event
        assert captured_callback is not None
        captured_callback(
            {
                "type": "result",
                "session_id": "s1",
                "duration_ms": 100,
                "total_cost_usd": 0.01,
                "num_turns": 1,
                "is_error": False,
                "usage": {},
                "result": "done",
            }
        )

    def test_on_event_callback_exception_handled(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """on_event should not raise if session store fails."""
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        mock_ss.update_or_add_reply.side_effect = RuntimeError("write fail")
        msg = make_message(body="Do stuff")

        captured_callback = None

        def capture_execute(**kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("on_event")

            return ExecutionResult(
                success=True,
                output={"events": [], "result": "ok"},
                error_message="",
                stdout="",
                stderr="",
                exit_code=0,
            )

        handler.executor.execute.side_effect = capture_execute

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            process_message(svc, msg, "task1", handler)

        # Should not raise
        assert captured_callback is not None
        captured_callback({"type": "assistant", "message": {"content": []}})

    def test_resumed_conversation_ignores_model_request(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_ss.get_model.return_value = "sonnet"
        mock_ss.get_session_id_for_resume.return_value = None

        msg = make_message(
            subject="[ID:aabb1122] Test",
            to="airut+opus@example.com",
            body="Continue",
        )

        with (
            patch(
                "lib.gateway.service.message_processing.SessionStore",
                return_value=mock_ss,
            ),
            patch(
                "lib.gateway.service.message_processing.extract_model_from_address",
                return_value="opus",
            ),
        ):
            process_message(svc, msg, "conv1", handler)
        # Should use stored model, not requested
        call_kwargs = handler.executor.execute.call_args[1]
        assert call_kwargs["model"] == "sonnet"

    def test_task_id_updated_for_new_conversation(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            process_message(svc, msg, "temp-123", handler)
        svc.tracker.update_task_id.assert_called_once_with("temp-123", "conv1")

    def test_long_subject_truncated_in_log(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Subjects > 50 chars are truncated in log messages."""
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        long_subject = "A" * 60
        msg = make_message(subject=long_subject, body="Do stuff")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            process_message(svc, msg, "task1", handler)
        # Just verify it doesn't crash

    def test_no_usage_stats_no_footer(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)

        handler.executor.execute.return_value = ExecutionResult(
            success=True,
            output={
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [{"type": "text", "text": "Done"}]
                        },
                    }
                ]
            },
            error_message="",
            stdout="",
            stderr="",
            exit_code=0,
        )
        msg = make_message(body="Do stuff")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            process_message(svc, msg, "task1", handler)
        reply_call = handler.responder.send_reply.call_args_list[-1]
        body = reply_call[1]["body"]
        assert "Cost:" not in body

    def test_failure_with_stderr(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)

        stderr_lines = "\n".join(f"line{i}" for i in range(15))
        handler.executor.execute.return_value = ExecutionResult(
            success=False,
            output=None,
            error_message="Crashed",
            stdout="",
            stderr=stderr_lines,
            exit_code=1,
        )
        msg = make_message(body="Do stuff")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, _ = process_message(svc, msg, "task1", handler)
        assert success is False
        # Check that stderr tail is in reply
        reply_call = handler.responder.send_reply.call_args_list[-1]
        body = reply_call[1]["body"]
        assert "Stderr (last 10 lines)" in body

    def test_failure_with_error_summary(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)

        handler.executor.execute.return_value = ExecutionResult(
            success=False,
            output=None,
            error_message="Crashed",
            stdout='{"type":"result","is_error":true,"result":"Bad"}',
            stderr="",
            exit_code=1,
        )
        msg = make_message(body="Do stuff")

        with (
            patch(
                "lib.gateway.service.message_processing.SessionStore",
                return_value=mock_ss,
            ),
            patch(
                "lib.gateway.service.message_processing.extract_error_summary",
                return_value="Error summary text",
            ),
        ):
            success, _ = process_message(svc, msg, "task1", handler)
        assert success is False

    def test_execution_failure_persists_session(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Session must be updated even when execution fails.

        Bug: when result.success is False, session_store.update_or_add_reply
        was never called, so the error execution's metadata (session_id,
        is_error flag) was lost.  The next message could not resume properly.
        """
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)

        handler.executor.execute.return_value = ExecutionResult(
            success=False,
            output={
                "session_id": "err-session-1",
                "is_error": True,
                "events": [{"type": "result", "is_error": True}],
                "duration_ms": 500,
                "total_cost_usd": 0.005,
                "num_turns": 1,
                "usage": {"input_tokens": 50, "output_tokens": 10},
            },
            error_message="Container crashed",
            stdout="",
            stderr="FATAL: OOM",
            exit_code=1,
        )
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)

        assert success is False
        # The critical assertion: session store must be updated with the
        # error execution's output so the session_id is available for resume.
        # Filter out streaming on_event calls (which pass partial_output with
        # request_text) — we want the final post-execution call.
        final_calls = [
            c
            for c in mock_ss.update_or_add_reply.call_args_list
            if c[1].get("response_text", "") != ""
            or c[0][1].get("is_error", False)
        ]
        assert len(final_calls) >= 1, (
            "session_store.update_or_add_reply must be called after failed "
            "execution to persist error metadata"
        )

    def test_container_timeout_persists_session(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Session must be updated when a container timeout occurs."""
        from lib.container.executor import ContainerTimeoutError

        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        handler.executor.execute.side_effect = ContainerTimeoutError("timeout")
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)

        assert success is False
        # Session store must record the error so next message can resume
        mock_ss.update_or_add_reply.assert_called()
        last_call = mock_ss.update_or_add_reply.call_args
        assert last_call[0][1].get("is_error") is True

    def test_unexpected_error_persists_session(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Session must be updated on unexpected exceptions."""
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        handler.executor.execute.side_effect = RuntimeError("unexpected")
        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)

        assert success is False
        mock_ss.update_or_add_reply.assert_called()
        last_call = mock_ss.update_or_add_reply.call_args
        assert last_call[0][1].get("is_error") is True

    def test_prompt_too_long_retries_with_new_session(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Prompt-too-long error triggers retry with fresh session."""
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)

        # Simulate resuming an existing conversation
        repo_path = tmp_path / "repo"
        handler.conversation_manager.exists.return_value = True
        handler.conversation_manager.resume_existing.return_value = repo_path
        mock_ss.get_session_id_for_resume.return_value = "old-session-id"
        mock_ss.get_last_successful_response.return_value = "I created the PR."

        # First call: prompt too long; second call: success
        prompt_too_long_result = ExecutionResult(
            success=False,
            output=None,
            error_message="Container execution failed (exit code 1).",
            stdout="Prompt is too long",
            stderr="",
            exit_code=1,
        )
        success_result = ExecutionResult(
            success=True,
            output={
                "events": [
                    {
                        "type": "assistant",
                        "message": {
                            "content": [{"type": "text", "text": "Recovered!"}]
                        },
                    }
                ],
                "total_cost_usd": 0.02,
            },
            error_message="",
            stdout="",
            stderr="",
            exit_code=0,
        )
        handler.executor.execute.side_effect = [
            prompt_too_long_result,
            success_result,
        ]

        msg = make_message(subject="[ID:aabb1122] Test", body="Continue please")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)

        assert success is True
        # Should have been called twice: first with session_id, then without
        assert handler.executor.execute.call_count == 2
        first_call = handler.executor.execute.call_args_list[0]
        second_call = handler.executor.execute.call_args_list[1]
        assert first_call.kwargs["session_id"] == "old-session-id"
        assert second_call.kwargs["session_id"] is None
        # Recovery prompt should mention context loss
        assert "context length limits" in second_call.kwargs["prompt"]
        # Should include last response
        assert "I created the PR." in second_call.kwargs["prompt"]

    def test_prompt_too_long_no_retry_without_session_id(
        self, email_config: Any, tmp_path: Path
    ) -> None:
        """Prompt-too-long without session_id does not retry (new conv)."""
        svc, handler, mock_ss = self._setup_svc(email_config, tmp_path)
        mock_ss.get_session_id_for_resume.return_value = None

        handler.executor.execute.return_value = ExecutionResult(
            success=False,
            output=None,
            error_message="Container execution failed (exit code 1).",
            stdout="Prompt is too long",
            stderr="",
            exit_code=1,
        )

        msg = make_message(body="Do something")

        with patch(
            "lib.gateway.service.message_processing.SessionStore",
            return_value=mock_ss,
        ):
            success, conv_id = process_message(svc, msg, "task1", handler)

        assert success is False
        # Should only be called once (no retry)
        assert handler.executor.execute.call_count == 1


class TestIsPromptTooLongError:
    """Tests for is_prompt_too_long_error."""

    def test_detects_prompt_too_long(self) -> None:
        result = ExecutionResult(
            success=False,
            output=None,
            error_message="Container execution failed (exit code 1).",
            stdout="Prompt is too long",
            stderr="",
            exit_code=1,
        )
        assert is_prompt_too_long_error(result) is True

    def test_ignores_successful_result(self) -> None:
        result = ExecutionResult(
            success=True,
            output={"events": []},
            error_message="",
            stdout="Prompt is too long",
            stderr="",
            exit_code=0,
        )
        assert is_prompt_too_long_error(result) is False

    def test_ignores_other_errors(self) -> None:
        result = ExecutionResult(
            success=False,
            output=None,
            error_message="Some other error",
            stdout="Something went wrong",
            stderr="",
            exit_code=1,
        )
        assert is_prompt_too_long_error(result) is False

    def test_detects_in_longer_output(self) -> None:
        result = ExecutionResult(
            success=False,
            output=None,
            error_message="error",
            stdout="Some preamble\nPrompt is too long\nMore text",
            stderr="",
            exit_code=1,
        )
        assert is_prompt_too_long_error(result) is True


class TestBuildRecoveryPrompt:
    """Tests for build_recovery_prompt."""

    def test_includes_user_message(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            email_context="Email context header",
            user_message="Please fix the bug",
        )
        assert "Please fix the bug" in result

    def test_includes_email_context(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            email_context="Email context header",
            user_message="hello",
        )
        assert "Email context header" in result

    def test_includes_context_loss_notice(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            email_context="ctx",
            user_message="hello",
        )
        assert "context length limits" in result
        assert "fresh session" in result

    def test_includes_last_response(self) -> None:
        result = build_recovery_prompt(
            last_response="I created a PR at https://example.com",
            email_context="ctx",
            user_message="hello",
        )
        assert "I created a PR at https://example.com" in result
        assert "Your last reply" in result

    def test_omits_last_response_when_none(self) -> None:
        result = build_recovery_prompt(
            last_response=None,
            email_context="ctx",
            user_message="hello",
        )
        assert "Your last reply" not in result

    def test_truncates_long_response(self) -> None:
        long_response = "x" * 5000
        result = build_recovery_prompt(
            last_response=long_response,
            email_context="ctx",
            user_message="hello",
        )
        assert "[...truncated]" in result
        # Should contain first 3000 chars
        assert "x" * 3000 in result
