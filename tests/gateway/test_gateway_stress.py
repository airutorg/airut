# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Comprehensive stress and adversarial tests for the gateway.

Tests cover:
- Full worker lifecycle with real TaskTracker (not mocked)
- Concurrent message submission and duplicate detection
- Task registration/unregistration lifecycle
- Garbage collection edge cases
- Shutdown and signal handling
- Multi-repo interactions
- Adversarial/malformed inputs
"""

import concurrent.futures
import os
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from airut.dashboard.tracker import (
    BootPhase,
    CompletionReason,
    RepoState,
    RepoStatus,
    TaskStatus,
    TaskTracker,
)
from airut.dashboard.versioned import VersionClock
from airut.gateway.channel import AuthenticationError, ParsedMessage, RawMessage

from .service.conftest import make_message, make_service, update_global


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_gateway_real_tracker(
    email_config: Any,
    tmp_path: Path,
    **global_kwargs: Any,
) -> tuple[Any, Any]:
    """Create a GatewayService with a *real* TaskTracker.

    The ``make_service`` helper mocks the tracker. Many tests here need
    real tracker state transitions, so we swap it after construction.
    """
    svc, handler = make_service(email_config, tmp_path, **global_kwargs)
    clock = VersionClock()
    svc.tracker = TaskTracker(clock=clock)
    svc._clock = clock
    return svc, handler


# ===================================================================
# Worker lifecycle with real tracker
# ===================================================================


class TestWorkerLifecycleRealTracker:
    """End-to-end worker thread tests using real TaskTracker state."""

    def test_new_message_full_lifecycle(
        self, email_config, tmp_path: Path
    ) -> None:
        """New message: add → start → subject update → complete(success)."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Build the feature",
            conversation_id=None,
            model_hint=None,
            display_title="Build the feature",
        )
        handler.adapter.authenticate_and_parse.return_value = parsed
        handler.conversation_manager.exists.return_value = False

        task_id = "new-aabb0011"
        svc.tracker.add_task(task_id, "(authenticating)", repo_id="test")

        def fake_process(svc_, parsed_, tid, handler_, adapter_):
            # In the new API, process_message sets conv_id on the task
            svc_.tracker.set_conversation_id(tid, "conv-xyz")
            return CompletionReason.SUCCESS, "conv-xyz"

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=fake_process,
        ):
            svc._process_message_worker(
                RawMessage(sender="test", content=None), task_id, handler
            )

        # Task stays under its task_id (never renamed)
        task = svc.tracker.get_task(task_id)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is True
        assert task.display_title == "Build the feature"
        assert task.sender == "user@example.com"
        assert task.conversation_id == "conv-xyz"

    def test_auth_failure_lifecycle(self, email_config, tmp_path: Path) -> None:
        """AuthenticationError records sender and marks task failed."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        handler.adapter.authenticate_and_parse.side_effect = (
            AuthenticationError(
                sender="evil@hacker.com",
                reason="DMARC check failed",
            )
        )

        task_id = "new-auth-fail"
        svc.tracker.add_task(task_id, "(authenticating)", repo_id="test")
        svc._process_message_worker(
            RawMessage(sender="test", content=None), task_id, handler
        )

        task = svc.tracker.get_task(task_id)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is False
        assert "(not authorized)" in task.display_title
        assert task.sender == "evil@hacker.com"

    def test_runtime_error_does_not_update_subject(
        self, email_config, tmp_path: Path
    ) -> None:
        """Non-auth exception leaves subject as-is."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        handler.adapter.authenticate_and_parse.side_effect = RuntimeError(
            "IMAP socket closed"
        )

        task_id = "new-crash-00"
        svc.tracker.add_task(task_id, "(authenticating)", repo_id="test")
        svc._process_message_worker(
            RawMessage(sender="test", content=None), task_id, handler
        )

        task = svc.tracker.get_task(task_id)
        assert task is not None
        assert task.succeeded is False
        assert task.display_title == "(authenticating)"

    def test_resume_conversation_full_lifecycle(
        self, email_config, tmp_path: Path
    ) -> None:
        """Resume: task gets conversation_id set, subject updated, completed."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        conv_id = "existing01"
        # Simulate previously completed conversation task
        svc.tracker.add_task("prev-task", "Original task", repo_id="test")
        svc.tracker.set_conversation_id("prev-task", conv_id)
        svc.tracker.set_authenticating("prev-task")
        svc.tracker.set_executing("prev-task")
        svc.tracker.complete_task("prev-task", CompletionReason.SUCCESS)

        parsed = ParsedMessage(
            sender="alice@example.com",
            body="Follow-up question",
            conversation_id=conv_id,
            model_hint=None,
            display_title="Re: [ID:existing01] Follow-up",
        )
        handler.adapter.authenticate_and_parse.return_value = parsed
        handler.conversation_manager.exists.return_value = True

        temp_id = "new-resume01"
        svc.tracker.add_task(temp_id, "(authenticating)", repo_id="test")

        with patch(
            "airut.gateway.service.gateway.process_message",
            return_value=(CompletionReason.SUCCESS, conv_id),
        ):
            svc._process_message_worker(
                RawMessage(sender="test", content=None), temp_id, handler
            )

        # Task stays under temp_id with conversation_id assigned
        task = svc.tracker.get_task(temp_id)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is True
        assert task.sender == "alice@example.com"
        assert task.conversation_id == conv_id


# ===================================================================
# Duplicate / concurrent message rejection
# ===================================================================


class TestDuplicateRejectionStress:
    """Stress duplicate message detection."""

    def test_duplicate_for_queued_task(
        self, email_config, tmp_path: Path
    ) -> None:
        """Message queued as pending when task is QUEUED (not yet started)."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)

        conv_id = "dup-queued"
        # Create an active task for this conversation
        svc.tracker.add_task("active-task", "Queued task")
        svc.tracker.set_conversation_id("active-task", conv_id)
        # Task is QUEUED (not started)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Follow-up",
            conversation_id=conv_id,
            model_hint=None,
        )
        handler.adapter.authenticate_and_parse.return_value = parsed

        temp_id = "new-dup-q"
        svc.tracker.add_task(temp_id, "(authenticating)")
        svc._process_message_worker(
            RawMessage(sender="test", content=None), temp_id, handler
        )

        # New behavior: messages for active conversations are queued
        handler.adapter.send_rejection.assert_not_called()
        task = svc.tracker.get_task(temp_id)
        assert task is not None
        assert task.status == TaskStatus.PENDING

    def test_duplicate_for_executing_task(
        self, email_config, tmp_path: Path
    ) -> None:
        """Message queued as pending when task is EXECUTING."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)

        conv_id = "dup-inprog"
        # Create an active executing task for this conversation
        svc.tracker.add_task("active-task", "Active task")
        svc.tracker.set_conversation_id("active-task", conv_id)
        svc.tracker.set_authenticating("active-task")
        svc.tracker.set_executing("active-task")

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Ping",
            conversation_id=conv_id,
            model_hint=None,
        )
        handler.adapter.authenticate_and_parse.return_value = parsed

        temp_id = "new-dup-ip"
        svc.tracker.add_task(temp_id, "(authenticating)")
        svc._process_message_worker(
            RawMessage(sender="test", content=None), temp_id, handler
        )

        # New behavior: messages for active conversations are queued
        handler.adapter.send_rejection.assert_not_called()
        task = svc.tracker.get_task(temp_id)
        assert task is not None
        assert task.status == TaskStatus.PENDING

    def test_not_duplicate_for_completed_task(
        self, email_config, tmp_path: Path
    ) -> None:
        """Message accepted when previous task is COMPLETED."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)
        update_global(svc, dashboard_base_url=None)

        conv_id = "dup-done"
        # Create a completed task for this conversation
        svc.tracker.add_task("done-task", "Done task")
        svc.tracker.set_conversation_id("done-task", conv_id)
        svc.tracker.set_authenticating("done-task")
        svc.tracker.set_executing("done-task")
        svc.tracker.complete_task("done-task", CompletionReason.SUCCESS)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="More work",
            conversation_id=conv_id,
            model_hint=None,
        )
        handler.adapter.authenticate_and_parse.return_value = parsed
        handler.conversation_manager.exists.return_value = True

        temp_id = "new-dup-ok"
        svc.tracker.add_task(temp_id, "(authenticating)")

        def fake_process(svc_, parsed_, tid, handler_, adapter_):
            return CompletionReason.SUCCESS, conv_id

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=fake_process,
        ):
            svc._process_message_worker(
                RawMessage(sender="test", content=None), temp_id, handler
            )

        handler.adapter.send_rejection.assert_not_called()

    def test_no_conv_id_never_triggers_duplicate_check(
        self, email_config, tmp_path: Path
    ) -> None:
        """New messages (conv_id=None) skip duplicate detection entirely."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Fresh request",
            conversation_id=None,
            model_hint=None,
        )
        handler.adapter.authenticate_and_parse.return_value = parsed
        handler.conversation_manager.exists.return_value = False

        temp_id = "new-fresh01"
        svc.tracker.add_task(temp_id, "(authenticating)")

        def fake_process(svc_, parsed_, tid, handler_, adapter_):
            svc_.tracker.set_conversation_id(tid, "new-conv-id")
            return CompletionReason.SUCCESS, "new-conv-id"

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=fake_process,
        ):
            svc._process_message_worker(
                RawMessage(sender="test", content=None), temp_id, handler
            )

        handler.adapter.send_rejection.assert_not_called()


# ===================================================================
# Task registration / unregistration / stop execution
# ===================================================================


class TestActiveTaskManagement:
    """Tests for register/unregister/stop execution lifecycle."""

    def test_register_and_unregister(
        self, email_config, tmp_path: Path
    ) -> None:
        """Tasks can be registered and unregistered."""
        svc, _ = make_service(email_config, tmp_path)
        mock_task = MagicMock()

        svc.register_active_task("conv1", mock_task)
        assert "conv1" in svc._active_tasks
        assert svc._active_tasks["conv1"] is mock_task

        svc.unregister_active_task("conv1")
        assert "conv1" not in svc._active_tasks

    def test_unregister_nonexistent_is_noop(
        self, email_config, tmp_path: Path
    ) -> None:
        """Unregistering a non-existent task doesn't raise."""
        svc, _ = make_service(email_config, tmp_path)
        svc.unregister_active_task("doesnt-exist")  # Should not raise

    def test_stop_execution_calls_task_stop(
        self, email_config, tmp_path: Path
    ) -> None:
        """_stop_execution calls task.stop() on registered task."""
        svc, _ = make_service(email_config, tmp_path)
        mock_task = MagicMock()
        mock_task.stop.return_value = True

        svc.register_active_task("conv1", mock_task)
        result = svc._stop_execution("conv1")

        assert result is True
        mock_task.stop.assert_called_once()

    def test_stop_execution_returns_false_for_unknown(
        self, email_config, tmp_path: Path
    ) -> None:
        """_stop_execution returns False for unregistered conversation."""
        svc, _ = make_service(email_config, tmp_path)
        result = svc._stop_execution("no-such-conv")
        assert result is False

    def test_stop_execution_returns_task_stop_result(
        self, email_config, tmp_path: Path
    ) -> None:
        """_stop_execution returns whatever task.stop() returns."""
        svc, _ = make_service(email_config, tmp_path)
        mock_task = MagicMock()
        mock_task.stop.return_value = False  # Task couldn't be stopped

        svc.register_active_task("conv1", mock_task)
        result = svc._stop_execution("conv1")
        assert result is False

    def test_concurrent_register_unregister(
        self, email_config, tmp_path: Path
    ) -> None:
        """Concurrent register/unregister operations are thread-safe."""
        svc, _ = make_service(email_config, tmp_path)
        errors: list[Exception] = []

        def register_tasks(start_id: int, count: int):
            try:
                for i in range(count):
                    conv_id = f"conv-{start_id + i}"
                    svc.register_active_task(conv_id, MagicMock())
                    svc.unregister_active_task(conv_id)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=register_tasks, args=(i * 100, 50))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(svc._active_tasks) == 0


# ===================================================================
# Garbage collector edge cases
# ===================================================================


class TestGarbageCollectorEdgeCases:
    """Edge cases in the garbage collector thread."""

    def test_gc_skips_nonexistent_conversation_path(
        self, email_config, tmp_path: Path
    ) -> None:
        """GC handles conversations whose workspace no longer exists."""
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, conversation_max_age_days=7)

        handler.conversation_manager.list_all.return_value = [
            "conv1",
            "conv2",
        ]
        handler.conversation_manager.get_workspace_path.return_value = (
            tmp_path / "vanished"
        )

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()

        handler.conversation_manager.delete.assert_not_called()

    def test_gc_handles_mixed_old_and_new(
        self, email_config, tmp_path: Path
    ) -> None:
        """GC removes only conversations older than max_age_days."""
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, conversation_max_age_days=7)

        old_path = tmp_path / "old_conv"
        old_path.mkdir()
        old_time = time.time() - (10 * 24 * 60 * 60)
        os.utime(old_path, (old_time, old_time))

        new_path = tmp_path / "new_conv"
        new_path.mkdir()

        handler.conversation_manager.list_all.return_value = [
            "old_conv",
            "new_conv",
        ]
        handler.conversation_manager.get_workspace_path.side_effect = (
            lambda cid: old_path if cid == "old_conv" else new_path
        )

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()

        handler.conversation_manager.delete.assert_called_once_with("old_conv")

    def test_gc_continues_despite_one_repo_error(
        self, email_config, tmp_path: Path
    ) -> None:
        """GC exception in one repo doesn't stop cleanup for others.

        Note: Current implementation wraps the entire repos loop in one
        try/except, so a failure in one repo's list_all will skip all
        remaining repos in that cycle. This test verifies the GC thread
        itself continues (doesn't crash).
        """
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.list_all.side_effect = RuntimeError(
            "disk error"
        )

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()  # Should not crash

    def test_gc_handles_delete_failure(
        self, email_config, tmp_path: Path
    ) -> None:
        """GC handles failure during conversation deletion."""
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, conversation_max_age_days=7)

        old_path = tmp_path / "old_conv"
        old_path.mkdir()
        old_time = time.time() - (10 * 24 * 60 * 60)
        os.utime(old_path, (old_time, old_time))

        handler.conversation_manager.list_all.return_value = ["conv1"]
        handler.conversation_manager.get_workspace_path.return_value = old_path
        handler.conversation_manager.delete.side_effect = OSError(
            "permission denied"
        )

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        # Should not crash — the entire exception is caught
        svc._garbage_collector_thread()

    def test_gc_conversation_within_boundary_not_removed(
        self, email_config, tmp_path: Path
    ) -> None:
        """Conversation younger than max_age_days is NOT removed."""
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, conversation_max_age_days=7)

        recent_path = tmp_path / "recent_conv"
        recent_path.mkdir()
        # Set mtime to 6 days ago (within the 7-day limit)
        recent_time = time.time() - (6 * 24 * 60 * 60)
        os.utime(recent_path, (recent_time, recent_time))

        handler.conversation_manager.list_all.return_value = ["recent"]
        handler.conversation_manager.get_workspace_path.return_value = (
            recent_path
        )

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()

        handler.conversation_manager.delete.assert_not_called()

    def test_gc_exits_on_shutdown_signal(
        self, email_config, tmp_path: Path
    ) -> None:
        """GC exits immediately when shutdown event is signaled."""
        svc, _ = make_service(email_config, tmp_path)
        svc._shutdown_event.wait = MagicMock(return_value=True)
        svc._garbage_collector_thread()
        # Should exit without doing any cleanup work


# ===================================================================
# Submit message edge cases
# ===================================================================


class TestSubmitMessageEdgeCases:
    """Edge cases in message submission."""

    def test_submit_adds_task_to_tracker(
        self, email_config, tmp_path: Path
    ) -> None:
        """submit_message registers a task in the tracker."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        mock_future = MagicMock()
        svc._executor_pool.submit.return_value = mock_future

        msg = make_message()
        result = svc.submit_message(msg, handler)

        assert result is True
        # There should be exactly one task (with a uuid-based task_id)
        tasks = svc.tracker.get_all_tasks()
        assert len(tasks) == 1
        assert tasks[0].display_title == "Test"

    def test_submit_message_tracks_future(
        self, email_config, tmp_path: Path
    ) -> None:
        """Submitted future is tracked in _pending_futures."""
        svc, handler = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        mock_future = MagicMock()
        svc._executor_pool.submit.return_value = mock_future

        svc.submit_message(make_message(), handler)
        assert mock_future in svc._pending_futures


# ===================================================================
# Shutdown edge cases
# ===================================================================


class TestShutdownEdgeCases:
    """Edge cases in service shutdown."""

    def test_double_stop_is_safe(self, email_config, tmp_path: Path) -> None:
        """Calling stop() twice doesn't crash."""
        svc, _ = make_service(email_config, tmp_path)
        svc.stop()
        svc.stop()  # Second call is a no-op

    def test_stop_with_no_pending_futures(
        self, email_config, tmp_path: Path
    ) -> None:
        """Stop with executor but no pending futures."""
        svc, _ = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        svc.stop()
        # Should not call concurrent.futures.wait since no futures

    def test_stop_cancels_timed_out_futures(
        self, email_config, tmp_path: Path
    ) -> None:
        """Futures not done after timeout get cancelled."""
        svc, _ = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        update_global(svc, shutdown_timeout_seconds=1)

        f1 = MagicMock(spec=concurrent.futures.Future)
        f2 = MagicMock(spec=concurrent.futures.Future)
        svc._pending_futures = {f1, f2}

        with patch(
            "concurrent.futures.wait",
            return_value=({f1}, {f2}),
        ):
            svc.stop()

        f2.cancel.assert_called_once()
        f1.cancel.assert_not_called()

    def test_stop_shuts_down_sandbox(
        self, email_config, tmp_path: Path
    ) -> None:
        """Stop calls sandbox.shutdown()."""
        svc, _ = make_service(email_config, tmp_path)
        svc.stop()
        svc.sandbox.shutdown.assert_called_once()


# ===================================================================
# Boot state edge cases
# ===================================================================


class TestBootStateEdgeCases:
    """Edge cases in boot state transitions."""

    def test_boot_proxy_phase_recorded(
        self, email_config, tmp_path: Path
    ) -> None:
        """Proxy phase is recorded during boot."""
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        phases_seen: list[BootPhase] = []

        def track_phase(*args, **kwargs):
            boot = svc._boot_store.get().value
            phases_seen.append(boot.phase)

        svc.sandbox.startup.side_effect = track_phase

        def fake_start(**kwargs):
            svc._running = False

        handler.adapter.listener.start.side_effect = fake_start
        svc.start()

        assert BootPhase.PROXY in phases_seen

    def test_resilient_mode_keeps_dashboard_running(
        self, email_config, tmp_path: Path
    ) -> None:
        """In resilient mode, dashboard stays alive after boot failure."""
        svc, handler = make_service(
            email_config, tmp_path, dashboard_enabled=True
        )

        handler.adapter.listener.start.side_effect = RuntimeError("fail")

        with (
            patch("airut.gateway.service.gateway.DashboardServer") as mock_ds,
            patch("time.sleep", side_effect=KeyboardInterrupt),
        ):
            svc.start(resilient=True)

        # Dashboard should NOT have been stopped in resilient mode
        mock_ds.return_value.stop.assert_not_called()

        boot = svc._boot_store.get().value
        assert boot.phase == BootPhase.FAILED


# ===================================================================
# Version info capture
# ===================================================================


class TestCaptureVersionInfo:
    """Tests for capture_version_info."""

    def test_returns_version_and_git_info(self) -> None:
        """capture_version_info returns both VersionInfo and GitVersionInfo."""
        from airut.gateway.service.gateway import capture_version_info

        with patch(
            "airut.gateway.service.gateway.get_git_version_info"
        ) as mock_git:
            mock_git.return_value = MagicMock(
                version="1.2.3",
                sha_short="abc1234",
                sha_full="abc1234567890",
                full_status="clean",
            )

            version_info, git_info = capture_version_info()

        assert version_info.version == "1.2.3"
        assert version_info.git_sha == "abc1234"
        assert version_info.git_sha_full == "abc1234567890"
        assert version_info.started_at > 0

    def test_version_label_falls_back_to_sha(self) -> None:
        """When version is None, git_sha is used as label."""
        from airut.gateway.service.gateway import capture_version_info

        with patch(
            "airut.gateway.service.gateway.get_git_version_info"
        ) as mock_git:
            mock_git.return_value = MagicMock(
                version=None,
                sha_short="def5678",
                sha_full="def5678901234",
                full_status="dirty",
            )

            version_info, _ = capture_version_info()

        # The version label fallback happens in __init__, not capture
        assert version_info.version is None
        assert version_info.git_sha == "def5678"


# ===================================================================
# Multi-repo interactions
# ===================================================================


class TestMultiRepoInteractions:
    """Tests for interactions across multiple repos."""

    def test_work_dirs_only_includes_live_repos(
        self, email_config, tmp_path: Path
    ) -> None:
        """_get_work_dirs returns dirs only for LIVE repos."""
        svc, handler = make_service(email_config, tmp_path)

        svc._repos_store.update(
            (
                RepoState(
                    repo_id="test",
                    status=RepoStatus.LIVE,
                    git_repo_url="https://example.com/r1",
                    channel_info="imap.example.com",
                    storage_dir="/s/test",
                ),
                RepoState(
                    repo_id="failed-repo",
                    status=RepoStatus.FAILED,
                    git_repo_url="https://example.com/r2",
                    channel_info="imap2.example.com",
                    storage_dir="/s/failed",
                ),
            )
        )

        dirs = svc._get_work_dirs()
        assert len(dirs) == 1

    def test_work_dirs_empty_when_no_repos(
        self, email_config, tmp_path: Path
    ) -> None:
        """_get_work_dirs returns empty list when no repos are live."""
        svc, _ = make_service(email_config, tmp_path)
        # Default repos_store is empty tuple
        dirs = svc._get_work_dirs()
        assert dirs == []


# ===================================================================
# Conversation lock edge cases
# ===================================================================


class TestConversationLockEdgeCases:
    """Edge cases in conversation locking."""

    def test_different_conversations_get_different_locks(
        self, email_config, tmp_path: Path
    ) -> None:
        """Each conversation gets its own lock."""
        svc, _ = make_service(email_config, tmp_path)
        lock1 = svc._get_conversation_lock("conv1")
        lock2 = svc._get_conversation_lock("conv2")
        assert lock1 is not lock2

    def test_same_conversation_gets_same_lock(
        self, email_config, tmp_path: Path
    ) -> None:
        """Same conversation always returns the same lock."""
        svc, _ = make_service(email_config, tmp_path)
        lock1 = svc._get_conversation_lock("conv1")
        lock2 = svc._get_conversation_lock("conv1")
        assert lock1 is lock2

    def test_concurrent_lock_creation(
        self, email_config, tmp_path: Path
    ) -> None:
        """Concurrent calls to _get_conversation_lock are thread-safe."""
        svc, _ = make_service(email_config, tmp_path)
        results: dict[int, threading.Lock] = {}

        def get_lock(thread_id):
            results[thread_id] = svc._get_conversation_lock("shared-conv")

        threads = [
            threading.Thread(target=get_lock, args=(i,)) for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads should get the same lock
        locks = list(results.values())
        assert all(lock is locks[0] for lock in locks)


# ===================================================================
# Worker thread with empty/whitespace body
# ===================================================================


class TestWorkerEdgeCases:
    """Edge cases in the message processing worker."""

    def test_whitespace_only_body(self, email_config, tmp_path: Path) -> None:
        """Whitespace-only body is treated as empty message."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="   \n\t  ",
            conversation_id=None,
            model_hint=None,
            display_title="Empty body",
        )
        handler.adapter.authenticate_and_parse.return_value = parsed
        handler.conversation_manager.exists.return_value = False

        temp_id = "new-empty01"
        svc.tracker.add_task(temp_id, "(authenticating)")

        def fake_process(svc_, parsed_, tid, handler_, adapter_):
            return CompletionReason.EXECUTION_FAILED, None

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=fake_process,
        ) as mock_process:
            svc._process_message_worker(
                RawMessage(sender="test", content=None), temp_id, handler
            )

        # process_message is called — it handles empty body detection
        mock_process.assert_called_once()

    def test_no_subject_defaults_to_placeholder(
        self, email_config, tmp_path: Path
    ) -> None:
        """Empty display_title falls back to '(no subject)'."""
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Do something",
            conversation_id=None,
            model_hint=None,
            display_title="",
        )
        handler.adapter.authenticate_and_parse.return_value = parsed
        handler.conversation_manager.exists.return_value = False

        temp_id = "new-nosub01"
        svc.tracker.add_task(temp_id, "(authenticating)")

        def fake_process(svc_, parsed_, tid, handler_, adapter_):
            svc_.tracker.set_conversation_id(tid, "conv-ns")
            return CompletionReason.SUCCESS, "conv-ns"

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=fake_process,
        ):
            svc._process_message_worker(
                RawMessage(sender="test", content=None), temp_id, handler
            )

        # display_title should be "(no subject)" since parsed.display_title
        # is empty. The update happens via tracker.update_task_display_title
        # with parsed.display_title or "(no subject)"
        task = svc.tracker.get_task(temp_id)
        assert task is not None
        assert task.display_title == "(no subject)"

    def test_process_message_exception_after_conv_id_set(
        self, email_config, tmp_path: Path
    ) -> None:
        """Exception after set_conversation_id still completes the task.

        When the worker calls set_conversation_id (because conv_id
        matches an existing conversation) and then process_message
        raises, the ``finally`` block should complete the task_id.
        """
        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)

        conv_id = "exn-after"
        # Simulate previously completed conversation task
        svc.tracker.add_task("prev-task", "Original")
        svc.tracker.set_conversation_id("prev-task", conv_id)
        svc.tracker.set_authenticating("prev-task")
        svc.tracker.set_executing("prev-task")
        svc.tracker.complete_task("prev-task", CompletionReason.SUCCESS)

        parsed = ParsedMessage(
            sender="user@example.com",
            body="Resume with error",
            conversation_id=conv_id,
            model_hint=None,
            display_title="Re: resume",
        )
        handler.adapter.authenticate_and_parse.return_value = parsed
        # exists=True means this is a resumed conversation; the worker
        # will acquire a conversation lock and call process_message inside it
        handler.conversation_manager.exists.return_value = True

        temp_id = "new-exnpost"
        svc.tracker.add_task(temp_id, "(authenticating)")

        with patch(
            "airut.gateway.service.gateway.process_message",
            side_effect=RuntimeError("kaboom"),
        ):
            svc._process_message_worker(
                RawMessage(sender="test", content=None), temp_id, handler
            )

        # Task stays under temp_id and should be completed (failed)
        task = svc.tracker.get_task(temp_id)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.succeeded is False
        assert task.conversation_id == conv_id


# ===================================================================
# Queue full rejection
# ===================================================================


class TestQueueFullRejection:
    """Test that queue full causes rejection when MAX_PENDING is reached."""

    def test_queue_full_sends_rejection(
        self, email_config, tmp_path: Path
    ) -> None:
        """When queue has MAX_PENDING_PER_CONVERSATION messages, reject."""
        from airut.dashboard.tracker import MAX_PENDING_PER_CONVERSATION

        svc, handler = _make_gateway_real_tracker(email_config, tmp_path)
        update_global(svc, dashboard_base_url="https://dash.example.com")

        conv_id = "queue-full-conv"
        # Create an active task for this conversation
        svc.tracker.add_task("active-task", "Active task", repo_id="test")
        svc.tracker.set_conversation_id("active-task", conv_id)
        svc.tracker.set_authenticating("active-task")
        svc.tracker.set_executing("active-task")

        # Fill the pending queue to MAX_PENDING_PER_CONVERSATION
        import collections

        from airut.gateway.service.gateway import PendingMessage

        queue = collections.deque()
        for i in range(MAX_PENDING_PER_CONVERSATION):
            queue.append(
                PendingMessage(
                    parsed=MagicMock(conversation_id=conv_id),
                    task_id=f"pending-{i}",
                    repo_handler=handler,
                    adapter=handler.adapter,
                )
            )
        svc._pending_messages[conv_id] = queue

        # Now send one more message — should be rejected
        parsed = ParsedMessage(
            sender="user@example.com",
            body="One too many",
            conversation_id=conv_id,
            model_hint=None,
            display_title="Overflow message",
        )
        handler.adapter.authenticate_and_parse.return_value = parsed

        temp_id = "new-overflow"
        svc.tracker.add_task(temp_id, "(authenticating)", repo_id="test")
        svc._process_message_worker(
            RawMessage(sender="test", content=None), temp_id, handler
        )

        # Should have called send_rejection
        handler.adapter.send_rejection.assert_called_once()
        call_args = handler.adapter.send_rejection.call_args
        assert call_args[0][0] is parsed
        assert call_args[0][1] == conv_id
        assert "Too many messages queued" in call_args[0][2]
        assert call_args[0][3] == "https://dash.example.com"

        # The overflow task should be completed as REJECTED
        task = svc.tracker.get_task(temp_id)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
