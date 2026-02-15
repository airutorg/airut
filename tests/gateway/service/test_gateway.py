# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for gateway module (EmailGatewayService orchestration)."""

import concurrent.futures
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from lib.gateway.service import EmailGatewayService, main

from .conftest import make_message, make_service, update_global


class TestEmailGatewayServiceInit:
    def test_init_sets_running(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        assert svc.running is True

    def test_init_no_executor_pool(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        assert svc._executor_pool is None

    def test_init_repo_root_default(self, email_config) -> None:
        """When repo_root=None, auto-detect from __file__."""
        from lib.gateway.config import GlobalConfig, ServerConfig

        global_config = GlobalConfig(dashboard_enabled=False)
        server_config = ServerConfig(
            global_config=global_config, repos={"test": email_config}
        )

        with (
            patch("lib.gateway.service.repo_handler.EmailListener"),
            patch("lib.gateway.service.repo_handler.EmailResponder"),
            patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
            patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
            patch("lib.gateway.service.repo_handler.ConversationManager"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.Sandbox"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = (MagicMock(git_sha="x"), MagicMock())
            svc = EmailGatewayService(server_config, repo_root=None)
            # repo_root should be auto-detected
            assert svc.repo_root is not None

    def test_init_custom_egress_network(
        self, email_config, tmp_path: Path
    ) -> None:
        """Custom egress_network is passed to Sandbox."""
        from lib.gateway.config import GlobalConfig, ServerConfig

        global_config = GlobalConfig(dashboard_enabled=False)
        server_config = ServerConfig(
            global_config=global_config, repos={"test": email_config}
        )

        with (
            patch("lib.gateway.service.repo_handler.EmailListener"),
            patch("lib.gateway.service.repo_handler.EmailResponder"),
            patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
            patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
            patch("lib.gateway.service.repo_handler.ConversationManager"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.Sandbox") as mock_sandbox,
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = (MagicMock(git_sha="x"), MagicMock())
            EmailGatewayService(
                server_config,
                repo_root=tmp_path,
                egress_network="custom-egress-net",
            )
            # Sandbox should receive custom egress_network
            assert (
                mock_sandbox.call_args.kwargs["egress_network"]
                == "custom-egress-net"
            )


class TestSubmitMessage:
    def test_no_pool(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        msg = make_message()
        assert svc.submit_message(msg, handler) is False

    def test_rejects_active_conversation(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        svc.tracker.is_task_active.return_value = True
        update_global(svc, dashboard_base_url=None)
        msg = make_message(subject="[ID:aabb1122] Test")
        result = svc.submit_message(msg, handler)
        assert result is False
        handler.responder.send_reply.assert_called_once()  # rejection sent

    def test_submits_successfully(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        svc.tracker.is_task_active.return_value = False
        mock_future = MagicMock()
        svc._executor_pool.submit.return_value = mock_future

        msg = make_message(subject="[ID:aabb1122] Test")
        result = svc.submit_message(msg, handler)
        assert result is True
        assert mock_future in svc._pending_futures

    def test_new_message_temp_id(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        svc.tracker.is_task_active.return_value = False
        mock_future = MagicMock()
        svc._executor_pool.submit.return_value = mock_future

        msg = make_message(subject="No conv id")
        svc.submit_message(msg, handler)
        # task_id should start with "new-"
        task_id = svc.tracker.add_task.call_args[0][0]
        assert task_id.startswith("new-")


class TestOnFutureComplete:
    def test_removes_future(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        future = MagicMock(spec=concurrent.futures.Future)
        future.exception.return_value = None
        svc._pending_futures.add(future)
        svc._on_future_complete(future)
        assert future not in svc._pending_futures

    def test_logs_exception(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        future = MagicMock(spec=concurrent.futures.Future)
        future.exception.return_value = RuntimeError("boom")
        svc._pending_futures.add(future)
        svc._on_future_complete(future)

    def test_handles_cancelled(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        future = MagicMock(spec=concurrent.futures.Future)
        future.exception.side_effect = concurrent.futures.CancelledError()
        svc._pending_futures.add(future)
        svc._on_future_complete(future)

    def test_keeps_other_futures(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        f1 = MagicMock(spec=concurrent.futures.Future)
        f1.exception.return_value = None
        f2 = MagicMock(spec=concurrent.futures.Future)
        svc._pending_futures = {f1, f2}
        svc._on_future_complete(f1)
        assert f2 in svc._pending_futures
        assert f1 not in svc._pending_futures


class TestGetConversationLock:
    def test_creates_new_lock(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        lock = svc._get_conversation_lock("conv1")
        assert isinstance(lock, threading.Lock)

    def test_returns_same_lock(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        lock1 = svc._get_conversation_lock("conv1")
        lock2 = svc._get_conversation_lock("conv1")
        assert lock1 is lock2


class TestProcessMessageWorker:
    def test_new_conversation(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.exists.return_value = False
        msg = make_message(subject="No conv id")

        with patch(
            "lib.gateway.service.gateway.process_message",
            return_value=(True, "conv1"),
        ):
            svc._process_message_worker(msg, "new-123", handler)
        svc.tracker.start_task.assert_called_once_with("new-123")
        svc.tracker.complete_task.assert_called_once_with("conv1", True)

    def test_existing_conversation_uses_lock(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.exists.return_value = True
        msg = make_message(subject="[ID:aabb1122] Test")

        with patch(
            "lib.gateway.service.gateway.process_message",
            return_value=(True, "conv1"),
        ):
            svc._process_message_worker(msg, "conv1", handler)
        svc.tracker.complete_task.assert_called_once_with("conv1", True)

    def test_exception_marks_failed(self, email_config, tmp_path: Path) -> None:
        import pytest

        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.exists.return_value = False
        msg = make_message(subject="Test")

        with patch(
            "lib.gateway.service.gateway.process_message",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(RuntimeError):
                svc._process_message_worker(msg, "task1", handler)
        svc.tracker.complete_task.assert_called_once_with("task1", False)

    def test_uses_returned_conv_id(self, email_config, tmp_path: Path) -> None:
        """When process_message returns a conv_id, use it for completion."""
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.exists.return_value = False
        msg = make_message(subject="New task")

        with patch(
            "lib.gateway.service.gateway.process_message",
            return_value=(False, "real-conv-id"),
        ):
            svc._process_message_worker(msg, "temp-123", handler)
        svc.tracker.complete_task.assert_called_once_with("real-conv-id", False)

    def test_none_conv_id_uses_task_id(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.exists.return_value = False
        msg = make_message(subject="Test")

        with patch(
            "lib.gateway.service.gateway.process_message",
            return_value=(False, None),
        ):
            svc._process_message_worker(msg, "task1", handler)
        svc.tracker.complete_task.assert_called_once_with("task1", False)


class TestStartStop:
    def test_start_calls_components(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        # Make _listener_loop exit immediately
        def fake_loop():
            svc.running = False

        with patch.object(handler, "_listener_loop", side_effect=fake_loop):
            svc.start()

        handler.conversation_manager.mirror.update_mirror.assert_called_once()
        handler.listener.connect.assert_called_once_with(max_retries=3)
        assert svc._executor_pool is not None

    def test_start_with_dashboard(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(
            email_config, tmp_path, dashboard_enabled=True
        )

        def fake_loop():
            svc.running = False

        with (
            patch.object(handler, "_listener_loop", side_effect=fake_loop),
            patch("lib.gateway.service.gateway.DashboardServer") as mock_ds,
        ):
            update_global(svc, dashboard_enabled=True)
            svc.start()
        mock_ds.return_value.start.assert_called_once()

    def test_stop_idempotent(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        svc.stop()
        svc.stop()  # Second call should be no-op
        handler.listener.close.assert_called_once()

    def test_stop_waits_for_pending(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        update_global(svc, shutdown_timeout_seconds=5)

        future = MagicMock(spec=concurrent.futures.Future)
        svc._pending_futures.add(future)

        with patch("concurrent.futures.wait", return_value=(set(), set())):
            svc.stop()

    def test_stop_cancels_not_done(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        update_global(svc, shutdown_timeout_seconds=1)

        future = MagicMock(spec=concurrent.futures.Future)
        svc._pending_futures.add(future)

        with patch(
            "concurrent.futures.wait",
            return_value=(set(), {future}),
        ):
            svc.stop()
        future.cancel.assert_called_once()

    def test_stop_with_dashboard(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        svc.dashboard = MagicMock()
        svc.stop()
        svc.dashboard.stop.assert_called_once()

    def test_stop_no_pool(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)
        svc._executor_pool = None
        svc.stop()  # should not raise

    def test_start_keyboard_interrupt(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        def fake_loop():
            pass  # Don't set running=False; let sleep raise

        with (
            patch.object(handler, "_listener_loop", side_effect=fake_loop),
            patch("time.sleep", side_effect=KeyboardInterrupt),
        ):
            svc.start()  # Should handle KeyboardInterrupt gracefully
        # Signal GC daemon thread to stop cleanly
        svc._shutdown_event.set()


class TestRepoHandlerInitError:
    def test_repo_handler_init_error_recorded(
        self, email_config, tmp_path: Path
    ) -> None:
        """RepoHandler.__init__ failure is recorded in _init_errors."""
        from lib.gateway.config import GlobalConfig, ServerConfig

        global_config = GlobalConfig(dashboard_enabled=False)
        server_config = ServerConfig(
            global_config=global_config, repos={"test": email_config}
        )

        # Make RepoHandler init fail by patching ConversationManager
        with (
            patch("lib.gateway.service.repo_handler.EmailListener"),
            patch("lib.gateway.service.repo_handler.EmailResponder"),
            patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
            patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
            patch(
                "lib.gateway.service.repo_handler.ConversationManager",
                side_effect=RuntimeError("Git clone failed"),
            ),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.Sandbox"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = (MagicMock(git_sha="x"), MagicMock())
            svc = EmailGatewayService(server_config, repo_root=tmp_path)

        # Handler was not created, but error was recorded
        assert "test" not in svc.repo_handlers
        assert "test" in svc._init_errors
        assert svc._init_errors["test"][0] == "RuntimeError"
        assert "Git clone failed" in svc._init_errors["test"][1]

    def test_init_error_recorded_as_failed_repo_state(
        self, email_config, tmp_path: Path
    ) -> None:
        """Init errors become FAILED repo_states when start() is called."""
        import pytest

        from lib.dashboard.tracker import RepoStatus
        from lib.gateway.config import GlobalConfig, ServerConfig

        global_config = GlobalConfig(dashboard_enabled=False)
        server_config = ServerConfig(
            global_config=global_config, repos={"test": email_config}
        )

        with (
            patch("lib.gateway.service.repo_handler.EmailListener"),
            patch("lib.gateway.service.repo_handler.EmailResponder"),
            patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
            patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
            patch(
                "lib.gateway.service.repo_handler.ConversationManager",
                side_effect=RuntimeError("Git clone failed"),
            ),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.Sandbox"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = (MagicMock(git_sha="x"), MagicMock())
            svc = EmailGatewayService(server_config, repo_root=tmp_path)

        # start() should fail since all repos failed during init
        with pytest.raises(RuntimeError, match="All 1 repo"):
            svc.start()

        # Error should be in repo_states
        repo_states = {r.repo_id: r for r in svc._repos_store.get().value}
        assert len(repo_states) == 1
        assert repo_states["test"].status == RepoStatus.FAILED
        assert "Git clone failed" in (repo_states["test"].error_message or "")


class TestStartRepoInitFailure:
    def test_repo_init_fails_records_error(
        self, email_config, tmp_path: Path
    ) -> None:
        """When a repo fails to init, error is recorded in repo_states."""
        import pytest

        from lib.dashboard.tracker import RepoStatus

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        # Make the repo fail during start_listener via mock's side_effect
        handler.conversation_manager.mirror.update_mirror.side_effect = (
            RuntimeError("IMAP auth failed")
        )

        # All repos fail so should raise
        with pytest.raises(RuntimeError, match="All 1 repo"):
            svc.start()

        # Check that error was recorded
        repo_states = {r.repo_id: r for r in svc._repos_store.get().value}
        assert len(repo_states) == 1
        assert repo_states["test"].status == RepoStatus.FAILED
        err_msg = repo_states["test"].error_message or ""
        assert "IMAP auth failed" in err_msg
        assert repo_states["test"].error_type == "RuntimeError"

    def test_all_repos_fail_raises(self, email_config, tmp_path: Path) -> None:
        """When all repos fail, service should raise RuntimeError."""
        import pytest

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        # Make the repo fail during start_listener
        handler.listener.connect.side_effect = RuntimeError(
            "Connection refused"
        )

        with pytest.raises(RuntimeError, match="All 1 repo"):
            svc.start()

    def test_partial_failure_logs_warning(
        self, email_config, tmp_path: Path
    ) -> None:
        """When some repos fail but at least one starts, service continues."""
        from lib.gateway.service.repo_handler import RepoHandler

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        # Add a second mock handler that will fail
        mock_handler2 = MagicMock(spec=RepoHandler)
        mock_handler2.config = MagicMock()
        mock_handler2.config.repo_id = "repo2"
        mock_handler2.config.git_repo_url = "https://example.com/repo2"
        mock_handler2.config.imap_server = "imap2.example.com"
        mock_handler2.config.storage_dir = tmp_path / "s2"
        mock_handler2.start_listener.side_effect = RuntimeError("Auth failed")
        svc.repo_handlers["repo2"] = mock_handler2

        # Make the first handler succeed but stop immediately
        def fake_start():
            svc.running = False
            return MagicMock()

        handler.start_listener = fake_start

        svc.start()

        # Service should start with partial failure
        repo_states = {r.repo_id: r for r in svc._repos_store.get().value}
        assert len(repo_states) == 2
        from lib.dashboard.tracker import RepoStatus

        assert repo_states["test"].status == RepoStatus.LIVE
        assert repo_states["repo2"].status == RepoStatus.FAILED


class TestBootState:
    def test_boot_state_ready_on_success(
        self, email_config, tmp_path: Path
    ) -> None:
        """Boot state should be READY after successful start."""
        from lib.dashboard.tracker import BootPhase

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        def fake_loop():
            svc.running = False

        with patch.object(handler, "_listener_loop", side_effect=fake_loop):
            svc.start()

        boot = svc._boot_store.get().value
        assert boot.phase == BootPhase.READY
        assert boot.completed_at is not None

    def test_boot_state_failed_on_error(
        self, email_config, tmp_path: Path
    ) -> None:
        """Boot state should be FAILED when boot raises."""
        import pytest

        from lib.dashboard.tracker import BootPhase

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        handler.listener.connect.side_effect = RuntimeError(
            "Connection refused"
        )

        with pytest.raises(RuntimeError, match="All 1 repo"):
            svc.start()

        boot = svc._boot_store.get().value
        assert boot.phase == BootPhase.FAILED
        assert boot.error_message is not None
        assert "All 1 repo" in boot.error_message
        assert boot.error_type == "RuntimeError"
        assert boot.error_traceback is not None

    def test_resilient_mode_stays_alive(
        self, email_config, tmp_path: Path
    ) -> None:
        """Resilient mode should not raise on boot failure."""
        from lib.dashboard.tracker import BootPhase

        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, dashboard_enabled=False)

        handler.listener.connect.side_effect = RuntimeError(
            "Connection refused"
        )

        # Make main loop exit immediately after boot failure
        with patch("time.sleep", side_effect=KeyboardInterrupt):
            svc.start(resilient=True)

        boot = svc._boot_store.get().value
        assert boot.phase == BootPhase.FAILED
        assert boot.error_message is not None

    def test_dashboard_stopped_on_boot_failure(
        self, email_config, tmp_path: Path
    ) -> None:
        """Dashboard stopped cleanly on boot failure (non-resilient)."""
        import pytest

        svc, handler = make_service(
            email_config, tmp_path, dashboard_enabled=True
        )

        handler.listener.connect.side_effect = RuntimeError("fail")

        with (
            patch("lib.gateway.service.gateway.DashboardServer") as mock_ds,
            pytest.raises(RuntimeError, match="All 1 repo"),
        ):
            svc.start()

        mock_ds.return_value.stop.assert_called_once()

    def test_dashboard_started_early(
        self, email_config, tmp_path: Path
    ) -> None:
        """Dashboard should start before boot completes."""
        svc, handler = make_service(
            email_config, tmp_path, dashboard_enabled=True
        )

        dashboard_started_during_boot = False

        original_boot = svc._boot

        def check_dashboard_then_boot():
            nonlocal dashboard_started_during_boot
            # Dashboard should already be started when _boot runs
            dashboard_started_during_boot = svc.dashboard is not None
            svc.running = False
            return original_boot()

        with (
            patch.object(handler, "_listener_loop", side_effect=lambda: None),
            patch("lib.gateway.service.gateway.DashboardServer") as mock_ds,
        ):
            svc._boot = check_dashboard_then_boot
            svc.start()

        assert dashboard_started_during_boot
        mock_ds.return_value.start.assert_called_once()


class TestStateProviders:
    def test_get_repo_states(self, email_config, tmp_path: Path) -> None:
        """_get_repo_states returns dirs based on repos_store."""
        from lib.dashboard.tracker import RepoState, RepoStatus

        svc, _ = make_service(email_config, tmp_path)
        svc._repos_store.update(
            (
                RepoState(
                    repo_id="r1",
                    status=RepoStatus.LIVE,
                    git_repo_url="https://example.com/r1",
                    imap_server="imap.example.com",
                    storage_dir="/s/r1",
                ),
            )
        )
        result = svc._repos_store.get().value
        assert len(result) == 1
        assert result[0].repo_id == "r1"

    def test_get_work_dirs(self, email_config, tmp_path: Path) -> None:
        """_get_work_dirs returns dirs for live repos only."""
        from lib.dashboard.tracker import RepoState, RepoStatus

        svc, handler = make_service(email_config, tmp_path)
        svc._repos_store.update(
            (
                RepoState(
                    repo_id="test",
                    status=RepoStatus.LIVE,
                    git_repo_url="https://example.com/r1",
                    imap_server="imap.example.com",
                    storage_dir="/s/test",
                ),
            )
        )
        result = svc._get_work_dirs()
        assert len(result) == 1
        assert result[0] == handler.conversation_manager.conversations_dir

    def test_get_work_dirs_excludes_failed(
        self, email_config, tmp_path: Path
    ) -> None:
        """_get_work_dirs excludes repos that failed to start."""
        from lib.dashboard.tracker import RepoState, RepoStatus

        svc, _ = make_service(email_config, tmp_path)
        svc._repos_store.update(
            (
                RepoState(
                    repo_id="test",
                    status=RepoStatus.FAILED,
                    git_repo_url="https://example.com/r1",
                    imap_server="imap.example.com",
                    storage_dir="/s/test",
                ),
            )
        )
        result = svc._get_work_dirs()
        assert len(result) == 0


class TestStopExecution:
    def test_found_active_task(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        mock_task = MagicMock()
        mock_task.stop.return_value = True
        svc._active_tasks["conv1"] = mock_task
        assert svc._stop_execution("conv1") is True
        mock_task.stop.assert_called_once()

    def test_not_found(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        assert svc._stop_execution("conv1") is False


class TestGarbageCollectorThread:
    def test_removes_old_conversations(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, conversation_max_age_days=7)

        conv_path = tmp_path / "old_conv"
        conv_path.mkdir()
        # Make it old (> 7 days)
        old_time = time.time() - (8 * 24 * 60 * 60)
        os.utime(conv_path, (old_time, old_time))

        handler.conversation_manager.list_all.return_value = ["conv1"]
        handler.conversation_manager.get_workspace_path.return_value = conv_path

        # First wait: False (timeout, run GC); second: True (shutdown)
        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()

        handler.conversation_manager.delete.assert_called_once_with("conv1")

    def test_keeps_recent_conversations(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, conversation_max_age_days=7)

        conv_path = tmp_path / "new_conv"
        conv_path.mkdir()

        handler.conversation_manager.list_all.return_value = ["conv1"]
        handler.conversation_manager.get_workspace_path.return_value = conv_path

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()

        handler.conversation_manager.delete.assert_not_called()

    def test_handles_exception(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.conversation_manager.list_all.side_effect = RuntimeError("boom")

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()

    def test_exits_when_not_running(self, email_config, tmp_path: Path) -> None:
        svc, _ = make_service(email_config, tmp_path)

        # Signal shutdown immediately
        svc._shutdown_event.wait = MagicMock(return_value=True)
        svc._garbage_collector_thread()

    def test_nonexistent_path(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        update_global(svc, conversation_max_age_days=7)

        handler.conversation_manager.list_all.return_value = ["conv1"]
        handler.conversation_manager.get_workspace_path.return_value = (
            tmp_path / "nonexistent"
        )

        svc._shutdown_event.wait = MagicMock(side_effect=[False, True])
        svc._garbage_collector_thread()

        handler.conversation_manager.delete.assert_not_called()


class TestMain:
    def test_config_error(self) -> None:
        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                side_effect=ValueError("missing ENV"),
            ),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=False
            )
            assert main() == 1

    def test_init_failure(self) -> None:
        mock_config = MagicMock()
        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                side_effect=RuntimeError("init fail"),
            ),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=False
            )
            assert main() == 2

    def test_runtime_error(self) -> None:
        mock_config = MagicMock()
        mock_svc = MagicMock()
        mock_svc.start.side_effect = RuntimeError("crash")
        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                return_value=mock_svc,
            ),
            patch.dict("os.environ", {}, clear=False),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=False
            )
            assert main() == 3
        mock_svc.stop.assert_called_once()

    def test_keyboard_interrupt(self) -> None:
        mock_config = MagicMock()
        mock_svc = MagicMock()
        mock_svc.start.side_effect = KeyboardInterrupt
        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                return_value=mock_svc,
            ),
            patch.dict("os.environ", {}, clear=False),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=False
            )
            assert main() == 0
        mock_svc.stop.assert_called_once()

    def test_success(self) -> None:
        mock_config = MagicMock()
        mock_svc = MagicMock()
        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                return_value=mock_svc,
            ),
            patch.dict("os.environ", {}, clear=False),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=False
            )
            assert main() == 0
        mock_svc.stop.assert_called_once()

    def test_debug_mode(self) -> None:
        import logging

        mock_config = MagicMock()
        mock_svc = MagicMock()
        with (
            patch("lib.gateway.service.gateway.configure_logging") as mock_cl,
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                return_value=mock_svc,
            ),
            patch.dict("os.environ", {}, clear=False),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=True, resilient=False
            )
            main()

        mock_cl.assert_called_once_with(
            level=logging.DEBUG, add_secret_filter=True
        )

    def test_signal_handlers_set(self) -> None:
        import signal as sig_mod

        mock_config = MagicMock()
        mock_svc = MagicMock()
        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                return_value=mock_svc,
            ),
            patch("lib.gateway.service.gateway.signal.signal") as mock_sig,
            patch.dict("os.environ", {}, clear=False),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=False
            )
            main()

        sig_calls = [c[0][0] for c in mock_sig.call_args_list]
        assert sig_mod.SIGINT in sig_calls
        assert sig_mod.SIGTERM in sig_calls

    def test_shutdown_handler(self) -> None:
        """Test that the shutdown handler sets running=False and interrupts."""
        mock_config = MagicMock()
        mock_svc = MagicMock()
        mock_svc.running = True
        mock_svc.repo_handlers = {"test": MagicMock()}
        captured_handler = None

        def capture_signal(signum, handler):
            nonlocal captured_handler
            if signum == 2:  # SIGINT
                captured_handler = handler

        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                return_value=mock_svc,
            ),
            patch(
                "lib.gateway.service.gateway.signal.signal",
                side_effect=capture_signal,
            ),
            patch.dict("os.environ", {}, clear=False),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=False
            )
            main()

        assert captured_handler is not None
        # Call the shutdown handler
        captured_handler(2, None)
        assert mock_svc.running is False
        mock_svc.repo_handlers["test"].listener.interrupt.assert_called_once()

    def test_resilient_flag_passed(self) -> None:
        """Test that --resilient flag is passed to service.start()."""
        mock_config = MagicMock()
        mock_svc = MagicMock()
        with (
            patch("lib.gateway.service.gateway.configure_logging"),
            patch(
                "lib.gateway.service.gateway.argparse.ArgumentParser"
            ) as mock_ap,
            patch(
                "lib.gateway.service.gateway.ServerConfig.from_yaml",
                return_value=mock_config,
            ),
            patch(
                "lib.gateway.service.gateway.EmailGatewayService",
                return_value=mock_svc,
            ),
            patch.dict("os.environ", {}, clear=False),
        ):
            mock_ap.return_value.parse_args.return_value = MagicMock(
                debug=False, resilient=True
            )
            assert main() == 0
        mock_svc.start.assert_called_once_with(resilient=True)


class TestUpstreamDnsResolution:
    """Tests for upstream DNS auto-detection in EmailGatewayService init."""

    def test_auto_detects_when_upstream_dns_is_none(
        self, email_config, tmp_path: Path
    ) -> None:
        """When upstream_dns is None, get_system_resolver() is called."""
        from lib.gateway.config import GlobalConfig, ServerConfig

        global_config = GlobalConfig(dashboard_enabled=False)
        assert global_config.upstream_dns is None

        server_config = ServerConfig(
            global_config=global_config, repos={"test": email_config}
        )

        with (
            patch("lib.gateway.service.repo_handler.EmailListener"),
            patch("lib.gateway.service.repo_handler.EmailResponder"),
            patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
            patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
            patch("lib.gateway.service.repo_handler.ConversationManager"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.Sandbox") as mock_sandbox,
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="192.168.1.1",
            ) as mock_resolver,
        ):
            mv.return_value = (MagicMock(git_sha="x"), MagicMock())
            EmailGatewayService(server_config, repo_root=tmp_path)
            mock_resolver.assert_called_once()
            # Sandbox should receive the auto-detected DNS via SandboxConfig
            assert mock_sandbox.call_args[0][0].upstream_dns == "192.168.1.1"

    def test_uses_explicit_upstream_dns(
        self, email_config, tmp_path: Path
    ) -> None:
        """Explicit upstream_dns skips get_system_resolver()."""
        from lib.gateway.config import GlobalConfig, ServerConfig

        global_config = GlobalConfig(
            dashboard_enabled=False, upstream_dns="8.8.8.8"
        )
        server_config = ServerConfig(
            global_config=global_config, repos={"test": email_config}
        )

        with (
            patch("lib.gateway.service.repo_handler.EmailListener"),
            patch("lib.gateway.service.repo_handler.EmailResponder"),
            patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
            patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
            patch("lib.gateway.service.repo_handler.ConversationManager"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.Sandbox") as mock_sandbox,
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
            ) as mock_resolver,
        ):
            mv.return_value = (MagicMock(git_sha="x"), MagicMock())
            EmailGatewayService(server_config, repo_root=tmp_path)
            mock_resolver.assert_not_called()
            # Sandbox should receive the explicit DNS via SandboxConfig
            assert mock_sandbox.call_args[0][0].upstream_dns == "8.8.8.8"

    def test_system_resolver_error_propagates(
        self, email_config, tmp_path: Path
    ) -> None:
        """SystemResolverError propagates to caller."""
        from lib.dns import SystemResolverError
        from lib.gateway.config import GlobalConfig, ServerConfig

        global_config = GlobalConfig(dashboard_enabled=False)
        server_config = ServerConfig(
            global_config=global_config, repos={"test": email_config}
        )

        with (
            patch("lib.gateway.service.repo_handler.EmailListener"),
            patch("lib.gateway.service.repo_handler.EmailResponder"),
            patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
            patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
            patch("lib.gateway.service.repo_handler.ConversationManager"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.Sandbox"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                side_effect=SystemResolverError("No nameserver entries found"),
            ),
        ):
            mv.return_value = (MagicMock(git_sha="x"), MagicMock())
            import pytest

            with pytest.raises(
                SystemResolverError, match="No nameserver entries"
            ):
                EmailGatewayService(server_config, repo_root=tmp_path)
