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
            patch("lib.gateway.service.repo_handler.ClaudeExecutor"),
            patch("lib.gateway.service.gateway.UpdateLock") as mock_ulock,
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.ProxyManager"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = MagicMock(git_sha="x", worktree_clean=True)
            EmailGatewayService(server_config, repo_root=None)
            # UpdateLock should receive a path derived from __file__
            lock_path = mock_ulock.call_args[0][0]
            assert lock_path.name == ".update.lock"

    def test_init_custom_egress_network(
        self, email_config, tmp_path: Path
    ) -> None:
        """Custom egress_network is passed to ProxyManager."""
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
            patch("lib.gateway.service.repo_handler.ClaudeExecutor"),
            patch("lib.gateway.service.gateway.UpdateLock"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.ProxyManager") as mock_pm,
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = MagicMock(git_sha="x", worktree_clean=True)
            EmailGatewayService(
                server_config,
                repo_root=tmp_path,
                egress_network="custom-egress-net",
            )
            # ProxyManager should receive custom egress_network
            call_kwargs = mock_pm.call_args.kwargs
            assert call_kwargs.get("egress_network") == "custom-egress-net"


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

    def test_acquires_update_lock_on_first(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        svc._executor_pool = MagicMock()
        svc.tracker.is_task_active.return_value = False
        mock_future = MagicMock()
        svc._executor_pool.submit.return_value = mock_future

        msg = make_message(subject="New task")
        svc.submit_message(msg, handler)
        svc._update_lock.try_acquire.assert_called_once()

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
    def test_removes_future_and_releases_lock(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, _ = make_service(email_config, tmp_path)
        future = MagicMock(spec=concurrent.futures.Future)
        future.exception.return_value = None
        svc._pending_futures.add(future)
        svc._on_future_complete(future)
        assert future not in svc._pending_futures
        svc._update_lock.release.assert_called_once()

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

    def test_no_release_if_still_pending(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, _ = make_service(email_config, tmp_path)
        f1 = MagicMock(spec=concurrent.futures.Future)
        f1.exception.return_value = None
        f2 = MagicMock(spec=concurrent.futures.Future)
        svc._pending_futures = {f1, f2}
        svc._on_future_complete(f1)
        svc._update_lock.release.assert_not_called()


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
            svc.dashboard = mock_ds.return_value
            update_global(svc, dashboard_enabled=True)
            svc.start()
        svc.dashboard.start.assert_called_once()

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
            patch("lib.gateway.service.repo_handler.ClaudeExecutor"),
            patch("lib.gateway.service.gateway.UpdateLock"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.ProxyManager"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = MagicMock(git_sha="x", worktree_clean=True)
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
            patch("lib.gateway.service.repo_handler.ClaudeExecutor"),
            patch("lib.gateway.service.gateway.UpdateLock"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.ProxyManager"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="127.0.0.53",
            ),
        ):
            mv.return_value = MagicMock(git_sha="x", worktree_clean=True)
            svc = EmailGatewayService(server_config, repo_root=tmp_path)

        # start() should fail since all repos failed during init
        with pytest.raises(RuntimeError, match="All 1 repo"):
            svc.start()

        # Error should be in repo_states
        assert len(svc.repo_states) == 1
        assert svc.repo_states["test"].status == RepoStatus.FAILED
        assert "Git clone failed" in (
            svc.repo_states["test"].error_message or ""
        )


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
        assert len(svc.repo_states) == 1
        assert svc.repo_states["test"].status == RepoStatus.FAILED
        err_msg = svc.repo_states["test"].error_message or ""
        assert "IMAP auth failed" in err_msg
        assert svc.repo_states["test"].error_type == "RuntimeError"

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
        assert len(svc.repo_states) == 2
        from lib.dashboard.tracker import RepoStatus

        assert svc.repo_states["test"].status == RepoStatus.LIVE
        assert svc.repo_states["repo2"].status == RepoStatus.FAILED


class TestStopExecution:
    def test_found_in_handler(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.executor.stop_execution.return_value = True
        assert svc._stop_execution("conv1") is True

    def test_found_via_conv_repo_map(
        self, email_config, tmp_path: Path
    ) -> None:
        svc, handler = make_service(email_config, tmp_path)
        svc._conv_repo_map["conv1"] = "test"
        handler.executor.stop_execution.return_value = True
        assert svc._stop_execution("conv1") is True
        handler.executor.stop_execution.assert_called_once_with("conv1")

    def test_not_found(self, email_config, tmp_path: Path) -> None:
        svc, handler = make_service(email_config, tmp_path)
        handler.executor.stop_execution.return_value = False
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
                debug=False
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
                debug=False
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
                debug=False
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
                debug=False
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
                debug=False
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
            mock_ap.return_value.parse_args.return_value = MagicMock(debug=True)
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
                debug=False
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
                debug=False
            )
            main()

        assert captured_handler is not None
        # Call the shutdown handler
        captured_handler(2, None)
        assert mock_svc.running is False
        mock_svc.repo_handlers["test"].listener.interrupt.assert_called_once()


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
            patch("lib.gateway.service.repo_handler.ClaudeExecutor"),
            patch("lib.gateway.service.gateway.UpdateLock"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.ProxyManager") as mock_pm,
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                return_value="192.168.1.1",
            ) as mock_resolver,
        ):
            mv.return_value = MagicMock(git_sha="x", worktree_clean=True)
            EmailGatewayService(server_config, repo_root=tmp_path)
            mock_resolver.assert_called_once()
            # ProxyManager should receive the auto-detected DNS
            call_kwargs = mock_pm.call_args.kwargs
            assert call_kwargs["upstream_dns"] == "192.168.1.1"

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
            patch("lib.gateway.service.repo_handler.ClaudeExecutor"),
            patch("lib.gateway.service.gateway.UpdateLock"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.ProxyManager") as mock_pm,
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
            ) as mock_resolver,
        ):
            mv.return_value = MagicMock(git_sha="x", worktree_clean=True)
            EmailGatewayService(server_config, repo_root=tmp_path)
            mock_resolver.assert_not_called()
            # ProxyManager should receive the explicit DNS
            call_kwargs = mock_pm.call_args.kwargs
            assert call_kwargs["upstream_dns"] == "8.8.8.8"

    def test_system_resolver_error_propagates(
        self, email_config, tmp_path: Path
    ) -> None:
        """SystemResolverError propagates to caller."""
        from lib.container.dns import SystemResolverError
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
            patch("lib.gateway.service.repo_handler.ClaudeExecutor"),
            patch("lib.gateway.service.gateway.UpdateLock"),
            patch("lib.gateway.service.gateway.capture_version_info") as mv,
            patch("lib.gateway.service.gateway.TaskTracker"),
            patch("lib.gateway.service.gateway.ProxyManager"),
            patch(
                "lib.gateway.service.gateway.get_system_resolver",
                side_effect=SystemResolverError("No nameserver entries found"),
            ),
        ):
            mv.return_value = MagicMock(git_sha="x", worktree_clean=True)
            import pytest

            with pytest.raises(
                SystemResolverError, match="No nameserver entries"
            ):
                EmailGatewayService(server_config, repo_root=tmp_path)
