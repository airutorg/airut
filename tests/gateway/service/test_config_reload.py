# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Unit tests for config live reload orchestration."""

from __future__ import annotations

import dataclasses
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from airut.dashboard.tracker import TaskTracker
from airut.gateway.config import (
    EmailChannelConfig,
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)
from airut.gateway.service import GatewayService


def _make_email_config(
    repo_id: str = "test",
    model: str = "opus",
    **overrides: object,
) -> RepoServerConfig:
    """Build a minimal RepoServerConfig with email channel.

    Uses repo_id-derived usernames so multiple repos don't collide
    on ServerConfig's IMAP inbox uniqueness check.
    """
    email = EmailChannelConfig(
        imap_server="localhost",
        imap_port=993,
        smtp_server="localhost",
        smtp_port=587,
        username=f"{repo_id}-user",
        password="test",
        from_address=f"claude-{repo_id}@test.local",
        authorized_senders=["user@test.local"],
        trusted_authserv_id="test.local",
    )
    kwargs: dict[str, Any] = {
        "repo_id": repo_id,
        "git_repo_url": f"https://github.com/test/{repo_id}",
        "channels": {"email": email},
        "model": model,
    }
    kwargs.update(overrides)
    return RepoServerConfig(**kwargs)


def _make_service(
    tmp_path: Path,
    repos: dict[str, RepoServerConfig] | None = None,
    **global_overrides: object,
) -> GatewayService:
    """Create a GatewayService with mocked externals."""
    if repos is None:
        repos = {"test": _make_email_config()}

    global_kwargs: dict[str, Any] = {"dashboard_enabled": False}
    global_kwargs.update(global_overrides)
    global_config = GlobalConfig(**global_kwargs)
    server_config = ServerConfig(global_config=global_config, repos=repos)

    with (
        patch(
            "airut.gateway.service.repo_handler.create_adapters"
        ) as mock_create,
        patch("airut.gateway.service.repo_handler.ConversationManager"),
        patch("airut.gateway.service.gateway.capture_version_info") as mock_ver,
        patch("airut.gateway.service.gateway.Sandbox"),
        patch(
            "airut.gateway.service.gateway.get_system_resolver",
            return_value="127.0.0.53",
        ),
    ):
        mock_adapter = MagicMock()
        mock_create.return_value = {"email": mock_adapter}
        mock_ver.return_value = (
            MagicMock(git_sha="abc1234"),
            MagicMock(),
        )
        svc = GatewayService(server_config, repo_root=tmp_path)

    return svc


class TestDiffGlobal:
    """Tests for _diff_global."""

    def test_no_change(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        assert not svc._diff_global(svc.config)

    def test_change(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config,
                dashboard_port=9999,
            ),
        )
        assert svc._diff_global(new_config)


class TestDiffRepos:
    """Tests for _diff_repos."""

    def test_no_change(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        assert svc._diff_repos(svc.config) == {}

    def test_task_scope_change(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_repo = dataclasses.replace(svc.config.repos["test"], model="sonnet")
        new_config = dataclasses.replace(svc.config, repos={"test": new_repo})
        result = svc._diff_repos(new_config)
        assert result == {"test": "task"}

    def test_repo_scope_change(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_repo = dataclasses.replace(
            svc.config.repos["test"],
            git_repo_url="https://github.com/test/other",
        )
        new_config = dataclasses.replace(svc.config, repos={"test": new_repo})
        result = svc._diff_repos(new_config)
        assert result == {"test": "repo"}

    def test_added_repo(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_repo = _make_email_config(repo_id="new-repo")
        new_config = dataclasses.replace(
            svc.config,
            repos={**svc.config.repos, "new-repo": new_repo},
        )
        result = svc._diff_repos(new_config)
        assert result == {"new-repo": "added"}

    def test_removed_repo(self, tmp_path: Path) -> None:
        repos = {
            "a": _make_email_config(repo_id="a"),
            "b": _make_email_config(repo_id="b"),
        }
        svc = _make_service(tmp_path, repos=repos)
        new_config = dataclasses.replace(svc.config, repos={"a": repos["a"]})
        result = svc._diff_repos(new_config)
        assert result == {"b": "removed"}


class TestApplyTaskScope:
    """Tests for _apply_task_scope."""

    def test_swaps_config(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_repo = dataclasses.replace(svc.config.repos["test"], model="sonnet")
        new_config = dataclasses.replace(svc.config, repos={"test": new_repo})
        svc._apply_task_scope(new_config)
        assert svc.repo_handlers["test"].config.model == "sonnet"


class TestOnConfigChanged:
    """Tests for full _on_config_changed flow."""

    def test_successful_reload(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        source = MagicMock()
        svc._config_source = source

        new_repo = dataclasses.replace(svc.config.repos["test"], model="sonnet")
        new_config = dataclasses.replace(svc.config, repos={"test": new_repo})
        from airut.config.snapshot import ConfigSnapshot

        new_snapshot = ConfigSnapshot(
            new_config, frozenset({"global_config", "repos"})
        )
        source.load.return_value = {}

        with (
            patch.object(
                ServerConfig,
                "from_source",
                return_value=new_snapshot,
            ),
            patch("airut.gateway.service.gateway.reset_dotenv_state"),
        ):
            svc._on_config_changed()

        assert svc.config.repos["test"].model == "sonnet"
        assert svc._config_generation == 1
        assert svc._last_reload_error is None

    def test_parse_error_keeps_old_config(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        source = MagicMock()
        svc._config_source = source

        with (
            patch.object(
                ServerConfig,
                "from_source",
                side_effect=ValueError("bad yaml"),
            ),
            patch("airut.gateway.service.gateway.reset_dotenv_state"),
        ):
            svc._on_config_changed()

        assert svc.config.repos["test"].model == "opus"
        assert svc._config_generation == 0
        assert svc._last_reload_error is not None

    def test_concurrent_reload_dropped(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        source = MagicMock()
        svc._config_source = source

        # Acquire lock to simulate in-progress reload
        svc._reload_lock.acquire()
        try:
            # This should return immediately (non-blocking)
            new_repo = dataclasses.replace(
                svc.config.repos["test"], model="sonnet"
            )
            new_config = dataclasses.replace(
                svc.config, repos={"test": new_repo}
            )
            from airut.config.snapshot import ConfigSnapshot

            new_snapshot = ConfigSnapshot(
                new_config,
                frozenset({"global_config", "repos"}),
            )
            with (
                patch.object(
                    ServerConfig,
                    "from_source",
                    return_value=new_snapshot,
                ),
                patch("airut.gateway.service.gateway.reset_dotenv_state"),
            ):
                svc._on_config_changed()

            # Config should NOT have changed
            assert svc.config.repos["test"].model == "opus"
        finally:
            svc._reload_lock.release()

    def test_no_change_skips_apply(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        source = MagicMock()
        svc._config_source = source

        # Return identical config
        from airut.config.snapshot import ConfigSnapshot

        same_snapshot = ConfigSnapshot(
            svc.config,
            frozenset({"global_config", "repos"}),
        )
        with (
            patch.object(
                ServerConfig,
                "from_source",
                return_value=same_snapshot,
            ),
            patch("airut.gateway.service.gateway.reset_dotenv_state"),
        ):
            svc._on_config_changed()

        assert svc._config_generation == 0


class TestRepoScopeReload:
    """Tests for repo-scope reload behavior."""

    def test_immediate_when_idle(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)

        # Tracker returns no active tasks
        with (
            patch.object(
                TaskTracker,
                "has_active_tasks_for_repo",
                return_value=False,
            ),
            patch(
                "airut.gateway.service.gateway.create_adapters"
            ) as mock_create,
        ):
            mock_create.return_value = {"email": MagicMock()}
            svc._apply_repo_scope(svc.config, {"test": "repo"})

        # Should have called create_adapters (listener restart)
        mock_create.assert_called_once()

    def test_deferred_when_busy(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)

        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=True,
        ):
            svc._apply_repo_scope(svc.config, {"test": "repo"})

        assert "test" in svc._pending_repo_reload

    def test_deferred_applied_after_task(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        svc._pending_repo_reload["test"] = None

        # First call: still busy
        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=True,
        ):
            svc._check_pending_repo_reload("test")
        assert "test" in svc._pending_repo_reload

        # Second call: now idle
        with (
            patch.object(
                TaskTracker,
                "has_active_tasks_for_repo",
                return_value=False,
            ),
            patch(
                "airut.gateway.service.gateway.create_adapters"
            ) as mock_create,
        ):
            mock_create.return_value = {"email": MagicMock()}
            svc._check_pending_repo_reload("test")

        assert "test" not in svc._pending_repo_reload


class TestServerScopeReload:
    """Tests for server-scope reload behavior."""

    def test_deferred_until_idle(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config, dashboard_port=9999
            ),
        )

        svc._apply_server_scope(new_config, True)
        assert svc._pending_server_config is not None

    def test_applied_when_idle(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config,
                max_concurrent_executions=10,
            ),
        )
        svc._pending_server_config = new_config

        svc._executor_pool = MagicMock()
        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=False,
        ):
            svc._check_pending_server_reload()

        assert svc._pending_server_config is None

    def test_not_applied_when_busy(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config, dashboard_port=9999
            ),
        )
        svc._pending_server_config = new_config

        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=True,
        ):
            svc._check_pending_server_reload()

        assert svc._pending_server_config is not None


class TestReloadStatus:
    """Tests for _get_reload_status."""

    def test_initial_status(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        status = svc._get_reload_status()
        assert status == {
            "config_generation": 0,
            "config_file_sha256": svc._config_file_sha256,
            "server_reload_pending": False,
            "last_reload_error": None,
        }

    def test_after_reload(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        svc._config_generation = 3
        svc._config_file_sha256 = "abc123"
        svc._pending_server_config = MagicMock()
        svc._last_reload_error = "some error"

        status = svc._get_reload_status()
        assert status["config_generation"] == 3
        assert status["config_file_sha256"] == "abc123"
        assert status["server_reload_pending"] is True
        assert status["last_reload_error"] == "some error"


class TestReloadCondition:
    """Tests for _reload_condition signaling."""

    def test_notify_wakes_waiter(self, tmp_path: Path) -> None:
        """_notify_reload wakes threads waiting on _reload_condition."""
        svc = _make_service(tmp_path)
        entered = threading.Event()
        notified = threading.Event()

        def waiter() -> None:
            with svc._reload_condition:
                entered.set()
                svc._reload_condition.wait(timeout=5.0)
            notified.set()

        t = threading.Thread(target=waiter, daemon=True)
        t.start()
        entered.wait(timeout=2.0)
        svc._notify_reload()
        t.join(timeout=2.0)
        assert notified.is_set()

    def test_get_source_file_sha256_no_source(self, tmp_path: Path) -> None:
        """Returns None when no config source is set."""
        svc = _make_service(tmp_path)
        svc._config_source = None
        assert svc._get_source_file_sha256() is None

    def test_get_source_file_sha256_with_file(self, tmp_path: Path) -> None:
        """Returns SHA-256 from last_file_sha256 on the source."""
        from airut.config.source import YamlConfigSource

        config_path = tmp_path / "test.yaml"
        config_path.write_text("key: value\n")

        source = YamlConfigSource(config_path)
        source.load()

        svc = _make_service(tmp_path)
        svc._config_source = source

        assert svc._get_source_file_sha256() == source.last_file_sha256
        assert source.last_file_sha256 is not None


class TestAddRemoveRepo:
    """Tests for adding and removing repos on reload."""

    def test_add_repo(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_repo = _make_email_config(repo_id="new-repo")

        with (
            patch(
                "airut.gateway.service.repo_handler.create_adapters"
            ) as mock_create,
            patch("airut.gateway.service.repo_handler.ConversationManager"),
        ):
            mock_create.return_value = {"email": MagicMock()}
            svc._add_repo("new-repo", new_repo)

        assert "new-repo" in svc.repo_handlers

    def test_remove_idle_repo(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=False,
        ):
            svc._remove_repo("test")
        assert "test" not in svc.repo_handlers

    def test_remove_busy_repo_deferred(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=True,
        ):
            svc._remove_repo("test")
        assert "test" in svc.repo_handlers
        assert "test" in svc._pending_repo_reload

    def test_add_repo_exception(self, tmp_path: Path) -> None:
        """Exception during _add_repo is logged, not raised."""
        svc = _make_service(tmp_path)
        new_repo = _make_email_config(repo_id="bad-repo")

        with (
            patch(
                "airut.gateway.service.repo_handler.create_adapters",
                side_effect=RuntimeError("listener fail"),
            ),
            patch("airut.gateway.service.repo_handler.ConversationManager"),
        ):
            svc._add_repo("bad-repo", new_repo)

        assert "bad-repo" not in svc.repo_handlers


class TestConfigWatcherIntegration:
    """Tests for config watcher start/stop lifecycle."""

    def test_start_config_watcher_with_yaml_source(
        self, tmp_path: Path
    ) -> None:
        """Watcher starts when config_source is a YamlConfigSource."""
        from airut.config.source import YamlConfigSource

        svc = _make_service(tmp_path)
        mock_source = MagicMock(spec=YamlConfigSource)
        mock_source.path = tmp_path / "airut.yaml"
        (tmp_path / "airut.yaml").write_text("test: true\n")
        svc._config_source = mock_source

        with patch(
            "airut.gateway.service.gateway.ConfigFileWatcher"
        ) as mock_cfw:
            mock_watcher = MagicMock()
            mock_cfw.return_value = mock_watcher
            svc._start_config_watcher()

        mock_cfw.assert_called_once()
        mock_watcher.start.assert_called_once()

    def test_start_config_watcher_without_source(self, tmp_path: Path) -> None:
        """Watcher does not start when config_source is None."""
        svc = _make_service(tmp_path)
        svc._config_source = None
        svc._start_config_watcher()
        assert svc._watcher is None

    def test_start_config_watcher_non_yaml_source(self, tmp_path: Path) -> None:
        """Watcher does not start for non-YAML config sources."""
        svc = _make_service(tmp_path)
        svc._config_source = MagicMock()  # Not a YamlConfigSource
        svc._start_config_watcher()
        assert svc._watcher is None

    def test_stop_with_watcher(self, tmp_path: Path) -> None:
        """Stop stops the watcher if present."""
        svc = _make_service(tmp_path)
        mock_watcher = MagicMock()
        svc._watcher = mock_watcher
        svc.stop()
        mock_watcher.stop.assert_called_once()

    def test_on_config_changed_no_source(self, tmp_path: Path) -> None:
        """_on_config_changed returns early when no config source."""
        svc = _make_service(tmp_path)
        svc._config_source = None
        svc._on_config_changed()
        assert svc._config_generation == 0


class TestLogConfigDiff:
    """Tests for _log_config_diff."""

    def test_global_change_logged(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        svc._log_config_diff(True, {})

    def test_mixed_changes_logged(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        svc._log_config_diff(True, {"test": "task", "foo": "added"})


class TestApplyRepoScopeRouting:
    """Tests for _apply_repo_scope routing to add/remove/reload."""

    def test_added_routes_to_add_repo(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        new_repo = _make_email_config(repo_id="new-repo")
        new_config = dataclasses.replace(
            svc.config,
            repos={**svc.config.repos, "new-repo": new_repo},
        )
        with (
            patch(
                "airut.gateway.service.repo_handler.create_adapters"
            ) as mock_create,
            patch("airut.gateway.service.repo_handler.ConversationManager"),
        ):
            mock_create.return_value = {"email": MagicMock()}
            svc._apply_repo_scope(new_config, {"new-repo": "added"})
        assert "new-repo" in svc.repo_handlers

    def test_removed_routes_to_remove_repo(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path)
        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=False,
        ):
            svc._apply_repo_scope(svc.config, {"test": "removed"})
        assert "test" not in svc.repo_handlers


class TestApplySingleRepoReload:
    """Tests for _apply_single_repo_reload."""

    def test_reload_with_git_url_change(self, tmp_path: Path) -> None:
        """Recreates ConversationManager when git_repo_url changes."""
        svc = _make_service(tmp_path)
        handler = svc.repo_handlers["test"]
        old_config = handler.config
        # Apply new config with different git_repo_url
        handler.config = dataclasses.replace(
            handler.config,
            git_repo_url="https://github.com/test/other",
        )

        with (
            patch(
                "airut.gateway.service.gateway.create_adapters"
            ) as mock_create,
            patch("airut.gateway.conversation.ConversationManager") as mock_cm,
        ):
            mock_create.return_value = {"email": MagicMock()}
            svc._apply_single_repo_reload("test", old_config)

        mock_cm.assert_called_once()

    def test_reload_failure_triggers_rollback(self, tmp_path: Path) -> None:
        """Failed reload rolls back to old config."""
        svc = _make_service(tmp_path)

        with patch(
            "airut.gateway.service.gateway.create_adapters",
            side_effect=[RuntimeError("fail"), {"email": MagicMock()}],
        ):
            svc._apply_single_repo_reload("test")

        # Rollback succeeded — config should be original
        assert svc.repo_handlers["test"].config.model == "opus"

    def test_reload_failure_rollback_also_fails(self, tmp_path: Path) -> None:
        """Double failure does not crash the service."""
        svc = _make_service(tmp_path)

        with patch(
            "airut.gateway.service.gateway.create_adapters",
            side_effect=RuntimeError("always fail"),
        ):
            # Should not raise despite double failure
            svc._apply_single_repo_reload("test")

    def test_reload_missing_handler(self, tmp_path: Path) -> None:
        """Returns early if handler not found."""
        svc = _make_service(tmp_path)
        svc._apply_single_repo_reload("nonexistent")


class TestCheckPendingRepoReloadEdgeCases:
    """Edge cases for _check_pending_repo_reload."""

    def test_deferred_removal_applied(self, tmp_path: Path) -> None:
        """Deferred removal is applied when repo is idle."""
        repos = {
            "a": _make_email_config(repo_id="a"),
            "b": _make_email_config(repo_id="b"),
        }
        svc = _make_service(tmp_path, repos=repos)
        svc._pending_repo_reload["b"] = None

        # Remove "b" from config so the check sees it as removal
        new_config = dataclasses.replace(svc.config, repos={"a": repos["a"]})
        svc.config = new_config

        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=False,
        ):
            svc._check_pending_repo_reload("b")

        assert "b" not in svc.repo_handlers
        assert "b" not in svc._pending_repo_reload


class TestCheckPendingServerReloadEdgeCases:
    """Edge cases for _check_pending_server_reload."""

    def test_pending_messages_block_reload(self, tmp_path: Path) -> None:
        """Server reload is blocked when pending messages exist."""
        svc = _make_service(tmp_path)
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config, dashboard_port=9999
            ),
        )
        svc._pending_server_config = new_config

        with (
            patch.object(
                TaskTracker,
                "has_active_tasks_for_repo",
                return_value=False,
            ),
        ):
            import collections

            from airut.gateway.service.gateway import PendingMessage

            svc._pending_messages["test-conv"] = collections.deque(
                [MagicMock(spec=PendingMessage)]
            )
            svc._check_pending_server_reload()

        assert svc._pending_server_config is not None

    def test_apply_failure_logged(self, tmp_path: Path) -> None:
        """Exception in _apply_server_reload is caught."""
        svc = _make_service(tmp_path)
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config,
                max_concurrent_executions=10,
            ),
        )
        svc._pending_server_config = new_config

        with (
            patch.object(
                TaskTracker,
                "has_active_tasks_for_repo",
                return_value=False,
            ),
            patch.object(
                svc,
                "_apply_server_reload",
                side_effect=RuntimeError("fail"),
            ),
        ):
            svc._check_pending_server_reload()

        assert svc._pending_server_config is None


class TestApplyServerReload:
    """Tests for _apply_server_reload."""

    def test_dashboard_recreated(self, tmp_path: Path) -> None:
        """Dashboard is stopped and recreated on port change."""
        svc = _make_service(
            tmp_path, dashboard_enabled=True, dashboard_port=5200
        )
        mock_dashboard = MagicMock()
        svc.dashboard = mock_dashboard

        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config, dashboard_port=9999
            ),
        )
        with patch("airut.gateway.service.gateway.DashboardServer") as mock_ds:
            mock_ds.return_value = MagicMock()
            svc._apply_server_reload(new_config)

        mock_dashboard.stop.assert_called_once()
        mock_ds.assert_called_once()


class TestTryImmediateServerReload:
    """Tests for _try_immediate_server_reload."""

    def test_applies_when_idle(self, tmp_path: Path) -> None:
        """Server reload applied immediately when service is idle."""
        svc = _make_service(
            tmp_path, dashboard_enabled=True, dashboard_port=5200
        )
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config, dashboard_port=9999
            ),
        )
        svc._pending_server_config = new_config
        svc._pending_server_old_global = svc.global_config

        with (
            patch.object(svc, "_apply_server_reload") as mock_apply,
            patch.object(
                TaskTracker,
                "has_active_tasks_for_repo",
                return_value=False,
            ),
        ):
            svc._try_immediate_server_reload()

        mock_apply.assert_called_once_with(new_config, svc.global_config)
        assert svc._pending_server_config is None
        assert svc._pending_server_old_global is None

    def test_skips_when_active_tasks(self, tmp_path: Path) -> None:
        """No immediate reload when tasks are active."""
        svc = _make_service(tmp_path)
        svc._pending_server_config = svc.config

        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=True,
        ):
            svc._try_immediate_server_reload()

        assert svc._pending_server_config is not None

    def test_skips_when_pending_messages(self, tmp_path: Path) -> None:
        """No immediate reload when messages are pending."""
        import collections

        svc = _make_service(tmp_path)
        svc._pending_server_config = svc.config

        with (
            patch.object(
                TaskTracker,
                "has_active_tasks_for_repo",
                return_value=False,
            ),
            svc._pending_messages_lock,
        ):
            pass

        # Add pending messages outside the lock
        svc._pending_messages["conv"] = collections.deque([MagicMock()])

        with patch.object(
            TaskTracker,
            "has_active_tasks_for_repo",
            return_value=False,
        ):
            svc._try_immediate_server_reload()

        assert svc._pending_server_config is not None

    def test_noop_when_no_pending(self, tmp_path: Path) -> None:
        """No action when no pending server config."""
        svc = _make_service(tmp_path)
        assert svc._pending_server_config is None

        with patch.object(svc, "_apply_server_reload") as mock_apply:
            svc._try_immediate_server_reload()

        mock_apply.assert_not_called()

    def test_exception_logged_and_swallowed(self, tmp_path: Path) -> None:
        """Exception in _apply_server_reload is caught."""
        svc = _make_service(
            tmp_path, dashboard_enabled=True, dashboard_port=5200
        )
        new_config = dataclasses.replace(
            svc.config,
            global_config=dataclasses.replace(
                svc.config.global_config, dashboard_port=9999
            ),
        )
        svc._pending_server_config = new_config
        svc._pending_server_old_global = svc.global_config

        with (
            patch.object(
                svc,
                "_apply_server_reload",
                side_effect=RuntimeError("boom"),
            ),
            patch.object(
                TaskTracker,
                "has_active_tasks_for_repo",
                return_value=False,
            ),
        ):
            svc._try_immediate_server_reload()

        # Pending state cleared despite error
        assert svc._pending_server_config is None
