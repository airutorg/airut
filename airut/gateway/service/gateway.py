# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Main gateway service orchestrator.

This module contains:
- GatewayService: Main service class that orchestrates all components
- capture_version_info: Git version capture at startup
- main: CLI entry point
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import dataclasses
import logging
import signal
import threading
import time
import traceback
import types
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from importlib.resources import files
from pathlib import Path
from typing import Any

from airut.config.schema import Scope, get_field_meta
from airut.config.snapshot import ConfigSnapshot
from airut.config.source import ConfigSource, YamlConfigSource
from airut.config.watcher import ConfigFileWatcher
from airut.dashboard import (
    DashboardServer,
    TaskTracker,
    VersionInfo,
)
from airut.dashboard.tracker import (
    MAX_PENDING_PER_CONVERSATION,
    BootPhase,
    BootState,
    ChannelInfo,
    CompletionReason,
    RepoState,
    RepoStatus,
)
from airut.dashboard.versioned import VersionClock, VersionedStore
from airut.dns import get_system_resolver
from airut.gateway.channel import (
    AuthenticationError,
    ChannelAdapter,
    ParsedMessage,
    RawMessage,
)
from airut.gateway.config import (
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
    get_config_path,
)
from airut.gateway.dotenv_loader import reset_dotenv_state
from airut.gateway.service.adapter_factory import create_adapters
from airut.gateway.service.message_processing import (
    process_message,
)
from airut.gateway.service.repo_handler import RepoHandler
from airut.logging import configure_logging
from airut.sandbox import AgentTask, Sandbox, SandboxConfig
from airut.version import GitVersionInfo, get_git_version_info


logger = logging.getLogger(__name__)


def _build_channel_infos(
    config: RepoServerConfig,
) -> tuple[ChannelInfo, ...]:
    """Build a tuple of ChannelInfo from a repo config's channels.

    Args:
        config: Per-repo server configuration.

    Returns:
        Tuple of ChannelInfo for dashboard display.
    """
    return tuple(
        ChannelInfo(
            channel_type=channel_type,
            info=channel_config.channel_info,
        )
        for channel_type, channel_config in config.channels.items()
    )


@dataclass
class PendingMessage:
    """Authenticated message waiting for a busy conversation.

    Stored in the per-conversation pending queue. When the active task
    finishes, the next pending message is submitted for execution
    without re-authentication.
    """

    parsed: ParsedMessage
    task_id: str
    repo_handler: RepoHandler
    adapter: ChannelAdapter


def capture_version_info() -> tuple[VersionInfo, GitVersionInfo]:
    """Capture git version information at startup.

    Returns:
        Tuple of (VersionInfo for dashboard display,
        GitVersionInfo for upstream update checks).
    """
    git_version = get_git_version_info()

    version_info = VersionInfo(
        version=git_version.version,
        git_sha=git_version.sha_short,
        git_sha_full=git_version.sha_full,
        full_status=git_version.full_status,
        started_at=time.time(),
    )

    return version_info, git_version


class GatewayService:
    """Main gateway service orchestrator.

    Manages multiple RepoHandlers, shared executor pool, dashboard, and
    proxy manager.  Each repo has its own listener thread; all repos
    share the executor pool and global task limit.
    """

    def __init__(
        self,
        config: ServerConfig,
        repo_root: Path | None = None,
        egress_network: str | None = None,
        config_source: ConfigSource | None = None,
        config_snapshot: ConfigSnapshot[ServerConfig] | None = None,
    ) -> None:
        """Initialize service with configuration.

        Args:
            config: Complete server configuration.
            repo_root: Path to repository root. If None, auto-detected.
            egress_network: Override for proxy egress network name. If None,
                uses the default ``airut-egress``. Useful for tests to avoid
                conflicts when running in parallel.
            config_source: Config source for live reload. When None,
                the file watcher is not started and reload is disabled.
            config_snapshot: Initial ConfigSnapshot from loading. Stored
                for diffing on reload.
        """
        self._egress_network = egress_network
        self.config = config
        self.global_config = config.global_config
        self._running = True
        self._stopped = False

        # Config reload state
        self._config_source = config_source
        self._config_snapshot = config_snapshot
        self._reload_lock = threading.Lock()
        self._reload_requested = threading.Event()
        self._pending_repo_reload: dict[str, RepoServerConfig | None] = {}
        self._pending_server_config: ServerConfig | None = None
        self._pending_server_old_global: GlobalConfig | None = None
        self._config_generation = 0
        self._last_reload_error: str | None = None
        self._watcher: ConfigFileWatcher | None = None

        if repo_root is None:
            repo_root = Path(__file__).parent.parent.parent.parent
        self.repo_root = repo_root

        # Shared resources
        self._executor_pool: ThreadPoolExecutor | None = None
        self._pending_futures: set[Future[None]] = set()
        self._futures_lock = threading.Lock()

        # Shutdown event for interruptible sleeps in background threads
        self._shutdown_event = threading.Event()

        # Per-conversation locks to prevent parallel processing
        self._conversation_locks: dict[str, threading.Lock] = {}
        self._conversation_locks_lock = threading.Lock()

        # Per-conversation pending message queue.
        #
        # Lock ordering invariant (nested acquisition):
        #   _reload_lock → _pending_messages_lock → tracker._lock
        #
        # ``_pending_messages_lock`` and the tracker's internal
        # ``_lock`` must NEVER be held at the same time.  Code that
        # holds ``_pending_messages_lock`` may call tracker methods
        # (which briefly acquire/release ``_lock`` internally), but
        # no code path may acquire ``_pending_messages_lock`` while
        # the tracker ``_lock`` is already held.
        #
        # ``_reload_lock`` is non-blocking in ``_on_config_changed``
        # (concurrent watcher triggers are dropped) but blocking in
        # ``_check_pending_repo_reload`` (worker threads wait briefly
        # for any in-progress reload to finish).
        self._pending_messages: dict[
            str, collections.deque[PendingMessage]
        ] = {}
        self._pending_messages_lock = threading.Lock()

        # Conversation-to-repo mapping for O(1) stop-execution lookup
        self._conv_repo_map: dict[str, str] = {}

        # Active tasks for stop functionality
        self._active_tasks: dict[str, AgentTask] = {}
        self._active_tasks_lock = threading.Lock()

        # Dashboard components — versioned state
        self._clock = VersionClock()
        self.tracker = TaskTracker(clock=self._clock)
        self.dashboard: DashboardServer | None = None
        self._version_info, self._git_version_info = capture_version_info()
        self._boot_store = VersionedStore(BootState(), self._clock)
        self._repos_store = VersionedStore(
            tuple[RepoState, ...](()), self._clock
        )

        # Resolve upstream DNS: explicit config value or auto-detect from
        # /etc/resolv.conf.  SystemResolverError propagates to fail startup.
        upstream_dns = self.global_config.upstream_dns
        if upstream_dns is None:
            upstream_dns = get_system_resolver()

        # Sandbox (shared infrastructure, per-task execution)
        proxy_dir = files("airut._bundled.proxy")
        sandbox_config = SandboxConfig(
            container_command=self.global_config.container_command,
            proxy_dir=Path(str(proxy_dir)),
            upstream_dns=upstream_dns,
        )
        self.sandbox = Sandbox(
            sandbox_config,
            egress_network=self._egress_network,
        )

        # Initialize per-repo handlers (failures are recorded, not raised)
        self.repo_handlers: dict[str, RepoHandler] = {}
        self._init_errors: dict[
            str, tuple[str, str]
        ] = {}  # repo_id -> (type, msg)
        for repo_id, repo_config in config.repos.items():
            try:
                self.repo_handlers[repo_id] = RepoHandler(repo_config, self)
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                self._init_errors[repo_id] = (error_type, error_msg)
                logger.error(
                    "Repo '%s': failed to initialize: %s: %s",
                    repo_id,
                    error_type,
                    error_msg,
                )

        logger.info("Gateway service initialized")
        version_label = self._version_info.version or self._version_info.git_sha
        logger.info("Version: %s", version_label)
        logger.info(
            "Repos: %s",
            ", ".join(config.repos.keys()),
        )

    def start(self, resilient: bool = False) -> None:
        """Start the service.

        Starts dashboard immediately, then boots remaining components
        (proxy, repos, executor) while reporting progress on the dashboard.

        Args:
            resilient: If True, catch boot errors and stay running with the
                error displayed on the dashboard instead of crashing.
                Useful for systemd services to avoid restart loops.

        Raises:
            RuntimeError: If all repos fail to initialize (unless resilient).
        """
        logger.info("Starting gateway service...")

        # Start dashboard immediately so it's visible during boot
        self._start_dashboard_early()

        try:
            self._boot()
        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            error_tb = traceback.format_exc()
            boot = self._boot_store.get().value
            self._boot_store.update(
                replace(
                    boot,
                    phase=BootPhase.FAILED,
                    message=error_msg,
                    error_message=error_msg,
                    error_type=error_type,
                    error_traceback=error_tb,
                    completed_at=time.time(),
                )
            )
            logger.error("Boot failed: %s: %s", error_type, error_msg)

            if not resilient:
                if self.dashboard:
                    self.dashboard.stop()
                raise

            logger.info(
                "Resilient mode: staying alive with boot error on dashboard"
            )

        # If stop() was called during boot, any listeners started after
        # stop() iterated them would be orphaned.  Re-stop all listeners
        # to clean up the race window.
        if self._stopped:
            for repo_handler in self.repo_handlers.values():
                repo_handler.stop()
            if self._executor_pool:
                self._executor_pool.shutdown(wait=False)
            return

        # Block main thread until shutdown
        try:
            self._shutdown_event.wait()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")

    def _start_dashboard_early(self) -> None:
        """Start the dashboard server before boot completes.

        The dashboard receives the versioned stores so it always
        reflects the latest state without manual updates.
        """
        if not self.global_config.dashboard_enabled:
            return

        self.dashboard = DashboardServer(
            tracker=self.tracker,
            host=self.global_config.dashboard_host,
            port=self.global_config.dashboard_port,
            version_info=self._version_info,
            work_dirs=self._get_work_dirs,
            stop_callback=self._stop_execution,
            boot_store=self._boot_store,
            repos_store=self._repos_store,
            clock=self._clock,
            git_version_info=self._git_version_info,
            status_callback=self._get_reload_status,
            get_config_snapshot=lambda: self._config_snapshot,
            get_config_generation=lambda: self._config_generation,
            get_config_source=lambda: self._config_source,
        )
        self.dashboard.start()

    def _boot(self) -> None:
        """Execute the boot sequence.

        Updates boot state via VersionedStore as each phase completes. On
        failure, the caller is responsible for recording the error.

        Checks ``_shutdown_event`` between phases so that a concurrent
        ``stop()`` call aborts the boot without starting new listeners
        (which would be orphaned since ``stop()`` already ran).

        Raises:
            RuntimeError: If all repos fail to initialize.
        """
        # Phase: proxy
        boot = self._boot_store.get().value
        self._boot_store.update(
            replace(
                boot,
                phase=BootPhase.PROXY,
                message="Building proxy image and creating network...",
            )
        )
        self.sandbox.startup()

        if self._shutdown_event.is_set():
            logger.info(
                "Shutdown requested during boot (proxy phase), aborting"
            )
            return

        # Initialize shared thread pool
        self._executor_pool = ThreadPoolExecutor(
            max_workers=self.global_config.max_concurrent_executions,
            thread_name_prefix="ClaudeWorker",
        )
        logger.info(
            "Started execution pool with %d workers",
            self.global_config.max_concurrent_executions,
        )

        # Start garbage collector thread
        gc_thread = threading.Thread(
            target=self._garbage_collector_thread,
            daemon=True,
            name="GarbageCollector",
        )
        gc_thread.start()

        # Phase: repos
        boot = self._boot_store.get().value
        self._boot_store.update(
            replace(
                boot,
                phase=BootPhase.REPOS,
                message="Starting repository listeners...",
            )
        )

        # Record repos that failed during __init__ (git mirror, etc.)
        repo_states: dict[str, RepoState] = {}
        for repo_id, (error_type, error_msg) in self._init_errors.items():
            repo_config = self.config.repos[repo_id]
            repo_states[repo_id] = RepoState(
                repo_id=repo_id,
                status=RepoStatus.FAILED,
                error_message=error_msg,
                error_type=error_type,
                git_repo_url=repo_config.git_repo_url,
                channels=_build_channel_infos(repo_config),
                storage_dir=str(repo_config.storage_dir),
            )

        # Start all repo listeners, tracking success/failure
        started_count = 0
        for repo_id, repo_handler in self.repo_handlers.items():
            if self._shutdown_event.is_set():
                logger.info(
                    "Shutdown requested during boot (listener loop), aborting"
                )
                break

            config = repo_handler.config
            boot = self._boot_store.get().value
            self._boot_store.update(
                replace(
                    boot,
                    message=f"Starting repository '{repo_id}'...",
                )
            )
            try:
                repo_handler.start_listener()
                started_count += 1
                repo_states[repo_id] = RepoState(
                    repo_id=repo_id,
                    status=RepoStatus.LIVE,
                    git_repo_url=config.git_repo_url,
                    channels=_build_channel_infos(config),
                    storage_dir=str(config.storage_dir),
                )
                logger.info("Repo '%s': started successfully", repo_id)
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                repo_states[repo_id] = RepoState(
                    repo_id=repo_id,
                    status=RepoStatus.FAILED,
                    error_message=error_msg,
                    error_type=error_type,
                    git_repo_url=config.git_repo_url,
                    channels=_build_channel_infos(config),
                    storage_dir=str(config.storage_dir),
                )
                logger.error(
                    "Repo '%s': failed to start: %s: %s",
                    repo_id,
                    error_type,
                    error_msg,
                )

        # Publish all repo states atomically
        self._repos_store.update(tuple(repo_states.values()))

        # Check if any repos started successfully
        live_repos = [
            r for r in repo_states.values() if r.status == RepoStatus.LIVE
        ]
        failed_repos = [
            r for r in repo_states.values() if r.status == RepoStatus.FAILED
        ]

        if not live_repos:
            raise RuntimeError(
                f"All {len(failed_repos)} repo(s) failed to initialize. "
                "Check credentials, network connectivity, and configuration."
            )

        if failed_repos:
            logger.warning(
                "Service started with %d of %d repo(s) failed: %s",
                len(failed_repos),
                len(repo_states),
                ", ".join(r.repo_id for r in failed_repos),
            )

        # Phase: ready
        boot = self._boot_store.get().value
        self._boot_store.update(
            replace(
                boot,
                phase=BootPhase.READY,
                message="Service ready",
                completed_at=time.time(),
            )
        )
        logger.info(
            "Service ready. %d repo listener(s) running.",
            started_count,
        )

        # Start config file watcher after boot completes
        self._start_config_watcher()

    def _start_config_watcher(self) -> None:
        """Start config file watcher if a file-based source is available."""
        if self._config_source is None:
            return

        if not isinstance(self._config_source, YamlConfigSource):
            return

        config_path = self._config_source.path
        self._watcher = ConfigFileWatcher(
            config_path,
            self._on_config_changed,
            reload_requested=self._reload_requested,
        )
        self._watcher.start()

    def _get_work_dirs(self) -> list[Path]:
        """Return current work dirs for the dashboard.

        Called by the dashboard on each request to get fresh state.
        Only includes directories for repos that started successfully.

        Returns:
            List of work directories for live repos.
        """
        repo_states = self._repos_store.get().value
        live_repo_ids = {
            r.repo_id for r in repo_states if r.status == RepoStatus.LIVE
        }
        return [
            repo.conversation_manager.conversations_dir
            for repo_id, repo in self.repo_handlers.items()
            if repo_id in live_repo_ids
        ]

    def stop(self) -> None:
        """Stop the service gracefully."""
        if self._stopped:
            return
        self._stopped = True

        logger.info("Stopping gateway service...")
        self._running = False
        self._shutdown_event.set()

        # Stop config watcher before listeners
        if self._watcher:
            self._watcher.stop()

        # Shutdown sandbox
        self.sandbox.shutdown()

        # Interrupt all listeners
        for repo_handler in self.repo_handlers.values():
            repo_handler.stop()

        # Shutdown thread pool with timeout
        if self._executor_pool:
            with self._futures_lock:
                pending_count = len(self._pending_futures)
                futures_copy = set(self._pending_futures)

            if pending_count > 0:
                logger.info(
                    "Waiting for %d pending executions (timeout: %ds)...",
                    pending_count,
                    self.global_config.shutdown_timeout_seconds,
                )

                done, not_done = concurrent.futures.wait(
                    futures_copy,
                    timeout=self.global_config.shutdown_timeout_seconds,
                )

                if not_done:
                    logger.warning(
                        "%d executions did not complete within timeout",
                        len(not_done),
                    )
                    for future in not_done:
                        future.cancel()

            self._executor_pool.shutdown(wait=False)
            logger.info("Execution pool shut down")

        # Stop dashboard server
        if self.dashboard:
            self.dashboard.stop()

        logger.info("Service stopped")

    # ------------------------------------------------------------------ #
    # Config Reload
    # ------------------------------------------------------------------ #

    def _get_reload_status(self) -> dict[str, object]:
        """Return config reload status for the dashboard API."""
        return {
            "config_generation": self._config_generation,
            "server_reload_pending": self._pending_server_config is not None,
            "last_reload_error": self._last_reload_error,
        }

    def _on_config_changed(self) -> None:
        """Handle config file change (inotify or SIGHUP).

        Serialized: concurrent calls are dropped (only one reload runs
        at a time).

        Lock ordering:
        ``_reload_lock`` → ``_pending_messages_lock`` → ``tracker._lock``
        """
        if self._config_source is None:
            return

        if not self._reload_lock.acquire(blocking=False):
            return  # another reload is in progress

        try:
            # 1. Re-read and parse
            reset_dotenv_state()
            new_snapshot = ServerConfig.from_source(self._config_source)
            new_config = new_snapshot.value

            # 2. Diff: global_config and per-repo
            global_changed = self._diff_global(new_config)
            repo_changes = self._diff_repos(new_config)

            if not global_changed and not repo_changes:
                logger.debug("Config reload: no effective changes")
                self._last_reload_error = None
                return

            # 3. Log changes
            self._log_config_diff(global_changed, repo_changes)

            # 4. Apply by scope — save old repo configs before task-scope
            #    swap so repo-scope reload can detect git_repo_url changes.
            old_repo_configs = {
                rid: h.config for rid, h in self.repo_handlers.items()
            }
            self._apply_task_scope(new_config)
            self._apply_repo_scope(new_config, repo_changes, old_repo_configs)
            self._apply_server_scope(new_config, global_changed)

            # 4b. Try immediate server reload if service is idle
            self._try_immediate_server_reload()

            # 5. Update stored snapshot
            self._config_snapshot = new_snapshot
            self.config = new_config
            self.global_config = new_config.global_config
            self._config_generation += 1
            self._last_reload_error = None

            logger.info(
                "Config reload successful (generation=%d)",
                self._config_generation,
            )

        except Exception:
            logger.exception("Config reload failed, keeping current config")
            self._last_reload_error = traceback.format_exc()
        finally:
            self._reload_lock.release()

    def _diff_global(self, new_config: ServerConfig) -> bool:
        """Return True if any GlobalConfig field changed."""
        return self.config.global_config != new_config.global_config

    def _diff_repos(self, new_config: ServerConfig) -> dict[str, str]:
        """Return {repo_id: change_type} for repos that changed.

        change_type is one of: "task", "repo", "added", "removed".
        "task" means only task-scope fields changed (swap suffices).
        "repo" means at least one repo-scope field changed (listener
        restart required).
        """
        result: dict[str, str] = {}
        old_repos = self.config.repos
        new_repos = new_config.repos

        for repo_id in new_repos.keys() - old_repos.keys():
            result[repo_id] = "added"
        for repo_id in old_repos.keys() - new_repos.keys():
            result[repo_id] = "removed"

        for repo_id in old_repos.keys() & new_repos.keys():
            old_cfg = old_repos[repo_id]
            new_cfg = new_repos[repo_id]
            if old_cfg == new_cfg:
                continue
            has_repo_scope = False
            for f in dataclasses.fields(old_cfg):
                fm = get_field_meta(f)
                if fm and fm.scope == Scope.REPO:
                    if getattr(old_cfg, f.name) != getattr(new_cfg, f.name):
                        has_repo_scope = True
                        break
            result[repo_id] = "repo" if has_repo_scope else "task"

        return result

    def _log_config_diff(
        self,
        global_changed: bool,
        repo_changes: dict[str, str],
    ) -> None:
        """Log config changes at INFO level."""
        parts: list[str] = []
        if global_changed:
            parts.append("global config changed")
        for repo_id, change_type in repo_changes.items():
            parts.append(f"repo '{repo_id}': {change_type}")
        logger.info("Config reload: %s", "; ".join(parts))

    def _apply_task_scope(self, new_config: ServerConfig) -> None:
        """Swap repo configs for task-scope changes (atomic)."""
        for repo_id, new_repo_cfg in new_config.repos.items():
            handler = self.repo_handlers.get(repo_id)
            if handler:
                handler.config = new_repo_cfg

    def _apply_repo_scope(
        self,
        new_config: ServerConfig,
        repo_changes: dict[str, str],
        old_repo_configs: dict[str, RepoServerConfig] | None = None,
    ) -> None:
        """Handle repo-scope changes: restart listeners or defer."""
        for repo_id, change_type in repo_changes.items():
            if change_type == "added":
                self._add_repo(repo_id, new_config.repos[repo_id])
            elif change_type == "removed":
                self._remove_repo(repo_id)
            elif change_type == "repo":
                if self.tracker.has_active_tasks_for_repo(repo_id):
                    old_cfg = (
                        old_repo_configs.get(repo_id)
                        if old_repo_configs
                        else None
                    )
                    self._pending_repo_reload[repo_id] = old_cfg
                    self._set_repo_status(repo_id, RepoStatus.RELOAD_PENDING)
                    logger.info(
                        "Repo '%s': reload deferred (active tasks)",
                        repo_id,
                    )
                else:
                    old_cfg = (
                        old_repo_configs.get(repo_id)
                        if old_repo_configs
                        else None
                    )
                    self._apply_single_repo_reload(repo_id, old_cfg)

    def _apply_server_scope(
        self,
        new_config: ServerConfig,
        global_changed: bool,
    ) -> None:
        """Handle server-scope changes: defer until globally idle."""
        if not global_changed:
            return
        # Preserve the first baseline when successive reloads arrive
        if self._pending_server_config is None:
            self._pending_server_old_global = self.global_config
        self._pending_server_config = new_config
        logger.info(
            "Server-scope config change detected, "
            "deferring until service is idle"
        )

    def _try_immediate_server_reload(self) -> None:
        """Try to apply pending server reload if the service is idle.

        Called from ``_on_config_changed()`` while ``_reload_lock`` is
        already held.  Applies the server-scope reload immediately when
        no tasks are active and no messages are pending — avoids the
        need for a subsequent task completion to trigger the check.
        """
        if self._pending_server_config is None:
            return

        for rid in list(self.repo_handlers):
            if self.tracker.has_active_tasks_for_repo(rid):
                return

        with self._pending_messages_lock:
            if self._pending_messages:
                return

        pending = self._pending_server_config
        old_global = self._pending_server_old_global
        self._pending_server_config = None
        self._pending_server_old_global = None

        try:
            self._apply_server_reload(pending, old_global)
        except Exception:
            logger.exception(
                "Immediate server-scope reload failed, keeping current config"
            )

    def _add_repo(self, repo_id: str, repo_config: RepoServerConfig) -> None:
        """Add a new repo handler and start its listeners."""
        try:
            handler = RepoHandler(repo_config, self)
            handler.start_listener()
            self.repo_handlers[repo_id] = handler

            repo_state = RepoState(
                repo_id=repo_id,
                status=RepoStatus.LIVE,
                git_repo_url=repo_config.git_repo_url,
                channels=_build_channel_infos(repo_config),
                storage_dir=str(repo_config.storage_dir),
            )
            self._update_repos_store_entry(repo_id, repo_state)
            logger.info("Repo '%s': added and started", repo_id)
        except Exception:
            logger.exception("Repo '%s': failed to add on reload", repo_id)

    def _remove_repo(self, repo_id: str) -> None:
        """Remove a repo, deferring if it has active tasks.

        Stops listeners immediately to prevent new messages, but keeps
        the handler until active tasks drain.
        """
        handler = self.repo_handlers.get(repo_id)
        if self.tracker.has_active_tasks_for_repo(repo_id):
            if handler:
                handler.stop()
            self._pending_repo_reload[repo_id] = None
            self._set_repo_status(repo_id, RepoStatus.RELOAD_PENDING)
            logger.info("Repo '%s': removal deferred (active tasks)", repo_id)
            return

        handler = self.repo_handlers.pop(repo_id, None)
        if handler:
            handler.stop()
        self._remove_repos_store_entry(repo_id)
        logger.info("Repo '%s': removed", repo_id)

    def _apply_single_repo_reload(
        self,
        repo_id: str,
        old_config: RepoServerConfig | None = None,
    ) -> None:
        """Restart a single repo's listeners with new config."""
        handler = self.repo_handlers.get(repo_id)
        if not handler:
            return

        if old_config is None:
            old_config = handler.config
        self._set_repo_status(repo_id, RepoStatus.RELOADING)

        try:
            handler.stop()
            handler.adapters = create_adapters(handler.config)

            if handler.config.git_repo_url != old_config.git_repo_url:
                from airut.gateway.conversation import (
                    ConversationManager,
                )

                handler.conversation_manager = ConversationManager(
                    repo_url=handler.config.git_repo_url,
                    storage_dir=handler.config.storage_dir,
                )

            handler.start_listener()
            self._set_repo_status(repo_id, RepoStatus.LIVE)
            logger.info("Repo '%s': reload complete", repo_id)
        except Exception:
            logger.exception(
                "Repo '%s': reload failed, reverting config", repo_id
            )
            # Attempt rollback.  Note: self.config.repos still has the
            # new config; the next reload will detect the mismatch and
            # retry the repo-scope reload.
            handler.config = old_config
            try:
                handler.adapters = create_adapters(old_config)
                handler.start_listener()
                self._set_repo_status(repo_id, RepoStatus.LIVE)
            except Exception:
                logger.exception("Repo '%s': rollback also failed", repo_id)
                self._set_repo_status(repo_id, RepoStatus.FAILED)

    def _check_pending_repo_reload(self, repo_id: str) -> None:
        """Check and apply pending repo reload after task completion.

        All checks are performed under ``_reload_lock`` to prevent a
        TOCTOU race where a new task starts between the idle check and
        the reload application.
        """
        with self._reload_lock:
            if repo_id not in self._pending_repo_reload:
                return
            if self.tracker.has_active_tasks_for_repo(repo_id):
                return  # still busy

            old_cfg = self._pending_repo_reload.pop(repo_id)

            if repo_id not in self.config.repos:
                handler = self.repo_handlers.pop(repo_id, None)
                if handler:
                    handler.stop()
                self._remove_repos_store_entry(repo_id)
                logger.info("Repo '%s': deferred removal applied", repo_id)
            else:
                self._apply_single_repo_reload(repo_id, old_cfg)

    def _check_pending_server_reload(self) -> None:
        """Check and apply pending server reload when globally idle.

        All checks are performed under ``_reload_lock`` to prevent a
        TOCTOU race where a new task starts between the idle check and
        the reload application.
        """
        with self._reload_lock:
            pending = self._pending_server_config
            if pending is None:
                return

            # Check if any repo has active tasks (snapshot keys to
            # avoid RuntimeError from concurrent dict modification).
            for repo_id in list(self.repo_handlers):
                if self.tracker.has_active_tasks_for_repo(repo_id):
                    return  # still busy

            # Also check that no pending messages are queued
            with self._pending_messages_lock:
                if self._pending_messages:
                    return

            old_global = self._pending_server_old_global
            self._pending_server_config = None
            self._pending_server_old_global = None

            try:
                self._apply_server_reload(pending, old_global)
            except Exception:
                logger.exception(
                    "Server-scope reload failed, keeping current config"
                )

    def _apply_server_reload(
        self,
        new_config: ServerConfig,
        old_global: GlobalConfig | None = None,
    ) -> None:
        """Apply server-scope config changes.

        Recreates thread pool, dashboard, or sandbox as needed.

        Args:
            new_config: New server config to apply.
            old_global: Global config snapshot from when the change was
                detected.  Falls back to ``self.global_config`` if not
                provided (for tests).
        """
        if old_global is None:
            old_global = self.global_config
        new_global = new_config.global_config

        # Thread pool
        if (
            old_global.max_concurrent_executions
            != new_global.max_concurrent_executions
        ):
            if self._executor_pool:
                self._executor_pool.shutdown(wait=False)
            self._executor_pool = ThreadPoolExecutor(
                max_workers=new_global.max_concurrent_executions,
                thread_name_prefix="ClaudeWorker",
            )
            logger.info(
                "Recreated execution pool with %d workers",
                new_global.max_concurrent_executions,
            )

        # Dashboard
        dashboard_changed = (
            old_global.dashboard_enabled != new_global.dashboard_enabled
            or old_global.dashboard_host != new_global.dashboard_host
            or old_global.dashboard_port != new_global.dashboard_port
            or old_global.dashboard_base_url != new_global.dashboard_base_url
        )
        if dashboard_changed:
            if self.dashboard:
                self.dashboard.stop()
                self.dashboard = None
            self.global_config = new_global
            self._start_dashboard_early()

        # Note: container_command, upstream_dns, and resource_limits
        # (global default) require a service restart to apply.  These
        # fields are detected as changed but take effect on next
        # restart.  Sandbox recreation is deferred to a future release.
        #
        # conversation_max_age_days and image_prune are re-read by the
        # GC thread each iteration, so they take effect on reload.
        # shutdown_timeout_seconds is read at shutdown time from
        # self.global_config, so it also takes effect on reload.

        logger.info("Server-scope reload applied")

    def _set_repo_status(self, repo_id: str, status: RepoStatus) -> None:
        """Update a single repo's status in the repos store.

        Read-modify-write on VersionedStore; callers must hold
        ``_reload_lock`` for synchronization (except during boot).
        """
        current = self._repos_store.get().value
        updated = tuple(
            replace(r, status=status) if r.repo_id == repo_id else r
            for r in current
        )
        self._repos_store.update(updated)

    def _update_repos_store_entry(
        self, repo_id: str, new_state: RepoState
    ) -> None:
        """Add or replace a repo entry in the repos store."""
        current = self._repos_store.get().value
        entries = [r for r in current if r.repo_id != repo_id]
        entries.append(new_state)
        self._repos_store.update(tuple(entries))

    def _remove_repos_store_entry(self, repo_id: str) -> None:
        """Remove a repo entry from the repos store."""
        current = self._repos_store.get().value
        updated = tuple(r for r in current if r.repo_id != repo_id)
        self._repos_store.update(updated)

    def register_active_task(
        self, conversation_id: str, task: AgentTask
    ) -> None:
        """Register an active task for stop functionality.

        The dashboard stop button works by conversation ID, so active
        tasks are keyed by ``conversation_id``.

        Args:
            conversation_id: Conversation this task belongs to.
            task: Active sandbox AgentTask.
        """
        with self._active_tasks_lock:
            self._active_tasks[conversation_id] = task

    def unregister_active_task(self, conversation_id: str) -> None:
        """Unregister a completed task.

        Args:
            conversation_id: Conversation whose active task finished.
        """
        with self._active_tasks_lock:
            self._active_tasks.pop(conversation_id, None)

    def _stop_execution(self, conversation_id: str) -> bool:
        """Stop a running execution by conversation ID.

        Args:
            conversation_id: Conversation ID to stop.

        Returns:
            True if stopped, False if not found.
        """
        with self._active_tasks_lock:
            task = self._active_tasks.get(conversation_id)
        if task is not None:
            return task.stop()
        logger.warning(
            "No active task found for conversation %s", conversation_id
        )
        return False

    def submit_message(
        self,
        raw_message: RawMessage[Any],
        repo_handler: RepoHandler,
        adapter: ChannelAdapter,
    ) -> bool:
        """Submit a raw message for authentication and processing.

        Called by RepoHandlers when they receive a new message.
        Authentication and parsing happen in the worker thread.

        Args:
            raw_message: Channel-agnostic raw message envelope.
            repo_handler: The repo handler that received this message.
            adapter: The originating channel adapter.

        Returns:
            True if message was submitted, False if pool not ready.
        """
        if not self._executor_pool:
            logger.error("Executor pool not initialized")
            return False

        task_id = uuid.uuid4().hex[:12]
        repo_id = repo_handler.config.repo_id
        # Use display_title from RawMessage for immediate tracker display;
        # falls back to truncated sender, then to a placeholder.
        initial_title = (
            raw_message.display_title
            or raw_message.sender[:40]
            or "(authenticating)"
        )
        self.tracker.add_task(
            task_id,
            initial_title,
            repo_id=repo_id,
        )

        future = self._executor_pool.submit(
            self._process_message_worker,
            raw_message,
            task_id,
            repo_handler,
            adapter,
        )

        with self._futures_lock:
            self._pending_futures.add(future)

        future.add_done_callback(self._on_future_complete)
        return True

    def _on_future_complete(self, future: Future[None]) -> None:
        """Callback when a future completes."""
        with self._futures_lock:
            self._pending_futures.discard(future)

        try:
            exception = future.exception()
            if exception:
                logger.error("Message processing failed: %s", exception)
        except concurrent.futures.CancelledError:
            logger.debug("Message processing was cancelled")

    def _get_conversation_lock(self, conv_id: str) -> threading.Lock:
        """Get or create a lock for a conversation."""
        with self._conversation_locks_lock:
            if conv_id not in self._conversation_locks:
                self._conversation_locks[conv_id] = threading.Lock()
            return self._conversation_locks[conv_id]

    def _process_message_worker(
        self,
        raw_message: RawMessage[Any],
        task_id: str,
        repo_handler: RepoHandler,
        adapter: ChannelAdapter,
    ) -> None:
        """Worker thread entry point for message processing."""
        self.tracker.set_authenticating(task_id)

        reason = CompletionReason.INTERNAL_ERROR
        detail = ""
        conv_id: str | None = None
        completed_elsewhere = False
        try:
            # Authenticate and parse through the channel adapter.
            # AuthenticationError carries sender/reason for dashboard.
            parsed = adapter.authenticate_and_parse(raw_message)

            # Update task title from "(authenticating)" to real title.
            # parsed.sender is the verified identity returned by
            # authenticate_and_parse (e.g., DMARC-verified email),
            # so it is safe to use as authenticated_sender.
            self.tracker.update_task_display_title(
                task_id,
                parsed.display_title or "(no subject)",
                sender=parsed.sender,
                authenticated_sender=parsed.sender,
            )

            conv_id = parsed.conversation_id

            # Queue messages for conversations that already have an
            # active task instead of rejecting them outright.
            #
            # The has_active_task check, set_conversation_id, depth-
            # check, and enqueue are ALL done under
            # _pending_messages_lock to prevent a TOCTOU race where the
            # active task completes (and drains) between the check and
            # the append — which would leave the message PENDING forever
            # with nothing to drain it.
            if conv_id:
                with self._pending_messages_lock:
                    if not self.tracker.has_active_task(conv_id):
                        # No active task — fall through to normal
                        # execution below (outside the lock).
                        pass
                    else:
                        # Set conversation_id on the task so the
                        # pending task shows the correct conversation
                        # in the dashboard.
                        self.tracker.set_conversation_id(task_id, conv_id)

                        queue = self._pending_messages.get(conv_id)
                        queue_len = len(queue) if queue else 0

                        if queue_len >= MAX_PENDING_PER_CONVERSATION:
                            logger.warning(
                                "Rejecting message for conversation %s "
                                "- queue full (%d pending)",
                                conv_id,
                                queue_len,
                            )
                            reject_reason = (
                                "Too many messages queued for this "
                                "conversation. Please wait for current "
                                "tasks to complete before sending another "
                                "message."
                            )
                            adapter.send_rejection(
                                parsed,
                                conv_id,
                                reject_reason,
                                self.global_config.dashboard_base_url,
                            )
                            reason = CompletionReason.REJECTED
                            detail = "queue full"
                            return

                        # Enqueue and free the worker thread.
                        pending = PendingMessage(
                            parsed=parsed,
                            task_id=task_id,
                            repo_handler=repo_handler,
                            adapter=adapter,
                        )
                        if conv_id not in self._pending_messages:
                            self._pending_messages[conv_id] = (
                                collections.deque()
                            )
                        self._pending_messages[conv_id].append(pending)

                        self.tracker.set_pending(task_id)
                        logger.info(
                            "Queued message for busy conversation %s "
                            "(queue depth: %d)",
                            conv_id,
                            queue_len + 1,
                        )

                        # Mark as queued so the finally block skips
                        # completion.  Task stays PENDING until
                        # _drain_pending picks it up.
                        completed_elsewhere = True
                        return

            # Assign conversation_id to the task for dashboard display.
            if conv_id:
                self.tracker.set_conversation_id(task_id, conv_id)

            # Delegate execution, completion, and drain to the shared
            # helper (also used by _process_pending_message).
            # Handles its own complete_task + _drain_pending.
            self._execute_and_complete(parsed, task_id, repo_handler, adapter)
            # Signal the finally block to skip duplicate completion.
            completed_elsewhere = True
            return
        except AuthenticationError as auth_err:
            self.tracker.update_task_display_title(
                task_id,
                "(not authorized)",
                sender=auth_err.sender,
            )
            if auth_err.reason == "sender not authorized":
                reason = CompletionReason.UNAUTHORIZED
            else:
                reason = CompletionReason.AUTH_FAILED
            detail = auth_err.reason
        except Exception:
            logger.exception("Error processing message (task %s)", task_id)
            reason = CompletionReason.INTERNAL_ERROR
        finally:
            if not completed_elsewhere:
                # complete_task acquires/releases the tracker lock;
                # only then does _drain_pending acquire
                # _pending_messages_lock.  This ordering is
                # load-bearing — see the invariant comment on
                # _pending_messages_lock above.
                self.tracker.complete_task(task_id, reason, detail)
                # Drain any pending messages for this conversation.
                # conv_id is set after authentication; for auth
                # failures or new conversations without a conv_id,
                # drain is a no-op (no pending messages exist).
                if conv_id:
                    self._drain_pending(conv_id)

    def _drain_pending(self, conv_id: str) -> None:
        """Submit the next queued message for a conversation, if any.

        Called after a task completes to pick up the next pending
        message. The pending message has already been authenticated,
        so it skips straight to execution.

        Args:
            conv_id: Conversation ID to drain.
        """
        with self._pending_messages_lock:
            queue = self._pending_messages.get(conv_id)
            if not queue:
                return
            pending = queue.popleft()
            if not queue:
                del self._pending_messages[conv_id]

        if not self._executor_pool:
            logger.error(
                "Cannot drain pending message for %s: pool not initialized",
                conv_id,
            )
            self.tracker.complete_task(
                pending.task_id,
                CompletionReason.INTERNAL_ERROR,
                "executor pool shut down",
            )
            return

        logger.info(
            "Draining pending message for conversation %s (task %s)",
            conv_id,
            pending.task_id,
        )
        future = self._executor_pool.submit(
            self._process_pending_message,
            pending,
        )
        with self._futures_lock:
            self._pending_futures.add(future)
        future.add_done_callback(self._on_future_complete)

    def _execute_and_complete(
        self,
        parsed: ParsedMessage,
        task_id: str,
        repo_handler: RepoHandler,
        adapter: ChannelAdapter,
    ) -> None:
        """Execute a message and complete the tracker task.

        Shared by both ``_process_message_worker`` (first-time execution)
        and ``_process_pending_message`` (drain from pending queue).
        Acquires the conversation lock for existing conversations,
        completes the task, then drains any further pending messages.

        Args:
            parsed: Authenticated and parsed message.
            task_id: Stable tracker task ID.
            repo_handler: Repository handler for this message.
            adapter: Channel adapter that produced the parsed message.
        """
        conv_id = parsed.conversation_id
        reason = CompletionReason.INTERNAL_ERROR
        detail = ""
        # Track the final conversation ID for draining.  process_message
        # may create a new conversation and return a new conv_id.
        drain_conv_id = conv_id

        try:
            self.tracker.set_executing(task_id)

            if conv_id and repo_handler.conversation_manager.exists(conv_id):
                lock = self._get_conversation_lock(conv_id)
                with lock:
                    reason, final_conv_id = process_message(
                        self, parsed, task_id, repo_handler, adapter
                    )
                    if final_conv_id:
                        drain_conv_id = final_conv_id
            else:
                reason, final_conv_id = process_message(
                    self, parsed, task_id, repo_handler, adapter
                )
                if final_conv_id:
                    drain_conv_id = final_conv_id
        except Exception:
            logger.exception("Error processing message (task %s)", task_id)
            reason = CompletionReason.INTERNAL_ERROR
        finally:
            # complete_task acquires/releases the tracker lock; only
            # then does _drain_pending acquire _pending_messages_lock.
            # This ordering is load-bearing — see the invariant comment
            # on _pending_messages_lock above.
            self.tracker.complete_task(task_id, reason, detail)
            # Drain any pending messages for this conversation.
            if drain_conv_id:
                self._drain_pending(drain_conv_id)

            # Check for deferred config reloads
            repo_id = repo_handler.config.repo_id
            self._check_pending_repo_reload(repo_id)
            self._check_pending_server_reload()

    def _process_pending_message(self, pending: PendingMessage) -> None:
        """Execute a previously-authenticated pending message.

        Skips authentication (already done when the message was queued)
        and goes directly to execution.

        Args:
            pending: The pending message to process.
        """
        self._execute_and_complete(
            pending.parsed,
            pending.task_id,
            pending.repo_handler,
            pending.adapter,
        )

    # Initial delay before first GC pass (seconds).  Short enough to
    # ensure GC runs even if the server restarts frequently, long enough
    # for boot to complete.
    GC_INITIAL_DELAY: int = 60
    GC_INTERVAL: int = 24 * 60 * 60  # 24 hours

    def _garbage_collector_thread(self) -> None:
        """Background housekeeping thread.

        Runs after a short initial delay, then every 24 hours.
        Prunes old conversations and (optionally) dangling container
        images.

        Config values (``conversation_max_age_days``, ``image_prune``)
        are re-read from ``self.global_config`` each iteration so that
        config reloads take effect without restarting the service.

        The initial delay ensures GC runs even when the server restarts
        frequently (previously, the full 24h wait before the first pass
        meant frequent restarts would skip GC entirely).
        """
        logger.info(
            "Garbage collector started "
            "(initial_delay: %ds, interval: %ds, max_age: %d days, "
            "image_prune: %s)",
            self.GC_INITIAL_DELAY,
            self.GC_INTERVAL,
            self.global_config.conversation_max_age_days,
            self.global_config.image_prune,
        )

        # Wait for boot to finish before first pass.
        if self._shutdown_event.wait(timeout=self.GC_INITIAL_DELAY):
            return  # Shutdown signaled during initial delay

        while self._running:
            # Re-read config each iteration so reloads take effect.
            gc_config = self.global_config
            max_age_days = gc_config.conversation_max_age_days
            image_prune = gc_config.image_prune

            try:
                self._gc_conversations(max_age_days)
            except Exception as e:
                logger.exception(
                    "Error in conversation garbage collection: %s", e
                )

            if image_prune:
                try:
                    self._gc_images()
                except Exception as e:
                    logger.exception("Error in image pruning: %s", e)

            if self._shutdown_event.wait(timeout=self.GC_INTERVAL):
                break  # Shutdown signaled

    def _gc_conversations(self, max_age_days: int) -> None:
        """Remove conversations older than *max_age_days*.

        Snapshots ``repo_handlers`` and each handler's ``adapters``
        before iterating to avoid ``RuntimeError`` from concurrent
        dict modification during config reload.
        """
        logger.info("Running conversation garbage collection...")
        total_removed = 0

        for repo_id, handler in list(self.repo_handlers.items()):
            conv_mgr = handler.conversation_manager
            conversations = conv_mgr.list_all()

            for conv_id in conversations:
                conv_path = conv_mgr.get_workspace_path(conv_id)

                if conv_path.exists():
                    mtime = conv_path.stat().st_mtime
                    age_days = (time.time() - mtime) / (24 * 60 * 60)

                    if age_days > max_age_days:
                        logger.info(
                            "Repo '%s': removing conversation %s "
                            "(age: %.1f days)",
                            repo_id,
                            conv_id,
                            age_days,
                        )
                        conv_mgr.delete(conv_id)
                        total_removed += 1

            # Notify adapters so they can prune stale state
            # (e.g. Slack thread-to-conversation mappings).
            # Snapshot adapters to avoid races with config reload
            # replacing handler.adapters concurrently.
            remaining = set(conv_mgr.list_all())
            for adapter in list(handler.adapters.values()):
                try:
                    adapter.cleanup_conversations(remaining)
                except Exception as e:
                    logger.warning(
                        "Adapter cleanup failed for repo '%s': %s",
                        repo_id,
                        e,
                    )

        if total_removed > 0:
            logger.info(
                "Garbage collection complete. Removed %d conversations",
                total_removed,
            )
        else:
            logger.debug(
                "Garbage collection complete. No conversations removed"
            )

    def _gc_images(self) -> None:
        """Prune dangling and old container images.

        Delegates to ``Sandbox.prune_images()`` which runs
        ``podman image prune -f`` and removes stale airut-prefixed
        images.  Does not hold the image build lock, so concurrent
        task startups are not blocked.
        """
        logger.info("Running container image pruning...")
        removed = self.sandbox.prune_images()
        if removed > 0:
            logger.info("Image pruning complete. Removed %d images", removed)
        else:
            logger.debug("Image pruning complete. No images removed")


def main(argv: list[str] | None = None) -> int:
    """Main entry point.

    Args:
        argv: Command-line arguments. If None, uses sys.argv[1:].

    Returns:
        Exit code (0=success, 1=config error, 2=startup, 3=runtime error).
    """
    parser = argparse.ArgumentParser(
        description="Airut Gateway Service",
        epilog=(
            "Monitors messaging channels and executes Claude Code in response."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--resilient",
        action="store_true",
        help=(
            "Stay alive on boot failure with error on dashboard instead of "
            "exiting. Useful for systemd services to avoid restart loops."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to airut.yaml config file"
            " (default: ~/.config/airut/airut.yaml)"
        ),
    )
    args = parser.parse_args(argv)

    configure_logging(
        level=logging.DEBUG if args.debug else logging.INFO,
        add_secret_filter=True,
    )

    logger.info("Airut Gateway Service starting...")

    try:
        config_path = args.config or get_config_path()
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.from_source(source)
        config = snapshot.value
    except (ValueError, Exception) as e:
        logger.critical("Configuration error: %s", e)
        return 1

    try:
        service = GatewayService(
            config,
            config_source=source,
            config_snapshot=snapshot,
        )
    except Exception as e:
        logger.exception("Failed to initialize service: %s", e)
        return 2

    def shutdown_handler(signum: int, frame: types.FrameType | None) -> None:
        """Handle shutdown signals."""
        logger.info("Received signal %d, initiating shutdown...", signum)
        service.stop()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(
        signal.SIGHUP,
        lambda *_: service._reload_requested.set(),
    )

    try:
        service.start(resilient=args.resilient)
        return 0
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except Exception as e:
        logger.exception("Fatal runtime error: %s", e)
        return 3
    finally:
        service.stop()
