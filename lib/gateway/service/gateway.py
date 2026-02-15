# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Main email gateway service orchestrator.

This module contains:
- EmailGatewayService: Main service class that orchestrates all components
- capture_version_info: Git version capture at startup
- main: CLI entry point
"""

from __future__ import annotations

import argparse
import concurrent.futures
import logging
import signal
import threading
import time
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from email.message import Message
from pathlib import Path

from lib.dashboard import (
    DashboardServer,
    TaskTracker,
    VersionInfo,
)
from lib.dashboard.tracker import BootPhase, BootState, RepoState, RepoStatus
from lib.dashboard.versioned import VersionClock, VersionedStore
from lib.dns import get_system_resolver
from lib.gateway.config import ServerConfig
from lib.gateway.parsing import decode_subject, extract_conversation_id
from lib.gateway.service.email_replies import send_rejection_reply
from lib.gateway.service.message_processing import (
    process_message,
)
from lib.gateway.service.repo_handler import RepoHandler
from lib.git_version import get_git_version_info
from lib.logging import configure_logging
from lib.sandbox import Sandbox, SandboxConfig, Task
from lib.update_lock import UpdateLock


logger = logging.getLogger(__name__)


def capture_version_info(repo_root: Path | None = None) -> VersionInfo:
    """Capture git version information at startup.

    Args:
        repo_root: Path to the repository root. If None, auto-detected.

    Returns:
        VersionInfo with git SHA and worktree status.
    """
    git_version = get_git_version_info(repo_root)

    return VersionInfo(
        git_sha=git_version.sha_short,
        git_sha_full=git_version.sha_full,
        worktree_clean=git_version.worktree_clean,
        full_status=git_version.full_status,
        started_at=time.time(),
    )


class EmailGatewayService:
    """Main email gateway service orchestrator.

    Manages multiple RepoHandlers, shared executor pool, dashboard, and
    proxy manager.  Each repo has its own listener thread; all repos
    share the executor pool and global task limit.
    """

    def __init__(
        self,
        config: ServerConfig,
        repo_root: Path | None = None,
        egress_network: str | None = None,
    ) -> None:
        """Initialize service with configuration.

        Args:
            config: Complete server configuration.
            repo_root: Path to repository root. If None, auto-detected.
            egress_network: Override for proxy egress network name. If None,
                uses the default ``airut-egress``. Useful for tests to avoid
                conflicts when running in parallel.
        """
        self._egress_network = egress_network
        self.config = config
        self.global_config = config.global_config
        self.running = True

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

        # Conversation-to-repo mapping for O(1) stop-execution lookup
        self._conv_repo_map: dict[str, str] = {}

        # Active tasks for stop functionality
        self._active_tasks: dict[str, object] = {}
        self._active_tasks_lock = threading.Lock()

        # Update lock for coordinating with auto-updater
        self._update_lock = UpdateLock(repo_root / ".update.lock")

        # Dashboard components — versioned state
        self._clock = VersionClock()
        self.tracker = TaskTracker(clock=self._clock)
        self.dashboard: DashboardServer | None = None
        self._version_info = capture_version_info(repo_root)
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
        sandbox_config = SandboxConfig(
            container_command=self.global_config.container_command,
            proxy_dir=self.repo_root / "proxy",
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

        logger.info("Email gateway service initialized")
        logger.info(
            "Version: %s (%s)",
            self._version_info.git_sha,
            "clean" if self._version_info.worktree_clean else "modified",
        )
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
        logger.info("Starting email gateway service...")

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

        # Block main thread until shutdown
        try:
            while self.running:
                time.sleep(1)
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
        )
        self.dashboard.start()

    def _boot(self) -> None:
        """Execute the boot sequence.

        Updates boot state via VersionedStore as each phase completes. On
        failure, the caller is responsible for recording the error.

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
                imap_server=repo_config.imap_server,
                storage_dir=str(repo_config.storage_dir),
            )

        # Start all repo listeners, tracking success/failure
        listener_threads = []
        for repo_id, repo_handler in self.repo_handlers.items():
            config = repo_handler.config
            boot = self._boot_store.get().value
            self._boot_store.update(
                replace(
                    boot,
                    message=f"Starting repository '{repo_id}'...",
                )
            )
            try:
                thread = repo_handler.start_listener()
                listener_threads.append(thread)
                repo_states[repo_id] = RepoState(
                    repo_id=repo_id,
                    status=RepoStatus.LIVE,
                    git_repo_url=config.git_repo_url,
                    imap_server=config.imap_server,
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
                    imap_server=config.imap_server,
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
            len(listener_threads),
        )

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
        if hasattr(self, "_stopped") and self._stopped:
            return
        self._stopped = True

        logger.info("Stopping email gateway service...")
        self.running = False
        self._shutdown_event.set()

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

    def register_active_task(self, task_id: str, task: Task) -> None:
        """Register an active task for stop functionality.

        Args:
            task_id: Task/conversation ID.
            task: Active sandbox Task.
        """
        with self._active_tasks_lock:
            self._active_tasks[task_id] = task

    def unregister_active_task(self, task_id: str) -> None:
        """Unregister a completed task.

        Args:
            task_id: Task/conversation ID.
        """
        with self._active_tasks_lock:
            self._active_tasks.pop(task_id, None)

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
            return task.stop()  # type: ignore[union-attr]
        logger.warning(
            "No active task found for conversation %s", conversation_id
        )
        return False

    def submit_message(
        self, message: Message, repo_handler: RepoHandler
    ) -> bool:
        """Submit message for parallel processing.

        Called by RepoHandlers when they receive a new message.

        Args:
            message: Email message to process.
            repo_handler: The repo handler that received this message.

        Returns:
            True if message was submitted, False if rejected.
        """
        if not self._executor_pool:
            logger.error("Executor pool not initialized")
            return False

        subject = decode_subject(message) or "(no subject)"
        sender = message.get("From", "")
        conv_id = extract_conversation_id(subject)
        repo_id = repo_handler.config.repo_id

        # Reject emails for conversations that already have an active task
        if conv_id and self.tracker.is_task_active(conv_id):
            logger.warning(
                "Rejecting duplicate email for conversation %s - active",
                conv_id,
            )
            send_rejection_reply(
                repo_handler,
                message,
                conv_id,
                "Your previous request for this conversation is still being "
                "processed. Please wait for it to complete before sending "
                "another message.",
                self.global_config,
            )
            return False

        # Use conversation ID if available, otherwise generate a temp ID
        task_id = conv_id if conv_id else f"new-{id(message):08x}"
        self.tracker.add_task(task_id, subject, repo_id=repo_id, sender=sender)

        future = self._executor_pool.submit(
            self._process_message_worker, message, task_id, repo_handler
        )

        with self._futures_lock:
            if len(self._pending_futures) == 0:
                self._update_lock.try_acquire()
            self._pending_futures.add(future)

        future.add_done_callback(self._on_future_complete)
        return True

    def _on_future_complete(self, future: Future[None]) -> None:
        """Callback when a future completes."""
        with self._futures_lock:
            self._pending_futures.discard(future)
            if len(self._pending_futures) == 0:
                self._update_lock.release()

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
        message: Message,
        task_id: str,
        repo_handler: RepoHandler,
    ) -> None:
        """Worker thread entry point for message processing."""
        self.tracker.start_task(task_id)

        subject = decode_subject(message)
        conv_id = extract_conversation_id(subject)

        success = False
        final_task_id = task_id
        try:
            if conv_id and repo_handler.conversation_manager.exists(conv_id):
                lock = self._get_conversation_lock(conv_id)
                with lock:
                    success, final_conv_id = process_message(
                        self, message, task_id, repo_handler
                    )
                    if final_conv_id:
                        final_task_id = final_conv_id
            else:
                success, final_conv_id = process_message(
                    self, message, task_id, repo_handler
                )
                if final_conv_id:
                    final_task_id = final_conv_id
        finally:
            self.tracker.complete_task(final_task_id, success)

    def _garbage_collector_thread(self) -> None:
        """Background thread for conversation garbage collection.

        Runs every 24 hours, removing old conversations from all repos.
        """
        gc_interval = 24 * 60 * 60  # 24 hours
        max_age_days = self.global_config.conversation_max_age_days

        logger.info(
            "Garbage collector started (interval: 24h, max_age: %d days)",
            max_age_days,
        )

        while self.running:
            if self._shutdown_event.wait(timeout=gc_interval):
                break  # Shutdown signaled

            try:
                logger.info("Running conversation garbage collection...")
                total_removed = 0

                for repo_id, handler in self.repo_handlers.items():
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

                if total_removed > 0:
                    logger.info(
                        "Garbage collection complete. Removed %d conversations",
                        total_removed,
                    )
                else:
                    logger.debug(
                        "Garbage collection complete. No conversations removed"
                    )

            except Exception as e:
                logger.exception("Error in garbage collector: %s", e)


def main() -> int:
    """Main entry point.

    Returns:
        Exit code (0=success, 1=config error, 2=startup, 3=runtime error).
    """
    parser = argparse.ArgumentParser(
        description="Airut Email Gateway Service",
        epilog="Monitors email and executes Claude Code in response.",
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
    args = parser.parse_args()

    configure_logging(
        level=logging.DEBUG if args.debug else logging.INFO,
        add_secret_filter=True,
    )

    logger.info("Airut Email Gateway Service starting...")

    try:
        config = ServerConfig.from_yaml()
    except (ValueError, Exception) as e:
        logger.critical("Configuration error: %s", e)
        return 1

    try:
        service = EmailGatewayService(config)
    except Exception as e:
        logger.exception("Failed to initialize service: %s", e)
        return 2

    def shutdown_handler(signum: int, frame: object) -> None:
        """Handle shutdown signals."""
        logger.info("Received signal %d, initiating shutdown...", signum)
        service.running = False
        for handler in service.repo_handlers.values():
            handler.listener.interrupt()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

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
