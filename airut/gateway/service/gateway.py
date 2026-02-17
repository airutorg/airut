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
import logging
import signal
import threading
import time
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from importlib.resources import files
from pathlib import Path
from typing import Any

from airut.dashboard import (
    DashboardServer,
    TaskTracker,
    VersionInfo,
)
from airut.dashboard.tracker import (
    MAX_PENDING_PER_CONVERSATION,
    BootPhase,
    BootState,
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
from airut.gateway.config import ServerConfig
from airut.gateway.service.message_processing import (
    process_message,
)
from airut.gateway.service.repo_handler import RepoHandler
from airut.logging import configure_logging
from airut.sandbox import Sandbox, SandboxConfig, Task
from airut.version import GitVersionInfo, get_git_version_info


logger = logging.getLogger(__name__)


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
        self._running = True
        self._stopped = False

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
        # Lock ordering invariant: ``_pending_messages_lock`` and the
        # tracker's internal ``_lock`` must NEVER be held at the same
        # time.  Code that holds ``_pending_messages_lock`` may call
        # tracker methods (which briefly acquire/release ``_lock``
        # internally), but no code path may acquire
        # ``_pending_messages_lock`` while the tracker ``_lock`` is
        # already held by the same thread.  In practice this is
        # guaranteed because ``_drain_pending`` (which acquires
        # ``_pending_messages_lock``) is always called *after*
        # ``complete_task`` returns (i.e. after the tracker ``_lock``
        # is released).  Violating this invariant would create a
        # deadlock between the enqueue path (pending lock → tracker
        # lock) and the drain path (tracker lock → pending lock).
        self._pending_messages: dict[
            str, collections.deque[PendingMessage]
        ] = {}
        self._pending_messages_lock = threading.Lock()

        # Conversation-to-repo mapping for O(1) stop-execution lookup
        self._conv_repo_map: dict[str, str] = {}

        # Active tasks for stop functionality
        self._active_tasks: dict[str, object] = {}
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

        # Block main thread until shutdown
        try:
            while self._running:
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
            git_version_info=self._git_version_info,
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
                channel_info=repo_config.channel_info,
                storage_dir=str(repo_config.storage_dir),
            )

        # Start all repo listeners, tracking success/failure
        started_count = 0
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
                repo_handler.start_listener()
                started_count += 1
                repo_states[repo_id] = RepoState(
                    repo_id=repo_id,
                    status=RepoStatus.LIVE,
                    git_repo_url=config.git_repo_url,
                    channel_info=config.channel_info,
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
                    channel_info=config.channel_info,
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
        self,
        raw_message: RawMessage[Any],
        repo_handler: RepoHandler,
    ) -> bool:
        """Submit a raw message for authentication and processing.

        Called by RepoHandlers when they receive a new message.
        Authentication and parsing happen in the worker thread.

        Args:
            raw_message: Channel-agnostic raw message envelope.
            repo_handler: The repo handler that received this message.

        Returns:
            True if message was submitted, False if pool not ready.
        """
        if not self._executor_pool:
            logger.error("Executor pool not initialized")
            return False

        task_id = f"new-{id(raw_message):08x}"
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
    ) -> None:
        """Worker thread entry point for message processing."""
        self.tracker.set_authenticating(task_id)
        adapter = repo_handler.adapter

        reason = CompletionReason.INTERNAL_ERROR
        detail = ""
        final_task_id = task_id
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
            # The is_task_active check, reassign, depth-check, and
            # enqueue are ALL done under _pending_messages_lock to
            # prevent a TOCTOU race where the active task completes
            # (and drains) between the check and the append — which
            # would leave the message PENDING forever with nothing
            # to drain it.
            if conv_id:
                with self._pending_messages_lock:
                    if not self.tracker.is_task_active(conv_id):
                        # No active task — fall through to normal
                        # execution below (outside the lock).
                        pass
                    else:
                        # Reassign temp task to real conv_id so the
                        # pending task shows the correct conversation
                        # ID.  Done inside the lock so the drain
                        # cannot interleave.
                        if conv_id != task_id:
                            self.tracker.reassign_task(task_id, conv_id)
                            final_task_id = conv_id

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
                            task_id=final_task_id,
                            repo_handler=repo_handler,
                            adapter=adapter,
                        )
                        if conv_id not in self._pending_messages:
                            self._pending_messages[conv_id] = (
                                collections.deque()
                            )
                        self._pending_messages[conv_id].append(pending)

                        self.tracker.set_pending(final_task_id)
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

            # Move the temp task to the real conv_id so the dashboard
            # tracks it under the correct ID during execution and after
            # completion.  For resumed conversations the conv_id task
            # already exists (completed); reassign_task merges state.
            if conv_id and conv_id != task_id:
                self.tracker.reassign_task(task_id, conv_id)
                final_task_id = conv_id

            # Delegate execution, completion, and drain to the shared
            # helper (also used by _process_pending_message).
            # Handles its own complete_task + _drain_pending.
            self._execute_and_complete(
                parsed, final_task_id, repo_handler, adapter
            )
            # Signal the finally block to skip duplicate completion.
            completed_elsewhere = True
            return
        except AuthenticationError as auth_err:
            self.tracker.update_task_display_title(
                final_task_id,
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
                self.tracker.complete_task(final_task_id, reason, detail)
                # Drain any pending messages for this conversation.
                # final_task_id is always the conversation ID (set by
                # reassign_task) or the temp ID if process_message
                # returned no conv_id.  New conversations (conv_id
                # starts as None) never have pending messages queued
                # under a temp ID, so a no-op lookup here is safe.
                self._drain_pending(final_task_id)

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
        adapter: ChannelAdapter[Any, Any],
    ) -> None:
        """Execute a message and complete the tracker task.

        Shared by both ``_process_message_worker`` (first-time execution)
        and ``_process_pending_message`` (drain from pending queue).
        Acquires the conversation lock for existing conversations,
        completes the task, then drains any further pending messages.

        Args:
            parsed: Authenticated and parsed message.
            task_id: Current tracker task ID (may be temp or conv ID).
            repo_handler: Repository handler for this message.
            adapter: Channel adapter that produced the parsed message.
        """
        conv_id = parsed.conversation_id
        reason = CompletionReason.INTERNAL_ERROR
        detail = ""
        final_task_id = task_id

        try:
            self.tracker.set_executing(task_id)

            if conv_id and repo_handler.conversation_manager.exists(conv_id):
                lock = self._get_conversation_lock(conv_id)
                with lock:
                    reason, final_conv_id = process_message(
                        self, parsed, task_id, repo_handler, adapter
                    )
                    if final_conv_id:
                        final_task_id = final_conv_id
            else:
                reason, final_conv_id = process_message(
                    self, parsed, task_id, repo_handler, adapter
                )
                if final_conv_id:
                    final_task_id = final_conv_id
        except Exception:
            logger.exception("Error processing message (task %s)", task_id)
            reason = CompletionReason.INTERNAL_ERROR
        finally:
            # complete_task acquires/releases the tracker lock; only
            # then does _drain_pending acquire _pending_messages_lock.
            # This ordering is load-bearing — see the invariant comment
            # on _pending_messages_lock above.
            self.tracker.complete_task(final_task_id, reason, detail)
            # Drain any pending messages for this conversation.
            # final_task_id is the conversation ID (or temp ID for
            # new conversations which never have pending messages).
            self._drain_pending(final_task_id)

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

        while self._running:
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
        config = ServerConfig.from_yaml(config_path=args.config)
    except (ValueError, Exception) as e:
        logger.critical("Configuration error: %s", e)
        return 1

    try:
        service = GatewayService(config)
    except Exception as e:
        logger.exception("Failed to initialize service: %s", e)
        return 2

    def shutdown_handler(signum: int, frame: object) -> None:
        """Handle shutdown signals."""
        logger.info("Received signal %d, initiating shutdown...", signum)
        service.stop()

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
