# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""HTTP request handlers for dashboard server.

Provides handler functions for all dashboard HTTP endpoints.
"""

import json
import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from werkzeug.wrappers import Request, Response

from lib.conversation import (
    CONVERSATION_FILE_NAME,
    ConversationMetadata,
    ConversationStore,
)
from lib.dashboard import views
from lib.dashboard.formatters import VersionInfo
from lib.dashboard.tracker import (
    BootState,
    RepoState,
    TaskState,
    TaskStatus,
    TaskTracker,
)
from lib.dashboard.views import get_favicon_svg
from lib.gateway.conversation import CONVERSATION_ID_PATTERN
from lib.sandbox import NETWORK_LOG_FILENAME, EventLog


logger = logging.getLogger(__name__)


class RequestHandlers:
    """Container for HTTP request handlers.

    Encapsulates all handler logic and dependencies needed to process
    dashboard HTTP requests.
    """

    def __init__(
        self,
        tracker: TaskTracker,
        version_info: VersionInfo | None = None,
        work_dirs: Callable[[], list[Path]] | None = None,
        stop_callback: Any = None,
        repo_states: Callable[[], list[RepoState]] | None = None,
        boot_state: BootState | None = None,
    ) -> None:
        """Initialize request handlers.

        Args:
            tracker: Task tracker to query for state.
            version_info: Optional version information to display.
            work_dirs: Callable returning directories where conversation data
                is stored.  Called on each request to get current state.
            stop_callback: Optional callable to stop an execution.
            repo_states: Callable returning list of repository states.
                Called on each request to get current state.
            boot_state: Shared boot state object for progress reporting.
        """
        self.tracker = tracker
        self.version_info = version_info
        self._work_dirs = work_dirs or (lambda: [])
        self.stop_callback = stop_callback
        self._repo_states = repo_states or (lambda: [])
        self.boot_state = boot_state

    def handle_favicon(self, request: Request) -> Response:
        """Handle favicon request.

        Serves the logo SVG as favicon.

        Args:
            request: Incoming request.

        Returns:
            SVG response with logo.
        """
        return Response(
            get_favicon_svg(),
            content_type="image/svg+xml",
            headers={
                "Cache-Control": "public, max-age=86400",
            },
        )

    def handle_index(self, request: Request) -> Response:
        """Handle main dashboard page.

        Args:
            request: Incoming request.

        Returns:
            HTML response with dashboard.
        """
        counts = self.tracker.get_counts()
        queued = self.tracker.get_tasks_by_status(TaskStatus.QUEUED)
        in_progress = self.tracker.get_tasks_by_status(TaskStatus.IN_PROGRESS)
        completed = self.tracker.get_tasks_by_status(TaskStatus.COMPLETED)

        return Response(
            views.render_dashboard(
                counts,
                queued,
                in_progress,
                completed,
                self.version_info,
                self._repo_states(),
                boot_state=self.boot_state,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_version(self, request: Request) -> Response:
        """Handle version info endpoint.

        Args:
            request: Incoming request.

        Returns:
            Plain text response with full git version info.
        """
        if not self.version_info:
            return Response(
                "Version info not available\n",
                status=404,
                content_type="text/plain; charset=utf-8",
            )

        return Response(
            self.version_info.full_status,
            content_type="text/plain; charset=utf-8",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    def handle_task_detail(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle conversation detail page.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to show.

        Returns:
            HTML response with conversation details.
        """
        result = self._load_task_with_conversation(conversation_id)
        if result is None:
            return Response("Conversation not found", status=404)
        task, conversation = result

        return Response(
            views.render_task_detail(task, conversation),
            content_type="text/html; charset=utf-8",
        )

    def handle_task_conversation_json(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle raw conversation JSON endpoint.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to get data for.

        Returns:
            JSON response with raw conversation file contents.
        """
        conversation_dir = self._find_conversation_dir(conversation_id)
        if conversation_dir is None:
            return Response(
                json.dumps({"error": "Conversation data not available"}),
                status=404,
                content_type="application/json",
            )

        conversation_path = conversation_dir / CONVERSATION_FILE_NAME
        if not conversation_path.exists():
            return Response(
                json.dumps({"error": "No conversation data found"}),
                status=404,
                content_type="application/json",
            )

        try:
            with conversation_path.open("r") as f:
                raw_data = json.load(f)
            return Response(
                json.dumps(raw_data, indent=2),
                content_type="application/json",
            )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Failed to read conversation file %s: %s",
                conversation_path,
                e,
            )
            return Response(
                json.dumps({"error": "Failed to read conversation data"}),
                status=500,
                content_type="application/json",
            )

    def handle_task_actions(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle actions viewer page.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to show actions for.

        Returns:
            HTML response with actions viewer.
        """
        result = self._load_task_with_conversation(conversation_id)
        if result is None:
            return Response("Conversation not found", status=404)
        task, conversation = result

        # Load events from event log for the actions view
        conversation_dir = self._find_conversation_dir(conversation_id)
        event_groups = None
        if conversation_dir is not None:
            event_log = EventLog(conversation_dir)
            event_groups = event_log.read_all()

        return Response(
            views.render_actions_page(task, conversation, event_groups),
            content_type="text/html; charset=utf-8",
        )

    def handle_task_network(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle network logs viewer page.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to show network logs for.

        Returns:
            HTML response with network logs viewer.
        """
        result = self._load_task_with_conversation(conversation_id)
        if result is None:
            return Response("Conversation not found", status=404)
        task, _ = result

        # Load network logs from conversation directory
        conversation_dir = self._find_conversation_dir(conversation_id)
        log_content: str | None = None
        if conversation_dir is not None:
            log_path = conversation_dir / NETWORK_LOG_FILENAME
            if log_path.exists():
                try:
                    log_content = log_path.read_text()
                except OSError as e:
                    logger.warning(
                        "Failed to read network log %s: %s", log_path, e
                    )

        return Response(
            views.render_network_page(task, log_content),
            content_type="text/html; charset=utf-8",
        )

    def handle_api_tasks(self, request: Request) -> Response:
        """Handle JSON API for all tasks.

        Args:
            request: Incoming request.

        Returns:
            JSON response with task list.
        """
        tasks = self.tracker.get_all_tasks()
        return Response(
            json.dumps([self._task_to_dict(t) for t in tasks]),
            content_type="application/json",
        )

    def handle_api_task(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle JSON API for single conversation.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to return.

        Returns:
            JSON response with conversation details.
        """
        result = self._load_task_with_conversation(conversation_id)
        if result is None:
            return Response(
                json.dumps({"error": "Conversation not found"}),
                status=404,
                content_type="application/json",
            )
        task, conversation = result

        # Load events for the API response
        conversation_dir = self._find_conversation_dir(conversation_id)
        event_groups = None
        if conversation_dir is not None:
            event_log = EventLog(conversation_dir)
            event_groups = event_log.read_all()

        return Response(
            json.dumps(
                self._task_to_dict(
                    task,
                    include_conversation=True,
                    conversation=conversation,
                    event_groups=event_groups,
                )
            ),
            content_type="application/json",
        )

    def handle_repo_detail(self, request: Request, repo_id: str) -> Response:
        """Handle repository detail page.

        Args:
            request: Incoming request.
            repo_id: Repository ID to show.

        Returns:
            HTML response with repository details.
        """
        repo_state = next(
            (r for r in self._repo_states() if r.repo_id == repo_id), None
        )
        if repo_state is None:
            return Response("Repository not found", status=404)

        return Response(
            views.render_repo_detail(repo_state),
            content_type="text/html; charset=utf-8",
        )

    def handle_api_repos(self, request: Request) -> Response:
        """Handle JSON API for repository status.

        Args:
            request: Incoming request.

        Returns:
            JSON response with repository status list.
        """
        repos = [
            {
                "repo_id": r.repo_id,
                "status": r.status.value,
                "error_message": r.error_message,
                "error_type": r.error_type,
                "git_repo_url": r.git_repo_url,
                "imap_server": r.imap_server,
                "storage_dir": r.storage_dir,
                "initialized_at": r.initialized_at,
            }
            for r in self._repo_states()
        ]
        return Response(
            json.dumps(repos),
            content_type="application/json",
        )

    def handle_health(self, request: Request) -> Response:
        """Handle health check endpoint.

        Args:
            request: Incoming request.

        Returns:
            JSON response indicating server health.
        """
        from lib.dashboard.tracker import BootPhase

        counts = self.tracker.get_counts()
        # Include repo status in health check
        repo_states = self._repo_states()
        live_repos = sum(1 for r in repo_states if r.status.value == "live")
        failed_repos = sum(1 for r in repo_states if r.status.value == "failed")

        # Determine overall status based on boot state
        if self.boot_state and self.boot_state.phase == BootPhase.FAILED:
            status = "error"
        elif self.boot_state and self.boot_state.phase != BootPhase.READY:
            status = "booting"
        elif live_repos > 0:
            status = "ok"
        else:
            status = "degraded"

        result: dict[str, Any] = {
            "status": status,
            "tasks": counts,
            "repos": {
                "live": live_repos,
                "failed": failed_repos,
                "total": len(repo_states),
            },
        }

        if self.boot_state:
            result["boot"] = {
                "phase": self.boot_state.phase.value,
                "message": self.boot_state.message,
            }
            if self.boot_state.error_message:
                result["boot"]["error"] = self.boot_state.error_message

        return Response(
            json.dumps(result),
            content_type="application/json",
        )

    def handle_api_task_stop(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle conversation stop API endpoint.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to stop.

        Returns:
            JSON response with stop result.
        """
        if self.stop_callback is None:
            return Response(
                json.dumps({"error": "Stop functionality not available"}),
                status=503,
                content_type="application/json",
            )

        # Check if task is active
        task = self.tracker.get_task(conversation_id)
        if task is None:
            return Response(
                json.dumps({"error": "Task not found"}),
                status=404,
                content_type="application/json",
            )

        if task.status != TaskStatus.IN_PROGRESS:
            status_value = task.status.value
            error_msg = f"Task is not running (status: {status_value})"
            return Response(
                json.dumps({"error": error_msg}),
                status=400,
                content_type="application/json",
            )

        # Call stop callback
        try:
            success = self.stop_callback(conversation_id)
            if success:
                return Response(
                    json.dumps({"success": True, "message": "Task stopped"}),
                    content_type="application/json",
                )
            else:
                return Response(
                    json.dumps(
                        {"success": False, "message": "Task not running"}
                    ),
                    status=404,
                    content_type="application/json",
                )
        except Exception as e:
            logger.exception("Failed to stop task %s: %s", conversation_id, e)
            return Response(
                json.dumps({"error": f"Failed to stop task: {e}"}),
                status=500,
                content_type="application/json",
            )

    def _find_conversation_dir(self, conversation_id: str) -> Path | None:
        """Find the conversation directory across all repos.

        Args:
            conversation_id: Conversation ID to locate.

        Returns:
            Path to the conversation directory, or None if not found.
        """
        for work_dir in self._work_dirs():
            candidate = work_dir / conversation_id
            if candidate.exists():
                return candidate
        return None

    def _load_conversation(
        self, conversation_id: str
    ) -> ConversationMetadata | None:
        """Load conversation metadata.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            ConversationMetadata if available, None otherwise.
        """
        conversation_dir = self._find_conversation_dir(conversation_id)
        if conversation_dir is None:
            return None

        store = ConversationStore(conversation_dir)
        return store.load()

    def _load_task_from_disk(
        self, conversation_id: str
    ) -> tuple[TaskState, ConversationMetadata] | None:
        """Load a task from disk when not in memory.

        Constructs a minimal TaskState from conversation metadata stored on
        disk. This enables viewing past tasks that were active before the
        current process started.

        Args:
            conversation_id: 8-character hex conversation ID.

        Returns:
            Tuple of (TaskState, ConversationMetadata) if found,
            None otherwise.
        """
        # Validate conversation ID format
        if not CONVERSATION_ID_PATTERN.match(conversation_id):
            return None

        conversation_path = self._find_conversation_dir(conversation_id)
        if conversation_path is None or not conversation_path.exists():
            return None

        # Load conversation metadata
        store = ConversationStore(conversation_path)
        conversation = store.load()
        if conversation is None:
            return None

        # Construct TaskState from conversation data
        # We mark it as COMPLETED since it's a past task not currently active
        # Use the last reply's timestamp to estimate completion time
        completed_at: float | None = None
        if conversation.replies:
            try:
                # Parse ISO 8601 timestamp from last reply
                last_timestamp = conversation.replies[-1].timestamp
                # Handle both timezone-aware and naive timestamps
                normalized = last_timestamp.replace("Z", "+00:00")
                dt = datetime.fromisoformat(normalized)
                completed_at = dt.timestamp()
            except (ValueError, AttributeError):
                pass

        task = TaskState(
            conversation_id=conversation_id,
            subject=f"[Past conversation {conversation_id}]",
            status=TaskStatus.COMPLETED,
            queued_at=completed_at or 0.0,
            started_at=completed_at,
            completed_at=completed_at,
            success=not any(r.is_error for r in conversation.replies),
            message_count=len(conversation.replies),
            model=conversation.model,
        )

        return task, conversation

    def _load_task_with_conversation(
        self, conversation_id: str
    ) -> tuple[TaskState, ConversationMetadata | None] | None:
        """Load task and conversation metadata from memory or disk.

        Tries to load from in-memory tracker first, then falls back to disk
        for past tasks. This is the unified entry point for all handlers that
        need both task state and conversation data.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            Tuple of (TaskState, ConversationMetadata or None) if found,
            None if task not found in memory or on disk.
        """
        task = self.tracker.get_task(conversation_id)

        if task is not None:
            # Task found in memory, load conversation separately
            conversation = self._load_conversation(conversation_id)
            return task, conversation

        # Try loading from disk for past tasks
        disk_result = self._load_task_from_disk(conversation_id)
        if disk_result is not None:
            return disk_result

        return None

    def _task_to_dict(
        self,
        task: TaskState,
        include_conversation: bool = False,
        conversation: ConversationMetadata | None = None,
        event_groups: list[list[Any]] | None = None,
    ) -> dict[str, Any]:
        """Convert TaskState to JSON-serializable dict.

        Args:
            task: Task to convert.
            include_conversation: If True, include conversation metadata.
            conversation: Pre-loaded conversation metadata.
            event_groups: Pre-loaded event groups from EventLog.

        Returns:
            Dict representation of task.
        """
        result: dict[str, Any] = {
            "conversation_id": task.conversation_id,
            "subject": task.subject,
            "status": task.status.value,
            "queued_at": task.queued_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "success": task.success,
            "message_count": task.message_count,
            "model": task.model,
            "queue_duration": task.queue_duration(),
            "execution_duration": task.execution_duration(),
            "total_duration": task.total_duration(),
        }

        if include_conversation:
            if conversation is None:
                conversation = self._load_conversation(task.conversation_id)
            if conversation:
                replies_data = []
                for i, r in enumerate(conversation.replies):
                    reply_dict: dict[str, Any] = {
                        "session_id": r.session_id,
                        "timestamp": r.timestamp,
                        "duration_ms": r.duration_ms,
                        "total_cost_usd": r.total_cost_usd,
                        "num_turns": r.num_turns,
                        "is_error": r.is_error,
                        "usage": {
                            "input_tokens": r.usage.input_tokens,
                            "output_tokens": r.usage.output_tokens,
                            "cache_creation_input_tokens": (
                                r.usage.cache_creation_input_tokens
                            ),
                            "cache_read_input_tokens": (
                                r.usage.cache_read_input_tokens
                            ),
                        },
                        "request_text": r.request_text,
                        "response_text": r.response_text,
                    }

                    # Include events from event log if available
                    if event_groups is not None and i < len(event_groups):
                        reply_dict["events"] = [
                            json.loads(e.raw) for e in event_groups[i]
                        ]
                    else:
                        reply_dict["events"] = []

                    replies_data.append(reply_dict)

                result["conversation"] = {
                    "total_cost_usd": conversation.total_cost_usd,
                    "total_turns": conversation.total_turns,
                    "reply_count": len(conversation.replies),
                    "replies": replies_data,
                }
            else:
                result["conversation"] = None

        return result
