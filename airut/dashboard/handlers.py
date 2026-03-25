# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""HTTP request handlers for dashboard server.

Provides handler functions for all dashboard HTTP endpoints.
"""

import json
import logging
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

from werkzeug.wrappers import Request, Response

from airut._json_types import JsonDict
from airut.claude_output.types import StreamEvent
from airut.conversation import (
    ConversationMetadata,
    ConversationStore,
)
from airut.dashboard.formatters import VersionInfo
from airut.dashboard.sse import (
    SSEConnectionManager,
    render_events_html,
    render_network_lines_html,
    sse_events_log_stream,
    sse_network_log_stream,
    sse_state_stream,
)
from airut.dashboard.templating import get_static_file, render_template
from airut.dashboard.tracker import (
    ACTIVE_STATUSES,
    BootState,
    CompletionReason,
    RepoState,
    TaskState,
    TaskStatus,
    TaskTracker,
    make_disk_task_id,
    parse_disk_task_id,
)
from airut.dashboard.versioned import VersionClock, VersionedStore
from airut.dashboard.views import get_favicon_svg
from airut.dashboard.views.actions import render_actions_timeline
from airut.dashboard.views.components import render_single_reply_section
from airut.dashboard.views.network import render_network_log_lines
from airut.gateway.conversation import CONVERSATION_ID_PATTERN
from airut.sandbox import NETWORK_LOG_FILENAME, EventLog, NetworkLog
from airut.version import (
    GitVersionInfo,
    check_upstream_version,
    github_commit_url,
    github_release_url,
)


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
        stop_callback: Callable[[str], bool] | None = None,
        boot_store: VersionedStore[BootState] | None = None,
        repos_store: VersionedStore[tuple[RepoState, ...]] | None = None,
        clock: VersionClock | None = None,
        sse_manager: SSEConnectionManager | None = None,
        git_version_info: GitVersionInfo | None = None,
        status_callback: Callable[[], dict[str, object]] | None = None,
    ) -> None:
        """Initialize request handlers.

        Args:
            tracker: Task tracker to query for state.
            version_info: Optional version information to display.
            work_dirs: Callable returning directories where conversation data
                is stored.  Called on each request to get current state.
            stop_callback: Optional callable to stop an execution.
            boot_store: Versioned boot state store.
            repos_store: Versioned repo states store.
            clock: Shared version clock for SSE streaming.
            sse_manager: SSE connection manager for enforcing limits.
            git_version_info: Git version info for upstream update checks.
            status_callback: Optional callable returning config reload status
                dict with keys: config_generation, config_file_sha256,
                server_reload_pending, last_reload_error.
        """
        self.tracker = tracker
        self.version_info = version_info
        self._work_dirs = work_dirs or (lambda: [])
        self.stop_callback = stop_callback
        self._boot_store = boot_store
        self._repos_store = repos_store
        self._clock = clock
        self._sse_manager = sse_manager or SSEConnectionManager()
        self._git_version_info = git_version_info
        self._status_callback = status_callback

    def _get_boot_state(self) -> BootState | None:
        """Read current boot state from versioned store."""
        if self._boot_store is None:
            return None
        return self._boot_store.get().value

    def _get_repo_states(self) -> list[RepoState]:
        """Read current repo states from versioned store."""
        if self._repos_store is None:
            return []
        return list(self._repos_store.get().value)

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
        pending = (
            self.tracker.get_tasks_by_status(TaskStatus.QUEUED)
            + self.tracker.get_tasks_by_status(TaskStatus.AUTHENTICATING)
            + self.tracker.get_tasks_by_status(TaskStatus.PENDING)
        )
        executing = self.tracker.get_tasks_by_status(TaskStatus.EXECUTING)
        completed = self.tracker.get_tasks_by_status(TaskStatus.COMPLETED)

        pending_count = (
            counts.get("queued", 0)
            + counts.get("authenticating", 0)
            + counts.get("pending", 0)
        )

        version_url = self._version_url()

        return Response(
            render_template(
                "pages/dashboard.html",
                breadcrumbs=[],
                version_info=self.version_info,
                version_url=version_url,
                boot_state=self._get_boot_state(),
                repo_states=self._get_repo_states(),
                pending_tasks=pending,
                executing_tasks=executing,
                completed_tasks=completed,
                pending_count=pending_count,
                executing_count=counts.get("executing", 0),
                completed_count=counts.get("completed", 0),
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_version(self, request: Request) -> Response:
        """Handle version info endpoint.

        Args:
            request: Incoming request.

        Returns:
            JSON response with structured version info.
        """
        if not self.version_info:
            return Response(
                json.dumps({"error": "Version info not available"}),
                status=404,
                content_type="application/json",
            )

        data = {
            "version": self.version_info.version,
            "sha_short": self.version_info.git_sha,
            "sha_full": self.version_info.git_sha_full,
        }

        return Response(
            json.dumps(data),
            content_type="application/json",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    def handle_update(self, request: Request) -> Response:
        """Handle update check endpoint.

        Returns the current version and the latest upstream version.
        The upstream check may involve an HTTP request to PyPI or GitHub,
        so this endpoint is separate from /api/version to avoid blocking
        dashboard load.

        When ``format=html`` is in the query string, returns a rendered
        HTML fragment suitable for htmx ``hx-swap="outerHTML"`` on the
        version status badge.

        Args:
            request: Incoming request.

        Returns:
            JSON or HTML response with version update info.
        """
        if not self._git_version_info:
            if request.args.get("format") == "html":
                return Response(
                    '<span class="version-badge version-status'
                    ' check-failed"></span>',
                    content_type="text/html; charset=utf-8",
                )
            return Response(
                json.dumps({"error": "Version info not available"}),
                status=404,
                content_type="application/json",
            )

        upstream = check_upstream_version(self._git_version_info)

        data: JsonDict = {
            "current": (
                self._git_version_info.version
                or self._git_version_info.sha_short
            ),
        }

        if upstream is not None:
            data["latest"] = upstream.latest
            data["update_available"] = upstream.update_available
            data["source"] = upstream.source
            if upstream.update_available:
                if upstream.source == "pypi":
                    data["release_url"] = github_release_url(upstream.latest)
                else:
                    data["release_url"] = github_commit_url(upstream.latest)
            else:
                data["release_url"] = None
        else:
            data["latest"] = None
            data["update_available"] = False
            data["source"] = None
            data["release_url"] = None

        if request.args.get("format") == "html":
            return self._render_update_html(data)

        return Response(
            json.dumps(data),
            content_type="application/json",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
            },
        )

    def _render_update_html(self, data: JsonDict) -> Response:
        """Render the update check result as an HTML badge fragment.

        Args:
            data: Update check data dict.

        Returns:
            HTML response with version status badge.
        """
        import html as html_mod

        if data.get("update_available"):
            release_url = data.get("release_url")
            current = html_mod.escape(str(data.get("current", "")))
            latest = html_mod.escape(str(data.get("latest", "")))
            title = f"{current} \u2192 {latest}"
            if release_url:
                badge = (
                    f'<a href="{html_mod.escape(str(release_url))}"'
                    f' target="_blank" rel="noopener"'
                    f' class="version-badge version-status update-available"'
                    f' title="{title}">update available</a>'
                )
            else:
                badge = (
                    '<span class="version-badge version-status'
                    f' update-available" title="{title}">'
                    "update available</span>"
                )
        else:
            current = html_mod.escape(str(data.get("current", "")))
            badge = (
                f'<span class="version-badge version-status up-to-date"'
                f' title="{current}">up to date</span>'
            )

        return Response(
            badge,
            content_type="text/html; charset=utf-8",
        )

    def handle_task_detail_by_id(
        self, request: Request, task_id: str
    ) -> Response:
        """Handle task detail page (by task_id).

        Args:
            request: Incoming request.
            task_id: Task ID to show.

        Returns:
            HTML response with task details.
        """
        result = self._resolve_task_by_id(task_id)
        if result is None:
            return Response("Task not found", status=404)
        task, conversation = result

        return Response(
            self._render_task_detail_page(task, conversation),
            content_type="text/html; charset=utf-8",
        )

    def handle_conversation_detail(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle conversation overview page.

        Shows all tasks for a conversation with links to individual
        task pages, plus aggregate stats and full reply history.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to show.

        Returns:
            HTML response with conversation overview.
        """
        tasks = self.tracker.get_tasks_for_conversation(conversation_id)
        conversation = self._load_conversation(conversation_id)

        # Fall back to disk for past conversations.  Both
        # _load_conversation and _load_task_from_disk resolve the same
        # directory, so if the disk result exists the conversation is
        # already loaded above.
        if not tasks:
            disk_result = self._load_task_from_disk(conversation_id)
            if disk_result is not None:
                task, _conv = disk_result
                tasks = [task]

        if not tasks and conversation is None:
            return Response("Conversation not found", status=404)

        # Compute aggregate stats
        cost_display = "-"
        turns_display = "-"
        reply_count = "0"
        model_display = "-"
        if conversation:
            if conversation.replies:
                cost_display = f"${conversation.total_cost_usd:.4f}"
                turns_display = str(conversation.total_turns)
                reply_count = str(len(conversation.replies))
            if conversation.model:
                model_display = conversation.model

        from airut.dashboard.views.components import (
            render_conversation_replies_section,
        )

        replies_section = render_conversation_replies_section(
            conversation_id, conversation
        )

        # Build breadcrumbs: use repo from first task if available
        repo_id = tasks[0].repo_id if tasks else None
        crumbs: list[tuple[str, str]] = []
        if repo_id:
            crumbs.append((repo_id, f"/repo/{repo_id}"))
        crumbs.append((f"Conversation {conversation_id}", ""))

        return Response(
            render_template(
                "pages/conversation.html",
                breadcrumbs=crumbs,
                conversation_id=conversation_id,
                tasks=tasks,
                reply_count=reply_count,
                cost_display=cost_display,
                turns_display=turns_display,
                model_display=model_display,
                replies_section=replies_section,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_task_actions_by_id(
        self, request: Request, task_id: str
    ) -> Response:
        """Handle actions viewer page via task ID.

        Resolves the conversation_id from the task and delegates to
        :meth:`_render_actions_page`.

        Args:
            request: Incoming request.
            task_id: Task ID to show actions for.

        Returns:
            HTML response with actions viewer.
        """
        result = self._resolve_task_by_id(task_id)
        if result is None:
            return Response("Task not found", status=404)
        task, _ = result
        if not task.conversation_id:
            return Response("No conversation for this task", status=404)
        return self._render_actions_page(task.conversation_id)

    def handle_task_actions(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle actions viewer page via conversation ID.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to show actions for.

        Returns:
            HTML response with actions viewer.
        """
        return self._render_actions_page(conversation_id)

    def _render_actions_page(self, conversation_id: str) -> Response:
        """Render the actions viewer page.

        Args:
            conversation_id: Conversation ID to show actions for.

        Returns:
            HTML response with actions viewer.
        """
        # Read events.jsonl BEFORE conversation.json to avoid a race
        # condition: if a reply completes between the two reads, the
        # stale pending_request_text from conversation.json would
        # duplicate the completed reply's prompt.  By reading
        # conversation.json second, it always reflects the latest
        # state relative to the events already captured.
        conversation_dir = self._find_conversation_dir(conversation_id)
        event_groups = None
        event_log_offset = 0
        if conversation_dir is not None:
            event_log = EventLog(conversation_dir)
            event_groups = event_log.read_all()
            # Capture byte offset so SSE starts after already-rendered events
            if event_log.file_path.exists():
                event_log_offset = event_log.file_path.stat().st_size

        result = self._load_task_with_conversation(conversation_id)
        if result is None:
            return Response("Conversation not found", status=404)
        task, conversation = result

        # Build actions content
        has_replies = conversation is not None and len(conversation.replies) > 0
        has_events = event_groups is not None and len(event_groups) > 0
        has_pending = (
            conversation is not None
            and conversation.pending_request_text is not None
        )
        if not has_replies and not has_events and not has_pending:
            actions_content = (
                '<div class="no-actions">No actions recorded</div>'
            )
        else:
            actions_content = render_actions_timeline(
                conversation, event_groups
            )

        is_active = task.status in ACTIVE_STATUSES

        # Build breadcrumbs
        crumbs: list[tuple[str, str]] = []
        if task.repo_id:
            crumbs.append((task.repo_id, f"/repo/{task.repo_id}"))
        if task.conversation_id:
            crumbs.append(
                (
                    f"Conversation {task.conversation_id}",
                    f"/conversation/{task.conversation_id}",
                )
            )
        crumbs.append((f"Task {task.task_id}", f"/task/{task.task_id}"))
        crumbs.append(("Actions", ""))

        return Response(
            render_template(
                "pages/actions.html",
                breadcrumbs=crumbs,
                task=task,
                is_active=is_active,
                actions_content=actions_content,
                event_log_offset=event_log_offset,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_task_network_by_id(
        self, request: Request, task_id: str
    ) -> Response:
        """Handle network logs viewer page via task ID.

        Resolves the conversation_id from the task and delegates to
        :meth:`_render_network_page`.

        Args:
            request: Incoming request.
            task_id: Task ID to show network logs for.

        Returns:
            HTML response with network logs viewer.
        """
        result = self._resolve_task_by_id(task_id)
        if result is None:
            return Response("Task not found", status=404)
        task, _ = result
        if not task.conversation_id:
            return Response("No conversation for this task", status=404)
        return self._render_network_page(task.conversation_id)

    def handle_task_network(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle network logs viewer page via conversation ID.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to show network logs for.

        Returns:
            HTML response with network logs viewer.
        """
        return self._render_network_page(conversation_id)

    def _render_network_page(self, conversation_id: str) -> Response:
        """Render the network logs viewer page.

        Args:
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
        network_log_offset = 0
        if conversation_dir is not None:
            log_path = conversation_dir / NETWORK_LOG_FILENAME
            if log_path.exists():
                try:
                    log_content = log_path.read_text()
                    # Capture byte offset so SSE starts after rendered lines
                    network_log_offset = log_path.stat().st_size
                except OSError as e:
                    logger.warning(
                        "Failed to read network log %s: %s", log_path, e
                    )

        # Build network logs HTML
        if log_content is None:
            logs_html = '<div class="no-logs">No network logs available</div>'
        elif not log_content.strip():
            logs_html = '<div class="no-logs">Network log is empty</div>'
        else:
            logs_html = render_network_log_lines(log_content)

        is_active = task.status in ACTIVE_STATUSES

        # Build breadcrumbs
        crumbs: list[tuple[str, str]] = []
        if task.repo_id:
            crumbs.append((task.repo_id, f"/repo/{task.repo_id}"))
        if task.conversation_id:
            crumbs.append(
                (
                    f"Conversation {task.conversation_id}",
                    f"/conversation/{task.conversation_id}",
                )
            )
        crumbs.append((f"Task {task.task_id}", f"/task/{task.task_id}"))
        crumbs.append(("Network", ""))

        return Response(
            render_template(
                "pages/network.html",
                breadcrumbs=crumbs,
                task=task,
                is_active=is_active,
                logs_html=logs_html,
                network_log_offset=network_log_offset,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_api_task_by_id(self, request: Request, task_id: str) -> Response:
        """Handle JSON API for single task by task_id.

        Args:
            request: Incoming request.
            task_id: Task ID to return.

        Returns:
            JSON response with task details.
        """
        result = self._resolve_task_by_id(task_id)
        if result is None:
            return Response(
                json.dumps({"error": "Task not found"}),
                status=404,
                content_type="application/json",
            )
        task, conversation = result

        return Response(
            json.dumps(
                self._task_to_dict(
                    task,
                    include_conversation=True,
                    conversation=conversation,
                )
            ),
            content_type="application/json",
        )

    def handle_api_tasks(self, request: Request) -> Response:
        """Handle JSON API for all tasks.

        Supports ETag-based conditional requests. If the client sends
        an ``If-None-Match`` header matching the current version, returns
        304 Not Modified.

        Args:
            request: Incoming request.

        Returns:
            JSON response with task list, or 304 if unchanged.
        """
        version = self._get_clock_version()
        etag = f'"v{version}"'

        if request.headers.get("If-None-Match") == etag:
            return Response(status=304, headers={"ETag": etag})

        tasks = self.tracker.get_all_tasks()
        return Response(
            json.dumps([self._task_to_dict(t) for t in tasks]),
            content_type="application/json",
            headers={"ETag": etag, "Cache-Control": "no-cache"},
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
            (r for r in self._get_repo_states() if r.repo_id == repo_id), None
        )
        if repo_state is None:
            return Response("Repository not found", status=404)

        channels_display = (
            ", ".join(
                f"{ch.channel_type}: {ch.info}" for ch in repo_state.channels
            )
            or "(none)"
        )

        crumbs: list[tuple[str, str]] = [(repo_id, "")]

        return Response(
            render_template(
                "pages/repo_detail.html",
                breadcrumbs=crumbs,
                repo=repo_state,
                channels_display=channels_display,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_api_repos(self, request: Request) -> Response:
        """Handle JSON API for repository status.

        Supports ETag-based conditional requests.

        Args:
            request: Incoming request.

        Returns:
            JSON response with repository status list, or 304.
        """
        version = self._get_clock_version()
        etag = f'"v{version}"'

        if request.headers.get("If-None-Match") == etag:
            return Response(status=304, headers={"ETag": etag})

        repos = [
            {
                "repo_id": r.repo_id,
                "status": r.status.value,
                "error_message": r.error_message,
                "error_type": r.error_type,
                "git_repo_url": r.git_repo_url,
                "channels": [
                    {"type": ch.channel_type, "info": ch.info}
                    for ch in r.channels
                ],
                "storage_dir": r.storage_dir,
                "initialized_at": r.initialized_at,
            }
            for r in self._get_repo_states()
        ]
        return Response(
            json.dumps(repos),
            content_type="application/json",
            headers={"ETag": etag, "Cache-Control": "no-cache"},
        )

    def handle_health(self, request: Request) -> Response:
        """Handle health check endpoint.

        Supports ETag-based conditional requests.

        Args:
            request: Incoming request.

        Returns:
            JSON response indicating server health, or 304.
        """
        from airut.dashboard.tracker import BootPhase

        version = self._get_clock_version()
        etag = f'"v{version}"'

        if request.headers.get("If-None-Match") == etag:
            return Response(status=304, headers={"ETag": etag})

        counts = self.tracker.get_counts()
        boot_state = self._get_boot_state()

        # Include repo status in health check
        repo_states = self._get_repo_states()
        live_repos = sum(1 for r in repo_states if r.status.value == "live")
        failed_repos = sum(1 for r in repo_states if r.status.value == "failed")

        # Determine overall status based on boot state
        if boot_state and boot_state.phase == BootPhase.FAILED:
            status = "error"
        elif boot_state and boot_state.phase != BootPhase.READY:
            status = "booting"
        elif live_repos > 0:
            status = "ok"
        else:
            status = "degraded"

        result = cast(
            JsonDict,
            {
                "status": status,
                "tasks": counts,
                "repos": {
                    "live": live_repos,
                    "failed": failed_repos,
                    "total": len(repo_states),
                },
            },
        )

        if boot_state:
            boot_info: JsonDict = {
                "phase": boot_state.phase.value,
                "message": boot_state.message,
            }
            if boot_state.error_message:
                boot_info["error"] = boot_state.error_message
            result["boot"] = boot_info

        return Response(
            json.dumps(result),
            content_type="application/json",
            headers={"ETag": etag, "Cache-Control": "no-cache"},
        )

    def handle_api_status(self, request: Request) -> Response:
        """Handle config reload status endpoint.

        Returns service-level status including config generation counter,
        server reload pending flag, and last reload error.

        Args:
            request: Incoming request.

        Returns:
            JSON response with config reload status.
        """
        if self._status_callback:
            data = self._status_callback()
        else:
            data = cast(
                JsonDict,
                {
                    "config_generation": 0,
                    "config_file_sha256": None,
                    "server_reload_pending": False,
                    "last_reload_error": None,
                },
            )
        return Response(
            json.dumps(data),
            content_type="application/json",
        )

    def handle_config_status(self, request: Request) -> Response:
        """Handle config reload status HTML fragment endpoint.

        Returns an HTML badge showing whether a config reload is pending.
        Used by htmx polling on the dashboard main page.

        Args:
            request: Incoming request.

        Returns:
            HTML response with config status badge (or empty span).
        """
        pending = False
        if self._status_callback:
            data = self._status_callback()
            pending = bool(data.get("server_reload_pending", False))

        if pending:
            html_str = (
                '<span id="config-status"'
                ' class="version-badge config-status reload-pending"'
                ' hx-get="/api/config-status"'
                ' hx-trigger="every 30s" hx-swap="outerHTML"'
                ">restart pending</span>"
            )
        else:
            html_str = (
                '<span id="config-status"'
                ' class="version-badge config-status"'
                ' hx-get="/api/config-status"'
                ' hx-trigger="every 30s" hx-swap="outerHTML"'
                "></span>"
            )

        return Response(
            html_str,
            content_type="text/html; charset=utf-8",
        )

    def _stop_result_html(self, message: str, css_class: str) -> str:
        """Render the stop-result HTML fragment.

        Args:
            message: User-visible message text.
            css_class: CSS modifier class (``"info"`` or ``"error"``).

        Returns:
            Rendered HTML string.
        """
        return render_template(
            "components/stop_result.html",
            message=message,
            css_class=css_class,
        )

    def handle_api_task_stop(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle conversation stop API endpoint.

        Requires a ``X-Requested-With`` header to prevent cross-origin
        CSRF.  Browsers will not send custom headers on a cross-origin
        POST without a CORS preflight, and this server does not set any
        ``Access-Control-Allow-*`` headers, so the preflight is denied.

        Returns an HTML fragment that htmx swaps into ``#stop-area``.

        Args:
            request: Incoming request.
            conversation_id: Conversation ID to stop.

        Returns:
            HTML response with stop result fragment.
        """
        if not request.headers.get("X-Requested-With"):
            return Response(
                json.dumps({"error": "Missing X-Requested-With header"}),
                status=403,
                content_type="application/json",
            )

        if self.stop_callback is None:
            return Response(
                self._stop_result_html(
                    "Stop functionality not available", "error"
                ),
                content_type="text/html; charset=utf-8",
            )

        # Find the executing task for this conversation
        tasks = self.tracker.get_tasks_for_conversation(conversation_id)
        if not tasks:
            return Response(
                self._stop_result_html("Task not found", "error"),
                content_type="text/html; charset=utf-8",
            )

        executing = [t for t in tasks if t.status == TaskStatus.EXECUTING]
        if not executing:
            # Summarize the actual statuses present so the caller
            # understands why stop was rejected.
            statuses = sorted({t.status.value for t in tasks})
            return Response(
                self._stop_result_html(
                    f"Task is not running (statuses: {', '.join(statuses)})",
                    "error",
                ),
                content_type="text/html; charset=utf-8",
            )

        # Call stop callback
        try:
            success = self.stop_callback(conversation_id)
            if success:
                return Response(
                    self._stop_result_html("Stop signal sent", "info"),
                    content_type="text/html; charset=utf-8",
                )
            else:
                return Response(
                    self._stop_result_html("Task not running", "error"),
                    content_type="text/html; charset=utf-8",
                )
        except Exception as e:
            logger.exception("Failed to stop task %s: %s", conversation_id, e)
            return Response(
                self._stop_result_html(f"Failed to stop task: {e}", "error"),
                content_type="text/html; charset=utf-8",
            )

    def handle_task_events_stream(
        self, request: Request, task_id: str
    ) -> Response:
        """Handle task-scoped SSE state stream endpoint.

        Resolves the task and delegates to :meth:`handle_events_stream`
        with the ``task_id`` query parameter set.  This provides a
        URL that can be gated per-task by a reverse proxy
        (``/api/task/<id>/events/stream``).

        Args:
            request: Incoming request.
            task_id: Task ID to stream events for.

        Returns:
            SSE streaming response, or error response.
        """
        task = self.tracker.get_task(task_id)
        if task is None:
            return Response(
                json.dumps({"error": "Task not found"}),
                status=404,
                content_type="application/json",
            )

        # Build a new request with task_id and format injected as
        # query params, avoiding mutation of the original request.
        args = dict(request.args)
        args["task_id"] = task_id
        args["format"] = "html"
        environ = dict(request.environ)
        environ["QUERY_STRING"] = urlencode(args)
        return self.handle_events_stream(Request(environ))

    def handle_events_stream(self, request: Request) -> Response:
        """Handle SSE state stream endpoint.

        Pushes composite state snapshots whenever any versioned state
        changes. Falls back to 429 when the SSE connection limit is
        reached.

        Args:
            request: Incoming request.

        Returns:
            SSE streaming response, or 429 if at connection limit.
        """
        if self._clock is None:
            return Response(
                json.dumps({"error": "SSE not available"}),
                status=503,
                content_type="application/json",
            )

        if not self._sse_manager.try_acquire():
            return Response(
                json.dumps({"error": "Too many SSE connections"}),
                status=429,
                content_type="application/json",
                headers={"Retry-After": "5"},
            )

        # Parse client version from query string or Last-Event-ID header
        client_version = 0
        last_event_id = request.headers.get("Last-Event-ID")
        if last_event_id is not None:
            try:
                client_version = int(last_event_id)
            except ValueError:
                pass
        else:
            version_param = request.args.get("version")
            if version_param is not None:
                try:
                    client_version = int(version_param)
                except ValueError:
                    pass

        clock = self._clock
        html_mode = request.args.get("format") == "html"
        task_id = request.args.get("task_id")
        repo_id = request.args.get("repo_id")

        def generate() -> Iterable[str]:
            try:
                yield from sse_state_stream(
                    clock,
                    self.tracker,
                    self._boot_store,
                    self._repos_store,
                    client_version,
                    html_mode=html_mode,
                    task_id=task_id,
                    repo_id=repo_id,
                )
            finally:
                self._sse_manager.release()

        return Response(
            generate(),
            content_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    def handle_events_log_stream(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle SSE stream for a conversation's event log.

        Streams new events from ``events.jsonl`` as they are appended.
        Sends a terminal ``done`` event when the task completes.

        Args:
            request: Incoming request.
            conversation_id: Conversation to stream events for.

        Returns:
            SSE streaming response, or error response.
        """
        conversation_dir = self._find_conversation_dir(conversation_id)
        if conversation_dir is None:
            return Response(
                json.dumps({"error": "Conversation not found"}),
                status=404,
                content_type="application/json",
            )

        if not self._sse_manager.try_acquire():
            return Response(
                json.dumps({"error": "Too many SSE connections"}),
                status=429,
                content_type="application/json",
                headers={"Retry-After": "5"},
            )

        client_offset = 0
        last_event_id = request.headers.get("Last-Event-ID")
        if last_event_id is not None:
            try:
                client_offset = int(last_event_id)
            except ValueError:
                pass
        else:
            offset_param = request.args.get("offset")
            if offset_param is not None:
                try:
                    client_offset = int(offset_param)
                except ValueError:
                    pass

        event_log = EventLog(conversation_dir)

        def generate() -> Iterable[str]:
            try:
                yield from sse_events_log_stream(
                    event_log,
                    self.tracker,
                    conversation_id,
                    client_offset,
                )
            finally:
                self._sse_manager.release()

        return Response(
            generate(),
            content_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    def handle_network_log_stream(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle SSE stream for a conversation's network log.

        Streams new lines from ``network-sandbox.log`` as they are
        appended. Sends a terminal ``done`` event when the task
        completes.

        Args:
            request: Incoming request.
            conversation_id: Conversation to stream network logs for.

        Returns:
            SSE streaming response, or error response.
        """
        conversation_dir = self._find_conversation_dir(conversation_id)
        if conversation_dir is None:
            return Response(
                json.dumps({"error": "Conversation not found"}),
                status=404,
                content_type="application/json",
            )

        if not self._sse_manager.try_acquire():
            return Response(
                json.dumps({"error": "Too many SSE connections"}),
                status=429,
                content_type="application/json",
                headers={"Retry-After": "5"},
            )

        client_offset = 0
        last_event_id = request.headers.get("Last-Event-ID")
        if last_event_id is not None:
            try:
                client_offset = int(last_event_id)
            except ValueError:
                pass
        else:
            offset_param = request.args.get("offset")
            if offset_param is not None:
                try:
                    client_offset = int(offset_param)
                except ValueError:
                    pass

        network_log = NetworkLog(conversation_dir / NETWORK_LOG_FILENAME)

        def generate() -> Iterable[str]:
            try:
                yield from sse_network_log_stream(
                    network_log,
                    self.tracker,
                    conversation_id,
                    client_offset,
                )
            finally:
                self._sse_manager.release()

        return Response(
            generate(),
            content_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    def handle_api_events_poll(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle polling endpoint for a conversation's event log.

        Returns new events since the given offset as pre-rendered HTML.
        Supports ETag-based conditional requests using the byte offset.

        Args:
            request: Incoming request.
            conversation_id: Conversation to poll events for.

        Returns:
            JSON response with ``{offset, html, done}``, or 304.
        """
        conversation_dir = self._find_conversation_dir(conversation_id)
        if conversation_dir is None:
            return Response(
                json.dumps({"error": "Conversation not found"}),
                status=404,
                content_type="application/json",
            )

        client_offset = 0
        offset_param = request.args.get("offset")
        if offset_param is not None:
            try:
                client_offset = int(offset_param)
            except ValueError:
                pass

        event_log = EventLog(conversation_dir)
        events, new_offset = event_log.tail(client_offset)

        etag = f'"o{new_offset}"'
        if not events and request.headers.get("If-None-Match") == etag:
            return Response(status=304, headers={"ETag": etag})

        html = render_events_html(events) if events else ""

        # Check if all tasks for this conversation are done
        tasks = self.tracker.get_tasks_for_conversation(conversation_id)
        done = not tasks or all(t.status == TaskStatus.COMPLETED for t in tasks)

        return Response(
            json.dumps({"offset": new_offset, "html": html, "done": done}),
            content_type="application/json",
            headers={"ETag": etag, "Cache-Control": "no-cache"},
        )

    def handle_api_network_poll(
        self, request: Request, conversation_id: str
    ) -> Response:
        """Handle polling endpoint for a conversation's network log.

        Returns new network log lines since the given offset as
        pre-rendered HTML. Supports ETag-based conditional requests.

        Args:
            request: Incoming request.
            conversation_id: Conversation to poll network logs for.

        Returns:
            JSON response with ``{offset, html, done}``, or 304.
        """
        conversation_dir = self._find_conversation_dir(conversation_id)
        if conversation_dir is None:
            return Response(
                json.dumps({"error": "Conversation not found"}),
                status=404,
                content_type="application/json",
            )

        client_offset = 0
        offset_param = request.args.get("offset")
        if offset_param is not None:
            try:
                client_offset = int(offset_param)
            except ValueError:
                pass

        network_log = NetworkLog(conversation_dir / NETWORK_LOG_FILENAME)
        lines, new_offset = network_log.tail(client_offset)

        etag = f'"o{new_offset}"'
        if not lines and request.headers.get("If-None-Match") == etag:
            return Response(status=304, headers={"ETag": etag})

        html = render_network_lines_html(lines) if lines else ""

        # Check if all tasks for this conversation are done
        tasks = self.tracker.get_tasks_for_conversation(conversation_id)
        done = not tasks or all(t.status == TaskStatus.COMPLETED for t in tasks)

        return Response(
            json.dumps({"offset": new_offset, "html": html, "done": done}),
            content_type="application/json",
            headers={"ETag": etag, "Cache-Control": "no-cache"},
        )

    def handle_api_tracker(self, request: Request) -> Response:
        """Handle JSON API for full task tracker state.

        Returns the complete tracker state including all tasks with their
        full details, counts by status, and version clock value.  Designed
        for integration tests and monitoring tools that need a single
        atomic snapshot of the tracker.

        Supports ETag-based conditional requests.

        Args:
            request: Incoming request.

        Returns:
            JSON response with tracker snapshot, or 304 if unchanged.
        """
        version = self._get_clock_version()
        etag = f'"v{version}"'

        if request.headers.get("If-None-Match") == etag:
            return Response(status=304, headers={"ETag": etag})

        snapshot = self.tracker.get_snapshot()
        tasks_data = [
            {
                "task_id": t.task_id,
                "conversation_id": t.conversation_id,
                "display_title": t.display_title,
                "repo_id": t.repo_id,
                "sender": t.sender,
                "authenticated_sender": t.authenticated_sender,
                "status": t.status.value,
                "completion_reason": (
                    t.completion_reason.value if t.completion_reason else None
                ),
                "completion_detail": t.completion_detail,
                "queued_at": t.queued_at,
                "started_at": t.started_at,
                "completed_at": t.completed_at,
                "model": t.model,
                "reply_index": t.reply_index,
            }
            for t in snapshot.value
        ]

        counts = self.tracker.get_counts()

        data = {
            "version": snapshot.version,
            "counts": counts,
            "tasks": tasks_data,
        }

        return Response(
            json.dumps(data),
            content_type="application/json",
            headers={"ETag": etag, "Cache-Control": "no-cache"},
        )

    def handle_static(self, request: Request, path: str) -> Response:
        """Handle static file requests.

        Serves files from the static/ package directory with
        content-hash ETags for cache validation.

        Args:
            request: Incoming request.
            path: File path relative to static/.

        Returns:
            File response with content-type and ETag, or 404.
        """
        result = get_static_file(path)
        if result is None:
            return Response("Not Found", status=404)

        data, content_type, etag = result

        # Check for conditional request
        if request.headers.get("If-None-Match") == etag:
            return Response(
                status=304,
                headers={"ETag": etag},
            )

        return Response(
            data,
            content_type=content_type,
            headers={
                "ETag": etag,
                "Cache-Control": "public, max-age=3600, immutable",
            },
        )

    def _render_task_detail_page(
        self,
        task: TaskState,
        conversation: ConversationMetadata | None,
    ) -> str:
        """Render the task detail page using Jinja2 templates.

        Prepares context variables (model, cost, turns, reply section)
        and renders the ``pages/task_detail.html`` template.

        Args:
            task: Task to display.
            conversation: Optional conversation metadata.

        Returns:
            Rendered HTML string.
        """
        model_display = task.model
        if not model_display and conversation:
            model_display = conversation.model
        model_display = model_display or "-"

        cost_display = "-"
        turns_display = "-"
        if (
            conversation
            and task.reply_index is not None
            and task.reply_index < len(conversation.replies)
        ):
            reply = conversation.replies[task.reply_index]
            cost_display = f"${reply.total_cost_usd:.4f}"
            turns_display = str(reply.num_turns)

        replies_section = render_single_reply_section(task, conversation)
        is_active = task.status in ACTIVE_STATUSES

        # Build breadcrumbs
        crumbs: list[tuple[str, str]] = []
        if task.repo_id:
            crumbs.append((task.repo_id, f"/repo/{task.repo_id}"))
        if task.conversation_id:
            crumbs.append(
                (
                    f"Conversation {task.conversation_id}",
                    f"/conversation/{task.conversation_id}",
                )
            )
        crumbs.append((f"Task {task.task_id}", ""))

        return render_template(
            "pages/task_detail.html",
            breadcrumbs=crumbs,
            task=task,
            todos=task.todos,
            is_active=is_active,
            model_display=model_display,
            cost_display=cost_display,
            turns_display=turns_display,
            replies_section=replies_section,
        )

    def _version_url(self) -> str:
        """Compute the GitHub URL for the current version.

        If a clean version tag is set (no ``-N-gSHA`` suffix), links to
        the GitHub release page.  Otherwise links to the commit page.

        Returns:
            GitHub URL string, or empty string if no version info.
        """
        if not self.version_info:
            return ""
        v = self.version_info.version
        # Exact tag (e.g. "v0.7.0") → release page
        if v and "-" not in v:
            return github_release_url(v)
        # Non-exact or no tag → commit page
        return github_commit_url(self.version_info.git_sha_full)

    def _get_clock_version(self) -> int:
        """Get the current version clock value.

        Returns:
            Current version number, or 0 if no clock is configured.
        """
        if self._clock is None:
            return 0
        return self._clock.version

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

    def _resolve_task_by_id(
        self, task_id: str
    ) -> tuple[TaskState, ConversationMetadata | None] | None:
        """Look up a task by ID from memory, falling back to disk.

        First checks the in-memory tracker.  If the task is not found
        and the *task_id* uses the ``disk-{conversation_id}`` format
        (see :func:`parse_disk_task_id`), attempts to load the task
        from the conversation directory on disk.

        Args:
            task_id: Task ID to resolve.

        Returns:
            Tuple of (TaskState, ConversationMetadata or None) if
            found, None otherwise.
        """
        task = self.tracker.get_task(task_id)
        if task is not None:
            conversation = (
                self._load_conversation(task.conversation_id)
                if task.conversation_id
                else None
            )
            return task, conversation

        # Fall back to disk for synthetic disk-{conversation_id} IDs
        conversation_id = parse_disk_task_id(task_id)
        if conversation_id is not None:
            return self._load_task_from_disk(conversation_id)

        return None

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

        has_errors = any(r.is_error for r in conversation.replies)
        task = TaskState(
            task_id=make_disk_task_id(conversation_id),
            conversation_id=conversation_id,
            display_title=f"[Past conversation {conversation_id}]",
            status=TaskStatus.COMPLETED,
            completion_reason=(
                CompletionReason.EXECUTION_FAILED
                if has_errors
                else CompletionReason.SUCCESS
            ),
            queued_at=completed_at or 0.0,
            started_at=completed_at,
            completed_at=completed_at,
            model=conversation.model,
        )

        return task, conversation

    def _load_task_with_conversation(
        self, conversation_id: str
    ) -> tuple[TaskState, ConversationMetadata | None] | None:
        """Load task and conversation metadata from memory or disk.

        Tries to load from in-memory tracker first (using
        ``get_tasks_for_conversation`` to find the most relevant task),
        then falls back to disk for past tasks.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            Tuple of (TaskState, ConversationMetadata or None) if found,
            None if task not found in memory or on disk.
        """
        tasks = self.tracker.get_tasks_for_conversation(conversation_id)

        if tasks:
            # Prefer EXECUTING over other active states, then any
            # active over completed, then fall back to newest.
            executing = next(
                (t for t in tasks if t.status == TaskStatus.EXECUTING),
                None,
            )
            task = executing or next(
                (t for t in tasks if t.status in ACTIVE_STATUSES),
                tasks[0],
            )
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
        event_groups: list[list[StreamEvent]] | None = None,
    ) -> JsonDict:
        """Convert TaskState to JSON-serializable dict.

        Args:
            task: Task to convert.
            include_conversation: If True, include conversation metadata.
            conversation: Pre-loaded conversation metadata.
            event_groups: Pre-loaded event groups from EventLog.

        Returns:
            Dict representation of task.
        """
        result: JsonDict = {
            "task_id": task.task_id,
            "conversation_id": task.conversation_id,
            "display_title": task.display_title,
            "repo_id": task.repo_id,
            "status": task.status.value,
            "completion_reason": (
                task.completion_reason.value if task.completion_reason else None
            ),
            "completion_detail": task.completion_detail,
            "sender": task.sender,
            "authenticated_sender": task.authenticated_sender,
            "queued_at": task.queued_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "model": task.model,
            "reply_index": task.reply_index,
            "queue_duration": task.queue_duration(),
            "execution_duration": task.execution_duration(),
            "total_duration": task.total_duration(),
        }
        if task.todos is not None:
            result["todos"] = [t.to_dict() for t in task.todos]

        if include_conversation:
            if conversation is None:
                conversation = self._load_conversation(task.conversation_id)
            if conversation:
                replies_data = []
                for i, r in enumerate(conversation.replies):
                    reply_dict: JsonDict = {
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
