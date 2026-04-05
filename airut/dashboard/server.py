# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Dashboard HTTP server for email gateway monitoring.

Provides a WSGI application that serves the dashboard web interface
for viewing task queue status and history.
"""

import json
import logging
import os
import select
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING
from wsgiref.types import WSGIEnvironment

from airut._json_types import JsonDict


if TYPE_CHECKING:
    from werkzeug.wrappers.response import StartResponse

from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule
from werkzeug.serving import BaseWSGIServer, make_server
from werkzeug.wrappers import Request, Response

from airut.claude_output.types import StreamEvent
from airut.config.snapshot import ConfigSnapshot
from airut.config.source import ConfigSource
from airut.conversation import ConversationMetadata
from airut.dashboard.formatters import VersionInfo
from airut.dashboard.handlers import RequestHandlers
from airut.dashboard.handlers_config import ConfigEditorHandlers
from airut.dashboard.sse import SSEConnectionManager
from airut.dashboard.tracker import BootState, RepoState, TaskState, TaskTracker
from airut.dashboard.versioned import VersionClock, VersionedStore
from airut.version import GitVersionInfo


logger = logging.getLogger(__name__)

#: Security headers applied to every dashboard response.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    ),
}


def _add_security_headers(response: Response) -> None:
    """Add security headers to a response.

    Applies defense-in-depth headers (CSP, X-Frame-Options, etc.)
    to every response regardless of whether a reverse proxy also
    sets them.
    """
    for name, value in _SECURITY_HEADERS.items():
        response.headers[name] = value


def _is_loopback(host: str) -> bool:
    """Check whether *host* is a common loopback address.

    Returns ``True`` for ``127.0.0.1``, ``::1``, and ``localhost``.
    This is a conservative check — non-standard loopback addresses like
    ``127.0.0.2`` (valid on Linux) will not match and will trigger the
    startup warning.  This is intentional: false-positive warnings are
    preferable to silently accepting a misconfigured bind address.
    """
    return host in ("127.0.0.1", "::1", "localhost")


class DashboardServer:
    """WSGI dashboard server for task monitoring.

    Runs in a background thread and serves the dashboard web interface.
    """

    def __init__(
        self,
        tracker: TaskTracker,
        host: str = "127.0.0.1",
        port: int = 5200,
        version_info: VersionInfo | None = None,
        work_dirs: Callable[[], list[Path]] | None = None,
        stop_callback: Callable[[str], bool] | None = None,
        boot_store: VersionedStore[BootState] | None = None,
        repos_store: VersionedStore[tuple[RepoState, ...]] | None = None,
        clock: VersionClock | None = None,
        git_version_info: GitVersionInfo | None = None,
        status_callback: Callable[[], dict[str, object]] | None = None,
        get_config_snapshot: Callable[[], ConfigSnapshot | None] | None = None,
        get_config_generation: Callable[[], int] | None = None,
        get_config_source: Callable[[], ConfigSource | None] | None = None,
    ) -> None:
        """Initialize dashboard server.

        Args:
            tracker: Task tracker to query for state.
            host: Host to bind to.
            port: Port to bind to.
            version_info: Optional version information to display.
            work_dirs: Callable returning directories where conversation
                data is stored (one per repo).  Called on each request.
            stop_callback: Optional callable to stop an execution.
                Should accept conversation_id and return bool.
            boot_store: Versioned boot state store.
            repos_store: Versioned repo states store.
            clock: Shared version clock for SSE streaming.
            git_version_info: Git version info for upstream update checks.
            status_callback: Optional callable returning config reload
                status dict.
            get_config_snapshot: Returns the current live ConfigSnapshot.
            get_config_generation: Returns the current config generation.
            get_config_source: Returns the YamlConfigSource for saving.
        """
        self.tracker = tracker
        self.host = host
        self.port = port
        self.version_info = version_info
        self.stop_callback = stop_callback
        self._server: BaseWSGIServer | None = None
        self._thread: threading.Thread | None = None
        self._sse_manager = SSEConnectionManager()
        self._wakeup_r: int = -1
        self._wakeup_w: int = -1

        # Initialize request handlers
        self._handlers = RequestHandlers(
            tracker=tracker,
            version_info=version_info,
            work_dirs=work_dirs,
            stop_callback=stop_callback,
            boot_store=boot_store,
            repos_store=repos_store,
            clock=clock,
            sse_manager=self._sse_manager,
            git_version_info=git_version_info,
            status_callback=status_callback,
        )

        # Config editor handlers
        self._config_handlers = ConfigEditorHandlers(
            get_snapshot=get_config_snapshot or (lambda: None),
            get_generation=get_config_generation or (lambda: 0),
            get_config_source=get_config_source or (lambda: None),
        )

        self._url_map = Map(
            [
                Rule("/", endpoint="index"),
                Rule("/favicon.svg", endpoint="favicon"),
                Rule("/static/<path:path>", endpoint="static"),
                Rule("/api/version", endpoint="version"),
                Rule("/api/update", endpoint="update"),
                Rule("/repo/<repo_id>", endpoint="repo_detail"),
                Rule(
                    "/task/<task_id>",
                    endpoint="task_detail_by_id",
                ),
                Rule(
                    "/conversation/<conversation_id>",
                    endpoint="conversation_detail",
                ),
                Rule(
                    "/task/<task_id>/actions",
                    endpoint="task_actions_by_id",
                ),
                Rule(
                    "/task/<task_id>/network",
                    endpoint="task_network_by_id",
                ),
                Rule(
                    "/conversation/<conversation_id>/actions",
                    endpoint="task_actions",
                ),
                Rule(
                    "/conversation/<conversation_id>/network",
                    endpoint="task_network",
                ),
                Rule("/api/conversations", endpoint="api_tasks"),
                Rule(
                    "/api/task/<task_id>",
                    endpoint="api_task_by_id",
                ),
                Rule(
                    "/api/conversation/<conversation_id>",
                    endpoint="api_task",
                ),
                Rule(
                    "/api/conversation/<conversation_id>/stop",
                    endpoint="api_task_stop",
                    methods=["POST"],
                ),
                Rule("/api/repos", endpoint="api_repos"),
                Rule("/api/events/stream", endpoint="events_stream"),
                Rule(
                    "/api/task/<task_id>/events/stream",
                    endpoint="task_events_stream",
                ),
                Rule(
                    "/api/conversation/<conversation_id>/events/stream",
                    endpoint="events_log_stream",
                ),
                Rule(
                    "/api/conversation/<conversation_id>/events/poll",
                    endpoint="api_events_poll",
                ),
                Rule(
                    "/api/conversation/<conversation_id>/network/stream",
                    endpoint="network_log_stream",
                ),
                Rule(
                    "/api/conversation/<conversation_id>/network/poll",
                    endpoint="api_network_poll",
                ),
                Rule("/api/health", endpoint="health"),
                Rule("/api/config-status", endpoint="api_config_status"),
                Rule("/api/status", endpoint="api_status"),
                Rule("/api/tracker", endpoint="api_tracker"),
                # Config editor routes
                Rule("/config", endpoint="config_page"),
                Rule(
                    "/config/repos/<repo_id>",
                    endpoint="config_repo_page",
                ),
                Rule(
                    "/api/config/field",
                    endpoint="api_config_field",
                    methods=["PATCH"],
                ),
                Rule(
                    "/api/config/add",
                    endpoint="api_config_add",
                    methods=["POST"],
                ),
                Rule(
                    "/api/config/remove",
                    endpoint="api_config_remove",
                    methods=["POST"],
                ),
                Rule("/api/config/diff", endpoint="api_config_diff"),
                Rule(
                    "/api/config/save",
                    endpoint="api_config_save",
                    methods=["POST"],
                ),
                Rule(
                    "/api/config/discard",
                    endpoint="api_config_discard",
                    methods=["POST"],
                ),
            ]
        )

        # Map endpoints to handler methods
        self._endpoint_handlers: dict[str, Callable[..., Response]] = {
            "index": self._handlers.handle_index,
            "favicon": self._handlers.handle_favicon,
            "static": self._handlers.handle_static,
            "version": self._handlers.handle_version,
            "update": self._handlers.handle_update,
            "repo_detail": self._handlers.handle_repo_detail,
            "task_detail_by_id": (self._handlers.handle_task_detail_by_id),
            "conversation_detail": (self._handlers.handle_conversation_detail),
            "task_actions_by_id": self._handlers.handle_task_actions_by_id,
            "task_actions": self._handlers.handle_task_actions,
            "task_network_by_id": self._handlers.handle_task_network_by_id,
            "task_network": self._handlers.handle_task_network,
            "api_tasks": self._handlers.handle_api_tasks,
            "api_task_by_id": self._handlers.handle_api_task_by_id,
            "api_task": self._handlers.handle_api_task,
            "api_task_stop": self._handlers.handle_api_task_stop,
            "api_repos": self._handlers.handle_api_repos,
            "events_stream": self._handlers.handle_events_stream,
            "task_events_stream": self._handlers.handle_task_events_stream,
            "events_log_stream": (self._handlers.handle_events_log_stream),
            "api_events_poll": self._handlers.handle_api_events_poll,
            "network_log_stream": (self._handlers.handle_network_log_stream),
            "api_network_poll": self._handlers.handle_api_network_poll,
            "health": self._handlers.handle_health,
            "api_config_status": self._handlers.handle_config_status,
            "api_status": self._handlers.handle_api_status,
            "api_tracker": self._handlers.handle_api_tracker,
            # Config editor endpoints
            "config_page": self._config_handlers.handle_config_page,
            "config_repo_page": self._config_handlers.handle_repo_page,
            "api_config_field": self._config_handlers.handle_field_patch,
            "api_config_add": self._config_handlers.handle_add,
            "api_config_remove": self._config_handlers.handle_remove,
            "api_config_diff": self._config_handlers.handle_diff,
            "api_config_save": self._config_handlers.handle_save,
            "api_config_discard": self._config_handlers.handle_discard,
        }

    def start(self) -> None:
        """Start the dashboard server in a background thread."""
        server = make_server(
            self.host,
            self.port,
            self._wsgi_app,
            threaded=True,
        )
        self._server = server
        self._wakeup_r, self._wakeup_w = os.pipe()
        self._thread = threading.Thread(
            target=self._serve,
            daemon=True,
            name="DashboardServer",
        )
        self._thread.start()
        logger.info(
            "Dashboard server started at http://%s:%d/",
            self.host,
            self.port,
        )
        if not _is_loopback(self.host):
            logger.warning(
                "Dashboard bound to non-loopback address %s — "
                "ensure a reverse proxy with authentication is in front",
                self.host,
            )

    def stop(self) -> None:
        """Stop the dashboard server."""
        if self._wakeup_w >= 0:
            try:
                os.write(self._wakeup_w, b"\x00")
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        if self._server:
            self._server.server_close()
            self._server = None
        self._close_pipe()
        logger.info("Dashboard server stopped")

    def _serve(self) -> None:
        """Select-based serve loop with instant wakeup on stop.

        Blocks on ``select()`` waiting for either an incoming connection
        on the server socket or a byte on the wakeup pipe (sent by
        ``stop()``).  This eliminates the polling overhead of the stdlib
        ``serve_forever(poll_interval=...)`` loop.
        """
        server = self._server
        assert server is not None
        server_fd = server.fileno()
        wakeup_r = self._wakeup_r
        try:
            while True:
                readable, _, _ = select.select([server_fd, wakeup_r], [], [])
                if wakeup_r in readable:
                    break
                if server_fd in readable:
                    server._handle_request_noblock()  # type: ignore[attr-defined]  # inherited from BaseServer  # ty:ignore[unresolved-attribute]
        except OSError:
            pass

    def _close_pipe(self) -> None:
        """Close wakeup pipe file descriptors (idempotent)."""
        for fd in (self._wakeup_r, self._wakeup_w):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._wakeup_r = -1
        self._wakeup_w = -1

    def _wsgi_app(
        self,
        environ: WSGIEnvironment,
        start_response: "StartResponse",
    ) -> Iterable[bytes]:
        """WSGI application entry point.

        Args:
            environ: WSGI environ dict.
            start_response: WSGI start_response callable.

        Returns:
            Response body iterable.
        """
        request = Request(environ)
        response = self._dispatch(request)
        return response(environ, start_response)

    def _dispatch(self, request: Request) -> Response:
        """Route request to appropriate handler.

        Args:
            request: Incoming request.

        Returns:
            Response to send.
        """
        adapter = self._url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            handler = self._endpoint_handlers[endpoint]
            response = handler(request, **values)
        except NotFound:
            response = Response("Not Found", status=404)
        except Exception:
            logger.exception("Error handling request %s", request.path)
            if request.path.startswith("/api/"):
                response = Response(
                    json.dumps({"error": "Internal server error"}),
                    status=500,
                    content_type="application/json",
                )
            else:
                response = Response("Internal Server Error", status=500)

        _add_security_headers(response)
        return response

    # Expose internal methods for tests
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
        return self._handlers._task_to_dict(
            task, include_conversation, conversation, event_groups
        )

    def _load_conversation(
        self, conversation_id: str
    ) -> ConversationMetadata | None:
        """Load conversation metadata.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            ConversationMetadata if available, None otherwise.
        """
        return self._handlers._load_conversation(conversation_id)

    def _load_task_from_disk(
        self, conversation_id: str
    ) -> tuple[TaskState, ConversationMetadata] | None:
        """Load a task from disk when not in memory.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            Tuple of (TaskState, ConversationMetadata) if found,
            None otherwise.
        """
        return self._handlers._load_task_from_disk(conversation_id)

    def _resolve_task_by_id(
        self, task_id: str
    ) -> tuple[TaskState, ConversationMetadata | None] | None:
        """Look up a task by ID from memory, falling back to disk.

        Args:
            task_id: Task ID to resolve.

        Returns:
            Tuple of (TaskState, ConversationMetadata or None) if found,
            None otherwise.
        """
        return self._handlers._resolve_task_by_id(task_id)

    def _load_task_with_conversation(
        self, conversation_id: str
    ) -> tuple[TaskState, ConversationMetadata | None] | None:
        """Load task and conversation from memory or disk.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            Tuple of (TaskState, ConversationMetadata or None) if found,
            None if not found.
        """
        return self._handlers._load_task_with_conversation(conversation_id)
