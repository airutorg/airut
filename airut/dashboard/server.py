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
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING
from wsgiref.types import WSGIEnvironment

from airut._json_types import JsonDict
from airut.config.snapshot import ConfigSnapshot
from airut.config.source import ConfigSource


if TYPE_CHECKING:
    from werkzeug.wrappers.response import StartResponse

from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule
from werkzeug.serving import BaseWSGIServer, make_server
from werkzeug.wrappers import Request, Response

from airut.claude_output.types import StreamEvent
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
        "style-src 'self'; "
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
        config_callback: (
            Callable[[], ConfigSnapshot[object] | None] | None
        ) = None,
        config_generation_callback: Callable[[], int] | None = None,
        config_source_callback: (
            Callable[[], ConfigSource | None] | None
        ) = None,
        config_vars_callback: (Callable[[], dict[str, object]] | None) = None,
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
            config_callback: Returns current ConfigSnapshot.
            config_generation_callback: Returns current config_generation.
            config_source_callback: Returns the ConfigSource.
            config_vars_callback: Returns resolved vars table.
        """
        self.tracker = tracker
        self.host = host
        self.port = port
        self.version_info = version_info
        self.stop_callback = stop_callback
        self._server: BaseWSGIServer | None = None
        self._thread: threading.Thread | None = None
        self._sse_manager = SSEConnectionManager()

        # Config editor is available when callbacks are provided
        self._config_editor_enabled = config_callback is not None

        # Initialize config editor handlers
        self._config_handlers: ConfigEditorHandlers | None = None
        if config_callback is not None:
            self._config_handlers = ConfigEditorHandlers(
                config_callback=config_callback,
                generation_callback=config_generation_callback or (lambda: 0),
                config_source_callback=config_source_callback or (lambda: None),
                vars_callback=config_vars_callback or (lambda: {}),
            )

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
            config_editor_enabled=self._config_editor_enabled,
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
                Rule("/api/status", endpoint="api_status"),
                Rule("/api/tracker", endpoint="api_tracker"),
                Rule("/config", endpoint="config_page"),
                Rule(
                    "/api/config",
                    endpoint="api_config_save",
                    methods=["POST"],
                ),
                Rule(
                    "/api/config/add",
                    endpoint="api_config_add",
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
            "api_status": self._handlers.handle_api_status,
            "api_tracker": self._handlers.handle_api_tracker,
            "config_page": self._handle_config_page,
            "api_config_save": self._handle_config_save,
            "api_config_add": self._handle_config_add,
        }

    def start(self) -> None:
        """Start the dashboard server in a background thread."""
        self._server = make_server(
            self.host,
            self.port,
            self._wsgi_app,
            threaded=True,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
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
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Dashboard server stopped")

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

    # ── Config editor delegates ──────────────────────────────────

    def _handle_config_page(self, request: Request, **kw: object) -> Response:
        """Delegate to config editor handler or return 404."""
        if self._config_handlers is None:
            return Response("Config editor not available", status=404)
        return self._config_handlers.handle_config_page(request)

    def _handle_config_save(self, request: Request, **kw: object) -> Response:
        """Delegate to config editor save handler."""
        if self._config_handlers is None:
            return Response("Config editor not available", status=404)
        return self._config_handlers.handle_config_save(request)

    def _handle_config_add(self, request: Request, **kw: object) -> Response:
        """Delegate to config editor add-fragment handler."""
        if self._config_handlers is None:
            return Response("Config editor not available", status=404)
        return self._config_handlers.handle_config_add_fragment(request)
