# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Dashboard HTTP server for email gateway monitoring.

Provides a WSGI application that serves the dashboard web interface
for viewing task queue status and history.
"""

import logging
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from werkzeug.wrappers.response import StartResponse

from werkzeug.exceptions import NotFound
from werkzeug.routing import Map, Rule
from werkzeug.serving import make_server
from werkzeug.wrappers import Request, Response

from lib.dashboard.formatters import VersionInfo
from lib.dashboard.handlers import RequestHandlers
from lib.dashboard.tracker import RepoState, TaskTracker


logger = logging.getLogger(__name__)


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
        work_dirs: list[Path] | None = None,
        stop_callback: Any = None,
        repo_states: list[RepoState] | None = None,
    ) -> None:
        """Initialize dashboard server.

        Args:
            tracker: Task tracker to query for state.
            host: Host to bind to.
            port: Port to bind to.
            version_info: Optional version information to display.
            work_dirs: Directories where conversation sessions are stored
                (one per repo).  If provided, enables session data display.
            stop_callback: Optional callable to stop an execution.
                Should accept conversation_id and return bool.
            repo_states: List of repository states to display on dashboard.
        """
        self.tracker = tracker
        self.host = host
        self.port = port
        self.version_info = version_info
        self.work_dirs = work_dirs or []
        self.stop_callback = stop_callback
        self.repo_states = repo_states or []
        self._server: Any = None
        self._thread: threading.Thread | None = None

        # Initialize request handlers
        self._handlers = RequestHandlers(
            tracker=tracker,
            version_info=version_info,
            work_dirs=self.work_dirs,
            stop_callback=stop_callback,
            repo_states=self.repo_states,
        )

        self._url_map = Map(
            [
                Rule("/", endpoint="index"),
                Rule("/favicon.svg", endpoint="favicon"),
                Rule("/.version", endpoint="version"),
                Rule("/repo/<repo_id>", endpoint="repo_detail"),
                Rule("/task/<conversation_id>", endpoint="task_detail"),
                Rule(
                    "/task/<conversation_id>/session",
                    endpoint="task_session_json",
                ),
                Rule(
                    "/task/<conversation_id>/actions",
                    endpoint="task_actions",
                ),
                Rule(
                    "/task/<conversation_id>/network",
                    endpoint="task_network",
                ),
                Rule("/api/tasks", endpoint="api_tasks"),
                Rule("/api/task/<conversation_id>", endpoint="api_task"),
                Rule(
                    "/api/task/<conversation_id>/stop",
                    endpoint="api_task_stop",
                    methods=["POST"],
                ),
                Rule("/api/repos", endpoint="api_repos"),
                Rule("/health", endpoint="health"),
            ]
        )

        # Map endpoints to handler methods
        self._endpoint_handlers = {
            "index": self._handlers.handle_index,
            "favicon": self._handlers.handle_favicon,
            "version": self._handlers.handle_version,
            "repo_detail": self._handlers.handle_repo_detail,
            "task_detail": self._handlers.handle_task_detail,
            "task_session_json": self._handlers.handle_task_session_json,
            "task_actions": self._handlers.handle_task_actions,
            "task_network": self._handlers.handle_task_network,
            "api_tasks": self._handlers.handle_api_tasks,
            "api_task": self._handlers.handle_api_task,
            "api_task_stop": self._handlers.handle_api_task_stop,
            "api_repos": self._handlers.handle_api_repos,
            "health": self._handlers.handle_health,
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

    def stop(self) -> None:
        """Stop the dashboard server."""
        if self._server:
            self._server.shutdown()
            logger.info("Dashboard server stopped")

    def _wsgi_app(
        self,
        environ: dict[str, Any],
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
            return handler(request, **values)
        except NotFound:
            return Response("Not Found", status=404)
        except Exception:
            logger.exception("Error handling request %s", request.path)
            return Response("Internal Server Error", status=500)

    # Expose internal methods for tests
    def _task_to_dict(
        self,
        task: Any,
        include_session: bool = False,
        session: Any = None,
    ) -> dict[str, Any]:
        """Convert TaskState to JSON-serializable dict.

        Args:
            task: Task to convert.
            include_session: If True, include session metadata.
            session: Pre-loaded session metadata.

        Returns:
            Dict representation of task.
        """
        return self._handlers._task_to_dict(task, include_session, session)

    def _load_session(self, conversation_id: str) -> Any:
        """Load session metadata for a conversation.

        Args:
            conversation_id: Conversation ID to load session for.

        Returns:
            SessionMetadata if available, None otherwise.
        """
        return self._handlers._load_session(conversation_id)

    def _load_task_from_disk(
        self, conversation_id: str
    ) -> tuple[Any, Any] | None:
        """Load a task from disk when not in memory.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            Tuple of (TaskState, SessionMetadata) if found, None otherwise.
        """
        return self._handlers._load_task_from_disk(conversation_id)

    def _load_task_with_session(
        self, conversation_id: str
    ) -> tuple[Any, Any | None] | None:
        """Load task and session from memory or disk.

        Args:
            conversation_id: Conversation ID to load.

        Returns:
            Tuple of (TaskState, SessionMetadata or None) if found,
            None if not found.
        """
        return self._handlers._load_task_with_session(conversation_id)
