# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor HTTP handlers.

Provides page routes for ``/config`` (global) and ``/config/repos/<repo_id>``
(per-repo), plus API routes for field mutation, diff, save, and discard.
All handlers operate on a shared ``EditBuffer`` instance.
"""

import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from werkzeug.wrappers import Request, Response

from airut.config.editor import (
    EditBuffer,
    EditorFieldSchema,
    collect_leaf_fields,
    format_raw_value,
    get_raw_value,
    raw_values_equal,
    schema_for_editor,
)
from airut.config.snapshot import ConfigSnapshot
from airut.config.source import (
    YAML_GLOBAL_STRUCTURE,
    YAML_REPO_STRUCTURE,
    ConfigSource,
)
from airut.dashboard.templating import render_template
from airut.yaml_env import EnvVar


logger = logging.getLogger(__name__)


def _make_repo_skeleton() -> dict[str, Any]:
    """Create a minimal repo skeleton for add-repo.

    Contains required ``git.repo_url`` placeholder and an email channel
    stub so the repo passes validation.  Sensitive fields use ``!env``
    references to avoid storing placeholder credentials.
    """
    return {
        "git": {"repo_url": "https://github.com/org/repo.git"},
        "email": {
            "imap_server": "imap.example.com",
            "imap_port": 993,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "username": "user@example.com",
            "password": EnvVar("EMAIL_PASSWORD"),
            "from": "bot@example.com",
            "authorized_senders": [],
            "trusted_authserv_id": "example.com",
        },
    }


def _require_xhr(request: Request) -> Response | None:
    """Check for X-Requested-With header (CSRF protection).

    Returns a 403 Response if the header is missing, None otherwise.
    """
    if not request.headers.get("X-Requested-With"):
        return Response("Forbidden: missing X-Requested-With", status=403)
    return None


def _coerce_value(value: object, python_type: str) -> object:
    """Coerce a form string value to the appropriate Python type.

    Empty or whitespace-only strings return zero for numeric types
    (``int`` → 0, ``float`` → 0.0) to support mode-switch transitions
    where no previous literal value exists.

    Raises:
        ValueError: If the value cannot be converted to the target type.
    """
    if value is None:
        return None
    if python_type == "int":
        # Handle bool first (bool is subclass of int in Python, but
        # str(True) == "True" which int() can't parse).
        if isinstance(value, bool):
            return int(value)
        s = str(value).strip()
        return int(s) if s else 0
    if python_type == "float":
        if isinstance(value, bool):
            return float(value)
        s = str(value).strip()
        return float(s) if s else 0.0
    if python_type == "bool":
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)
    return str(value)


def _find_field_schema(
    fields: list[EditorFieldSchema], path: str
) -> EditorFieldSchema | None:
    """Find a field schema by its path, searching recursively."""
    for fs in fields:
        if fs.path == path:
            return fs
        if fs.nested_fields:
            found = _find_field_schema(fs.nested_fields, path)
            if found:
                return found
    return None


class ConfigEditorHandlers:
    """HTTP handlers for the config editor.

    Manages a shared ``EditBuffer`` and exposes page routes and
    API routes for the config editor.
    """

    def __init__(
        self,
        get_snapshot: Callable[[], ConfigSnapshot | None],
        get_generation: Callable[[], int],
        get_config_source: Callable[[], ConfigSource | None],
    ) -> None:
        """Initialize config editor handlers.

        Args:
            get_snapshot: Returns the current live ``ConfigSnapshot``.
            get_generation: Returns the current ``_config_generation``.
            get_config_source: Returns the ``ConfigSource`` for saving.
        """
        self._get_snapshot = get_snapshot
        self._get_generation = get_generation
        self._get_config_source = get_config_source
        self._buffer: EditBuffer | None = None

    def _ensure_buffer(self) -> EditBuffer | None:
        """Ensure an edit buffer exists, creating one if needed.

        If a buffer exists but is stale and clean (no unsaved edits),
        it is replaced with a fresh copy from the current snapshot.
        This handles the post-save case where the file watcher has
        reloaded but the buffer was created from the old snapshot.

        Returns None if no config snapshot is available.
        """
        if self._buffer is not None:
            gen = self._get_generation()
            if self._buffer.is_stale(gen) and not self._buffer.dirty:
                # Stale clean buffer — replace with current snapshot.
                self._buffer = None
            else:
                return self._buffer

        snapshot = self._get_snapshot()
        if snapshot is None or snapshot.raw is None:
            return None

        self._buffer = EditBuffer(snapshot.raw, self._get_generation())
        return self._buffer

    def _get_global_schema(self) -> list[EditorFieldSchema]:
        """Get editor schema for GlobalConfig."""
        from airut.gateway.config import GlobalConfig

        return schema_for_editor(GlobalConfig, structure=YAML_GLOBAL_STRUCTURE)

    def _get_repo_schema(self, repo_id: str) -> list[EditorFieldSchema]:
        """Get editor schema for a repo's RepoServerConfig fields."""
        from airut.gateway.config import RepoServerConfig

        prefix = f"repos.{repo_id}"
        return schema_for_editor(
            RepoServerConfig,
            path_prefix=prefix,
            structure=YAML_REPO_STRUCTURE,
            exclude={"repo_id"},
        )

    def _get_common_repo_ids(self) -> set[str]:
        """Get repo IDs that exist in both the buffer and live snapshot.

        Used to skip per-field comparison for repos that are wholly
        added or removed — those are tracked as repo-level entries.
        """
        if self._buffer is None:
            return set()
        snapshot = self._get_snapshot()
        if snapshot is None or snapshot.raw is None:
            return set()
        buf_repos = set(self._buffer.raw.get("repos", {}))
        live_repos = set(snapshot.raw.get("repos", {}))
        return buf_repos & live_repos

    def _get_repo_summaries(self) -> list[dict[str, Any]]:
        """Get summary info for each repo in the edit buffer."""
        buffer = self._buffer
        if buffer is None:
            return []

        repos = buffer.raw.get("repos", {})
        summaries = []
        for repo_id, repo_data in sorted(repos.items()):
            channels = []
            if isinstance(repo_data, dict):
                if "email" in repo_data:
                    channels.append("email")
                if "slack" in repo_data:
                    channels.append("slack")
            summaries.append(
                {
                    "id": repo_id,
                    "channels": channels,
                    "model": repo_data.get("model", "opus")
                    if isinstance(repo_data, dict)
                    else "opus",
                }
            )
        return summaries

    def _find_field_in_all_schemas(self, path: str) -> EditorFieldSchema | None:
        """Search for a field schema across global and all repo schemas."""
        found = _find_field_schema(self._get_global_schema(), path)
        if found:
            return found

        if self._buffer is not None:
            for repo_id in self._buffer.raw.get("repos", {}):
                found = _find_field_schema(self._get_repo_schema(repo_id), path)
                if found:
                    return found
        return None

    def _compute_dirty_count(self) -> int:
        """Count leaf fields that differ between the buffer and live snapshot.

        Covers global settings and per-repo settings for repos that
        exist in both the buffer and live snapshot.  Wholly added or
        removed repos are counted once each (not per-field).
        """
        if self._buffer is None:
            return 0

        snapshot = self._get_snapshot()
        if snapshot is None or snapshot.raw is None:
            return 0

        # Global fields
        global_schema = self._get_global_schema()
        count = 0
        for fs in collect_leaf_fields(global_schema):
            buf_val = get_raw_value(self._buffer.raw, fs.path)
            live_val = get_raw_value(snapshot.raw, fs.path)
            if not raw_values_equal(buf_val, live_val):
                count += 1

        # Per-field diff only for repos present on both sides
        for repo_id in sorted(self._get_common_repo_ids()):
            for fs in collect_leaf_fields(self._get_repo_schema(repo_id)):
                buf_val = get_raw_value(self._buffer.raw, fs.path)
                live_val = get_raw_value(snapshot.raw, fs.path)
                if not raw_values_equal(buf_val, live_val):
                    count += 1

        # Added/removed repos count once each
        buf_repos = set(self._buffer.raw.get("repos", {}))
        live_repos = set((snapshot.raw or {}).get("repos", {}))
        count += len(buf_repos - live_repos)
        count += len(live_repos - buf_repos)

        return count

    def _add_dirty_count_header(self, response: Response) -> Response:
        """Add ``X-Dirty-Count`` header to a mutation response."""
        response.headers["X-Dirty-Count"] = str(self._compute_dirty_count())
        return response

    @staticmethod
    def _redirect_target(request: Request) -> str:
        """Determine redirect target from the request's Referer header.

        Returns the Referer path if it starts with ``/config``, otherwise
        falls back to ``/config``.  This keeps save/discard on the repo
        page when triggered from ``/config/repos/<id>``.
        """
        referer = request.headers.get("Referer", "")
        # Extract path from full URL (Referer is an absolute URL).
        path = urlparse(referer).path
        if path.startswith("/config"):
            return path
        return "/config"

    # -- Page routes --

    def handle_config_page(self, request: Request) -> Response:
        """Render the global settings page (GET /config).

        Creates an edit buffer if none exists.
        """
        buffer = self._ensure_buffer()
        if buffer is None:
            return Response(
                render_template(
                    "pages/config.html",
                    error="No config available for editing. "
                    "Config must be file-backed.",
                    breadcrumbs=[("Configuration", "/config")],
                    schema=[],
                    buffer=None,
                    repos=[],
                    stale=False,
                ),
                content_type="text/html",
            )

        schema = self._get_global_schema()
        stale = buffer.is_stale(self._get_generation())

        return Response(
            render_template(
                "pages/config.html",
                breadcrumbs=[("Configuration", "/config")],
                schema=schema,
                buffer=buffer,
                repos=self._get_repo_summaries(),
                stale=stale and buffer.dirty,
                error=None,
            ),
            content_type="text/html",
        )

    def handle_repo_page(self, request: Request, repo_id: str) -> Response:
        """Render per-repo settings page (GET /config/repos/<repo_id>)."""
        buffer = self._ensure_buffer()
        if buffer is None:
            return Response(
                render_template(
                    "pages/config_repo.html",
                    error="No config available for editing. "
                    "Config must be file-backed.",
                    breadcrumbs=[
                        ("Configuration", "/config"),
                        (repo_id, f"/config/repos/{repo_id}"),
                    ],
                    repo_id=repo_id,
                    schema=[],
                    buffer=None,
                    stale=False,
                ),
                content_type="text/html",
            )

        repos = buffer.raw.get("repos", {})
        if repo_id not in repos:
            return Response(
                render_template(
                    "pages/config_repo.html",
                    error=f"Repository '{repo_id}' not found in config.",
                    breadcrumbs=[
                        ("Configuration", "/config"),
                        (repo_id, f"/config/repos/{repo_id}"),
                    ],
                    repo_id=repo_id,
                    schema=[],
                    buffer=None,
                    stale=False,
                ),
                content_type="text/html",
            )

        schema = self._get_repo_schema(repo_id)
        stale = buffer.is_stale(self._get_generation())

        return Response(
            render_template(
                "pages/config_repo.html",
                breadcrumbs=[
                    ("Configuration", "/config"),
                    (repo_id, f"/config/repos/{repo_id}"),
                ],
                repo_id=repo_id,
                schema=schema,
                buffer=buffer,
                stale=stale and buffer.dirty,
                error=None,
            ),
            content_type="text/html",
        )

    # -- API routes --

    def handle_field_patch(self, request: Request) -> Response:
        """Handle PATCH /api/config/field — set or clear a field."""
        csrf_err = _require_xhr(request)
        if csrf_err:
            return csrf_err

        buffer = self._ensure_buffer()
        if buffer is None:
            return Response("No edit buffer", status=400)

        form = request.form
        if "path" not in form or "source" not in form:
            return Response("Missing path or source", status=400)

        path = form["path"]
        source = form["source"]
        value = form.get("value")

        # Reject literal source without a value
        if source == "literal" and value is None:
            return Response("Missing value for literal source", status=400)

        # Coerce literal values based on field schema
        # Search across global + all repo schemas
        if source == "literal":
            fs = self._find_field_in_all_schemas(path)
            if fs:
                try:
                    value = _coerce_value(value, fs.python_type)
                except (ValueError, TypeError) as e:
                    return Response(
                        f"Invalid value for {path}: {e}", status=422
                    )

        buffer.set_field(path, source, value)

        # Return the updated field HTML fragment
        fs = self._find_field_in_all_schemas(path)
        if fs:
            return self._add_dirty_count_header(
                Response(
                    render_template(
                        "components/config/field.html",
                        f=fs,
                        buffer=buffer,
                    ),
                    content_type="text/html",
                )
            )

        return self._add_dirty_count_header(Response("OK", status=200))

    def handle_add(self, request: Request) -> Response:
        """Handle POST /api/config/add — add item to collection."""
        csrf_err = _require_xhr(request)
        if csrf_err:
            return csrf_err

        buffer = self._ensure_buffer()
        if buffer is None:
            return Response("No edit buffer", status=400)

        form = request.form
        if "path" not in form:
            return Response("Missing path", status=400)

        path = form["path"]
        key = form.get("key")

        # Special handling for adding a repo
        if path == "repos" and key:
            repos = buffer.raw.setdefault("repos", {})
            if key not in repos:
                repos[key] = _make_repo_skeleton()
                buffer.mark_dirty()
            return self._add_dirty_count_header(Response("OK", status=200))

        buffer.add_item(path, key)

        return self._add_dirty_count_header(Response("OK", status=200))

    def handle_remove(self, request: Request) -> Response:
        """Handle POST /api/config/remove — remove item from collection."""
        csrf_err = _require_xhr(request)
        if csrf_err:
            return csrf_err

        buffer = self._ensure_buffer()
        if buffer is None:
            return Response("No edit buffer", status=400)

        form = request.form
        if "path" not in form:
            return Response("Missing path", status=400)

        path = form["path"]
        key = form.get("key")
        index = form.get("index")
        if index is not None:
            try:
                index = int(index)
            except (ValueError, TypeError):
                return Response("Invalid index", status=400)
        buffer.remove_item(path, key=key, index=index)

        return self._add_dirty_count_header(Response("OK", status=200))

    def handle_diff(self, request: Request) -> Response:
        """Handle GET /api/config/diff — compare buffer vs live config.

        Compares each leaf field individually.  Wholly added/removed
        repos appear as single entries (not per-field).
        """
        buffer = self._ensure_buffer()
        if buffer is None:
            return Response("No edit buffer", status=400)

        snapshot = self._get_snapshot()
        if snapshot is None or snapshot.raw is None:
            return Response("No live config", status=400)

        scope_summary: dict[str, int] = {}
        requires_restart = False
        all_changes: list[dict[str, Any]] = []

        def _diff_fields(schema: list[EditorFieldSchema]) -> None:
            nonlocal requires_restart
            for fs in collect_leaf_fields(schema):
                buf_val = get_raw_value(buffer.raw, fs.path)
                live_val = get_raw_value(snapshot.raw, fs.path)

                if raw_values_equal(buf_val, live_val):
                    continue

                scope_str = fs.scope
                scope_summary[scope_str] = scope_summary.get(scope_str, 0) + 1
                if scope_str == "server":
                    requires_restart = True

                all_changes.append(
                    {
                        "field": fs.path,
                        "scope": scope_str,
                        "old": format_raw_value(live_val),
                        "new": format_raw_value(buf_val),
                    }
                )

        # Global fields
        _diff_fields(self._get_global_schema())

        # Per-field diff only for repos present on both sides
        for repo_id in sorted(self._get_common_repo_ids()):
            _diff_fields(self._get_repo_schema(repo_id))

        # Added/removed repos as single entries
        buf_repos = set(buffer.raw.get("repos", {}))
        live_repos = set((snapshot.raw or {}).get("repos", {}))
        for repo_id in sorted(buf_repos - live_repos):
            scope_summary["repo"] = scope_summary.get("repo", 0) + 1
            all_changes.append(
                {
                    "field": f"repos.{repo_id}",
                    "scope": "repo",
                    "old": "(not set)",
                    "new": "(added)",
                }
            )
        for repo_id in sorted(live_repos - buf_repos):
            scope_summary["repo"] = scope_summary.get("repo", 0) + 1
            all_changes.append(
                {
                    "field": f"repos.{repo_id}",
                    "scope": "repo",
                    "old": "(configured)",
                    "new": "(removed)",
                }
            )

        return Response(
            render_template(
                "components/config/diff_result.html",
                error=None,
                changes=all_changes,
                scope_summary=scope_summary,
                requires_restart=requires_restart,
                total_changes=sum(scope_summary.values()),
            ),
            content_type="text/html",
        )

    def handle_save(self, request: Request) -> Response:
        """Handle POST /api/config/save — validate and write YAML."""
        csrf_err = _require_xhr(request)
        if csrf_err:
            return csrf_err

        buffer = self._ensure_buffer()
        if buffer is None:
            return Response("No edit buffer", status=400)

        # Check staleness
        if buffer.is_stale(self._get_generation()):
            return Response(
                render_template(
                    "components/config/save_result.html",
                    status="stale",
                    message="Config changed externally since you started "
                    "editing. Review changes and reload.",
                ),
                status=409,
                content_type="text/html",
            )

        # Validate
        try:
            buffer.validate()
        except Exception as e:
            return Response(
                render_template(
                    "components/config/save_result.html",
                    status="error",
                    message=str(e),
                ),
                status=422,
                content_type="text/html",
            )

        # Write via config source
        config_source = self._get_config_source()
        if config_source is None:
            return Response(
                render_template(
                    "components/config/save_result.html",
                    status="error",
                    message="No config source available for saving.",
                ),
                status=400,
                content_type="text/html",
            )

        try:
            config_source.save(buffer.raw)
        except Exception as e:
            logger.exception("Failed to save config")
            return Response(
                render_template(
                    "components/config/save_result.html",
                    status="error",
                    message=f"Failed to write config file: {e}",
                ),
                status=500,
                content_type="text/html",
            )

        # Mark buffer clean instead of discarding.  The buffer keeps
        # the saved raw dict so the redirect page load shows saved values
        # even before the file watcher reloads.  Once the watcher bumps
        # the generation, _ensure_buffer will auto-refresh the stale
        # clean buffer on the next page load.
        buffer.mark_clean()

        return Response(
            status=200,
            headers={"HX-Redirect": self._redirect_target(request)},
        )

    def handle_discard(self, request: Request) -> Response:
        """Handle POST /api/config/discard — reset edit buffer."""
        csrf_err = _require_xhr(request)
        if csrf_err:
            return csrf_err

        self._buffer = None

        return Response(
            status=200,
            headers={"HX-Redirect": self._redirect_target(request)},
        )
