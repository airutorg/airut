# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor HTTP handlers.

Handles all config editor API endpoints and the editor page route.
Separated from the main ``handlers.py`` to keep file sizes manageable.
"""

from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from werkzeug.wrappers import Request, Response

from airut._json_types import JsonDict, JsonValue
from airut.config.editor import (
    FieldChange,
    PreviewResult,
    atomic_save,
    backup_config,
    json_to_raw,
    preview_changes,
    raw_to_json,
    validate_raw,
)
from airut.config.schema import full_schema_for_api
from airut.dashboard.formatters import VersionInfo
from airut.dashboard.templating import render_template
from airut.gateway.config import ConfigError


if TYPE_CHECKING:
    from airut.config.snapshot import ConfigSnapshot
    from airut.config.source import YamlConfigSource
    from airut.gateway.config import ServerConfig

ConfigCallback = Callable[
    [],
    tuple["ConfigSnapshot[ServerConfig]", "YamlConfigSource", int] | None,
]
StatusCallback = Callable[[], dict[str, object]]


def _require_csrf(request: Request) -> Response | None:
    """Return a 403 response if CSRF header is missing, else None."""
    if not request.headers.get("X-Requested-With"):
        return Response(
            json.dumps({"error": "Missing X-Requested-With header"}),
            status=403,
            content_type="application/json",
        )
    return None


def _config_unavailable() -> Response:
    """Return a 503 response when config editing is not available."""
    return Response(
        json.dumps({"error": "Config editing not available"}),
        status=503,
        content_type="application/json",
    )


def handle_config_editor(
    request: Request,
    config_callback: ConfigCallback | None,
    version_info: VersionInfo | None,
) -> Response:
    """Serve the config editor page."""
    available = True
    if config_callback is None:
        available = False
    elif config_callback() is None:
        available = False

    return Response(
        render_template(
            "pages/config.html",
            breadcrumbs=[("Config", "/config")],
            version_info=version_info,
            config_available=available,
        ),
        content_type="text/html; charset=utf-8",
    )


def handle_api_config_schema(request: Request) -> Response:
    """Return UI metadata for all config types."""
    schema = full_schema_for_api()
    return Response(
        json.dumps(schema),
        content_type="application/json",
        headers={"Cache-Control": "public, max-age=3600"},
    )


def handle_api_config(
    request: Request,
    config_callback: ConfigCallback | None,
) -> Response:
    """Return the current raw config with tag markers."""
    if config_callback is None:
        return _config_unavailable()
    result = config_callback()
    if result is None:
        return _config_unavailable()

    snapshot, _source, generation = result
    raw = snapshot.raw
    if raw is None:
        return _config_unavailable()

    return Response(
        json.dumps(
            {
                "config_generation": generation,
                "config": raw_to_json(raw),
            }
        ),
        content_type="application/json",
    )


def handle_api_config_preview(
    request: Request,
    config_callback: ConfigCallback | None,
) -> Response:
    """Validate edited config and return scope-grouped diff."""
    csrf_error = _require_csrf(request)
    if csrf_error is not None:
        return csrf_error

    if config_callback is None:
        return _config_unavailable()
    result = config_callback()
    if result is None:
        return _config_unavailable()

    snapshot, _source, _generation = result

    try:
        body = json.loads(request.get_data(as_text=True))
    except (json.JSONDecodeError, ValueError) as e:
        return Response(
            json.dumps(
                {
                    "valid": False,
                    "error": f"Invalid JSON: {e}",
                    "diff": None,
                    "warnings": [],
                }
            ),
            status=400,
            content_type="application/json",
        )

    edited_config = body.get("config", body)
    preview = preview_changes(snapshot.value, edited_config)

    return Response(
        json.dumps(preview_to_dict(preview)),
        content_type="application/json",
    )


def handle_api_config_save(
    request: Request,
    config_callback: ConfigCallback | None,
    status_callback: StatusCallback | None,
) -> Response:
    """Validate, save config, and wait for reload."""
    csrf_error = _require_csrf(request)
    if csrf_error is not None:
        return csrf_error

    if config_callback is None:
        return _config_unavailable()
    result = config_callback()
    if result is None:
        return _config_unavailable()

    snapshot, source, generation = result

    try:
        body = json.loads(request.get_data(as_text=True))
    except (json.JSONDecodeError, ValueError) as e:
        return Response(
            json.dumps({"error": f"Invalid JSON: {e}"}),
            status=400,
            content_type="application/json",
        )

    # Optimistic concurrency check (required field)
    client_generation = body.get("config_generation")
    if client_generation is None:
        return Response(
            json.dumps({"error": "Missing required field: config_generation"}),
            status=400,
            content_type="application/json",
        )
    if client_generation != generation:
        return Response(
            json.dumps(
                {
                    "error": "Config was modified since you loaded it. "
                    "Please reload and try again.",
                    "current_generation": generation,
                }
            ),
            status=409,
            content_type="application/json",
        )

    edited_config = body.get("config")
    if edited_config is None:
        return Response(
            json.dumps({"error": "Missing required field: config"}),
            status=400,
            content_type="application/json",
        )
    edited_raw = json_to_raw(edited_config)

    # Validate before writing
    try:
        validate_raw(edited_raw)
    except (ConfigError, ValueError) as e:
        return Response(
            json.dumps({"error": str(e)}),
            status=400,
            content_type="application/json",
        )

    # Create backup and save atomically
    backup_config(source.path)
    atomic_save(edited_raw, source.path)

    # Poll for reload (inotify typically fires within 100ms)
    reload_status = "pending"
    new_generation = generation
    warnings: list[str] = []

    for _ in range(40):  # 40 * 50ms = 2 seconds
        time.sleep(0.05)
        cb_result = config_callback()
        if cb_result is None:
            break
        _, _, new_gen = cb_result
        if new_gen != generation:
            new_generation = new_gen
            # Check for reload error
            if status_callback:
                status = status_callback()
                last_error = status.get("last_reload_error")
                if last_error:
                    reload_status = "reload_error"
                else:
                    reload_status = "applied"
                if status.get("server_reload_pending"):
                    warnings.append(
                        "server-scope changes will apply when all "
                        "tasks complete"
                    )
            else:
                reload_status = "applied"
            break

    return Response(
        json.dumps(
            {
                "saved": True,
                "config_generation": new_generation,
                "reload_status": reload_status,
                "warnings": warnings,
            }
        ),
        content_type="application/json",
    )


# ------------------------------------------------------------------
# JSON serialization helpers
# ------------------------------------------------------------------


def field_change_to_dict(fc: FieldChange) -> JsonDict:
    """Convert a FieldChange to a JSON-serializable dict."""
    return {
        "field": fc.field,
        "doc": fc.doc,
        "old": json_safe(fc.old),
        "new": json_safe(fc.new),
        "repo": fc.repo,
    }


def json_safe(value: object) -> JsonValue:
    """Convert a value to a JSON-serializable form."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, frozenset):
        result: list[JsonValue] = []
        for v in sorted(value, key=str):
            result.append(str(v))
        return result
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            str(k): json_safe(v) for k, v in dataclasses.asdict(value).items()
        }
    return str(value)


def preview_to_dict(preview: PreviewResult) -> JsonDict:
    """Convert a PreviewResult to a JSON-serializable dict."""
    diff_value: JsonValue = None
    if preview.diff is not None:
        diff_value = {
            scope: [field_change_to_dict(fc) for fc in changes]
            for scope, changes in preview.diff.items()
        }
    warnings: list[JsonValue] = []
    for w in preview.warnings:
        warnings.append(w)
    result: JsonDict = {
        "valid": preview.valid,
        "error": preview.error,
        "diff": diff_value,
        "warnings": warnings,
    }
    return result
