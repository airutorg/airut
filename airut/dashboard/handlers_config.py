# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor HTTP handlers for the dashboard.

Provides page rendering, form save, and add-fragment endpoints for the
schema-driven config editor.
"""

import html
import json
import logging
from collections.abc import Callable

from werkzeug.wrappers import Request, Response

from airut.config.editor import build_editor_context
from airut.config.editor_form import InMemoryConfigSource, form_to_raw_dict
from airut.config.snapshot import ConfigSnapshot
from airut.config.source import ConfigSource
from airut.dashboard.templating import render_template


logger = logging.getLogger(__name__)


class ConfigEditorHandlers:
    """HTTP handlers for the config editor page.

    Dependencies are injected via callbacks from the gateway service.
    """

    def __init__(
        self,
        config_callback: Callable[[], ConfigSnapshot[object] | None],
        generation_callback: Callable[[], int],
        config_source_callback: Callable[[], ConfigSource | None],
        vars_callback: Callable[[], dict[str, object]],
    ) -> None:
        """Initialize config editor handlers.

        Args:
            config_callback: Returns current ConfigSnapshot.
            generation_callback: Returns current config_generation.
            config_source_callback: Returns the ConfigSource for saving.
            vars_callback: Returns resolved vars table.
        """
        self._config_callback = config_callback
        self._generation_callback = generation_callback
        self._config_source_callback = config_source_callback
        self._vars_callback = vars_callback

    def handle_config_page(self, request: Request) -> Response:
        """Render the full config editor page.

        GET /config
        """
        snapshot = self._config_callback()
        if snapshot is None:
            return Response(
                render_template(
                    "pages/config.html",
                    error="Configuration not loaded yet.",
                    breadcrumbs=[("Configuration", "/config")],
                ),
                status=200,
                content_type="text/html; charset=utf-8",
            )

        generation = self._generation_callback()
        vars_section = self._vars_callback()

        context = build_editor_context(snapshot, generation, vars_section)
        context["breadcrumbs"] = [("Configuration", "/config")]

        return Response(
            render_template("pages/config.html", **context),
            status=200,
            content_type="text/html; charset=utf-8",
        )

    def handle_config_save(self, request: Request) -> Response:
        """Validate and save config changes.

        POST /api/config
        Returns HTML fragment for #save-result.
        """
        # CSRF check
        if not request.headers.get("X-Requested-With"):
            return Response(
                '<div class="cfg-banner error">'
                "Missing X-Requested-With header</div>",
                status=403,
                content_type="text/html; charset=utf-8",
            )

        form_data = request.form.to_dict(flat=True)

        # Check optimistic concurrency
        submitted_gen = form_data.get("_generation", "")
        try:
            submitted_gen_int = int(submitted_gen)
        except (ValueError, TypeError):
            submitted_gen_int = -1

        current_gen = self._generation_callback()
        if submitted_gen_int != current_gen:
            return Response(
                '<div class="cfg-banner warning">'
                "Config changed externally since you loaded this page. "
                '<a href="/config">Reload</a> to see the latest version.'
                "</div>",
                status=409,
                content_type="text/html; charset=utf-8",
            )

        # Parse form data into raw dict
        raw_dict = form_to_raw_dict(form_data)

        # Validate through full pipeline
        try:
            from airut.gateway.config import ServerConfig

            ServerConfig.from_source(InMemoryConfigSource(raw_dict))
        except Exception as e:
            error_msg = str(e)
            logger.warning("Config validation failed: %s", error_msg)
            return Response(
                f'<div class="cfg-banner error">'
                f"Validation failed: {html.escape(error_msg)}"
                f"</div>",
                status=422,
                content_type="text/html; charset=utf-8",
            )

        # Write atomically via YamlConfigSource
        source = self._config_source_callback()
        if source is None:
            return Response(
                '<div class="cfg-banner error">'
                "Config source not available."
                "</div>",
                status=500,
                content_type="text/html; charset=utf-8",
            )

        try:
            source.save(raw_dict)
        except Exception as e:
            logger.exception("Config save failed")
            return Response(
                f'<div class="cfg-banner error">'
                f"Save failed: {html.escape(str(e))}"
                f"</div>",
                status=500,
                content_type="text/html; charset=utf-8",
            )

        return Response(
            '<div class="cfg-banner success">'
            "Saved. The server will reload automatically."
            "</div>",
            status=200,
            content_type="text/html; charset=utf-8",
        )

    def handle_config_add_fragment(self, request: Request) -> Response:
        """Render a new empty item fragment for list/dict/collection.

        POST /api/config/add
        Accepts form-encoded data with ``type``, ``path``, and ``index``.
        """
        # CSRF check
        if not request.headers.get("X-Requested-With"):
            return Response("Forbidden", status=403)

        # htmx sends hx-vals as form-encoded parameters
        data = request.form

        fragment_type = data.get("type", "")
        path = data.get("path", "")
        try:
            index = int(data.get("index", "0"))
        except (ValueError, TypeError):
            index = 0

        if fragment_type == "list_item":
            fragment = _render_list_item_fragment(path, index)
        elif fragment_type == "dict_entry":
            fragment = _render_dict_entry_fragment(path, index)
        elif fragment_type == "collection_entry":
            fragment = _render_collection_entry_fragment(path, index)
        elif fragment_type == "tagged_union_item":
            rules_json = data.get("rules", "[]")
            fragment = _render_tagged_union_item_fragment(
                path, index, rules_json
            )
        else:
            return Response("Unknown fragment type", status=400)

        return Response(
            fragment,
            status=200,
            content_type="text/html; charset=utf-8",
        )


# ---------------------------------------------------------------------------
# Fragment renderers
# ---------------------------------------------------------------------------


def _render_list_item_fragment(path: str, index: int) -> str:
    """Render a new empty list item row."""
    name = html.escape(f"{path}.{index}")
    src = "cfg-source-btn"
    return (
        f'<div class="cfg-list-item">'
        f'<div class="cfg-source-group">'
        f'<div class="cfg-source" data-path="{name}">'
        f'<button type="button" class="{src} active"'
        f' data-source="literal">Literal</button>'
        f'<button type="button" class="{src}"'
        f' data-source="env">!env</button>'
        f'<button type="button" class="{src}"'
        f' data-source="var">!var</button>'
        f"</div>"
        f'<input type="hidden"'
        f' name="{name}._source" value="literal">'
        f'<input type="text" class="cfg-input"'
        f' name="{name}._value" value=""'
        f' placeholder="value">'
        f"</div>"
        f'<button type="button" class="cfg-remove-btn"'
        f" onclick=\"this.closest('.cfg-list-item')"
        f'.remove()">&times;</button>'
        f"</div>"
    )


def _render_dict_entry_fragment(path: str, index: int) -> str:
    """Render a new empty dict key-value row."""
    key_name = html.escape(f"{path}.{index}.key")
    val_name = html.escape(f"{path}.{index}.value")
    src = "cfg-source-btn"
    return (
        f'<div class="cfg-dict-entry">'
        f'<input type="text"'
        f' class="cfg-input cfg-dict-key"'
        f' name="{key_name}" value=""'
        f' placeholder="key">'
        f'<div class="cfg-source-group">'
        f'<div class="cfg-source" data-path="{val_name}">'
        f'<button type="button" class="{src} active"'
        f' data-source="literal">Literal</button>'
        f'<button type="button" class="{src}"'
        f' data-source="env">!env</button>'
        f'<button type="button" class="{src}"'
        f' data-source="var">!var</button>'
        f"</div>"
        f'<input type="hidden"'
        f' name="{val_name}._source" value="literal">'
        f'<input type="text" class="cfg-input"'
        f' name="{val_name}._value" value=""'
        f' placeholder="value">'
        f"</div>"
        f'<button type="button" class="cfg-remove-btn"'
        f" onclick=\"this.closest('.cfg-dict-entry')"
        f'.remove()">&times;</button>'
        f"</div>"
    )


def _render_collection_entry_fragment(path: str, index: int) -> str:
    """Render a new empty keyed collection entry card."""
    key_name = html.escape(f"{path}._new_{index}")
    toggle = "this.parentElement.classList.toggle('open')"
    rm = (
        "event.stopPropagation(); "
        "this.closest('.cfg-collection-entry').remove()"
    )
    return (
        f'<div class="cfg-collection-entry cfg-expandable open">'
        f'<div class="cfg-expandable-header"'
        f' onclick="{toggle}">'
        f'<span class="cfg-expand-icon"></span>'
        f'<input type="text"'
        f' class="cfg-input cfg-collection-key"'
        f' name="{key_name}._key" value=""'
        f' placeholder="entry name"'
        f' onclick="event.stopPropagation()">'
        f'<button type="button" class="cfg-remove-btn"'
        f' onclick="{rm}">&times;</button>'
        f"</div>"
        f'<div class="cfg-expandable-body">'
        f'<p class="cfg-help">'
        f"Fill in the entry name above, "
        f"then configure fields.</p>"
        f"</div>"
        f"</div>"
    )


def _render_tagged_union_item_fragment(
    path: str, index: int, rules_json: str
) -> str:
    """Render a new tagged union list item."""
    try:
        rules = json.loads(rules_json)
    except (json.JSONDecodeError, TypeError):
        rules = []

    name = html.escape(f"{path}.{index}")

    # Build option elements
    options = ""
    for tag, vtype, label in rules:
        t = html.escape(str(tag))
        options += f'<option value="{t}">{t}</option>'

    return (
        f'<div class="cfg-list-item cfg-union-item">'
        f'<select class="cfg-input cfg-union-select"'
        f' name="{name}._tag">'
        f"{options}"
        f"</select>"
        f'<input type="text" class="cfg-input"'
        f' name="{name}._value" value=""'
        f' placeholder="value">'
        f'<button type="button" class="cfg-remove-btn"'
        f" onclick=\"this.closest('.cfg-list-item')"
        f'.remove()">&times;</button>'
        f"</div>"
    )
