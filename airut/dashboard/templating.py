# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Jinja2 template engine setup for the dashboard.

Provides template loading (via importlib.resources with filesystem
fallback for editable installs), a shared Jinja2 environment with
auto-escaping, and the ``render_template`` helper used by handlers.
"""

import dataclasses
import hashlib
import re
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path

from jinja2 import BaseLoader, Environment, TemplateNotFound

from airut.dashboard.formatters import format_duration, format_timestamp


# Load logo SVG once at import time for use as a Jinja2 global.
# Add CSS class and aria-label.  Keep the original black fill —
# dark-mode inversion is handled via CSS filter on the container.
_LOGO_SVG = (
    files("airut._bundled.assets")
    .joinpath("logo.svg")
    .read_text()
    .replace(
        'viewBox="0 0 2816 1536"',
        'class="logo" viewBox="0 0 2816 1536" aria-label="Airut logo"',
    )
)


def _resolve_directory(package: str, subdir: str) -> Path:
    """Resolve a package sub-directory to a filesystem path.

    Uses ``importlib.resources.files()`` which works for both installed
    wheels and editable (development) installs.

    Args:
        package: Dotted package name (e.g. ``airut.dashboard``).
        subdir: Sub-directory within the package (e.g. ``templates``).

    Returns:
        Resolved filesystem path.
    """
    return Path(str(files(package).joinpath(subdir)))


class _PackageLoader(BaseLoader):
    """Jinja2 loader that reads from package data directories.

    Resolves templates and static files from the ``airut.dashboard``
    package using ``importlib.resources``, which works for both wheel
    installs and editable development installs.
    """

    def __init__(self) -> None:
        self._template_dir = _resolve_directory("airut.dashboard", "templates")

    def get_source(
        self,
        environment: Environment,
        template: str,
    ) -> tuple[str, str | None, Callable[[], bool] | None]:
        """Load template source.

        Args:
            environment: Jinja2 environment (unused).
            template: Template path relative to templates/ directory.

        Returns:
            Tuple of (source, filename, uptodate_callable).

        Raises:
            TemplateNotFound: If the template does not exist.
        """
        path = (self._template_dir / template).resolve()
        if not str(path).startswith(str(self._template_dir.resolve())):
            raise TemplateNotFound(template)
        if not path.is_file():
            raise TemplateNotFound(template)
        source = path.read_text(encoding="utf-8")
        return source, str(path), lambda: True


def _content_hash(data: bytes) -> str:
    """Compute a short content hash for ETag generation.

    Args:
        data: Raw file content.

    Returns:
        First 12 hex characters of the SHA-256 hash.
    """
    return hashlib.sha256(data).hexdigest()[:12]


def _build_static_hashes() -> dict[str, str]:
    """Compute content hashes for all static files at startup.

    Returns:
        Dict mapping relative path to short hex hash.
    """
    hashes: dict[str, str] = {}
    static_dir = _resolve_directory("airut.dashboard", "static")
    for p in static_dir.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(static_dir))
            h = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
            hashes[rel] = h
    return hashes


# Pre-computed hashes for cache-busted URLs.
_STATIC_HASHES = _build_static_hashes()


def static_url(path: str) -> str:
    """Return a cache-busted URL for a static file.

    Appends a content-hash query parameter so the browser fetches a
    new copy whenever the file content changes, even if the filename
    stays the same.  This is critical because static files are served
    with ``Cache-Control: immutable``.

    Args:
        path: Path relative to ``static/`` (e.g. ``styles/base.css``).

    Returns:
        URL string like ``/static/styles/base.css?v=a1b2c3d4e5f6``.
    """
    h = _STATIC_HASHES.get(path, "")
    if h:
        return f"/static/{path}?v={h}"
    return f"/static/{path}"


def create_jinja_env() -> Environment:
    """Create and configure the shared Jinja2 environment.

    Auto-escaping is enabled globally. Template globals include
    formatting functions available to all templates.

    Returns:
        Configured Jinja2 Environment.
    """
    env = Environment(
        loader=_PackageLoader(),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Register template globals (available in all templates)
    globals_dict: dict[str, object] = env.globals  # type: ignore[assignment]  # ty:ignore[invalid-assignment]
    globals_dict["format_duration"] = format_duration
    globals_dict["format_timestamp"] = format_timestamp
    globals_dict["logo_svg"] = _LOGO_SVG
    globals_dict["static_url"] = static_url
    globals_dict["MISSING"] = dataclasses.MISSING

    # Config editor helpers — lazy import to avoid circular deps
    def _value_source(value: object) -> tuple[str, object]:
        from airut.config.editor import value_source

        return value_source(value)

    def _prefixed_field(field: object, prefix: str) -> object:
        from airut.config.editor_schema import EditorFieldSchema

        if not isinstance(field, EditorFieldSchema):
            raise TypeError(f"Expected EditorFieldSchema, got {type(field)}")
        new_path = f"{prefix}.{field.path}" if field.path else prefix
        new_nested = None
        if field.nested_fields:
            new_nested = [
                _prefixed_field(f, prefix) for f in field.nested_fields
            ]
        new_item_fields = None
        if field.item_fields:
            new_item_fields = [
                _prefixed_field(f, prefix) for f in field.item_fields
            ]
        return dataclasses.replace(
            field,
            path=new_path,
            nested_fields=new_nested,
            item_fields=new_item_fields,
        )

    globals_dict["value_source"] = _value_source
    globals_dict["prefixed_field"] = _prefixed_field

    # Filters
    type_display_names: dict[str, str] = {
        "MaskedSecret": "Masked Secret",
        "SigningCredential": "Signing Credential",
        "GitHubAppCredential": "GitHub App Credential",
    }

    def _humanize_type(name: str) -> str:
        """Convert CamelCase type name to 'Human Readable' form."""
        if name in type_display_names:
            return type_display_names[name]
        # Fallback: insert space before uppercase following lowercase
        return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)

    env.filters["humanize_type"] = _humanize_type

    return env


# Module-level singleton — created once at import time.
_jinja_env = create_jinja_env()

# Resolve static directory for the static file handler.
STATIC_DIR = _resolve_directory("airut.dashboard", "static")


def render_template(template_name: str, **context: object) -> str:
    """Render a Jinja2 template with the given context.

    Args:
        template_name: Template path relative to the templates/
            directory (e.g. ``pages/dashboard.html``).
        **context: Template variables.

    Returns:
        Rendered HTML string.
    """
    template = _jinja_env.get_template(template_name)
    return template.render(**context)


def render_template_string(source: str, **context: object) -> str:
    """Render a Jinja2 template from a string source.

    Used for rendering SSE HTML fragments from inline template
    strings without requiring a file on disk.

    Args:
        source: Jinja2 template source string.
        **context: Template variables.

    Returns:
        Rendered HTML string.
    """
    template = _jinja_env.from_string(source)
    return template.render(**context)


def get_static_file(path: str) -> tuple[bytes, str, str] | None:
    """Read a static file and return its content with metadata.

    Args:
        path: File path relative to the static/ directory.

    Returns:
        Tuple of (content_bytes, content_type, etag) if the file
        exists, None otherwise.
    """
    # Prevent directory traversal
    resolved = (STATIC_DIR / path).resolve()
    if not str(resolved).startswith(str(STATIC_DIR.resolve())):
        return None
    if not resolved.is_file():
        return None

    data = resolved.read_bytes()
    etag = f'"{_content_hash(data)}"'

    # Determine content type from extension
    suffix = resolved.suffix.lower()
    content_types: dict[str, str] = {
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".ico": "image/x-icon",
    }
    content_type = content_types.get(suffix, "application/octet-stream")

    return data, content_type, etag
