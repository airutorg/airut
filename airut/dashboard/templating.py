# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Jinja2 template engine setup for the dashboard.

Provides template loading (via importlib.resources with filesystem
fallback for editable installs), a shared Jinja2 environment with
auto-escaping, and the ``render_template`` helper used by handlers.
"""

import hashlib
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path

from jinja2 import BaseLoader, Environment, TemplateNotFound

from airut.dashboard.formatters import format_duration, format_timestamp


# Load logo SVG once at import time for use as a Jinja2 global.
# Add CSS class, aria-label, and replace fill with currentColor so the
# logo inherits the text color and scales to match the h1 text height.
_LOGO_SVG = (
    files("airut._bundled.assets")
    .joinpath("logo.svg")
    .read_text()
    .replace(
        'viewBox="0 0 2816 1536"',
        'class="logo" viewBox="0 0 2816 1536" aria-label="Airut logo"',
    )
    .replace('fill="#000000"', 'fill="currentColor"')
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
    globals_dict: dict[str, object] = env.globals  # type: ignore[assignment]
    globals_dict["format_duration"] = format_duration
    globals_dict["format_timestamp"] = format_timestamp
    globals_dict["logo_svg"] = _LOGO_SVG

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
