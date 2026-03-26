#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Generate dashboard screenshots for documentation.

Starts a dashboard server with rich mock data, then uses Playwright to
capture screenshots of each page in both light and dark color schemes.

Playwright renders at 3840x2160 (1920x1080 viewport at 2x device scale),
then ImageMagick downscales to 1920x1080 (main) and 480x270 (thumbnail).

Usage:
    uv run --project screenshots python screenshots/generate.py
    uv run --project screenshots python screenshots/generate.py \
        --output /tmp/shots
    uv run --project screenshots python screenshots/generate.py --scheme dark
"""

from __future__ import annotations

import argparse
import logging
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

from mock_data import MockDashboard, create_mock_dashboard
from playwright.sync_api import Page, sync_playwright


logger = logging.getLogger(__name__)

# Pages to capture: (name, url_template)
# URL templates use {key} placeholders resolved from MockDashboard.ids.
PAGES: list[tuple[str, str]] = [
    ("dashboard", "/"),
    ("task-executing", "/task/{executing_task}"),
    ("task-completed", "/task/{completed_task}"),
    ("conversation", "/conversation/{completed_conv}"),
    ("repo-live", "/repo/{live_repo}"),
    ("repo-failed", "/repo/{failed_repo}"),
    ("actions", "/conversation/{executing_conv}/actions"),
    ("network", "/conversation/{executing_conv}/network"),
]

SCHEMES = ("light", "dark")

# Playwright renders at 2x the viewport for high-fidelity capture.
# Raw output is 3840x2160, then downscaled via ImageMagick.
VIEWPORT = {"width": 1920, "height": 1080}
DEVICE_SCALE_FACTOR = 2

# Final output sizes after ImageMagick downscaling.
MAIN_SIZE = (1920, 1080)
THUMB_SIZE = (480, 270)


def resolve_url(base: str, template: str, ids: dict[str, str]) -> str:
    """Resolve a URL template with ID substitutions.

    Args:
        base: Base URL (e.g. http://127.0.0.1:5200).
        template: URL path template with {key} placeholders.
        ids: Mapping of placeholder names to values.

    Returns:
        Fully resolved URL.
    """
    path = template
    for key, value in ids.items():
        placeholder = "{" + key + "}"
        if placeholder in path:
            path = path.replace(placeholder, quote(value, safe=""))
    return base + path


def capture_page(
    page: Page,
    url: str,
    output_path: Path,
) -> None:
    """Navigate to a URL and capture a viewport-sized screenshot.

    The screenshot dimensions are determined by the viewport set on the
    browser context (see ``VIEWPORT`` and ``DEVICE_SCALE_FACTOR``).

    Args:
        page: Playwright page instance.
        url: URL to navigate to.
        output_path: Path to save the PNG screenshot.
    """
    page.goto(url)
    page.wait_for_load_state("load")

    page.screenshot(path=str(output_path))


def _png_dimensions(path: Path) -> tuple[int, int]:
    """Read width and height from a PNG file's IHDR chunk."""
    with path.open("rb") as f:
        # Skip 8-byte PNG signature, 4-byte chunk length, 4-byte chunk type
        f.seek(16)
        width, height = struct.unpack(">II", f.read(8))
    return width, height


def _find_magick() -> str:
    """Find the ImageMagick command (v7 ``magick`` or v6 ``convert``)."""
    for cmd in ("magick", "convert"):
        if shutil.which(cmd):
            return cmd
    raise FileNotFoundError(
        "ImageMagick not found (tried 'magick' and 'convert')"
    )


def _downscale(src: Path, dst: Path, width: int, height: int) -> None:
    """Downscale an image using ImageMagick with Lanczos filtering.

    Args:
        src: Source image path.
        dst: Destination image path.
        width: Target width in pixels.
        height: Target height in pixels.
    """
    cmd = _find_magick()
    subprocess.run(
        [
            cmd,
            str(src),
            "-filter",
            "Lanczos",
            "-resize",
            f"{width}x{height}!",
            "-strip",
            str(dst),
        ],
        check=True,
        capture_output=True,
    )


def generate_screenshots(
    dashboard: MockDashboard,
    output_dir: Path,
    *,
    schemes: tuple[str, ...] = SCHEMES,
    pages: list[tuple[str, str]] | None = None,
) -> list[Path]:
    """Generate all screenshots.

    Captures at full resolution via Playwright, then downscales with
    ImageMagick to produce main (1920x1080) and thumbnail (480x270) variants.

    Args:
        dashboard: Running mock dashboard server.
        output_dir: Directory to save screenshots.
        schemes: Color schemes to capture.
        pages: Pages to capture (defaults to PAGES).

    Returns:
        List of generated screenshot file paths (main + thumbnails).
    """
    if pages is None:
        pages = PAGES

    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = f"http://127.0.0.1:{dashboard.port}"
    raw_paths: list[tuple[str, str, Path]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()

        for scheme in schemes:
            context = browser.new_context(
                color_scheme=scheme,
                viewport=VIEWPORT,
                device_scale_factor=DEVICE_SCALE_FACTOR,
            )
            page = context.new_page()

            for name, url_template in pages:
                url = resolve_url(base_url, url_template, dashboard.ids)
                raw_path = output_dir / f"{name}-{scheme}-raw.png"
                logger.info("Capturing %s (%s)", name, scheme)
                capture_page(page, url, raw_path)
                w, h = _png_dimensions(raw_path)
                logger.info("  -> raw %dx%d", w, h)
                raw_paths.append((name, scheme, raw_path))

            context.close()

        browser.close()

    # Downscale raw captures to main and thumbnail sizes.
    generated: list[Path] = []
    main_w, main_h = MAIN_SIZE
    thumb_w, thumb_h = THUMB_SIZE

    mismatches: list[str] = []

    for name, scheme, raw_path in raw_paths:
        main_path = output_dir / f"{name}-{scheme}.png"
        thumb_path = output_dir / f"{name}-{scheme}-thumb.png"

        logger.info("Downscaling %s (%s)", name, scheme)
        _downscale(raw_path, main_path, main_w, main_h)
        _downscale(raw_path, thumb_path, thumb_w, thumb_h)

        raw_path.unlink()

        for path, exp_w, exp_h in [
            (main_path, main_w, main_h),
            (thumb_path, thumb_w, thumb_h),
        ]:
            w, h = _png_dimensions(path)
            logger.info("  -> %s (%dx%d)", path.name, w, h)
            if w != exp_w or h != exp_h:
                mismatches.append(
                    f"{path.name}: {w}x{h} (expected {exp_w}x{exp_h})"
                )
            generated.append(path)

    if mismatches:
        for msg in mismatches:
            logger.error("DIMENSION MISMATCH: %s", msg)
        raise RuntimeError(f"Dimension mismatches in {len(mismatches)} file(s)")

    generate_index(generated, output_dir)
    return generated


def generate_index(files: list[Path], output_dir: Path) -> None:
    """Generate an index.html listing all screenshot files as links.

    Args:
        files: List of generated screenshot file paths.
        output_dir: Directory containing the screenshots.
    """
    names = sorted(f.name for f in files)
    links = "\n".join(f'<li><a href="{name}">{name}</a></li>' for name in names)
    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Screenshots</title>
</head>
<body>
<h1>Screenshots</h1>
<ul>
{links}
</ul>
</body>
</html>
"""
    (output_dir / "index.html").write_text(html)
    logger.info("Generated index.html")


def main() -> None:
    """Entry point for screenshot generation."""
    parser = argparse.ArgumentParser(
        description="Generate Airut dashboard screenshots"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("screenshots/output"),
        help="Output directory for screenshots (default: screenshots/output)",
    )
    parser.add_argument(
        "--scheme",
        choices=("light", "dark", "both"),
        default="both",
        help="Color scheme to capture (default: both)",
    )
    parser.add_argument(
        "--page",
        help="Capture only this page (by name, e.g. 'dashboard')",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    schemes: tuple[str, ...]
    if args.scheme == "both":
        schemes = SCHEMES
    else:
        schemes = (args.scheme,)

    pages: list[tuple[str, str]] | None = None
    if args.page:
        pages = [(n, t) for n, t in PAGES if n == args.page]
        if not pages:
            valid = ", ".join(n for n, _ in PAGES)
            logger.error(
                "Unknown page '%s'. Valid: %s",
                args.page,
                valid,
            )
            sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="airut-screenshots-") as tmp:
        work_dir = Path(tmp)
        logger.info("Starting mock dashboard...")
        dashboard = create_mock_dashboard(work_dir)
        try:
            logger.info(
                "Dashboard running at http://127.0.0.1:%d/",
                dashboard.port,
            )
            generated = generate_screenshots(
                dashboard,
                args.output,
                schemes=schemes,
                pages=pages,
            )
            logger.info(
                "Generated %d screenshots in %s",
                len(generated),
                args.output,
            )
        finally:
            dashboard.shutdown()


if __name__ == "__main__":
    main()
