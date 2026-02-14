# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Two-layer container image building for the sandbox.

The container image is built in two layers:
1. **Repo image**: Built from a Dockerfile and context files provided
   by the caller. Contains the tools and dependencies the repository needs.
2. **Overlay image**: Built on top of the repo image, adding the
   sandbox-generated entrypoint script.

Images are cached by content hash (SHA-256 of Dockerfile / entrypoint)
and rebuilt when stale (default 24 hours) to pick up upstream updates.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lib.sandbox._entrypoint import get_entrypoint_content


logger = logging.getLogger(__name__)


class ImageBuildError(Exception):
    """Raised when container image build fails."""


@dataclass
class _ImageInfo:
    """Tracks a built image and its build time."""

    tag: str
    built_at: datetime


def _content_hash(content: bytes | str) -> str:
    """Compute SHA-256 hex digest of content."""
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()


def build_repo_image(
    container_command: str,
    dockerfile_content: bytes,
    context_files: dict[str, bytes],
    repo_images: dict[str, _ImageInfo],
    max_age_hours: int,
) -> str:
    """Build the repo image from Dockerfile content.

    Args:
        container_command: Container runtime command.
        dockerfile_content: Raw Dockerfile bytes.
        context_files: Additional files for build context.
        repo_images: Cache of built repo images.
        max_age_hours: Maximum image age before rebuild.

    Returns:
        Image tag (e.g., ``airut-repo:abcdef0123456789``).

    Raises:
        ImageBuildError: If build fails.
    """
    # Include context files in hash for cache key
    hash_input = dockerfile_content
    for filename in sorted(context_files.keys()):
        hash_input += filename.encode() + context_files[filename]
    content_hash = _content_hash(hash_input)
    tag = f"airut-repo:{content_hash}"

    # Check cache
    cached = repo_images.get(content_hash)
    if cached and _is_image_fresh(cached, max_age_hours):
        logger.debug("Repo image %s is fresh, reusing", tag)
        return tag

    # Build in temp directory
    logger.info("Building repo image: %s", tag)
    start_time = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        dockerfile_path = Path(tmpdir) / "Dockerfile"
        dockerfile_path.write_bytes(dockerfile_content)

        # Write additional context files
        for filename, content in context_files.items():
            file_path = Path(tmpdir) / filename
            file_path.write_bytes(content)
            logger.debug("Added context file: %s", filename)

        cmd = [
            container_command,
            "build",
            "-t",
            tag,
            "-f",
            str(dockerfile_path),
            tmpdir,
        ]

        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            logger.error("Failed to build repo image: %s", error_msg)
            raise ImageBuildError(f"Repo image build failed: {error_msg}")

    elapsed = time.time() - start_time
    logger.info("Repo image built in %.2fs: %s", elapsed, tag)

    repo_images[content_hash] = _ImageInfo(tag=tag, built_at=datetime.now(UTC))

    return tag


def build_overlay_image(
    container_command: str,
    repo_tag: str,
    overlay_images: dict[str, _ImageInfo],
    max_age_hours: int,
) -> str:
    """Build the overlay image on top of the repo image.

    The entrypoint is generated in code (not read from an external file).

    Args:
        container_command: Container runtime command.
        repo_tag: Tag of the repo image to use as base.
        overlay_images: Cache of built overlay images.
        max_age_hours: Maximum image age before rebuild.

    Returns:
        Overlay image tag (e.g., ``airut:abcdef0123456789``).

    Raises:
        ImageBuildError: If build fails.
    """
    entrypoint_content = get_entrypoint_content()

    overlay_hash = _content_hash(repo_tag.encode() + entrypoint_content)
    tag = f"airut:{overlay_hash}"

    # Check cache
    cached = overlay_images.get(overlay_hash)
    if cached and _is_image_fresh(cached, max_age_hours):
        logger.debug("Overlay image %s is fresh, reusing", tag)
        return tag

    logger.info("Building overlay image: %s (base: %s)", tag, repo_tag)
    start_time = time.time()

    # Build overlay with entrypoint
    overlay_dockerfile = (
        f"FROM {repo_tag}\n"
        "COPY airut-entrypoint.sh /entrypoint.sh\n"
        "RUN chmod +x /entrypoint.sh\n"
        'ENTRYPOINT ["/entrypoint.sh"]\n'
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write overlay Dockerfile
        df_path = Path(tmpdir) / "Dockerfile"
        df_path.write_text(overlay_dockerfile)

        # Copy entrypoint into build context
        ep_path = Path(tmpdir) / "airut-entrypoint.sh"
        ep_path.write_bytes(entrypoint_content)

        cmd = [
            container_command,
            "build",
            "-t",
            tag,
            "-f",
            str(df_path),
            tmpdir,
        ]

        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            logger.error("Failed to build overlay image: %s", error_msg)
            raise ImageBuildError(f"Overlay image build failed: {error_msg}")

    elapsed = time.time() - start_time
    logger.info("Overlay image built in %.2fs: %s", elapsed, tag)

    overlay_images[overlay_hash] = _ImageInfo(
        tag=tag, built_at=datetime.now(UTC)
    )

    return tag


def _is_image_fresh(info: _ImageInfo, max_age_hours: int) -> bool:
    """Check if an image is younger than max_age_hours."""
    age = datetime.now(UTC) - info.built_at
    return age <= timedelta(hours=max_age_hours)
