# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Unified image cache with content-hash tags and staleness checking.

Provides a single ``ImageCache`` that handles all container image
builds: repo layer, overlay layer, and proxy.

Images are tagged ``{resource_prefix}-{kind}:{content_hash}`` and
their age is determined by ``podman image inspect``, not in-memory
state.  Stale rebuilds use ``--no-cache`` to defeat podman layer
caching and actually pick up upstream changes.
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path


logger = logging.getLogger(__name__)


class ImageBuildError(Exception):
    """Raised when container image build fails."""


@dataclass(frozen=True)
class ImageBuildSpec:
    """Everything needed to build a container image.

    Attributes:
        kind: Image kind, used as the middle segment of the tag
            (e.g. "repo", "overlay", "proxy").
        dockerfile: Dockerfile content (bytes).
        context_files: Additional files for build context. Mapping
            of filename to content bytes. All files are written to
            a temporary directory alongside the Dockerfile for the
            build.
    """

    kind: str
    dockerfile: bytes
    context_files: dict[str, bytes] = field(default_factory=dict)


def content_hash(spec: ImageBuildSpec) -> str:
    """SHA-256 of dockerfile + sorted context file names and contents."""
    h = hashlib.sha256()
    h.update(spec.dockerfile)
    for name in sorted(spec.context_files):
        h.update(name.encode())
        h.update(spec.context_files[name])
    return h.hexdigest()


# Go's time.Time.String() format: "2006-01-02 15:04:05.999999999 -0700 MST"
# Nanosecond fractional part is variable-length. Trailing timezone name ignored.
_GO_TIME_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})\s+"
    r"(\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d+))?"
    r"\s+([+-]\d{4})"
)


def _parse_timestamp(raw: str) -> datetime | None:
    """Parse a container-engine timestamp into a timezone-aware datetime.

    Handles both ISO 8601 (docker) and Go ``time.Time.String()`` format
    (podman).  Returns ``None`` if parsing fails.
    """
    # Try ISO 8601 first (docker, and some podman versions).
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        pass

    # Try Go time.Time.String() format used by podman's {{.Created}}.
    m = _GO_TIME_RE.match(raw)
    if m:
        date_str, time_str, frac, tz_offset = m.groups()
        # Truncate nanoseconds to microseconds (Python max precision).
        micros = 0
        if frac:
            micros = int(frac[:6].ljust(6, "0"))
        # Parse timezone offset like "+0000" or "-0500".
        sign = 1 if tz_offset[0] == "+" else -1
        tz_hours = int(tz_offset[1:3])
        tz_mins = int(tz_offset[3:5])
        tz = timezone(timedelta(hours=sign * tz_hours, minutes=sign * tz_mins))
        return datetime.fromisoformat(
            f"{date_str}T{time_str}.{micros:06d}"
        ).replace(tzinfo=tz)

    return None


def _format_age(age: timedelta) -> str:
    """Format a timedelta as a human-readable age string."""
    total_seconds = int(age.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h{minutes}m"
    if minutes > 0:
        return f"{minutes}m{seconds}s"
    return f"{seconds}s"


class ImageCache:
    """Thread-safe container image cache with staleness checking.

    All builds are serialized via a lock. Image age is determined
    by ``podman image inspect``, not in-memory state.
    """

    def __init__(
        self,
        container_command: str,
        resource_prefix: str,
        max_age_hours: int,
    ) -> None:
        self._cmd = container_command
        self._resource_prefix = resource_prefix
        self._max_age_hours = max_age_hours
        self._lock = threading.Lock()

    def ensure(self, spec: ImageBuildSpec, *, force: bool = False) -> str:
        """Build or reuse an image. Returns the image tag.

        Args:
            spec: What to build.
            force: If True, rebuild with --no-cache regardless of age.
        """
        tag = self.tag_for(spec)

        with self._lock:
            created = self.get_image_created(tag)

            if created is None:
                # Image does not exist -- first build.
                # Podman layer cache is fine here (nothing stale to bust).
                logger.info("%s: not found, building (no_cache=False)", tag)
                self._build(spec, tag, no_cache=False)

            elif force or self._max_age_hours == 0:
                # Force-rebuild mode (explicit force, or max_age_hours 0).
                age = datetime.now(UTC) - created
                logger.info(
                    "%s: age %s, force-rebuilding (no_cache=True)",
                    tag,
                    _format_age(age),
                )
                self._build(spec, tag, no_cache=True)

            elif self._is_stale(created):
                # Image exists but is stale -- rebuild with --no-cache
                # to pick up upstream changes (new Claude Code, etc.).
                age = datetime.now(UTC) - created
                logger.info(
                    "%s: age %s > %dh max, rebuilding (no_cache=True)",
                    tag,
                    _format_age(age),
                    self._max_age_hours,
                )
                self._build(spec, tag, no_cache=True)

            else:
                age = datetime.now(UTC) - created
                logger.info(
                    "%s: age %s <= %dh max, reusing",
                    tag,
                    _format_age(age),
                    self._max_age_hours,
                )

        return tag

    def prune_images(self) -> int:
        """Remove dangling images and old airut-prefixed images.

        Runs ``<cmd> image prune -f`` to remove dangling (untagged)
        images, then lists images matching the resource prefix and
        removes any that exceed ``max_age_hours``.

        This method does NOT hold the build lock while running prune
        commands, so concurrent image builds are not blocked.

        There is a benign TOCTOU race: ``prune_images`` may check an
        image's age and then ``rmi`` it just after a concurrent
        ``ensure()`` rebuilt the same tag.  The next ``ensure()`` call
        will find the image missing and rebuild it.  The worst outcome
        is one extra rebuild, never data loss or task failure.

        In normal operation most prefixed images are kept fresh by
        ``ensure()`` rebuilds during task startup.  This method mainly
        catches images whose content hash changed (e.g., Dockerfile
        edits) and are no longer actively requested.

        Returns:
            Number of old prefixed images removed.
        """
        if self._max_age_hours == 0:
            # max_age_hours=0 means "always rebuild" -- pruning all images
            # every GC cycle would cause needless churn.
            return 0

        # 1. Remove dangling (untagged) images.
        result = subprocess.run(
            [self._cmd, "image", "prune", "-f"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning("image prune -f failed: %s", result.stderr.strip())
        else:
            stdout = result.stdout.strip()
            if stdout:
                logger.info("Dangling image prune output: %s", stdout)

        # 2. Remove old airut-prefixed images beyond max_age_hours.
        # Uses the same staleness threshold as ensure() -- in practice most
        # images are kept fresh by ensure() rebuilds during task startup, so
        # this mainly catches images whose content hash changed.
        result = subprocess.run(
            [
                self._cmd,
                "images",
                "--format",
                "{{.Repository}}:{{.Tag}}",
                "--filter",
                f"reference={self._resource_prefix}-*",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning("image list failed: %s", result.stderr.strip())
            return 0

        removed = 0
        for line in result.stdout.strip().splitlines():
            tag = line.strip()
            if not tag or tag == "<none>:<none>":
                continue
            created = self.get_image_created(tag)
            if created is None:
                continue
            if self._is_stale(created):
                age = datetime.now(UTC) - created
                logger.info(
                    "Pruning old image %s (age: %s)", tag, _format_age(age)
                )
                rm_result = subprocess.run(
                    [self._cmd, "rmi", tag],
                    capture_output=True,
                    text=True,
                )
                if rm_result.returncode == 0:
                    removed += 1
                else:
                    logger.warning(
                        "Failed to remove %s: %s",
                        tag,
                        rm_result.stderr.strip(),
                    )
        return removed

    def tag_for(self, spec: ImageBuildSpec) -> str:
        """Compute the tag for a spec without building.

        Useful for pre-build inspection (e.g., checking whether a
        rebuild was triggered).
        """
        chash = content_hash(spec)
        return f"{self._resource_prefix}-{spec.kind}:{chash}"

    def get_image_created(self, tag: str) -> datetime | None:
        """Query podman for image creation timestamp.

        Returns:
            Image creation time (timezone-aware), or None if the image
            does not exist or the timestamp cannot be parsed.
        """
        result = subprocess.run(
            [self._cmd, "image", "inspect", tag, "--format", "{{.Created}}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return None
        raw = result.stdout.strip()
        dt = _parse_timestamp(raw)
        if dt is None:
            logger.warning("Cannot parse image timestamp for %s: %r", tag, raw)
        return dt

    def _is_stale(self, created: datetime) -> bool:
        """Check if an image creation time is older than max_age_hours."""
        age = datetime.now(UTC) - created
        return age > timedelta(hours=self._max_age_hours)

    def _build(
        self,
        spec: ImageBuildSpec,
        tag: str,
        *,
        no_cache: bool,
    ) -> None:
        """Execute podman build.

        Raises:
            ImageBuildError: If the build fails.
        """
        logger.info("Building image %s (no_cache=%s)", tag, no_cache)

        with tempfile.TemporaryDirectory() as tmpdir:
            df_path = Path(tmpdir) / "Dockerfile"
            df_path.write_bytes(spec.dockerfile)

            for name, content in spec.context_files.items():
                if "/" in name or "\\" in name or name in (".", ".."):
                    msg = f"Invalid context file name: {name!r}"
                    raise ValueError(msg)
                (Path(tmpdir) / name).write_bytes(content)

            cmd = [self._cmd, "build", "-t", tag, "-f", str(df_path)]
            if no_cache:
                cmd.append("--no-cache")
            cmd.append(tmpdir)

            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                raise ImageBuildError(
                    f"Image build failed for {tag}: {e.stderr.strip()}"
                ) from e

        logger.info("Image built: %s", tag)
