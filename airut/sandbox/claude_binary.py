# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Host-side Claude Code binary cache.

Downloads, verifies, and caches Claude Code binaries by version.
Binaries are bind-mounted into containers at runtime instead of
being installed inside container images.

Cache layout::

    {cache_dir}/
        {version}/
            claude              # executable binary
            manifest.json       # cached manifest for verification

Version resolution:

- ``"latest"`` and ``"stable"`` are resolved via the release
  distribution CDN (``downloads.claude.ai``).  The resolved version
  string is cached with a TTL to avoid network calls on every task
  startup.
- Explicit semver versions (e.g. ``"1.0.33"``) are used directly.

Thread Safety:
    All public methods are thread-safe.  Concurrent calls to
    ``ensure()`` for the same version are serialized by a per-version
    lock; calls for different versions proceed in parallel.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import platform
import re
import shutil
import tempfile
import threading
import time
import urllib.error
from pathlib import Path

from airut.http import urlopen_with_retry


logger = logging.getLogger(__name__)


#: CDN URL for Claude Code releases.
DOWNLOADS_BASE = "https://downloads.claude.ai/claude-code-releases"

#: Container path where the binary is bind-mounted.
CLAUDE_BINARY_CONTAINER_PATH = "/opt/claude/claude"

#: Valid version pattern: ``latest``, ``stable``, or semver.
_VERSION_PATTERN = re.compile(r"^(latest|stable|\d+\.\d+\.\d+(-[^\s]+)?)$")

#: Channels that require resolution to a concrete version.
_CHANNEL_NAMES = frozenset({"latest", "stable"})


def detect_platform() -> str:
    """Detect the host platform string for Claude Code downloads.

    Returns:
        Platform string like ``linux-x64``, ``linux-arm64``,
        ``linux-x64-musl``, or ``linux-arm64-musl``.

    Raises:
        RuntimeError: If the OS or architecture is unsupported.
    """
    system = platform.system().lower()
    if system != "linux":
        raise RuntimeError(f"Unsupported OS for Claude binary: {system}")

    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        raise RuntimeError(
            f"Unsupported architecture for Claude binary: {machine}"
        )

    # Detect musl libc
    is_musl = False
    for musl_lib in (
        "/lib/libc.musl-x86_64.so.1",
        "/lib/libc.musl-aarch64.so.1",
    ):
        if os.path.exists(musl_lib):
            is_musl = True
            break

    plat = f"linux-{arch}"
    if is_musl:
        plat += "-musl"
    return plat


def validate_version(version: str) -> None:
    """Validate a Claude version string.

    Args:
        version: Version string to validate.

    Raises:
        ValueError: If the version format is invalid.
    """
    if not _VERSION_PATTERN.match(version):
        raise ValueError(
            f"Invalid claude_version '{version}': "
            f"expected 'latest', 'stable', or semver (e.g. '1.0.33')"
        )


def _open_release_url(
    path: str,
    *,
    timeout: int = 30,
    max_retries: int = 3,
) -> http.client.HTTPResponse:
    """Fetch a release artifact from the CDN with retries.

    Args:
        path: Relative path within the releases directory
            (e.g. ``latest``, ``1.0.0/manifest.json``).
        timeout: Per-request timeout in seconds.
        max_retries: Retry attempts for transient failures
            (connection errors, timeouts, 5xx responses).

    Returns:
        HTTP response (usable as context manager).

    Raises:
        urllib.error.URLError: If the CDN is unreachable.
    """
    return urlopen_with_retry(
        f"{DOWNLOADS_BASE}/{path}", timeout=timeout, max_retries=max_retries
    )


class ClaudeBinaryCache:
    """Thread-safe cache for Claude Code binaries.

    Downloads binaries from ``downloads.claude.ai``, verifies SHA-256
    checksums from the manifest, and caches them on disk.

    Args:
        cache_dir: Root directory for cached binaries.
        resolution_ttl_seconds: How long to cache channel (latest/stable)
            resolution before re-checking.  Defaults to 1 hour.
        platform_override: Override detected platform (for testing).
    """

    def __init__(
        self,
        cache_dir: Path,
        *,
        resolution_ttl_seconds: int = 3600,
        platform_override: str | None = None,
    ) -> None:
        self._cache_dir = cache_dir
        self._resolution_ttl = resolution_ttl_seconds
        self._platform = platform_override or detect_platform()
        self._lock = threading.Lock()
        self._version_locks: dict[str, threading.Lock] = {}

        # Channel resolution cache: channel -> (version, timestamp)
        self._resolved: dict[str, tuple[str, float]] = {}

        self._cache_dir.mkdir(parents=True, exist_ok=True)
        logger.info(
            "Claude binary cache initialized: %s (platform=%s)",
            self._cache_dir,
            self._platform,
        )

    @property
    def cache_dir(self) -> Path:
        """Root directory for cached binaries."""
        return self._cache_dir

    def ensure(self, version: str = "latest") -> tuple[Path, str]:
        """Ensure a Claude binary is cached and return its path.

        For channel names (``latest``, ``stable``), resolves to a
        concrete version via the CDN.  Downloads and verifies
        the binary if not already cached.

        Args:
            version: Version string (``latest``, ``stable``, or semver).

        Returns:
            Tuple of (path to binary, resolved version string).

        Raises:
            ClaudeBinaryError: If download, verification, or resolution
                fails.
        """
        validate_version(version)

        # Resolve channel to concrete version
        if version in _CHANNEL_NAMES:
            resolved = self._resolve_channel(version)
        else:
            resolved = version

        # Get per-version lock
        with self._lock:
            if resolved not in self._version_locks:
                self._version_locks[resolved] = threading.Lock()
            version_lock = self._version_locks[resolved]

        with version_lock:
            binary_path = self._cache_dir / resolved / "claude"
            if binary_path.exists():
                logger.info("Claude %s: cached at %s", resolved, binary_path)
                return binary_path, resolved

            # Download and verify
            logger.info(
                "Claude %s: downloading for %s", resolved, self._platform
            )
            self._download_and_verify(resolved)
            return binary_path, resolved

    def prune(self, active_versions: set[str]) -> int:
        """Remove cached versions not in the active set.

        Args:
            active_versions: Set of version strings to keep.

        Returns:
            Number of versions removed.
        """
        removed = 0
        if not self._cache_dir.exists():
            return 0

        for entry in self._cache_dir.iterdir():
            if not entry.is_dir():
                continue
            version = entry.name
            if version in active_versions:
                continue
            logger.info("Pruning cached Claude binary: %s", version)
            shutil.rmtree(entry, ignore_errors=True)
            with self._lock:
                self._version_locks.pop(version, None)
            removed += 1

        return removed

    def list_cached_versions(self) -> list[str]:
        """List all cached version directories.

        Returns:
            Sorted list of cached version strings.
        """
        if not self._cache_dir.exists():
            return []
        versions = []
        for entry in self._cache_dir.iterdir():
            if entry.is_dir() and (entry / "claude").exists():
                versions.append(entry.name)
        return sorted(versions)

    def _resolve_channel(self, channel: str) -> str:
        """Resolve a channel name to a concrete version.

        Uses a cached resolution if within TTL.

        Args:
            channel: Channel name (``latest`` or ``stable``).

        Returns:
            Concrete version string.

        Raises:
            ClaudeBinaryError: If resolution fails.
        """
        now = time.monotonic()
        with self._lock:
            if channel in self._resolved:
                resolved, timestamp = self._resolved[channel]
                if now - timestamp < self._resolution_ttl:
                    logger.debug(
                        "Claude %s: using cached resolution → %s",
                        channel,
                        resolved,
                    )
                    return resolved

        try:
            with _open_release_url(channel) as resp:
                resolved = resp.read().decode().strip()
        except urllib.error.URLError as e:
            raise ClaudeBinaryError(
                f"Failed to resolve Claude '{channel}' version: {e}"
            ) from e

        if not resolved or not re.match(r"^\d+\.\d+\.\d+", resolved):
            raise ClaudeBinaryError(
                f"Invalid version from '{channel}' channel: {resolved!r}"
            )

        with self._lock:
            self._resolved[channel] = (resolved, time.monotonic())

        logger.info("Claude %s resolved to %s", channel, resolved)
        return resolved

    def _download_and_verify(self, version: str) -> None:
        """Download binary and manifest, verify checksum.

        Args:
            version: Concrete version string.

        Raises:
            ClaudeBinaryError: If download or verification fails.
        """
        version_dir = self._cache_dir / version
        version_dir.mkdir(parents=True, exist_ok=True)

        # Download manifest
        try:
            with _open_release_url(f"{version}/manifest.json") as resp:
                manifest_json = resp.read().decode()
        except urllib.error.URLError as e:
            raise ClaudeBinaryError(
                f"Failed to download manifest for {version}: {e}"
            ) from e

        # Extract checksum
        checksum = _extract_checksum(manifest_json, self._platform)
        if checksum is None:
            raise ClaudeBinaryError(
                f"Platform {self._platform} not found in manifest "
                f"for version {version}"
            )

        # Download binary to temp file
        binary_path = version_dir / "claude"

        # Use a temp file in the same directory for atomic rename
        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(version_dir), prefix=".claude-download-"
        )
        tmp_path = Path(tmp_path_str)
        try:
            try:
                with _open_release_url(
                    f"{version}/{self._platform}/claude", timeout=300
                ) as resp:
                    with os.fdopen(fd, "wb") as f:
                        while True:
                            chunk = resp.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)
                        fd = -1  # Prevent double-close
            except urllib.error.URLError as e:
                raise ClaudeBinaryError(
                    f"Failed to download Claude {version} binary: {e}"
                ) from e

            # Verify checksum
            actual = _sha256_file(tmp_path)
            if actual != checksum:
                raise ClaudeBinaryError(
                    f"Checksum mismatch for Claude {version} "
                    f"({self._platform}): "
                    f"expected {checksum}, got {actual}"
                )

            # Make executable and atomically move into place
            tmp_path.chmod(0o755)
            tmp_path.rename(binary_path)

            # Save manifest for reference
            (version_dir / "manifest.json").write_text(manifest_json)

            logger.info(
                "Claude %s: downloaded and verified (%s)",
                version,
                self._platform,
            )

        except BaseException:
            # Clean up temp file on any failure
            if fd >= 0:
                os.close(fd)
            tmp_path.unlink(missing_ok=True)
            raise

    def resolve_version(self, version: str) -> str:
        """Resolve a version string without downloading.

        Useful for determining active versions during GC.

        Args:
            version: Version string (channel or semver).

        Returns:
            Concrete version string.

        Raises:
            ClaudeBinaryError: If resolution fails.
        """
        validate_version(version)
        if version in _CHANNEL_NAMES:
            return self._resolve_channel(version)
        return version


class ClaudeBinaryError(Exception):
    """Raised when Claude binary operations fail."""


def _extract_checksum(manifest_json: str, plat: str) -> str | None:
    """Extract SHA-256 checksum from manifest JSON for a platform.

    Parses the manifest JSON and extracts the SHA-256 checksum
    for the given platform.

    Args:
        manifest_json: Raw manifest JSON string.
        plat: Platform string (e.g. ``linux-x64``).

    Returns:
        64-character hex checksum, or None if platform not found.
    """
    try:
        manifest = json.loads(manifest_json)
        platforms = manifest.get("platforms", {})
        platform_info = platforms.get(plat, {})
        checksum = platform_info.get("checksum", "")
        if re.match(r"^[a-f0-9]{64}$", checksum):
            return checksum
        return None
    except (json.JSONDecodeError, AttributeError):
        return None


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file.

    Args:
        path: File to hash.

    Returns:
        64-character lowercase hex digest.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
