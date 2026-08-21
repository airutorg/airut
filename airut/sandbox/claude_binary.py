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
        .resolutions.json       # last known version per channel
        {version}/
            claude              # executable binary
            manifest.json       # cached manifest for verification

Version resolution:

- ``"latest"`` and ``"stable"`` are resolved via the release
  distribution CDN (``downloads.claude.ai``).  The resolved version
  string is cached with a TTL to avoid network calls on every task
  startup, and persisted to disk so it survives a restart.
- Explicit semver versions (e.g. ``"1.0.33"``) are used directly.

A channel refresh happens on the task-startup path, so an unreachable
CDN would otherwise fail the task outright even when a perfectly good
binary is already cached.  Instead, a failed refresh falls back to the
last known resolution for that channel and logs a warning: a task
starts on a slightly stale Claude rather than not at all.  While a
fallback is in effect the refresh uses a tight timeout and is not
re-attempted for a minute, so an outage costs one task a few seconds
instead of every task the full retry budget.

Download integrity:
    The binary is several hundred megabytes, so a transfer routinely
    fails mid-body -- long after the connection was established, which
    is all ``urlopen_with_retry()`` can retry.  Each attempt therefore
    verifies the transferred byte count against the manifest ``size``
    and the SHA-256 digest against the manifest ``checksum``, and the
    whole download is retried on mismatch or transport error.

    The byte count matters because
    :meth:`http.client.HTTPResponse.read` returns an empty chunk
    (rather than raising) when the connection drops before
    ``Content-Length`` bytes have arrived: a truncated download is
    otherwise indistinguishable from a complete one, and surfaces as a
    checksum mismatch that looks like corruption.

Thread Safety:
    All public methods are thread-safe.  Concurrent calls to
    ``ensure()`` for the same version are serialized by a per-version
    lock; calls for different versions proceed in parallel.  ``prune()``
    takes the same per-version lock, so it cannot delete a directory
    while a download into it is in flight.
"""

from __future__ import annotations

import errno
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
import urllib.request
from dataclasses import dataclass
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

#: Read chunk size for streaming the binary (64 KiB).
_CHUNK_SIZE = 64 * 1024

#: Per-request timeout for the binary transfer, in seconds.
_BINARY_TIMEOUT = 300

#: Attempts for a full binary download (transfer plus verification).
_DOWNLOAD_ATTEMPTS = 3

#: Base delay in seconds between download attempts (doubles each time).
_DOWNLOAD_BACKOFF_BASE = 2.0

#: File (inside the cache dir) holding the last channel resolutions.
_RESOLUTIONS_FILE = ".resolutions.json"

#: Request budget for a channel refresh with no fallback available:
#: failing means failing the task, so try hard.
_CHANNEL_TIMEOUT = 30
_CHANNEL_RETRIES = 3

#: Request budget for a channel refresh that has a fallback: getting
#: an answer is optional, so do not stall task startup for it.
_CHANNEL_FAST_TIMEOUT = 5
_CHANNEL_FAST_RETRIES = 1

#: How long a fallback resolution is used before re-checking the CDN.
_RESOLUTION_FAILURE_TTL = 60.0


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
    no_cache: bool = False,
) -> http.client.HTTPResponse:
    """Fetch a release artifact from the CDN with retries.

    Args:
        path: Relative path within the releases directory
            (e.g. ``latest``, ``1.0.0/manifest.json``).
        timeout: Per-request timeout in seconds.
        max_retries: Retry attempts for transient failures
            (connection errors, timeouts, 5xx responses).
        no_cache: Ask intermediaries to revalidate instead of serving
            a cached copy.  Best-effort -- caches are free to ignore
            it -- but it gives a retry a chance to see fresh bytes
            when the cached ones were the problem.

    Returns:
        HTTP response (usable as context manager).

    Raises:
        urllib.error.URLError: If the CDN is unreachable.
    """
    url = f"{DOWNLOADS_BASE}/{path}"
    target: str | urllib.request.Request = url
    if no_cache:
        target = urllib.request.Request(
            url, headers={"Cache-Control": "no-cache", "Pragma": "no-cache"}
        )
    return urlopen_with_retry(target, timeout=timeout, max_retries=max_retries)


class ClaudeBinaryCache:
    """Thread-safe cache for Claude Code binaries.

    Downloads binaries from ``downloads.claude.ai``, verifies size and
    SHA-256 checksum against the manifest, and caches them on disk.

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

        # Channel resolution cache: channel -> (version, expires_at)
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

        with self._version_lock(resolved):
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
            # Hold the per-version lock so pruning cannot delete a
            # directory that ensure() is downloading into.
            with self._version_lock(version):
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

    def _version_lock(self, version: str) -> threading.Lock:
        """Return the (created on demand) lock guarding *version*.

        Args:
            version: Concrete version string.

        Returns:
            Lock serializing cache mutations for that version.
        """
        with self._lock:
            lock = self._version_locks.get(version)
            if lock is None:
                lock = threading.Lock()
                self._version_locks[version] = lock
            return lock

    def _resolve_channel(self, channel: str) -> str:
        """Resolve a channel name to a concrete version.

        Uses the cached resolution while it is fresh.  If a refresh
        fails but a previous resolution is known -- from this process
        or a previous one -- that version is used instead of failing:
        an unreachable CDN should not stop a task that has a usable
        binary cached already.

        Args:
            channel: Channel name (``latest`` or ``stable``).

        Returns:
            Concrete version string.

        Raises:
            ClaudeBinaryError: If resolution fails and no previous
                resolution is known.
        """
        with self._lock:
            cached = self._resolved.get(channel)
        if cached is not None and time.monotonic() < cached[1]:
            logger.debug(
                "Claude %s: using cached resolution → %s", channel, cached[0]
            )
            return cached[0]

        fallback = (
            cached[0]
            if cached is not None
            else self._read_persisted_resolution(channel)
        )

        try:
            resolved = self._fetch_channel(channel, fast=fallback is not None)
        except ClaudeBinaryError as e:
            if fallback is None:
                raise
            cached_note = (
                ""
                if (self._cache_dir / fallback / "claude").exists()
                else " (not cached -- download will be attempted)"
            )
            logger.warning(
                "Claude %s: resolution failed (%s); falling back to last "
                "known version %s%s",
                channel,
                e,
                fallback,
                cached_note,
            )
            with self._lock:
                self._resolved[channel] = (
                    fallback,
                    time.monotonic() + _RESOLUTION_FAILURE_TTL,
                )
            return fallback

        with self._lock:
            self._resolved[channel] = (
                resolved,
                time.monotonic() + self._resolution_ttl,
            )
            self._persist_resolution(channel, resolved)

        logger.info("Claude %s resolved to %s", channel, resolved)
        return resolved

    def _fetch_channel(self, channel: str, *, fast: bool) -> str:
        """Fetch and validate the current version for a channel.

        Args:
            channel: Channel name (``latest`` or ``stable``).
            fast: Use the reduced request budget -- set when a
                fallback resolution is available.

        Returns:
            Concrete version string.

        Raises:
            ClaudeBinaryError: If the fetch fails or returns a version
                that does not look like semver.
        """
        timeout = _CHANNEL_FAST_TIMEOUT if fast else _CHANNEL_TIMEOUT
        retries = _CHANNEL_FAST_RETRIES if fast else _CHANNEL_RETRIES
        try:
            with _open_release_url(
                channel, timeout=timeout, max_retries=retries
            ) as resp:
                resolved = resp.read().decode().strip()
        except (OSError, http.client.HTTPException) as e:
            raise ClaudeBinaryError(
                f"Failed to resolve Claude '{channel}' version: {e}"
            ) from e

        if not resolved or not re.match(r"^\d+\.\d+\.\d+", resolved):
            raise ClaudeBinaryError(
                f"Invalid version from '{channel}' channel: {resolved!r}"
            )
        return resolved

    def _read_persisted_resolution(self, channel: str) -> str | None:
        """Read the last resolution for a channel from disk.

        Args:
            channel: Channel name (``latest`` or ``stable``).

        Returns:
            Version string, or None if nothing usable is stored.
        """
        try:
            raw = (self._cache_dir / _RESOLUTIONS_FILE).read_text()
            stored = json.loads(raw).get(channel)
        except (OSError, json.JSONDecodeError, AttributeError):
            return None
        if isinstance(stored, str) and re.match(r"^\d+\.\d+\.\d+", stored):
            return stored
        return None

    def _persist_resolution(self, channel: str, version: str) -> None:
        """Store a channel resolution so it survives a restart.

        Best-effort: a cache directory we cannot write to is not worth
        failing a task over.  Caller must hold ``self._lock``.

        Args:
            channel: Channel name (``latest`` or ``stable``).
            version: Resolved version string.
        """
        path = self._cache_dir / _RESOLUTIONS_FILE
        try:
            stored = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            stored = {}
        if not isinstance(stored, dict):
            stored = {}
        stored[channel] = version

        tmp_path = path.parent / f"{_RESOLUTIONS_FILE}.tmp"
        try:
            tmp_path.write_text(json.dumps(stored))
            tmp_path.replace(path)
        except OSError as e:
            tmp_path.unlink(missing_ok=True)
            logger.warning(
                "Failed to persist Claude '%s' resolution: %s", channel, e
            )

    def _download_and_verify(self, version: str) -> None:
        """Download binary and manifest, verifying integrity.

        Retries the full download on transport errors, truncated
        bodies, and checksum mismatches.  Retries bypass intermediary
        caches, so a stale cached manifest or binary is not simply
        re-served.

        Args:
            version: Concrete version string.

        Raises:
            ClaudeBinaryError: If download or verification fails.
        """
        version_dir = self._cache_dir / version
        last_error: _TransferError | None = None

        for attempt in range(1, _DOWNLOAD_ATTEMPTS + 1):
            try:
                self._attempt_download(
                    version, version_dir, no_cache=attempt > 1
                )
            except _TransferError as e:
                last_error = e
                if attempt < _DOWNLOAD_ATTEMPTS:
                    delay = _DOWNLOAD_BACKOFF_BASE * 2 ** (attempt - 1)
                    logger.warning(
                        "Claude %s: download attempt %d/%d failed (%s); "
                        "retrying in %.0fs",
                        version,
                        attempt,
                        _DOWNLOAD_ATTEMPTS,
                        e,
                        delay,
                    )
                    time.sleep(delay)
                continue

            logger.info(
                "Claude %s: downloaded and verified (%s)",
                version,
                self._platform,
            )
            return

        raise ClaudeBinaryError(
            f"Failed to download Claude {version} for {self._platform} "
            f"after {_DOWNLOAD_ATTEMPTS} attempts: {last_error}"
        )

    def _attempt_download(
        self, version: str, version_dir: Path, *, no_cache: bool
    ) -> None:
        """Run one full download: manifest, binary, verify, install.

        The binary is streamed to a temp file in *version_dir* and
        moved into place only after its size and checksum match the
        manifest, so a failed attempt never leaves a usable-looking
        binary behind.

        Args:
            version: Concrete version string.
            version_dir: Cache directory for this version.
            no_cache: Bypass intermediary caches (used on retries).

        Raises:
            _TransferError: Transient failure -- worth another attempt.
            ClaudeBinaryError: Permanent failure (unknown platform,
                HTTP status error, no disk space, unwritable cache).
        """
        manifest_json = self._fetch_manifest(version, no_cache=no_cache)
        info = _extract_platform_info(manifest_json, self._platform)
        if info is None:
            raise ClaudeBinaryError(
                f"Platform {self._platform} not found in manifest "
                f"for version {version}"
            )

        try:
            version_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_path_str = tempfile.mkstemp(
                dir=str(version_dir), prefix=".claude-download-"
            )
        except OSError as e:
            raise ClaudeBinaryError(
                f"Failed to prepare cache directory {version_dir}: {e}"
            ) from e

        tmp_path = Path(tmp_path_str)
        try:
            digest = hashlib.sha256()
            written = 0
            try:
                with (
                    _open_release_url(
                        f"{version}/{self._platform}/claude",
                        timeout=_BINARY_TIMEOUT,
                        no_cache=no_cache,
                    ) as resp,
                    os.fdopen(fd, "wb") as f,
                ):
                    fd = -1  # os.fdopen() owns the descriptor now
                    while True:
                        chunk = resp.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
                        digest.update(chunk)
                        written += len(chunk)
            except OSError as e:
                if e.errno == errno.ENOSPC:
                    raise ClaudeBinaryError(
                        f"Out of disk space downloading Claude {version} "
                        f"to {version_dir}"
                    ) from e
                raise _fetch_error(
                    f"Failed to download Claude {version} binary", e
                ) from e
            except http.client.HTTPException as e:
                raise _TransferError(
                    f"Failed to download Claude {version} binary: {e}"
                ) from e

            # HTTPResponse.read() reports a dropped connection as EOF,
            # so a short body is the signal that the transfer was cut.
            if info.size is not None and written != info.size:
                raise _TransferError(
                    f"Incomplete download of Claude {version} "
                    f"({self._platform}): got {written} of "
                    f"{info.size} bytes"
                )

            actual = digest.hexdigest()
            if actual != info.checksum:
                raise _TransferError(
                    f"Checksum mismatch for Claude {version} "
                    f"({self._platform}): "
                    f"expected {info.checksum}, got {actual}"
                )

            try:
                (version_dir / "manifest.json").write_text(manifest_json)
                tmp_path.chmod(0o755)
                # Atomic: the binary only becomes visible once verified.
                tmp_path.rename(version_dir / "claude")
            except OSError as e:
                raise ClaudeBinaryError(
                    f"Failed to install Claude {version} binary: {e}"
                ) from e

        except BaseException:
            # Clean up temp file on any failure
            if fd >= 0:
                os.close(fd)
            tmp_path.unlink(missing_ok=True)
            raise

    def _fetch_manifest(self, version: str, *, no_cache: bool) -> str:
        """Download the release manifest for a version.

        Args:
            version: Concrete version string.
            no_cache: Bypass intermediary caches (used on retries).

        Returns:
            Raw manifest JSON.

        Raises:
            _TransferError: Transient failure -- worth another attempt.
            ClaudeBinaryError: HTTP status error (e.g. unknown version).
        """
        try:
            with _open_release_url(
                f"{version}/manifest.json", no_cache=no_cache
            ) as resp:
                return resp.read().decode()
        except OSError as e:
            raise _fetch_error(
                f"Failed to download manifest for {version}", e
            ) from e
        except http.client.HTTPException as e:
            raise _TransferError(
                f"Failed to download manifest for {version}: {e}"
            ) from e

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


class _TransferError(Exception):
    """A download failure that a fresh attempt might succeed at."""


def _fetch_error(context: str, error: OSError) -> Exception:
    """Classify a fetch failure as retryable or permanent.

    ``urlopen_with_retry()`` already retried retryable statuses, and
    everything else (404 for an unknown version, 403) will not fix
    itself, so any HTTP status error is permanent.  Connection resets,
    timeouts, and TLS errors are worth another attempt.

    Args:
        context: Human-readable description of what was being fetched.
        error: The exception raised by the fetch.

    Returns:
        Exception to raise (never raises itself).
    """
    if isinstance(error, urllib.error.HTTPError):
        return ClaudeBinaryError(f"{context}: HTTP {error.code} {error.reason}")
    return _TransferError(f"{context}: {error}")


@dataclass(frozen=True)
class _PlatformInfo:
    """Manifest entry for one platform.

    Attributes:
        checksum: Expected SHA-256 hex digest of the binary.
        size: Expected size in bytes, or None if the manifest omits it.
    """

    checksum: str
    size: int | None


def _extract_platform_info(
    manifest_json: str, plat: str
) -> _PlatformInfo | None:
    """Extract the manifest entry for a platform.

    Args:
        manifest_json: Raw manifest JSON string.
        plat: Platform string (e.g. ``linux-x64``).

    Returns:
        Platform info, or None if the platform is missing or its
        checksum is not a 64-character hex digest.
    """
    try:
        manifest = json.loads(manifest_json)
        platforms = manifest.get("platforms", {})
        platform_info = platforms.get(plat, {})
        checksum = platform_info.get("checksum", "")
        if not re.match(r"^[a-f0-9]{64}$", checksum):
            return None
        size = platform_info.get("size")
        if not isinstance(size, int) or size <= 0:
            size = None
        return _PlatformInfo(checksum=checksum, size=size)
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None
