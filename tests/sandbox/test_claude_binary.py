# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/sandbox/claude_binary.py."""

from __future__ import annotations

import hashlib
import json
import shutil
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from airut.sandbox.claude_binary import (
    CLAUDE_BINARY_CONTAINER_PATH,
    DOWNLOADS_BASE,
    ClaudeBinaryCache,
    ClaudeBinaryError,
    _extract_checksum,
    _open_release_url,
    _sha256_file,
    detect_platform,
    validate_version,
)


_URLOPEN_WITH_RETRY = "airut.sandbox.claude_binary.urlopen_with_retry"


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


def _url_response(data: bytes | list[bytes]) -> MagicMock:
    """Create a mock ``urlopen()`` return value (context manager).

    Args:
        data: If bytes, ``read()`` always returns that value.
              If list, ``read()`` returns items sequentially
              (use for chunked streaming; append ``b""`` as sentinel).
    """
    resp = MagicMock()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    if isinstance(data, list):
        resp.read.side_effect = data
    else:
        resp.read.return_value = data
    return resp


# -------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------


class TestConstants:
    """Tests for module-level constants."""

    def test_container_path(self) -> None:
        """Container path is /opt/claude/claude."""
        assert CLAUDE_BINARY_CONTAINER_PATH == "/opt/claude/claude"

    def test_downloads_base(self) -> None:
        """CDN URL is downloads.claude.ai."""
        assert "downloads.claude.ai" in DOWNLOADS_BASE


# -------------------------------------------------------------------
# _open_release_url
# -------------------------------------------------------------------


class TestOpenReleaseUrl:
    """Tests for _open_release_url()."""

    def test_cdn_succeeds(self) -> None:
        """Returns response from CDN."""
        resp = _url_response(b"data")

        with patch(_URLOPEN_WITH_RETRY) as mock_fetch:
            mock_fetch.return_value = resp
            result = _open_release_url("latest")

        assert result is resp
        mock_fetch.assert_called_once()
        url = mock_fetch.call_args[0][0]
        assert url.startswith(DOWNLOADS_BASE)

    def test_cdn_failure_propagates(self) -> None:
        """Raises URLError when CDN fails."""
        with (
            patch(_URLOPEN_WITH_RETRY) as mock_fetch,
            pytest.raises(URLError, match="cdn down"),
        ):
            mock_fetch.side_effect = URLError("cdn down")
            _open_release_url("latest")

    def test_timeout_passed_through(self) -> None:
        """Custom timeout is forwarded to urlopen_with_retry."""
        resp = _url_response(b"data")

        with patch(_URLOPEN_WITH_RETRY) as mock_fetch:
            mock_fetch.return_value = resp
            _open_release_url("1.0.0/manifest.json", timeout=300)

        mock_fetch.assert_called_once()
        assert mock_fetch.call_args[1]["timeout"] == 300

    def test_max_retries_passed_through(self) -> None:
        """Custom max_retries is forwarded to urlopen_with_retry."""
        resp = _url_response(b"data")

        with patch(_URLOPEN_WITH_RETRY) as mock_fetch:
            mock_fetch.return_value = resp
            _open_release_url("latest", max_retries=5)

        mock_fetch.assert_called_once()
        assert mock_fetch.call_args[1]["max_retries"] == 5

    def test_path_appended_to_base(self) -> None:
        """Path is appended to base URL."""
        resp = _url_response(b"data")

        with patch(_URLOPEN_WITH_RETRY) as mock_fetch:
            mock_fetch.return_value = resp
            _open_release_url("1.2.3/linux-x64/claude")

        url = mock_fetch.call_args[0][0]
        assert url.endswith("/1.2.3/linux-x64/claude")


# -------------------------------------------------------------------
# detect_platform
# -------------------------------------------------------------------


class TestDetectPlatform:
    """Tests for detect_platform()."""

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    @patch("os.path.exists", return_value=False)
    def test_linux_x64(self, *_mocks: MagicMock) -> None:
        """Detects linux-x64."""
        assert detect_platform() == "linux-x64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="aarch64")
    @patch("os.path.exists", return_value=False)
    def test_linux_arm64(self, *_mocks: MagicMock) -> None:
        """Detects linux-arm64."""
        assert detect_platform() == "linux-arm64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="x86_64")
    @patch("os.path.exists", side_effect=lambda p: "musl" in p)
    def test_linux_x64_musl(self, *_mocks: MagicMock) -> None:
        """Detects linux-x64-musl when musl lib exists."""
        assert detect_platform() == "linux-x64-musl"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="amd64")
    @patch("os.path.exists", return_value=False)
    def test_linux_amd64_alias(self, *_mocks: MagicMock) -> None:
        """Handles amd64 alias for x86_64."""
        assert detect_platform() == "linux-x64"

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="arm64")
    @patch("os.path.exists", return_value=False)
    def test_linux_arm64_alias(self, *_mocks: MagicMock) -> None:
        """Handles arm64 alias for aarch64."""
        assert detect_platform() == "linux-arm64"

    @patch("platform.system", return_value="Darwin")
    def test_unsupported_os(self, _mock: MagicMock) -> None:
        """Raises RuntimeError for non-Linux."""
        with pytest.raises(RuntimeError, match="Unsupported OS"):
            detect_platform()

    @patch("platform.system", return_value="Linux")
    @patch("platform.machine", return_value="mips")
    def test_unsupported_arch(self, *_mocks: MagicMock) -> None:
        """Raises RuntimeError for unsupported architecture."""
        with pytest.raises(RuntimeError, match="Unsupported arch"):
            detect_platform()


# -------------------------------------------------------------------
# validate_version
# -------------------------------------------------------------------


class TestValidateVersion:
    """Tests for validate_version()."""

    def test_latest(self) -> None:
        """Accepts 'latest'."""
        validate_version("latest")

    def test_stable(self) -> None:
        """Accepts 'stable'."""
        validate_version("stable")

    def test_semver(self) -> None:
        """Accepts semver version."""
        validate_version("1.0.33")

    def test_semver_with_prerelease(self) -> None:
        """Accepts semver with prerelease suffix."""
        validate_version("1.0.33-beta.1")

    def test_invalid(self) -> None:
        """Rejects invalid version string."""
        with pytest.raises(ValueError, match="Invalid claude_version"):
            validate_version("not-a-version")

    def test_empty(self) -> None:
        """Rejects empty string."""
        with pytest.raises(ValueError, match="Invalid claude_version"):
            validate_version("")


# -------------------------------------------------------------------
# _extract_checksum
# -------------------------------------------------------------------


class TestExtractChecksum:
    """Tests for _extract_checksum()."""

    def test_valid_manifest(self) -> None:
        """Extracts checksum from valid manifest JSON."""
        checksum = "a" * 64
        manifest = json.dumps(
            {"platforms": {"linux-x64": {"checksum": checksum}}}
        )
        assert _extract_checksum(manifest, "linux-x64") == checksum

    def test_missing_platform(self) -> None:
        """Returns None for missing platform."""
        manifest = json.dumps(
            {"platforms": {"linux-arm64": {"checksum": "b" * 64}}}
        )
        assert _extract_checksum(manifest, "linux-x64") is None

    def test_invalid_checksum_format(self) -> None:
        """Returns None for non-hex checksum."""
        manifest = json.dumps(
            {"platforms": {"linux-x64": {"checksum": "not-hex"}}}
        )
        assert _extract_checksum(manifest, "linux-x64") is None

    def test_invalid_json(self) -> None:
        """Returns None for invalid JSON."""
        assert _extract_checksum("not-json{", "linux-x64") is None

    def test_missing_platforms_key(self) -> None:
        """Returns None when platforms key is missing."""
        assert _extract_checksum("{}", "linux-x64") is None


# -------------------------------------------------------------------
# _sha256_file
# -------------------------------------------------------------------


class TestSha256File:
    """Tests for _sha256_file()."""

    def test_correct_hash(self, tmp_path: Path) -> None:
        """Computes correct SHA-256 for a file."""
        content = b"hello world"
        f = tmp_path / "test"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert _sha256_file(f) == expected

    def test_empty_file(self, tmp_path: Path) -> None:
        """Computes hash for empty file."""
        f = tmp_path / "empty"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert _sha256_file(f) == expected

    def test_large_file(self, tmp_path: Path) -> None:
        """Computes hash for file larger than chunk size."""
        content = b"x" * 20000
        f = tmp_path / "large"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert _sha256_file(f) == expected


# -------------------------------------------------------------------
# ClaudeBinaryCache
# -------------------------------------------------------------------


def _make_manifest(checksum: str, platform: str = "linux-x64") -> str:
    """Create a manifest JSON string."""
    return json.dumps({"platforms": {platform: {"checksum": checksum}}})


_OPEN_RELEASE_URL = "airut.sandbox.claude_binary._open_release_url"


class TestClaudeBinaryCache:
    """Tests for ClaudeBinaryCache."""

    def test_init_creates_cache_dir(self, tmp_path: Path) -> None:
        """Constructor creates the cache directory."""
        cache_dir = tmp_path / "cache"
        ClaudeBinaryCache(cache_dir, platform_override="linux-x64")
        assert cache_dir.is_dir()

    def test_cache_dir_property(self, tmp_path: Path) -> None:
        """cache_dir property returns the path."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        assert cache.cache_dir == tmp_path

    def test_ensure_downloads_on_miss(self, tmp_path: Path) -> None:
        """ensure() downloads binary on cache miss."""
        binary_content = b"fake-claude-binary"
        checksum = hashlib.sha256(binary_content).hexdigest()
        manifest = _make_manifest(checksum)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        manifest_resp = _url_response(manifest.encode())
        binary_resp = _url_response([binary_content, b""])

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [manifest_resp, binary_resp]
            path, version = cache.ensure("1.2.3")

        assert version == "1.2.3"
        assert path == tmp_path / "1.2.3" / "claude"
        assert path.exists()
        assert path.read_bytes() == binary_content

    def test_ensure_uses_cache_on_hit(self, tmp_path: Path) -> None:
        """ensure() returns cached path without download."""
        version_dir = tmp_path / "1.2.3"
        version_dir.mkdir()
        (version_dir / "claude").write_bytes(b"cached")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        path, version = cache.ensure("1.2.3")

        assert version == "1.2.3"
        assert path == version_dir / "claude"

    def test_ensure_latest_resolves_channel(self, tmp_path: Path) -> None:
        """ensure('latest') resolves to concrete version."""
        # Pre-populate cache for the resolved version
        version_dir = tmp_path / "2.0.0"
        version_dir.mkdir()
        (version_dir / "claude").write_bytes(b"binary")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        channel_resp = _url_response(b"2.0.0")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [channel_resp]
            path, version = cache.ensure("latest")

        assert version == "2.0.0"

    def test_ensure_invalid_version_raises(self, tmp_path: Path) -> None:
        """ensure() raises ValueError for invalid version."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        with pytest.raises(ValueError, match="Invalid claude_version"):
            cache.ensure("bad-version")

    def test_ensure_checksum_mismatch_raises(self, tmp_path: Path) -> None:
        """ensure() raises on checksum mismatch."""
        wrong_checksum = "f" * 64
        manifest = _make_manifest(wrong_checksum)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        manifest_resp = _url_response(manifest.encode())
        binary_resp = _url_response([b"binary", b""])

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Checksum mismatch"),
        ):
            mock_open.side_effect = [manifest_resp, binary_resp]
            cache.ensure("1.2.3")

    def test_ensure_http_error_on_channel_resolution(
        self, tmp_path: Path
    ) -> None:
        """Channel resolution HTTP error raises ClaudeBinaryError."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to resolve"),
        ):
            mock_open.side_effect = URLError("connection failed")
            cache.ensure("latest")

    def test_ensure_invalid_channel_response(self, tmp_path: Path) -> None:
        """ensure() raises on invalid version from channel endpoint."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        channel_resp = _url_response(b"not-a-version")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Invalid version"),
        ):
            mock_open.side_effect = [channel_resp]
            cache.ensure("latest")

    def test_ensure_http_error_on_manifest(self, tmp_path: Path) -> None:
        """ensure() raises ClaudeBinaryError when manifest download fails."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to download"),
        ):
            mock_open.side_effect = URLError("refused")
            cache.ensure("1.2.3")

    def test_ensure_platform_not_in_manifest(self, tmp_path: Path) -> None:
        """ensure() raises when platform not found in manifest."""
        manifest = json.dumps(
            {"platforms": {"linux-arm64": {"checksum": "a" * 64}}}
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        manifest_resp = _url_response(manifest.encode())

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Platform.*not found"),
        ):
            mock_open.side_effect = [manifest_resp]
            cache.ensure("1.2.3")

    def test_ensure_cleanup_on_download_failure(self, tmp_path: Path) -> None:
        """ensure() cleans up temp file when binary download fails."""
        checksum = "a" * 64
        manifest = _make_manifest(checksum)
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        manifest_resp = _url_response(manifest.encode())

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to download"),
        ):
            mock_open.side_effect = [
                manifest_resp,
                URLError("download fail"),
            ]
            cache.ensure("1.2.3")

        # Temp file should be cleaned up
        version_dir = tmp_path / "1.2.3"
        claude_files = list(version_dir.glob(".claude-download-*"))
        assert claude_files == []

    def test_ensure_channel_resolution_cached(self, tmp_path: Path) -> None:
        """Channel resolution is cached within TTL."""
        version_dir = tmp_path / "3.0.0"
        version_dir.mkdir()
        (version_dir / "claude").write_bytes(b"binary")

        cache = ClaudeBinaryCache(
            tmp_path,
            platform_override="linux-x64",
            resolution_ttl_seconds=3600,
        )

        channel_resp = _url_response(b"3.0.0")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [channel_resp]
            # First call resolves via network
            cache.ensure("latest")
            # Second call uses cache
            cache.ensure("latest")

        # Only 1 HTTP call (not 2) -- the second was cached
        assert mock_open.call_count == 1


# -------------------------------------------------------------------
# prune
# -------------------------------------------------------------------


class TestPrune:
    """Tests for ClaudeBinaryCache.prune()."""

    def test_prune_removes_inactive(self, tmp_path: Path) -> None:
        """Prune removes versions not in the active set."""
        for v in ("1.0.0", "2.0.0", "3.0.0"):
            d = tmp_path / v
            d.mkdir()
            (d / "claude").write_bytes(b"binary")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        removed = cache.prune({"2.0.0"})

        assert removed == 2
        assert not (tmp_path / "1.0.0").exists()
        assert (tmp_path / "2.0.0").exists()
        assert not (tmp_path / "3.0.0").exists()

    def test_prune_cleans_up_version_locks(self, tmp_path: Path) -> None:
        """Prune removes stale entries from _version_locks."""
        for v in ("1.0.0", "2.0.0"):
            d = tmp_path / v
            d.mkdir()
            (d / "claude").write_bytes(b"binary")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        # Simulate locks being created by ensure()
        cache._version_locks["1.0.0"] = threading.Lock()
        cache._version_locks["2.0.0"] = threading.Lock()

        cache.prune({"2.0.0"})
        assert "1.0.0" not in cache._version_locks
        assert "2.0.0" in cache._version_locks

    def test_prune_keeps_active(self, tmp_path: Path) -> None:
        """Prune keeps all active versions."""
        for v in ("1.0.0", "2.0.0"):
            d = tmp_path / v
            d.mkdir()
            (d / "claude").write_bytes(b"binary")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        removed = cache.prune({"1.0.0", "2.0.0"})
        assert removed == 0

    def test_prune_skips_non_directories(self, tmp_path: Path) -> None:
        """Prune ignores non-directory entries in cache dir."""
        d = tmp_path / "1.0.0"
        d.mkdir()
        (d / "claude").write_bytes(b"binary")
        # Create a regular file in cache dir
        (tmp_path / "stale.tmp").write_bytes(b"junk")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        removed = cache.prune(set())
        # Only the directory is counted as removed, not the file
        assert removed == 1

    def test_prune_empty_cache(self, tmp_path: Path) -> None:
        """Prune on empty cache returns 0."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        assert cache.prune(set()) == 0

    def test_prune_nonexistent_cache_dir(self, tmp_path: Path) -> None:
        """Prune with missing cache dir returns 0."""
        cache_dir = tmp_path / "missing"
        cache_dir.mkdir()
        cache = ClaudeBinaryCache(cache_dir, platform_override="linux-x64")
        shutil.rmtree(cache_dir)
        assert cache.prune(set()) == 0


# -------------------------------------------------------------------
# list_cached_versions
# -------------------------------------------------------------------


class TestListCachedVersions:
    """Tests for ClaudeBinaryCache.list_cached_versions()."""

    def test_lists_versions(self, tmp_path: Path) -> None:
        """Returns sorted list of cached versions."""
        for v in ("2.0.0", "1.0.0"):
            d = tmp_path / v
            d.mkdir()
            (d / "claude").write_bytes(b"binary")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        assert cache.list_cached_versions() == ["1.0.0", "2.0.0"]

    def test_lists_empty_when_no_cache_dir(self, tmp_path: Path) -> None:
        """Returns empty list when cache directory does not exist."""
        cache_dir = tmp_path / "missing"
        cache_dir.mkdir()
        cache = ClaudeBinaryCache(cache_dir, platform_override="linux-x64")
        shutil.rmtree(cache_dir)
        assert cache.list_cached_versions() == []

    def test_ignores_incomplete(self, tmp_path: Path) -> None:
        """Ignores directories without claude binary."""
        (tmp_path / "1.0.0").mkdir()
        # No claude file inside

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        assert cache.list_cached_versions() == []


# -------------------------------------------------------------------
# resolve_version
# -------------------------------------------------------------------


class TestResolveVersion:
    """Tests for ClaudeBinaryCache.resolve_version()."""

    def test_semver_passthrough(self, tmp_path: Path) -> None:
        """Semver versions pass through without network."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        assert cache.resolve_version("1.2.3") == "1.2.3"

    def test_latest_resolves(self, tmp_path: Path) -> None:
        """'latest' resolves via CDN."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        channel_resp = _url_response(b"4.0.0")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [channel_resp]
            assert cache.resolve_version("latest") == "4.0.0"

    def test_invalid_raises(self, tmp_path: Path) -> None:
        """Invalid version raises ValueError."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        with pytest.raises(ValueError, match="Invalid claude_version"):
            cache.resolve_version("bad")
