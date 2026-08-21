# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/sandbox/claude_binary.py."""

from __future__ import annotations

import email.message
import errno
import hashlib
import http.client
import json
import logging
import os
import shutil
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from airut.sandbox.claude_binary import (
    _CHANNEL_FAST_RETRIES,
    _CHANNEL_FAST_TIMEOUT,
    _CHANNEL_RETRIES,
    _CHANNEL_TIMEOUT,
    _DOWNLOAD_ATTEMPTS,
    _RESOLUTIONS_FILE,
    CLAUDE_BINARY_CONTAINER_PATH,
    DOWNLOADS_BASE,
    ClaudeBinaryCache,
    ClaudeBinaryError,
    _extract_platform_info,
    _open_release_url,
    detect_platform,
    validate_version,
)


_URLOPEN_WITH_RETRY = "airut.sandbox.claude_binary.urlopen_with_retry"


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


def _url_response(data: bytes | list[bytes] | Exception) -> MagicMock:
    """Create a mock ``urlopen()`` return value (context manager).

    Args:
        data: If bytes, ``read()`` always returns that value.
              If a list, ``read()`` returns items sequentially
              (use for chunked streaming; append ``b""`` as sentinel).
              If an exception, ``read()`` raises it.
    """
    resp = MagicMock()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    if isinstance(data, Exception):
        resp.read.side_effect = data
    elif isinstance(data, list):
        resp.read.side_effect = data
    else:
        resp.read.return_value = data
    return resp


def _http_error(code: int, msg: str) -> HTTPError:
    """Build an HTTPError the way urlopen raises it for a status."""
    return HTTPError(
        f"{DOWNLOADS_BASE}/1.2.3/manifest.json",
        code,
        msg,
        email.message.Message(),
        None,
    )


@pytest.fixture
def no_sleep() -> Iterator[MagicMock]:
    """Skip retry backoff delays."""
    with patch("airut.sandbox.claude_binary.time.sleep") as mock_sleep:
        yield mock_sleep


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

    def test_no_cache_sends_revalidation_headers(self) -> None:
        """no_cache=True issues a Request with cache-busting headers."""
        resp = _url_response(b"data")

        with patch(_URLOPEN_WITH_RETRY) as mock_fetch:
            mock_fetch.return_value = resp
            _open_release_url("latest", no_cache=True)

        request = mock_fetch.call_args[0][0]
        assert isinstance(request, urllib.request.Request)
        assert request.full_url == f"{DOWNLOADS_BASE}/latest"
        assert request.get_header("Cache-control") == "no-cache"
        assert request.get_header("Pragma") == "no-cache"


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
# _extract_platform_info
# -------------------------------------------------------------------


class TestExtractPlatformInfo:
    """Tests for _extract_platform_info()."""

    def test_valid_manifest(self) -> None:
        """Extracts checksum and size from valid manifest JSON."""
        checksum = "a" * 64
        manifest = json.dumps(
            {"platforms": {"linux-x64": {"checksum": checksum, "size": 42}}}
        )
        info = _extract_platform_info(manifest, "linux-x64")
        assert info is not None
        assert info.checksum == checksum
        assert info.size == 42

    def test_missing_size(self) -> None:
        """Size is None when the manifest omits it."""
        manifest = json.dumps(
            {"platforms": {"linux-x64": {"checksum": "a" * 64}}}
        )
        info = _extract_platform_info(manifest, "linux-x64")
        assert info is not None
        assert info.size is None

    def test_non_integer_size(self) -> None:
        """Size is None when the manifest value is not an integer."""
        manifest = json.dumps(
            {"platforms": {"linux-x64": {"checksum": "a" * 64, "size": "42"}}}
        )
        info = _extract_platform_info(manifest, "linux-x64")
        assert info is not None
        assert info.size is None

    def test_non_positive_size(self) -> None:
        """Size is None when the manifest value is not positive."""
        manifest = json.dumps(
            {"platforms": {"linux-x64": {"checksum": "a" * 64, "size": 0}}}
        )
        info = _extract_platform_info(manifest, "linux-x64")
        assert info is not None
        assert info.size is None

    def test_missing_platform(self) -> None:
        """Returns None for missing platform."""
        manifest = json.dumps(
            {"platforms": {"linux-arm64": {"checksum": "b" * 64}}}
        )
        assert _extract_platform_info(manifest, "linux-x64") is None

    def test_invalid_checksum_format(self) -> None:
        """Returns None for non-hex checksum."""
        manifest = json.dumps(
            {"platforms": {"linux-x64": {"checksum": "not-hex"}}}
        )
        assert _extract_platform_info(manifest, "linux-x64") is None

    def test_non_string_checksum(self) -> None:
        """Returns None when the checksum is not a string."""
        manifest = json.dumps({"platforms": {"linux-x64": {"checksum": 7}}})
        assert _extract_platform_info(manifest, "linux-x64") is None

    def test_invalid_json(self) -> None:
        """Returns None for invalid JSON."""
        assert _extract_platform_info("not-json{", "linux-x64") is None

    def test_missing_platforms_key(self) -> None:
        """Returns None when platforms key is missing."""
        assert _extract_platform_info("{}", "linux-x64") is None

    def test_platforms_not_a_mapping(self) -> None:
        """Returns None when platforms is not a mapping."""
        manifest = json.dumps({"platforms": ["linux-x64"]})
        assert _extract_platform_info(manifest, "linux-x64") is None


# -------------------------------------------------------------------
# ClaudeBinaryCache
# -------------------------------------------------------------------


def _make_manifest(
    checksum: str,
    platform: str = "linux-x64",
    size: int | None = None,
) -> str:
    """Create a manifest JSON string."""
    entry: dict[str, object] = {"checksum": checksum}
    if size is not None:
        entry["size"] = size
    return json.dumps({"platforms": {platform: entry}})


def _manifest_for(content: bytes, platform: str = "linux-x64") -> str:
    """Create a manifest matching *content* exactly."""
    return _make_manifest(
        hashlib.sha256(content).hexdigest(), platform, len(content)
    )


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
        manifest = _manifest_for(binary_content)

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
        assert path.stat().st_mode & 0o111
        assert (tmp_path / "1.2.3" / "manifest.json").read_text() == manifest
        # First attempt does not bypass caches.
        assert mock_open.call_args_list[0][1]["no_cache"] is False

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

    def test_ensure_checksum_mismatch_raises(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """ensure() raises after retrying a persistent checksum mismatch."""
        manifest = _make_manifest("f" * 64, size=len(b"binary"))

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        responses: list[MagicMock] = []
        for _ in range(_DOWNLOAD_ATTEMPTS):
            responses.append(_url_response(manifest.encode()))
            responses.append(_url_response([b"binary", b""]))

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Checksum mismatch"),
        ):
            mock_open.side_effect = responses
            cache.ensure("1.2.3")

        assert mock_open.call_count == 2 * _DOWNLOAD_ATTEMPTS
        assert not (tmp_path / "1.2.3" / "claude").exists()
        assert no_sleep.call_count == _DOWNLOAD_ATTEMPTS - 1

    def test_ensure_truncated_download_detected(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """A short body is reported as an incomplete download.

        HTTPResponse.read() reports a dropped connection as EOF rather
        than raising, so only the byte count catches truncation.
        """
        full = b"x" * 100
        manifest = _manifest_for(full)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        responses: list[MagicMock] = []
        for _ in range(_DOWNLOAD_ATTEMPTS):
            responses.append(_url_response(manifest.encode()))
            responses.append(_url_response([full[:40], b""]))

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="got 40 of 100 bytes"),
        ):
            mock_open.side_effect = responses
            cache.ensure("1.2.3")

        assert not (tmp_path / "1.2.3" / "claude").exists()

    def test_ensure_retries_truncated_download(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """A truncated transfer is retried with a fresh download."""
        full = b"y" * 100
        manifest = _manifest_for(full)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [
                _url_response(manifest.encode()),
                _url_response([full[:10], b""]),
                _url_response(manifest.encode()),
                _url_response([full, b""]),
            ]
            path, _ = cache.ensure("1.2.3")

        assert path.read_bytes() == full
        # The retry asks intermediaries to revalidate.
        assert mock_open.call_args_list[0][1]["no_cache"] is False
        assert mock_open.call_args_list[2][1]["no_cache"] is True
        assert mock_open.call_args_list[3][1]["no_cache"] is True
        # No temp files left behind by the failed attempt.
        assert list((tmp_path / "1.2.3").glob(".claude-download-*")) == []

    def test_ensure_retries_midstream_connection_reset(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """A connection reset mid-body is retried, not propagated raw."""
        content = b"claude"
        manifest = _manifest_for(content)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [
                _url_response(manifest.encode()),
                _url_response(ConnectionResetError("reset by peer")),
                _url_response(manifest.encode()),
                _url_response([content, b""]),
            ]
            path, _ = cache.ensure("1.2.3")

        assert path.read_bytes() == content

    def test_ensure_midstream_failure_raises_claude_binary_error(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """Persistent transport failures surface as ClaudeBinaryError.

        Timeouts and resets are not URLErrors; without explicit
        handling they would escape as raw OSErrors and bypass the
        gateway's Claude-binary error path.
        """
        manifest = _make_manifest("a" * 64, size=10)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        responses: list[MagicMock] = []
        for _ in range(_DOWNLOAD_ATTEMPTS):
            responses.append(_url_response(manifest.encode()))
            responses.append(_url_response(TimeoutError("timed out")))

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="timed out"),
        ):
            mock_open.side_effect = responses
            cache.ensure("1.2.3")

    def test_ensure_incomplete_read_retried(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """An IncompleteRead during transfer is retried."""
        content = b"claude-binary"
        manifest = _manifest_for(content)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [
                _url_response(manifest.encode()),
                _url_response(http.client.IncompleteRead(b"claude")),
                _url_response(manifest.encode()),
                _url_response([content, b""]),
            ]
            path, _ = cache.ensure("1.2.3")

        assert path.read_bytes() == content

    def test_ensure_manifest_incomplete_read_retried(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """An IncompleteRead fetching the manifest is retried."""
        content = b"claude-binary"
        manifest = _manifest_for(content)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [
                _url_response(http.client.IncompleteRead(b"{")),
                _url_response(manifest.encode()),
                _url_response([content, b""]),
            ]
            path, _ = cache.ensure("1.2.3")

        assert path.read_bytes() == content

    def test_ensure_http_error_not_retried(self, tmp_path: Path) -> None:
        """An HTTP status error fails immediately without retrying."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="HTTP 404"),
        ):
            mock_open.side_effect = _http_error(404, "Not Found")
            cache.ensure("9.9.9")

        assert mock_open.call_count == 1

    def test_ensure_binary_http_error_not_retried(self, tmp_path: Path) -> None:
        """An HTTP status error on the binary fails immediately."""
        manifest = _make_manifest("a" * 64, size=10)
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="HTTP 403"),
        ):
            mock_open.side_effect = [
                _url_response(manifest.encode()),
                _http_error(403, "Forbidden"),
            ]
            cache.ensure("1.2.3")

        assert mock_open.call_count == 2

    def test_ensure_out_of_disk_space_not_retried(self, tmp_path: Path) -> None:
        """A full disk fails immediately instead of re-downloading."""
        manifest = _make_manifest("a" * 64, size=10)
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        def fake_fdopen(fd: int, _mode: str) -> MagicMock:
            os.close(fd)
            handle = MagicMock()
            handle.__enter__ = MagicMock(return_value=handle)
            handle.__exit__ = MagicMock(return_value=False)
            handle.write.side_effect = OSError(
                errno.ENOSPC, "No space left on device"
            )
            return handle

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            patch("airut.sandbox.claude_binary.os.fdopen", fake_fdopen),
            pytest.raises(ClaudeBinaryError, match="Out of disk space"),
        ):
            mock_open.side_effect = [
                _url_response(manifest.encode()),
                _url_response([b"binary", b""]),
            ]
            cache.ensure("1.2.3")

        assert mock_open.call_count == 2

    def test_ensure_temp_file_creation_failure(self, tmp_path: Path) -> None:
        """A non-writable cache directory raises ClaudeBinaryError."""
        manifest = _make_manifest("a" * 64, size=10)
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            patch(
                "airut.sandbox.claude_binary.tempfile.mkstemp",
                side_effect=OSError("read-only file system"),
            ),
            pytest.raises(
                ClaudeBinaryError, match="Failed to prepare cache directory"
            ),
        ):
            mock_open.side_effect = [_url_response(manifest.encode())]
            cache.ensure("1.2.3")

    def test_ensure_install_failure(self, tmp_path: Path) -> None:
        """A failure moving the verified binary into place is reported."""
        content = b"claude-binary"
        manifest = _manifest_for(content)
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            patch.object(Path, "rename", side_effect=OSError("cross-device")),
            pytest.raises(ClaudeBinaryError, match="Failed to install"),
        ):
            mock_open.side_effect = [
                _url_response(manifest.encode()),
                _url_response([content, b""]),
            ]
            cache.ensure("1.2.3")

        assert list((tmp_path / "1.2.3").glob(".claude-download-*")) == []

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

    def test_ensure_incomplete_read_on_channel_resolution(
        self, tmp_path: Path
    ) -> None:
        """A truncated channel response raises ClaudeBinaryError."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to resolve"),
        ):
            mock_open.side_effect = [
                _url_response(http.client.IncompleteRead(b"2.0"))
            ]
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

    def test_ensure_http_error_on_manifest(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """ensure() raises ClaudeBinaryError when manifest download fails."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to download"),
        ):
            mock_open.side_effect = URLError("refused")
            cache.ensure("1.2.3")

        assert mock_open.call_count == _DOWNLOAD_ATTEMPTS

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

        # A missing platform will not fix itself -- no retry.
        assert mock_open.call_count == 1

    def test_ensure_no_size_in_manifest(self, tmp_path: Path) -> None:
        """Download succeeds when the manifest omits the size field."""
        content = b"claude-binary"
        manifest = _make_manifest(hashlib.sha256(content).hexdigest())
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [
                _url_response(manifest.encode()),
                _url_response([content, b""]),
            ]
            path, _ = cache.ensure("1.2.3")

        assert path.read_bytes() == content

    def test_ensure_cleanup_on_download_failure(
        self, tmp_path: Path, no_sleep: MagicMock
    ) -> None:
        """ensure() cleans up temp file when binary download fails."""
        manifest = _make_manifest("a" * 64, size=6)
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        responses: list[MagicMock | Exception] = []
        for _ in range(_DOWNLOAD_ATTEMPTS):
            responses.append(_url_response(manifest.encode()))
            responses.append(URLError("download fail"))

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to download"),
        ):
            mock_open.side_effect = responses
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
# Channel resolution
# -------------------------------------------------------------------


class TestChannelResolution:
    """Tests for channel resolution and its stale-if-error fallback."""

    def _cached_binary(self, tmp_path: Path, version: str) -> Path:
        """Create a cached binary for *version*."""
        version_dir = tmp_path / version
        version_dir.mkdir()
        (version_dir / "claude").write_bytes(b"binary")
        return version_dir / "claude"

    def test_resolution_persisted_to_disk(self, tmp_path: Path) -> None:
        """A successful resolution is written to the cache directory."""
        self._cached_binary(tmp_path, "2.0.0")
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"2.0.0")]
            cache.ensure("latest")

        stored = json.loads((tmp_path / _RESOLUTIONS_FILE).read_text())
        assert stored == {"latest": "2.0.0"}

    def test_persisted_resolution_used_after_restart(
        self, tmp_path: Path
    ) -> None:
        """A fresh cache falls back to the resolution left on disk.

        The in-memory cache is empty after a gateway restart, which is
        exactly when an unreachable CDN would otherwise fail tasks.
        """
        binary = self._cached_binary(tmp_path, "2.0.0")
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"latest": "2.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = URLError("timed out")
            path, version = cache.ensure("latest")

        assert version == "2.0.0"
        assert path == binary

    def test_stale_resolution_used_when_refresh_fails(
        self, tmp_path: Path
    ) -> None:
        """An expired resolution is reused when the CDN is unreachable."""
        self._cached_binary(tmp_path, "2.0.0")
        cache = ClaudeBinaryCache(
            tmp_path,
            platform_override="linux-x64",
            resolution_ttl_seconds=0,
        )

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"2.0.0")]
            cache.ensure("latest")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = URLError("timed out")
            _, version = cache.ensure("latest")

        assert version == "2.0.0"

    def test_stale_resolution_used_for_invalid_response(
        self, tmp_path: Path
    ) -> None:
        """A garbage channel response also falls back."""
        self._cached_binary(tmp_path, "2.0.0")
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"latest": "2.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"<html>error</html>")]
            _, version = cache.ensure("latest")

        assert version == "2.0.0"

    def test_fallback_reported_when_binary_not_cached(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The warning says so when the fallback is not cached."""
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"latest": "2.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            caplog.at_level(logging.WARNING),
        ):
            mock_open.side_effect = URLError("timed out")
            assert cache.resolve_version("latest") == "2.0.0"

        assert "not cached" in caplog.text

    def test_failed_refresh_is_not_retried_immediately(
        self, tmp_path: Path
    ) -> None:
        """A fallback suppresses re-checks for a short window.

        Otherwise every task start pays the full request budget while
        the CDN is down.
        """
        self._cached_binary(tmp_path, "2.0.0")
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"latest": "2.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = URLError("timed out")
            cache.ensure("latest")
            cache.ensure("latest")

        assert mock_open.call_count == 1

    def test_no_fallback_raises(self, tmp_path: Path) -> None:
        """With nothing known, resolution failure still fails the task."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to resolve"),
        ):
            mock_open.side_effect = URLError("timed out")
            cache.ensure("latest")

    def test_full_request_budget_without_fallback(self, tmp_path: Path) -> None:
        """Without a fallback the refresh uses the full retry budget."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"2.0.0")]
            cache.resolve_version("latest")

        assert mock_open.call_args[1]["timeout"] == _CHANNEL_TIMEOUT
        assert mock_open.call_args[1]["max_retries"] == _CHANNEL_RETRIES

    def test_reduced_request_budget_with_fallback(self, tmp_path: Path) -> None:
        """With a fallback the refresh does not stall task startup."""
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"latest": "1.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"2.0.0")]
            cache.resolve_version("latest")

        assert mock_open.call_args[1]["timeout"] == _CHANNEL_FAST_TIMEOUT
        assert mock_open.call_args[1]["max_retries"] == _CHANNEL_FAST_RETRIES

    def test_channels_resolve_independently(self, tmp_path: Path) -> None:
        """The stable channel does not reuse the latest resolution."""
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"latest": "2.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to resolve"),
        ):
            mock_open.side_effect = URLError("timed out")
            cache.resolve_version("stable")

    def test_persisted_resolutions_merged(self, tmp_path: Path) -> None:
        """Persisting one channel keeps the other channel's entry."""
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"stable": "1.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"2.0.0")]
            cache.resolve_version("latest")

        stored = json.loads((tmp_path / _RESOLUTIONS_FILE).read_text())
        assert stored == {"stable": "1.0.0", "latest": "2.0.0"}

    @pytest.mark.parametrize(
        "content",
        [
            "not json{",
            json.dumps(["2.0.0"]),
            json.dumps({"latest": "not-a-version"}),
            json.dumps({"latest": 200}),
        ],
    )
    def test_unusable_resolution_file_ignored(
        self, tmp_path: Path, content: str
    ) -> None:
        """A corrupt resolutions file is not treated as a fallback."""
        (tmp_path / _RESOLUTIONS_FILE).write_text(content)
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            pytest.raises(ClaudeBinaryError, match="Failed to resolve"),
        ):
            mock_open.side_effect = URLError("timed out")
            cache.resolve_version("latest")

    def test_corrupt_resolution_file_overwritten(self, tmp_path: Path) -> None:
        """A corrupt resolutions file is replaced on the next success."""
        (tmp_path / _RESOLUTIONS_FILE).write_text("not json{")
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"2.0.0")]
            cache.resolve_version("latest")

        stored = json.loads((tmp_path / _RESOLUTIONS_FILE).read_text())
        assert stored == {"latest": "2.0.0"}

    def test_non_mapping_resolution_file_overwritten(
        self, tmp_path: Path
    ) -> None:
        """A resolutions file holding a non-object is replaced."""
        (tmp_path / _RESOLUTIONS_FILE).write_text(json.dumps(["2.0.0"]))
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = [_url_response(b"2.0.0")]
            cache.resolve_version("latest")

        stored = json.loads((tmp_path / _RESOLUTIONS_FILE).read_text())
        assert stored == {"latest": "2.0.0"}

    def test_unwritable_cache_dir_does_not_fail_resolution(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Failing to persist is logged, not fatal."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        with (
            patch(_OPEN_RELEASE_URL) as mock_open,
            patch.object(Path, "write_text", side_effect=OSError("read-only")),
            caplog.at_level(logging.WARNING),
        ):
            mock_open.side_effect = [_url_response(b"2.0.0")]
            assert cache.resolve_version("latest") == "2.0.0"

        assert "Failed to persist" in caplog.text

    def test_resolutions_file_is_not_pruned(self, tmp_path: Path) -> None:
        """Pruning ignores the resolutions file."""
        self._cached_binary(tmp_path, "2.0.0")
        (tmp_path / _RESOLUTIONS_FILE).write_text(
            json.dumps({"latest": "2.0.0"})
        )
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")

        cache.prune(set())

        assert (tmp_path / _RESOLUTIONS_FILE).exists()


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
        cache._version_lock("1.0.0")
        cache._version_lock("2.0.0")

        cache.prune({"2.0.0"})
        assert "1.0.0" not in cache._version_locks
        assert "2.0.0" in cache._version_locks

    def test_prune_holds_version_lock(self, tmp_path: Path) -> None:
        """Prune holds the per-version lock while deleting.

        Otherwise GC could delete a directory that ensure() is
        downloading into.
        """
        d = tmp_path / "1.0.0"
        d.mkdir()
        (d / "claude").write_bytes(b"binary")

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        lock = cache._version_lock("1.0.0")
        held: list[bool] = []

        with patch(
            "shutil.rmtree",
            side_effect=lambda *a, **kw: held.append(lock.locked()),
        ):
            cache.prune(set())

        assert held == [True]

    def test_version_lock_is_reused(self, tmp_path: Path) -> None:
        """The same lock object is returned for a given version."""
        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        assert cache._version_lock("1.0.0") is cache._version_lock("1.0.0")

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
# Concurrency
# -------------------------------------------------------------------


class TestConcurrency:
    """Tests for concurrent ensure() calls."""

    def test_concurrent_ensure_downloads_once(self, tmp_path: Path) -> None:
        """Concurrent ensure() calls for one version download once."""
        content = b"claude-binary"
        manifest = _manifest_for(content)

        cache = ClaudeBinaryCache(tmp_path, platform_override="linux-x64")
        barrier = threading.Barrier(2)
        results: list[Path] = []

        def responses(*_args: object, **_kwargs: object) -> MagicMock:
            if mock_open.call_count % 2 == 1:
                return _url_response(manifest.encode())
            return _url_response([content, b""])

        def run() -> None:
            barrier.wait(timeout=5)
            results.append(cache.ensure("1.2.3")[0])

        with patch(_OPEN_RELEASE_URL) as mock_open:
            mock_open.side_effect = responses
            threads = [threading.Thread(target=run) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        assert len(results) == 2
        # Second caller saw the cached binary: one manifest + one binary.
        assert mock_open.call_count == 2
        assert results[0].read_bytes() == content


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
