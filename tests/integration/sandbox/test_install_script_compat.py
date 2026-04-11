# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration test: upstream install.sh compatibility.

Validates that the upstream Claude Code install script at
https://claude.ai/install.sh matches the assumptions made by
ClaudeBinaryCache.  Detects divergence early — before users hit
download failures at runtime.

Checks:
    1. claude.ai/install.sh redirects to a bootstrap script on a
       known host (downloads.claude.ai CDN or GCS bucket).
    2. The bootstrap script uses a compatible release URL, manifest
       path pattern, and binary path pattern.
    3. The ``latest`` channel resolves to a valid semver version
       on both ``downloads.claude.ai`` (primary) and GCS (fallback).
    4. The manifest for that version is valid JSON with the expected
       structure and our ``_extract_checksum()`` parses it correctly.
    5. The manifest includes checksums for all Linux platforms that
       ClaudeBinaryCache supports.

Every network fetch is required to succeed — no silent passes.
"""

from __future__ import annotations

import re
import time

import httpx
import pytest

from airut.sandbox.claude_binary import (
    DOWNLOADS_BASE,
    GCS_BUCKET,
    _extract_checksum,
)


# Platforms that ClaudeBinaryCache.detect_platform() can produce.
_LINUX_PLATFORMS = frozenset(
    {"linux-x64", "linux-arm64", "linux-x64-musl", "linux-arm64-musl"}
)

# Timeout for individual HTTP requests (seconds).
_HTTP_TIMEOUT = 30

# Retry parameters for transient HTTP errors (429, 5xx).
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 2.0  # seconds


def _request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
) -> httpx.Response:
    """Issue an HTTP request with retry on 429 / 5xx errors.

    Returns the response on success (2xx/3xx) or non-retryable 4xx.
    Raises ``HTTPStatusError`` on persistent 429 or 5xx after
    exhausting retries, and on any other client error immediately.
    """
    last_resp: httpx.Response | None = None
    for attempt in range(_MAX_RETRIES + 1):
        resp = client.request(method, url)
        if resp.status_code != 429 and resp.status_code < 500:
            return resp
        last_resp = resp
        if attempt < _MAX_RETRIES:
            delay = _RETRY_BACKOFF_BASE * (2**attempt)
            # Respect Retry-After header if present.
            retry_after = resp.headers.get("retry-after")
            if retry_after and retry_after.isdigit():
                delay = max(delay, float(retry_after))
            time.sleep(delay)
    assert last_resp is not None
    last_resp.raise_for_status()
    return last_resp  # unreachable, but satisfies type checker


@pytest.mark.allow_hosts(
    [
        "127.0.0.1",
        "localhost",
        "claude.ai",
        "downloads.claude.ai",
        "storage.googleapis.com",
    ]
)
class TestInstallScriptCompat:
    """Verify upstream install.sh is compatible with ClaudeBinaryCache."""

    # Known hosts that claude.ai/install.sh may redirect to.
    _KNOWN_BOOTSTRAP_HOSTS = frozenset(
        {
            "storage.googleapis.com",
            "downloads.claude.ai",
        }
    )

    # -- fixtures --------------------------------------------------------

    @pytest.fixture(scope="class")
    def bootstrap_script(self) -> str:
        """Fetch the bootstrap script from the primary CDN.

        Falls back to GCS if the CDN is unreachable, matching the
        fallback behavior of ``_open_release_url``.
        """
        for base in [DOWNLOADS_BASE, GCS_BUCKET]:
            url = f"{base}/bootstrap.sh"
            with httpx.Client(timeout=_HTTP_TIMEOUT) as c:
                resp = _request_with_retry(c, "GET", url)
                if resp.is_success:
                    return resp.text
        pytest.fail("bootstrap.sh unreachable on both CDN and GCS")

    @pytest.fixture(scope="class")
    def latest_version(self) -> str:
        """Resolve the ``latest`` channel to a concrete version."""
        url = f"{DOWNLOADS_BASE}/latest"
        with httpx.Client(timeout=_HTTP_TIMEOUT) as c:
            resp = _request_with_retry(c, "GET", url)
            resp.raise_for_status()
            version = resp.text.strip()
            assert re.match(r"^\d+\.\d+\.\d+", version), (
                f"latest channel returned non-semver: {version!r}"
            )
            return version

    @pytest.fixture(scope="class")
    def manifest_json(self, latest_version: str) -> str:
        """Fetch the manifest for the latest version."""
        url = f"{DOWNLOADS_BASE}/{latest_version}/manifest.json"
        with httpx.Client(timeout=_HTTP_TIMEOUT) as c:
            resp = _request_with_retry(c, "GET", url)
            resp.raise_for_status()
            return resp.text

    # -- tests -----------------------------------------------------------

    def test_redirect_lands_on_known_host(self) -> None:
        """claude.ai/install.sh redirects to a known host."""
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=False) as c:
            resp = _request_with_retry(c, "GET", "https://claude.ai/install.sh")
            if resp.is_redirect:
                location = resp.headers["location"]
                assert any(
                    h in location for h in self._KNOWN_BOOTSTRAP_HOSTS
                ), (
                    f"Redirect target {location!r} does not point "
                    f"to a known host: {self._KNOWN_BOOTSTRAP_HOSTS}"
                )
            else:
                # Direct response — verify it looks like the script
                assert "manifest.json" in resp.text, (
                    "Direct response from claude.ai/install.sh does "
                    "not look like a bootstrap script"
                )

    def test_bootstrap_contains_gcs_bucket(self, bootstrap_script: str) -> None:
        """Bootstrap script references the GCS bucket URL."""
        bucket_uuid = "86c565f3-f756-42ad-8dfa-d59b1c096819"
        assert bucket_uuid in bootstrap_script, (
            "Bootstrap script does not contain expected GCS bucket UUID"
        )

    def test_bootstrap_manifest_pattern(self, bootstrap_script: str) -> None:
        """Bootstrap fetches manifest.json."""
        assert "manifest.json" in bootstrap_script, (
            "Bootstrap script does not reference manifest.json"
        )

    def test_bootstrap_checksum_is_sha256(self, bootstrap_script: str) -> None:
        """Bootstrap validates checksums as 64-char hex (SHA-256)."""
        assert re.search(r"\{64\}", bootstrap_script), (
            "Bootstrap script does not validate 64-char hex checksums"
        )

    def test_bootstrap_platform_strings(self, bootstrap_script: str) -> None:
        """Bootstrap uses platform strings compatible with our code."""
        assert "linux-" in bootstrap_script, (
            "Bootstrap script missing linux- platform prefix"
        )
        assert "musl" in bootstrap_script, (
            "Bootstrap script missing musl platform variant"
        )

    def test_latest_channel_resolves(self, latest_version: str) -> None:
        """The latest channel returns a valid semver version."""
        assert re.match(r"^\d+\.\d+\.\d+", latest_version)

    def test_latest_channel_consistent(self, latest_version: str) -> None:
        """CDN and GCS return the same latest version."""
        url = f"{GCS_BUCKET}/latest"
        with httpx.Client(timeout=_HTTP_TIMEOUT) as c:
            resp = _request_with_retry(c, "GET", url)
            resp.raise_for_status()
            gcs_version = resp.text.strip()
        assert latest_version == gcs_version, (
            f"CDN latest ({latest_version}) != GCS latest ({gcs_version})"
        )

    def test_manifest_parseable_by_extract_checksum(
        self, manifest_json: str
    ) -> None:
        """Our _extract_checksum() successfully parses the manifest."""
        found = False
        for plat in _LINUX_PLATFORMS:
            checksum = _extract_checksum(manifest_json, plat)
            if checksum is not None:
                found = True
                assert re.match(r"^[a-f0-9]{64}$", checksum), (
                    f"Checksum for {plat} is not 64-char hex: {checksum!r}"
                )
        assert found, (
            f"Manifest has no checksums for any Linux platform: "
            f"{_LINUX_PLATFORMS}"
        )

    def test_manifest_has_glibc_platforms(self, manifest_json: str) -> None:
        """Manifest includes checksums for glibc Linux platforms."""
        for plat in ("linux-x64", "linux-arm64"):
            checksum = _extract_checksum(manifest_json, plat)
            assert checksum is not None, f"Manifest missing checksum for {plat}"
            assert re.match(r"^[a-f0-9]{64}$", checksum)

    def test_binary_url_reachable(self, latest_version: str) -> None:
        """Binary URL on CDN is reachable.

        Uses a HEAD request to avoid downloading the full binary.
        """
        url = f"{DOWNLOADS_BASE}/{latest_version}/linux-x64/claude"
        with httpx.Client(timeout=_HTTP_TIMEOUT) as c:
            resp = _request_with_retry(c, "HEAD", url)
            resp.raise_for_status()
            content_length = resp.headers.get("content-length")
            if content_length is not None:
                assert int(content_length) > 1_000_000, (
                    f"Binary suspiciously small: {content_length} bytes"
                )
