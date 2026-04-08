# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Sandbox canary verification tests.

These tests verify sandbox isolation properties by checking
environment-injected canary values and network restrictions.
The canary environment variables (CANARY_PLAIN, CANARY_MASKED) are
configured in the airut server and GitHub Actions environments.
Tests silently pass when variables are unset.

The network canary test only runs inside the sandbox (IS_SANDBOX
env var set by the sandbox entrypoint).
"""

import hashlib
import os

import pytest


# Expected SHA-256 digests of the real canary values.
# CANARY_PLAIN may hold different values depending on the environment
# (local server vs GitHub Actions), so we accept either hash.
CANARY_PLAIN_SHA256 = {
    "e218f7e0267877ee8954cb3bc9370778c068e957f52d7d477fd07d80177141a4",
    "12dcaa38e872129878d32016f72ca03652b90599da91ca0dcc9c5da074e8711f",
}
CANARY_MASKED_SHA256 = (
    "88a0e31e943b800d7f36f580a7cc354d9b8995199974170c37d61f4f14baab3e"
)
CANARY_URL_SHA256 = (
    "833ef01e990d75d07e831d49d0e586efff35e1be40402e6899f7afcf524f13e5"
)


def _sha256(data: str | bytes) -> str:
    """Return hex SHA-256 digest of *data*."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


class TestSandboxCanary:
    """Verify sandbox isolation via canary values."""

    def test_plain_env_var_sha256_matches(self) -> None:
        """Non-masked env var passes through: SHA-256 matches."""
        value = os.environ.get("CANARY_PLAIN")
        if value is None:
            return
        assert _sha256(value) in CANARY_PLAIN_SHA256, (
            "CANARY_PLAIN SHA-256 mismatch — "
            "value does not match expected canary"
        )

    def test_masked_secret_sha256_differs(self) -> None:
        """Masked secret is replaced with surrogate: SHA-256 differs."""
        value = os.environ.get("CANARY_MASKED")
        if value is None:
            return
        assert _sha256(value) != CANARY_MASKED_SHA256, (
            "CANARY_MASKED SHA-256 matches real value — secret was not masked"
        )

    @pytest.mark.enable_socket()
    def test_canary_url_content_blocked(self) -> None:
        """Network sandbox blocks canary URL: content SHA-256 differs.

        Attempts to fetch https://airut.org/canary.txt. Regardless
        of the failure mode (connection refused, proxy block, timeout),
        the content must NOT match the real resource's SHA-256.

        Only runs inside the sandbox (IS_SANDBOX is set by the
        sandbox entrypoint).
        """
        if "IS_SANDBOX" not in os.environ:
            return

        import urllib.request

        req = urllib.request.Request(
            "https://airut.org/canary.txt",
            headers={"User-Agent": "airut-canary/1.0"},
        )
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            content = resp.read()
        except Exception as exc:
            content = str(exc).encode()

        assert _sha256(content) != CANARY_URL_SHA256, (
            "canary.txt SHA-256 matches real content — "
            "network sandbox is not working"
        )
