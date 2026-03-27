# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""GitHub App JWT generation and installation token management.

Provides functions to generate JWTs signed with a GitHub App's RSA private
key and exchange them for short-lived installation access tokens. Used by
the proxy to transparently rotate tokens behind a stable surrogate.

No PyJWT dependency -- uses only stdlib + cryptography (already present
for AWS SigV4A signing).
"""

from __future__ import annotations

import base64
import json
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


# Credential type identifier for GitHub App credentials in the replacement map.
CREDENTIAL_TYPE_GITHUB_APP = "github-app"

# Refresh margin: refresh the token when it is within this many seconds
# of expiry.  5 minutes is generous enough to avoid edge-case races.
_REFRESH_MARGIN_SECONDS = 300


@dataclass(frozen=True)
class CachedToken:
    """In-memory cache entry for a GitHub App installation token."""

    token: str
    expires_at: float  # Unix timestamp


def _base64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_jwt(app_id: str, private_key_pem: str) -> str:
    """Generate a short-lived JWT for GitHub App authentication.

    The JWT is signed with RS256 using the app's RSA private key.
    It has a 9-minute lifetime with a 60-second backdated ``iat``
    to accommodate clock skew.

    Args:
        app_id: GitHub App ID or Client ID (the ``iss`` claim).
        private_key_pem: PEM-encoded RSA private key.

    Returns:
        Signed JWT string.
    """
    header = _base64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = _base64url(
        json.dumps(
            {
                "iss": app_id,
                "iat": now - 60,
                "exp": now + 540,  # 9 minutes
            }
        ).encode()
    )

    signing_input = f"{header}.{payload}".encode()
    key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("GitHub App private key must be RSA")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    return f"{header}.{payload}.{_base64url(signature)}"


def fetch_installation_token(
    base_url: str,
    installation_id: int,
    jwt: str,
    permissions: dict[str, str] | None = None,
    repositories: list[str] | None = None,
) -> tuple[str, float]:
    """Exchange a JWT for an installation access token.

    Calls the GitHub API to create a new installation token.  The
    token has a 1-hour lifetime and is scoped to the installation's
    permissions (optionally narrowed by ``permissions`` and
    ``repositories``).

    Args:
        base_url: GitHub API base URL (e.g., "https://api.github.com").
        installation_id: Installation ID for the target org/user.
        jwt: Signed JWT for authenticating the request.
        permissions: Optional permission restrictions.
        repositories: Optional repository name restrictions.

    Returns:
        Tuple of (token, expires_at_unix_timestamp).

    Raises:
        urllib.error.HTTPError: If the GitHub API returns an error.
        urllib.error.URLError: If the network request fails.
    """
    url = f"{base_url}/app/installations/{installation_id}/access_tokens"

    body: dict[str, object] = {}
    if permissions:
        body["permissions"] = permissions
    if repositories:
        body["repositories"] = repositories

    data = json.dumps(body).encode() if body else b"{}"
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {jwt}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )

    # Bypass proxy environment variables (HTTP_PROXY etc.) to avoid
    # routing the token fetch through mitmproxy itself.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=30) as resp:
        result = json.loads(resp.read())

    token: str = result["token"]
    expires_at_iso: str = result["expires_at"]

    # Convert ISO 8601 timestamp to Unix time (Python 3.11+ handles "Z")
    expires_at = datetime.fromisoformat(expires_at_iso).timestamp()

    return token, expires_at


def is_token_valid(cached: CachedToken | None) -> bool:
    """Check whether a cached token is still valid (not near expiry).

    Args:
        cached: Cached token entry, or None if no token is cached.

    Returns:
        True if the token exists and is not within the refresh margin.
    """
    if cached is None:
        return False
    return time.time() < (cached.expires_at - _REFRESH_MARGIN_SECONDS)
