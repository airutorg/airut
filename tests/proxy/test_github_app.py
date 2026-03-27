# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the GitHub App JWT generation and token management module."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from airut._bundled.proxy.github_app import (
    _REFRESH_MARGIN_SECONDS,
    CREDENTIAL_TYPE_GITHUB_APP,
    CachedToken,
    _base64url,
    fetch_installation_token,
    generate_jwt,
    is_token_valid,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def rsa_private_key_pem() -> str:
    """Generate a test RSA private key in PEM format."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture()
def rsa_private_key_pkcs8_pem() -> str:
    """Generate a test RSA private key in PKCS#8 PEM format."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBase64Url:
    """Tests for _base64url helper."""

    def test_no_padding(self) -> None:
        """Output has no padding characters."""
        result = _base64url(b"test")
        assert "=" not in result

    def test_url_safe(self) -> None:
        """Output uses URL-safe characters."""
        result = _base64url(b"\xff\xfe\xfd")
        assert "+" not in result
        assert "/" not in result

    def test_roundtrip(self) -> None:
        """Can be decoded with standard base64url."""
        data = b"hello world"
        encoded = _base64url(data)
        # Add back padding for standard decode
        padded = encoded + "=" * (4 - len(encoded) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        assert decoded == data


class TestCredentialType:
    """Tests for the credential type constant."""

    def test_value(self) -> None:
        assert CREDENTIAL_TYPE_GITHUB_APP == "github-app"


class TestGenerateJwt:
    """Tests for generate_jwt function."""

    def test_produces_three_part_token(self, rsa_private_key_pem: str) -> None:
        """JWT has three dot-separated parts."""
        jwt = generate_jwt("Iv23liXyz", rsa_private_key_pem)
        parts = jwt.split(".")
        assert len(parts) == 3

    def test_header_claims(self, rsa_private_key_pem: str) -> None:
        """JWT header has correct algorithm and type."""
        jwt = generate_jwt("Iv23liXyz", rsa_private_key_pem)
        header_b64 = jwt.split(".")[0]
        # Add padding
        padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        assert header["alg"] == "RS256"
        assert header["typ"] == "JWT"

    def test_payload_claims(self, rsa_private_key_pem: str) -> None:
        """JWT payload has correct iss, iat, and exp claims."""
        now = int(time.time())
        jwt = generate_jwt("Iv23liXyz", rsa_private_key_pem)
        payload_b64 = jwt.split(".")[1]
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))

        assert payload["iss"] == "Iv23liXyz"
        # iat is backdated by 60s
        assert abs(payload["iat"] - (now - 60)) <= 2
        # exp is 9 minutes from now
        assert abs(payload["exp"] - (now + 540)) <= 2

    def test_supports_pkcs1_format(self, rsa_private_key_pem: str) -> None:
        """Works with PKCS#1 (BEGIN RSA PRIVATE KEY) format."""
        assert "BEGIN RSA PRIVATE KEY" in rsa_private_key_pem
        jwt = generate_jwt("12345", rsa_private_key_pem)
        assert len(jwt.split(".")) == 3

    def test_supports_pkcs8_format(
        self, rsa_private_key_pkcs8_pem: str
    ) -> None:
        """Works with PKCS#8 (BEGIN PRIVATE KEY) format."""
        assert "BEGIN PRIVATE KEY" in rsa_private_key_pkcs8_pem
        jwt = generate_jwt("12345", rsa_private_key_pkcs8_pem)
        assert len(jwt.split(".")) == 3

    def test_non_rsa_key_raises_type_error(self) -> None:
        """Raises TypeError for non-RSA keys."""
        from cryptography.hazmat.primitives.asymmetric import ec

        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_pem = ec_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        with pytest.raises(TypeError, match="must be RSA"):
            generate_jwt("12345", ec_pem)

    def test_signature_verifiable(self, rsa_private_key_pem: str) -> None:
        """JWT signature can be verified with the public key."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import (
            padding as asym_padding,
        )
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicKey,
        )

        jwt_str = generate_jwt("test-app", rsa_private_key_pem)
        parts = jwt_str.split(".")
        header_b64, payload_b64, sig_b64 = parts

        private_key = serialization.load_pem_private_key(
            rsa_private_key_pem.encode(), password=None
        )
        public_key = private_key.public_key()
        assert isinstance(public_key, RSAPublicKey)

        sig_padded = sig_b64 + "=" * (4 - len(sig_b64) % 4)
        signature = base64.urlsafe_b64decode(sig_padded)

        signing_input = f"{header_b64}.{payload_b64}".encode()
        public_key.verify(
            signature,
            signing_input,
            asym_padding.PKCS1v15(),
            hashes.SHA256(),
        )


class TestFetchInstallationToken:
    """Tests for fetch_installation_token function."""

    @staticmethod
    def _mock_opener(response_data: dict) -> MagicMock:
        """Create a mock opener that returns the given response."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(response_data).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_response
        return mock_opener

    def test_basic_exchange(self) -> None:
        """Exchanges JWT for installation token."""
        opener = self._mock_opener(
            {
                "token": "ghs_realtoken123",
                "expires_at": "2026-01-01T01:00:00Z",
            }
        )

        with patch(
            "airut._bundled.proxy.github_app.urllib.request.build_opener",
            return_value=opener,
        ):
            token, expires_at = fetch_installation_token(
                "https://api.github.com",
                12345,
                "fake-jwt",
            )

        assert token == "ghs_realtoken123"
        assert isinstance(expires_at, float)

        # Verify the request was made correctly
        req = opener.open.call_args[0][0]
        assert req.full_url == (
            "https://api.github.com/app/installations/12345/access_tokens"
        )
        assert req.method == "POST"
        assert req.headers["Authorization"] == "Bearer fake-jwt"
        assert req.headers["Accept"] == ("application/vnd.github+json")

    def test_with_permissions_and_repositories(self) -> None:
        """Sends permissions and repositories in request body."""
        opener = self._mock_opener(
            {
                "token": "ghs_scoped123",
                "expires_at": "2026-01-01T01:00:00Z",
            }
        )

        with patch(
            "airut._bundled.proxy.github_app.urllib.request.build_opener",
            return_value=opener,
        ):
            fetch_installation_token(
                "https://api.github.com",
                12345,
                "fake-jwt",
                permissions={"contents": "write"},
                repositories=["my-repo"],
            )

        req = opener.open.call_args[0][0]
        body = json.loads(req.data)
        assert body["permissions"] == {"contents": "write"}
        assert body["repositories"] == ["my-repo"]

    def test_empty_body_when_no_restrictions(self) -> None:
        """Sends empty JSON object when no permissions or repos."""
        opener = self._mock_opener(
            {
                "token": "ghs_basic123",
                "expires_at": "2026-01-01T01:00:00Z",
            }
        )

        with patch(
            "airut._bundled.proxy.github_app.urllib.request.build_opener",
            return_value=opener,
        ):
            fetch_installation_token(
                "https://api.github.com",
                12345,
                "fake-jwt",
            )

        req = opener.open.call_args[0][0]
        assert req.data == b"{}"

    def test_ghes_base_url(self) -> None:
        """Works with GHES API base URL."""
        opener = self._mock_opener(
            {
                "token": "ghs_ghes123",
                "expires_at": "2026-01-01T01:00:00Z",
            }
        )

        with patch(
            "airut._bundled.proxy.github_app.urllib.request.build_opener",
            return_value=opener,
        ):
            fetch_installation_token(
                "https://github.example.com/api/v3",
                67890,
                "fake-jwt",
            )

        req = opener.open.call_args[0][0]
        assert req.full_url == (
            "https://github.example.com/api/v3"
            "/app/installations/67890/access_tokens"
        )


class TestIsTokenValid:
    """Tests for is_token_valid function."""

    def test_none_is_invalid(self) -> None:
        """None cached token is not valid."""
        assert is_token_valid(None) is False

    def test_fresh_token_is_valid(self) -> None:
        """Token expiring far in the future is valid."""
        cached = CachedToken(
            token="ghs_test",
            expires_at=time.time() + 3600,
        )
        assert is_token_valid(cached) is True

    def test_near_expiry_is_invalid(self) -> None:
        """Token within refresh margin is invalid."""
        cached = CachedToken(
            token="ghs_test",
            expires_at=time.time() + _REFRESH_MARGIN_SECONDS - 10,
        )
        assert is_token_valid(cached) is False

    def test_expired_is_invalid(self) -> None:
        """Expired token is invalid."""
        cached = CachedToken(
            token="ghs_test",
            expires_at=time.time() - 100,
        )
        assert is_token_valid(cached) is False

    def test_exactly_at_margin_is_invalid(self) -> None:
        """Token exactly at refresh margin boundary is invalid."""
        cached = CachedToken(
            token="ghs_test",
            expires_at=time.time() + _REFRESH_MARGIN_SECONDS,
        )
        assert is_token_valid(cached) is False


class TestCachedToken:
    """Tests for CachedToken dataclass."""

    def test_create(self) -> None:
        """Creates CachedToken with token and expiry."""
        cached = CachedToken(token="ghs_abc", expires_at=1234567890.0)
        assert cached.token == "ghs_abc"
        assert cached.expires_at == 1234567890.0
