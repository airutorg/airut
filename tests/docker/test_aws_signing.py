# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for AWS SigV4/SigV4A re-signing logic.

Tests the signing functions defined in docker/aws_signing.py. Since
the file is a proxy addon helper, we test the logic by importing
the key functions directly.
"""

import hashlib
from unittest.mock import patch

from docker.aws_signing import (
    ChunkedResigner,
    ParsedAuth,
    _uri_encode,
    build_canonical_request,
    build_sigv4_string_to_sign,
    build_sigv4a_string_to_sign,
    canonical_headers_string,
    canonical_query_string,
    canonical_uri,
    check_clock_skew,
    derive_sigv4_signing_key,
    derive_sigv4a_key,
    parse_auth_header,
    parse_presigned_url_params,
    resign_presigned_url,
    resign_request,
    sigv4_chunk_string_to_sign,
    sigv4_sign,
    sigv4_trailer_string_to_sign,
    sigv4a_chunk_string_to_sign,
    sigv4a_sign,
    sigv4a_trailer_string_to_sign,
)


# ---------------------------------------------------------------------------
# URI encoding
# ---------------------------------------------------------------------------


class TestUriEncode:
    """Tests for _uri_encode."""

    def test_unreserved_chars_not_encoded(self) -> None:
        """Unreserved characters pass through unchanged."""
        assert _uri_encode("abc123-_.~") == "abc123-_.~"

    def test_space_encoded_as_percent20(self) -> None:
        """Spaces are encoded as %20, not +."""
        assert _uri_encode("hello world") == "hello%20world"

    def test_slash_encoded_by_default(self) -> None:
        """Forward slashes are encoded by default."""
        assert _uri_encode("a/b") == "a%2Fb"

    def test_slash_preserved_when_requested(self) -> None:
        """Forward slashes preserved when encode_slash=False."""
        assert _uri_encode("a/b", encode_slash=False) == "a/b"

    def test_special_chars_encoded(self) -> None:
        """Special characters are percent-encoded."""
        assert _uri_encode("a=b&c") == "a%3Db%26c"

    def test_uppercase_hex(self) -> None:
        """Hex digits in encoding are uppercase."""
        assert _uri_encode("@") == "%40"


# ---------------------------------------------------------------------------
# Canonical URI
# ---------------------------------------------------------------------------


class TestCanonicalUri:
    """Tests for canonical_uri."""

    def test_empty_path_becomes_slash(self) -> None:
        """Empty path returns /."""
        assert canonical_uri("") == "/"

    def test_simple_path(self) -> None:
        """Simple path is URI-encoded."""
        assert canonical_uri("/bucket/key") == "/bucket/key"

    def test_path_normalization(self) -> None:
        """Redundant segments are normalized."""
        assert canonical_uri("/a/b/../c") == "/a/c"

    def test_s3_skips_normalization(self) -> None:
        """S3 preserves double slashes and ..."""
        # S3 doesn't normalize, so double slashes are preserved
        result = canonical_uri("/bucket//key", is_s3=True)
        assert "//" in result

    def test_query_stripped(self) -> None:
        """Query string is stripped from path."""
        assert canonical_uri("/path?query=1") == "/path"

    def test_space_in_path_encoded(self) -> None:
        """Spaces in path segments are encoded."""
        assert canonical_uri("/my path/file") == "/my%20path/file"


# ---------------------------------------------------------------------------
# Canonical query string
# ---------------------------------------------------------------------------


class TestCanonicalQueryString:
    """Tests for canonical_query_string."""

    def test_empty_query(self) -> None:
        """Empty query returns empty string."""
        assert canonical_query_string("") == ""

    def test_single_param(self) -> None:
        """Single parameter is encoded."""
        assert canonical_query_string("key=value") == "key=value"

    def test_sorted_params(self) -> None:
        """Parameters are sorted by name."""
        result = canonical_query_string("b=2&a=1")
        assert result == "a=1&b=2"

    def test_exclude_signature(self) -> None:
        """X-Amz-Signature is excluded when requested."""
        result = canonical_query_string(
            "X-Amz-Signature=abc&key=val",
            exclude_signature=True,
        )
        assert "X-Amz-Signature" not in result
        assert result == "key=val"


# ---------------------------------------------------------------------------
# Canonical headers
# ---------------------------------------------------------------------------


class TestCanonicalHeaders:
    """Tests for canonical_headers_string."""

    def test_basic_headers(self) -> None:
        """Basic header canonicalization."""
        headers = {"Host": "example.com", "x-amz-date": "20260101T000000Z"}
        result = canonical_headers_string(headers, ["host", "x-amz-date"])
        assert result == "host:example.com\nx-amz-date:20260101T000000Z\n"

    def test_whitespace_trimming(self) -> None:
        """Leading/trailing whitespace and sequential spaces collapsed."""
        headers = {"Host": "  example.com  ", "X-Custom": "a  b  c"}
        result = canonical_headers_string(headers, ["host", "x-custom"])
        assert "host:example.com\n" in result
        assert "x-custom:a b c\n" in result

    def test_sorted_output(self) -> None:
        """Headers are sorted alphabetically."""
        headers = {"z-header": "z", "a-header": "a"}
        result = canonical_headers_string(headers, ["z-header", "a-header"])
        assert result.startswith("a-header:")


# ---------------------------------------------------------------------------
# Authorization header parsing
# ---------------------------------------------------------------------------


class TestParseAuthHeader:
    """Tests for parse_auth_header."""

    def test_sigv4_header(self) -> None:
        """Parse a SigV4 Authorization header."""
        auth = (
            "AWS4-HMAC-SHA256 "
            "Credential=AKIAIOSFODNN7EXAMPLE"
            "/20260101/us-east-1/s3/aws4_request, "
            "SignedHeaders=host;x-amz-date, "
            "Signature=abcdef1234567890"
        )
        result = parse_auth_header(auth)
        assert result is not None
        assert result.algorithm == "AWS4-HMAC-SHA256"
        assert result.key_id == "AKIAIOSFODNN7EXAMPLE"
        assert result.scope == "20260101/us-east-1/s3/aws4_request"
        assert result.signed_headers == "host;x-amz-date"
        assert result.signature == "abcdef1234567890"
        assert not result.is_sigv4a

    def test_sigv4a_header(self) -> None:
        """Parse a SigV4A Authorization header."""
        auth = (
            "AWS4-ECDSA-P256-SHA256 "
            "Credential=AKIAIOSFODNN7EXAMPLE/20260101/s3/aws4_request, "
            "SignedHeaders=host;x-amz-date, "
            "Signature=abcdef1234567890"
        )
        result = parse_auth_header(auth)
        assert result is not None
        assert result.is_sigv4a

    def test_non_aws_header(self) -> None:
        """Non-AWS header returns None."""
        assert parse_auth_header("Bearer token123") is None

    def test_malformed_header(self) -> None:
        """Malformed AWS header returns None."""
        assert parse_auth_header("AWS4-HMAC-SHA256 garbage") is None

    def test_parsed_auth_date(self) -> None:
        """ParsedAuth.date extracts date from scope."""
        p = ParsedAuth(
            algorithm="AWS4-HMAC-SHA256",
            key_id="AKIA",
            scope="20260101/us-east-1/s3/aws4_request",
            signed_headers="host",
            signature="abc",
        )
        assert p.date == "20260101"


# ---------------------------------------------------------------------------
# SigV4 signing
# ---------------------------------------------------------------------------


class TestSigV4Signing:
    """Tests for SigV4 signing key derivation and signature computation.

    Uses the AWS test vector from:
    https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    """

    def test_signing_key_derivation(self) -> None:
        """Derive signing key from known inputs."""
        key = derive_sigv4_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        )
        assert isinstance(key, bytes)
        assert len(key) == 32  # SHA-256 output

    def test_full_sigv4_signature(self) -> None:
        """End-to-end SigV4 signature computation."""
        key = derive_sigv4_signing_key("secret", "20260101", "us-east-1", "s3")
        string_to_sign = build_sigv4_string_to_sign(
            "20260101T000000Z",
            "20260101/us-east-1/s3/aws4_request",
            "GET\n/\n\nhost:example.com\n\nhost\nUNSIGNED-PAYLOAD",
        )
        sig = sigv4_sign(key, string_to_sign)
        assert len(sig) == 64  # Hex-encoded SHA-256
        assert all(c in "0123456789abcdef" for c in sig)


# ---------------------------------------------------------------------------
# SigV4A signing
# ---------------------------------------------------------------------------


class TestSigV4ASigning:
    """Tests for SigV4A ECDSA key derivation and signing."""

    def test_key_derivation(self) -> None:
        """Derive ECDSA key from known inputs."""
        key = derive_sigv4a_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "AKIAIOSFODNN7EXAMPLE",
        )
        # Should be an EC private key
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePrivateKey,
        )

        assert isinstance(key, EllipticCurvePrivateKey)

    def test_sigv4a_sign(self) -> None:
        """Compute ECDSA signature."""
        key = derive_sigv4a_key("secret", "AKIAEXAMPLE")
        string_to_sign = build_sigv4a_string_to_sign(
            "20260101T000000Z",
            "20260101/s3/aws4_request",
            "GET\n/\n\nhost:example.com\n\nhost\nUNSIGNED-PAYLOAD",
        )
        sig = sigv4a_sign(key, string_to_sign)
        # ECDSA P-256 signature: r (32 bytes) + s (32 bytes) = 128 hex chars
        assert len(sig) == 128
        assert all(c in "0123456789abcdef" for c in sig)


# ---------------------------------------------------------------------------
# Full request re-signing
# ---------------------------------------------------------------------------


class TestResignRequest:
    """Tests for resign_request."""

    def test_sigv4_resign(self) -> None:
        """Re-sign a SigV4 request."""
        parsed = ParsedAuth(
            algorithm="AWS4-HMAC-SHA256",
            key_id="AKIA_SURROGATE",
            scope="20260101/us-east-1/s3/aws4_request",
            signed_headers="host;x-amz-content-sha256;x-amz-date",
            signature="old_sig",
        )
        headers = {
            "Host": "mybucket.s3.amazonaws.com",
            "x-amz-date": "20260101T000000Z",
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        }
        result = resign_request(
            method="GET",
            path="/key",
            query="",
            headers=headers,
            parsed_auth=parsed,
            real_key_id="AKIAIOSFODNN7EXAMPLE",
            real_secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            content_sha256="UNSIGNED-PAYLOAD",
        )
        assert "AKIAIOSFODNN7EXAMPLE" in result.auth_header
        assert "Signature=" in result.auth_header
        assert result.region == "us-east-1"
        assert not result.is_chunked

    def test_sigv4a_resign(self) -> None:
        """Re-sign a SigV4A request."""
        parsed = ParsedAuth(
            algorithm="AWS4-ECDSA-P256-SHA256",
            key_id="AKIA_SURROGATE",
            scope="20260101/s3/aws4_request",
            signed_headers="host;x-amz-content-sha256;x-amz-date",
            signature="old_sig",
        )
        headers = {
            "Host": "mybucket.s3.amazonaws.com",
            "x-amz-date": "20260101T000000Z",
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        }
        result = resign_request(
            method="GET",
            path="/key",
            query="",
            headers=headers,
            parsed_auth=parsed,
            real_key_id="AKIAIOSFODNN7EXAMPLE",
            real_secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            content_sha256="UNSIGNED-PAYLOAD",
        )
        assert "AWS4-ECDSA-P256-SHA256" in result.auth_header
        assert result.region == ""  # SigV4A has no region in scope

    def test_chunked_detected(self) -> None:
        """Streaming payload is detected as chunked."""
        parsed = ParsedAuth(
            algorithm="AWS4-HMAC-SHA256",
            key_id="AKIA_SURROGATE",
            scope="20260101/us-east-1/s3/aws4_request",
            signed_headers="host;x-amz-content-sha256;x-amz-date",
            signature="old_sig",
        )
        headers = {
            "Host": "mybucket.s3.amazonaws.com",
            "x-amz-date": "20260101T000000Z",
            "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        }
        result = resign_request(
            method="PUT",
            path="/key",
            query="",
            headers=headers,
            parsed_auth=parsed,
            real_key_id="AKIAIOSFODNN7EXAMPLE",
            real_secret_key="secret",
            content_sha256="STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        )
        assert result.is_chunked


# ---------------------------------------------------------------------------
# Chunk re-signing
# ---------------------------------------------------------------------------


class TestChunkedResigner:
    """Tests for ChunkedResigner state machine."""

    def _make_sigv4_resigner(self) -> tuple[ChunkedResigner, bytes]:
        """Create a SigV4 ChunkedResigner with test credentials."""
        signing_key = derive_sigv4_signing_key(
            "secret", "20260101", "us-east-1", "s3"
        )
        return ChunkedResigner(
            signing_key=signing_key,
            ecdsa_key=None,
            seed_signature="seed_sig_hex",
            timestamp="20260101T000000Z",
            scope="20260101/us-east-1/s3/aws4_request",
            is_sigv4a=False,
            has_trailer=False,
        ), signing_key

    def test_single_chunk_and_terminal(self) -> None:
        """Process a single data chunk followed by terminal chunk."""
        resigner, signing_key = self._make_sigv4_resigner()

        chunk_data = b"Hello, world!"
        hex_size = format(len(chunk_data), "x").encode()
        body = (
            hex_size
            + b";chunk-signature=aa00bb11cc22dd33\r\n"
            + chunk_data
            + b"\r\n"
            + b"0;chunk-signature=ee44ff5500661177\r\n"
        )

        result = resigner.process(body)

        # Should contain re-signed chunk signatures
        assert b"chunk-signature=" in result
        assert b"Hello, world!" in result
        # Old signatures should be replaced
        assert b"aa00bb11cc22dd33" not in result
        assert b"ee44ff5500661177" not in result

    def test_incremental_data(self) -> None:
        """Process data arriving in small increments."""
        resigner, _ = self._make_sigv4_resigner()

        chunk_data = b"test"
        hex_size = format(len(chunk_data), "x").encode()
        full_body = (
            hex_size
            + b";chunk-signature=aa00bb11cc22dd33\r\n"
            + chunk_data
            + b"\r\n"
            + b"0;chunk-signature=ee44ff5500661177\r\n"
        )

        # Feed byte by byte
        output = b""
        for i in range(len(full_body)):
            output += resigner.process(full_body[i : i + 1])

        assert b"test" in output
        assert b"chunk-signature=" in output
        assert b"aa00bb11cc22dd33" not in output

    def test_terminal_chunk_only(self) -> None:
        """Process just a terminal chunk."""
        resigner, _ = self._make_sigv4_resigner()

        result = resigner.process(b"0;chunk-signature=aa00bb11cc22dd33\r\n")
        assert b"0;chunk-signature=" in result
        assert b"aa00bb11cc22dd33" not in result

    def test_trailer_mode(self) -> None:
        """Process chunks with trailing header signature."""
        signing_key = derive_sigv4_signing_key(
            "secret", "20260101", "us-east-1", "s3"
        )
        resigner = ChunkedResigner(
            signing_key=signing_key,
            ecdsa_key=None,
            seed_signature="aa00bb11",
            timestamp="20260101T000000Z",
            scope="20260101/us-east-1/s3/aws4_request",
            is_sigv4a=False,
            has_trailer=True,
        )

        body = (
            b"0;chunk-signature=cc22dd33ee44ff55\r\n"
            b"x-amz-checksum-sha256:abc123\r\n"
            b"x-amz-trailer-signature:0011223344556677\r\n"
        )

        result = resigner.process(body)
        assert b"x-amz-trailer-signature:" in result
        assert b"0011223344556677" not in result


# ---------------------------------------------------------------------------
# Chunk string-to-sign
# ---------------------------------------------------------------------------


class TestChunkStringToSign:
    """Tests for chunk signature string-to-sign builders."""

    def test_sigv4_chunk_sts(self) -> None:
        """SigV4 chunk string-to-sign format."""
        string_to_sign = sigv4_chunk_string_to_sign(
            "20260101T000000Z",
            "20260101/us-east-1/s3/aws4_request",
            "prev_sig",
            b"chunk data",
        )
        assert string_to_sign.startswith("AWS4-HMAC-SHA256-PAYLOAD")
        assert "prev_sig" in string_to_sign
        assert hashlib.sha256(b"chunk data").hexdigest() in string_to_sign

    def test_sigv4_trailer_sts(self) -> None:
        """SigV4 trailer string-to-sign format."""
        string_to_sign = sigv4_trailer_string_to_sign(
            "20260101T000000Z",
            "20260101/us-east-1/s3/aws4_request",
            "prev_sig",
            b"x-amz-checksum-sha256:abc",
        )
        assert string_to_sign.startswith("AWS4-HMAC-SHA256-TRAILER")
        assert "prev_sig" in string_to_sign


# ---------------------------------------------------------------------------
# Presigned URL
# ---------------------------------------------------------------------------


class TestPresignedUrl:
    """Tests for presigned URL parsing and re-signing."""

    def test_parse_presigned_params(self) -> None:
        """Parse presigned URL query parameters."""
        query = (
            "X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=AKIA%2F20260101%2Fus-east-1%2Fs3%2Faws4_request"
            "&X-Amz-Date=20260101T000000Z"
            "&X-Amz-Expires=3600"
            "&X-Amz-SignedHeaders=host"
            "&X-Amz-Signature=abcdef"
        )
        params = parse_presigned_url_params(query)
        assert params is not None
        assert "X-Amz-Credential" in params

    def test_non_presigned_returns_none(self) -> None:
        """Non-presigned query returns None."""
        assert parse_presigned_url_params("key=value") is None

    def test_resign_presigned_url(self) -> None:
        """Re-sign a presigned URL."""
        query = (
            "X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=AKIA_SURROGATE/20260101/us-east-1/s3/aws4_request"
            "&X-Amz-Date=20260101T000000Z"
            "&X-Amz-Expires=3600"
            "&X-Amz-SignedHeaders=host"
            "&X-Amz-Signature=oldsig"
        )
        params = parse_presigned_url_params(query)
        assert params is not None

        new_query = resign_presigned_url(
            method="GET",
            path="/bucket/key",
            query=query,
            headers={"Host": "s3.amazonaws.com"},
            params=params,
            real_key_id="AKIAIOSFODNN7EXAMPLE",
            real_secret_key="secret",
        )
        assert "AKIAIOSFODNN7EXAMPLE" in new_query
        assert "oldsig" not in new_query


# ---------------------------------------------------------------------------
# Clock skew detection
# ---------------------------------------------------------------------------


class TestClockSkew:
    """Tests for check_clock_skew."""

    def test_no_skew(self) -> None:
        """Current time has no skew."""
        from datetime import UTC, datetime

        now = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        is_skewed, drift = check_clock_skew(now)
        assert not is_skewed
        assert drift < 2  # Allow 1 minute of test execution time

    def test_large_skew(self) -> None:
        """Old timestamp is detected as skewed."""
        is_skewed, drift = check_clock_skew("20200101T000000Z")
        assert is_skewed
        assert drift > 60  # More than an hour

    def test_invalid_timestamp(self) -> None:
        """Invalid timestamp returns no skew."""
        is_skewed, drift = check_clock_skew("invalid")
        assert not is_skewed
        assert drift == 0


# ---------------------------------------------------------------------------
# Build canonical request
# ---------------------------------------------------------------------------


class TestBuildCanonicalRequest:
    """Tests for build_canonical_request."""

    def test_basic_request(self) -> None:
        """Build canonical request for a simple GET."""
        creq = build_canonical_request(
            method="GET",
            path="/",
            query="",
            headers={"Host": "example.com", "x-amz-date": "20260101T000000Z"},
            signed_headers="host;x-amz-date",
            payload_hash="UNSIGNED-PAYLOAD",
        )
        lines = creq.split("\n")
        assert lines[0] == "GET"
        assert lines[1] == "/"
        assert lines[2] == ""  # Empty query
        assert "host:example.com" in lines[3]
        assert lines[-1] == "UNSIGNED-PAYLOAD"

    def test_s3_path_not_normalized(self) -> None:
        """S3 paths are not normalized."""
        creq = build_canonical_request(
            method="GET",
            path="/bucket//key",
            query="",
            headers={"Host": "s3.amazonaws.com"},
            signed_headers="host",
            payload_hash="UNSIGNED-PAYLOAD",
            is_s3=True,
        )
        assert "//key" in creq


# ---------------------------------------------------------------------------
# SigV4A key derivation exhaustion
# ---------------------------------------------------------------------------


class TestSigV4AKeyDerivationExhaustion:
    """Cover RuntimeError when 254 iterations all fail."""

    def test_key_derivation_fails_after_254(self) -> None:
        """Raises RuntimeError if no valid key found."""
        # Always return a value > P256_ORDER - 2 to force all iterations to fail
        from docker.aws_signing import _P256_ORDER

        big = (_P256_ORDER - 1).to_bytes(32, "big")
        with patch("docker.aws_signing._hmac_sha256", return_value=big):
            import pytest

            with pytest.raises(RuntimeError, match="254 iterations"):
                derive_sigv4a_key("secret", "AKIAEXAMPLE")


# ---------------------------------------------------------------------------
# SigV4A chunk and trailer string-to-sign
# ---------------------------------------------------------------------------


class TestSigV4AChunkStringToSign:
    """Cover sigv4a_chunk_string_to_sign."""

    def test_format(self) -> None:
        """SigV4A chunk string-to-sign starts with correct algorithm."""
        string_to_sign = sigv4a_chunk_string_to_sign(
            "20260101T000000Z",
            "20260101/s3/aws4_request",
            "prev_sig",
            b"chunk data",
        )
        assert string_to_sign.startswith("AWS4-ECDSA-P256-SHA256-PAYLOAD")
        assert "prev_sig" in string_to_sign
        assert hashlib.sha256(b"chunk data").hexdigest() in string_to_sign


class TestSigV4ATrailerStringToSign:
    """Cover sigv4a_trailer_string_to_sign."""

    def test_format(self) -> None:
        """SigV4A trailer string-to-sign starts with correct algorithm."""
        string_to_sign = sigv4a_trailer_string_to_sign(
            "20260101T000000Z",
            "20260101/s3/aws4_request",
            "prev_sig",
            b"x-amz-checksum:abc",
        )
        assert string_to_sign.startswith("AWS4-ECDSA-P256-SHA256-TRAILER")
        assert "prev_sig" in string_to_sign


# ---------------------------------------------------------------------------
# resign_request: case-insensitive x-amz-date fallback
# ---------------------------------------------------------------------------


class TestResignRequestCaseInsensitiveDate:
    """Cover the fallback loop for case-insensitive x-amz-date lookup."""

    def test_uppercase_amz_date(self) -> None:
        """Re-sign succeeds when x-amz-date key is mixed case."""
        parsed = ParsedAuth(
            algorithm="AWS4-HMAC-SHA256",
            key_id="AKIA_SURROGATE",
            scope="20260101/us-east-1/s3/aws4_request",
            signed_headers="host;x-amz-content-sha256;x-amz-date",
            signature="old_sig",
        )
        # Use "X-Amz-Date" (mixed case) instead of lowercase "x-amz-date"
        headers = {
            "Host": "mybucket.s3.amazonaws.com",
            "X-Amz-Date": "20260101T000000Z",
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        }
        result = resign_request(
            method="GET",
            path="/key",
            query="",
            headers=headers,
            parsed_auth=parsed,
            real_key_id="AKIAIOSFODNN7EXAMPLE",
            real_secret_key="secret",
            content_sha256="UNSIGNED-PAYLOAD",
        )
        assert "Signature=" in result.auth_header


# ---------------------------------------------------------------------------
# ChunkedResigner SigV4A paths
# ---------------------------------------------------------------------------


class TestChunkedResignerSigV4A:
    """Cover ChunkedResigner with is_sigv4a=True (ECDSA paths)."""

    def _make_sigv4a_resigner(
        self, has_trailer: bool = False
    ) -> ChunkedResigner:
        """Create a SigV4A ChunkedResigner."""
        ecdsa_key = derive_sigv4a_key("secret", "AKIAEXAMPLE")
        return ChunkedResigner(
            signing_key=None,
            ecdsa_key=ecdsa_key,
            seed_signature="aa00bb11",
            timestamp="20260101T000000Z",
            scope="20260101/s3/aws4_request",
            is_sigv4a=True,
            has_trailer=has_trailer,
        )

    def test_sigv4a_single_chunk(self) -> None:
        """Process a single chunk with SigV4A re-signing."""
        resigner = self._make_sigv4a_resigner()
        chunk_data = b"test data"
        hex_size = format(len(chunk_data), "x").encode()
        body = (
            hex_size
            + b";chunk-signature=deadbeef\r\n"
            + chunk_data
            + b"\r\n"
            + b"0;chunk-signature=cafebabe\r\n"
        )
        result = resigner.process(body)
        assert b"chunk-signature=" in result
        assert b"test data" in result
        assert b"deadbeef" not in result
        assert b"cafebabe" not in result

    def test_sigv4a_trailer(self) -> None:
        """Process SigV4A chunks with trailing header signature."""
        resigner = self._make_sigv4a_resigner(has_trailer=True)
        body = (
            b"0;chunk-signature=cc22dd33\r\n"
            b"x-amz-checksum-sha256:abc123\r\n"
            b"x-amz-trailer-signature:0011223344\r\n"
        )
        result = resigner.process(body)
        assert b"x-amz-trailer-signature:" in result
        assert b"0011223344" not in result


# ---------------------------------------------------------------------------
# ChunkedResigner edge cases
# ---------------------------------------------------------------------------


class TestChunkedResignerEdgeCases:
    """Cover process() edge cases: done state, non-chunk pass-through."""

    def _make_sigv4_resigner(
        self, has_trailer: bool = False
    ) -> ChunkedResigner:
        """Create a SigV4 ChunkedResigner."""
        signing_key = derive_sigv4_signing_key(
            "secret", "20260101", "us-east-1", "s3"
        )
        return ChunkedResigner(
            signing_key=signing_key,
            ecdsa_key=None,
            seed_signature="seed_sig",
            timestamp="20260101T000000Z",
            scope="20260101/us-east-1/s3/aws4_request",
            is_sigv4a=False,
            has_trailer=has_trailer,
        )

    def test_process_after_done(self) -> None:
        """After processing completes, extra data passes through."""
        resigner = self._make_sigv4_resigner()
        # Process terminal chunk to mark done
        resigner.process(b"0;chunk-signature=aa00bb11\r\n")
        # Now process more data — should pass through
        result = resigner.process(b"trailing data")
        assert result == b"trailing data"

    def test_non_chunk_header_no_trailer(self) -> None:
        """Non-chunk data with no trailer passes through and marks done."""
        resigner = self._make_sigv4_resigner(has_trailer=False)
        # Feed data that has \r\n but isn't a valid chunk header
        result = resigner.process(b"not-a-chunk-header\r\n")
        assert result == b"not-a-chunk-header\r\n"
        assert resigner._done is True
        # Further data passes through via the _done early return
        result2 = resigner.process(b"more data")
        assert result2 == b"more data"

    def test_trailer_incomplete_buffer(self) -> None:
        """Trailer processing with incomplete buffer passes through."""
        resigner = self._make_sigv4_resigner(has_trailer=True)
        # Feed terminal chunk followed by partial trailer (no signature line)
        body = b"0;chunk-signature=aabb\r\nx-amz-checksum-sha256:abc123\r\n"
        # The process should handle the incomplete trailer
        result = resigner.process(body)
        # The terminal chunk gets re-signed, trailer data buffered/passed
        assert b"chunk-signature=" in result

    def test_trailer_arrives_separately(self) -> None:
        """Trailer data arriving in a separate process() call."""
        resigner = self._make_sigv4_resigner(has_trailer=True)
        # First: terminal chunk only (no trailer in same segment)
        result1 = resigner.process(b"0;chunk-signature=aabb\r\n")
        assert b"chunk-signature=" in result1
        # Then: trailer data arrives as a separate TCP segment
        trailer = (
            b"x-amz-checksum-sha256:abc123\r\n"
            b"x-amz-trailer-signature:0011223344\r\n"
        )
        result2 = resigner.process(trailer)
        assert b"x-amz-trailer-signature:" in result2
        assert b"0011223344" not in result2


# ---------------------------------------------------------------------------
# Presigned URL re-signing with SigV4A
# ---------------------------------------------------------------------------


class TestPresignedUrlSigV4A:
    """Cover resign_presigned_url with SigV4A (ECDSA path)."""

    def test_resign_presigned_sigv4a(self) -> None:
        """Re-sign a SigV4A presigned URL."""
        query = (
            "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256"
            "&X-Amz-Credential=AKIA_SURROGATE/20260101/s3/aws4_request"
            "&X-Amz-Date=20260101T000000Z"
            "&X-Amz-Expires=3600"
            "&X-Amz-SignedHeaders=host"
            "&X-Amz-Signature=oldsig"
        )
        params = parse_presigned_url_params(query)
        assert params is not None

        new_query = resign_presigned_url(
            method="GET",
            path="/bucket/key",
            query=query,
            headers={"Host": "s3.amazonaws.com"},
            params=params,
            real_key_id="AKIAIOSFODNN7EXAMPLE",
            real_secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        )
        assert "AKIAIOSFODNN7EXAMPLE" in new_query
        assert "oldsig" not in new_query
