# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""AWS SigV4/SigV4A request re-signing for the proxy.

Provides functions to re-sign AWS requests with real credentials after
the container signed them with surrogates. Supports:

- SigV4 (HMAC-SHA256)
- SigV4A (ECDSA P-256)
- Chunked transfer re-signing (streaming)
- Presigned URL re-signing

No boto3/botocore dependency — uses only stdlib + cryptography.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import urllib.parse
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
)


# P-256 curve order for SigV4A key derivation
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Signing type identifier for AWS SigV4/SigV4A credential re-signing
SIGNING_TYPE_AWS_SIGV4 = "aws-sigv4"

_SHA256_EMPTY = hashlib.sha256(b"").hexdigest()

_AWS_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)

# Authorization header regex
_AUTH_HEADER_RE = re.compile(
    r"(?P<algorithm>AWS4-HMAC-SHA256|AWS4-ECDSA-P256-SHA256)\s+"
    r"Credential=(?P<key_id>[^/]+)/(?P<scope>[^,]+),\s*"
    r"SignedHeaders=(?P<signed_headers>[^,]+),\s*"
    r"Signature=(?P<signature>[0-9a-f]+)"
)

# Chunked body line regex: {hex};chunk-signature={sig}\r\n
_CHUNK_HEADER_RE = re.compile(
    rb"(?P<hex_size>[0-9a-fA-F]+);chunk-signature=(?P<sig>[0-9a-f]+)\r\n"
)

# Trailer signature regex
_TRAILER_SIG_RE = re.compile(rb"x-amz-trailer-signature:(?P<sig>[0-9a-f]+)")

# Streaming content-sha256 values that indicate chunked signing
STREAMING_PAYLOAD_SIGV4 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
STREAMING_PAYLOAD_SIGV4_TRAILER = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
STREAMING_PAYLOAD_SIGV4A = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
STREAMING_PAYLOAD_SIGV4A_TRAILER = (
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"
)

STREAMING_VALUES = frozenset(
    {
        STREAMING_PAYLOAD_SIGV4,
        STREAMING_PAYLOAD_SIGV4_TRAILER,
        STREAMING_PAYLOAD_SIGV4A,
        STREAMING_PAYLOAD_SIGV4A_TRAILER,
    }
)


# ---------------------------------------------------------------------------
# Parsed authorization header
# ---------------------------------------------------------------------------


class ParsedAuth:
    """Parsed AWS Authorization header."""

    __slots__ = (
        "algorithm",
        "key_id",
        "scope",
        "signed_headers",
        "signature",
    )

    def __init__(
        self,
        algorithm: str,
        key_id: str,
        scope: str,
        signed_headers: str,
        signature: str,
    ) -> None:
        self.algorithm = algorithm
        self.key_id = key_id
        self.scope = scope
        self.signed_headers = signed_headers
        self.signature = signature

    @property
    def scope_parts(self) -> list[str]:
        """Split scope into parts.

        Returns date/region/service/aws4_request for SigV4 or
        date/service/aws4_request for SigV4A.
        """
        return self.scope.split("/")

    @property
    def date(self) -> str:
        """Date from credential scope (YYYYMMDD)."""
        return self.scope_parts[0]

    @property
    def is_sigv4a(self) -> bool:
        """True if this is a SigV4A (ECDSA) signature."""
        return self.algorithm == "AWS4-ECDSA-P256-SHA256"


def parse_auth_header(auth_value: str) -> ParsedAuth | None:
    """Parse an AWS Authorization header.

    Args:
        auth_value: Full Authorization header value.

    Returns:
        ParsedAuth if valid AWS auth, None otherwise.
    """
    m = _AUTH_HEADER_RE.match(auth_value)
    if not m:
        return None
    return ParsedAuth(
        algorithm=m.group("algorithm"),
        key_id=m.group("key_id"),
        scope=m.group("scope"),
        signed_headers=m.group("signed_headers"),
        signature=m.group("signature"),
    )


# ---------------------------------------------------------------------------
# URI encoding (AWS-specific RFC 3986 subset)
# ---------------------------------------------------------------------------


def _uri_encode(value: str, *, encode_slash: bool = True) -> str:
    """URI-encode a value using AWS's specific rules.

    - Unreserved characters are not encoded: A-Z, a-z, 0-9, -, _, ., ~
    - All other characters are percent-encoded as %XX (uppercase hex)
    - Forward slashes (/) are optionally preserved

    Args:
        value: String to encode.
        encode_slash: If True, encode '/'; if False, preserve '/'.

    Returns:
        URI-encoded string.
    """
    result: list[str] = []
    for ch in value:
        if ch in _AWS_UNRESERVED:
            result.append(ch)
        elif ch == "/" and not encode_slash:
            result.append("/")
        else:
            result.append(f"%{ord(ch):02X}")
    return "".join(result)


# ---------------------------------------------------------------------------
# Canonical request construction
# ---------------------------------------------------------------------------


def canonical_uri(path: str, *, is_s3: bool = False) -> str:
    """Build canonical URI from request path.

    The path may arrive already percent-encoded (from the HTTP request line
    as seen by the proxy).

    SigV4 has a per-service ``doubleURIEncode`` setting:

    * **S3** (``is_s3=True``): single-encode only.  Decode any existing
      percent-encoding first, then URI-encode once.  ``%3A`` → ``%3A``.
    * **All other services** (``is_s3=False``, default): double-encode.
      URI-encode the path *as-is*, so ``%`` in existing escapes becomes
      ``%25``.  ``%3A`` → ``%253A``.

    Args:
        path: Request path, possibly already percent-encoded.
        is_s3: If True, use S3 canonicalization (single-encode, skip
            path normalization).

    Returns:
        URI-encoded canonical path.
    """
    if not path:
        return "/"

    # Strip query string if present
    path = path.split("?")[0]

    if is_s3:
        # S3: decode first, then single-encode (no double encoding).
        # S3 also preserves double slashes and . / .. segments.
        path = urllib.parse.unquote(path)
        return _uri_encode(path, encode_slash=False)

    # Non-S3: normalize path, then double-encode.
    # First decode so normalization works on raw characters.
    decoded = urllib.parse.unquote(path)
    parts = decoded.split("/")
    normalized: list[str] = []
    for part in parts:
        if part == "..":
            if normalized:
                normalized.pop()
        elif part != "." and part != "":
            normalized.append(part)
    normalized_path = "/" + "/".join(normalized)

    # Single-encode raw characters, then encode the result again
    # (the "double URI encode" rule).  This means pre-encoded
    # %3A becomes %253A, which is what AWS expects for non-S3.
    single = _uri_encode(normalized_path, encode_slash=False)
    return _uri_encode(single, encode_slash=False)


def canonical_query_string(
    query: str, *, exclude_signature: bool = False
) -> str:
    """Build canonical query string.

    Args:
        query: Raw query string (without leading ?).
        exclude_signature: If True, exclude X-Amz-Signature parameter
            (for presigned URL re-signing).

    Returns:
        Canonical query string (sorted, encoded).
    """
    if not query:
        return ""

    params = urllib.parse.parse_qsl(query, keep_blank_values=True)

    if exclude_signature:
        params = [(k, v) for k, v in params if k != "X-Amz-Signature"]

    # URI-encode names and values, sort by encoded name then value
    encoded = [(_uri_encode(k), _uri_encode(v)) for k, v in params]
    encoded.sort()

    return "&".join(f"{k}={v}" for k, v in encoded)


def canonical_headers_string(
    headers: dict[str, str], signed_headers_list: list[str]
) -> str:
    """Build canonical headers string.

    Args:
        headers: Request headers (name -> value).
        signed_headers_list: List of signed header names (lowercase).

    Returns:
        Canonical headers string (each line: "name:value" + newline).
    """
    lines: list[str] = []
    # Build case-insensitive lookup
    lower_headers: dict[str, str] = {}
    for name, value in headers.items():
        lower_headers[name.lower()] = value

    for name in sorted(signed_headers_list):
        value = lower_headers.get(name, "")
        # Trim leading/trailing whitespace, collapse sequential spaces
        trimmed = " ".join(value.split())
        lines.append(f"{name}:{trimmed}\n")

    return "".join(lines)


def build_canonical_request(
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    signed_headers: str,
    payload_hash: str,
    *,
    is_s3: bool = False,
    exclude_signature: bool = False,
) -> str:
    """Build the canonical request string.

    Args:
        method: HTTP method.
        path: Request path.
        query: Query string (without leading ?).
        headers: Request headers.
        signed_headers: Semicolon-separated signed header names.
        payload_hash: Payload hash (from x-amz-content-sha256 or computed).
        is_s3: If True, skip S3-specific path normalization.
        exclude_signature: If True, exclude X-Amz-Signature from query.

    Returns:
        Canonical request string.
    """
    signed_list = signed_headers.split(";")

    return "\n".join(
        [
            method,
            canonical_uri(path, is_s3=is_s3),
            canonical_query_string(query, exclude_signature=exclude_signature),
            canonical_headers_string(headers, signed_list),
            signed_headers,
            payload_hash,
        ]
    )


# ---------------------------------------------------------------------------
# SigV4 signing
# ---------------------------------------------------------------------------


def _hmac_sha256(key: bytes, msg: str | bytes) -> bytes:
    """HMAC-SHA256 helper."""
    if isinstance(msg, str):
        msg = msg.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).digest()


def derive_sigv4_signing_key(
    secret_key: str, date: str, region: str, service: str
) -> bytes:
    """Derive the SigV4 signing key.

    Args:
        secret_key: AWS secret access key.
        date: Date string (YYYYMMDD).
        region: AWS region.
        service: AWS service name.

    Returns:
        Derived signing key bytes.
    """
    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    k_signing = _hmac_sha256(k_service, "aws4_request")
    return k_signing


def sigv4_sign(signing_key: bytes, string_to_sign: str) -> str:
    """Compute SigV4 signature.

    Args:
        signing_key: Derived signing key.
        string_to_sign: The string to sign.

    Returns:
        Hex-encoded signature.
    """
    return hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def build_sigv4_string_to_sign(
    timestamp: str, scope: str, canonical_request: str
) -> str:
    """Build the SigV4 string to sign.

    Args:
        timestamp: ISO8601 timestamp (from x-amz-date).
        scope: Credential scope (date/region/service/aws4_request).
        canonical_request: The canonical request string.

    Returns:
        String to sign.
    """
    return "\n".join(
        [
            "AWS4-HMAC-SHA256",
            timestamp,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )


# ---------------------------------------------------------------------------
# SigV4A signing (ECDSA P-256)
# ---------------------------------------------------------------------------


def derive_sigv4a_key(
    secret_key: str, access_key_id: str
) -> EllipticCurvePrivateKey:
    """Derive the ECDSA P-256 private key for SigV4A.

    Uses the AWS key derivation algorithm:
    1. input_key = "AWS4A" + secret_access_key
    2. Counter starts at 0x01
    3. HMAC-SHA256(input_key, label || 0x00 || access_key_id || counter)
    4. Interpret as integer c; if c <= n-2, private_key = c + 1

    Args:
        secret_key: AWS secret access key.
        access_key_id: AWS access key ID (real, not surrogate).

    Returns:
        cryptography EllipticCurvePrivateKey object.

    Raises:
        ImportError: If cryptography is not installed.
        RuntimeError: If key derivation fails after 254 iterations.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        derive_private_key,
    )

    input_key = ("AWS4A" + secret_key).encode("utf-8")
    label = b"AWS4-ECDSA-P256-SHA256"

    for counter in range(1, 255):
        msg = label + b"\x00" + access_key_id.encode("utf-8") + bytes([counter])
        kdf_output = _hmac_sha256(input_key, msg)
        c = int.from_bytes(kdf_output, "big")
        if c <= _P256_ORDER - 2:
            private_key_int = c + 1
            return derive_private_key(private_key_int, SECP256R1())

    raise RuntimeError("SigV4A key derivation failed after 254 iterations")


def sigv4a_sign(
    private_key: EllipticCurvePrivateKey, string_to_sign: str
) -> str:
    """Compute SigV4A ECDSA signature.

    Args:
        private_key: ECDSA P-256 private key.
        string_to_sign: The string to sign.

    Returns:
        Hex-encoded DER signature.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA256

    digest = hashlib.sha256(string_to_sign.encode("utf-8")).digest()
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
    )

    sig_der = private_key.sign(digest, ECDSA(SHA256()))
    r, s = decode_dss_signature(sig_der)

    # Encode r and s as fixed-width 32-byte big-endian, concatenated
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    return (r_bytes + s_bytes).hex()


def build_sigv4a_string_to_sign(
    timestamp: str, scope: str, canonical_request: str
) -> str:
    """Build the SigV4A string to sign.

    Args:
        timestamp: ISO8601 timestamp.
        scope: Credential scope (date/service/aws4_request, no region).
        canonical_request: The canonical request string.

    Returns:
        String to sign.
    """
    return "\n".join(
        [
            "AWS4-ECDSA-P256-SHA256",
            timestamp,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )


# ---------------------------------------------------------------------------
# Chunk re-signing
# ---------------------------------------------------------------------------


def sigv4_chunk_string_to_sign(
    timestamp: str,
    scope: str,
    previous_signature: str,
    chunk_data: bytes,
) -> str:
    """Build the string to sign for a SigV4 chunked payload.

    Args:
        timestamp: ISO8601 timestamp.
        scope: Credential scope.
        previous_signature: Previous chunk's (or seed) signature.
        chunk_data: Raw chunk data bytes.

    Returns:
        String to sign for this chunk.
    """
    return "\n".join(
        [
            "AWS4-HMAC-SHA256-PAYLOAD",
            timestamp,
            scope,
            previous_signature,
            _SHA256_EMPTY,
            hashlib.sha256(chunk_data).hexdigest(),
        ]
    )


def sigv4_trailer_string_to_sign(
    timestamp: str,
    scope: str,
    previous_signature: str,
    trailing_headers: bytes,
) -> str:
    """Build the string to sign for a SigV4 trailing header signature.

    Args:
        timestamp: ISO8601 timestamp.
        scope: Credential scope.
        previous_signature: Terminal chunk's signature.
        trailing_headers: Raw trailing header bytes.

    Returns:
        String to sign for the trailer.
    """
    return "\n".join(
        [
            "AWS4-HMAC-SHA256-TRAILER",
            timestamp,
            scope,
            previous_signature,
            hashlib.sha256(trailing_headers).hexdigest(),
        ]
    )


def sigv4a_chunk_string_to_sign(
    timestamp: str,
    scope: str,
    previous_signature: str,
    chunk_data: bytes,
) -> str:
    """Build the string to sign for a SigV4A chunked payload."""
    return "\n".join(
        [
            "AWS4-ECDSA-P256-SHA256-PAYLOAD",
            timestamp,
            scope,
            previous_signature,
            _SHA256_EMPTY,
            hashlib.sha256(chunk_data).hexdigest(),
        ]
    )


def sigv4a_trailer_string_to_sign(
    timestamp: str,
    scope: str,
    previous_signature: str,
    trailing_headers: bytes,
) -> str:
    """Build the string to sign for a SigV4A trailing header signature."""
    return "\n".join(
        [
            "AWS4-ECDSA-P256-SHA256-TRAILER",
            timestamp,
            scope,
            previous_signature,
            hashlib.sha256(trailing_headers).hexdigest(),
        ]
    )


# ---------------------------------------------------------------------------
# Request re-signing orchestration
# ---------------------------------------------------------------------------


class ResignResult:
    """Result of a request re-signing operation."""

    __slots__ = (
        "auth_header",
        "region",
        "is_chunked",
        "canonical_request_hash",
        "signed_headers",
        "canonical_request",
    )

    def __init__(
        self,
        auth_header: str,
        region: str,
        *,
        is_chunked: bool = False,
        canonical_request_hash: str = "",
        signed_headers: str = "",
        canonical_request: str = "",
    ) -> None:
        self.auth_header = auth_header
        self.region = region
        self.is_chunked = is_chunked
        self.canonical_request_hash = canonical_request_hash
        self.signed_headers = signed_headers
        self.canonical_request = canonical_request


def resign_request(
    *,
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    parsed_auth: ParsedAuth,
    real_key_id: str,
    real_secret_key: str,
    content_sha256: str,
) -> ResignResult:
    """Re-sign a request with real AWS credentials.

    Handles both SigV4 and SigV4A.

    Args:
        method: HTTP method.
        path: Request path (without query string).
        query: Query string (without leading ?).
        headers: All request headers.
        parsed_auth: Parsed surrogate Authorization header.
        real_key_id: Real AWS access key ID.
        real_secret_key: Real AWS secret access key.
        content_sha256: Value of x-amz-content-sha256 header.

    Returns:
        ResignResult with the new Authorization header value.
    """
    scope_parts = parsed_auth.scope_parts
    is_s3 = scope_parts[-2] == "s3" if len(scope_parts) >= 2 else False

    # Normalize HTTP/2 :authority pseudo-header → host.
    # AWS SDKs using HTTP/2 sign with :authority, but mitmproxy converts
    # it to a Host header.  We must re-sort after replacement and also
    # ensure the headers dict has a "host" entry with the right value,
    # since mitmproxy may not always synthesize a Host header from
    # :authority (especially in the requestheaders hook).
    signed_headers = parsed_auth.signed_headers
    if ":authority" in signed_headers.split(";"):
        parts = signed_headers.split(";")
        parts = ["host" if p == ":authority" else p for p in parts]
        signed_headers = ";".join(sorted(set(parts)))

        # Copy :authority value into headers as "host".
        # mitmproxy may not synthesize a proper Host header from
        # :authority (can be empty or missing), so we always
        # populate it from :authority when available.
        authority_val = ""
        for k, v in headers.items():
            if k.lower() == ":authority":
                authority_val = v
                break
        if authority_val:
            headers = dict(headers)  # Avoid mutating caller's dict
            # Remove any existing Host/host variants to avoid
            # duplicates in the case-insensitive lookup.
            for k in list(headers):
                if k.lower() == "host":
                    del headers[k]
            headers["host"] = authority_val

    # Build canonical request
    creq = build_canonical_request(
        method=method,
        path=path,
        query=query,
        headers=headers,
        signed_headers=signed_headers,
        payload_hash=content_sha256,
        is_s3=is_s3,
    )

    timestamp = headers.get("x-amz-date", "")
    if not timestamp:
        # Fall back to case-insensitive search
        for name, value in headers.items():
            if name.lower() == "x-amz-date":
                timestamp = value
                break

    is_chunked = content_sha256 in STREAMING_VALUES

    if parsed_auth.is_sigv4a:
        # SigV4A: scope is date/service/aws4_request (no region)
        region = ""
        string_to_sign = build_sigv4a_string_to_sign(
            timestamp, parsed_auth.scope, creq
        )
        private_key = derive_sigv4a_key(real_secret_key, real_key_id)
        signature = sigv4a_sign(private_key, string_to_sign)
    else:
        # SigV4: scope is date/region/service/aws4_request
        region = scope_parts[1] if len(scope_parts) >= 3 else ""
        string_to_sign = build_sigv4_string_to_sign(
            timestamp, parsed_auth.scope, creq
        )
        date = parsed_auth.date
        service = scope_parts[2] if len(scope_parts) >= 3 else ""
        signing_key = derive_sigv4_signing_key(
            real_secret_key, date, region, service
        )
        signature = sigv4_sign(signing_key, string_to_sign)

    auth_header = (
        f"{parsed_auth.algorithm} "
        f"Credential={real_key_id}/{parsed_auth.scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    creq_hash = hashlib.sha256(creq.encode("utf-8")).hexdigest()
    return ResignResult(
        auth_header,
        region,
        is_chunked=is_chunked,
        canonical_request_hash=creq_hash,
        signed_headers=signed_headers,
        canonical_request=creq,
    )


# ---------------------------------------------------------------------------
# ChunkedResigner state machine
# ---------------------------------------------------------------------------


class ChunkedResigner:
    """State machine for re-signing aws-chunked request bodies.

    Processes streaming body data and re-signs each chunk's signature.
    """

    def __init__(
        self,
        *,
        signing_key: bytes | None,
        ecdsa_key: EllipticCurvePrivateKey | None,
        seed_signature: str,
        timestamp: str,
        scope: str,
        is_sigv4a: bool,
        has_trailer: bool,
    ) -> None:
        """Initialize the resigner.

        Either signing_key (SigV4) or ecdsa_key (SigV4A) must be provided.

        Args:
            signing_key: Derived SigV4 HMAC signing key.
            ecdsa_key: ECDSA P-256 private key for SigV4A.
            seed_signature: Newly computed seed (Authorization) signature.
            timestamp: ISO8601 timestamp from x-amz-date.
            scope: Credential scope from Authorization header.
            is_sigv4a: Whether this is SigV4A.
            has_trailer: Whether to expect trailing header signatures.
        """
        self._signing_key = signing_key
        self._ecdsa_key = ecdsa_key
        self._current_sig = seed_signature
        self._timestamp = timestamp
        self._scope = scope
        self._is_sigv4a = is_sigv4a
        self._has_trailer = has_trailer
        self._buffer = b""
        self._done = False

    def _sign(self, string_to_sign: str) -> str:
        """Sign a string using the appropriate algorithm."""
        if self._is_sigv4a:
            return sigv4a_sign(self._ecdsa_key, string_to_sign)
        assert self._signing_key is not None
        return sigv4_sign(self._signing_key, string_to_sign)

    def _chunk_string_to_sign(self, chunk_data: bytes) -> str:
        """Build string-to-sign for a data/terminal chunk."""
        if self._is_sigv4a:
            return sigv4a_chunk_string_to_sign(
                self._timestamp, self._scope, self._current_sig, chunk_data
            )
        return sigv4_chunk_string_to_sign(
            self._timestamp, self._scope, self._current_sig, chunk_data
        )

    def _trailer_string_to_sign(self, trailing_headers: bytes) -> str:
        """Build string-to-sign for trailing headers."""
        if self._is_sigv4a:
            return sigv4a_trailer_string_to_sign(
                self._timestamp,
                self._scope,
                self._current_sig,
                trailing_headers,
            )
        return sigv4_trailer_string_to_sign(
            self._timestamp,
            self._scope,
            self._current_sig,
            trailing_headers,
        )

    def process(self, data: bytes) -> bytes:
        """Process incoming body data and return re-signed output.

        State machine transitions::

            BUFFERING ──chunk header──> RE-SIGN CHUNK ──> BUFFERING
                │                              │
                │                         (size == 0)
                │                              │
                │                              v
                │                     TERMINAL CHUNK
                │                       ┌──────┴──────┐
                │                 has_trailer     no trailer
                │                       │             │
                │                       v             v
                ├─(not a chunk)──> TRAILER/DONE     DONE
                │
                v
              DONE ──(any data)──> passthrough

        Args:
            data: Raw bytes from the request body stream.

        Returns:
            Re-signed bytes to forward upstream.
        """
        if self._done:
            return data

        self._buffer += data
        output = b""

        while True:
            # Try to find a chunk header
            header_end = self._buffer.find(b"\r\n")
            if header_end == -1:
                break  # Need more data

            # Parse chunk header: {hex};chunk-signature={sig}
            m = _CHUNK_HEADER_RE.match(self._buffer)
            if not m:
                # Not a chunk header — could be trailing headers or
                # trailer signature. Handle as pass-through.
                if self._has_trailer:
                    output += self._process_trailer()
                else:
                    output += self._buffer
                    self._buffer = b""
                    self._done = True
                break

            hex_size = m.group("hex_size")
            chunk_size = int(hex_size, 16)
            header_len = header_end + 2  # Include \r\n

            if chunk_size == 0:
                # Terminal chunk
                string_to_sign = self._chunk_string_to_sign(b"")
                new_sig = self._sign(string_to_sign)
                self._current_sig = new_sig

                terminal = (
                    hex_size + b";chunk-signature=" + new_sig.encode() + b"\r\n"
                )
                output += terminal
                self._buffer = self._buffer[header_len:]

                # After terminal chunk, handle trailer if present
                if self._has_trailer and self._buffer:
                    output += self._process_trailer()
                elif not self._has_trailer:
                    # Pass through any remaining data (final \r\n)
                    output += self._buffer
                    self._buffer = b""
                    self._done = True
                break

            # Need header + chunk_data + \r\n
            total_needed = header_len + chunk_size + 2
            if len(self._buffer) < total_needed:
                break  # Need more data

            chunk_data = self._buffer[header_len : header_len + chunk_size]

            # Re-sign this chunk
            string_to_sign = self._chunk_string_to_sign(chunk_data)
            new_sig = self._sign(string_to_sign)
            self._current_sig = new_sig

            # Build re-signed chunk
            output += (
                hex_size + b";chunk-signature=" + new_sig.encode() + b"\r\n"
            )
            output += chunk_data + b"\r\n"

            # Advance buffer past this chunk
            self._buffer = self._buffer[total_needed:]

        return output

    def _process_trailer(self) -> bytes:
        """Process trailing headers and their signature.

        Returns re-signed trailer data. Must be called when the buffer
        contains trailing header data after the terminal chunk.
        """
        output = b""
        # Find the trailer signature line
        m = _TRAILER_SIG_RE.search(self._buffer)
        if m:
            # Everything before the trailer sig line is trailing headers
            sig_start = m.start()
            # The trailing headers are everything from start to the
            # x-amz-trailer-signature line
            trailing_data = self._buffer[:sig_start]

            # Remove the trailing \r\n before the signature line
            trailing_headers = trailing_data.rstrip(b"\r\n")

            # Re-sign the trailer
            string_to_sign = self._trailer_string_to_sign(trailing_headers)
            new_sig = self._sign(string_to_sign)
            self._current_sig = new_sig

            # Reconstruct: trailing headers + new trailer signature
            output += trailing_data
            output += b"x-amz-trailer-signature:" + new_sig.encode()

            # Pass through anything after the original signature
            after_sig = self._buffer[m.end() :]
            output += after_sig
        else:
            # No trailer signature found yet — might need more data.
            # For now, pass through buffer.
            output += self._buffer

        self._buffer = b""
        self._done = True
        return output


# ---------------------------------------------------------------------------
# Presigned URL helpers
# ---------------------------------------------------------------------------


def parse_presigned_url_params(
    query: str,
) -> dict[str, str] | None:
    """Parse presigned URL query parameters.

    Args:
        query: Query string (without leading ?).

    Returns:
        Dict of relevant X-Amz-* parameters if this is a presigned URL,
        None otherwise.
    """
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    if "X-Amz-Credential" not in params:
        return None
    return params


def resign_presigned_url(
    *,
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    params: dict[str, str],
    real_key_id: str,
    real_secret_key: str,
) -> str:
    """Re-sign a presigned URL and return the new query string.

    Args:
        method: HTTP method.
        path: Request path.
        query: Original query string.
        headers: Request headers.
        params: Parsed X-Amz-* query parameters.
        real_key_id: Real AWS access key ID.
        real_secret_key: Real AWS secret access key.

    Returns:
        New query string with updated signature and credentials.
    """
    credential = params["X-Amz-Credential"]
    key_id, scope = credential.split("/", 1)
    algorithm = params.get("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
    signed_headers = params.get("X-Amz-SignedHeaders", "host")
    timestamp = params.get("X-Amz-Date", "")

    scope_parts = scope.split("/")
    is_s3 = scope_parts[-2] == "s3" if len(scope_parts) >= 2 else False

    # Build canonical request (exclude X-Amz-Signature from query)
    creq = build_canonical_request(
        method=method,
        path=path,
        query=query,
        headers=headers,
        signed_headers=signed_headers,
        payload_hash="UNSIGNED-PAYLOAD",
        is_s3=is_s3,
        exclude_signature=True,
    )

    is_sigv4a = algorithm == "AWS4-ECDSA-P256-SHA256"

    if is_sigv4a:
        string_to_sign = build_sigv4a_string_to_sign(timestamp, scope, creq)
        private_key = derive_sigv4a_key(real_secret_key, real_key_id)
        new_sig = sigv4a_sign(private_key, string_to_sign)
    else:
        string_to_sign = build_sigv4_string_to_sign(timestamp, scope, creq)
        date = scope_parts[0]
        region = scope_parts[1] if len(scope_parts) >= 3 else ""
        service = scope_parts[2] if len(scope_parts) >= 3 else ""
        signing_key = derive_sigv4_signing_key(
            real_secret_key, date, region, service
        )
        new_sig = sigv4_sign(signing_key, string_to_sign)

    # Replace credential and signature in query parameters
    new_params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    new_params["X-Amz-Credential"] = f"{real_key_id}/{scope}"
    new_params["X-Amz-Signature"] = new_sig

    return urllib.parse.urlencode(new_params, quote_via=urllib.parse.quote)


# ---------------------------------------------------------------------------
# Clock skew detection
# ---------------------------------------------------------------------------


def check_clock_skew(amz_date: str) -> tuple[bool, int]:
    """Check if x-amz-date differs significantly from system time.

    Args:
        amz_date: ISO8601 timestamp from x-amz-date header.

    Returns:
        Tuple of (is_skewed, drift_minutes). is_skewed is True if
        drift exceeds 5 minutes.
    """
    try:
        request_time = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(
            tzinfo=UTC
        )
        now = datetime.now(UTC)
        drift = abs((now - request_time).total_seconds())
        drift_minutes = int(drift / 60)
        return drift_minutes > 5, drift_minutes
    except (ValueError, TypeError):
        return False, 0
