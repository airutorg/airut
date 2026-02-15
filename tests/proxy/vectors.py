# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared test vectors for AWS SigV4/SigV4A re-signing tests.

Centralizes credential constants and Authorization header strings
used across ``test_aws_signing.py`` and ``test_proxy_filter.py``.
"""

from typing import Any

from lib._bundled.proxy.aws_signing import SIGNING_TYPE_AWS_SIGV4


# Real credential pair used in AWS documentation examples
REAL_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
REAL_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

# Surrogate access key ID (injected into the container)
SURROGATE_ACCESS_KEY_ID = "AKIA_SURROGATE"

# A valid SigV4 Authorization header for testing (signature must be hex)
SIGV4_AUTH = (
    "AWS4-HMAC-SHA256 "
    f"Credential={SURROGATE_ACCESS_KEY_ID}/20260101/us-east-1/s3/aws4_request, "
    "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
    "Signature=aa00bb11cc22dd33ee44ff5500661177"
)

# A valid SigV4A Authorization header for testing (signature must be hex)
SIGV4A_AUTH = (
    "AWS4-ECDSA-P256-SHA256 "
    f"Credential={SURROGATE_ACCESS_KEY_ID}/20260101/s3/aws4_request, "
    "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
    "Signature=aa00bb11cc22dd33ee44ff5500661177"
)

# SigV4A Authorization header for Bedrock (service=bedrock-runtime)
SIGV4A_BEDROCK_AUTH = (
    "AWS4-ECDSA-P256-SHA256 "
    f"Credential={SURROGATE_ACCESS_KEY_ID}"
    "/20260101/bedrock/aws4_request, "
    "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
    "Signature=aa00bb11cc22dd33ee44ff5500661177"
)

# Signing credential replacement map entry
SIGNING_REPLACEMENT: dict[str, Any] = {
    "type": SIGNING_TYPE_AWS_SIGV4,
    "access_key_id": REAL_ACCESS_KEY_ID,
    "secret_access_key": REAL_SECRET_ACCESS_KEY,
    "session_token": "real_session_token_value",
    "surrogate_session_token": "surr_session_token",
    "scopes": ["*.amazonaws.com", "*.r2.cloudflarestorage.com"],
}
