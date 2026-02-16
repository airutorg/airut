# AWS SigV4/SigV4A Re-signing (Credential Masking)

Extends masked secrets with support for AWS-style request signing. Unlike bearer
tokens (which appear verbatim in headers), AWS credentials are used to compute
HMAC or ECDSA signatures over the request — the secret key never appears on the
wire. The proxy must **re-sign** outbound requests with the real credentials
rather than performing simple string replacement.

This is designed to work with any S3-compatible API (AWS, Cloudflare R2, MinIO,
etc.), not just `*.amazonaws.com`.

For general masked secrets (bearer tokens, API keys), see
[masked-secrets.md](masked-secrets.md).

## Config Schema

### Server Config

AWS signing credentials are declared in a `signing_credentials` block alongside
`masked_secrets`. Each field uses a `name`/`value` structure — `name` declares
the secret name visible to repo config (via `!secret`), and `value` provides the
real credential:

```yaml
repos:
  my-project:
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes: ["api.github.com"]
        headers: ["Authorization"]

    signing_credentials:
      AWS_PROD:
        type: aws-sigv4                        # signing protocol
        access_key_id:
          name: AWS_ACCESS_KEY_ID              # secret name for repo config
          value: !env PROD_AWS_ACCESS_KEY_ID
        secret_access_key:
          name: AWS_SECRET_ACCESS_KEY
          value: !env PROD_AWS_SECRET_ACCESS_KEY
        session_token:                         # optional (STS temp credentials)
          name: AWS_SESSION_TOKEN
          value: !env AWS_SESSION_TOKEN
        scopes:
          - "*.amazonaws.com"
          - "*.r2.cloudflarestorage.com"

      R2_STORAGE:
        type: aws-sigv4
        access_key_id:
          name: R2_ACCESS_KEY_ID
          value: !env R2_ACCESS_KEY_ID
        secret_access_key:
          name: R2_SECRET_ACCESS_KEY
          value: !env R2_SECRET_ACCESS_KEY
        scopes:
          - "*.r2.cloudflarestorage.com"
```

Each `name` registers a secret into the server's secrets pool. The repo config
references these names with plain `!secret` — exactly like masked secrets or
plain secrets. The repo author doesn't know (or care) that signing credentials
are handled specially.

### Fields

| Field                                                | Type        | Required | Description                                |
| ---------------------------------------------------- | ----------- | -------- | ------------------------------------------ |
| `signing_credentials`                                | mapping     | No       | Named signing credential sets              |
| `signing_credentials.<name>.type`                    | string      | Yes      | Signing protocol (`aws-sigv4`)             |
| `signing_credentials.<name>.access_key_id.name`      | string      | Yes      | Secret name for repo config                |
| `signing_credentials.<name>.access_key_id.value`     | string/!env | Yes      | AWS access key ID                          |
| `signing_credentials.<name>.secret_access_key.name`  | string      | Yes      | Secret name for repo config                |
| `signing_credentials.<name>.secret_access_key.value` | string/!env | Yes      | AWS secret access key                      |
| `signing_credentials.<name>.session_token.name`      | string      | Yes      | Secret name for repo config                |
| `signing_credentials.<name>.session_token.value`     | string/!env | No       | STS session token (`X-Amz-Security-Token`) |
| `signing_credentials.<name>.scopes`                  | list[str]   | Yes      | Fnmatch patterns for allowed hosts         |

### Repo Config

Repo config references signing credentials with `!secret`, exactly like any
other secret. The repo author doesn't need to know about signing credentials —
the server decides whether masking and re-signing is used.

```yaml
container_env:
  AWS_ACCESS_KEY_ID: !secret AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY: !secret AWS_SECRET_ACCESS_KEY
  AWS_SESSION_TOKEN: !secret? AWS_SESSION_TOKEN
```

This is identical to referencing plain secrets. If the server later decides to
switch from signing credentials to plain secrets (for debugging, fallback,
etc.), only the server config changes — the repo config is untouched.

### Transparent upgrade path

The server admin can migrate between plain secrets and signing credentials
without any repo config changes:

**Plain secrets (no masking):**

```yaml
secrets:
  AWS_ACCESS_KEY_ID: !env AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY: !env AWS_SECRET_ACCESS_KEY
  AWS_SESSION_TOKEN: !env AWS_SESSION_TOKEN
```

**Signing credentials (proxy re-signs):**

```yaml
signing_credentials:
  AWS_PROD:
    type: aws-sigv4
    access_key_id:
      name: AWS_ACCESS_KEY_ID
      value: !env AWS_ACCESS_KEY_ID
    secret_access_key:
      name: AWS_SECRET_ACCESS_KEY
      value: !env AWS_SECRET_ACCESS_KEY
    session_token:
      name: AWS_SESSION_TOKEN
      value: !env AWS_SESSION_TOKEN
    scopes: ["*.amazonaws.com"]
```

In both cases, the repo config uses `!secret AWS_ACCESS_KEY_ID`. The difference
is only in whether the container receives real values or surrogates, and whether
the proxy performs re-signing.

## Surrogate Generation

Each signing credential gets **two surrogates** (key ID + secret key) and
optionally a third (session token):

| Component         | Prefix        | Surrogate preserves                       |
| ----------------- | ------------- | ----------------------------------------- |
| Access key ID     | `AKIA`/`ASIA` | Length (20 chars), prefix                 |
| Secret access key | _(none)_      | Length (40 chars), charset (base64-like)  |
| Session token     | _(none)_      | Fixed 512 chars (see note below), charset |

**Session token length**: Real STS session tokens vary in length (typically
400–1200+ characters) and change on every credential rotation. The surrogate
must be generated at a **fixed length of 512 characters** regardless of the real
token's length. This avoids leaking information about the real token and ensures
the surrogate is a plausible size. Because the proxy replaces the entire
`X-Amz-Security-Token` header value (not a substring), a length mismatch between
surrogate and real token is not a problem — the re-signed request will carry the
real token at its actual length.

The access key ID surrogate is the **detection key** — the proxy identifies
requests needing re-signing by matching the surrogate key ID in the
`Credential=` field of the `Authorization` header or the `X-Amz-Credential`
query parameter.

### Prefix Handling

Access key IDs have well-known prefixes:

- `AKIA` — long-term credentials
- `ASIA` — temporary credentials (STS)

The surrogate preserves the prefix. These are added to `_TOKEN_PREFIXES` in
`generate_surrogate()`.

## Replacement Map Extension

The replacement map gains a new entry type for signing credentials:

```python
@dataclass(frozen=True)
class SigningCredentialEntry:
    """Replacement map entry for AWS-style signing credentials."""

    access_key_id: str  # real access key ID
    secret_access_key: str  # real secret access key
    session_token: str | None  # real session token (optional)
    scopes: tuple[str, ...]  # fnmatch host patterns
```

### JSON Format (proxy mount)

```json
{
  "AKIA_surrogate_id": {
    "type": "aws-sigv4",
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "session_token": null,
    "scopes": ["*.amazonaws.com", "*.r2.cloudflarestorage.com"]
  },
  "ghp_surrogate123...": {
    "value": "ghp_realtoken...",
    "scopes": ["api.github.com"],
    "headers": ["Authorization"]
  }
}
```

The `type` field distinguishes signing credentials from regular token
replacements (which have no `type` field). This allows the proxy to handle both
in a single replacement map.

## Proxy Re-signing

### Detection

The proxy detects AWS-signed requests by checking the `Authorization` header:

1. Header starts with `AWS4-HMAC-SHA256` (SigV4) or `AWS4-ECDSA-P256-SHA256`
   (SigV4A)
2. Parse `Credential=<key-id>/<scope>` from the header
3. Look up `<key-id>` in the replacement map
4. Verify host matches the credential's scopes

If any condition fails, fall through to regular token replacement (or no-op).

### SigV4 Re-signing

When a SigV4 request is detected:

1. **Parse the existing Authorization header** to extract:

   - Access key ID (surrogate)
   - Credential scope: `{date}/{region}/{service}/aws4_request`
   - Signed headers list
   - (The existing signature is discarded)

2. **Reconstruct the canonical request** from the wire request:

   ```
   {METHOD}\n
   {CanonicalURI}\n
   {CanonicalQueryString}\n
   {CanonicalHeaders}\n
   {SignedHeaders}\n
   {HashedPayload}
   ```

   - **Method**: From `flow.request.method`
   - **CanonicalURI**: For non-S3 services, double-URI-encode the path (so `%3A`
     becomes `%253A`). For S3, decode then single-encode (so `%3A` stays `%3A`).
     Empty path becomes `/`.
   - **CanonicalQueryString**: URI-encode parameter names and values, sort by
     encoded name, join with `&`. Exclude `X-Amz-Signature` if present (for
     presigned URL re-signing).
   - **CanonicalHeaders**: For each header in SignedHeaders, emit
     `lowercase(name):trimmed(value)\n`. Headers must be sorted by lowercase
     name.
   - **SignedHeaders**: Semicolon-separated lowercase header names (from the
     parsed Authorization header). The proxy normalizes HTTP/2 pseudo-headers:
     `:authority` is replaced with `host` and the list is re-sorted. This is
     necessary because AWS SDKs using HTTP/2 sign with `:authority`, but
     mitmproxy converts it to a `Host` header — without normalization, the
     canonical request would reference a header that doesn't exist.
   - **HashedPayload**: Use the `x-amz-content-sha256` header value from the
     request. This is either a hex-encoded SHA-256 hash, `UNSIGNED-PAYLOAD`,
     `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, or
     `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`.

3. **Build the string to sign**:

   ```
   AWS4-HMAC-SHA256\n
   {ISO8601 timestamp from x-amz-date}\n
   {date}/{region}/{service}/aws4_request\n
   {SHA256(CanonicalRequest)}
   ```

4. **Derive the signing key** using the real secret access key:

   ```
   kDate    = HMAC-SHA256("AWS4" + real_secret, date)
   kRegion  = HMAC-SHA256(kDate, region)
   kService = HMAC-SHA256(kRegion, service)
   kSigning = HMAC-SHA256(kService, "aws4_request")
   ```

5. **Compute the signature**: `HMAC-SHA256(kSigning, StringToSign)`

6. **Replace the Authorization header**:

   ```
   AWS4-HMAC-SHA256 Credential={real_key_id}/{scope},
       SignedHeaders={signed_headers}, Signature={new_signature}
   ```

7. **Replace the session token** (if present): Swap the surrogate session token
   for the real one in the `X-Amz-Security-Token` header.

### SigV4A Re-signing

SigV4A uses ECDSA (P-256) instead of HMAC. The proxy must:

1. **Parse the Authorization header** — same structure, but algorithm is
   `AWS4-ECDSA-P256-SHA256` and credential scope omits region
   (`{date}/{service}/aws4_request`).

2. **Derive the ECDSA key pair** from the real secret access key:

   ```
   input_key = "AWS4A" + real_secret_access_key
   counter = 0x01
   loop:
       kdf_output = HMAC-SHA256(input_key,
           "AWS4-ECDSA-P256-SHA256" || 0x00 || access_key_id || counter)
       c = int(kdf_output)
       if c <= n - 2:    # n = P-256 curve order
           private_key = c + 1
           break
       counter += 1
   ```

3. **Build the string to sign** — similar to SigV4 but includes the region set
   from the `X-Amz-Region-Set` header (typically `*`):

   ```
   AWS4-ECDSA-P256-SHA256\n
   {timestamp}\n
   {date}/{service}/aws4_request\n
   {SHA256(CanonicalRequest)}
   ```

4. **Sign with ECDSA**: Sign the SHA-256 hash of the string-to-sign using the
   derived private key on the P-256 curve.

5. **Replace the Authorization header** with the new credential and signature.

### Chunked Transfer Re-signing

S3 supports `aws-chunked` transfer encoding where each chunk carries its own
signature. This is indicated by
`x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (or the `-TRAILER`
variant).

#### Detection

The proxy detects chunked signing by the `x-amz-content-sha256` header value:

| Header value                                       | Mode                      |
| -------------------------------------------------- | ------------------------- |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`               | Chunked SigV4             |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`       | Chunked SigV4 + trailers  |
| `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD`         | Chunked SigV4A            |
| `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER` | Chunked SigV4A + trailers |

#### Re-signing Process

1. **Re-sign the seed signature** (the `Authorization` header) using the
   standard SigV4/SigV4A process described above.

2. **Re-sign each chunk** in the request body. Each chunk has the format:

   ```
   {hex-size};chunk-signature={signature}\r\n
   {chunk-data}\r\n
   ```

   For each chunk, compute a new signature:

   ```
   AWS4-HMAC-SHA256-PAYLOAD\n
   {timestamp}\n
   {credential-scope}\n
   {previous-signature}\n
   {SHA256("")}\n
   {SHA256(chunk-data)}
   ```

   Where `{previous-signature}` is the newly computed seed signature (for the
   first chunk) or the newly computed previous chunk signature.

3. **Replace each chunk's signature** in the body before forwarding.

4. **Terminal chunk** (size 0): Re-sign using the same process with empty chunk
   data.

5. **Trailing header signature** (if `-TRAILER` variant): After the terminal
   chunk, the trailing headers are followed by a trailer signature:

   ```
   AWS4-HMAC-SHA256-TRAILER\n
   {timestamp}\n
   {credential-scope}\n
   {previous-signature}\n
   {SHA256(trailing-headers)}
   ```

   Re-sign this with the real credentials and replace in the body.

#### Streaming Re-signing

Chunked uploads can be multi-GB. Buffering the full body would OOM the proxy
container. The proxy **must** use mitmproxy's streaming API to re-sign chunks in
constant memory.

**Hook structure:**

1. **`requestheaders(flow)`** — fires after headers arrive, before body. The
   proxy detects AWS signing (Authorization header + streaming content-sha256),
   re-signs the seed signature in the Authorization header, then sets
   `flow.request.stream = True` to enable streaming. Stores a `ChunkedResigner`
   state machine in `flow.metadata`.

2. **`request_data(flow)`** — fires for each TCP segment of the body. The proxy
   feeds raw bytes into the `ChunkedResigner`, which parses AWS chunk
   boundaries, re-signs complete chunks, and yields rewritten bytes to forward
   upstream.

**`ChunkedResigner` state machine:**

```
Initialize:
    signing_key     = derived from real secret (SigV4) or ECDSA key (SigV4A)
    current_sig     = newly computed seed signature
    partial_buffer  = b""
    timestamp       = from x-amz-date header
    credential_scope = from Authorization header

process(data: bytes) -> bytes:
    partial_buffer += data
    output = b""

    loop:
        Try to read chunk header: "{hex-size};chunk-signature={sig}\r\n"
        If incomplete header: break (wait for more data)

        chunk_size = parse hex size
        If chunk_size == 0:
            Re-sign terminal chunk (empty data)
            output += rewritten terminal chunk
            Handle trailing headers/signature if TRAILER mode
            break

        If partial_buffer has < chunk_size + 2 bytes after header:
            break (wait for more data — put header back)

        Extract chunk_data (chunk_size bytes) + trailing \r\n
        new_sig = sign(signing_key, current_sig, chunk_data, ...)
        output += "{hex-size};chunk-signature={new_sig}\r\n"
        output += chunk_data + "\r\n"
        current_sig = new_sig
        Remove processed bytes from partial_buffer

    return output
```

**Memory constraint**: O(max chunk size), typically 64 KiB–1 MiB per AWS SDK
defaults. The proxy never buffers more than one chunk plus a partial header.

**Non-chunked requests** (standard `x-amz-content-sha256` with a hex hash or
`UNSIGNED-PAYLOAD`) do not use streaming — they are re-signed entirely in the
`requestheaders` hook since only headers need modification.

### Deferred Re-signing (Non-S3 Services)

For non-S3 services where the SDK doesn't send `x-amz-content-sha256`, the proxy
cannot compute the correct payload hash in `requestheaders()` because the body
hasn't arrived yet. The re-signing is split across two hooks:

1. **`requestheaders()`** — detects the request needs re-signing, verifies
   credentials and scope, prepares the signing context, but does **not** compute
   the signature. Stores the context in `flow.metadata["aws_deferred_resign"]`.

2. **`request()`** — fires after the full body is available. Computes
   `SHA256(body)`, injects it into the signing context as the payload hash,
   performs the actual re-signing, and replaces the Authorization header.

This only applies when `x-amz-content-sha256` is absent. S3 requests (which
always include the header) and streaming uploads (which use special
`STREAMING-*` values) are handled entirely in `requestheaders()`.

### Presigned URL Re-signing

Presigned URLs carry authentication in query parameters instead of headers:

| Parameter              | Content                                        |
| ---------------------- | ---------------------------------------------- |
| `X-Amz-Algorithm`      | `AWS4-HMAC-SHA256` or `AWS4-ECDSA-P256-SHA256` |
| `X-Amz-Credential`     | `{key-id}/{scope}`                             |
| `X-Amz-Date`           | ISO8601 timestamp                              |
| `X-Amz-Expires`        | Validity duration in seconds                   |
| `X-Amz-SignedHeaders`  | Semicolon-separated signed header names        |
| `X-Amz-Signature`      | Hex-encoded signature                          |
| `X-Amz-Security-Token` | Session token (if using STS)                   |

#### Detection

The proxy checks query parameters when no `Authorization` header is present:

1. `X-Amz-Credential` contains a surrogate key ID
2. Host matches the credential's scopes

#### Re-signing Process

1. Parse `X-Amz-Credential` to extract surrogate key ID and scope
2. Reconstruct the canonical request (same as header-based, but
   `X-Amz-Signature` is excluded from the canonical query string)
3. Compute the new signature with the real credentials
4. Replace `X-Amz-Credential` (surrogate key ID → real key ID)
5. Replace `X-Amz-Signature` with the new signature
6. Replace `X-Amz-Security-Token` if present

This requires modifying query parameters, not just headers. The proxy must
reconstruct the URL with updated parameters.

## Canonical Request Construction

The canonical request is the most error-prone component. The proxy must exactly
match the canonicalization the SDK performed inside the container.

### URI Encoding Rules

AWS uses a specific URI encoding (RFC 3986):

- Unreserved characters are not encoded: `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`
- All other characters are percent-encoded as `%XX` (uppercase hex)
- Forward slashes (`/`) in the path are **not** encoded
- Spaces are encoded as `%20` (not `+`)

### Path Canonicalization

SigV4 has a per-service `doubleURIEncode` setting that controls how the
canonical URI is computed from the HTTP path:

- **Non-S3 services** (default): **double URI encode**. URI-encode the path
  as-is (preserving existing percent-encoding), so `%` in SDK-encoded escapes
  becomes `%25`. Example: SDK sends `v1%3A0` → canonical URI has `v1%253A0`.
- **S3** (`service=s3` in credential scope): **single URI encode**. Decode any
  existing percent-encoding first, then URI-encode once. `%3A` stays `%3A`. S3
  also does **not** normalize paths (double slashes and `.` / `..` are
  preserved).

The proxy detects S3 requests by checking the service component in the
credential scope (`scope_parts[-2] == "s3"`).

### Query String Canonicalization

1. URI-encode each parameter name and value
2. Sort parameters by encoded name (byte-order)
3. If two parameters share a name, sort by encoded value
4. Join with `&`
5. Exclude `X-Amz-Signature` (for presigned URLs)

### Header Canonicalization

1. Convert header names to lowercase
2. Trim leading/trailing whitespace from values
3. Collapse sequential spaces in values to a single space
4. Sort headers by lowercase name
5. Format: `{lowercase-name}:{trimmed-value}\n` for each

### Payload Hash

**S3 and services that send `x-amz-content-sha256`:** The proxy reads the header
value and uses it as-is in the canonical request. The proxy does **not** hash
the body itself — it trusts the SDK's declared payload hash. This is safe
because AWS verifies the payload hash server-side, and for `UNSIGNED-PAYLOAD`
there is nothing to verify.

**Non-S3 services (Bedrock, DynamoDB, etc.):** botocore's `SigV4Auth` does
**not** send the `x-amz-content-sha256` header. Instead, it computes
`SHA256(body)` internally and uses it in the canonical request. The proxy must
do the same — compute `SHA256(body)` when the header is absent. Because the
request body is not yet available in the `requestheaders` hook, the proxy
**defers** re-signing to the `request` hook where the full body is available
(see Deferred Re-signing below).

## S3-Compatible Services

The re-signing mechanism is not AWS-specific. Any S3-compatible service that
accepts SigV4 signatures works, provided:

1. The service's hostname is included in the credential's `scopes`
2. The service accepts standard SigV4 (which all S3-compatible services do)

### Cloudflare R2

R2 uses SigV4 with region `auto`. The credential scope in requests to R2 looks
like `{date}/auto/s3/aws4_request`. The proxy handles this transparently — it
reads the scope from the request and re-signs with the same scope.

R2 does **not** support `aws-chunked` transfer encoding. AWS SDKs configured for
R2 typically disable payload signing (using `UNSIGNED-PAYLOAD`). The proxy
handles this case without chunked re-signing.

### MinIO, Backblaze B2, DigitalOcean Spaces

All accept standard SigV4. Configure appropriate `scopes` patterns.

## Data Flow

```
_parse_repo_server_config()
    │
    ├─ Parse signing_credentials block
    ├─ For each credential:
    │   ├─ Register name→value fields into secrets pool as SigningSecrets
    │   └─ Store SigningCredential with real values and scopes
    │
    └─ Returns RepoServerConfig
           │
           ▼
RepoConfig.from_mirror(server_secrets, masked_secrets, signing_credentials)
    │
    ├─ Parse .airut/airut.yaml
    ├─ Resolve !secret references (all types handled uniformly)
    ├─ For signing credential secrets:
    │   ├─ Generate surrogates for key ID, secret key, session token
    │   ├─ Add SigningCredentialEntry to replacement map (keyed by surrogate key ID)
    │   └─ Inject surrogates into container_env
    │
    └─ Returns (RepoConfig, ReplacementMap)
           │
           ▼
ProxyManager.start_task_proxy(replacement_map)
    │
    ├─ Write replacement_map to temp JSON (includes both token and signing entries)
    ├─ Mount at /replacements.json
    │
    └─ Proxy container starts
           │
           ▼
proxy-filter.py requestheaders()          [fires before body]
    │
    ├─ Allowlist check (existing)
    ├─ Check Authorization header for AWS4-HMAC-SHA256 / AWS4-ECDSA-P256-SHA256
    │   ├─ Parse Credential= to get key ID
    │   ├─ Look up key ID in replacement map
    │   ├─ If found and type=aws-sigv4:
    │   │   ├─ If x-amz-content-sha256 header present (S3, streaming):
    │   │   │   ├─ Reconstruct canonical request (from headers)
    │   │   │   ├─ Re-sign seed signature with real credentials
    │   │   │   ├─ Replace Authorization header
    │   │   │   ├─ Replace X-Amz-Security-Token if present
    │   │   │   ├─ If chunked (STREAMING-* content-sha256):
    │   │   │   │   ├─ Set flow.request.stream = True
    │   │   │   │   └─ Store ChunkedResigner in flow.metadata
    │   │   │   └─ If not chunked: done (no body modification needed)
    │   │   └─ If x-amz-content-sha256 absent (Bedrock, DynamoDB, etc.):
    │   │       └─ Store signing context in flow.metadata (deferred)
    │   └─ If not found: fall through to token replacement
    ├─ Check query params for X-Amz-Credential (presigned URLs)
    │   └─ Same re-signing flow, operating on query parameters
    ├─ Token replacement (existing, for non-AWS secrets)
    │
    └─ Headers forwarded; body follows
           │
           ▼
proxy-filter.py request()                [fires after full body received]
    │
    ├─ If deferred re-signing context in flow.metadata:
    │   ├─ Compute SHA256(body) as payload hash
    │   ├─ Complete re-signing with body hash
    │   ├─ Replace Authorization header
    │   └─ Replace X-Amz-Security-Token if present
    │
    └─ Else: token replacement (existing, for non-AWS secrets)
           │
           ▼
proxy-filter.py request_data()            [fires per TCP segment, only if streaming]
    │
    ├─ Feed bytes into ChunkedResigner
    ├─ Parse complete AWS chunks from buffer
    ├─ Re-sign each chunk, update signature chain
    ├─ Yield rewritten bytes upstream
    │
    └─ Repeat until terminal chunk + optional trailer
```

## Log Redaction

| Value              | Registered with SecretFilter | Visible in logs |
| ------------------ | ---------------------------- | --------------- |
| Real key ID        | Yes                          | No (redacted)   |
| Real secret key    | Yes                          | No (redacted)   |
| Real session token | Yes                          | No (redacted)   |
| Surrogate key ID   | No                           | Yes (debugging) |
| Surrogate secret   | No                           | Yes (debugging) |

The `[masked: N]` suffix in network logs applies to re-signed requests as well
(counts as 1 per re-signed request, regardless of how many fields were
replaced).

## Dependencies

### Proxy Container

The re-signing logic runs in `airut/_bundled/proxy/proxy_filter.py` inside the
proxy container. New dependencies:

- **`hmac` + `hashlib`** (stdlib) — SigV4 signing key derivation and signature
  computation. Already available.
- **`cryptography`** (PyPI) — ECDSA P-256 operations for SigV4A. Needs to be
  added to the proxy container image. The `ecdsa` pure-Python library is an
  alternative but `cryptography` is preferred for performance and correctness.
- **`urllib.parse`** (stdlib) — URL encoding for canonical request construction.
  Already available.

The proxy Dockerfile (`airut/_bundled/proxy/proxy.dockerfile`) needs
`cryptography` added to its pip install.

### No SDK Dependency

The proxy does **not** use `boto3` or `botocore`. The signing logic is
implemented directly using stdlib + `cryptography`. This keeps the proxy image
slim and avoids pulling in the full AWS SDK.

## Security Properties

| Property                 | Mechanism                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------ |
| Credential isolation     | Container receives surrogates; real keys only in proxy                               |
| Scope enforcement        | Re-signing only for requests to scoped hosts                                         |
| Exfiltration prevention  | Surrogate key ID is not valid; signatures computed with surrogate secret are invalid |
| Signature integrity      | Proxy re-signs from scratch; does not relay invalid signatures                       |
| Fail-secure              | If re-signing fails, request goes out with surrogate credentials (which are invalid) |
| Session token protection | Surrogate session token swapped only on scoped requests                              |

## Diagnostics

### Region Logging

The proxy logs the **region used for signing** (extracted from the credential
scope) on every re-signed request. This is included in the network log line:

```
allowed PUT https://my-bucket.s3.amazonaws.com/key -> 200 [masked: 1] [region: us-east-1]
```

When the upstream returns a `400` or `403` with an
`AuthorizationHeaderMalformed` or `SignatureDoesNotMatch` error, the region in
the log helps diagnose region mismatches — e.g., the SDK signed for `us-east-1`
but the bucket is in `eu-west-1`. The proxy cannot detect this mismatch itself
(it re-signs with whatever region the SDK chose), but the log makes debugging
straightforward.

### Clock Skew Detection

AWS rejects requests where the `x-amz-date` timestamp differs from server time
by more than 15 minutes. When the proxy detects that `x-amz-date` differs from
its own system clock by more than 5 minutes, it logs a warning:

```
WARNING: Container clock skew detected: x-amz-date=20260210T120000Z,
    proxy-time=20260210T130500Z (drift=65m). Upstream rejection likely.
```

This catches "ghost" debugging scenarios where the signature is
cryptographically correct but rejected due to container clock drift. The proxy
does **not** modify the timestamp — it re-signs with the container's original
timestamp and lets AWS accept or reject it.

### Verbose Signing Diagnostics (`DEBUG_SIGNING`)

Set `DEBUG_SIGNING=1` as an environment variable in the proxy container to
enable verbose diagnostic logging for re-signing. This is a
development/debugging aid — it is not exposed in the server config:

- **Pre-signing context**: Service name, canonical URI (with encoding), signed
  headers, payload hash
- **Post-signing result**: Canonical request hash, output signed headers
- **Full canonical request**: The complete canonical request string (with
  `repr()` to show whitespace)
- **Deferred signing**: When body hash computation is deferred to the
  `request()` hook
- **AWS error body**: Response body for failed (4xx/5xx) re-signed requests,
  showing the exact AWS error type

These logs are **disabled by default** to keep the network log clean. Enable
them when debugging `SignatureDoesNotMatch` errors to compare the proxy's
canonical request against AWS's expected canonical string.

## Error Handling

| Error                                | Behavior                                               |
| ------------------------------------ | ------------------------------------------------------ |
| Malformed Authorization header       | Skip re-signing, forward as-is (will fail upstream)    |
| Unknown key ID in Credential=        | Skip re-signing, fall through to token replacement     |
| Host doesn't match scopes            | Skip re-signing, forward as-is                         |
| Canonical request construction fails | Log error, forward with surrogate (will fail upstream) |
| ECDSA signing fails                  | Log error, forward with surrogate (will fail upstream) |
| Chunked body parsing fails           | Log error, forward with surrogate (will fail upstream) |

All errors are fail-secure: the request proceeds with invalid surrogate
credentials and will be rejected by the upstream service. The proxy never blocks
a request due to re-signing failure — it logs the error and lets the upstream
reject it.

## Testing

### Unit Tests

AWS publishes official SigV4 test vectors. The proxy's canonicalization and
signing logic must pass these vectors:

- **Canonical request construction**: Test URI encoding, header
  canonicalization, query string sorting, S3 path handling
- **Signing key derivation**: Test against known key/date/region/service
  combinations
- **Full signature computation**: End-to-end test with AWS example requests
- **SigV4A key derivation and ECDSA signing**: Test against
  `aws-samples/sigv4a-signing-examples` reference outputs
- **Chunked body re-signing**: Test chunk parsing, signature chain computation,
  body reconstruction
- **Presigned URL re-signing**: Test query parameter parsing, signature
  replacement, URL reconstruction

### Integration Tests

- Container with surrogate AWS credentials makes S3 API calls through the proxy
- Verify the proxy re-signs correctly and the request succeeds
- Test with both SigV4 and SigV4A requests
- Test with chunked uploads
- Test with presigned URLs (container generates URL, request goes through proxy)
