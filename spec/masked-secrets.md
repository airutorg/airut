# Masked Secrets (Token Replacement)

Masked secrets extend the server config secrets pool with scope-restricted
credentials. Instead of injecting real values into containers, surrogates are
injected and swapped for real values at the proxy level only for requests to
scoped hosts.

For high-level documentation (threat model, security properties, when to use),
see
[doc/network-sandbox.md](../doc/network-sandbox.md#masked-secrets-token-replacement).

## Server Config Schema

Masked secrets are declared in the `masked_secrets:` block under each repo in
the server config, alongside regular `secrets`. For the full field reference
(types, defaults, examples), see
[`config/airut.example.yaml`](../config/airut.example.yaml).

Both `scopes` and `headers` use fnmatch pattern matching. Header matching is
**case-insensitive** per RFC 7230 (e.g., `"Authorization"` matches
`authorization`, `AUTHORIZATION`, etc.). Common header patterns:

- `"Authorization"` — match a specific header
- `"*"` — match all headers (scan everything)
- `"X-*"` — match headers starting with X- (any case)
- `"Private-Token"` — GitLab-style header

## Resolution Behavior

All credential pools are defined in the server config per repo. Masked secret
entries auto-inject into the container as environment variables by their key
name. For each masked secret:

1. If value is non-empty → generate surrogate, add to replacement map, inject
   surrogate as env var
2. If value is empty → skip (no env var set)

The server determines protection level based on which credential pool the entry
belongs to. See [repo-config.md](repo-config.md#credential-auto-injection) for
the full priority ordering when the same env var name appears in multiple pools.

## Surrogate Format

Surrogates preserve the original token's format:

| Property     | Preserved | Example                               |
| ------------ | --------- | ------------------------------------- |
| Length       | Yes       | 40-char token → 40-char surrogate     |
| Charset      | Yes       | Alphanumeric → alphanumeric surrogate |
| Known prefix | Yes       | `ghp_xxx...` → `ghp_yyy...`           |

Known prefixes: `github_pat_`, `ghp_`, `gho_`, `ghs_`, `ghr_`, `sk-ant-`, `sk-`,
`xoxb-`, `xoxp-`.

Generation uses `secrets.choice()` (cryptographically secure).

## Replacement Map

The replacement map is built by `prepare_secrets()` in
`airut/sandbox/secrets.py` and passed to the proxy via `SecretReplacements` (an
opaque container). The internal representation maps surrogate tokens to
replacement entries:

```
# Internal structure (not part of public API)
surrogate -> ReplacementEntry(real_value, scopes, headers)
```

### JSON Format (proxy mount)

```json
{
  "ghp_surrogate123...": {
    "value": "ghp_realtoken...",
    "scopes": ["github.com", "api.github.com", "*.githubusercontent.com"],
    "headers": ["Authorization"]
  }
}
```

When `allow_foreign_credentials` is true, it is included in the entry:

```json
{
  "ghp_surrogate123...": {
    "value": "ghp_realtoken...",
    "scopes": ["github.com", "api.github.com"],
    "headers": ["Authorization"],
    "allow_foreign_credentials": true
  }
}
```

When absent or false, the proxy strips matching headers that do not contain the
surrogate (default secure behavior).

- Written to temp file at proxy start
- Mounted read-only at `/replacements.json` in proxy container
- Deleted at proxy stop
- Always created, even if empty (simplifies code path)

## Proxy Replacement

The proxy addon (`airut/_bundled/proxy/proxy_filter.py`) performs replacement in
`request()` using a two-pass approach:

1. Load replacement map from `/replacements.json` at startup
2. **Replace pass**: For each request, check if host matches any surrogate's
   scopes. If match, replace surrogate → real value in matching headers.
3. **Strip pass**: For any header where the surrogate was NOT found, the header
   pattern was an **exact name** (no glob characters), and
   `allow_foreign_credentials` is false (default), the header is **removed
   entirely**. This prevents attacker-supplied credentials from being used on
   allowlisted hosts (e.g., exfiltrating data via an attacker's own API key).
   Glob patterns like `"*"` or `"X-*"` do not trigger stripping — they mean
   "scan everywhere for the surrogate", not "every matching header is a
   credential".
4. Log each stripped header with a `STRIPPED` line. Append `[dropped: N]` to the
   response log line (alongside `[masked: N]`) indicating how many headers were
   stripped. The dashboard renders `[dropped: N]` as a warning tag and
   `STRIPPED` lines with warning styling.

Headers that were successfully replaced by any credential are never stripped,
even if a different credential also matches the same header pattern but does not
find its surrogate.

### Headers Scanned

Headers to scan are specified per masked secret using fnmatch patterns. Matching
is **case-insensitive** per RFC 7230:

- `"Authorization"` — matches `Authorization`, `authorization`, `AUTHORIZATION`
- `"*"` — match all headers
- `"X-*"` — match headers starting with X- (any case)

### Basic Auth Support

For `Authorization` headers, the proxy handles both direct tokens and
Base64-encoded Basic Auth:

- **Bearer tokens**: `Authorization: Bearer ghp_surrogate...` → direct
  replacement
- **Basic Auth**: `Authorization: Basic <base64>` → decode, replace, re-encode

This enables git operations (`git push`, `git fetch`) which use Basic Auth with
`x-access-token:TOKEN` format.

Body and query parameter tokens are **not** replaced.

## Data Flow

```
Server config resolution
    │
    ├─ Parse per-repo masked_secrets from server config
    ├─ Resolve credential values (via !env tags)
    │
    └─ Provide MaskedSecret entries to sandbox
           │
           ▼
prepare_secrets() (airut/sandbox/secrets.py)
    │
    ├─ Generate surrogates for masked secrets
    ├─ Return PreparedSecrets (env_vars + SecretReplacements)
    │
    └─ SecretReplacements passed to NetworkSandboxConfig
           │
           ▼
Task.execute() -> ProxyManager.start_task_proxy()
    │
    ├─ Serialize SecretReplacements to JSON temp file
    ├─ Mount at /replacements.json
    │
    └─ Proxy container starts with filter addon
           │
           ▼
proxy_filter.py request()
    │
    ├─ Allowlist check
    ├─ Token replacement (if host matches scopes)
    │
    └─ Forward request with real credentials
```

## Log Redaction

| Value     | Registered with SecretFilter | Visible in logs |
| --------- | ---------------------------- | --------------- |
| Real      | Yes                          | No (redacted)   |
| Surrogate | No                           | Yes (debugging) |

## Network Sandbox Requirement

Masked secrets depend on the network sandbox proxy to function. The proxy is
what swaps surrogates for real values on matching requests. When the sandbox is
disabled (`network.sandbox_enabled: false` in server config):

- Surrogates are **still generated** and injected into the container
- The proxy **never starts**, so surrogates are never swapped for real values
- API calls using masked secrets will **fail** (the surrogate is not a valid
  credential)

This is by design — disabling the sandbox removes the proxy, and the proxy is
the enforcement mechanism for masked secrets.

**If you need to disable the sandbox but still need credentials**, temporarily
move them from `masked_secrets` to `secrets` (plain injection) in server config.
Remember to move them back after re-enabling the sandbox.

A warning is logged when this condition is detected:

> Network sandbox is disabled but masked secrets are configured. Masked secrets
> require the proxy to swap surrogates for real values — they will not work
> without the sandbox.

## Migration

To mask a secret that is currently a plain `secrets` entry:

1. Move entry from `secrets` to `masked_secrets` in server config
2. Add `scopes` list (fnmatch patterns for allowed hosts)
3. Add `headers` list (fnmatch patterns, e.g., `["Authorization"]` or `["*"]`)

## AWS Credentials

Masked secrets handle credentials that appear verbatim in headers. AWS
credentials require a different approach — the secret key is used to compute
request signatures, not sent as a header value. For AWS credentials (or any
S3-compatible API), use `signing_credentials` instead. See
[aws-sigv4-resigning.md](aws-sigv4-resigning.md) for the full specification.
