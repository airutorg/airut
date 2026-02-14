# Masked Secrets (Token Replacement)

Masked secrets extend the server config secrets pool with scope-restricted
credentials. Instead of injecting real values into containers, surrogates are
injected and swapped for real values at the proxy level only for requests to
scoped hosts.

For high-level documentation (threat model, security properties, when to use),
see
[doc/network-sandbox.md](../doc/network-sandbox.md#masked-secrets-token-replacement).

## Server Config Schema

Masked secrets are declared alongside regular `secrets` in `config/airut.yaml`:

```yaml
repos:
  my-project:
    secrets:
      OPENAI_API_KEY: !env OPENAI_API_KEY      # Plain secret

    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
          - "api.github.com"
          - "*.githubusercontent.com"
      ANTHROPIC_API_KEY:
        value: !env ANTHROPIC_API_KEY
        scopes:
          - "api.anthropic.com"
```

### Fields

| Field                           | Type         | Required | Description                          |
| ------------------------------- | ------------ | -------- | ------------------------------------ |
| `masked_secrets`                | mapping      | No       | Named masked secrets for this repo   |
| `masked_secrets.<name>.value`   | string/!env  | Yes      | Secret value (supports `!env` tag)   |
| `masked_secrets.<name>.scopes`  | list[string] | Yes      | Fnmatch patterns for allowed hosts   |
| `masked_secrets.<name>.headers` | list[string] | Yes      | Fnmatch patterns for headers to scan |

Both `scopes` and `headers` use fnmatch pattern matching. Header matching is
**case-insensitive** per RFC 7230 (e.g., `"Authorization"` matches
`authorization`, `AUTHORIZATION`, etc.).

**Headers examples:**

```yaml
masked_secrets:
  # Match all headers (scan everything)
  UNIVERSAL_TOKEN:
    value: !env UNIVERSAL_TOKEN
    scopes: ["api.example.com"]
    headers: ["*"]

  # Match specific header
  GH_TOKEN:
    value: !env GH_TOKEN
    scopes: ["api.github.com"]
    headers: ["Authorization"]

  # Match pattern (e.g., all X-* headers)
  CUSTOM_TOKEN:
    value: !env CUSTOM_TOKEN
    scopes: ["api.example.com"]
    headers: ["X-*"]

  # GitLab-style header
  GITLAB_TOKEN:
    value: !env GITLAB_TOKEN
    scopes: ["gitlab.com"]
    headers: ["Private-Token"]
```

## Resolution Behavior

When repo config references `!secret NAME` or `!secret? NAME`:

1. Check `masked_secrets[NAME]` first
2. If found and value non-empty → generate surrogate, add to replacement map
3. If not found → check `secrets[NAME]` (plain injection)
4. If `!secret` and missing/empty → `ConfigError`
5. If `!secret?` and missing/empty → skip (no env var set)

The repo config is unaware of masking — it uses `!secret` for both plain and
masked secrets. The server determines protection level at resolution time.

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

The replacement map is built by `prepare_secrets()` in `lib/sandbox/secrets.py`
and passed to the proxy via `SecretReplacements` (an opaque container). The
internal representation maps surrogate tokens to replacement entries:

```
# Internal structure (not part of public API)
surrogate -> ReplacementEntry(real_value, scopes, headers)
```

### JSON Format (proxy mount)

```json
{
  "ghp_surrogate123...": {
    "value": "ghp_realtoken...",
    "scopes": ["api.github.com", "*.githubusercontent.com"],
    "headers": ["Authorization"]
  }
}
```

- Written to temp file at proxy start
- Mounted read-only at `/replacements.json` in proxy container
- Deleted at proxy stop
- Always created, even if empty (simplifies code path)

## Proxy Replacement

The proxy addon (`proxy/proxy_filter.py`) performs replacement in `request()`:

1. Load replacement map from `/replacements.json` at startup
2. For each request, check if host matches any surrogate's scopes
3. If match, replace surrogate → real value in headers
4. Log request with `[masked: N]` suffix indicating replacement count

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
Gateway config resolution
    │
    ├─ Parse .airut/airut.yaml
    ├─ Resolve !secret references against masked_secrets + secrets
    │
    └─ Provide MaskedSecret / SigningCredential to sandbox
           │
           ▼
prepare_secrets() (lib/sandbox/secrets.py)
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
disabled (`network.sandbox_enabled: false` in either repo or server config):

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

Existing `secrets` continue to work. To mask a secret:

1. Move entry from `secrets` to `masked_secrets` in server config
2. Add `scopes` list (fnmatch patterns for allowed hosts)
3. Add `headers` list (fnmatch patterns, e.g., `["Authorization"]` or `["*"]`)
4. No repo config changes needed

## AWS Credentials

Masked secrets handle credentials that appear verbatim in headers. AWS
credentials require a different approach — the secret key is used to compute
request signatures, not sent as a header value. For AWS credentials (or any
S3-compatible API), use `signing_credentials` instead. See
[aws-sigv4-resigning.md](aws-sigv4-resigning.md) for the full specification.
