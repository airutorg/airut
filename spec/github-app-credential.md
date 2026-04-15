# GitHub App Credential (Proxy-Managed Token Rotation)

Extends the network sandbox with GitHub App credentials, where the proxy manages
the full token lifecycle instead of performing simple string replacement. Unlike
masked secrets (which swap a surrogate for a static PAT), GitHub App credentials
generate short-lived installation tokens on demand, eliminating long-lived
tokens entirely.

For high-level documentation (setup guide, permissions, troubleshooting), see
[doc/github-app-setup.md](../doc/github-app-setup.md). For general masked
secrets (bearer tokens, API keys), see [masked-secrets.md](masked-secrets.md).

## GitHub App Authentication Overview

A GitHub App authenticates in two steps:

1. **JWT generation** (local, no network): Sign a JWT with the app's RSA private
   key. Claims: `iss` = app ID/client ID, `iat` = now - 60s, `exp` = now + 9m.
   Algorithm: RS256. Max lifetime: 10 minutes.

2. **Installation token exchange** (network):
   `POST /app/installations/{installation_id}/access_tokens` with
   `Authorization: Bearer <JWT>`. Returns a `ghs_`-prefixed token valid for **1
   hour**. Optional request body can restrict `permissions` and `repositories`.

Key properties:

- **Overlap**: Generating a new installation token does NOT invalidate the old
  one. Both remain valid until their own expiry.
- **No refresh mechanism**: There is no refresh token. To get a new token,
  generate a fresh JWT and call the exchange endpoint again.
- **Rate limits**: Installation tokens get 5,000-12,500 req/hr (scales with org
  size), better than PATs (fixed 5,000/hr).

## Server Config Schema

GitHub App credentials are declared in the `github_app_credentials:` block under
each repo in the server config, alongside `masked_secrets` and
`signing_credentials`. For the full field reference (types, defaults, examples),
see [`config/airut.example.yaml`](../config/airut.example.yaml).

The `app_id` field maps to the JWT `iss` claim. On GitHub.com (and GHES 3.19+),
this should be the **Client ID** (string starting with `Iv`). On older GHES
versions, use the numeric App ID.

The `private_key` is the PEM-encoded RSA private key downloaded from the GitHub
App settings page. Both PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8
(`BEGIN PRIVATE KEY`) formats are supported —
`cryptography.load_pem_private_key()` handles both.

For GitHub Enterprise Server, set the `base_url` field to the GHES API base URL
(e.g. `https://github.example.com/api/v3`). When absent, the proxy uses
`https://api.github.com` as default.

## Resolution Flow

GitHub App credentials are declared in the server config per repo. The key name
(e.g. `GH_TOKEN`) becomes the environment variable name auto-injected into the
container.

Resolution priority for duplicate env var names:

1. **Check `signing_credentials`** (highest priority)
2. Check `github_app_credentials`
3. Check `masked_secrets`
4. Fall back to `secrets`

When a GitHub App credential is matched:

1. Generate a surrogate with `ghs_` prefix and 36 random alphanumeric characters
   (mimics a real `ghs_` installation token format -- 40 chars total).
2. Add a `GitHubAppEntry` to the replacement map, keyed by the surrogate.
3. Inject the surrogate into the container environment.

## Replacement Map Entry

The JSON replacement map (mounted at `/replacements.json` in the proxy) gets a
new entry type discriminated by `"type": "github-app"`:

```json
{
  "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345": {
    "type": "github-app",
    "app_id": "Iv23li8e2xyz123",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----",
    "installation_id": "12345678",
    "base_url": "https://api.github.com",
    "scopes": ["github.com", "api.github.com", "*.githubusercontent.com"],
    "allow_foreign_credentials": false,
    "permissions": {"contents": "write", "pull_requests": "write"},
    "repositories": ["my-repo"]
  }
}
```

The `type` field distinguishes GitHub App credentials from regular token
replacements (which have no `type` field) and signing credentials (which have
`"type": "aws-sigv4"`).

## Proxy Behavior

### Token Cache

The proxy maintains an in-memory cache per GitHub App credential, mapping
surrogate to a cached token (value + Unix timestamp expiry). A token is
considered expired when current time is within 5 minutes of `expires_at`.

### Request Flow

When a request arrives at an allowlisted host:

1. **Detect**: Check if the request's `Authorization` header contains a
   surrogate matching a `"type": "github-app"` entry. The surrogate may appear
   in two forms:

   - **Bearer token**: `Authorization: Bearer ghs_surrogate...` -- direct string
     match.
   - **Basic Auth**: `Authorization: Basic <base64>` -- the proxy decodes the
     Base64 payload, checks for the surrogate in the password field, and
     re-encodes after replacement. This is how git operations work: the
     `gh auth git-credential` helper sends `x-access-token:<token>` as Basic
     Auth credentials.

2. **Scope check**: Verify request host matches the entry's `scopes` patterns.

3. **Token check**: Look up the surrogate in the token cache.

   - If cached token exists and is not within refresh margin -- use it.
   - If cached token is missing or near expiry -- refresh (step 4).

4. **Token refresh** (synchronous): mitmproxy hooks are synchronous (blocking
   the event loop), so concurrent requests naturally serialize. Steps:

   a. Generate a JWT: sign `{iss, iat, exp}` with the private key using RS256.
   b. Call `POST {base_url}/app/installations/{installation_id}/access_tokens`
   with `Authorization: Bearer <JWT>` and optional `permissions` /
   `repositories` body. c. Parse response: extract `token` and `expires_at`. d.
   Update the cache.

5. **Replace**: Substitute the surrogate with the real installation token in the
   `Authorization` header. Apply the same foreign-credential stripping logic as
   masked secrets (strip non-surrogate Authorization headers on scoped hosts
   when `allow_foreign_credentials` is false).

6. **Log**: Log the replacement with `[github-app: refreshed]` or
   `[github-app: cached]` in the network log.

### Hook Integration

GitHub App token replacement integrates into the existing hook flow:

```
requestheaders(flow)
  ├── _check_host_mismatch()
  ├── _is_allowed()
  ├── _try_resign_aws()           # existing: AWS SigV4
  └── (no github-app work here — needs full headers)

request(flow)
  ├── allowlist check
  ├── deferred AWS re-signing     # existing
  ├── _try_github_app(flow)       # GitHub App token replacement
  └── _replace_tokens(flow)       # existing: masked secrets
```

GitHub App handling runs in the `request()` hook (not `requestheaders()`)
because it needs the full request headers to detect the surrogate. It runs
before `_replace_tokens()` so that if the same request has both a GitHub App
surrogate and other masked secrets, both are handled.

### JWT Generation

JWT generation uses `cryptography` directly (already a proxy dependency for AWS
SigV4A ECDSA signing), avoiding a new `PyJWT` dependency:

1. Construct a standard JWT header (`{"alg": "RS256", "typ": "JWT"}`) and
   payload (`{iss, iat, exp}`) as base64url-encoded JSON segments.
2. Sign the `header.payload` string with the RSA private key using PKCS#1 v1.5
   padding and SHA-256.
3. Append the base64url-encoded signature.

### Installation Token Fetch

Uses `urllib.request` (stdlib) for the HTTPS call. The proxy container has
direct network access via the egress network -- the call does not route through
the proxy itself.

The call sends `Authorization: Bearer <JWT>`,
`Accept: application/vnd.github+json`, and `X-GitHub-Api-Version: 2022-11-28`.
The response contains `token` (the `ghs_`-prefixed installation token) and
`expires_at` (ISO 8601 timestamp converted to Unix time for cache storage).

### Error Handling

If the token refresh HTTP call fails:

- **Network error**: Return HTTP 502 to the container with a JSON body:
  ```json
  {
    "error": "github_app_token_refresh_failed",
    "message": "Failed to refresh GitHub App installation token: <detail>"
  }
  ```
- **GitHub API error** (4xx/5xx): Return HTTP 502 with the upstream error
  detail. Common errors: 401 (bad JWT/key), 404 (wrong installation ID), 403
  (insufficient permissions).
- **Log**: Always log refresh failures via `_log_loud()`.

The container sees a clean HTTP error and can retry. The surrogate is never sent
to the upstream server.

If the app is suspended or uninstalled mid-session, token refresh will
persistently fail. The proxy does not cache error state -- each request retries
independently (the overhead of one failed HTTP call per request is acceptable,
and the app could be reinstated).

## Data Flow

```
Server config resolution
    │
    ├─ Parse per-repo github_app_credentials from server config
    ├─ Resolve credential values (via !env tags)
    │
    └─ Provide GitHubAppCredential to sandbox
           │
           ▼
prepare_secrets() (airut/sandbox/secrets.py)
    │
    ├─ Generate ghs_-prefixed surrogate (40 chars, alphanumeric)
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
    ├─ Detect surrogate in Authorization header (Bearer or Basic Auth)
    ├─ Scope check (host matches entry's scopes)
    ├─ Token refresh if cache miss or near expiry (JWT → installation token)
    ├─ Replace surrogate with real installation token
    │
    └─ Forward request with real credentials
```

## Security Properties

01. **Private key isolation**: The RSA private key exists only in the proxy
    container's replacement map. The container never sees it.

02. **Short-lived tokens**: Installation tokens expire in 1 hour. Even if leaked
    via response echo, the blast radius is time-bounded.

03. **Surrogate stability**: The container sees a single, unchanging surrogate
    for the entire session. Token rotation is invisible.

04. **No PAT on the wire**: Eliminates long-lived PATs entirely for GitHub API
    access. The only tokens on the wire are 1-hour installation tokens.

05. **Foreign credential blocking**: The `allow_foreign_credentials: false`
    default strips non-surrogate Authorization headers on scoped hosts, same as
    masked secrets.

06. **Permission scoping**: Installation tokens can be restricted to specific
    permissions and repositories, following least-privilege.

07. **No new dependencies**: JWT generation uses `cryptography` (already in
    proxy for SigV4A). Token fetch uses `urllib.request` (stdlib).

08. **No token escalation**: Even if a leaked installation token is captured via
    response echo, it cannot be used to generate additional tokens. The
    `POST /app/installations/{id}/access_tokens` endpoint requires JWT
    authentication (signed with the private key), not installation token auth.

09. **Private key log redaction**: The private key is registered with
    `SecretFilter.register_secret()` in `RepoServerConfig.__post_init__()`, same
    as other credential values.

10. **JWT is memory-only**: JWTs generated by the proxy for token exchange exist
    only in memory for the brief duration of the HTTP call. They are never
    written to disk.

11. **Private key file lifecycle**: The replacement map JSON
    (`/replacements.json`) is created with restrictive permissions (0600),
    mounted read-only into the proxy container, and deleted after proxy stop.
    This is the same trust boundary as existing masked secret values.

## Comparison With Masked Secrets

| Aspect                    | Masked Secret (PAT)      | GitHub App Credential             |
| ------------------------- | ------------------------ | --------------------------------- |
| Token lifetime            | Months/years (or never)  | 1 hour                            |
| Token rotation            | None (static value)      | Automatic (proxy-managed)         |
| Private key in container  | N/A                      | Never                             |
| Real token in container   | Never (surrogate)        | Never (surrogate)                 |
| Proxy complexity          | Stateless string replace | Stateful (cache + HTTP refresh)   |
| Network call from proxy   | None                     | 1 call per hour to GitHub API     |
| Response echo risk        | High (PAT valid forever) | Low (token expires in 1 hour)     |
| Public repo mutation risk | No protection            | Blocked by GraphQL repo scoping   |
| GitHub rate limits        | 5,000/hr (PAT)           | 5,000-12,500/hr (scales with org) |

## Design Decisions

1. **Lazy token loading**: The first request triggers a synchronous token fetch,
   adding ~200-500ms latency on the first GitHub API call. This is acceptable:
   agent tasks are asynchronous and the delay is negligible compared to overall
   task time. Pre-fetching at startup would add complexity and a failure mode
   during initialization.

2. **Synchronous serialization**: mitmproxy hooks are synchronous, so concurrent
   requests naturally serialize through token refresh. This is fine -- security
   and robustness take priority over latency in Airut's model.

3. **Hardcoded `Authorization` header with Basic Auth support**: Unlike masked
   secrets (which have configurable `headers`), GitHub App credentials always
   scan only the `Authorization` header. The proxy handles both Bearer tokens
   (API calls via `gh` CLI, `curl`, etc.) and Basic Auth (git push/fetch via
   `gh auth git-credential`, which sends `x-access-token:<token>` as Basic Auth
   credentials). For Basic Auth, the proxy decodes the Base64 payload, replaces
   the surrogate in the password field, and re-encodes. This follows the same
   pattern as masked secrets' `_replace_in_header()` method.

## GraphQL Repository Scoping

GitHub App installation tokens can perform certain mutations (e.g.,
`createIssue`) on **any public repository**, regardless of the App's
installation scope. To prevent data exfiltration via GraphQL mutations targeting
out-of-scope repos, the proxy parses the GraphQL query AST (via `graphql-core`)
and scans the JSON variables to extract all `repositoryId` values, blocking
requests targeting repos outside the configured set.

**How it works:**

1. At token refresh time, the proxy calls `GET /installation/repositories` to
   resolve configured repository names to node IDs (stored in `CachedToken`).
2. GraphQL requests with URL query parameters are rejected outright (HTTP 403).
   The GraphQL endpoint only accepts POST with a JSON body; query parameters
   could bypass body-based scope checking. The `gh` CLI never uses query
   parameters for GraphQL.
3. For each GraphQL request (`POST /graphql`), `check_repo_scope()` extracts
   `repositoryId` from three paths: inlined in the query AST, variable
   references resolved against the variables dict, and variable objects scanned
   from JSON. The request path is percent-decoded before matching to prevent
   bypass via encoded path variants (e.g. `/%67raphql`).
4. Any out-of-scope `repositoryId` or unparseable request results in HTTP 403.
   Requests with no `repositoryId` or all values in scope are allowed.

The check is **fail-secure**: parse failures, unresolvable variables, and
requests checked against an empty allowed set (node ID resolution failed) all
result in a block. The `graphql_scope.py` module is a pure function with no
mitmproxy dependency, taking `bytes` in and returning a structured
`ScopeResult(verdict, detail)` where `verdict` is an enum
(`ALLOWED | OUT_OF_SCOPE | PARSE_ERROR | UNRESOLVED_VARIABLE`).

## Future Enhancements

- **Token revocation on session end**: The proxy could revoke the installation
  token (`DELETE /installation/token`) during teardown to minimize the window of
  a leaked token. Not implemented initially -- the risk is low in practice since
  the execution container never receives the JWT (only the surrogate), and
  tokens are removed from memory when the proxy exits. The only theoretical
  vector is a reflection attack where a GitHub API response echoes the
  installation token back to the container, which could then forward it to
  another allowlisted destination. The 1-hour expiry already bounds this risk.
