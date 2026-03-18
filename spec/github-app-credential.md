# GitHub App Credential (Proxy-Managed Token Rotation)

## Problem

Classic PATs used as masked secrets create a network sandbox escape that cannot
be closed. The proxy replaces the surrogate with the real PAT before forwarding
to GitHub, and certain GitHub API responses can echo the authentication token
back in the response body. Since the proxy only scrubs outbound request headers
(not inbound response bodies), the container can extract the real PAT from the
response. A classic PAT is long-lived, so a leaked token provides persistent
access beyond the sandbox session.

## Solution

A new credential type — **GitHub App credential** — where the proxy manages the
full token lifecycle:

1. The container receives a **stable surrogate** in `GH_TOKEN` and never sees a
   real credential.
2. The proxy holds the GitHub App **private key** and generates short-lived
   **installation access tokens** on demand.
3. Token rotation is invisible to the container: the surrogate never changes,
   only the real token behind it rotates.
4. Even if a token leaks via response echo, it expires in **1 hour** and cannot
   be used to create new long-lived credentials.

## GitHub App Authentication Overview

A GitHub App authenticates in two steps:

1. **JWT generation** (local, no network): Sign a JWT with the app's RSA private
   key. Claims: `iss` = app ID/client ID, `iat` = now − 60s, `exp` = now + 9m.
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
- **Rate limits**: Installation tokens get 5,000–12,500 req/hr (scales with org
  size), better than PATs (fixed 5,000/hr).

## Server Config Schema

GitHub App credentials are declared in a new `github_app_credentials` block
alongside `masked_secrets` and `signing_credentials`:

```yaml
repos:
  my-project:
    github_app_credentials:
      GH_TOKEN:
        app_id: !env GH_APP_ID                    # Client ID (Iv23li...) on github.com
        private_key: !env GH_APP_PRIVATE_KEY       # PEM-encoded RSA private key
        installation_id: !env GH_APP_INSTALLATION_ID
        scopes:
          - "api.github.com"
          - "*.githubusercontent.com"
        allow_foreign_credentials: false            # Optional, default: false
        # Optional: restrict token permissions (subset of app's granted permissions)
        permissions:
          contents: write
          pull_requests: write
        # Optional: restrict token to specific repos
        repositories:
          - "my-repo"
```

### Fields

| Field                       | Type          | Required | Description                                                   |
| --------------------------- | ------------- | -------- | ------------------------------------------------------------- |
| `app_id`                    | string / !env | Yes      | GitHub App Client ID (`Iv23li...`) or numeric App ID for GHES |
| `private_key`               | string / !env | Yes      | PEM-encoded RSA private key                                   |
| `installation_id`           | string / !env | Yes      | Installation ID for the target org/user                       |
| `scopes`                    | list[string]  | Yes      | Fnmatch host patterns where token replacement is allowed      |
| `base_url`                  | string / !env | No       | GitHub API base URL (default: `https://api.github.com`)       |
| `allow_foreign_credentials` | bool          | No       | Allow non-surrogate credentials through (default: false)      |
| `permissions`               | dict          | No       | Restrict token permissions (subset of app's grants)           |
| `repositories`              | list[string]  | No       | Restrict token to specific repository names                   |

The `app_id` field maps to the JWT `iss` claim. On GitHub.com (and GHES 3.19+),
this should be the **Client ID** (string starting with `Iv`). On older GHES
versions, use the numeric App ID.

The `private_key` is the PEM-encoded RSA private key downloaded from the GitHub
App settings page. Both PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8
(`BEGIN PRIVATE KEY`) formats are supported —
`cryptography.load_pem_private_key()` handles both.

### GHES Support

For GitHub Enterprise Server, add a `base_url` field:

```yaml
github_app_credentials:
  GH_TOKEN:
    app_id: "12345"
    private_key: !env GH_APP_PEM
    installation_id: "67890"
    base_url: "https://github.example.com/api/v3"   # GHES API base
    scopes:
      - "github.example.com"
      - "*.github.example.com"
```

When `base_url` is absent, the proxy uses `https://api.github.com` as default.

## Resolution Flow

Repo config is unaware of the credential type — it uses plain `!secret`:

```yaml
# .airut/airut.yaml (repo config)
container_env:
  GH_TOKEN: !secret GH_TOKEN
```

Resolution priority in `_resolve_container_env()` (extended):

1. Check `signing_credentials` (existing)
2. **Check `github_app_credentials`** (new)
3. Check `masked_secrets` (existing)
4. Fall back to `secrets` (existing)

When a GitHub App credential is matched:

1. Generate a surrogate with `ghs_` prefix and 36 random alphanumeric characters
   (mimics a real `ghs_` installation token format).
2. Add a `GitHubAppEntry` to the replacement map, keyed by the surrogate.
3. Inject the surrogate into `container_env`.

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
    "scopes": ["api.github.com", "*.githubusercontent.com"],
    "allow_foreign_credentials": false,
    "permissions": {"contents": "write", "pull_requests": "write"},
    "repositories": ["my-repo"]
  }
}
```

## Proxy Behavior

### Token Cache

The proxy maintains an in-memory cache per GitHub App credential:

```python
@dataclass
class _CachedToken:
    token: str
    expires_at: float  # Unix timestamp
```

Cache is an instance variable on the `ProxyFilter` class (initialized in
`load()`), mapping surrogate → `_CachedToken`. Token is considered expired when
current time is within `_REFRESH_MARGIN` (5 minutes) of `expires_at`.

### Request Flow

When a request arrives at an allowlisted host:

1. **Detect**: In a new `_try_github_app()` handler, check if the request's
   `Authorization` header contains a surrogate matching a `"type": "github-app"`
   entry. The header is always `Authorization` — this is not configurable
   (GitHub tokens are always Bearer tokens in the Authorization header; if
   GitHub changes this, Airut updates accordingly).

2. **Scope check**: Verify request host matches the entry's `scopes` patterns.

3. **Token check**: Look up the surrogate in the token cache.

   - If cached token exists and is not within refresh margin → use it.
   - If cached token is missing or near expiry → refresh (step 4).

4. **Token refresh** (synchronous): mitmproxy hooks are synchronous (blocking
   the event loop), so concurrent requests naturally serialize. This is
   acceptable — security and robustness take priority over latency, and agent
   tasks are asynchronous by nature. Steps:

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

The GitHub App token replacement integrates into the existing hook flow:

```
requestheaders(flow)
  ├── _check_host_mismatch()
  ├── _is_allowed()
  ├── _try_resign_aws()           # existing: AWS SigV4
  └── (no github-app work here — needs full headers)

request(flow)
  ├── allowlist check
  ├── deferred AWS re-signing     # existing
  ├── _try_github_app(flow)       # NEW: GitHub App token replacement
  └── _replace_tokens(flow)       # existing: masked secrets
```

GitHub App handling runs in the `request()` hook (not `requestheaders()`)
because it needs the full request headers to detect the surrogate. It runs
before `_replace_tokens()` so that if the same request has both a GitHub App
surrogate and other masked secrets, both are handled.

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
persistently fail. The proxy should not cache error state — each request retries
independently (the overhead of one failed HTTP call per request is acceptable,
and the app could be reinstated).

### JWT Generation Without PyJWT

The proxy already depends on `cryptography` (used for AWS SigV4A ECDSA signing).
JWT generation uses `cryptography` directly, avoiding a new `PyJWT` dependency:

```python
import base64
import json
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_jwt(app_id: str, private_key_pem: str) -> str:
    header = _base64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = _base64url(
        json.dumps(
            {
                "iss": app_id,
                "iat": now - 60,
                "exp": now + 540,  # 9 minutes (with 60s clock-drift margin)
            }
        ).encode()
    )

    signing_input = f"{header}.{payload}".encode()
    key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    return f"{header}.{payload}.{_base64url(signature)}"
```

No new proxy dependencies required.

### Installation Token Fetch

Uses `urllib.request` (stdlib) for the HTTPS call. The proxy container has
direct network access via the egress network — the call does not route through
the proxy itself.

```python
import json
import urllib.request


def fetch_installation_token(
    base_url: str,
    installation_id: str,
    jwt: str,
    permissions: dict | None = None,
    repositories: list[str] | None = None,
) -> tuple[str, str]:
    """Exchange JWT for installation access token.

    Returns (token, expires_at_iso).
    """
    url = f"{base_url}/app/installations/{installation_id}/access_tokens"

    body: dict = {}
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

    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
        return result["token"], result["expires_at"]


# The caller converts expires_at from ISO 8601 to Unix timestamp:
#   from datetime import datetime, timezone
#   expires_at = datetime.fromisoformat(
#       expires_at_iso.replace("Z", "+00:00")
#   ).timestamp()
```

## Implementation Plan

### New Files

| File                                 | Description                         |
| ------------------------------------ | ----------------------------------- |
| `airut/_bundled/proxy/github_app.py` | JWT generation, token fetch & cache |

### Modified Files

| File                                          | Change                                                                                                                                     |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `airut/gateway/config.py`                     | New `GitHubAppCredential`, `GitHubAppEntry` dataclasses; add `GitHubAppEntry` to `ReplacementMap` union; extend `_resolve_container_env()` |
| `airut/sandbox/secrets.py`                    | New `GitHubAppCredential` input type, `_GitHubAppEntry` internal type; extend `prepare_secrets()`                                          |
| `airut/_bundled/proxy/proxy_filter.py`        | New `_try_github_app()` handler; integrate into `request()` hook                                                                           |
| `airut/_bundled/proxy/proxy.dockerfile`       | `COPY github_app.py`                                                                                                                       |
| `airut/gateway/service/message_processing.py` | Extend `_convert_replacement_map()` for `GitHubAppEntry`                                                                                   |
| `spec/repo-config.md`                         | Document new credential type in server config schema                                                                                       |

### Dataclasses

**Gateway config** (`airut/gateway/config.py`):

```python
@dataclass(frozen=True)
class GitHubAppCredential:
    """GitHub App credential for proxy-managed token rotation."""

    app_id: str
    private_key: str
    installation_id: str
    scopes: frozenset[str]
    allow_foreign_credentials: bool = False
    base_url: str = "https://api.github.com"
    permissions: dict[str, str] | None = None
    repositories: tuple[str, ...] | None = None


@dataclass(frozen=True)
class GitHubAppEntry:
    """Entry in the replacement map for GitHub App credentials."""

    app_id: str
    private_key: str
    installation_id: str
    base_url: str
    scopes: tuple[str, ...]
    allow_foreign_credentials: bool = False
    permissions: dict[str, str] | None = None
    repositories: tuple[str, ...] | None = None
```

**Sandbox secrets** (`airut/sandbox/secrets.py`):

```python
@dataclass(frozen=True)
class GitHubAppCredential:
    """GitHub App credential for proxy-managed token rotation."""

    env_var: str
    app_id: str
    private_key: str
    installation_id: str
    scopes: tuple[str, ...]
    allow_foreign_credentials: bool = False
    base_url: str = "https://api.github.com"
    permissions: dict[str, str] | None = None
    repositories: tuple[str, ...] | None = None
```

### Surrogate Generation

GitHub App credentials don't have a real token at config time. The surrogate is
generated from a fixed template:

```python
# Template must include mixed case + digits so generate_surrogate()
# detects the correct charset (real ghs_ tokens are alphanumeric).
_GITHUB_APP_SURROGATE_TEMPLATE = "ghs_" + "aA0" * 12  # 40 chars total
surrogate = generate_surrogate(_GITHUB_APP_SURROGATE_TEMPLATE)
```

This produces a `ghs_`-prefixed, 40-character random alphanumeric token that
looks like a real GitHub installation token.

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

09. **Private key log redaction**: The private key must be registered with
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

| Aspect                   | Masked Secret (PAT)      | GitHub App Credential             |
| ------------------------ | ------------------------ | --------------------------------- |
| Token lifetime           | Months/years (or never)  | 1 hour                            |
| Token rotation           | None (static value)      | Automatic (proxy-managed)         |
| Private key in container | N/A                      | Never                             |
| Real token in container  | Never (surrogate)        | Never (surrogate)                 |
| Proxy complexity         | Stateless string replace | Stateful (cache + HTTP refresh)   |
| Network call from proxy  | None                     | 1 call per hour to GitHub API     |
| Response echo risk       | High (PAT valid forever) | Low (token expires in 1 hour)     |
| GitHub rate limits       | 5,000/hr (PAT)           | 5,000–12,500/hr (scales with org) |

## Design Decisions

1. **Lazy token loading**: The first request triggers a synchronous token fetch,
   adding ~200-500ms latency on the first GitHub API call. This is acceptable:
   agent tasks are asynchronous and the delay is negligible compared to overall
   task time. Pre-fetching at startup would add complexity and a failure mode
   during initialization.

2. **Synchronous serialization**: mitmproxy hooks are synchronous, so concurrent
   requests naturally serialize through token refresh. This is fine — security
   and robustness take priority over latency in Airut's model.

3. **Hardcoded `Authorization` header**: Unlike masked secrets (which have
   configurable `headers`), GitHub App credentials always scan only the
   `Authorization` header. GitHub tokens are always Bearer tokens in this
   header. This simplifies config and follows the "Airut handles everything"
   contract — if GitHub changes the header convention, Airut updates
   accordingly.

## Future Enhancements

- **Token revocation on session end**: The proxy could revoke the installation
  token (`DELETE /installation/token`) during teardown to minimize the window of
  a leaked token. Not implemented initially — the risk is low in practice since
  the execution container never receives the JWT (only the surrogate), and
  tokens are removed from memory when the proxy exits. The only theoretical
  vector is a reflection attack where a GitHub API response echoes the
  installation token back to the container, which could then forward it to
  another allowlisted destination. The 1-hour expiry already bounds this risk.
