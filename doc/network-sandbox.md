# Network Sandbox

The network sandbox restricts Claude Code container network access to a
configurable set of trusted hosts, mitigating data exfiltration risk from prompt
injection attacks. It works by transparently routing all traffic through an
mitmproxy instance that enforces an allowlist — no `HTTP_PROXY` env vars needed,
so it works with all tools (Node.js, Go, curl, Python, git).

> **Terminology**: "Network sandbox" refers to the overall isolation concept.
> "Network allowlist" is the configuration specifying permitted hosts. "Proxy"
> (mitmproxy) is the enforcement mechanism.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Threat Model](#threat-model)
- [Security Model](#security-model)
  - [Why This Is Secure](#why-this-is-secure)
  - [Fail-Secure Behavior](#fail-secure-behavior)
  - [Security Analysis](#security-analysis)
  - [Limitations](#limitations)
- [Architecture](#architecture)
- [Configuration](#configuration)
  - [Enabling/Disabling the Sandbox](#enablingdisabling-the-sandbox)
  - [Upstream DNS](#upstream-dns)
  - [Network Allowlist](#network-allowlist)
    - [Pattern Matching Rules](#pattern-matching-rules)
    - [HTTP Method Filtering](#http-method-filtering)
    - [GraphQL Operation Filtering](#graphql-operation-filtering)
    - [Wildcard Host for Credential-Only Sandboxing](#wildcard-host-for-credential-only-sandboxing)
  - [Agent Self-Service Flow](#agent-self-service-flow)
- [Masked Secrets (Token Replacement)](#masked-secrets-token-replacement)
  - [Problem](#problem)
  - [Solution](#solution)
  - [Security Properties](#security-properties)
  - [Foreign credential blocking](#foreign-credential-blocking)
  - [Limitations](#limitations-1)
  - [When to Use](#when-to-use)
- [Signing Credentials (AWS SigV4 Re-signing)](#signing-credentials-aws-sigv4-re-signing)
  - [Problem](#problem-1)
  - [Solution](#solution-1)
  - [What Gets Re-signed](#what-gets-re-signed)
  - [Security Properties](#security-properties-1)
  - [Limitations](#limitations-2)
  - [Transparent Upgrade Path](#transparent-upgrade-path)
- [GitHub App Credentials (Proxy-Managed Token Rotation)](#github-app-credentials-proxy-managed-token-rotation)
  - [Problem](#problem-2)
  - [Solution](#solution-2)
  - [Security Properties](#security-properties-2)
  - [Comparison With Masked Secrets](#comparison-with-masked-secrets)
  - [GraphQL Repository Scoping](#graphql-repository-scoping)
  - [Limitations](#limitations-3)
  - [When to Use](#when-to-use-1)
- [Troubleshooting](#troubleshooting)
  - [Broken allowlist checked into main](#broken-allowlist-checked-into-main)
  - [Masked secrets stopped working](#masked-secrets-stopped-working)
  - [Debugging container network issues](#debugging-container-network-issues)
- [Further Reading](#further-reading)

<!-- mdformat-toc end -->

## Threat Model

Claude Code containers execute arbitrary code on behalf of the agent. A prompt
injection attack — malicious instructions embedded in fetched content (web
pages, API responses, imported files) — could direct the agent to exfiltrate
sensitive data (credentials, ledger data, API keys) to attacker-controlled
servers.

The network sandbox breaks this exfiltration path: even if the agent is tricked
into making a request, it can only reach pre-approved hosts.

**Combined with surrogate credentials** (see
[Masked Secrets](#masked-secrets-token-replacement),
[Signing Credentials](#signing-credentials-aws-sigv4-re-signing), and
[GitHub App Credentials](#github-app-credentials-proxy-managed-token-rotation)),
real credentials never enter the container — they stay with the proxy and are
only inserted into upstream requests to scoped hosts. A compromised container
can still make authenticated requests to scoped hosts through the proxy, but
cannot extract the real credentials for use elsewhere. The attacker's ability to
act is bound to the container's lifetime and the proxy's scope — once the
container stops, the credentials are inaccessible.

## Security Model

The security of the network sandbox rests on two properties:

1. **Allowlist is authoritative**: The agent can only access hosts explicitly
   listed in `.airut/network-allowlist.yaml`.

2. **Allowlist is protected**: The allowlist is read from the repository's
   **default branch** (typically `main`), not from the agent's working
   directory. The agent cannot modify the active allowlist during a task.

### Why This Is Secure

The agent operates in a conversation workspace cloned from the repository. While
it can modify files in that workspace — including the allowlist file — those
changes have no effect until merged to the default branch. The active allowlist
is always fetched fresh from the git mirror's default branch at task start.

This design enables a self-service workflow: the agent can propose allowlist
changes by creating a PR, but a human must review and merge before the change
takes effect. Security relies on:

- **Branch protection**: The default branch requires PR approval
- **Human review**: Allowlist changes are auditable and require explicit
  approval
- **Isolation**: Each task fetches the allowlist independently; mid-task changes
  to the repo have no effect on running tasks

### Fail-Secure Behavior

The system fails secure at multiple levels:

- If the proxy infrastructure isn't ready, the container won't start
- If the proxy health check fails, the task aborts
- Containers never run with unrestricted access when the sandbox is expected

### Security Analysis

The following attack vectors have been analyzed and verified as mitigated:

**DNS exfiltration**: The sandbox uses a custom DNS responder inside the proxy
container that returns the proxy IP for all A queries unconditionally. No
queries are ever forwarded upstream — the DNS responder never contacts external
nameservers. Allowlist enforcement happens at the proxy layer (HTTP 403 for
blocked requests), not at DNS.

**Non-HTTP traffic**: The client container's only network route points to the
proxy IP. The proxy only listens on ports 80 and 443. Any attempt to connect on
other ports (SSH, raw TCP, etc.) gets "connection refused" because no service is
listening. No iptables or `CAP_NET_ADMIN` needed.

**Direct IP access**: Even if the container hardcodes an external IP address
(bypassing DNS), the default route sends the traffic to the proxy IP, where
mitmproxy can only handle it as HTTP(S). Direct IP connections to non-proxy
ports fail because no service is listening.

**Proxy admin interface**: The proxy uses `mitmdump` (not `mitmweb`), so no web
interface exists. Only ports 80 and 443 are exposed. Additionally, requests to
the proxy's own hostname are filtered by the allowlist — the proxy checks ALL
requests, including those addressed to itself.

**Redirect following**: The proxy operates as a client-driven proxy, not a
server-side redirect follower. When an allowed domain returns a 301/302
redirect, the proxy returns that response to the client. The client then makes a
*new* request to the redirect target, which is checked against the allowlist
independently. Redirects to blocked domains result in a 403.

**CONNECT tunneling** (defense-in-depth): The proxy unconditionally blocks all
CONNECT requests with HTTP 403 via the `http_connect` hook, regardless of target
host. Note that mitmproxy would MITM a CONNECT tunnel and still apply
`request()` hooks to inner HTTP requests, so the allowlist is not actually
bypassed by CONNECT — this was confirmed during penetration testing. The block
is defense-in-depth: CONNECT is never needed in this DNS-spoofing architecture,
so blocking it eliminates an unnecessary code path and simplifies security
reasoning.

**Host header mismatch** (defense-in-depth): In regular proxy mode, HTTP
requests with absolute-form URIs (e.g., `GET http://target.com/path`) are routed
by mitmproxy to the URL host, but `pretty_host` returns the Host header value.
An attacker could set the Host header to an allowed domain while routing the
request to a blocked host via the URL. The proxy blocks any request where the
Host header and URL host disagree (case-insensitive comparison), returning HTTP
403\. This only affects plain HTTP — HTTPS requests in the DNS-spoofing model do
not use absolute-form URIs.

### Limitations

The sandbox handles **HTTP(S) traffic only**. Other protocols (raw TCP, SSH,
etc.) are blocked entirely — the container's default route goes to the proxy,
which only has HTTP(S) listeners. Non-HTTP connection attempts get "connection
refused."

## Architecture

The Airut service manages sandbox infrastructure automatically — no separate
setup required. On startup, it creates networks, builds the proxy image, and
generates the CA certificate. The implementation uses rootless Podman, so no
root privileges are needed.

**Requirements**: Podman 4.x+ with netavark backend, rootless mode. No
`CAP_NET_ADMIN` needed on any container.

Each task gets its own internal network and proxy container, providing complete
isolation between concurrent tasks. See
[spec/network-sandbox.md](../spec/network-sandbox.md) for the network topology,
proxy lifecycle, resource scoping, CA certificate trust, log format, and crash
recovery details.

## Configuration

### Enabling/Disabling the Sandbox

The network sandbox is controlled in the server config per repo. It defaults to
`true`.

```yaml
# ~/.config/airut/airut.yaml (server config, per-repo)
repos:
  my-project:
    network:
      sandbox_enabled: true  # default; set to false to disable (break-glass)
```

When disabled, containers get unrestricted network access without the proxy.
**Use only for debugging or emergencies** — this removes the exfiltration
protection.

This setting is useful as a **break-glass** for operators: if a broken allowlist
gets checked in, the operator can disable the sandbox while a fix is prepared.
Config changes are picked up automatically via live reload (or when saved
through the config editor). The change takes effect once any in-flight tasks for
the repo complete.

When the sandbox is disabled, a warning is logged. If masked secrets are
configured, an additional warning is logged because masked secrets depend on the
proxy (see [Masked Secrets](#masked-secrets-token-replacement)).

### Upstream DNS

The proxy container needs its own DNS to resolve real hostnames when connecting
upstream. By default, Airut auto-detects the system resolver from
`/etc/resolv.conf` (the first `nameserver` entry). You can override this in the
server config:

```yaml
network:
  upstream_dns: "1.1.1.1"  # optional: override auto-detected system resolver
```

If auto-detection fails (e.g., `/etc/resolv.conf` is missing or contains no
`nameserver` entries), the service will refuse to start with a clear error
message asking you to set `network.upstream_dns` explicitly.

This only affects the proxy container's resolution of real hostnames. Client
containers never contact this DNS server — they only talk to the custom DNS
responder.

### Network Allowlist

The allowlist at `.airut/network-allowlist.yaml` defines permitted hosts using
fnmatch-style pattern matching:

```yaml
# Domain entries: all paths and methods allowed
domains:
  - "*.github.com"         # matches api.github.com, NOT github.com

# URL pattern entries: host + path pattern required, optional method filter
url_prefixes:
  # Anthropic API — path-restricted to prevent exfiltration via /v1/files
  # (attacker can use their own API key to upload/fetch material)
  - host: api.anthropic.com
    path: /v1/messages*
    methods: [POST]
  - host: api.github.com
    path: /repos/your-org/your-repo*   # matches /repos/your-org/your-repo and subpaths
  - host: api.github.com
    path: /graphql                 # exact match only
    methods: [POST]                # only POST allowed (GraphQL is POST-only)
```

#### Pattern Matching Rules

Both domains and paths support fnmatch-style wildcards (`*` and `?`):

| Pattern          | Matches                                         | Does NOT Match                    |
| ---------------- | ----------------------------------------------- | --------------------------------- |
| `api.github.com` | `api.github.com`                                | `uploads.github.com`              |
| `*.github.com`   | `api.github.com`, `uploads.github.com`          | `github.com` (no subdomain)       |
| `/repos/foo`     | `/repos/foo`                                    | `/repos/foo/bar`, `/repos/foobar` |
| `/repos/foo/*`   | `/repos/foo/bar`, `/repos/foo/x/y`              | `/repos/foo`, `/repos/foobar`     |
| `/repos/foo*`    | `/repos/foo`, `/repos/foobar`, `/repos/foo/bar` | `/repos/fo`                       |

**Key principles:**

- Domain/host matching is **case-insensitive** per RFC 4343
- No implicit prefix matching — use explicit `*` for prefix behavior
- `*.example.com` does NOT match `example.com` (requires subdomain)
- No path normalization — `/api` and `/api/` are different patterns
- Empty path in `url_prefixes` allows all paths on that host

#### HTTP Method Filtering

URL prefix entries can optionally restrict which HTTP methods are allowed using
the `methods` field:

```yaml
url_prefixes:
  - host: api.github.com
    path: /graphql
    methods: [POST]              # only POST allowed
  - host: pypi.org
    path: /simple*
    methods: [GET, HEAD]         # read-only access
  - host: api.github.com
    path: /repos/org/repo*       # no methods field = all methods allowed
```

**Rules:**

- `methods` is an optional list of HTTP method strings (e.g., `GET`, `POST`,
  `HEAD`, `PUT`, `DELETE`, `PATCH`)
- Omitting `methods` or setting it to an empty list allows all methods
- Method comparison is case-insensitive (`get` and `GET` are equivalent)
- Domain entries (`domains` section) always allow all methods — use
  `url_prefixes` if you need method restrictions
- The 403 response distinguishes method-blocked from host/path-blocked requests,
  so agents get actionable feedback

#### GraphQL Operation Filtering

GraphQL APIs collapse all operations into a single URL endpoint
(`POST /graphql`), making URL-level filtering insufficient to distinguish
between safe reads and dangerous mutations. The optional `graphql` block on URL
prefix entries provides default-deny filtering of GraphQL operations by type
(query, mutation, subscription) and top-level field name:

```yaml
url_prefixes:
  - host: api.github.com
    path: /graphql
    methods: [POST]
    graphql:
      queries:
        - "*"                          # allow all queries
      mutations:
        - createIssue
        - createPullRequest
        - updatePullRequest
        - mergePullRequest
      # subscriptions: omitted = blocked
```

**Rules:**

- `graphql` is optional. Omitting it disables operation filtering (backwards
  compatible)
- Each operation type (`queries`, `mutations`, `subscriptions`) is an optional
  list of fnmatch patterns. Omitted or empty lists block all operations of that
  type (default-deny)
- Pattern matching is case-sensitive (GraphQL field names are case-sensitive per
  the GraphQL spec)
- The same `fnmatch.fnmatch()` wildcards as host/path matching are supported:
  `"*"` (all), `"create*"` (prefix), `"*PullRequest"` (suffix)
- Fail-secure: parse errors, batched queries, fragment spreads at the operation
  root, and any ambiguous structure result in a block
- Blocked requests return HTTP 403 with `error: "graphql_operation_blocked"`

For GitHub App credentials, this acts as Layer 1 in a two-layer defense. Layer 2
([GraphQL Repository Scoping](#graphql-repository-scoping)) ensures that allowed
mutations target only permitted repositories. See
[spec/graphql-operation-allowlist.md](../spec/graphql-operation-allowlist.md)
for the full specification.

#### Wildcard Host for Credential-Only Sandboxing

If the sandbox is used primarily for
[credential masking](#masked-secrets-token-replacement) and the repository
contains only public material, you can allow read-only access to all domains
while restricting write methods to specific hosts:

```yaml
url_prefixes:
  # Read-only access to all domains
  - host: "*"
    path: ""
    methods: [GET, HEAD]

  # Write access only where needed
  - host: api.anthropic.com
    path: /v1/messages*
    methods: [POST]
  - host: api.github.com
    path: /graphql
    methods: [POST]
```

**How it works:** `host: "*"` matches any hostname (via fnmatch). The proxy
checks entries sequentially — if the wildcard entry rejects a method, later
entries for specific hosts can still allow it. Domain entries (`domains`
section) are checked first and allow all methods unconditionally, so they
override the wildcard restriction.

**Security note:** This opens read access to the entire internet from the
sandbox. A compromised agent could exfiltrate data via GET query parameters or
URL paths to any domain. This is acceptable when the repository contains only
public material and the sandbox is used solely to protect credentials via masked
secrets, signing credentials, or GitHub App credentials.

### Agent Self-Service Flow

When the agent encounters a blocked request:

1. Proxy returns HTTP 403 with JSON explaining the block
2. Agent edits `.airut/network-allowlist.yaml` to add the needed host
3. Agent commits, pushes, and creates a PR
4. Human reviews and merges
5. Next task reads the updated allowlist from the default branch

This flow lets agents discover and request access to new resources while keeping
humans in the approval loop.

## Masked Secrets (Token Replacement)

The network allowlist controls *where* the agent can connect. Masked secrets
control *what credentials* are usable at each destination. Together they provide
layered protection against credential exfiltration.

### Problem

Even with a network allowlist, a compromised container could exfiltrate
credentials to allowed hosts:

- Send `GH_TOKEN` to a GitHub issue on a repo the attacker controls
- Embed credentials in request parameters to an allowed API
- Use an allowed webhook endpoint to leak secrets

Plain secrets in the `secrets` pool are fully exposed to the container — if the
agent is tricked via prompt injection, it can read and exfiltrate them.

### Solution

Masked secrets inject **surrogate tokens** into containers instead of real
credentials. The proxy swaps surrogates for real values only when the request
host matches configured scopes.

```yaml
# In ~/.config/airut/airut.yaml (server config)
repos:
  my-project:
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
          - "github.com"
          - "api.github.com"
          - "*.githubusercontent.com"
        headers:
          - "Authorization"
```

**How it works:**

1. Server generates a format-preserving surrogate (same length, charset, known
   prefix like `ghp_`) using `secrets.choice()`
2. Container receives the surrogate in its environment — never the real value
3. Proxy intercepts outbound requests to scoped hosts
4. For matching requests, proxy swaps surrogate → real value in specified
   headers
5. Requests to other hosts see only the useless surrogate

### Security Properties

| Property                    | Mechanism                                       |
| --------------------------- | ----------------------------------------------- |
| Credential isolation        | Container only sees surrogates, never real keys |
| Scope enforcement           | Proxy only replaces for matching hosts          |
| Exfiltration prevention     | Surrogate useless at unauthorized endpoints     |
| Foreign credential blocking | Non-surrogate credential headers are stripped   |
| Fail-secure                 | If proxy fails, no credentials reach network    |
| Audit trail                 | Network log shows `[masked: N]` for requests    |
| Log safety                  | Real values redacted; surrogates visible        |

### Foreign credential blocking

By default, if a request to a scoped host contains a credential header that does
NOT match the expected surrogate, the header is stripped entirely. This prevents
an attacker from supplying their own API key (e.g., to upload data to their
account on an allowlisted service). Stripping only applies when the header
matches an **exact** header pattern (e.g., `"Authorization"`); glob patterns
like `"*"` or `"X-*"` scan for surrogates but do not trigger stripping. Set
`allow_foreign_credentials: true` on a per-secret basis to opt out of this
protection.

### Limitations

1. **Header-only replacement**: Tokens in request body or query parameters are
   not replaced. Use plain `secrets` if body tokens are required.
2. **Requires sandbox**: When the sandbox is disabled, surrogates are still
   injected but never swapped — API calls using masked secrets will fail.

### When to Use

Use `masked_secrets` for credentials that are used via `Authorization`,
`X-Api-Key`, or `X-Auth-Token` headers and should only be usable with specific
hosts. Use plain `secrets` for credentials passed in request bodies or that need
to work with arbitrary hosts.

**For GitHub tokens specifically**, prefer
[`github_app_credentials`](#github-app-credentials-proxy-managed-token-rotation)
over `masked_secrets` with a classic PAT. Masked secrets provide no protection
against data exfiltration via public repositories — the proxy performs simple
string replacement without inspecting request bodies, so a compromised agent can
use a PAT to create issues, comments, or other mutations on any accessible
public repository. GitHub App credentials eliminate this risk through
short-lived tokens, fine-grained permissions (no repository creation), and
[GraphQL repository scoping](#graphql-repository-scoping) that blocks mutations
targeting out-of-scope repositories.

See [spec/masked-secrets.md](../spec/masked-secrets.md) for the full
specification (surrogate format, replacement map, proxy addon details).

## Signing Credentials (AWS SigV4 Re-signing)

Masked secrets handle credentials that appear verbatim in headers (bearer
tokens, API keys). AWS credentials are different — the secret key is used to
compute HMAC or ECDSA signatures over the request and never appears on the wire.
Signing credentials extend the proxy to **re-sign** requests instead of
performing string replacement.

### Problem

If you pass AWS credentials as plain secrets, the container has the real access
key ID, secret access key, and session token. A compromised container could
exfiltrate these to any allowed host, and the attacker gains full access to
whatever AWS resources the credentials allow.

Masked secrets don't solve this either — AWS SDKs don't send the secret key in
headers, so there's nothing to replace.

### Solution

`signing_credentials` in the server config inject **surrogate** AWS credentials
into the container. The AWS SDK signs requests normally using the surrogates.
The proxy then:

1. Intercepts requests to scoped hosts (e.g., `*.amazonaws.com`)
2. Verifies the request was signed with the surrogate credentials
3. Re-signs the request with the real credentials
4. Forwards the correctly-signed request upstream

```yaml
# In ~/.config/airut/airut.yaml (server config)
repos:
  my-project:
    signing_credentials:
      AWS_PROD:
        type: aws-sigv4
        access_key_id:
          name: AWS_ACCESS_KEY_ID        # env var name injected into container
          value: !env AWS_ACCESS_KEY_ID
        secret_access_key:
          name: AWS_SECRET_ACCESS_KEY
          value: !env AWS_SECRET_ACCESS_KEY
        session_token:                   # optional (STS temporary credentials)
          name: AWS_SESSION_TOKEN
          value: !env AWS_SESSION_TOKEN
        scopes:
          - "*.amazonaws.com"
```

The container receives surrogate env vars (`AWS_ACCESS_KEY_ID`, etc.)
auto-injected from the signing credential `.name` fields. The proxy re-signs
requests with the real credentials for scoped hosts.

### What Gets Re-signed

| Authentication method | Where credentials appear        | Re-signed |
| --------------------- | ------------------------------- | --------- |
| Authorization header  | `AWS4-HMAC-SHA256 Credential=…` | Yes       |
| Presigned URL         | `X-Amz-Credential=…` in query   | Yes       |
| Chunked upload        | Per-chunk signatures in body    | Yes       |
| SigV4A (multi-region) | `AWS4-ECDSA-P256-SHA256` header | Yes       |

### Security Properties

| Property                | Mechanism                                                          |
| ----------------------- | ------------------------------------------------------------------ |
| Secret key isolation    | Container never sees real secret key                               |
| Scope enforcement       | Proxy only re-signs for matching hosts                             |
| Exfiltration resistance | Surrogate credentials are useless outside the proxy                |
| Contained blast radius  | Attacker can act within scope but only through proxy               |
| Fail-secure             | If proxy fails, surrogates are not valid AWS credentials           |
| Audit trail             | Network log shows `[masked: 1] [region: …]` for re-signed requests |
| S3-compatible           | Works with AWS, Cloudflare R2, MinIO, any SigV4 service            |

### Limitations

1. **SigV4/SigV4A only**: Only AWS-style HMAC-SHA256 and ECDSA-P256 signing is
   supported. Other signing protocols (e.g., GCP, Azure) are not covered.
2. **Requires sandbox**: Like masked secrets, signing credentials depend on the
   proxy. When the sandbox is disabled, the container has surrogate credentials
   that fail to authenticate.

### Transparent Upgrade Path

The server admin can switch between plain secrets and signing credentials by
changing only the server config.

See [spec/aws-sigv4-resigning.md](../spec/aws-sigv4-resigning.md) for the full
specification (surrogate generation, re-signing algorithm, chunked transfer
encoding, data flow).

## GitHub App Credentials (Proxy-Managed Token Rotation)

Masked secrets handle credentials that appear as static tokens in headers.
GitHub App credentials extend the proxy to manage the full token lifecycle --
generating short-lived installation tokens from a private key and rotating them
automatically.

### Problem

Even with masked secrets, GitHub API responses can echo the authentication token
back in the response body. The proxy only scrubs outbound request headers, not
inbound response bodies. If a classic PAT is used as a masked secret, a
compromised container can extract the real PAT from a GitHub API response. Since
classic PATs are long-lived (months to years), this provides persistent access
beyond the sandbox session.

Additionally, classic PATs cannot prevent repository creation. A compromised
agent could create public repositories under the dedicated user's account via
the GraphQL endpoint and leak information through repository names or
descriptions -- even with the network allowlist restricting which hosts the
agent can push to.

### Solution

`github_app_credentials` in the server config inject a **surrogate** `ghs_`
token into the container. The proxy holds the GitHub App's RSA private key and
manages installation tokens:

1. Container sends a request with the surrogate in the `Authorization` header.
   The surrogate may appear as a **Bearer token** (`Bearer ghs_...`) for API
   calls, or inside **Basic Auth** (`Basic base64(x-access-token:ghs_...)`) for
   git operations via credential helpers.
2. Proxy detects the surrogate and checks scope match
3. Proxy generates a JWT from the private key (in-memory, never written to disk)
4. Proxy exchanges the JWT for a short-lived installation token (1-hour expiry)
5. Proxy caches the token and reuses it until near expiry (5-minute margin)
6. Proxy replaces the surrogate with the real installation token in the header.
   For Basic Auth, the proxy decodes the Base64 payload, replaces the surrogate
   in the password field, and re-encodes — the same mechanism used for
   [masked secrets](../spec/masked-secrets.md#basic-auth-support).
7. Request goes to GitHub with a valid, short-lived token

```yaml
# In ~/.config/airut/airut.yaml (server config)
repos:
  my-project:
    github_app_credentials:
      GH_TOKEN:
        app_id: !env GH_APP_ID
        private_key: !env GH_APP_PRIVATE_KEY
        installation_id: !env GH_APP_INSTALLATION_ID
        scopes:
          - "github.com"
          - "api.github.com"
          - "*.githubusercontent.com"
        # Optional: restrict token permissions
        permissions:
          contents: write
          pull_requests: write
        # Optional: restrict token to specific repos
        repositories:
          - "my-repo"
```

The container receives a surrogate `GH_TOKEN` env var auto-injected from the
GitHub App credential key name. The proxy replaces the surrogate with a
short-lived installation token for scoped hosts.

### Security Properties

| Property                    | Mechanism                                                  |
| --------------------------- | ---------------------------------------------------------- |
| Private key isolation       | Key only in proxy container, never in client container     |
| Short-lived tokens          | Installation tokens expire in 1 hour                       |
| No token escalation         | Leaked token cannot generate new tokens (requires JWT)     |
| No repository creation      | GitHub Apps cannot create repos without explicit grant     |
| Surrogate stability         | Container sees unchanging surrogate for entire session     |
| Scope enforcement           | Proxy only replaces for matching hosts                     |
| Foreign credential blocking | Non-surrogate Authorization headers stripped by default    |
| Fail-secure                 | If proxy fails, surrogate is not a valid token             |
| Audit trail                 | Network log shows `[github-app: cached/refreshed]`         |
| No new dependencies         | Uses `cryptography` (existing) + `urllib.request` (stdlib) |

### Comparison With Masked Secrets

| Aspect                    | Masked Secret (PAT)      | GitHub App Credential             |
| ------------------------- | ------------------------ | --------------------------------- |
| Token lifetime            | Months/years (or never)  | 1 hour                            |
| Token rotation            | None (static value)      | Automatic (proxy-managed)         |
| Real token in container   | Never (surrogate)        | Never (surrogate)                 |
| Proxy complexity          | Stateless string replace | Stateful (cache + HTTP refresh)   |
| Network call from proxy   | None                     | 1 call per hour to GitHub API     |
| Response echo risk        | High (PAT valid forever) | Low (token expires in 1 hour)     |
| Repository creation risk  | Cannot prevent           | Impossible without explicit grant |
| Public repo mutation risk | No protection            | Blocked by GraphQL repo scoping   |

### GraphQL Repository Scoping

GitHub App installation tokens can perform certain mutations (e.g.,
`createIssue`) on **any public repository** where issues are enabled, regardless
of App installation scope. The proxy provides two layers of GraphQL defense:

**Layer 1: Operation allowlist** (generic, via
[`graphql` block](#graphql-operation-filtering)). Default-deny filtering that
blocks entire classes of dangerous mutations (e.g., `deleteRepository`,
`addComment`) before they reach credential-specific checks. Mutations that
accept non-`repositoryId` targeting fields (e.g., `addComment` with `subjectId`)
are simply not listed in the operation allowlist — the agent uses REST API
equivalents where URL-level path scoping naturally restricts repository access.

**Layer 2: Repository scope checking** (GitHub-specific). For mutations that
Layer 1 allows (e.g., `createIssue`, `createPullRequest`), the proxy performs
two scope checks:

1. **`repositoryId` field check** — Parses the GraphQL query AST (via
   `graphql-core`) and scans JSON variables to extract all `repositoryId`
   values, blocking requests targeting repos outside the configured set with
   HTTP 403.
2. **Node ID ownership check** — Extracts values from all `*Id`/`*Ids`-suffixed
   input fields and arguments (`subjectId`, `pullRequestId`, `labelIds`, etc.),
   including list values and recursively nested variable objects, decodes GitHub
   node IDs to extract the embedded parent repository database ID, and verifies
   ownership against the allowed repository set. This catches mutations that
   target repo-scoped objects without an explicit `repositoryId` field.

Additionally, GraphQL requests with URL query parameters are rejected outright
to prevent bypass of body-based scope checking.

Node IDs of allowed repositories are resolved at token refresh time via
`GET /installation/repositories`. No additional API calls are made for request
inspection — node ID decoding is pure local computation. See
[spec/graphql-operation-allowlist.md](../spec/graphql-operation-allowlist.md)
for the operation allowlist specification and
[spec/github-app-credential.md](../spec/github-app-credential.md) for the
repository scoping specification.

### Limitations

1. **Stateful**: Requires network access from the proxy container to the GitHub
   API for token refresh. If the proxy cannot reach GitHub, token refresh fails
   and requests return HTTP 502.
2. **Requires sandbox**: Like masked secrets, GitHub App credentials depend on
   the proxy. When the sandbox is disabled, the container receives a surrogate
   that is not a valid token.
3. **GitHub-specific**: This credential type only works with GitHub (and GHES).
   For other services, use `masked_secrets` or `signing_credentials`.

### When to Use

For GitHub API access, prefer `github_app_credentials` over `masked_secrets`
with a classic PAT. The short-lived tokens mitigate the response echo risk, the
fine-grained permissions eliminate repository creation as an exfiltration
vector, and [GraphQL repository scoping](#graphql-repository-scoping) blocks
mutations targeting out-of-scope public repositories. Masked secrets provide no
protection against public repository mutations — the proxy performs simple
string replacement without inspecting request bodies, so a compromised agent can
use a PAT to create issues or comments on any public repository as an
exfiltration channel.

Use `masked_secrets` for non-GitHub tokens (e.g., other API keys) and
`signing_credentials` for AWS credentials.

See [github-app-setup.md](github-app-setup.md) for the setup guide and
[spec/github-app-credential.md](../spec/github-app-credential.md) for the full
specification.

## Troubleshooting

### Broken allowlist checked into main

If a broken `.airut/network-allowlist.yaml` gets merged to the default branch
(e.g., required domains were removed), use the server-side sandbox override to
temporarily disable the sandbox:

```yaml
# In ~/.config/airut/airut.yaml
repos:
  my-project:
    network:
      sandbox_enabled: false
```

The change takes effect automatically via live config reload (once in-flight
tasks complete). With the sandbox disabled, the agent has unrestricted network
access and can create a PR to fix the allowlist. After the fix merges, re-enable
the sandbox by removing the override (or setting it back to `true`).

### Masked secrets stopped working

If API calls that previously worked start failing with authentication errors,
check whether the sandbox was disabled:

1. Check server config: `network.sandbox_enabled` under the repo's section

Masked secrets require the proxy to swap surrogates for real values. When the
sandbox is disabled, the proxy doesn't start, and the container receives
surrogates that are not valid credentials. Look for this log warning:

> Network sandbox is disabled but masked secrets are configured.

**Fix**: Either re-enable the sandbox, or temporarily move credentials from
`masked_secrets`/`signing_credentials` to `secrets` (plain injection) in server
config.

### Debugging container network issues

When investigating connectivity problems from inside a container:

1. **Prefer the server-side override** — set `network.sandbox_enabled: false` in
   server config. The change takes effect via live reload once in-flight tasks
   complete. This avoids modifying the repo.
2. After debugging, re-enable the sandbox (the change applies via live reload).
3. Check `conversation_dir/network-sandbox.log` for the audit trail of allowed
   and blocked requests from previous tasks.

## Further Reading

- [spec/network-sandbox.md](../spec/network-sandbox.md) — Implementation details
  (network topology, proxy lifecycle, resource scoping, log format, crash
  recovery)
- [spec/masked-secrets.md](../spec/masked-secrets.md) — Full masked secrets
  specification
- [spec/aws-sigv4-resigning.md](../spec/aws-sigv4-resigning.md) — AWS
  SigV4/SigV4A re-signing specification
- [spec/graphql-operation-allowlist.md](../spec/graphql-operation-allowlist.md)
  — GraphQL operation filtering specification
- [spec/github-app-credential.md](../spec/github-app-credential.md) — GitHub App
  credential specification
- [github-app-setup.md](github-app-setup.md) — GitHub App setup guide
- [ci-sandbox.md](ci-sandbox.md) — Using the sandbox for CI pipelines
- [execution-sandbox.md](execution-sandbox.md) — Container isolation
- [security.md](security.md) — Overall security model
