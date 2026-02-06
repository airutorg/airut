# Network Sandbox

The network sandbox restricts Claude Code container network access to a
configurable set of trusted hosts, mitigating data exfiltration risk from prompt
injection attacks. It works by routing all HTTP(S) traffic through a mitmproxy
instance that enforces an allowlist.

> **Terminology**: "Network sandbox" refers to the overall isolation concept.
> "Network allowlist" is the configuration specifying permitted hosts. "Proxy"
> (mitmproxy) is the enforcement mechanism.

## Threat Model

Claude Code containers execute arbitrary code on behalf of the agent. A prompt
injection attack — malicious instructions embedded in fetched content (web
pages, API responses, imported files) — could direct the agent to exfiltrate
sensitive data (credentials, ledger data, API keys) to attacker-controlled
servers.

The network sandbox breaks this exfiltration path: even if the agent is tricked
into making a request, it can only reach pre-approved hosts.

**Combined with masked secrets** (see
[below](#masked-secrets-token-replacement)), credentials can be scoped to
specific hosts at the proxy level. Even if an attacker tricks the agent into
sending credentials to an allowed host they control, the surrogate token is
useless — real values only appear for requests to scoped domains.

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

**DNS exfiltration**: Podman's `--internal` network flag configures aardvark-dns
to resolve only container names on the same network. External DNS queries (e.g.,
`<secret>.attacker.com`) return NXDOMAIN. The container cannot encode data into
DNS queries because no external DNS resolution is available.

**Proxy admin interface**: The proxy uses `mitmdump` (not `mitmweb`), so no web
interface exists. Only port 8080 is exposed. Additionally, requests to the
proxy's own hostname are filtered by the allowlist — the proxy checks ALL
requests, including those addressed to itself.

**Redirect following**: The proxy operates as a client-driven proxy, not a
server-side redirect follower. When an allowed domain returns a 301/302
redirect, the proxy returns that response to the client. The client then makes a
*new* request to the redirect target, which is checked against the allowlist
independently. Redirects to blocked domains result in a 403.

### Limitations

The sandbox currently supports **HTTP(S) traffic only**. Other protocols (raw
TCP, SSH, etc.) are blocked entirely by the isolated network — the container
simply cannot establish non-HTTP connections. Supporting additional protocols is
a potential future extension.

To disable the sandbox entirely for debugging or emergencies, set
`sandbox_enabled: false` in either the repo config (`.airut/airut.yaml`) or
server config (`config/airut.yaml`). See Configuration below.

## Architecture

The Airut service manages sandbox infrastructure automatically — no separate
setup required. On startup, it creates networks, builds the proxy image, and
generates the CA certificate. The implementation uses rootless Podman, so no
root privileges are needed.

```
┌──────────────────────────────────────────────────────────────┐
│  Podman network: airut-task-{id} (--internal, per-task)      │
│                                                              │
│  ┌────────────────┐       ┌──────────────────────┐           │
│  │  Claude Code   │──────▶│  airut-proxy-{id}    │─┐         │
│  │  container     │ :8080 │  (mitmdump)          │ │         │
│  └────────────────┘       └──────────────────────┘ │         │
└────────────────────────────────────────────────────┼─────────┘
                              ┌──────────────────────┼─────────┐
                              │  Podman network:               │
                              │  airut-egress (internet)       │
                              └────────────────────────────────┘
```

Each task gets its own internal network and proxy container, providing complete
isolation between concurrent tasks:

- **`airut-task-{id}`** (`--internal`): Per-task network. The Claude Code
  container and its proxy are the only members. The `--internal` flag blocks
  direct internet access.
- **`airut-egress`**: Shared egress network. Only proxy containers connect here,
  giving them internet access to forward allowed requests.

### Request Flow

1. Container makes HTTP(S) request via `HTTP_PROXY`/`HTTPS_PROXY` env vars
2. mitmproxy terminates TLS (container trusts the mitmproxy CA)
3. Allowlist addon checks host + path against configuration
4. **Allowed**: Request forwarded to the internet
5. **Blocked**: HTTP 403 returned with instructions on how to request access

### Components

| Component                       | Purpose                                       |
| ------------------------------- | --------------------------------------------- |
| `.airut/network-allowlist.yaml` | Allowlist configuration (domains + URLs)      |
| `docker/proxy.dockerfile`       | Proxy container image (slim + mitmproxy)      |
| `docker/proxy-filter.py`        | mitmproxy addon for allowlist + token masking |
| `lib/container/network.py`      | Podman args for sandbox integration           |
| `lib/container/proxy.py`        | Per-task proxy lifecycle management           |

## Configuration

### Enabling/Disabling the Sandbox

The network sandbox is controlled at two levels. Both default to `true`; the
effective value is the **logical AND** — if either is `false`, the sandbox is
disabled.

**Repo config** (`.airut/airut.yaml`):

```yaml
network:
  sandbox_enabled: true  # default; set to false to disable (break-glass)
```

**Server config** (`config/airut.yaml`, per-repo):

```yaml
repos:
  my-project:
    network:
      sandbox_enabled: true  # default; set to false to override repo config
```

| Server config | Repo config | Effective |
| ------------- | ----------- | --------- |
| `true`        | `true`      | **true**  |
| `true`        | `false`     | **false** |
| `false`       | `true`      | **false** |
| `false`       | `false`     | **false** |

When disabled, containers get unrestricted network access without the proxy.
**Use only for debugging or emergencies** — this removes the exfiltration
protection.

The server-side setting is useful as a **break-glass** for operators: if the
agent corrupts the network allowlist in the repo, the operator can disable the
sandbox server-side immediately without waiting for a repo config fix to merge.

When the sandbox is disabled, a warning is logged indicating which config layer
disabled it. If masked secrets are configured, an additional warning is logged
because masked secrets depend on the proxy (see
[Masked Secrets](#masked-secrets-token-replacement)).

### Network Allowlist

The allowlist at `.airut/network-allowlist.yaml` defines permitted hosts using
fnmatch-style pattern matching:

```yaml
# Domain entries: all paths allowed
domains:
  - api.anthropic.com      # exact match
  - "*.github.com"         # matches api.github.com, NOT github.com

# URL pattern entries: host + path pattern required
url_prefixes:
  - host: api.github.com
    path: /repos/your-org/your-repo*   # matches /repos/your-org/your-repo and subpaths
  - host: api.github.com
    path: /graphql                 # exact match only
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

- No implicit prefix matching — use explicit `*` for prefix behavior
- `*.example.com` does NOT match `example.com` (requires subdomain)
- No path normalization — `/api` and `/api/` are different patterns
- Empty path in `url_prefixes` allows all paths on that host

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

Plain secrets in `container_env` are fully exposed to the container — if the
agent is tricked via prompt injection, it can read and exfiltrate them.

### Solution

Masked secrets inject **surrogate tokens** into containers instead of real
credentials. The proxy swaps surrogates for real values only when the request
host matches configured scopes.

```yaml
# In config/airut.yaml (server config)
repos:
  my-project:
    masked_secrets:
      GH_TOKEN:
        value: !env GH_TOKEN
        scopes:
          - "api.github.com"
          - "*.githubusercontent.com"
```

**How it works:**

1. Container receives a surrogate token (random, format-preserving)
2. Proxy intercepts outbound requests
3. For requests to scoped hosts, proxy swaps surrogate → real value in headers
4. Requests to other hosts see only the useless surrogate

### Security Properties

| Property                | Mechanism                                       |
| ----------------------- | ----------------------------------------------- |
| Credential isolation    | Container only sees surrogates, never real keys |
| Scope enforcement       | Proxy only replaces for matching hosts          |
| Exfiltration prevention | Surrogate useless at unauthorized endpoints     |
| Fail-secure             | If proxy fails, no credentials reach network    |
| Audit trail             | Network log shows `[masked: N]` for requests    |
| Log safety              | Real values redacted; surrogates visible        |

### Surrogate Generation

Surrogates mimic the original token's format to avoid breaking client-side
validation:

- **Exact length** preserved
- **Character set** preserved (uppercase, lowercase, digits, special)
- **Known prefixes** preserved (`ghp_`, `sk-ant-`, `gho_`, `sk-`, etc.)

Example:

```
Original:  ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Surrogate: ghp_a8f2k9m3b7c1d4e6g5h0j2l8n4p6q9r3s7t1
```

Surrogates are generated with `secrets.choice()` (cryptographically secure) and
are uncorrelated with the original value.

### Headers Replaced

Headers to scan are specified per masked secret using fnmatch patterns. Matching
is **case-insensitive** per RFC 7230 (e.g., `"Authorization"` matches
`authorization`, `AUTHORIZATION`, etc.):

```yaml
masked_secrets:
  # Match only Authorization header
  GH_TOKEN:
    value: !env GH_TOKEN
    scopes: ["api.github.com"]
    headers: ["Authorization"]

  # Match all headers
  UNIVERSAL_TOKEN:
    value: !env UNIVERSAL_TOKEN
    scopes: ["api.example.com"]
    headers: ["*"]

  # GitLab-style header
  GITLAB_TOKEN:
    value: !env GITLAB_TOKEN
    scopes: ["gitlab.com"]
    headers: ["Private-Token"]
```

### Basic Auth Support

For `Authorization` headers, the proxy handles both Bearer tokens and
Base64-encoded Basic Auth. This enables git operations which use Basic Auth:

```
git push → Authorization: Basic <base64("x-access-token:ghp_surrogate...")>
         → proxy decodes, replaces surrogate, re-encodes
         → Authorization: Basic <base64("x-access-token:ghp_realtoken...")>
```

### Limitations

1. **Header-only replacement**: Tokens in request body or query parameters are
   not replaced. Use plain `secrets` if body tokens are required.

2. **No response masking**: Real tokens are never sent to the container. If a
   service echoes tokens in responses, they would be visible (but still redacted
   in logs).

### Configuration

Repo config (`.airut/airut.yaml`) references secrets by name, unaware of whether
they're masked or plain:

```yaml
container_env:
  GH_TOKEN: !secret GH_TOKEN           # Required (error if missing)
  API_KEY: !secret? API_KEY            # Optional (skip if missing)
```

The server determines at resolution time whether a secret is masked or plain.
This separation means repos declare what they need; operators control how
credentials are protected.

### When to Use Masked Secrets

Use `masked_secrets` for credentials that:

- Are used via `Authorization`, `X-Api-Key`, or `X-Auth-Token` headers
- Should only be usable with specific hosts (e.g., GitHub tokens for GitHub
  APIs)
- Carry high exfiltration risk if exposed

Use plain `secrets` for credentials that:

- Are passed in request bodies (not headers)
- Need to work with arbitrary hosts
- Are low-sensitivity (e.g., public API keys)

See `spec/masked-secrets.md` for the full specification.

## Implementation Details

### CA Certificate Trust

mitmproxy intercepts HTTPS by terminating TLS with its own CA. All tools in the
container must trust this CA:

| Tool/Library         | Trust mechanism                        |
| -------------------- | -------------------------------------- |
| Node.js (Claude CLI) | `NODE_EXTRA_CA_CERTS` env var          |
| Python requests      | `REQUESTS_CA_BUNDLE` env var           |
| Python ssl module    | `SSL_CERT_FILE` env var                |
| curl                 | `CURL_CA_BUNDLE` env var               |
| git, uv, system      | `update-ca-certificates` in entrypoint |

### Session Network Logging

Network activity is logged to `session_dir/network-sandbox.log` for each task.
This provides an audit trail of all allowed and blocked requests:

```
=== TASK START 2026-02-03T12:34:56Z ===
allowed GET https://api.github.com/repos/your-org/your-repo/pulls -> 200 [masked: 1]
BLOCKED GET https://evil.com/exfiltrate -> 403
allowed POST https://api.anthropic.com/v1/messages -> 200 [masked: 1]
```

The `[masked: N]` suffix indicates that N masked secret tokens were replaced in
that request. See [Masked Secrets](#masked-secrets-token-replacement) above for
details.

The log file is created in the session directory and persists with the session.
It is cleaned up automatically when sessions are pruned.

### Proxy Lifecycle

The proxy is managed by `ProxyManager` in `lib/container/proxy.py`:

**Gateway lifecycle** (shared resources):

- On startup: clean orphans, build image, ensure CA cert, create egress network
- On shutdown: stop task proxies, remove egress network

**Task lifecycle** (per-task resources):

- `start_task_proxy()`: create internal network, start proxy container, health
  check
- `stop_task_proxy()`: remove container and network

### Resource Scoping

| Resource                             | Scope   | Created                  | Destroyed           |
| ------------------------------------ | ------- | ------------------------ | ------------------- |
| Egress network (`airut-egress`)      | Gateway | `startup()`              | `shutdown()`        |
| Proxy image (`airut-proxy`)          | Gateway | `startup()`              | Never (cached)      |
| CA certificate                       | Gateway | `startup()` (if missing) | Never               |
| Internal network (`airut-task-{id}`) | Task    | `start_task_proxy()`     | `stop_task_proxy()` |
| Proxy container (`airut-proxy-{id}`) | Task    | `start_task_proxy()`     | `stop_task_proxy()` |
| Network log (`network-sandbox.log`)  | Task    | `start_task_proxy()`     | Session pruning     |

### Crash Recovery

On startup, `ProxyManager` cleans orphaned resources from previous unclean
shutdowns: containers matching `airut-proxy-*` and networks matching
`airut-task-*` are removed.

## Troubleshooting

### Agent broke the network allowlist

If the agent creates a malformed `.airut/network-allowlist.yaml` that blocks its
own access (e.g., removes required domains), use the server-side sandbox
override to temporarily disable the sandbox:

```yaml
# In config/airut.yaml
repos:
  my-project:
    network:
      sandbox_enabled: false
```

This takes effect on the next task without requiring any repo changes. With the
sandbox disabled, the agent has unrestricted network access and can create a PR
to fix the allowlist. After the fix merges, re-enable the sandbox by removing
the override (or setting it back to `true`).

### Masked secrets stopped working

If API calls that previously worked start failing with authentication errors,
check whether the sandbox was disabled on either side:

1. Check repo config: `network.sandbox_enabled` in `.airut/airut.yaml`
2. Check server config: `network.sandbox_enabled` under the repo's section

Masked secrets require the proxy to swap surrogates for real values. When the
sandbox is disabled, the proxy doesn't start, and the container receives
surrogates that are not valid credentials. Look for this log warning:

> Network sandbox is disabled but masked secrets are configured.

**Fix**: Either re-enable the sandbox, or temporarily move credentials from
`masked_secrets` to `secrets` (plain injection) in server config.

### Debugging container network issues

When investigating connectivity problems from inside a container:

1. **Prefer the server-side override** — set `network.sandbox_enabled: false` in
   server config. This avoids modifying the repo and takes effect immediately on
   the next task.
2. After debugging, re-enable the sandbox.
3. Check `session_dir/network-sandbox.log` for the audit trail of allowed and
   blocked requests from previous tasks.
