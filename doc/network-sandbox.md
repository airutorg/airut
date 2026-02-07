# Network Sandbox

The network sandbox restricts Claude Code container network access to a
configurable set of trusted hosts, mitigating data exfiltration risk from prompt
injection attacks. It works by transparently routing all traffic through an
mitmproxy instance that enforces an allowlist — no `HTTP_PROXY` env vars needed,
so it works with all tools (Node.js, Go, curl, Python, git).

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

**DNS exfiltration**: Podman's default DNS (aardvark-dns) forwards queries to
host resolvers, which would allow encoding stolen data in DNS queries to
attacker-controlled domains. The sandbox replaces this with a custom DNS
responder inside the proxy container that checks each query against the
allowlist: allowed domains resolve to the proxy IP, blocked domains get
NXDOMAIN. No queries are ever forwarded upstream — the DNS responder is
authoritative for all domains. Podman's `--disable-dns` flag prevents
aardvark-dns from running, and `--dns <proxy_ip>` points all container queries
to the custom responder.

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

### Requirements

- **Podman 4.x+** with **netavark** backend (provides `--route` and
  `--disable-dns` flags for `podman network create`)
- Rootless mode — no root privileges required
- No `CAP_NET_ADMIN` needed on any container

### Network Topology

```
┌───────────────────────────────────────────────────────────┐
│  Podman network: airut-task-{id}                          │
│  (--internal, --disable-dns, --route → proxy IP)          │
│                                                           │
│  ┌────────────────┐    DNS    ┌──────────────────────┐    │
│  │  Claude Code   │──────────▶│  airut-proxy-{id}    │─┐  │
│  │  container     │  :80/:443 │  (mitmdump)          │ │  │
│  │  (--dns proxy) │──────────▶│  + dns_responder.py  │ │  │
│  └────────────────┘           └──────────────────────┘ │  │
└────────────────────────────────────────────────────────┼──┘
                              ┌──────────────────────────┼──┐
                              │  Podman network:            │
                              │  airut-egress (internet)    │
                              │  (metric=5, wins over       │
                              │   internal metric=10)       │
                              └─────────────────────────────┘
```

Each task gets its own internal network and proxy container, providing complete
isolation between concurrent tasks:

- **Internal network** (`--internal --disable-dns`): Per-task network with a
  `--route` that sends all client traffic to the proxy. The `--internal` flag
  blocks direct internet access. `--disable-dns` prevents aardvark-dns from
  overriding the client's `--dns` setting.
- **Egress network**: Shared network with internet access. Only proxy containers
  connect here. A lower route metric ensures the egress default route wins over
  the internal route inside the dual-homed proxy.

### Request Flow (Transparent DNS-Spoofing)

1. Container makes a DNS query (e.g., `api.github.com`)
2. The query goes to the proxy IP (set via `--dns` on the container)
3. `dns_responder.py` checks the domain against the allowlist:
   - **Allowed**: Returns the proxy IP as the A record
   - **Blocked**: Returns NXDOMAIN
4. Container connects to the proxy IP on port 80/443
5. mitmproxy in `regular` mode reads SNI (HTTPS) or Host header (HTTP)
6. `proxy-filter.py` checks host + path against the allowlist:
   - **Allowed**: mitmproxy connects upstream and forwards the request
   - **Blocked**: HTTP 403 returned with instructions

### CA Certificate Trust

mitmproxy intercepts HTTPS by terminating TLS with its own CA. The CA
certificate is generated once at gateway startup and mounted into every
container. All tools must trust it — the container entrypoint runs
`update-ca-certificates`, and per-tool env vars (`NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`) are set to cover tools
that don't use the system store.

### Network Logging

Network activity is logged to `session_dir/network-sandbox.log` for each task,
providing a complete audit trail from DNS resolution through HTTP request.
Allowed and blocked requests are both logged. The `[masked: N]` suffix on HTTP
lines indicates masked secret token replacements (see
[Masked Secrets](#masked-secrets-token-replacement) below). Upstream connection
errors are also logged. The log persists with the session and is visible in the
dashboard.

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

When disabled, containers get unrestricted network access without the proxy.
**Use only for debugging or emergencies** — this removes the exfiltration
protection.

The server-side setting is useful as a **break-glass** for operators: if a
broken allowlist gets checked in, the operator can disable the sandbox
server-side while a fix is prepared. Note that server config changes require a
**server restart** to take effect.

When the sandbox is disabled, a warning is logged showing both settings. If
masked secrets are configured, an additional warning is logged because masked
secrets depend on the proxy (see
[Masked Secrets](#masked-secrets-token-replacement)).

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
containers never contact this DNS server — they only talk to `dns_responder.py`.

### Network Allowlist

The allowlist at `.airut/network-allowlist.yaml` defines permitted hosts using
fnmatch-style pattern matching:

```yaml
# Domain entries: all paths and methods allowed
domains:
  - api.anthropic.com      # exact match
  - "*.github.com"         # matches api.github.com, NOT github.com

# URL pattern entries: host + path pattern required, optional method filter
url_prefixes:
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

The proxy also handles **Base64-encoded Basic Auth** (used by git operations):
it decodes the `Authorization: Basic` header, replaces the surrogate, and
re-encodes.

### Security Properties

| Property                | Mechanism                                       |
| ----------------------- | ----------------------------------------------- |
| Credential isolation    | Container only sees surrogates, never real keys |
| Scope enforcement       | Proxy only replaces for matching hosts          |
| Exfiltration prevention | Surrogate useless at unauthorized endpoints     |
| Fail-secure             | If proxy fails, no credentials reach network    |
| Audit trail             | Network log shows `[masked: N]` for requests    |
| Log safety              | Real values redacted; surrogates visible        |

### Limitations

1. **Header-only replacement**: Tokens in request body or query parameters are
   not replaced. Use plain `secrets` if body tokens are required.

2. **No response masking**: Real tokens are never sent to the container. If a
   service echoes tokens in responses, they would be visible (but still redacted
   in logs).

3. **Requires sandbox**: Masked secrets depend on the proxy. When the sandbox is
   disabled, surrogates are still injected but never swapped — API calls using
   masked secrets will fail. Move credentials to plain `secrets` if the sandbox
   must be temporarily disabled.

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

See `spec/masked-secrets.md` for the full specification (surrogate format,
replacement map, proxy addon details).

## Troubleshooting

### Broken allowlist checked into main

If a broken `.airut/network-allowlist.yaml` gets merged to the default branch
(e.g., required domains were removed), use the server-side sandbox override to
temporarily disable the sandbox:

```yaml
# In config/airut.yaml
repos:
  my-project:
    network:
      sandbox_enabled: false
```

After changing server config, **restart the server** for it to take effect. With
the sandbox disabled, the agent has unrestricted network access and can create a
PR to fix the allowlist. After the fix merges, re-enable the sandbox by removing
the override (or setting it back to `true`) and restart again.

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
   server config and restart the server. This avoids modifying the repo.
2. After debugging, re-enable the sandbox and restart.
3. Check `session_dir/network-sandbox.log` for the audit trail of allowed and
   blocked requests from previous tasks.

## Further Reading

- [spec/network-sandbox.md](../spec/network-sandbox.md) — Implementation details
  (proxy lifecycle, resource scoping, log format, crash recovery)
- [spec/masked-secrets.md](../spec/masked-secrets.md) — Full masked secrets
  specification
- [execution-sandbox.md](execution-sandbox.md) — Container isolation
- [security.md](security.md) — Overall security model
