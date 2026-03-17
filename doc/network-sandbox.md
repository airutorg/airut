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
  - [Agent Self-Service Flow](#agent-self-service-flow)
- [Masked Secrets (Token Replacement)](#masked-secrets-token-replacement)
- [Signing Credentials (AWS SigV4 Re-signing)](#signing-credentials-aws-sigv4-re-signing)
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

**Combined with masked secrets and signing credentials** (see
[Masked Secrets](#masked-secrets-token-replacement) and
[Signing Credentials](#signing-credentials-aws-sigv4-re-signing)), real
credentials never enter the container — they stay with the proxy and are only
inserted into upstream requests to scoped hosts. A compromised container can
still make authenticated requests to scoped hosts through the proxy, but cannot
extract the real credentials for use elsewhere. The attacker's ability to act is
bound to the container's lifetime and the proxy's scope — once the container
stops, the credentials are inaccessible.

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

The network sandbox is controlled at two levels. Both default to `true`; the
effective value is the **logical AND** — if either is `false`, the sandbox is
disabled.

**Repo config** (`.airut/airut.yaml`):

```yaml
network:
  sandbox_enabled: true  # default; set to false to disable (break-glass)
```

**Server config** (`~/.config/airut/airut.yaml`, per-repo):

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

Even with a network allowlist, a compromised container could exfiltrate plain
secrets to allowed hosts (e.g., embed a token in a GitHub issue on an
attacker-controlled repo). Masked secrets close this gap: the container receives
a **surrogate token** instead of the real credential, and the proxy swaps
surrogates for real values only when the request host matches configured scopes.
Requests to other hosts carry only the useless surrogate.

```yaml
# In ~/.config/airut/airut.yaml (server config)
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

Use `masked_secrets` for credentials sent via `Authorization`, `X-Api-Key`, or
similar headers that should only be usable with specific hosts. Use plain
`secrets` for credentials passed in request bodies or that need to work with
arbitrary hosts. Both require the network sandbox to be enabled — when disabled,
surrogates are still injected but never swapped, so API calls will fail.

See [security.md](security.md#credential-management) for how masked secrets fit
into the overall credential model and
[spec/masked-secrets.md](../spec/masked-secrets.md) for the full specification
(surrogate format, foreign credential blocking, replacement map).

## Signing Credentials (AWS SigV4 Re-signing)

AWS credentials are different from bearer tokens — the secret key is used to
compute HMAC/ECDSA signatures and never appears in headers. Masked secrets can't
handle this since there's no literal token to replace. Signing credentials
extend the proxy to **re-sign** requests: the container receives surrogate AWS
credentials, the AWS SDK signs normally, and the proxy re-signs with real
credentials for scoped hosts.

```yaml
# In ~/.config/airut/airut.yaml (server config)
repos:
  my-project:
    signing_credentials:
      AWS_PROD:
        type: aws-sigv4
        access_key_id:
          name: AWS_ACCESS_KEY_ID
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

The repo config uses standard `!secret` references — it doesn't need to know
whether signing credentials are involved. The server admin can switch between
plain secrets and signing credentials without any repo config changes.

Re-signing covers Authorization headers, presigned URLs, chunked uploads (S3
`aws-chunked`), and SigV4A (multi-region). Works with any S3-compatible API
(AWS, Cloudflare R2, MinIO).

See [security.md](security.md#credential-management) for how signing credentials
fit into the overall credential model and
[spec/aws-sigv4-resigning.md](../spec/aws-sigv4-resigning.md) for the full
specification (surrogate generation, re-signing algorithm, chunked transfer).

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
`masked_secrets`/`signing_credentials` to `secrets` (plain injection) in server
config.

### Debugging container network issues

When investigating connectivity problems from inside a container:

1. **Prefer the server-side override** — set `network.sandbox_enabled: false` in
   server config and restart the server. This avoids modifying the repo.
2. After debugging, re-enable the sandbox and restart.
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
- [ci-sandbox.md](ci-sandbox.md) — Using the sandbox for CI pipelines
- [execution-sandbox.md](execution-sandbox.md) — Container isolation
- [security.md](security.md) — Overall security model
