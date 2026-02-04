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
`sandbox_enabled: false` in `.airut/airut.yaml` (see Configuration below).

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

| Component                       | Purpose                                  |
| ------------------------------- | ---------------------------------------- |
| `.airut/network-allowlist.yaml` | Allowlist configuration (domains + URLs) |
| `docker/proxy.dockerfile`       | Proxy container image (slim + mitmproxy) |
| `docker/proxy-allowlist.py`     | mitmproxy addon enforcing the allowlist  |
| `lib/container/network.py`      | Podman args for sandbox integration      |
| `lib/container/proxy.py`        | Per-task proxy lifecycle management      |

## Configuration

### Enabling/Disabling the Sandbox

The network sandbox is controlled via `.airut/airut.yaml`:

```yaml
network:
  sandbox_enabled: true  # default; set to false to disable (break-glass)
```

When disabled, containers get unrestricted network access without the proxy.
**Use only for debugging or emergencies** — this removes the exfiltration
protection.

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
allowed GET https://api.github.com/repos/your-org/your-repo/pulls -> 200
BLOCKED GET https://evil.com/exfiltrate -> 403
allowed POST https://api.anthropic.com/v1/messages -> 200
```

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
