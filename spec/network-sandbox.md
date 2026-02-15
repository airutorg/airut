# Network Sandbox

Implementation details for the network sandbox proxy infrastructure. For
high-level documentation (threat model, security properties, configuration), see
[doc/network-sandbox.md](../doc/network-sandbox.md).

## Network Topology

```
┌───────────────────────────────────────────────────────────┐
│  Podman network: airut-conv-{id}                          │
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

- **Internal network** (`--internal --disable-dns`): Per-conversation network
  with a `--route` that sends all client traffic to the proxy. The `--internal`
  flag blocks direct internet access. `--disable-dns` prevents aardvark-dns from
  overriding the client's `--dns` setting.
- **Egress network**: Shared network with internet access. Only proxy containers
  connect here. A lower route metric ensures the egress default route wins over
  the internal route inside the dual-homed proxy.

### Request Flow (Transparent DNS-Spoofing)

1. Container makes a DNS query (e.g., `api.github.com`)
2. The query goes to the proxy IP (set via `--dns` on the container)
3. `dns_responder.py` returns the proxy IP for all A queries (no allowlist
   check, no upstream DNS resolution)
4. Container connects to the proxy IP on port 80/443
5. mitmproxy in `regular` mode reads SNI (HTTPS) or Host header (HTTP)
6. `proxy_filter.py` checks host + path against the allowlist:
   - **Allowed**: mitmproxy connects upstream and forwards the request
   - **Blocked**: HTTP 403 returned with instructions

Note: Non-existent domains will appear to resolve from within the container.
This is by design — the DNS responder intentionally avoids upstream DNS
resolution to prevent DNS exfiltration (encoding stolen data in queries to
attacker-controlled nameservers). The proxy handles all access control.

## Components

| Component                                | Purpose                                               |
| ---------------------------------------- | ----------------------------------------------------- |
| `.airut/network-allowlist.yaml`          | Allowlist configuration (domains + URLs + methods)    |
| `lib/_bundled/proxy/proxy.dockerfile`    | Proxy container image (slim + mitmproxy)              |
| `lib/_bundled/proxy/proxy-entrypoint.sh` | Starts DNS responder + mitmproxy in regular mode      |
| `lib/_bundled/proxy/dns_responder.py`    | DNS server: returns proxy IP for all A queries        |
| `lib/_bundled/proxy/proxy_filter.py`     | mitmproxy addon: allowlist, token masking, re-signing |
| `lib/_bundled/proxy/aws_signing.py`      | AWS SigV4/SigV4A request re-signing                   |
| `lib/sandbox/_network.py`                | Podman args for sandbox integration (--dns, CA cert)  |
| `lib/sandbox/_proxy.py`                  | Per-task proxy lifecycle management                   |

## Proxy Lifecycle

The proxy is managed by `ProxyManager` in `lib/sandbox/_proxy.py`:

**Gateway lifecycle** (shared resources):

- On startup: clean orphans, build image, ensure CA cert, create egress network
- On shutdown: stop task proxies, remove egress network

**Conversation lifecycle** (per-conversation resources):

- `start_task_proxy()`: allocate subnet, create internal network with route,
  start dual-homed proxy container, health check
- `stop_task_proxy()`: remove container and network

## Resource Scoping

| Resource                             | Scope   | Created                  | Destroyed           |
| ------------------------------------ | ------- | ------------------------ | ------------------- |
| Egress network (`airut-egress`)      | Gateway | `startup()`              | `shutdown()`        |
| Proxy image (`airut-proxy`)          | Gateway | `startup()`              | Never (cached)      |
| CA certificate                       | Gateway | `startup()` (if missing) | Never               |
| Internal network (`airut-conv-{id}`) | Task    | `start_task_proxy()`     | `stop_task_proxy()` |
| Proxy container (`airut-proxy-{id}`) | Task    | `start_task_proxy()`     | `stop_task_proxy()` |
| Network log (`network-sandbox.log`)  | Task    | `start_task_proxy()`     | Session pruning     |

## CA Certificate Trust

mitmproxy intercepts HTTPS by terminating TLS with its own CA. All tools in the
container must trust this CA:

| Tool/Library          | Trust mechanism                        |
| --------------------- | -------------------------------------- |
| Node.js (Claude CLI)  | `NODE_EXTRA_CA_CERTS` env var          |
| Python requests       | `REQUESTS_CA_BUNDLE` env var           |
| Python ssl module     | `SSL_CERT_FILE` env var                |
| curl                  | `CURL_CA_BUNDLE` env var               |
| git, uv, system tools | `update-ca-certificates` in entrypoint |

## Session Network Logging

Network activity is logged to `conversation_dir/network-sandbox.log` for each
task. Both the DNS responder and the mitmproxy addon write to this shared log
file, providing a complete audit trail from DNS resolution through HTTP request:

```
=== TASK START 2026-02-03T12:34:56Z ===
DNS A api.github.com -> 10.199.1.100
DNS A evil.com -> 10.199.1.100
DNS AAAA evil.com -> NOTIMP
allowed GET https://api.github.com/repos/your-org/your-repo/pulls -> 200 [masked: 1]
BLOCKED GET https://evil.com/exfiltrate -> 403
allowed POST https://api.anthropic.com/v1/messages -> 200 [masked: 1]
ERROR GET https://down.example.com/api -> Connection failed: Name or service not known
```

### Log Format

DNS log lines use the format `DNS {type} {domain} -> {result}` where type is the
query type (A, AAAA, MX, etc.) and result is the proxy IP (for A queries) or
NOTIMP (for non-A queries). All A queries resolve to the proxy IP — the DNS
responder does not perform allowlist checking or upstream DNS resolution.

HTTP log lines use the format
`{BLOCKED|allowed} {METHOD} {URL} -> {status} [masked: N]` where `[masked: N]`
is present only when masked secret tokens were replaced.

ERROR lines indicate upstream connection failures — the domain passed the
allowlist but mitmproxy could not connect (e.g. DNS resolution failure, timeout,
connection refused). The format is `ERROR {METHOD} {URL} -> {error message}`.

The log file is created in the conversation directory and persists with the
session. It is cleaned up automatically when conversations are pruned.

## Crash Recovery

On startup, `ProxyManager` cleans orphaned resources from previous unclean
shutdowns: containers matching `airut-proxy-*` and networks matching
`airut-conv-*` are removed.
