# Network Sandbox

Implementation details for the network sandbox proxy infrastructure. For
high-level documentation (threat model, security properties, configuration), see
[doc/network-sandbox.md](../doc/network-sandbox.md).

## Components

| Component                       | Purpose                                              |
| ------------------------------- | ---------------------------------------------------- |
| `.airut/network-allowlist.yaml` | Allowlist configuration (domains + URLs + methods)   |
| `docker/proxy.dockerfile`       | Proxy container image (slim + mitmproxy + pyyaml)    |
| `docker/proxy-entrypoint.sh`    | Starts DNS responder + mitmproxy in regular mode     |
| `docker/dns_responder.py`       | DNS server: returns proxy IP or NXDOMAIN             |
| `docker/proxy-filter.py`        | mitmproxy addon for allowlist + token masking        |
| `lib/container/network.py`      | Podman args for sandbox integration (--dns, CA cert) |
| `lib/container/proxy.py`        | Per-conversation proxy lifecycle management          |

## Proxy Configuration

The proxy runs `mitmdump` (mitmproxy's non-interactive mode) with the following
key settings:

| Flag                                      | Purpose                                                   |
| ----------------------------------------- | --------------------------------------------------------- |
| `--mode regular@80 --mode regular@443`    | Listen on ports 80 and 443 in regular proxy mode          |
| `--set connection_strategy=lazy`          | Defer upstream connection until request is fully received |
| `--set upstream_cert=false`               | Don't sniff upstream cert before client TLS handshake     |
| `--anticache`                             | Strip `If-None-Match`/`If-Modified-Since` from requests   |
| `--modify-headers '/~q/Connection/close'` | Force upstream connections to close after each request    |
| `--set confdir=/mitmproxy-confdir`        | CA certificate location                                   |
| `--set flow_detail=0`                     | Minimal flow logging to stdout                            |
| `-s /proxy-filter.py`                     | Load allowlist + token masking addon                      |

### Stale connection prevention

Three flags work together to prevent stale upstream state from causing
persistent failures (e.g., a server with a briefly-expired certificate remaining
unreachable after the certificate is fixed):

- **`upstream_cert=false`**: By default, mitmproxy eagerly connects upstream to
  sniff the server certificate before completing the client TLS handshake. This
  can cache stale TLS state from a failed connection. Disabling this ensures
  each request gets a fresh TLS negotiation.
- **`--anticache`**: Strips conditional request headers so upstream servers
  always return full responses, never 304 Not Modified from stale cache state.
- **`Connection: close`**: Forces each upstream connection to close after the
  response, preventing keep-alive connection reuse that could carry stale TLS or
  HTTP state between requests.

## Proxy Lifecycle

The proxy is managed by `ProxyManager` in `lib/container/proxy.py`:

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
allowed DNS A api.github.com -> 10.199.1.100
BLOCKED DNS A evil.com -> NXDOMAIN
BLOCKED DNS AAAA evil.com -> NOTIMP
allowed GET https://api.github.com/repos/your-org/your-repo/pulls -> 200 [masked: 1]
BLOCKED GET https://evil.com/exfiltrate -> 403
allowed POST https://api.anthropic.com/v1/messages -> 200 [masked: 1]
ERROR GET https://down.example.com/api -> Connection failed: Name or service not known
```

### Log Format

DNS log lines use the format `{BLOCKED|allowed} DNS {type} {domain} -> {result}`
where type is the query type (A, AAAA, MX, etc.) and result is the DNS response
(proxy IP for allowed, NXDOMAIN for blocked A queries, NOTIMP for non-A
queries).

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
