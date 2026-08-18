# Anthropic Server-Side-Tool Domain Trimming

Proxy-side mitigation that prevents agents from using Anthropic's server-side
fetcher tools (`web_fetch_*`, `web_search_*`, etc.) to read URLs the airut
network allowlist would otherwise deny. The proxy rewrites each covered tool's
`allowed_domains` in `/v1/messages*` request bodies to the intersection of the
agent's declared list and the hosts the allowlist already permits for
unconstrained HTTP `GET`.

It is one filter in the request-body filter pipeline; the pipeline mechanics
(gating, body rewrite, 403 construction, log annotation) are specified in
[`request-body-filters.md`](request-body-filters.md). For the high-level network
sandbox documentation, see
[`doc/network-sandbox.md`](../doc/network-sandbox.md). For the sibling filter
this one mirrors structurally, see
[`graphql-operation-allowlist.md`](graphql-operation-allowlist.md).

## Motivation

`api.anthropic.com /v1/messages*` is allowlisted for POST because Claude Code
needs it to converse with the model. The Messages API `tools` array can declare
server-side tools such as `web_fetch`. When the model invokes one,
**Anthropic's** infrastructure performs the outbound request — constrained only
by the tool's `allowed_domains` / `blocked_domains` — and returns the response
body to the agent. The fetch happens from Anthropic's egress, not from inside
the sandbox, so the airut proxy never sees it and the network allowlist does not
apply.

This is not a credential-isolation issue: the masked-secret boundary is intact
and Anthropic legitimately needs the real OAuth token. The bypass leaks
*third-party URL content*, not airut-managed credentials.

Anthropic-side mitigations cannot be relied on: `robots.txt` enforcement is
best-effort by Anthropic's own framing, with a short per-host cache, and URL
variants that don't string-match the `Disallow` line (`#a`, `?x=1`, `//path`,
`/./path`, `/foo/../path`) bypass it. The mitigation must therefore live on the
airut side and assume nothing about Anthropic's URL hygiene.

## Threat Model

**In scope:** an agent with a valid OAuth token for the configured Claude API
account, running inside the sandbox, attempting to read content from a URL the
network allowlist denies. The agent fully controls the `tools` array and may use
any tool definition Anthropic supports, current or future.

**Out of scope:**

- Authentication of the agent against Anthropic. The OAuth token reaching
  Anthropic is the real value, by design.
- Content the model relays in the assistant message itself. If `web_search` is
  permitted at all, result snippets carry third-party content into the agent's
  context. The trim narrows what the model can *fetch*, not what it can *quote*
  (see [Open Questions](#open-questions)).
- Anthropic-side bugs in tool URL canonicalisation. We assume Anthropic enforces
  nothing helpful and design accordingly.

## Design Principles

1. **Default-deny.** A covered tool without an explicit, intersection-checked
   `allowed_domains` ends up with `allowed_domains: []` — except for tools that
   reject an empty list upstream (see
   [Empty-list handling](#empty-list-handling)), where default-deny is expressed
   by removing the key instead.
2. **Fail-secure.** Anything ambiguous (malformed JSON, body nested too deeply
   to parse, oversized body, unknown blocklist shape) yields a 403, never an
   unfiltered pass-through — as does an unexpected exception anywhere in the
   filter, which the pipeline converts into a 403 rather than letting it escape
   (see [`request-body-filters.md`](request-body-filters.md)). The size cap is
   set at Anthropic's own request limit so fail-secure never costs functionality
   (see [Body size cap](#body-size-cap)).
3. **Generic.** No tool-specific schema knowledge beyond the `type` prefix list;
   only `allowed_domains` / `blocked_domains` are touched.
4. **Independent of header gating.** The rewrite is body-level, so it survives
   Anthropic moving tools out of beta. Stripping the beta header was rejected as
   an alternative: fragile (a future GA tool would slip through) and overly
   aggressive (it kills unrelated beta-gated features).

## Covered Tools

A maintainer-controlled prefix list (`_COVERED_TOOL_PREFIXES` in
[`tool_domains.py`](../airut/_bundled/proxy/tool_domains.py)) selects which
`tools[].type` values are subject to the trim: the server-side fetcher families
`web_fetch_*`, `web_search_*`, `computer_*`, `bash_*` (the cloud-hosted bash,
not the local Claude Code Bash), and `code_execution_*`. A `_*` suffix matches
any date-versioned release.

Entries with types not on the list pass through unmodified — Claude Code's local
tools declare `type: "custom"` (or omit `type`) and MCP definitions declare
`type: "mcp"`, none of which expose server-side fetching today. The list is the
maintenance hook for when that changes (see [Maintenance](#maintenance)).

## Contract

### What counts as a reachable host

A host qualifies for `allowed_domains` only if the agent could already reach it
over its own network for arbitrary `GET` traffic. Concretely, the allowlist must
contain an entry that matches the host, imposes **no path restriction**, and
permits `GET` (an empty/absent `methods` list, or one that includes `GET`).
Top-level `domains` entries qualify unconditionally.

Path-restricted entries are excluded because `allowed_domains` is host-only on
Anthropic's side: opening such a domain via `web_fetch` would expose paths the
agent cannot reach directly. Non-`GET` entries (e.g. a POST-only telemetry host)
are excluded for the same reason. The set of hosts reachable via Anthropic's
tools is therefore a strict subset of what the agent can already reach directly,
preserving the sandbox invariant: *the agent cannot read content from any URL
outside the configured allowlist.*

### Per-request behavior

The filter runs for any request whose **incoming** target is `api.anthropic.com`
with path `/v1/messages` or a sub-path of `/v1/messages/`. The gate is on the
request, not the matched allowlist entry, so a broader configuration (e.g.
allowing `/v1/*`) cannot silently disable this security control. The gate
matches the **percent-decoded** path (the pipeline passes
`unquote(flow.request.path)`, mirroring the allowlist), so an encoded path such
as `/v1/messag%65s` — which the allowlist still admits — cannot evade the trim.
It walks the parsed body for every reachable `tools` array — so the Batches API
shape (`requests[i].params.tools[]`) is covered as well as the top-level
Messages shape — and applies the per-entry rules below to covered tools only.

| Condition (covered tool unless noted)                                                | Result                          |
| ------------------------------------------------------------------------------------ | ------------------------------- |
| Body exceeds 32 MiB                                                                  | 403                             |
| Body is empty / not valid JSON / not valid UTF-8 / nested too deeply                 | 403                             |
| `blocked_domains` present and non-empty (or not a list)                              | 403                             |
| `allowed_domains` element is empty, non-string, or has `*` `?` whitespace `.`-prefix | 403                             |
| `allowed_domains` missing or not a list (default-deny tool)                          | injected as `[]`                |
| `allowed_domains` missing or not a list (unrestricted-on-empty tool)                 | left absent (runs unrestricted) |
| `allowed_domains` present, trims non-empty                                           | trimmed to reachable hosts      |
| `allowed_domains` present, trims empty (default-deny tool)                           | set to `[]`                     |
| `allowed_domains` present, trims empty (unrestricted-on-empty tool)                  | key removed (runs unrestricted) |
| No `tools` array reachable                                                           | pass-through                    |
| Only `custom` / `mcp` / unknown tool types                                           | pass-through                    |

A blocklist is rejected because it cannot be reconciled with a positive
allowlist — anything not blocked would be implicitly permitted, inverting the
security default. Wildcards are rejected so the trim does not silently fall out
of sync with whatever wildcard syntax Anthropic might later adopt. For
default-deny tools a trimmed entry is left with `allowed_domains: []` rather
than deleted, since Anthropic treats an empty list as deny-all.

### Body size cap

The filter must parse the body to enforce the trim, so it rejects bodies too
large to parse rather than forwarding them unfiltered. The cap is **32 MiB**,
rounded up from the Anthropic Messages API's own 32 MB request limit.

Sizing the cap to the upstream limit is deliberate. A `/v1/messages` body
carries the whole conversation on every turn — base64 images from `Read`,
document attachments, accumulated file contents — so a cap below the upstream
limit makes the proxy, not the API, the binding constraint. Because history is
resent each turn, a single oversized request also bricks every subsequent
request in that conversation, not just the one that crossed the line. For
`/v1/messages` the cap therefore costs no functionality: anything it rejects
Anthropic would have rejected anyway.

The one exception is `/v1/messages/batches`, which this filter also matches and
which accepts up to 256 MB per batch. Between 32 MiB and that limit the proxy
*is* the binding constraint. Claude Code does not use the Batches API, so this
is accepted rather than solved; raising the cap for batches specifically would
mean parsing bodies an order of magnitude larger, which the amplification note
below argues against.

Parse cost at the cap is ~50 ms and negligible extra memory for a realistic
Messages body (one large base64 string), against an API round-trip measured in
seconds. It is **not** linear in body size for degenerate input: 32 MiB of tiny
JSON objects parses in ~0.5 s and allocates ~740 MB, roughly 23x the body. The
proxy is per-task and a proxy that dies takes only its own task's network with
it (fail-closed), but the proxy container is not memory-limited, so this
amplification is the cost of the higher cap — see
[Open Questions](#open-questions).

This is why the cap differs from the 1 MiB used by the GraphQL filters, whose
request bodies are queries rather than conversation payloads.

### Empty-list handling

The default-deny-via-`[]` strategy assumes Anthropic honours an empty
`allowed_domains` as deny-all. That holds for `web_fetch`, but **not** for
`web_search`: Anthropic rejects an empty list with
`400 ... allowed_domains: Empty list of domains is ambiguous. Provide at least one domain or null.`,
which fails the entire `/v1/messages` request — so the default-deny injection
would break web search outright rather than restricting it.

Tools with this behavior are listed in `_UNRESTRICTED_ON_EMPTY_PREFIXES`
(`web_search_*` today). For them, an empty effective allow-list — whether
because none was declared or because the trim removed every host — is expressed
by **removing the `allowed_domains` key**, leaving the tool unrestricted, rather
than injecting or leaving `[]`. A list that trims to a non-empty subset is still
narrowed to that subset, exactly as for default-deny tools.

This is an accepted policy trade-off, not a containment regression: `web_search`
returns search-engine snippets rather than full page bodies, so its
`allowed_domains` only scopes which result *domains* surface. Snippet content
from arbitrary third-party URLs already leaks regardless of the trim (see
[Threat Model](#threat-model) and [Open Questions](#open-questions)), so running
search unrestricted does not widen the exfiltration surface the way it would for
a full-content fetcher like `web_fetch`. The host-level trim is preserved for
`web_fetch_*`, `computer_*`, `bash_*`, and `code_execution_*`, where
`allowed_domains: []` remains a valid deny-all.

Blocked requests return a 403 and rewrites/rejections are annotated on the
access-decision log line under the `tool-domains` namespace; both the JSON error
shape and the log format are defined in
[`request-body-filters.md`](request-body-filters.md).

## Maintenance

Tool `type` strings are date-stamped (`web_fetch_20250910`); the prefix match
catches new releases of an existing family automatically, but two changes need a
maintainer decision:

1. **New tool family.** A server-side tool whose `type` does not start with an
   existing prefix must be added to `_COVERED_TOOL_PREFIXES` (with a
   representative test case) — otherwise it passes through untrimmed.
2. **New constraining parameter.** If a covered tool starts constraining fetches
   via a parameter other than `allowed_domains` / `blocked_domains` (e.g. a
   path-level `allowed_urls`), the trim must be extended to cover it or to
   reject the tool outright.
3. **Empty-list rejection.** If a covered tool rejects `allowed_domains: []`
   upstream instead of honouring it as deny-all (as `web_search` does), add its
   prefix to `_UNRESTRICTED_ON_EMPTY_PREFIXES` so an empty allow-list removes
   the key rather than 400'ing the request. Weigh this against the tool's
   leakage profile first — key removal runs it unrestricted, which is only
   acceptable for snippet-style tools, not full-content fetchers.

Monitoring Anthropic's tool-release notes is part of routine maintenance.

## Open Questions

- **Parse-memory amplification.** Degenerate JSON at the 32 MiB cap allocates
  ~740 MB during `json.loads`, and the proxy container runs without a `--memory`
  limit. The blast radius is one task's own proxy, and losing it fails closed,
  but the allocation lands on host memory shared with the gateway. The cap does
  not bound proxy memory end-to-end either way: mitmproxy buffers and
  **decompresses** the body before any filter sees it, and the cap is measured
  on the decoded bytes, so a small compressed bomb allocates without ever
  reaching the check. **Unresolved:** give the proxy container a memory limit,
  which contains both effects at the point they actually matter.
- **`web_search` snippet leakage.** Even with a trimmed `allowed_domains`,
  `web_search` returns engine snippets containing content from arbitrary
  third-party URLs. If snippets carry enough data to reconstruct a canary, the
  trim does not fully contain it. **Resolved:** snippet leakage is accepted as
  the cost of keeping search. Because `web_search` rejects `allowed_domains: []`
  upstream, an empty effective allow-list runs the tool unrestricted rather than
  blocking it (see [Empty-list handling](#empty-list-handling)).
- **Default-deny vs. drop-tool.** Leaving a covered entry with an empty
  `allowed_domains` assumes Anthropic always treats `allowed_domains: []` as
  deny-all. **Partially resolved:** that assumption is false for `web_search`
  (Anthropic 400s on `[]`), so it is on `_UNRESTRICTED_ON_EMPTY_PREFIXES` and an
  empty allow-list is expressed by key removal instead. `web_fetch` and the
  other covered tools still rely on `[]` as deny-all; if that ever changes for
  one of them, add it to the same list.
- **Future fetchers without a domain allowlist.** A server-side fetcher with no
  domain-allowlist parameter cannot be trimmed; injecting `allowed_domains: []`
  may be silently ignored upstream. Such a tool should switch from "trim" to
  "reject the entire entry", forcing a maintainer decision before it can be
  used.
