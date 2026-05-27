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
   `allowed_domains` ends up with `allowed_domains: []`.
2. **Fail-secure.** Anything ambiguous (malformed JSON, oversized body, unknown
   blocklist shape) yields a 403, never an unfiltered pass-through.
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
allowing `/v1/*`) cannot silently disable this security control. It walks the
parsed body for every reachable `tools` array — so the Batches API shape
(`requests[i].params.tools[]`) is covered as well as the top-level Messages
shape — and applies the per-entry rules below to covered tools only.

| Condition (covered tool unless noted)                                                | Result                                    |
| ------------------------------------------------------------------------------------ | ----------------------------------------- |
| Body exceeds 1 MiB                                                                   | 403                                       |
| Body is empty / not valid JSON / not valid UTF-8                                     | 403                                       |
| `blocked_domains` present and non-empty (or not a list)                              | 403                                       |
| `allowed_domains` element is empty, non-string, or has `*` `?` whitespace `.`-prefix | 403                                       |
| `allowed_domains` missing or not a list                                              | injected as `[]`                          |
| `allowed_domains` present                                                            | trimmed to reachable hosts (`[]` if none) |
| No `tools` array reachable                                                           | pass-through                              |
| Only `custom` / `mcp` / unknown tool types                                           | pass-through                              |

A blocklist is rejected because it cannot be reconciled with a positive
allowlist — anything not blocked would be implicitly permitted, inverting the
security default. Wildcards are rejected so the trim does not silently fall out
of sync with whatever wildcard syntax Anthropic might later adopt. A trimmed
entry is left with `allowed_domains: []` rather than deleted, since Anthropic
treats an empty list as deny-all.

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

Monitoring Anthropic's tool-release notes is part of routine maintenance.

## Open Questions

- **`web_search` snippet leakage.** Even with a trimmed `allowed_domains`,
  `web_search` returns engine snippets containing content from arbitrary
  third-party URLs. If snippets carry enough data to reconstruct a canary, the
  trim does not fully contain it. A future decision: block `web_search_*`
  outright (drop the entry rather than trim) or accept snippet leakage as the
  cost of keeping search.
- **Default-deny vs. drop-tool.** Leaving a covered entry with an empty
  `allowed_domains` is friendlier to the agent (it sees an explicit deny) but
  assumes Anthropic always treats `allowed_domains: []` as deny-all. If that
  assumption ever changes, dropping the entry entirely is more robust.
- **Future fetchers without a domain allowlist.** A server-side fetcher with no
  domain-allowlist parameter cannot be trimmed; injecting `allowed_domains: []`
  may be silently ignored upstream. Such a tool should switch from "trim" to
  "reject the entire entry", forcing a maintainer decision before it can be
  used.
