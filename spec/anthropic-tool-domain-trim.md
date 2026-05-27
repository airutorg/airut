# Anthropic Server-Side-Tool Domain Trimming

Proxy-side mitigation that prevents agents from using Anthropic's server-side
fetcher tools (`web_fetch_*`, `web_search_*`, etc.) to read URLs the airut
network allowlist would otherwise deny. The proxy parses `/v1/messages*` POST
bodies and rewrites each covered tool's `allowed_domains` to the intersection of
the agent's declared list and the set of hosts the airut allowlist already
permits for unconstrained HTTP `GET` access.

For the high-level network sandbox documentation, see
[`doc/network-sandbox.md`](../doc/network-sandbox.md). For the related GraphQL
operation filter that this implementation mirrors structurally, see
[`graphql-operation-allowlist.md`](graphql-operation-allowlist.md).

## Motivation

`api.anthropic.com /v1/messages*` is allowlisted for POST because Claude Code
needs it to converse with the model. The Messages API accepts a `tools` array
that can declare server-side tools — e.g.

```json
{
  "type": "web_fetch_20250910",
  "name": "web_fetch",
  "max_uses": 1,
  "allowed_domains": ["airut.org"]
}
```

When the model invokes `web_fetch`, **Anthropic's** infrastructure performs the
outbound HTTP request (constrained only by `allowed_domains` /
`blocked_domains`) and returns the response body to the agent as a
`web_fetch_tool_result` content block. The fetch happens from Anthropic's
egress, not from inside the sandbox, so the airut network proxy never sees it —
the allowlist that governs what the container can reach directly does not apply.

This is not a credential-isolation issue: the masked-secret boundary is intact
and Anthropic legitimately needs the real OAuth token. The bypass leaks
*third-party URL content*, not airut-managed credentials.

Anthropic-side mitigations (per-URL blocklists, `robots.txt` enforcement) cannot
be relied on:

- `robots.txt` is best-effort by Anthropic's own framing, and URL variants that
  don't string-match the `Disallow` line (`#a`, `?x=1`, `//path`, `/./path`,
  `/foo/../path`) reliably bypass the check.
- Anthropic caches the parsed `robots.txt` per-host with a TTL on the order of
  minutes, and the comparator is sensitive to fragment / query / path-equivalent
  variants.

The mitigation must therefore live on the airut side and not depend on
Anthropic's URL hygiene.

## Threat Model

**In scope:** an agent with a valid OAuth token for the configured Claude API
account, running inside the airut sandbox, attempting to read content from a URL
that the airut network allowlist denies. The agent has full control of the
`tools` array in `/v1/messages*` POST bodies and the freedom to choose any tool
definition Anthropic supports (current and future).

**Out of scope:**

- Authentication of the agent against Anthropic. The OAuth token reaching
  Anthropic is the real value, by design.
- Content within tool results that the model relays via the assistant message
  itself (e.g., the model summarising a search result). If `web_search` is
  permitted at all, snippets in its results carry third-party content into the
  agent's context. The trim narrows what the model can fetch, not what it can
  quote.
- Anthropic-side bugs in `web_fetch` URL canonicalisation. We assume Anthropic
  enforces nothing helpful and design accordingly.

## Design Principles

1. **Default-deny.** Covered tools without an explicit, intersection-checked
   `allowed_domains` end up with `allowed_domains: []`.
2. **Independent of header gating.** The rewrite is body-level — it survives
   Anthropic moving tools out of beta.
3. **Generic.** No tool-specific schema knowledge beyond the `type` prefix list;
   only `allowed_domains` / `blocked_domains` are touched.
4. **Fail-secure.** Anything ambiguous (malformed JSON, oversized body, unknown
   blocklist shape) results in a 403, not an unfiltered pass-through.

## Covered Tool Types

The proxy maintains a hard-coded list of server-side-tool `type` prefixes in
[`tool_domains.py`](../airut/_bundled/proxy/tool_domains.py). Any `tools[].type`
matching one of these is subject to the trim:

- `web_fetch_*`
- `web_search_*`
- `computer_*`
- `bash_*` (cloud-hosted bash variant; not the local Claude Code Bash)
- `code_execution_*`

The list is maintainer-controlled and must be reviewed when Anthropic ships new
server-side tools (see [Maintenance](#maintenance) below). A `_*` suffix matches
any date-versioned release. Tool entries with types not on the list pass through
unmodified — Claude Code's local tools declare `type: "custom"` (or omit `type`)
and MCP definitions declare `type: "mcp"`, neither of which is touched.

## Host Permission Predicate

`host_get_open(host, domains, url_prefixes) -> bool` returns true iff the airut
allowlist contains an entry that

1. matches `host` via the existing `_match_host_pattern`,
2. has no path restriction (`path == ""` or absent), and
3. has either an empty / absent `methods` list (any method) or includes `"GET"`
   in `methods`.

Top-level `domains` entries qualify unconditionally — they are unrestricted by
definition.

Path-restricted entries (`/repos/airutorg/airut*`, `/htmx.org*`, etc.) are
excluded: `allowed_domains` is host-only on Anthropic's side, so opening those
domains via `web_fetch` would expose paths the agent cannot reach over its own
network. Method-restricted entries that don't include `GET` (e.g.
`statsig.anthropic.com` with `methods: [POST]`) are also excluded.

Against the current `.airut/network-allowlist.yaml`:

| Host                        | `host_get_open` | Reason                             |
| --------------------------- | --------------- | ---------------------------------- |
| `pypi.org`                  | yes             | `path: ""`, `methods: [GET, HEAD]` |
| `files.pythonhosted.org`    | yes             | `path: ""`, `methods: [GET, HEAD]` |
| `docs.slack.dev`            | yes             | `path: ""`, `methods: [GET, HEAD]` |
| `cdn.playwright.dev`        | yes             | `path: ""`, `methods: [GET, HEAD]` |
| `statsig.anthropic.com`     | no              | `methods: [POST]` only             |
| `api.anthropic.com`         | no              | path-restricted                    |
| `api.github.com`            | no              | path-restricted                    |
| `github.com`                | no              | path-restricted                    |
| `raw.githubusercontent.com` | no              | path-restricted                    |
| `unpkg.com`                 | no              | path-restricted                    |
| `storage.googleapis.com`    | no              | path-restricted                    |
| `claude.ai`                 | no              | `path: /install.sh` only           |
| `archive.ubuntu.com`        | no              | path-restricted                    |
| `airut.org`                 | no              | not in allowlist                   |

The list of hosts the agent can reach via Anthropic's tools is therefore a
strict subset of what it can already reach over its own network, preserving the
sandbox invariant: *the agent cannot read content from any URL outside the
configured allowlist*.

## Request Processing

### Scope

The trim is packaged as `tool_domains.ToolDomainFilter`, a member of the
request-body filter pipeline (see
[`request-body-filters.md`](request-body-filters.md)). The pipeline runs in
`ProxyFilter.request()` after URL allowlist matching, and before AWS re-signing
and credential replacement; the GraphQL operation filter runs ahead of it in the
same pipeline.

The trim applies whenever the **incoming request** targets `api.anthropic.com`
and its path is `/v1/messages` itself or any sub-path of `/v1/messages/`. The
gate is deliberately on the request (not on the shape of the matched allowlist
entry): a broader allowlist configuration — e.g. a user who allows `/v1/*` —
must not silently disable the trim. Other Anthropic endpoints (`oauth/*`,
`event_logging/*`, `eval/*`, `claude_code_*`) carry no `tools` field and do not
need parsing. See `tool_domains.is_anthropic_messages_request`, which the
filter's `matches()` method delegates to.

### Algorithm

1. **Reject oversized bodies.** If the request body exceeds 1 MiB → **403** with
   `error: "tool_config_too_large"`. Bounds parser CPU.

2. **Parse JSON.** Decode the body. If decoding fails (invalid JSON or invalid
   UTF-8 or empty body) → **403** with `error: "tool_config_invalid"`.

3. **Walk for `tools` arrays.** Walk every dict / list reachable from the parsed
   body (iteratively, so adversarially nested bodies cannot trigger
   `RecursionError`). Whenever a key named `tools` whose value is a list is
   encountered, apply the per-entry rules below. The walk descends through all
   other dict values and list elements — but does **not** descend back into the
   matched `tools` array itself, so a tool entry whose own fields happen to
   contain another `tools` key is untouched. This handles both the Messages API
   top-level shape (`{"tools": [...]}`) and the Batches API shape
   (`{"requests": [{"params": {"tools": [...]}}, ...]}`). Bodies without any
   `tools` array pass through unchanged.

4. **For each entry whose `type` matches a covered prefix:**

   1. **Reject `blocked_domains`.** If `blocked_domains` is present and is
      either non-empty or not a list → **403** with
      `error: "blocklist_tool_config_unsupported"`. A blocklist cannot be
      reconciled with a positive allowlist — anything not blocked is implicitly
      permitted, which inverts the security default. An empty list is tolerated
      and falls through to step 4.iii.

   2. **Reject wildcard entries.** If any string in `allowed_domains` contains
      `*`, `?`, whitespace, or a leading `.` — or is empty, or is not a string —
      → **403** with `error: "wildcard_tool_domain_unsupported"`. Anthropic's
      API already rejects literal `*` but may add wildcard syntax later; we
      don't want to be subtly out-of-sync with whatever syntax they pick.

   3. **Force `allowed_domains` presence.** If `allowed_domains` is missing or
      not a list, inject `allowed_domains: []` (default-deny). This applies even
      when `blocked_domains: []` was present — an explicit empty blocklist with
      no allowlist is otherwise equivalent to "fetch anything", and we can't
      tolerate that fallback.

   4. **Trim `allowed_domains`.** Replace with
      `[d for d in allowed_domains if host_get_open(d)]`. If the resulting list
      is empty, the entry is left with `allowed_domains: []` rather than being
      deleted — Anthropic's API treats an empty list as default-deny.

5. **Re-serialise the body** with compact separators and replace the request
   content. mitmproxy updates `Content-Length` automatically when
   `flow.request.content` is assigned. All other tool config (`max_uses`,
   `name`, etc.) and all other body fields are left untouched.

### Fail-Secure Summary

| Condition                              | Result                  |
| -------------------------------------- | ----------------------- |
| Body exceeds 1 MiB                     | 403                     |
| Body is not valid JSON / valid UTF-8   | 403                     |
| Body is empty                          | 403                     |
| Covered tool has `blocked_domains` set | 403                     |
| Covered tool has wildcard / non-string | 403                     |
| Covered tool has no `allowed_domains`  | injected `[]`           |
| Covered tool's `allowed_domains` mixes | trimmed to intersection |
| No `tools` array reachable             | pass-through            |
| Only `custom` / `mcp` / unknown types  | pass-through            |

### Error Responses

Blocked requests return HTTP 403 with a JSON body:

```json
{
  "error": "blocklist_tool_config_unsupported",
  "message": "Server-side tool 'blocked_domains' is not supported …",
  "detail": "web_fetch_20250910"
}
```

| `error`                             | When                                          |
| ----------------------------------- | --------------------------------------------- |
| `tool_config_too_large`             | Body exceeds 1 MiB                            |
| `tool_config_invalid`               | Malformed JSON / UTF-8                        |
| `blocklist_tool_config_unsupported` | Covered tool sets non-empty `blocked_domains` |
| `wildcard_tool_domain_unsupported`  | Covered tool has wildcard / non-string entry  |

## Logging

Each rewrite produces one log annotation in the existing network-log format,
attached to the same flow line as the access decision, under the filter's
`tool-domains` namespace:

```
ALLOWED POST https://api.anthropic.com/v1/messages -> 200
  [tool-domains: web_fetch_20250910: dropped 1 of 1 domains: airut.org]
```

Multiple covered tool entries in a single request produce a single
semicolon-separated annotation. Rule 1 / rule 2 rejections log as
`BLOCKED ... [tool-domains: <tool_type>: <reason>]` to surface in syslog (the
`403` status code distinguishes a rejection from a rewrite). No annotation is
emitted when a request has no covered tools — that is the quiet path.

Implementation: the filter returns its annotation in `FilterResult.log_tag`, and
the pipeline records it under the `tool-domains` namespace (see
[`request-body-filters.md`](request-body-filters.md)). `ProxyFilter.response()`
emits the bracket-wrapped annotation in the same line as the other access
metadata.

## Streaming

The Messages endpoint supports streaming **responses**, but request bodies are
sent in one shot — the `tools` array is part of the request, not the response
stream. The rewrite operates entirely on the request body and does not need
streaming hooks.

## Edge Cases

- **Tools array nested in MCP / sub-agent payloads.** `/v1/messages` also
  accepts MCP tool definitions inside `tools` (`type: "mcp"`). These declare
  client-side tools and do not include `allowed_domains`. They are not on the
  covered list and pass through. If a future MCP variant declares server-side
  fetching, the covered-list update is the maintenance hook.

- **Batches API (`/v1/messages/batches`).** The Batches API nests Messages-style
  payloads as `requests[i].params`. Because the trim recursively walks every
  reachable `tools` array, batches are covered automatically:
  `requests[i].params.tools[]` is trimmed exactly like a top-level `tools`
  array. (The current allowlist's `/v1/messages*` entry matches the batches
  path, so coverage matters.)

- **Tool result echoes.** Subsequent agent turns must repeat prior `tool_use`
  and `tool_result` content blocks. The trim does not inspect message history —
  only the `tools` config. A `web_fetch_tool_result` from a previous turn is
  re-sent as opaque content; no additional fetching happens. (If at some point
  Anthropic starts re-executing tool calls based on history, this would need
  revisiting.)

- **Beta header dependence.** `web_fetch` requires
  `anthropic-beta: web-fetch-2025-09-10`. Stripping the beta header was
  considered as an alternative mitigation but rejected: it is fragile (any
  future tool released in non-beta form would slip through) and overly
  aggressive (it kills legitimate beta-gated features that have nothing to do
  with fetching). The body-level rewrite is independent of header gating and
  survives Anthropic moving tools to GA.

- **Tools loaded via `ToolSearch`.** This proxy mitigation is independent of the
  Claude Code client. The trim runs at the network boundary and applies
  regardless of whether the agent reached the tool via `ToolSearch`, a deferred
  registration, direct API call, or any other path.

- **Future tools that don't expose `allowed_domains`.** If Anthropic ships a
  server-side fetcher that has no domain-allowlist parameter, this mitigation
  cannot trim it. Step 4.iii still injects `allowed_domains: []` for any covered
  type. If the entry is silently ignored upstream because the field is unknown,
  the covered-list entry should switch from "trim" to "reject the entire tool
  entry", forcing a maintainer decision before the tool can be used.

## Maintenance

Tool type strings are date-stamped (`web_fetch_20250910`). When Anthropic ships
`web_fetch_20260101`, the prefix match in `_COVERED_TOOL_PREFIXES` still catches
it, but any *semantic* change to the parameter shape needs a code review. Two
maintenance hooks:

1. **New tool family.** When Anthropic announces a new server-side tool whose
   `type` does not start with one of the existing prefixes, add it to
   `_COVERED_TOOL_PREFIXES` and re-run the test suite. Tests in
   `tests/proxy/test_tool_domains.py` should be extended with a representative
   `type` string.
2. **Parameter-shape change.** If a covered tool starts using a parameter other
   than `allowed_domains` / `blocked_domains` to constrain its fetches (e.g.
   path-level `allowed_urls`), the trim must be extended to cover the new
   parameter or to reject the tool outright. The covered-list comment in
   `tool_domains.py` should be updated.

Monitoring Anthropic's tool-release notes (changelog, beta-header release
threads) is part of routine maintenance.

## Open Questions

- **`web_search` snippet leakage.** Even with a trimmed `allowed_domains`,
  `web_search` returns search-engine snippets that contain content from
  arbitrary third-party URLs. If snippets contain enough data to reconstruct a
  canary, the trim does not fully contain it. A future decision: block
  `web_search_*` outright (drop the entry rather than trim), or accept snippet
  leakage as the cost of keeping search.

- **Default-deny vs. drop-tool.** This spec leaves the tool entry in place with
  an empty `allowed_domains`. An alternative is to remove the entry entirely.
  Empty-allowed-domains is friendlier to the agent (it sees an explicit deny)
  but assumes Anthropic always treats `allowed_domains: []` as deny-all. If that
  assumption ever changes, dropping the entry is more robust.
