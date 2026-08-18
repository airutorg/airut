# Request-Body Filter Pipeline

Shared structure for **service-specific request-body filtering** at the network
proxy. A request-body filter inspects an allowlisted request's body and decides
to pass it through, rewrite it, or reject it with a 403. The pipeline owns the
gating dispatch, body rewrite, 403 construction, and log annotation so that each
filter is a small, self-contained class rather than another inline block in
`ProxyFilter.request()`.

For the high-level network sandbox documentation, see
[`doc/network-sandbox.md`](../doc/network-sandbox.md). The two filters that
currently use this pipeline are specified in
[`graphql-operation-allowlist.md`](graphql-operation-allowlist.md) and
[`anthropic-tool-domain-trim.md`](anthropic-tool-domain-trim.md).

## Motivation

The proxy increasingly needs to inspect and rewrite request bodies for specific
services (the GraphQL operation allowlist, the Anthropic server-side-tool domain
trim, and more to come). Each such control shares the same mechanics — gate on
the request, parse the body, allow / rewrite / block, attach a log tag — but
historically each was open-coded inline in `ProxyFilter.request()`, with its own
host/path predicate, its own 403 builder, its own `flow.metadata` log key, and a
hand-placed position in the hook's statement ordering.

That pattern does not scale: a new payload filter meant a new private method, a
new hardcoded gate, a new metadata key, and a fragile manual insertion point.
The pipeline factors the common mechanics out so a new filter is one class plus
one registry entry.

## Scope

This pipeline covers **request-body authorization** only: deciding whether an
already-allowlisted request may proceed, optionally rewriting its body.

It deliberately does **not** cover credential transformation — AWS SigV4
re-signing, GitHub App token minting, and masked-secret token replacement. Those
are keyed off the replacement map (not the request body), mutate headers rather
than bodies, and run as their own stage in `ProxyFilter` after the body-filter
pipeline. The GraphQL **repository scope** check (`graphql_scope`) is part of
that credential stage, not a body filter: it depends on per-credential state
(the installation token's resolved repository node IDs) and must run while the
GitHub App token is being injected. See
[`github-app-credential.md`](github-app-credential.md).

## Contract

Defined in `airut/_bundled/proxy/request_filter.py`.

### `FilterRequest`

The request context a filter sees, decoupled from mitmproxy's flow object so
filters are unit-testable without the proxy:

| Field           | Meaning                                                                                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `host`          | Request hostname (`flow.request.pretty_host`).                                                                                                                        |
| `path`          | Request path including any query string, percent-decoded (`unquote(flow.request.path)`) so it matches the canonical path the allowlist matched and upstream resolves. |
| `matched_entry` | The `url_prefixes` entry that allowlisted the request, or `None` for a top-level `domains` match.                                                                     |

### `RequestBodyFilter`

A `Protocol` with:

- `name: str` — the log namespace, emitted as `[{name}: {log_tag}]` (e.g.
  `graphql-op`, `tool-domains`).
- `matches(req: FilterRequest) -> bool` — whether this filter runs for the
  request. Filters gate on the request, never on shared proxy state.
- `apply(req: FilterRequest, body: bytes) -> FilterResult` — inspect the body
  and return the action. Filters must **not** mutate the flow directly.

### `FilterResult`

Constructed via `FilterResult.passthrough()`, `FilterResult.rewrite(body)`, or
`FilterResult.block(error, message, detail)`:

| `action`  | Pipeline behaviour                                       |
| --------- | -------------------------------------------------------- |
| `PASS`    | Forward the request unchanged.                           |
| `REWRITE` | Swap `body` into `flow.request.content`, then continue.  |
| `BLOCK`   | Set a 403 with `{error, message, detail}` JSON and stop. |

A raised exception is coerced to `BLOCK` by the pipeline — see
[Pipeline Execution](#pipeline-execution).

Any action may carry a `log_tag`. A `PASS` result with a `log_tag` is the
mechanism by which an allowed-but-noteworthy request is still annotated (e.g.
the GraphQL operation tag is logged even when the operation is permitted).

## Gating Modes

`matches()` supports two intentionally different gating strategies, both present
in the current filters:

1. **Config-attached (opt-in per allowlist entry).** The GraphQL operation
   filter matches only when `req.matched_entry` carries a `graphql` block. The
   control is declarative — it is enabled by the allowlist configuration for
   that entry.
2. **Request-gated (unconditional security control).** The Anthropic tool-domain
   trim matches every `api.anthropic.com /v1/messages*` request regardless of
   which allowlist entry matched. This is deliberate: a broader allowlist
   configuration (e.g. `/v1/*`) must **not** silently disable a security
   control. The gate is a property of the request, not of the matched entry.

A filter must pick the mode that matches its security semantics. A control that
exists to contain a bypass uses request-gating; an opt-in narrowing of an
already-allowed surface uses config-attachment.

## Pipeline Execution

`ProxyFilter._run_body_filters(flow, host, path, matched_entry)` runs after URL
allowlist matching and before AWS re-signing / credential replacement. The
`path` it receives is **percent-decoded** (`unquote(flow.request.path)`),
mirroring the decode in `_is_allowed`. A request-gated filter that compares
against the literal path (e.g. the tool-domain trim's
`is_anthropic_messages_request`) must see the same canonical path the allowlist
matched and the upstream server resolves; otherwise an encoded path such as
`/v1/messag%65s` would pass the allowlist (which decodes) yet evade the filter
(which would see the still-encoded path), letting an untrimmed `allowed_domains`
reach Anthropic. It:

1. Builds a `FilterRequest` from the request (with the decoded `path`).
2. Iterates `self._body_filters` **in registration order**. The registry is an
   explicit ordered list built in `ProxyFilter.__init__`; ordering is part of
   the contract (the GraphQL operation filter is registered before the
   tool-domain trim).
3. For each filter whose `matches()` is true, reads the current request body
   (re-read each time, so a filter sees any rewrite an earlier filter applied)
   and calls `apply()`. A missing body (`get_content()` returns `None`) is
   passed to the filter as `b""`, which the body-parsing filters reject as
   invalid — fail-secure rather than forwarding an opaque body. An
   **undecodable** body is different: `get_content()` raises for any
   `Content-Encoding` mitmproxy cannot decode (`ValueError` for an unknown
   codec, `TypeError` for a str-only one such as `rot13`), and that raise is
   caught by the same guard as a raising filter (below) and blocked. The header
   is fully agent-controlled, so this path must not escape.
4. Translates the `FilterResult`: `PASS` continues, `REWRITE` writes
   `flow.request.content` and continues, `BLOCK` sets `flow.metadata`
   `allowlist_action = "BLOCKED"`, emits the 403, and returns `True` (caller
   stops processing).
5. Records each non-empty `log_tag` as `"{name}: {log_tag}"` in
   `flow.metadata["filter_tags"]`, truncating the tag as a backstop (see
   [Logging](#logging)).

An exception raised **anywhere in a filter's gating or body read** —
`matches()`, `get_content()`, or `apply()` — is treated as `BLOCK`, with `error`
`filter_error` and `detail` `<{name}: {ExceptionType}>`. Filters are security
controls, so an escaping exception would leave mitmproxy's `safecall` to log the
error and forward the original, uninspected body — the worst available outcome.
Individual filters still catch what they can predict (a filter that recognises
the failure returns a `BLOCK` with a specific error code); this backstop covers
what they cannot, such as a `RecursionError` raised inside `json.loads` on a
deeply nested body.

`mitmproxy` updates `Content-Length` automatically when `flow.request.content`
is assigned, so a rewrite needs no further bookkeeping.

## Logging

Tags interpolate request-controlled values — tool types, dropped domains,
GraphQL operation names — so their size scales with the request body. A single
request declaring thousands of `allowed_domains` would otherwise write a
multi-megabyte line to the network log, to syslog, and to the dashboard's log
stream. Bounding happens at two levels:

1. **Each filter bounds its own variable-length parts.** The tool-domain trim
   names at most 10 domains and summarises the rest as `+N more`, keeping the
   counts that precede them. This is what keeps the annotation useful: a filter
   emitting one annotation per tool stays readable, because no single entry can
   crowd out the ones after it.
2. **`_add_filter_tag` truncates the finished tag** to 1000 characters,
   suffixing `… (truncated)`. This is a catch-all for a filter that neglects
   step 1, not the primary mechanism — a well-behaved filter never reaches it.

`ProxyFilter.response()` emits each entry in `flow.metadata["filter_tags"]` as a
bracket-wrapped annotation on the single access-decision line, in filter
execution order:

```
ALLOWED POST https://api.github.com/graphql -> 200 [graphql-op: mutation/createIssue]
ALLOWED POST https://api.anthropic.com/v1/messages -> 200 [tool-domains: web_fetch_20250910: dropped 1 of 1 domains: airut.org]
BLOCKED POST https://api.anthropic.com/v1/messages -> 403 [tool-domains: web_fetch_20250910: blocked-domains]
```

A single filter namespace covers both the allowed (rewrite) and blocked cases;
the `ALLOWED` / `BLOCKED` prefix and status code distinguish them. No annotation
is emitted for a filter that returns a `PASS` with no `log_tag` — that is the
quiet path.

## Adding a Filter

1. Write the pure check as a function returning a verdict/result (the existing
   `check_operations` and `check_and_trim_tools` pattern), kept in a
   service-specific module so the parsing logic stays cohesive and directly
   unit-testable.
2. Add a small filter class in the same module exposing `name`, `matches`, and
   `apply`, translating the check's result into a `FilterResult`.
3. Register an instance in `ProxyFilter.__init__`'s `_body_filters` list at the
   correct ordering position.
4. If the filter needs live proxy state (e.g. the allowlist for a host
   predicate), inject it as a constructor argument bound to a `ProxyFilter`
   method so it reads current configuration at call time.

No changes to `ProxyFilter.request()` or `response()` are needed — the pipeline
and the unified log path absorb the new filter automatically.
