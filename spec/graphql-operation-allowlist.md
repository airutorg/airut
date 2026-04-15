# GraphQL Operation Allowlist

Generic GraphQL operation filtering at the proxy layer. Extends the network
allowlist to support default-deny filtering of GraphQL operations by type
(query, mutation, subscription) and top-level field name.

## Motivation

The network allowlist operates at the URL level: host + path + method. GraphQL
APIs collapse all operations into a single URL endpoint (`POST /graphql`),
making URL-level filtering insufficient to distinguish between safe reads and
dangerous mutations.

For GitHub App credentials specifically, the existing `repositoryId` scope check
(`graphql_scope.py`) only validates one targeting field. Many mutations accept
other node ID fields (`subjectId`, `pullRequestId`, `issueId`, etc.) that
implicitly target repositories without going through the scope check. Rather
than chasing every possible ID field across GitHub's evolving schema, a
default-deny operation allowlist eliminates entire classes of dangerous
operations before they reach credential-specific checks.

This feature is generic — it works for any GraphQL API, not just GitHub. The
same mechanism can filter operations on GitLab, Linear, Hasura, or any other
GraphQL service behind the proxy.

## Design Principles

1. **Default-deny.** When a `graphql` block is present on an allowlist entry,
   only explicitly listed operations are permitted. Unlisted operation types and
   field names are blocked.

2. **Fail-secure.** If the proxy cannot conclusively determine that a request is
   allowed — due to parse errors, missing fields, ambiguous structure, or any
   other reason — the request is blocked.

3. **Generic.** The filter uses standard GraphQL AST parsing. It has no
   knowledge of any specific GraphQL schema (GitHub, GitLab, etc.). It inspects
   only the operation type and top-level field selections.

4. **Layered.** This is Layer 1 in a defense-in-depth stack. Service-specific
   checks (like GitHub's `repositoryId` scoping) operate as Layer 2, providing
   additional constraints on operations that Layer 1 allows through.

## Configuration

### YAML Format

The `graphql` field is an optional extension to `url_prefixes` entries in
`.airut/network-allowlist.yaml`:

```yaml
url_prefixes:
  # Without graphql block — no operation filtering (backwards compatible)
  - host: api.example.com
    path: /graphql
    methods: [POST]

  # With graphql block — default-deny operation filtering
  - host: api.github.com
    path: /graphql
    methods: [POST]
    graphql:
      queries:
        - "*"                          # allow all queries
      mutations:
        - createIssue
        - createPullRequest
        - updatePullRequest
        - mergePullRequest
        - enablePullRequestAutoMerge
        - markPullRequestReadyForReview
        - addPullRequestReview
        - submitPullRequestReview
        - requestReviews
        - createRef
        - updateRef
        - deleteRef
        - createCommitOnBranch
      # subscriptions: omitted = blocked
```

### Schema

```yaml
graphql:                              # Optional. Omit for no GraphQL filtering.
  queries: ["*"]                      # fnmatch patterns for allowed query fields.
  mutations: ["createIssue", "update*"]  # fnmatch patterns for allowed mutation fields.
  subscriptions: []                   # fnmatch patterns (empty = blocked, default-deny).
```

All three fields are optional lists of fnmatch patterns. An omitted or empty
list means no operations of that type are allowed (default-deny). To allow all
operations of a type, use `["*"]`.

**Pattern matching uses Python's `fnmatch.fnmatch()`** (case-sensitive on all
platforms) — the same mechanism as host and path matching in the existing
allowlist:

- `"*"` — matches everything
- `"create*"` — matches `createIssue`, `createPullRequest`, etc.
- `"*PullRequest"` — matches `createPullRequest`, `updatePullRequest`, etc.
- `"createIssue"` — exact match

Pattern matching is case-sensitive (GraphQL field names are case-sensitive per
the GraphQL spec).

### JSON Serialization

The `graphql` field is serialized into the proxy JSON unchanged. Omitted
operation types serialize as empty lists to make the default-deny behavior
explicit in the JSON consumed by the proxy:

```json
{
  "host": "api.github.com",
  "path": "/graphql",
  "methods": ["POST"],
  "graphql": {
    "queries": ["*"],
    "mutations": ["createIssue", "createPullRequest"],
    "subscriptions": []
  }
}
```

## Request Processing

### Flow

```
POST /graphql arrives at proxy
        │
        ▼
┌─────────────────────────────────┐
│  URL Allowlist Check            │  host + path + method
│                                 │  If blocked → 403 (existing behavior)
└──────────┬──────────────────────┘
           │ URL allowed
           ▼
┌─────────────────────────────────┐
│  GraphQL Operation Check        │  Does matching entry have graphql config?
│                                 │  If no config → skip (no filtering)
└──────────┬──────────────────────┘
           │ operations allowed
           ▼
┌─────────────────────────────────┐
│  Credential Handling            │  Token replacement, GitHub App, AWS signing
│  (includes Layer 2 repo scope)  │
└──────────┬──────────────────────┘
           │
           ▼
      Forward request
```

The operation check runs in the `request()` hook, after URL allowlist matching
and before credential handling. URL pattern entries without a `graphql` block
are unaffected (backwards compatible).

### Algorithm

When a request matches a URL pattern that has a `graphql` configuration:

1. **Reject oversized bodies.** If the request body exceeds 1 MiB → **BLOCKED**.
   This prevents CPU exhaustion via parsing of very large query strings.

2. **Parse JSON body.** Decode the request body as JSON. If decoding fails or
   the result is not a dict → **BLOCKED** (fail-secure).

3. **Reject arrays.** If the body is a JSON array (batched queries) →
   **BLOCKED**. Batched queries are not supported by the filter.

4. **Extract query string.** Read the `query` field. If missing or not a string
   → **BLOCKED**.

5. **Parse GraphQL AST.** Parse the query string using `graphql-core`. If
   parsing fails → **BLOCKED**.

6. **Identify the executing operation.** If the document contains multiple
   operation definitions, read `operationName` from the JSON body to identify
   which one executes. If `operationName` is missing or does not match any
   definition → **BLOCKED**. If there is exactly one operation definition,
   `operationName` is optional.

7. **Resolve top-level fields.** For the executing operation definition, collect
   all top-level field selections. Inline fragments on the root type are
   resolved — their field selections are collected as if they were top-level.
   Named fragment spreads at the operation root are not resolved → **BLOCKED**
   (fail-secure; these are not used in practice and resolving them adds
   complexity).

8. **Match against allowlist.** Determine the operation type (`query`,
   `mutation`, or `subscription`). Look up the corresponding pattern list from
   the `graphql` config. If no pattern list exists for this operation type
   (omitted or empty) → **BLOCKED**. For each collected field name, check if it
   matches any pattern using `fnmatch`. If any field does not match →
   **BLOCKED**.

9. **Return allowed.** If all fields match at least one pattern → **ALLOWED**.

### Fail-Secure Summary

| Condition                                      | Result  |
| ---------------------------------------------- | ------- |
| Body is not valid JSON                         | BLOCKED |
| Body is a JSON array (batched)                 | BLOCKED |
| `query` field missing or not a string          | BLOCKED |
| GraphQL parse error                            | BLOCKED |
| Multiple operations without `operationName`    | BLOCKED |
| `operationName` doesn't match any definition   | BLOCKED |
| Body exceeds 1 MiB size limit                  | BLOCKED |
| Named fragment spread at operation root        | BLOCKED |
| Operation type has no patterns (omitted/empty) | BLOCKED |
| Field name doesn't match any pattern           | BLOCKED |

### GraphQL Edge Cases

**Aliases.** GraphQL allows aliasing fields: `{ x: createIssue(...) { ... } }`.
The AST preserves the original field name (`createIssue`), not the alias (`x`).
Aliases do not bypass the allowlist.

**Inline fragments.** Inline fragments at the operation root (e.g.,
`mutation { ... on Mutation { createIssue(...) { ... } } }`) are resolved — the
field selections inside are treated as top-level. This prevents bypass via
trivial wrapping. The type condition is ignored — the filter has no schema
knowledge and cannot validate type conditions. Collecting fields from all inline
fragments is fail-secure (it can only cause false blocks, never false allows).

**Named fragment spreads.** Named fragment spreads at the operation root (e.g.,
`mutation { ...MyFragment }`) are blocked (fail-secure). Resolving these
requires walking the full document to find the fragment definition, adding
complexity for a pattern that does not occur in practice.

**Multiple operations.** A document may contain multiple named operations. The
filter checks **only the executing operation** (identified by `operationName`).
Non-executing operation definitions are ignored — they are inert text that never
executes.

**Introspection.** `__schema` and `__type` are standard query fields subject to
the same pattern matching. If `queries` includes `"*"`, introspection is
allowed. Otherwise, `"__schema"` and/or `"__type"` must be listed explicitly.

**Anonymous (shorthand) queries.** The shorthand syntax `{ viewer { login } }`
is implicitly a `query` operation per the GraphQL spec. It is matched against
the `queries` pattern list.

**Persisted queries.** Requests with no `query` field (hash-based persisted
queries) are fail-secure blocked. Sandboxed agents do not use persisted queries.

## Interaction with GitHub App Credential Scoping

For GitHub App credentials, two layers of GraphQL filtering apply:

```
POST /graphql with GitHub App surrogate token
        │
        ▼
┌─────────────────────────────────────┐
│  Layer 1: Operation Allowlist       │  network-allowlist.yaml
│  (this spec)                        │
│                                     │  "Is this operation permitted at all?"
│  Generic — no GitHub knowledge      │  Blocks: deleteRepository, addComment,
│  Default-deny on operations         │  transferRepository, any unlisted mutation
└──────────┬──────────────────────────┘
           │ operation allowed
           ▼
┌─────────────────────────────────────┐
│  Layer 2: Repository ID Scoping     │  github-app-credential spec
│  (graphql_scope.py — unchanged)     │
│                                     │  "Does this target an allowed repo?"
│  GitHub-specific                    │  Extracts repositoryId from AST + variables
│  Checks only repositoryId field     │  Blocks out-of-scope repo targeting
└──────────┬──────────────────────────┘
           │ repo in scope
           ▼
      Forward request with real token
```

**Layer 1 eliminates the residual risk in Layer 2.** Mutations that accept
non-`repositoryId` targeting fields (e.g., `addComment` with `subjectId`,
`closeIssue` with `issueId`) are simply not listed in the operation allowlist.
The agent uses REST API equivalents for these operations, where URL-level path
scoping naturally restricts which repositories are accessible.

**Layer 2 remains valuable** for mutations that Layer 1 allows. Mutations like
`createIssue` and `createPullRequest` accept `repositoryId`, and Layer 2 ensures
they can only target repositories in the configured set.

## Error Responses

Blocked requests return HTTP 403 with a JSON body:

```json
{
  "error": "graphql_operation_blocked",
  "message": "GraphQL operation 'deleteRepository' is not in the operation allowlist. ...",
  "detail": "deleteRepository"
}
```

Detail values:

| Scenario                        | `detail` value                                          |
| ------------------------------- | ------------------------------------------------------- |
| Unlisted field name             | The field name (e.g., `"deleteRepository"`)             |
| Unlisted operation type         | `"<type>:<blocked>"` (e.g., `"subscription:<blocked>"`) |
| Parse failure                   | `"<unparseable>"`                                       |
| Body exceeds size limit         | `"<too-large>"`                                         |
| Batched request (array body)    | `"<batched>"`                                           |
| Missing/invalid `operationName` | `"<operation-name-invalid>"`                            |
| Fragment spread at root         | `"<fragment-spread>"`                                   |

## Logging

GraphQL operation allowlist events use the existing network log format with a
`graphql-op` tag:

```
ALLOWED POST https://api.github.com/graphql -> 200 [graphql-op: mutation/createIssue] [github-app: cached, graphql-scoped]
BLOCKED POST https://api.github.com/graphql -> 403 [graphql-op: mutation/deleteRepository]
```

The tag format is `[graphql-op: {type}/{field}]` where `type` is `query`,
`mutation`, or `subscription`, and `field` is the first top-level field in AST
order. For BLOCKED responses, `field` is the first field that did not match any
pattern. For requests with multiple top-level fields, only one field is logged
to keep the format concise.
