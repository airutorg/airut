# GraphQL Repository Scoping for GitHub App Credentials

Credential-scoped filtering to prevent data exfiltration via GraphQL mutations
targeting public repositories outside the configured set.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Problem](#problem)
  - [Discovery](#discovery)
  - [Root Cause](#root-cause)
  - [Attack Scenario](#attack-scenario)
  - [Scope of Exposure](#scope-of-exposure)
- [Solution: AST-Based GraphQL Repository Scoping](#solution-ast-based-graphql-repository-scoping)
  - [Design Overview](#design-overview)
  - [Why This Approach](#why-this-approach)
  - [Alternatives Considered](#alternatives-considered)
- [Specification](#specification)
  - [Module Structure](#module-structure)
  - [Dependency Isolation](#dependency-isolation)
  - [Repository Node ID Resolution](#repository-node-id-resolution)
  - [GraphQL Request Inspection](#graphql-request-inspection)
  - [Decision Logic](#decision-logic)
  - [Proxy Integration Point](#proxy-integration-point)
  - [Cache Lifecycle](#cache-lifecycle)
  - [Error Handling](#error-handling)
- [Security Analysis](#security-analysis)
  - [What This Blocks](#what-this-blocks)
  - [What Remains Allowed (by Design)](#what-remains-allowed-by-design)
  - [Evasion Analysis](#evasion-analysis)
- [Implementation Scope](#implementation-scope)
- [Test Plan](#test-plan)
  - [Unit: `check_repo_scope()`](#unit-check_repo_scope)
  - [Unit: `fetch_installation_repos()`](#unit-fetch_installation_repos)
  - [Unit: `_try_github_app()` integration](#unit-_try_github_app-integration)
  - [Integration](#integration)

<!-- mdformat-toc end -->

## Problem

### Discovery

During sandbox penetration testing (PR #529), a scope boundary violation was
discovered in the network sandbox's handling of GitHub GraphQL requests. Despite
the REST API being correctly scoped to specific repositories via path-based
allowlist rules, the GraphQL endpoint (`POST /graphql`) is a single URL that
serves all operations — the proxy's path-based filtering cannot distinguish
between operations on allowed vs. disallowed repositories.

### Root Cause

Two independent factors combine to create the vulnerability:

1. **GraphQL is a single endpoint.** All GitHub GraphQL operations go through
   `POST https://api.github.com/graphql`. The REST API allowlist scopes requests
   to specific repos via path patterns (e.g., `/repos/airutorg/airut*`), but the
   GraphQL endpoint has no path structure to filter on.

2. **GitHub platform behavior.** Any authenticated GitHub account — including
   App installation tokens — can perform certain mutations on **public
   repositories** regardless of the App's installation scope. Specifically,
   `createIssue` works on any public repo where issues are enabled. The App does
   not need to be installed on the target repository.

Together, this means a compromised sandbox container can use the GitHub App
installation token (via its surrogate) to create issues on public repositories
outside the configured set, enabling data exfiltration through issue titles,
bodies, and comments.

### Attack Scenario

```
1. Attacker injects prompt into content the agent processes
2. Agent is tricked into constructing a GraphQL mutation:
   mutation {
     createIssue(input: {
       repositoryId: "<public-repo-node-id>",
       title: "exfiltrated data here"
     }) { issue { id } }
   }
3. Proxy sees: POST /graphql → allowed by allowlist
4. Proxy sees: surrogate in Authorization header → replaces with real token
5. GitHub executes the mutation on the attacker's public repo
6. Data is exfiltrated
```

During the pentest, this was confirmed by successfully creating issues on
`airutorg/website` (a public repo) using the App token that was configured only
for `airut` and `sandbox-action` repositories. The issues (#67, #530, #531) were
created despite the App having no installation on the `website` repository.

### Scope of Exposure

An introspection of all 248 GitHub GraphQL mutations reveals a clean split:

- **Repository-targeting mutations** use `repositoryId: ID!` in their input
  type. These are the ones that can target arbitrary public repos. Examples:
  `createIssue`, `createPullRequest`, `createRef`, `createDiscussion`,
  `createLabel`.

- **Object-targeting mutations** use opaque node IDs (e.g., `issueId`,
  `pullRequestId`). These operate on existing objects that are already scoped by
  the App's permissions — the App cannot obtain valid node IDs for objects in
  repos it has no access to.

- **Non-repo mutations** (user settings, org-level, etc.) require permissions
  the App does not have.

The fix needs to address mutations that accept `repositoryId` in their input.
One mutation (`createCommitOnBranch`) uses `repositoryNameWithOwner` instead of
`repositoryId`, but this requires `contents: write` permission on the target
repo, which the App only has on installed repos. See
[Evasion Analysis](#evasion-analysis) for details.

## Solution: AST-Based GraphQL Repository Scoping

### Design Overview

When the proxy handles a GitHub App surrogate replacement for a GraphQL request,
it parses the GraphQL query using `graphql-core` and inspects both the query AST
and the JSON variables for `repositoryId` values. If any `repositoryId` does not
match the configured repositories' node IDs, the proxy **blocks the request**
with HTTP 403, consistent with how other blocked requests are handled.

**The check is fail-secure:** the request is allowed **only** when the function
can conclusively determine that either no `repositoryId` is present or all
`repositoryId` values are in the allowed set. Any parse failure, malformed
payload, or unresolvable variable reference results in a block. In practice,
only well-formed GraphQL from `gh` CLI needs to pass through — exotic or broken
requests are not legitimate and are exactly what an attacker crafting `curl`
commands via prompt injection would produce.

The check extracts `repositoryId` values from three paths:

1. **Inlined in the query text.** The GraphQL AST is parsed to find
   `repositoryId` arguments with literal string values (e.g.,
   `{repositoryId: "R_xxx"}`).
2. **Variable references in the query text.** The AST is parsed to find
   `repositoryId` arguments bound to variables (e.g., `{repositoryId: $id}`).
   The variable name is resolved against the JSON `variables` dict.
3. **Variable objects in the JSON body.** The `variables` dict is scanned for
   top-level values containing a `repositoryId` key (e.g.,
   `variables.input.repositoryId`). This catches the case where an entire input
   object is passed as a variable.

This is not generic GraphQL filtering. It is a targeted check within the
existing GitHub App credential replacement logic that ensures the token is only
provided for operations on in-scope repositories.

### Why This Approach

| Property                  | Benefit                                                                                                                                         |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **Watertight**            | Covers all three paths a `repositoryId` can reach a mutation: inlined values, variable references, and variable objects                         |
| **No false positives**    | AST parsing correctly distinguishes `repositoryId` arguments from the same string appearing inside comments or string literals                  |
| **Credential-scoped**     | Only affects GitHub App credential flow, not the allowlist                                                                                      |
| **Fail-secure**           | Blocks unless it can conclusively prove the request is safe: out-of-scope `repositoryId`, unparseable body, or malformed GraphQL all return 403 |
| **Clean module boundary** | `graphql_scope.py` is a pure function with no mitmproxy dependency — takes bytes in, returns a verdict                                          |
| **Proxy-only dependency** | `graphql-core` is installed only in the proxy container, not in the main airut package                                                          |
| **Zero transitive deps**  | `graphql-core` has zero runtime dependencies on Python 3.13                                                                                     |

### Alternatives Considered

1. **JSON-only variables inspection (no AST parsing).** Scans only the
   `variables` JSON dict for `repositoryId` keys. Simpler (~40 lines, no
   dependencies) but leaves three evasion gaps: (a) inlined values in the query
   string, (b) flat variable bindings (e.g., `$id: ID!` mapped to a string in
   variables), and (c) non-standard variable names. These gaps are exploitable
   via `curl` or raw HTTP from a prompt injection. Rejected because the
   practical barrier to exploitation is low — the surrogate token is in
   `$GH_TOKEN` and a single `curl` command suffices.

2. **Regex scan of the query string.** Scan the `query` field with a regex like
   `repositoryId\s*:\s*(?:"([^"]+)"|\$(\w+))` to find inlined values and
   variable references. Simpler than AST parsing but fragile: cannot distinguish
   `repositoryId` inside string literals or comments from actual arguments,
   leading to false positives. Also mishandles escaped quotes in GraphQL
   strings.

3. **Minimal hand-written tokenizer.** A ~60-line tokenizer that tracks string
   and comment boundaries before scanning for `repositoryId` patterns. More
   robust than regex but still a custom parser that needs its own test surface.
   The `graphql-core` library (the reference implementation port) already solves
   this correctly.

4. **Block all GraphQL mutations (allow only queries).** Would inspect the
   request body for `mutation` keyword. Rejected: Claude Code legitimately needs
   GraphQL mutations for its core workflow — creating PRs, pushing commits,
   updating branch protections, etc.

5. **Remove the `/graphql` allowlist entry entirely.** Rejected: Claude Code
   uses GraphQL for many read operations and some mutations that are essential
   to the workflow (PR creation, commit pushing).

6. **Withhold token replacement instead of blocking.** Would leave the surrogate
   in the Authorization header and let GitHub return 401. Rejected in favor of a
   proxy-level 403 because: (a) a 403 with a descriptive JSON body gives the
   agent clear, actionable feedback; (b) it avoids sending the request to GitHub
   (no rate limit consumption); (c) it is consistent with how the proxy handles
   other blocked requests (allowlist violations, host mismatches).

## Specification

### Module Structure

The GraphQL scope checking logic lives in a dedicated module within the proxy
bundle, separate from `proxy_filter.py`:

```
airut/_bundled/proxy/
  proxy_filter.py       # Calls graphql_scope.check_repo_scope()
  github_app.py         # CachedToken with repo_node_ids, fetch_installation_repos()
  graphql_scope.py      # NEW: pure function, no mitmproxy dependency
  aws_signing.py        # Unchanged
  dns_responder.py      # Unchanged
```

**`graphql_scope.py`** exports a single public function:

```python
"""GraphQL repository scope checking for GitHub App credentials.

Parses GitHub GraphQL requests to extract all repositoryId values —
both inlined in the query text and passed via variables — and checks
them against a set of allowed repository node IDs.

Uses graphql-core for AST parsing. Only installed inside the proxy
container (not a main airut runtime dependency).
"""

from __future__ import annotations


def check_repo_scope(
    request_body: bytes,
    allowed_repo_ids: frozenset[str],
) -> str | None:
    """Check if a GraphQL request targets only allowed repositories.

    Extracts repositoryId values from three paths:

    1. **Inlined in query**: ``{repositoryId: "R_xxx"}`` in the
       GraphQL text — parsed via graphql-core AST.
    2. **Variable references**: ``{repositoryId: $varName}`` in the
       query — resolved against the ``variables`` dict.
    3. **Variable objects**: ``variables.*.repositoryId`` — scanned
       from the JSON variables dict directly.

    This function is **fail-secure**: it returns None (allow) only when
    it can conclusively determine that either no repositoryId is present
    or all repositoryId values are in the allowed set. Any parse failure,
    malformed body, or unexpected structure results in a block. In
    practice, only well-formed GraphQL from ``gh`` CLI needs to pass
    through — exotic or broken requests are not legitimate.

    Args:
        request_body: Raw HTTP request body bytes.
        allowed_repo_ids: Set of allowed GitHub repository node IDs.

    Returns:
        None if the request is conclusively safe (no repositoryId
        found, or all values are in the allowed set). A non-None string
        describing the block reason otherwise: the first out-of-scope
        repositoryId, or a sentinel like ``"<unparseable>"`` for
        requests that could not be conclusively analyzed.
    """
```

**Key design properties:**

- **No mitmproxy dependency.** Takes `bytes` in, returns `str | None`. No `flow`
  object, no HTTP concepts. Testable without the mitmproxy mock infrastructure.
- **Fail-secure.** If JSON decoding, GraphQL parsing, or structural analysis
  fails for any reason, the function returns a sentinel string (block). The
  function returns `None` (allow) **only** when it can conclusively prove the
  request is safe. In practice, `gh` CLI generates clean, standard GraphQL —
  only legitimate requests pass through. Exotic, malformed, or adversarial
  payloads are blocked, which is the correct default for a security boundary.
- **Covers all three extraction paths.** AST parsing handles inlined values and
  variable references. Dict scanning handles whole-input-as-variable.

### Dependency Isolation

`graphql-core` is a proxy-only dependency. It is **not** a runtime dependency of
the main airut package.

**Proxy container** (`airut/_bundled/proxy/pyproject.toml`):

```toml
dependencies = [
    "mitmproxy",
    "cryptography",
    "graphql-core",  # GraphQL AST parsing for repo scope checking
]
```

The `requirements.txt` lockfile is regenerated with hash pins. The existing CI
drift check (`uv export ... | diff - requirements.txt`) ensures the lockfile
stays in sync.

**Main project** (`pyproject.toml`): `graphql-core` is added to the dev
dependency group only, so proxy tests can import it:

```toml
[dependency-groups]
dev = [
    ...
    "graphql-core>=3.2.8",  # For testing proxy graphql_scope module
]
```

This mirrors the existing pattern: `cryptography` is in the dev group for
testing proxy code but is not a main airut runtime dependency.

**Properties of `graphql-core` (v3.2.8):**

- Zero runtime dependencies on Python 3.13 (the only dependency,
  `typing_extensions`, is conditional on `python_version < "3.10"`)
- Pure Python (no C extensions, no native code)
- MIT licensed
- ~3.3M weekly PyPI downloads; port of GraphQL.js (GraphQL Foundation reference
  implementation)

### Repository Node ID Resolution

The proxy resolves configured repository names to GitHub node IDs at **token
refresh time**, immediately after the installation token exchange. This adds one
API call per refresh cycle (once per hour, or on first use).

**API call:** `GET /installation/repositories` authenticated with the freshly
obtained installation access token. This endpoint returns repositories the App
installation can access, each with full metadata including `node_id`. The proxy
uses `per_page=100` and paginates through all results (most installations have
fewer than 100 repos).

**Resolution rules:**

- If the credential config has a `repositories` field (list of bare repo names),
  **only** repos matching those names are included in the node ID set. This
  ensures the GraphQL filter is consistent with the token's repository scope.
- If `repositories` is not configured, **all** repos from the API response are
  included (the token has access to the full installation).
- If a configured repo name does not appear in the API response, it is logged as
  a warning but does not prevent the token from being issued. (The repo may have
  been removed from the App installation.)
- Matching is by bare name (the `name` field from the API response), which is
  unambiguous within a single App installation.

**Data stored alongside the cached token:**

```python
@dataclass(frozen=True)
class CachedToken:
    token: str
    expires_at: float
    repo_node_ids: frozenset[str]  # e.g., {"R_kgDORH34qw", "R_kgDORm2NDQ"}
```

The `repo_node_ids` field defaults to `frozenset()` for backwards compatibility
with existing `CachedToken` instantiation. It is populated during token refresh
and cached with the token. No additional API calls are needed for GraphQL
request inspection.

**New function in `github_app.py`:**

```python
def fetch_installation_repos(
    base_url: str,
    token: str,
    configured_repos: list[str] | None = None,
) -> frozenset[str]:
    """Fetch node IDs of repositories accessible to the installation.

    Args:
        base_url: GitHub API base URL (e.g., "https://api.github.com").
        token: Installation access token (not JWT).
        configured_repos: Optional list of bare repo names to filter by.
            When provided, only repos matching these names are included.
            When None, all installation repos are included.

    Returns:
        Frozenset of repository node IDs.
    """
```

The function paginates through `GET {base_url}/installation/repositories` with
`per_page=100`, collecting `node_id` values. It uses the same
`urllib.request.build_opener(ProxyHandler({}))` pattern as
`fetch_installation_token()` to bypass the proxy.

### GraphQL Request Inspection

The `check_repo_scope()` function in `graphql_scope.py` performs the following
steps:

**Step 1: Parse JSON body.** Extract `query` (string) and `variables` (dict)
from the request body. If JSON decoding fails, the body is not a dict, or the
`query` field is missing or not a string, return `"<unparseable>"` (block).

**Step 2: Parse GraphQL query.** Use `graphql.parse()` to build an AST from the
`query` string. If parsing fails (malformed GraphQL), return `"<unparseable>"`
(block).

**Step 3: Walk the AST.** Use `graphql.visitor.visit()` with a custom visitor
that finds all `repositoryId` arguments in object fields:

```python
from graphql import parse
from graphql.language import ast as gql_ast, visitor


class _RepoIdFinder(visitor.Visitor):
    """AST visitor that collects repositoryId values and variable refs."""

    def __init__(self) -> None:
        super().__init__()
        self.inlined: list[str] = []  # literal string values
        self.var_refs: list[str] = []  # variable names to resolve

    def enter_object_field(self, node: gql_ast.ObjectFieldNode, *_args):
        if node.name.value != "repositoryId":
            return
        if isinstance(node.value, gql_ast.StringValueNode):
            self.inlined.append(node.value.value)
        elif isinstance(node.value, gql_ast.VariableNode):
            self.var_refs.append(node.value.name.value)
```

This correctly handles:

- **Inlined values:** `{repositoryId: "R_xxx"}` → captured in `inlined`.
- **Variable references:** `{repositoryId: $id}` → captured in `var_refs`,
  resolved against `variables` dict in step 4.
- **String literals containing `repositoryId`:** Ignored — the AST distinguishes
  field arguments from string content.
- **Comments containing `repositoryId`:** Ignored — comments are stripped during
  parsing.

**Step 4: Resolve variable references.** For each variable name in `var_refs`,
look up the corresponding value in the `variables` dict. If the value is a
string (flat variable like `$id: ID!`), check it directly. If the variable name
is not found in `variables`, return `"<unresolved-variable>"` (block) — a
variable reference that cannot be resolved cannot be proven safe. If the value
is a dict (should not happen for a `repositoryId` variable reference, but handle
gracefully), skip it (the dict scan in step 5 will catch it).

**Step 5: Scan variable objects.** Independently of the AST, scan all top-level
values in the `variables` dict. For each value that is a dict, check if it
contains a `repositoryId` key. This catches the case where the entire input
object is passed as a variable (`$input: CreateIssueInput!`), where the
`repositoryId` exists only in the JSON, not in the query text.

**Step 6: Check all collected IDs.** For every `repositoryId` found (from
inlined values, resolved variable references, and variable objects), check
against `allowed_repo_ids`. Return the first out-of-scope ID, or `None` if all
are in scope.

### Decision Logic

```
Request arrives at _try_github_app()
  │
  ├─ Surrogate matched in Authorization header? → No → continue to next entry
  │
  ├─ Host in scopes? → No → continue to next entry
  │
  ├─ Get/refresh cached token (with repo_node_ids)
  │
  ├─ Is request to /graphql? (check host against base_url)
  │   │
  │   ├─ No → proceed with normal token replacement (unchanged behavior)
  │   │
  │   └─ Yes → call check_repo_scope(body, cached.repo_node_ids):
  │       │
  │       ├─ Returns None → ALLOW (no out-of-scope repositoryId found)
  │       │
  │       └─ Returns repositoryId string → BLOCK
  │           Return HTTP 403 with JSON error body. Do not replace
  │           surrogate. Return True to prevent _replace_tokens.
  │
  └─ Replace surrogate with real token in header
```

**Key design decisions:**

- **No `repositoryId` → allow.** If the request parses successfully and contains
  no `repositoryId` in any of the three extraction paths, it is conclusively
  safe. Most GraphQL traffic is queries (reads) and object-targeting mutations
  (which are already permission-scoped). Blocking these would break the core
  workflow.
- **Parse failure → block (fail-secure).** If the body is not valid JSON, the
  `query` field is missing, or the GraphQL does not parse, the request is
  blocked. The function cannot conclusively prove the request is safe, so it
  must be disallowed. In practice this does not affect legitimate use — `gh` CLI
  and standard GraphQL clients always send well-formed requests. Exotic,
  malformed, or adversarial payloads crafted via `curl` from a prompt injection
  are exactly what should be blocked.
- **Unresolved variable reference → block.** If the AST contains
  `repositoryId: $varName` but `$varName` is not present in the `variables`
  dict, the function cannot determine whether the repositoryId is in scope. The
  request is blocked.
- **Any `repositoryId` out of scope → block.** If a request carries multiple
  `repositoryId` values (e.g., aliased mutations), **all** must be in scope. One
  out-of-scope ID blocks the entire request.
- **Empty `repo_node_ids` → skip check.** If node ID resolution failed (API
  error), the `check_repo_scope()` function is not called — the caller checks
  `cached.repo_node_ids` before invoking. This is a **degraded mode**: the
  filter is temporarily ineffective, but availability is preserved. The next
  token refresh will retry resolution.

**403 response body (out-of-scope repositoryId):**

```json
{
  "error": "graphql_repo_scope_blocked",
  "message": "GraphQL mutation targets repository outside configured scope. The repositoryId R_xxx is not in the set of allowed repositories for this GitHub App credential.",
  "detail": "R_xxx"
}
```

**403 response body (unparseable request):**

```json
{
  "error": "graphql_repo_scope_blocked",
  "message": "GraphQL request blocked: could not verify repository scope (<unparseable>). Only well-formed GraphQL requests are allowed when repository scoping is active.",
  "detail": "<unparseable>"
}
```

### Proxy Integration Point

The check is added to `_try_github_app()` in `proxy_filter.py`. The GraphQL
scope check runs **after** token refresh (so `repo_node_ids` are available) but
**before** replacing the surrogate with the real token in the header:

```python
from graphql_scope import check_repo_scope

# In _try_github_app(), after successful token refresh/cache lookup:

# GraphQL repository scope check (fail-secure)
if cached.repo_node_ids and flow.request.path.startswith("/graphql"):
    blocked = check_repo_scope(
        flow.request.get_content(),
        cached.repo_node_ids,
    )
    if blocked is not None:
        # blocked is either a repositoryId or a sentinel like "<unparseable>"
        is_parse_error = blocked.startswith("<")
        if is_parse_error:
            msg = (
                f"GraphQL request blocked: could not verify "
                f"repository scope ({blocked}). Only well-formed "
                f"GraphQL requests are allowed when repository "
                f"scoping is active."
            )
        else:
            msg = (
                f"GraphQL mutation targets repository outside "
                f"configured scope. The repositoryId {blocked} "
                f"is not in the set of allowed repositories "
                f"for this GitHub App credential."
            )
        self._log_loud(
            f"BLOCKED {flow.request.method} "
            f"{flow.request.pretty_url} "
            f"[github-app: {blocked}]"
        )
        flow.response = http.Response.make(
            403,
            json.dumps(
                {
                    "error": "graphql_repo_scope_blocked",
                    "message": msg,
                    "detail": blocked,
                }
            ),
            {"Content-Type": "application/json"},
        )
        return True

# ... existing token replacement logic ...
```

The `/graphql` path check applies regardless of the host — it covers both
`api.github.com` and GHES instances. The host is already verified against the
credential's scopes earlier in `_try_github_app()`.

### Cache Lifecycle

The `repo_node_ids` set follows the same lifecycle as the installation token:

1. **First request:** No cached token, no node IDs. Token refresh fires →
   exchanges JWT for installation token → calls `fetch_installation_repos()`
   with the new token → populates both token and node IDs in `CachedToken`.

2. **Subsequent requests (cache hit):** Token and node IDs served from cache. No
   API calls.

3. **Token near expiry (5-min margin):** Token refresh fires → refreshes both
   token and node IDs. If the App's installation has changed repos since last
   refresh, the node ID set updates.

4. **Proxy restart:** Cache is empty (in-memory only). First request triggers
   fresh resolution.

### Error Handling

**`fetch_installation_repos()` call fails:**

- Log a warning via `_log_loud()`.
- Set `repo_node_ids` to an empty frozenset.
- With empty node IDs, the GraphQL check is skipped entirely (the
  `if cached.repo_node_ids` guard). This is a **degraded mode** — the filter is
  temporarily ineffective, but availability is preserved.
- The token itself is still usable — only the GraphQL scoping is degraded.
- Next refresh cycle will retry.

**Token refresh fails (existing behavior, unchanged):**

- Return HTTP 502 to the container.
- No node ID resolution attempted (no token to use).

**GraphQL parse failure (in `check_repo_scope()`):**

- Return a sentinel string like `"<unparseable>"` (block). The function cannot
  conclusively prove the request is safe, so it must be disallowed.
- The caller logs the block and returns HTTP 403 with a descriptive message.
- In practice, this only fires for adversarial or malformed payloads — `gh` CLI
  always sends well-formed GraphQL. Legitimate traffic is unaffected.

## Security Analysis

### What This Blocks

- `createIssue` on public repos outside the configured set
- `createPullRequest` on public repos outside the configured set
- `createRef`, `createLabel`, `createDiscussion`, etc. on out-of-scope repos
- Any future GitHub mutation that uses `repositoryId` in its input
- Aliased mutations where multiple `repositoryId` values target different repos
- Inlined `repositoryId` values in the GraphQL query string (not just variables)
- Flat variable bindings (`$id: ID!` → `variables.id = "R_xxx"`)
- Malformed or unparseable GraphQL requests (fail-secure: if it can't be
  verified, it's blocked)
- Requests with unresolvable variable references (`repositoryId: $x` where `$x`
  is not in `variables`)

### What Remains Allowed (by Design)

- **All GraphQL queries (reads).** Queries do not modify state and do not carry
  `repositoryId` in the same input pattern.

- **Mutations on configured repos.** `createIssue` on `airutorg/airut` works
  normally — this is the intended workflow.

- **Object-targeting mutations.** Mutations like
  `updateIssue(input: {issueId: ...})` do not use `repositoryId` and are already
  scoped by the App's permissions. The App cannot obtain valid node IDs for
  objects in repos it has no access to.

- **Non-repo mutations.** User or org-level mutations require permissions the
  App does not have. These are blocked by GitHub's permission model, not by this
  filter.

### Evasion Analysis

| Evasion Vector                                           | Mitigated              | How                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Inlined `repositoryId` in query text**                 | Yes                    | The GraphQL AST is parsed; inlined string values in `repositoryId` object fields are extracted and checked.                                                                                                                                                                                                                                                       |
| **Flat variable binding (`$id: ID!`)**                   | Yes                    | The AST finds `repositoryId: $id`, resolves `$id` against the `variables` dict, and checks the string value.                                                                                                                                                                                                                                                      |
| **Whole input object as variable**                       | Yes                    | The `variables` dict is scanned independently of the AST. `variables.input.repositoryId` and similar patterns are caught.                                                                                                                                                                                                                                         |
| **Aliased mutations with different variable names**      | Yes                    | The AST visitor finds all `repositoryId` fields regardless of mutation aliases or variable names. The variables dict scan covers all top-level values.                                                                                                                                                                                                            |
| **`repositoryId` in comments**                           | Yes                    | GraphQL comments are stripped during AST parsing and never produce object field nodes.                                                                                                                                                                                                                                                                            |
| **`repositoryId` in string literals**                    | Yes                    | String literal values (e.g., in a `title` argument) produce `StringValueNode` under the `title` field, not under a `repositoryId` field. The AST distinguishes these structurally.                                                                                                                                                                                |
| **Batch queries**                                        | Yes                    | GitHub's GraphQL endpoint does not support batch queries (array of operations).                                                                                                                                                                                                                                                                                   |
| **Automatic Persisted Queries (APQ)**                    | N/A                    | GitHub does not support APQ. All queries include the full query text.                                                                                                                                                                                                                                                                                             |
| **GET-based GraphQL**                                    | N/A                    | GitHub's GraphQL endpoint only accepts POST.                                                                                                                                                                                                                                                                                                                      |
| **Constructing `repositoryId` from known patterns**      | Mitigated              | Node IDs are opaque Base64 strings. The attacker needs the database ID, which is enumerable but limits opportunistic exfiltration.                                                                                                                                                                                                                                |
| **Using REST instead of GraphQL**                        | Yes                    | REST paths are already scoped to configured repos (e.g., `/repos/airutorg/airut*`).                                                                                                                                                                                                                                                                               |
| **`createCommitOnBranch` via `repositoryNameWithOwner`** | N/A (GitHub-mitigated) | This mutation uses `branch.repositoryNameWithOwner` instead of `repositoryId`. However, it requires `contents: write` permission on the target repo, which the App only has on installed repos. An out-of-scope repo would return a permission error from GitHub regardless of this filter.                                                                       |
| **`createPullRequest` with `headRepositoryId`**          | Partial                | `createPullRequest` accepts both `repositoryId` (base repo, checked) and optional `headRepositoryId` (head repo for cross-fork PRs, not checked). However, `headRepositoryId` only specifies where commits come *from*, not where the PR is *created*. The PR is created on the base repo (`repositoryId`), which is checked. This is not an exfiltration vector. |
| **Malformed/adversarial GraphQL payload**                | Yes                    | Fail-secure: if JSON or GraphQL parsing fails for any reason, the request is blocked. An attacker cannot bypass the check by sending broken syntax — only well-formed requests that can be conclusively analyzed are allowed through.                                                                                                                             |
| **Unresolvable variable reference**                      | Yes                    | If the AST contains `repositoryId: $x` but `$x` is not in the `variables` dict, the request is blocked — the repositoryId value cannot be verified.                                                                                                                                                                                                               |
| **Unicode escapes in GraphQL strings**                   | Yes                    | `graphql-core` resolves Unicode escapes during parsing. The extracted string value is the resolved form, which is compared directly against the allowed set.                                                                                                                                                                                                      |

## Implementation Scope

| Component                                 | Change                                                                                                        |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `graphql_scope.py` (new)                  | `check_repo_scope()` function — GraphQL AST parsing + variables scanning, no mitmproxy dependency             |
| `github_app.py`                           | Add `fetch_installation_repos()` function; add `repo_node_ids` field to `CachedToken` (default `frozenset()`) |
| `proxy_filter.py`                         | Import `check_repo_scope`; call it from `_try_github_app()` after token refresh but before replacement        |
| `proxy/pyproject.toml`                    | Add `graphql-core` to dependencies                                                                            |
| `proxy/requirements.txt`                  | Regenerate with hash pins (via `uv lock && uv export`)                                                        |
| `pyproject.toml`                          | Add `graphql-core>=3.2.8` to dev dependency group                                                             |
| `tests/proxy/test_graphql_scope.py` (new) | Unit tests for `check_repo_scope()` — the bulk of test cases                                                  |
| `tests/proxy/test_github_app.py`          | Unit tests for `fetch_installation_repos()`                                                                   |
| `tests/proxy/test_proxy_filter.py`        | Integration tests for `_try_github_app()` with GraphQL scoping                                                |
| `spec/github-app-credential.md`           | Add reference to this spec                                                                                    |
| `doc/network-sandbox.md`                  | Add note about GraphQL scoping in the GitHub App Credentials section                                          |

Estimated addition: ~100 lines of production code (60 in `graphql_scope.py`, 40
in `github_app.py`, ~10 in `proxy_filter.py`), plus tests.

No changes to:

- Network allowlist format or parsing
- Server config schema (repos are already declared in `repositories` field)
- Container environment or surrogate generation
- Other credential types (masked secrets, signing credentials)
- Non-GitHub-App credential flows
- Main airut runtime dependencies

## Test Plan

### Unit: `check_repo_scope()`

Tests for `graphql_scope.check_repo_scope()` — the core logic. These tests
import the module directly and do not require mitmproxy mocks.

**Inlined values (AST path 1):**

- [ ] Inlined `repositoryId` in scope → returns None.
- [ ] Inlined `repositoryId` out of scope → returns the ID.
- [ ] Multiple inlined `repositoryId` values (aliased mutations) — all in scope
  → None.
- [ ] Multiple inlined `repositoryId` values — one out of scope → returns that
  ID.

**Variable references (AST path 2):**

- [ ] `repositoryId: $id` with `variables.id` as flat string — in scope → None.
- [ ] `repositoryId: $id` with `variables.id` as flat string — out of scope →
  returns the ID.
- [ ] `repositoryId: $myVar` with non-standard variable name — correctly
  resolved.

**Variable objects (JSON path 3):**

- [ ] `repositoryId` in `variables.input` — in scope → None.
- [ ] `repositoryId` in `variables.input` — out of scope → returns the ID.
- [ ] Multiple variable objects (`variables.a`, `variables.b`) — all in scope →
  None.
- [ ] Multiple variable objects — one out of scope → returns that ID.

**Combined paths:**

- [ ] Inlined value + variable object in same request — both checked.
- [ ] Variable reference + variable object in same request — both checked.

**No `repositoryId` (allow):**

- [ ] GraphQL query (read) with no `repositoryId` → None.
- [ ] Object-targeting mutation (e.g., `updateIssue` with `issueId`) → None.
- [ ] Empty variables → None.
- [ ] Non-dict variables → None.
- [ ] No `variables` field at all → None.

**Parse failures (fail-secure — block):**

- [ ] Malformed JSON body → returns sentinel (block).
- [ ] Valid JSON but invalid GraphQL query string → returns sentinel (block).
- [ ] Empty request body → returns sentinel (block).
- [ ] Non-UTF-8 bytes → returns sentinel (block).
- [ ] JSON body missing `query` field → returns sentinel (block).
- [ ] `query` field is not a string (e.g., integer) → returns sentinel (block).
- [ ] `repositoryId: $x` where `$x` is not in `variables` → returns sentinel
  (block).

**False positive resistance:**

- [ ] `repositoryId` appearing inside a string literal (e.g., `title`) is NOT
  extracted.
- [ ] `repositoryId` appearing in a comment is NOT extracted.
- [ ] Unicode escapes in `repositoryId` value are resolved before comparison.

### Unit: `fetch_installation_repos()`

- [ ] Mock `/installation/repositories` response, verify bare repo names are
  resolved to node IDs correctly.
- [ ] Verify filtering by `configured_repos` — only matching names included.
- [ ] Verify `configured_repos=None` includes all repos from API response.
- [ ] Verify pagination — mock response requiring two pages (100+N repos),
  verify all node IDs collected.
- [ ] Verify API failure returns empty frozenset and logs warning.
- [ ] Verify configured repo not in API response logs warning but does not fail.

### Unit: `_try_github_app()` integration

- [ ] GraphQL mutation with out-of-scope `repositoryId` returns HTTP 403 with
  `graphql_repo_scope_blocked` error.
- [ ] GraphQL mutation with in-scope `repositoryId` proceeds normally (token
  replaced).
- [ ] Non-GraphQL request (REST API) skips body inspection entirely.
- [ ] GraphQL query (no `repositoryId`) proceeds normally.
- [ ] Verify 403 response body contains the blocked `repositoryId`.
- [ ] Verify `repo_node_ids` populated during token refresh (mock both
  `fetch_installation_token` and `fetch_installation_repos`).
- [ ] Malformed GraphQL body returns HTTP 403 (fail-secure).
- [ ] Empty `repo_node_ids` (resolution failed) → GraphQL check skipped, request
  proceeds.

### Integration

- [ ] End-to-end: `createIssue` mutation targeting out-of-scope public repo →
  receives 403 from proxy.
- [ ] End-to-end: `createIssue` mutation targeting configured repo → succeeds.
- [ ] End-to-end: GraphQL queries unaffected by the filter.
