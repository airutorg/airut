# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""GraphQL repository scope checking for GitHub App credentials.

Parses GitHub GraphQL requests to extract all repositoryId values —
both inlined in the query text and passed via variables — and checks
them against a set of allowed repository node IDs.

Uses graphql-core for AST parsing. Only installed inside the proxy
container (not a main airut runtime dependency).
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass

from graphql import parse
from graphql.language import ast as gql_ast
from graphql.language import visitor


class ScopeVerdict(enum.Enum):
    """Result of a GraphQL repository scope check."""

    ALLOWED = "allowed"
    OUT_OF_SCOPE = "out_of_scope"
    PARSE_ERROR = "parse_error"
    UNRESOLVED_VARIABLE = "unresolved_variable"


@dataclass(frozen=True)
class ScopeResult:
    """Structured result from check_repo_scope().

    Attributes:
        verdict: The scope check outcome.
        detail: For OUT_OF_SCOPE, the offending repositoryId.
            For PARSE_ERROR / UNRESOLVED_VARIABLE, a diagnostic label.
            For ALLOWED, always None.
    """

    verdict: ScopeVerdict
    detail: str | None = None


# Pre-built results for common cases.
_ALLOWED = ScopeResult(ScopeVerdict.ALLOWED)
_PARSE_ERROR = ScopeResult(ScopeVerdict.PARSE_ERROR, "<unparseable>")
_UNRESOLVED = ScopeResult(
    ScopeVerdict.UNRESOLVED_VARIABLE, "<unresolved-variable>"
)


class _RepoIdFinder(visitor.Visitor):
    """AST visitor that collects repositoryId values and variable refs."""

    def __init__(self) -> None:
        super().__init__()
        self.inlined: list[str] = []
        self.var_refs: list[str] = []

    def enter_object_field(
        self, node: gql_ast.ObjectFieldNode, *_args: object
    ) -> None:
        if node.name.value != "repositoryId":
            return
        if isinstance(node.value, gql_ast.StringValueNode):
            self.inlined.append(node.value.value)
        elif isinstance(node.value, gql_ast.VariableNode):
            self.var_refs.append(node.value.name.value)


def check_repo_scope(
    request_body: bytes,
    allowed_repo_ids: frozenset[str],
) -> ScopeResult:
    """Check if a GraphQL request targets only allowed repositories.

    Extracts repositoryId values from three paths:

    1. **Inlined in query**: ``{repositoryId: "R_xxx"}`` in the
       GraphQL text — parsed via graphql-core AST.
    2. **Variable references**: ``{repositoryId: $varName}`` in the
       query — resolved against the ``variables`` dict.
    3. **Variable objects**: ``variables.*.repositoryId`` — scanned
       from the JSON variables dict directly.

    This function is **fail-secure**: it returns ALLOWED only when it
    can conclusively determine that either no repositoryId is present
    or all repositoryId values are in the allowed set. Any parse
    failure, malformed body, or unexpected structure results in a
    non-ALLOWED verdict.

    Args:
        request_body: Raw HTTP request body bytes.
        allowed_repo_ids: Set of allowed GitHub repository node IDs.

    Returns:
        ScopeResult with verdict and optional detail.
    """
    # Step 1: Parse JSON body.
    try:
        body = json.loads(request_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _PARSE_ERROR

    if not isinstance(body, dict):
        return _PARSE_ERROR

    query = body.get("query")
    if not isinstance(query, str):
        return _PARSE_ERROR

    variables = body.get("variables")
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        variables = {}

    # Step 2: Parse GraphQL query.
    try:
        document = parse(query)
    except Exception:
        return _PARSE_ERROR

    # Step 3: Walk the AST.
    finder = _RepoIdFinder()
    visitor.visit(document, finder)

    collected_ids: list[str] = list(finder.inlined)

    # Step 4: Resolve variable references.
    for var_name in finder.var_refs:
        if var_name not in variables:
            return _UNRESOLVED
        value = variables[var_name]
        if isinstance(value, str):
            collected_ids.append(value)
        # If the value is a dict, the dict scan in step 5 will catch it.

    # Step 5: Scan variable objects.
    for value in variables.values():
        if isinstance(value, dict) and "repositoryId" in value:
            repo_id = value["repositoryId"]
            if isinstance(repo_id, str):
                collected_ids.append(repo_id)

    # Step 6: Check all collected IDs.
    for repo_id in collected_ids:
        if repo_id not in allowed_repo_ids:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, repo_id)

    return _ALLOWED
