# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""GraphQL repository scope checking for GitHub App credentials.

Parses GitHub GraphQL requests to extract repository-targeting values
and checks them against allowed repositories.  Two layers of checking:

1. **repositoryId field check** — extracts ``repositoryId`` values
   (inlined, variable-referenced, or in variable objects) and checks
   them against the allowed set of repository node IDs (string match).

2. **Node ID ownership check** — extracts values from all other
   ``*Id``/``*Ids``-suffixed input fields and arguments (including
   list values and recursively nested variable objects), decodes
   GitHub node IDs to extract the embedded parent repository database
   ID, and checks ownership against the allowed repositories.  This
   catches mutations like ``addComment(input: {subjectId: ...})``
   that target repo-scoped objects without an explicit
   ``repositoryId`` field.

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
from node_id import decode_repo_db_id, repo_db_ids_from_node_ids


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
        detail: For OUT_OF_SCOPE, the offending node ID.
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
_TOO_LARGE = ScopeResult(ScopeVerdict.PARSE_ERROR, "<too-large>")

# Maximum request body size for GraphQL scope checking (1 MiB).
# Requests larger than this are blocked to prevent CPU exhaustion via
# graphql-core parsing of very large query strings.
_MAX_BODY_SIZE = 1024 * 1024

# Fields ending in "Id" that are NOT GitHub node IDs.
_SKIP_FIELDS = frozenset({"clientMutationId"})


def _is_id_field(name: str) -> bool:
    """Check if a field name could contain a GitHub node ID.

    Matches ``id``, any name ending with ``Id`` (e.g., ``subjectId``,
    ``pullRequestId``) or ``Ids`` (e.g., ``labelIds``,
    ``assigneeIds``), excluding known non-node-ID fields like
    ``clientMutationId``.
    """
    if name in _SKIP_FIELDS:
        return False
    return name == "id" or name.endswith("Id") or name.endswith("Ids")


class _IdFieldFinder(visitor.Visitor):
    """AST visitor that collects ID field values from input arguments.

    Collects two categories:

    - **repo_***: values from ``repositoryId`` fields (for the primary
      string-match check).
    - **node_id_***: values from all other ``*Id``/``*Ids``-suffixed
      fields (for the node ID ownership check).

    Handles both ``ObjectFieldNode`` (fields inside input objects) and
    ``ArgumentNode`` (top-level mutation arguments) to catch all ID
    values regardless of GraphQL schema conventions.  Also extracts
    string items from ``ListValueNode`` for plural fields like
    ``labelIds``.
    """

    def __init__(self) -> None:
        super().__init__()
        # Primary: repositoryId values
        self.repo_inlined: list[str] = []
        self.repo_var_refs: list[str] = []
        # Defense-in-depth: other *Id field values
        self.node_id_inlined: list[str] = []
        self.node_id_var_refs: list[str] = []

    def _collect_id_value(self, name: str, value: gql_ast.Node) -> None:
        """Route an ID field's value to the appropriate collection."""
        if name == "repositoryId":
            if isinstance(value, gql_ast.StringValueNode):
                self.repo_inlined.append(value.value)
            elif isinstance(value, gql_ast.VariableNode):
                self.repo_var_refs.append(value.name.value)
        elif _is_id_field(name):
            if isinstance(value, gql_ast.StringValueNode):
                self.node_id_inlined.append(value.value)
            elif isinstance(value, gql_ast.VariableNode):
                self.node_id_var_refs.append(value.name.value)
            elif isinstance(value, gql_ast.ListValueNode):
                for item in value.values:
                    if isinstance(item, gql_ast.StringValueNode):
                        self.node_id_inlined.append(item.value)
                    elif isinstance(item, gql_ast.VariableNode):
                        self.node_id_var_refs.append(item.name.value)

    def enter_object_field(
        self, node: gql_ast.ObjectFieldNode, *_args: object
    ) -> None:
        self._collect_id_value(node.name.value, node.value)

    def enter_argument(
        self, node: gql_ast.ArgumentNode, *_args: object
    ) -> None:
        self._collect_id_value(node.name.value, node.value)


def _collect_repo_ids_from_variables(
    obj: dict[str, object], out: list[str]
) -> None:
    """Recursively collect ``repositoryId`` string values from a dict."""
    for key, value in obj.items():
        if key == "repositoryId" and isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            _collect_repo_ids_from_variables(value, out)


def _collect_node_ids_from_variables(
    obj: dict[str, object], out: list[str]
) -> None:
    """Recursively collect ``*Id``/``*Ids`` string values from a dict.

    Skips ``repositoryId`` (handled by layer 1) and known
    non-node-ID fields.  Also extracts string items from lists
    for plural fields like ``labelIds``.
    """
    for key, value in obj.items():
        if key == "repositoryId":
            continue
        if _is_id_field(key):
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        out.append(item)
        elif isinstance(value, dict):
            _collect_node_ids_from_variables(value, out)


def check_repo_scope(
    request_body: bytes,
    allowed_repo_ids: frozenset[str],
) -> ScopeResult:
    """Check if a GraphQL request targets only allowed repositories.

    Performs two layers of scope checking:

    **Layer 1 — repositoryId field check:**

    Extracts ``repositoryId`` values from three paths:

    1. **Inlined in query**: ``{repositoryId: "R_xxx"}`` in the
       GraphQL text — parsed via graphql-core AST.
    2. **Variable references**: ``{repositoryId: $varName}`` in the
       query — resolved against the ``variables`` dict.
    3. **Variable objects**: ``variables.*.repositoryId`` — scanned
       from the JSON variables dict directly.

    **Layer 2 — node ID ownership check:**

    Extracts values from all ``*Id``-suffixed input fields (excluding
    ``clientMutationId``), decodes GitHub node IDs to extract the
    embedded parent repository database ID, and checks ownership.

    This function is **fail-secure**: it returns ALLOWED only when it
    can conclusively determine that all repository-targeting values
    are in the allowed set.  Any parse failure, malformed body, or
    undecodable node ID results in a non-ALLOWED verdict.

    Args:
        request_body: Raw HTTP request body bytes.
        allowed_repo_ids: Set of allowed GitHub repository node IDs.

    Returns:
        ScopeResult with verdict and optional detail.
    """
    # Step 0: Reject oversized bodies to prevent CPU exhaustion
    # via graphql-core parsing of very large query strings.
    if len(request_body) > _MAX_BODY_SIZE:
        return _TOO_LARGE

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
    finder = _IdFieldFinder()
    visitor.visit(document, finder)

    # ------------------------------------------------------------------
    # Layer 1: repositoryId field check (string match)
    # ------------------------------------------------------------------
    collected_ids: list[str] = list(finder.repo_inlined)

    # Step 4: Resolve variable references.
    for var_name in finder.repo_var_refs:
        if var_name not in variables:
            return _UNRESOLVED
        value = variables[var_name]
        if isinstance(value, str):
            collected_ids.append(value)
        # If the value is a dict, the dict scan in step 5 will catch it.

    # Step 5: Scan variable objects (recursively — nested input
    # objects may contain repositoryId at any depth).
    _collect_repo_ids_from_variables(variables, collected_ids)

    # Step 6: Check all collected repositoryId values.
    for repo_id in collected_ids:
        if repo_id not in allowed_repo_ids:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, repo_id)

    # ------------------------------------------------------------------
    # Layer 2: Node ID ownership check (decode + db ID match)
    # ------------------------------------------------------------------
    node_id_values: list[str] = list(finder.node_id_inlined)

    # Resolve *Id variable references.
    for var_name in finder.node_id_var_refs:
        if var_name not in variables:
            return _UNRESOLVED
        value = variables[var_name]
        if isinstance(value, str):
            node_id_values.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    node_id_values.append(item)

    # Scan variable objects for *Id fields (recursively).
    _collect_node_ids_from_variables(variables, node_id_values)

    if not node_id_values:
        return _ALLOWED

    # Build allowed repo database ID set (decoded from R_ node IDs).
    try:
        allowed_db_ids = repo_db_ids_from_node_ids(allowed_repo_ids)
    except ValueError:
        return _PARSE_ERROR

    # Check each node ID value.
    for node_id_value in node_id_values:
        try:
            repo_db_id = decode_repo_db_id(node_id_value)
        except ValueError:
            # Looks like a node ID but can't be decoded — fail-secure.
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, node_id_value)

        if repo_db_id is not None and repo_db_id not in allowed_db_ids:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, node_id_value)

    return _ALLOWED
