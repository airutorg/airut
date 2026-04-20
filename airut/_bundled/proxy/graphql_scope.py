# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""GraphQL repository scope checking for GitHub App credentials.

Parses GitHub GraphQL requests to extract repository-targeting values
and checks them against allowed repositories.  Four layers of checking:

0. **repository(owner, name) field selection check** — catches
   GitHub's ``Query.repository(owner, name)`` and the chained
   ``organization(login).repository(name)`` /
   ``repositoryOwner(login).repository(name)`` /
   ``user(login).repository(name)`` paths that address a repository
   via plain ``String!`` arguments (no ``*Id``/``Name`` field).
   Combines ``owner/name`` and matches against the allowed full names
   case-insensitively.  Without this check, an in-scope GitHub App
   surrogate token can read **any** repository the underlying
   installation token is authorized to see.

1. **repositoryId field check** — extracts ``repositoryId`` values
   (inlined, variable-referenced, or in variable objects) and checks
   them against the allowed set of repository node IDs (string match).

2. **repositoryNameWithOwner field check** — extracts
   ``repositoryNameWithOwner`` string values (e.g. used by
   ``createCommitOnBranch.branch.repositoryNameWithOwner``) and checks
   them against the allowed set of ``owner/name`` repository full
   names, case-insensitively.

3. **Node ID ownership check** — extracts values from all other
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
from node_id import (
    decode_repo_db_id,
    is_non_repo_node_id,
    repo_db_ids_from_node_ids,
)


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


class _StringResolution(enum.Enum):
    """Non-string outcomes of :func:`_resolve_string_value`.

    ``UNRESOLVED`` means the value referenced a variable that wasn't
    bound in the request's ``variables`` dict.  ``MALFORMED`` means
    the AST node was an unsupported kind (e.g. ``IntValueNode``) or
    the bound variable's value wasn't a string.
    """

    UNRESOLVED = "unresolved"
    MALFORMED = "malformed"


def _resolve_string_value(
    value: gql_ast.ValueNode, variables: dict[str, object]
) -> str | _StringResolution:
    """Resolve an AST value or variable reference to a string.

    Returns the literal string for ``StringValueNode``, the bound
    variable's string value for ``VariableNode``,
    :attr:`_StringResolution.UNRESOLVED` if the variable isn't bound,
    or :attr:`_StringResolution.MALFORMED` for any other shape (wrong
    AST node kind, non-string variable value).
    """
    if isinstance(value, gql_ast.StringValueNode):
        return value.value
    if isinstance(value, gql_ast.VariableNode):
        var_name = value.name.value
        if var_name not in variables:
            return _StringResolution.UNRESOLVED
        bound = variables[var_name]
        if isinstance(bound, str):
            return bound
        return _StringResolution.MALFORMED
    return _StringResolution.MALFORMED


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


@dataclass(frozen=True)
class _RepoFieldRef:
    """A ``repository(owner, name)`` field selection awaiting resolution.

    ``owner`` is ``None`` when no parent ``login`` argument could be
    located — e.g. ``viewer.repository(name)`` or a bare
    ``repository(name)`` at the document root — and the reference
    fail-secure blocks during resolution.
    """

    owner: gql_ast.ValueNode | None
    name: gql_ast.ValueNode


def _find_parent_login_arg(
    ancestors: list[gql_ast.Node],
) -> gql_ast.ValueNode | None:
    """Find the immediate parent FieldNode and return its ``login`` arg.

    GitHub's chained repository accessors —
    ``organization(login)``, ``repositoryOwner(login)``,
    ``user(login)`` — all expose ``login`` as a direct argument.  This
    helper walks the visitor's ``ancestors`` list backwards to the
    *immediate* parent ``FieldNode`` and returns its ``login``
    argument value, or ``None`` if no parent ``FieldNode`` is
    reachable or the immediate parent has no ``login`` argument.  We
    deliberately do not look past the immediate parent: if it lacks a
    ``login`` arg, a more-distant ancestor's ``login`` could refer to
    a different entity, so we fail-secure rather than guess.
    """
    for ancestor in reversed(ancestors):
        if isinstance(ancestor, gql_ast.FieldNode):
            for arg in ancestor.arguments or ():
                if arg.name.value == "login":
                    return arg.value
            return None
    return None


class _IdFieldFinder(visitor.Visitor):
    """AST visitor that collects ID field values from input arguments.

    Collects four categories:

    - **repo_field_refs**: ``repository(owner, name)`` field
      selections (Layer 0).
    - **repo_***: values from ``repositoryId`` fields (for the primary
      string-match check against node IDs).
    - **repo_name_***: values from ``repositoryNameWithOwner`` string
      fields (for the ``owner/name`` string-match check).
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
        # Layer 0: repository(owner, name) field selections
        self.repo_field_refs: list[_RepoFieldRef] = []
        # Primary: repositoryId values
        self.repo_inlined: list[str] = []
        self.repo_var_refs: list[str] = []
        # Primary: repositoryNameWithOwner values
        self.repo_name_inlined: list[str] = []
        self.repo_name_var_refs: list[str] = []
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
        elif name == "repositoryNameWithOwner":
            if isinstance(value, gql_ast.StringValueNode):
                self.repo_name_inlined.append(value.value)
            elif isinstance(value, gql_ast.VariableNode):
                self.repo_name_var_refs.append(value.name.value)
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

    def enter_field(
        self,
        node: gql_ast.FieldNode,
        _key: object,
        _parent: object,
        _path: object,
        ancestors: list[gql_ast.Node],
    ) -> None:
        """Collect ``repository(owner, name)`` field selections.

        Selections without a ``name`` argument are ignored: ``Commit``,
        ``Ref`` and several other GitHub types expose ``repository`` as
        an argument-less output field that cannot itself address a
        new repository.
        """
        if node.name.value != "repository":
            return
        owner_val: gql_ast.ValueNode | None = None
        name_val: gql_ast.ValueNode | None = None
        for arg in node.arguments or ():
            if arg.name.value == "owner":
                owner_val = arg.value
            elif arg.name.value == "name":
                name_val = arg.value
        if name_val is None:
            return
        if owner_val is None:
            owner_val = _find_parent_login_arg(ancestors)
        self.repo_field_refs.append(_RepoFieldRef(owner_val, name_val))


def _collect_repo_ids_from_variables(
    obj: dict[str, object], out: list[str]
) -> None:
    """Recursively collect ``repositoryId`` string values from a dict."""
    for key, value in obj.items():
        if key == "repositoryId" and isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            _collect_repo_ids_from_variables(value, out)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _collect_repo_ids_from_variables(item, out)


def _collect_repo_names_from_variables(
    obj: dict[str, object], out: list[str]
) -> None:
    """Recursively collect ``repositoryNameWithOwner`` values from a dict."""
    for key, value in obj.items():
        if key == "repositoryNameWithOwner" and isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            _collect_repo_names_from_variables(value, out)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _collect_repo_names_from_variables(item, out)


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
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _collect_node_ids_from_variables(item, out)


def check_repo_scope(
    request_body: bytes,
    allowed_repo_ids: frozenset[str],
    allowed_repo_full_names: frozenset[str] = frozenset(),
) -> ScopeResult:
    """Check if a GraphQL request targets only allowed repositories.

    Performs four layers of scope checking:

    **Layer 0 — repository(owner, name) field selection check:**

    Extracts ``Query.repository(owner, name)`` selections and the
    chained ``organization(login).repository(name)`` /
    ``repositoryOwner(login).repository(name)`` /
    ``user(login).repository(name)`` shapes that address a repository
    via plain ``String!`` arguments.  Combines ``owner/name`` and
    matches case-insensitively against ``allowed_repo_full_names``.
    A ``repository(name)`` selection without a resolvable parent
    ``login`` is fail-secure blocked.

    **Layer 1 — repositoryId field check:**

    Extracts ``repositoryId`` values from three paths:

    1. **Inlined in query**: ``{repositoryId: "R_xxx"}`` in the
       GraphQL text — parsed via graphql-core AST.
    2. **Variable references**: ``{repositoryId: $varName}`` in the
       query — resolved against the ``variables`` dict.
    3. **Variable objects**: ``variables.*.repositoryId`` — scanned
       from the JSON variables dict directly.

    **Layer 2 — repositoryNameWithOwner field check:**

    Extracts ``repositoryNameWithOwner`` string values (used by
    mutations like ``createCommitOnBranch`` to target a repository by
    ``owner/name``) from the same three paths as Layer 1 and checks
    them against ``allowed_repo_full_names`` case-insensitively.

    **Layer 3 — node ID ownership check:**

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
        allowed_repo_full_names: Set of allowed ``owner/name``
            repository full names.  Matching is case-insensitive.
            An empty set blocks any ``repositoryNameWithOwner``
            value encountered.

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

    allowed_names_lower = frozenset(n.lower() for n in allowed_repo_full_names)

    # ------------------------------------------------------------------
    # Layer 0: repository(owner, name) field selection check
    # ------------------------------------------------------------------
    for ref in finder.repo_field_refs:
        name_str = _resolve_string_value(ref.name, variables)
        if name_str is _StringResolution.UNRESOLVED:
            return _UNRESOLVED
        if name_str is _StringResolution.MALFORMED:
            return _PARSE_ERROR
        if ref.owner is None:
            return ScopeResult(
                ScopeVerdict.OUT_OF_SCOPE, f"<unknown>/{name_str}"
            )
        owner_str = _resolve_string_value(ref.owner, variables)
        if owner_str is _StringResolution.UNRESOLVED:
            return _UNRESOLVED
        if owner_str is _StringResolution.MALFORMED:
            return _PARSE_ERROR
        full_name = f"{owner_str}/{name_str}"
        if full_name.lower() not in allowed_names_lower:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, full_name)

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
    # Layer 2: repositoryNameWithOwner check (case-insensitive match)
    # ------------------------------------------------------------------
    collected_names: list[str] = list(finder.repo_name_inlined)

    for var_name in finder.repo_name_var_refs:
        if var_name not in variables:
            return _UNRESOLVED
        value = variables[var_name]
        if isinstance(value, str):
            collected_names.append(value)

    _collect_repo_names_from_variables(variables, collected_names)

    for name in collected_names:
        if name.lower() not in allowed_names_lower:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, name)

    # ------------------------------------------------------------------
    # Layer 3: Node ID ownership check (decode + db ID match)
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

        if repo_db_id is not None:
            if repo_db_id not in allowed_db_ids:
                return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, node_id_value)
        elif not is_non_repo_node_id(node_id_value):
            # Value in an *Id field that isn't a known non-repo type
            # or a decodable repo-scoped ID.  Fail-secure: block
            # unrecognized formats so future node ID changes can't
            # silently bypass scope checking.
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, node_id_value)

    return _ALLOWED
