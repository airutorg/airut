# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""GraphQL operation allowlist checking.

Parses GraphQL requests to extract the executing operation's type and
top-level field names, then checks them against fnmatch patterns from
the network allowlist.

Uses graphql-core for AST parsing. Only installed inside the proxy
container (not a main airut runtime dependency).
"""

from __future__ import annotations

import enum
import fnmatch
import json
from dataclasses import dataclass

from graphql import parse
from graphql.language import ast as gql_ast


class OperationVerdict(enum.Enum):
    """Result of a GraphQL operation allowlist check."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class OperationResult:
    """Structured result from check_operations().

    Attributes:
        verdict: The operation check outcome.
        detail: For BLOCKED, the field name or diagnostic label that
            caused the block.  For ALLOWED, always None.
        operation_tag: Log tag in the format ``type/field`` (e.g.,
            ``mutation/createIssue``).  Set for both ALLOWED and
            BLOCKED verdicts when the operation could be parsed.
    """

    verdict: OperationVerdict
    detail: str | None = None
    operation_tag: str | None = None


# Pre-built results for common block reasons.
_PARSE_ERROR = OperationResult(OperationVerdict.BLOCKED, "<unparseable>")
_BATCHED = OperationResult(OperationVerdict.BLOCKED, "<batched>")
_OP_NAME_INVALID = OperationResult(
    OperationVerdict.BLOCKED, "<operation-name-invalid>"
)
_FRAGMENT_SPREAD = OperationResult(
    OperationVerdict.BLOCKED, "<fragment-spread>"
)
_TOO_LARGE = OperationResult(OperationVerdict.BLOCKED, "<too-large>")

# Maximum request body size for GraphQL operation checking (1 MiB).
# Requests larger than this are blocked to prevent CPU exhaustion via
# graphql-core parsing of very large query strings.
_MAX_BODY_SIZE = 1024 * 1024

# Map GraphQL OperationType enum values to config keys.
_OP_TYPE_KEYS = {
    "query": "queries",
    "mutation": "mutations",
    "subscription": "subscriptions",
}


def _collect_top_level_fields(
    selections: tuple[gql_ast.SelectionNode, ...],
) -> list[str] | None:
    """Collect top-level field names from a selection set.

    Resolves inline fragments (collects their field selections as
    top-level).  Returns None if a named fragment spread is found
    at the operation root (fail-secure block).

    Args:
        selections: The selection set from the operation definition.

    Returns:
        List of field names, or None if a fragment spread is found.
    """
    fields: list[str] = []
    for sel in selections:
        if isinstance(sel, gql_ast.FieldNode):
            fields.append(sel.name.value)
        elif isinstance(sel, gql_ast.InlineFragmentNode):
            # Resolve inline fragments — collect their fields as
            # top-level.  Type condition is ignored (no schema
            # knowledge).
            if sel.selection_set is not None:
                for inner in sel.selection_set.selections:
                    if isinstance(inner, gql_ast.FieldNode):
                        fields.append(inner.name.value)
                    elif isinstance(inner, gql_ast.InlineFragmentNode):
                        # Nested inline fragments — resolve one more
                        # level for robustness.
                        if inner.selection_set is not None:
                            for nested in inner.selection_set.selections:
                                if isinstance(nested, gql_ast.FieldNode):
                                    fields.append(nested.name.value)
                                else:
                                    # Fragment spread or deeper nesting
                                    return None
                    else:
                        # Named fragment spread inside inline fragment
                        return None
        elif isinstance(sel, gql_ast.FragmentSpreadNode):
            # Named fragment spread at operation root — fail-secure.
            return None
    return fields


def check_operations(
    request_body: bytes,
    graphql_config: dict[str, list[str]],
) -> OperationResult:
    """Check if a GraphQL request's operations are allowed.

    Args:
        request_body: Raw HTTP request body bytes.
        graphql_config: Dict with ``queries``, ``mutations``,
            ``subscriptions`` keys mapping to lists of fnmatch patterns.

    Returns:
        OperationResult with verdict and detail.
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

    # Step 2: Reject arrays (batched queries).
    if isinstance(body, list):
        return _BATCHED

    if not isinstance(body, dict):
        return _PARSE_ERROR

    # Step 3: Extract query string.
    query = body.get("query")
    if not isinstance(query, str):
        return _PARSE_ERROR

    # Step 4: Parse GraphQL AST.
    try:
        document = parse(query)
    except Exception:
        return _PARSE_ERROR

    # Step 5: Identify the executing operation.
    op_defs = [
        d
        for d in document.definitions
        if isinstance(d, gql_ast.OperationDefinitionNode)
    ]

    if not op_defs:
        return _PARSE_ERROR

    if len(op_defs) == 1:
        op = op_defs[0]
    else:
        # Multiple operations — need operationName.
        op_name = body.get("operationName")
        if not isinstance(op_name, str):
            return _OP_NAME_INVALID
        matched = [d for d in op_defs if d.name and d.name.value == op_name]
        if len(matched) != 1:
            return _OP_NAME_INVALID
        op = matched[0]

    # Determine operation type.
    op_type = op.operation.value  # "query", "mutation", "subscription"

    # Step 6: Resolve top-level fields.
    # selection_set is always present for parsed operation definitions.
    assert op.selection_set is not None

    fields = _collect_top_level_fields(op.selection_set.selections)
    if fields is None:
        return _FRAGMENT_SPREAD

    # fields is never empty here: graphql-core requires at least one
    # selection per selection set, and _collect_top_level_fields only
    # returns an empty list if all selections are resolved inline
    # fragments with no fields — which graphql-core rejects at parse
    # time (empty selection sets are a syntax error).
    assert fields

    # Step 7: Match against allowlist.
    # graphql-core OperationType has exactly query/mutation/subscription.
    config_key = _OP_TYPE_KEYS[op_type]

    patterns = graphql_config.get(config_key, [])
    if not patterns:
        # No patterns for this operation type — default-deny.
        tag = f"{op_type}/{fields[0]}"
        return OperationResult(
            OperationVerdict.BLOCKED,
            f"{op_type}:<blocked>",
            operation_tag=tag,
        )

    for field in fields:
        try:
            matched = any(fnmatch.fnmatch(field, pat) for pat in patterns)
        except TypeError:
            # Non-string pattern in config — fail-secure.
            matched = False
        if not matched:
            tag = f"{op_type}/{field}"
            return OperationResult(
                OperationVerdict.BLOCKED,
                field,
                operation_tag=tag,
            )

    # Step 8: All fields match — allowed.
    tag = f"{op_type}/{fields[0]}"
    return OperationResult(OperationVerdict.ALLOWED, operation_tag=tag)
