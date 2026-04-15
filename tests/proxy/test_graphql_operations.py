# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for graphql_operations.check_operations()."""

from __future__ import annotations

import json

from graphql_operations import (  # ty:ignore[unresolved-import]
    OperationResult,
    OperationVerdict,
    check_operations,
)


# Shorthand for expected results used across many tests.
_OK = OperationVerdict.ALLOWED
_BLOCKED = OperationVerdict.BLOCKED

# Standard config that allows all queries and specific mutations.
_STANDARD_CONFIG: dict[str, list[str]] = {
    "queries": ["*"],
    "mutations": ["createIssue", "createPullRequest", "updatePullRequest"],
    "subscriptions": [],
}


def _body(
    query: str,
    variables: dict | None = None,
    operation_name: str | None = None,
) -> bytes:
    """Build a JSON request body for a GraphQL request."""
    payload: dict = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    if operation_name is not None:
        payload["operationName"] = operation_name
    return json.dumps(payload).encode()


# -------------------------------------------------------------------
# Basic allowed/blocked
# -------------------------------------------------------------------


class TestBasicOperations:
    """Tests for basic query/mutation allow/block behavior."""

    def test_query_allowed_wildcard(self) -> None:
        result = check_operations(
            _body("query { viewer { login } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "query/viewer"

    def test_mutation_allowed_exact(self) -> None:
        result = check_operations(
            _body("mutation { createIssue(input: {}) { issue { id } } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "mutation/createIssue"

    def test_mutation_blocked(self) -> None:
        result = check_operations(
            _body(
                "mutation { deleteRepository(input: {}) { clientMutationId } }"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "deleteRepository"
        assert result.operation_tag == "mutation/deleteRepository"

    def test_subscription_blocked_empty_list(self) -> None:
        result = check_operations(
            _body("subscription { issueUpdated { id } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "subscription:<blocked>"
        assert result.operation_tag == "subscription/issueUpdated"

    def test_subscription_blocked_omitted(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["*"],
            "mutations": [],
        }
        result = check_operations(
            _body("subscription { issueUpdated { id } }"),
            config,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "subscription:<blocked>"

    def test_mutation_blocked_no_patterns(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["*"],
            "mutations": [],
            "subscriptions": [],
        }
        result = check_operations(
            _body("mutation { createIssue(input: {}) { issue { id } } }"),
            config,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "mutation:<blocked>"


# -------------------------------------------------------------------
# Pattern matching
# -------------------------------------------------------------------


class TestPatternMatching:
    """Tests for fnmatch pattern matching on field names."""

    def test_wildcard_prefix(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["*"],
            "mutations": ["create*"],
            "subscriptions": [],
        }
        result = check_operations(
            _body("mutation { createIssue(input: {}) { issue { id } } }"),
            config,
        )
        assert result.verdict is _OK

    def test_wildcard_suffix(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["*"],
            "mutations": ["*PullRequest"],
            "subscriptions": [],
        }
        q = "mutation { updatePullRequest(input: {}) { pullRequest { id } } }"
        result = check_operations(_body(q), config)
        assert result.verdict is _OK

    def test_pattern_no_match(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["*"],
            "mutations": ["create*"],
            "subscriptions": [],
        }
        result = check_operations(
            _body(
                "mutation { deleteRepository(input: {}) { clientMutationId } }"
            ),
            config,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "deleteRepository"

    def test_case_sensitive(self) -> None:
        """Pattern matching is case-sensitive per GraphQL spec."""
        config: dict[str, list[str]] = {
            "queries": ["*"],
            "mutations": ["createissue"],  # lowercase
            "subscriptions": [],
        }
        result = check_operations(
            _body("mutation { createIssue(input: {}) { issue { id } } }"),
            config,
        )
        assert result.verdict is _BLOCKED

    def test_multiple_patterns(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["*"],
            "mutations": ["create*", "update*", "merge*"],
            "subscriptions": [],
        }
        q = "mutation { mergePullRequest(input: {}) { pullRequest { id } } }"
        result = check_operations(_body(q), config)
        assert result.verdict is _OK


# -------------------------------------------------------------------
# Multiple top-level fields
# -------------------------------------------------------------------


class TestMultipleFields:
    """Tests for mutations with multiple top-level fields."""

    def test_all_fields_allowed(self) -> None:
        result = check_operations(
            _body(
                "mutation {"
                "  a: createIssue(input: {}) { issue { id } }"
                "  b: createPullRequest(input: {}) { pullRequest { id } }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "mutation/createIssue"

    def test_one_field_blocked(self) -> None:
        result = check_operations(
            _body(
                "mutation {"
                "  a: createIssue(input: {}) { issue { id } }"
                "  b: deleteRepository(input: {}) { clientMutationId }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "deleteRepository"

    def test_first_field_blocked(self) -> None:
        result = check_operations(
            _body(
                "mutation {"
                "  a: deleteRepository(input: {}) { clientMutationId }"
                "  b: createIssue(input: {}) { issue { id } }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "deleteRepository"


# -------------------------------------------------------------------
# Aliases
# -------------------------------------------------------------------


class TestAliases:
    """Tests that aliases don't bypass the allowlist."""

    def test_alias_uses_real_name(self) -> None:
        result = check_operations(
            _body("mutation { x: createIssue(input: {}) { issue { id } } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "mutation/createIssue"

    def test_alias_blocked_by_real_name(self) -> None:
        q = (
            "mutation { safe: deleteRepository(input: {})"
            " { clientMutationId } }"
        )
        result = check_operations(
            _body(q),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "deleteRepository"


# -------------------------------------------------------------------
# Inline fragments
# -------------------------------------------------------------------


class TestInlineFragments:
    """Tests for inline fragment resolution at operation root."""

    def test_inline_fragment_fields_collected(self) -> None:
        result = check_operations(
            _body(
                "mutation {"
                "  ... on Mutation {"
                "    createIssue(input: {}) { issue { id } }"
                "  }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "mutation/createIssue"

    def test_inline_fragment_blocked(self) -> None:
        result = check_operations(
            _body(
                "mutation {"
                "  ... on Mutation {"
                "    deleteRepository(input: {}) { clientMutationId }"
                "  }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "deleteRepository"

    def test_inline_fragment_no_type_condition(self) -> None:
        """Inline fragments without type condition are collected."""
        result = check_operations(
            _body(
                "mutation {"
                "  ... {"
                "    createIssue(input: {}) { issue { id } }"
                "  }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK

    def test_mixed_inline_and_direct_fields(self) -> None:
        result = check_operations(
            _body(
                "mutation {"
                "  createIssue(input: {}) { issue { id } }"
                "  ... on Mutation {"
                "    deleteRepository(input: {}) { clientMutationId }"
                "  }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "deleteRepository"


# -------------------------------------------------------------------
# Named fragment spreads
# -------------------------------------------------------------------


class TestFragmentSpreads:
    """Tests that named fragment spreads at operation root are blocked."""

    def test_fragment_spread_blocked(self) -> None:
        result = check_operations(
            _body(
                "mutation { ...MyFragment }"
                "fragment MyFragment on Mutation {"
                "  createIssue(input: {}) { issue { id } }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<fragment-spread>"

    def test_fragment_spread_inside_inline_fragment(self) -> None:
        result = check_operations(
            _body(
                "mutation {"
                "  ... on Mutation {"
                "    ...MyFragment"
                "  }"
                "}"
                "fragment MyFragment on Mutation {"
                "  createIssue(input: {}) { issue { id } }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<fragment-spread>"


# -------------------------------------------------------------------
# Multiple operations with operationName
# -------------------------------------------------------------------


class TestMultipleOperations:
    """Tests for documents with multiple named operations."""

    def test_selects_named_operation(self) -> None:
        q = (
            "mutation Safe {"
            "  createIssue(input: {}) { issue { id } }"
            "}"
            "mutation Dangerous {"
            "  deleteRepository(input: {}) { clientMutationId }"
            "}"
        )
        result = check_operations(
            _body(q, operation_name="Safe"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "mutation/createIssue"

    def test_missing_operation_name(self) -> None:
        q = (
            "mutation A {"
            "  createIssue(input: {}) { issue { id } }"
            "}"
            "mutation B {"
            "  createPullRequest(input: {}) { pullRequest { id } }"
            "}"
        )
        result = check_operations(
            _body(q),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<operation-name-invalid>"

    def test_non_string_operation_name(self) -> None:
        q = (
            "mutation A {"
            "  createIssue(input: {}) { issue { id } }"
            "}"
            "mutation B {"
            "  createPullRequest(input: {}) { pullRequest { id } }"
            "}"
        )
        body = json.dumps({"query": q, "operationName": 42}).encode()
        result = check_operations(body, _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<operation-name-invalid>"

    def test_operation_name_not_found(self) -> None:
        q = (
            "mutation A {"
            "  createIssue(input: {}) { issue { id } }"
            "}"
            "mutation B {"
            "  createPullRequest(input: {}) { pullRequest { id } }"
            "}"
        )
        result = check_operations(
            _body(q, operation_name="C"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<operation-name-invalid>"

    def test_single_operation_no_name_required(self) -> None:
        """OperationName is optional when there's exactly one operation."""
        result = check_operations(
            _body("mutation { createIssue(input: {}) { issue { id } } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK


# -------------------------------------------------------------------
# Anonymous (shorthand) queries
# -------------------------------------------------------------------


class TestAnonymousQueries:
    """Tests for shorthand query syntax without operation keyword."""

    def test_shorthand_query_allowed(self) -> None:
        result = check_operations(
            _body("{ viewer { login } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "query/viewer"

    def test_shorthand_query_blocked(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["repository"],
            "mutations": [],
            "subscriptions": [],
        }
        result = check_operations(
            _body("{ viewer { login } }"),
            config,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "viewer"


# -------------------------------------------------------------------
# Introspection
# -------------------------------------------------------------------


class TestIntrospection:
    """Tests for __schema and __type introspection fields."""

    def test_introspection_allowed_with_wildcard(self) -> None:
        result = check_operations(
            _body("{ __schema { types { name } } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK

    def test_introspection_blocked_without_pattern(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["viewer", "repository"],
            "mutations": [],
            "subscriptions": [],
        }
        result = check_operations(
            _body("{ __schema { types { name } } }"),
            config,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "__schema"

    def test_introspection_allowed_with_explicit_pattern(self) -> None:
        config: dict[str, list[str]] = {
            "queries": ["viewer", "__schema", "__type"],
            "mutations": [],
            "subscriptions": [],
        }
        result = check_operations(
            _body("{ __schema { types { name } } }"),
            config,
        )
        assert result.verdict is _OK


# -------------------------------------------------------------------
# Parse failures (fail-secure)
# -------------------------------------------------------------------


class TestParseFailures:
    """Tests for malformed payloads that must be blocked."""

    def test_malformed_json(self) -> None:
        result = check_operations(b"not json", _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_empty_body(self) -> None:
        result = check_operations(b"", _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_non_utf8_bytes(self) -> None:
        result = check_operations(b"\xff\xfe", _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_body_is_array(self) -> None:
        body = json.dumps([{"query": "{ viewer { login } }"}]).encode()
        result = check_operations(body, _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<batched>"

    def test_missing_query_field(self) -> None:
        body = json.dumps({"variables": {}}).encode()
        result = check_operations(body, _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_query_not_string(self) -> None:
        body = json.dumps({"query": 42}).encode()
        result = check_operations(body, _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_invalid_graphql(self) -> None:
        body = json.dumps({"query": "this is not graphql!!!"}).encode()
        result = check_operations(body, _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_body_is_string(self) -> None:
        body = json.dumps("a string").encode()
        result = check_operations(body, _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_body_is_number(self) -> None:
        result = check_operations(b"42", _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_null_body(self) -> None:
        result = check_operations(b"null", _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"


# -------------------------------------------------------------------
# OperationResult dataclass
# -------------------------------------------------------------------


class TestOperationResult:
    """Tests for the OperationResult dataclass."""

    def test_defaults(self) -> None:
        r = OperationResult(OperationVerdict.ALLOWED)
        assert r.verdict is OperationVerdict.ALLOWED
        assert r.detail is None
        assert r.operation_tag is None

    def test_all_fields(self) -> None:
        r = OperationResult(
            OperationVerdict.BLOCKED,
            detail="deleteRepository",
            operation_tag="mutation/deleteRepository",
        )
        assert r.verdict is OperationVerdict.BLOCKED
        assert r.detail == "deleteRepository"
        assert r.operation_tag == "mutation/deleteRepository"

    def test_frozen(self) -> None:
        r = OperationResult(OperationVerdict.ALLOWED)
        import pytest

        with pytest.raises(AttributeError):
            r.verdict = OperationVerdict.BLOCKED


# -------------------------------------------------------------------
# Edge cases
# -------------------------------------------------------------------


class TestEdgeCases:
    """Tests for various edge cases in operation checking."""

    def test_query_with_variables(self) -> None:
        """Variables don't affect operation checking."""
        result = check_operations(
            _body(
                "query($owner: String!, $name: String!) {"
                "  repository(owner: $owner, name: $name) { id }"
                "}",
                variables={"owner": "org", "name": "repo"},
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "query/repository"

    def test_empty_config_blocks_everything(self) -> None:
        """Empty config blocks all operations."""
        config: dict[str, list[str]] = {}
        result = check_operations(
            _body("{ viewer { login } }"),
            config,
        )
        assert result.verdict is _BLOCKED

    def test_only_queries_allowed(self) -> None:
        config: dict[str, list[str]] = {"queries": ["*"]}
        # Query should work
        result = check_operations(
            _body("query { viewer { login } }"),
            config,
        )
        assert result.verdict is _OK
        # Mutation should be blocked
        result = check_operations(
            _body("mutation { createIssue(input: {}) { issue { id } } }"),
            config,
        )
        assert result.verdict is _BLOCKED

    def test_nested_inline_fragment(self) -> None:
        """Nested inline fragments are resolved."""
        result = check_operations(
            _body(
                "mutation {"
                "  ... on Mutation {"
                "    ... on Mutation {"
                "      createIssue(input: {}) { issue { id } }"
                "    }"
                "  }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _OK
        assert result.operation_tag == "mutation/createIssue"

    def test_triple_nested_inline_fragment_blocked(self) -> None:
        """3+ levels of inline fragment nesting is blocked."""
        result = check_operations(
            _body(
                "mutation {"
                "  ... on Mutation {"
                "    ... on Mutation {"
                "      ... on Mutation {"
                "        createIssue(input: {}) { issue { id } }"
                "      }"
                "    }"
                "  }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<fragment-spread>"

    def test_fragment_spread_inside_nested_inline(self) -> None:
        """Fragment spread inside nested inline fragment is blocked."""
        result = check_operations(
            _body(
                "mutation {"
                "  ... on Mutation {"
                "    ... on Mutation {"
                "      ...MyFragment"
                "    }"
                "  }"
                "}"
                "fragment MyFragment on Mutation {"
                "  createIssue(input: {}) { issue { id } }"
                "}"
            ),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<fragment-spread>"

    def test_no_operation_definitions(self) -> None:
        """Document with only fragment definitions is blocked."""
        result = check_operations(
            _body("fragment F on Query { viewer { login } }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_empty_selection_set_is_parse_error(self) -> None:
        """Empty selection set is a GraphQL syntax error."""
        result = check_operations(
            _body("mutation { }"),
            _STANDARD_CONFIG,
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "<unparseable>"

    def test_oversized_body_blocked(self) -> None:
        """Request bodies exceeding 1 MiB are blocked."""
        # Construct an oversized body (just over 1 MiB of padding).
        large_body = b'{"query": "query { viewer { login } }"' + b" " * (
            1024 * 1024
        )
        large_body += b"}"
        result = check_operations(large_body, _STANDARD_CONFIG)
        assert result.verdict is _BLOCKED
        assert result.detail == "<too-large>"

    def test_non_string_pattern_fails_secure(self) -> None:
        """Non-string pattern values cause fail-secure block."""
        bad_config: dict[str, list[object]] = {
            "queries": [42],  # type: ignore[dict-item]
            "mutations": [],
            "subscriptions": [],
        }
        result = check_operations(
            _body("query { viewer { login } }"),
            bad_config,  # type: ignore[arg-type]
        )
        assert result.verdict is _BLOCKED
        assert result.detail == "viewer"
