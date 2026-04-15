# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for graphql_scope.check_repo_scope()."""

from __future__ import annotations

import json

from graphql_scope import (  # ty:ignore[unresolved-import]
    ScopeResult,
    ScopeVerdict,
    check_repo_scope,
)


ALLOWED = frozenset({"R_kgDORH34qw", "R_kgDORm2NDQ"})

# Shorthand for expected results used across many tests.
_OK = ScopeResult(ScopeVerdict.ALLOWED)
_PARSE = ScopeResult(ScopeVerdict.PARSE_ERROR, "<unparseable>")
_UNRESOLVED = ScopeResult(
    ScopeVerdict.UNRESOLVED_VARIABLE, "<unresolved-variable>"
)


def _oos(repo_id: str) -> ScopeResult:
    """Build an OUT_OF_SCOPE result for *repo_id*."""
    return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, repo_id)


def _body(
    query: str,
    variables: dict | None = None,
) -> bytes:
    """Build a JSON request body for a GraphQL request."""
    payload: dict = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    return json.dumps(payload).encode()


# -------------------------------------------------------------------
# Inlined values (AST path 1)
# -------------------------------------------------------------------


class TestInlinedValues:
    """Tests for repositoryId values inlined directly in the query."""

    def test_inlined_in_scope(self) -> None:
        body = _body(
            'mutation { createIssue(input: {repositoryId: "R_kgDORH34qw",'
            ' title: "test"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_inlined_out_of_scope(self) -> None:
        body = _body(
            'mutation { createIssue(input: {repositoryId: "R_bad_id",'
            ' title: "test"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_bad_id")

    def test_multiple_inlined_all_in_scope(self) -> None:
        body = _body(
            "mutation {"
            '  a: createIssue(input: {repositoryId: "R_kgDORH34qw",'
            '    title: "a"}) { issue { id } }'
            '  b: createIssue(input: {repositoryId: "R_kgDORm2NDQ",'
            '    title: "b"}) { issue { id } }'
            "}"
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_multiple_inlined_one_out_of_scope(self) -> None:
        body = _body(
            "mutation {"
            '  a: createIssue(input: {repositoryId: "R_kgDORH34qw",'
            '    title: "a"}) { issue { id } }'
            '  b: createIssue(input: {repositoryId: "R_evil",'
            '    title: "b"}) { issue { id } }'
            "}"
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")


# -------------------------------------------------------------------
# Variable references (AST path 2)
# -------------------------------------------------------------------


class TestVariableReferences:
    """Tests for repositoryId bound to variables in the query."""

    def test_var_ref_in_scope(self) -> None:
        body = _body(
            "mutation($id: ID!) {"
            "  createIssue(input: {repositoryId: $id,"
            '    title: "t"}) { issue { id } }'
            "}",
            variables={"id": "R_kgDORH34qw"},
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_var_ref_out_of_scope(self) -> None:
        body = _body(
            "mutation($id: ID!) {"
            "  createIssue(input: {repositoryId: $id,"
            '    title: "t"}) { issue { id } }'
            "}",
            variables={"id": "R_evil"},
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_var_ref_nonstandard_name(self) -> None:
        body = _body(
            "mutation($myRepoVar: ID!) {"
            "  createIssue(input: {repositoryId: $myRepoVar,"
            '    title: "t"}) { issue { id } }'
            "}",
            variables={"myRepoVar": "R_kgDORm2NDQ"},
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_var_ref_unresolved(self) -> None:
        body = _body(
            "mutation($id: ID!) {"
            "  createIssue(input: {repositoryId: $id,"
            '    title: "t"}) { issue { id } }'
            "}",
            variables={},
        )
        assert check_repo_scope(body, ALLOWED) == _UNRESOLVED


# -------------------------------------------------------------------
# Variable objects (JSON path 3)
# -------------------------------------------------------------------


class TestVariableObjects:
    """Tests for repositoryId inside variable objects."""

    def test_var_object_in_scope(self) -> None:
        body = _body(
            "mutation($input: CreateIssueInput!) {"
            "  createIssue(input: $input) { issue { id } }"
            "}",
            variables={
                "input": {
                    "repositoryId": "R_kgDORH34qw",
                    "title": "test",
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_var_object_out_of_scope(self) -> None:
        body = _body(
            "mutation($input: CreateIssueInput!) {"
            "  createIssue(input: $input) { issue { id } }"
            "}",
            variables={
                "input": {
                    "repositoryId": "R_evil",
                    "title": "test",
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_multiple_var_objects_all_in_scope(self) -> None:
        body = _body(
            "mutation($a: CreateIssueInput!, $b: CreateIssueInput!) {"
            "  x: createIssue(input: $a) { issue { id } }"
            "  y: createIssue(input: $b) { issue { id } }"
            "}",
            variables={
                "a": {
                    "repositoryId": "R_kgDORH34qw",
                    "title": "a",
                },
                "b": {
                    "repositoryId": "R_kgDORm2NDQ",
                    "title": "b",
                },
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_multiple_var_objects_one_out_of_scope(self) -> None:
        body = _body(
            "mutation($a: CreateIssueInput!, $b: CreateIssueInput!) {"
            "  x: createIssue(input: $a) { issue { id } }"
            "  y: createIssue(input: $b) { issue { id } }"
            "}",
            variables={
                "a": {
                    "repositoryId": "R_kgDORH34qw",
                    "title": "a",
                },
                "b": {
                    "repositoryId": "R_evil",
                    "title": "b",
                },
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")


# -------------------------------------------------------------------
# Combined paths
# -------------------------------------------------------------------


class TestCombinedPaths:
    """Tests for repositoryId found through multiple extraction paths."""

    def test_inlined_plus_var_object(self) -> None:
        body = _body(
            "mutation($b: CreateIssueInput!) {"
            '  a: createIssue(input: {repositoryId: "R_kgDORH34qw",'
            '    title: "a"}) { issue { id } }'
            "  b: createIssue(input: $b) { issue { id } }"
            "}",
            variables={
                "b": {
                    "repositoryId": "R_evil",
                    "title": "b",
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_var_ref_plus_var_object(self) -> None:
        body = _body(
            "mutation($id: ID!, $input: CreateIssueInput!) {"
            '  a: createIssue(input: {repositoryId: $id, title: "a"})'
            "    { issue { id } }"
            "  b: createIssue(input: $input) { issue { id } }"
            "}",
            variables={
                "id": "R_kgDORH34qw",
                "input": {
                    "repositoryId": "R_kgDORm2NDQ",
                    "title": "b",
                },
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK


# -------------------------------------------------------------------
# No repositoryId (allow)
# -------------------------------------------------------------------


class TestNoRepositoryId:
    """Tests for requests that do not contain repositoryId."""

    def test_query_no_repo_id(self) -> None:
        body = _body("query { viewer { login } }")
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_object_targeting_mutation(self) -> None:
        body = _body(
            'mutation { updateIssue(input: {id: "I_123",'
            ' title: "updated"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_empty_variables(self) -> None:
        body = _body("query { viewer { login } }", variables={})
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_no_variables_field(self) -> None:
        body = json.dumps({"query": "query { viewer { login } }"}).encode()
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_non_dict_variables(self) -> None:
        body = json.dumps(
            {"query": "query { viewer { login } }", "variables": "null"}
        ).encode()
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_null_variables(self) -> None:
        body = json.dumps(
            {"query": "query { viewer { login } }", "variables": None}
        ).encode()
        assert check_repo_scope(body, ALLOWED) == _OK


# -------------------------------------------------------------------
# Parse failures (fail-secure — block)
# -------------------------------------------------------------------


class TestParseFailures:
    """Tests for malformed/adversarial payloads that must be blocked."""

    def test_malformed_json(self) -> None:
        assert check_repo_scope(b"not json", ALLOWED) == _PARSE

    def test_invalid_graphql(self) -> None:
        body = json.dumps({"query": "this is not graphql!!!"}).encode()
        assert check_repo_scope(body, ALLOWED) == _PARSE

    def test_empty_body(self) -> None:
        assert check_repo_scope(b"", ALLOWED) == _PARSE

    def test_non_utf8_bytes(self) -> None:
        assert check_repo_scope(b"\xff\xfe", ALLOWED) == _PARSE

    def test_missing_query_field(self) -> None:
        body = json.dumps({"variables": {}}).encode()
        assert check_repo_scope(body, ALLOWED) == _PARSE

    def test_query_not_string(self) -> None:
        body = json.dumps({"query": 42}).encode()
        assert check_repo_scope(body, ALLOWED) == _PARSE

    def test_body_is_array(self) -> None:
        body = json.dumps([{"query": "{ viewer { login } }"}]).encode()
        assert check_repo_scope(body, ALLOWED) == _PARSE

    def test_unresolved_variable_reference(self) -> None:
        body = _body(
            "mutation($x: ID!) {"
            "  createIssue(input: {repositoryId: $x,"
            '    title: "t"}) { issue { id } }'
            "}",
            variables={"other": "R_kgDORH34qw"},
        )
        assert check_repo_scope(body, ALLOWED) == _UNRESOLVED


# -------------------------------------------------------------------
# False positive resistance
# -------------------------------------------------------------------


class TestFalsePositiveResistance:
    """Tests that repositoryId in non-argument positions is ignored."""

    def test_repo_id_in_string_literal(self) -> None:
        body = _body(
            'mutation { createIssue(input: {repositoryId: "R_kgDORH34qw",'
            ' title: "repositoryId: R_evil"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_repo_id_in_comment(self) -> None:
        body = _body(
            "mutation {\n"
            "  # repositoryId: R_evil\n"
            '  createIssue(input: {repositoryId: "R_kgDORH34qw",'
            ' title: "t"}) { issue { id } }\n'
            "}"
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_unicode_escape_in_value(self) -> None:
        # GraphQL \u0052 resolves to "R" during parsing
        query = (
            "mutation { createIssue(input: "
            '{repositoryId: "\\u0052_kgDORH34qw",'
            ' title: "t"}) { issue { id } } }'
        )
        body = json.dumps({"query": query}).encode()
        assert check_repo_scope(body, ALLOWED) == _OK
