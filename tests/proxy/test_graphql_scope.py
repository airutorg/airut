# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for graphql_scope.check_repo_scope()."""

from __future__ import annotations

import json

from graphql_scope import (  # ty:ignore[unresolved-import]
    _MAX_BODY_SIZE,
    ScopeResult,
    ScopeVerdict,
    _is_id_field,
    check_repo_scope,
)


ALLOWED = frozenset({"R_kgDORH34qw", "R_kgDORm2NDQ"})
ALLOWED_NAMES = frozenset({"airutorg/airut", "airutorg/sandbox-action"})

# Synthetic node IDs for node ID ownership tests.
# R_kgDORH34qw decodes to repo_db_id 1149106347
# R_kgDORm2NDQ decodes to repo_db_id 1181584653
ISSUE_IN_SCOPE = "I_kwDORH34q80wOQ"  # repo_db_id = 1149106347
PR_IN_SCOPE = "PR_kwDORm2NDc4AAQky"  # repo_db_id = 1181584653
COMMENT_IN_SCOPE = "IC_kwDORH34q80rZw"  # repo_db_id = 1149106347
DISCUSSION_IN_SCOPE = "D_kwDORm2NDc1Wzg"  # repo_db_id = 1181584653
ISSUE_EVIL = "I_kwDOO5rJ/84AAYaf"  # repo_db_id = 999999999
PR_EVIL = "PR_kwDOO5rJ/84AAVs4"  # repo_db_id = 999999999
COMMENT_EVIL = "IC_kwDOO5rJ/84AAS/R"  # repo_db_id = 999999999
USER_ID = "U_kgDOAAjmPw"  # non-repo-scoped

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
        # "I_123" doesn't match the node ID regex — fail-secure blocks
        # unrecognized values in *Id fields.
        body = _body(
            'mutation { updateIssue(input: {id: "I_123",'
            ' title: "updated"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos("I_123")

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

    def test_oversized_body_blocked(self) -> None:
        body = b"x" * (_MAX_BODY_SIZE + 1)
        assert check_repo_scope(body, ALLOWED) == ScopeResult(
            ScopeVerdict.PARSE_ERROR, "<too-large>"
        )

    def test_body_at_size_limit_not_blocked(self) -> None:
        body = _body("query { viewer { login } }")
        # Pad to exactly _MAX_BODY_SIZE — should still be processed.
        body = body + b" " * (_MAX_BODY_SIZE - len(body))
        assert check_repo_scope(body, ALLOWED) == _OK

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


# -------------------------------------------------------------------
# Node ID ownership check (layer 2)
# -------------------------------------------------------------------


class TestNodeIdOwnership:
    """Tests for *Id field node ID ownership checking."""

    def test_subject_id_in_scope(self) -> None:
        body = _body(
            'mutation { addComment(input: {subjectId: "'
            + ISSUE_IN_SCOPE
            + '", body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_subject_id_out_of_scope(self) -> None:
        body = _body(
            'mutation { addComment(input: {subjectId: "'
            + ISSUE_EVIL
            + '", body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)

    def test_pull_request_id_in_scope(self) -> None:
        body = _body(
            'mutation { closePullRequest(input: {pullRequestId: "'
            + PR_IN_SCOPE
            + '"}) { pullRequest { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_pull_request_id_out_of_scope(self) -> None:
        body = _body(
            'mutation { closePullRequest(input: {pullRequestId: "'
            + PR_EVIL
            + '"}) { pullRequest { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(PR_EVIL)

    def test_issue_id_in_scope(self) -> None:
        body = _body(
            'mutation { closeIssue(input: {issueId: "'
            + ISSUE_IN_SCOPE
            + '"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_issue_id_out_of_scope(self) -> None:
        body = _body(
            'mutation { closeIssue(input: {issueId: "'
            + ISSUE_EVIL
            + '"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)

    def test_discussion_id_in_scope(self) -> None:
        body = _body(
            'mutation { addDiscussionComment(input: {discussionId: "'
            + DISCUSSION_IN_SCOPE
            + '", body: "hi"}) { comment { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_comment_id_out_of_scope(self) -> None:
        body = _body(
            'mutation { deleteIssueComment(input: {id: "'
            + COMMENT_EVIL
            + '"}) { clientMutationId } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(COMMENT_EVIL)

    def test_multiple_node_ids_all_in_scope(self) -> None:
        body = _body(
            "mutation {"
            '  a: addComment(input: {subjectId: "'
            + ISSUE_IN_SCOPE
            + '", body: "a"}) { commentEdge { node { id } } }'
            '  b: closePullRequest(input: {pullRequestId: "'
            + PR_IN_SCOPE
            + '"}) { pullRequest { id } }'
            "}"
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_multiple_node_ids_one_evil(self) -> None:
        body = _body(
            "mutation {"
            '  a: addComment(input: {subjectId: "'
            + ISSUE_IN_SCOPE
            + '", body: "a"}) { commentEdge { node { id } } }'
            '  b: closePullRequest(input: {pullRequestId: "'
            + PR_EVIL
            + '"}) { pullRequest { id } }'
            "}"
        )
        assert check_repo_scope(body, ALLOWED) == _oos(PR_EVIL)


class TestNodeIdVariables:
    """Tests for node ID checking via variable references."""

    def test_var_ref_in_scope(self) -> None:
        body = _body(
            "mutation($sid: ID!) {"
            '  addComment(input: {subjectId: $sid, body: "hi"})'
            "    { commentEdge { node { id } } }"
            "}",
            variables={"sid": ISSUE_IN_SCOPE},
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_var_ref_out_of_scope(self) -> None:
        body = _body(
            "mutation($sid: ID!) {"
            '  addComment(input: {subjectId: $sid, body: "hi"})'
            "    { commentEdge { node { id } } }"
            "}",
            variables={"sid": ISSUE_EVIL},
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)

    def test_var_ref_unresolved(self) -> None:
        body = _body(
            "mutation($sid: ID!) {"
            '  addComment(input: {subjectId: $sid, body: "hi"})'
            "    { commentEdge { node { id } } }"
            "}",
            variables={},
        )
        assert check_repo_scope(body, ALLOWED) == _UNRESOLVED

    def test_var_object_in_scope(self) -> None:
        body = _body(
            "mutation($input: AddCommentInput!) {"
            "  addComment(input: $input)"
            "    { commentEdge { node { id } } }"
            "}",
            variables={
                "input": {
                    "subjectId": ISSUE_IN_SCOPE,
                    "body": "hello",
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_var_object_out_of_scope(self) -> None:
        body = _body(
            "mutation($input: AddCommentInput!) {"
            "  addComment(input: $input)"
            "    { commentEdge { node { id } } }"
            "}",
            variables={
                "input": {
                    "subjectId": ISSUE_EVIL,
                    "body": "hello",
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)


class TestNodeIdNonRepoScoped:
    """Tests that non-repo-scoped node IDs are allowed through."""

    def test_user_id_allowed(self) -> None:
        body = _body(
            'mutation { followUser(input: {userId: "'
            + USER_ID
            + '"}) { user { login } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK


class TestNodeIdClientMutationId:
    """Tests that clientMutationId is not checked."""

    def test_client_mutation_id_not_checked(self) -> None:
        body = _body(
            'mutation { closeIssue(input: {issueId: "'
            + ISSUE_IN_SCOPE
            + '", clientMutationId: "EVIL_notANodeId1234"}'
            ") { issue { id } } }"
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_client_mutation_id_with_node_id_format(self) -> None:
        # clientMutationId happens to look like a node ID — should
        # still be skipped.
        body = _body(
            'mutation { closeIssue(input: {issueId: "'
            + ISSUE_IN_SCOPE
            + '", clientMutationId: "'
            + ISSUE_EVIL
            + '"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK


class TestNodeIdFailSecure:
    """Tests for fail-secure behavior on undecodable node IDs."""

    def test_non_matching_pattern_blocked(self) -> None:
        # "I_!!!invalid!!!" doesn't match _NODE_ID_RE (contains !).
        # Fail-secure: unrecognized values in *Id fields are blocked.
        body = _body(
            'mutation { addComment(input: {subjectId: "I_!!!invalid!!!",'
            ' body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos("I_!!!invalid!!!")

    def test_plain_string_in_id_field_blocked(self) -> None:
        # A plain string that doesn't look like a node ID at all.
        body = _body(
            'mutation { addComment(input: {subjectId: "not-a-node-id",'
            ' body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos("not-a-node-id")

    def test_uuid_in_id_field_blocked(self) -> None:
        # A UUID in an *Id field — unrecognized format, blocked.
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        body = _body(
            'mutation { addComment(input: {subjectId: "'
            + uuid
            + '", body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(uuid)

    def test_long_prefix_node_id_blocked(self) -> None:
        # Hypothetical future format with >6 char prefix — doesn't
        # match current regex, fail-secure blocks it.
        bad_id = "NEWTYPE_kgDOAbcdef"
        body = _body(
            'mutation { addComment(input: {subjectId: "'
            + bad_id
            + '", body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(bad_id)

    def test_lowercase_prefix_node_id_blocked(self) -> None:
        # Hypothetical future format with lowercase prefix.
        bad_id = "i_kgDOAbcdef"
        body = _body(
            'mutation { addComment(input: {subjectId: "'
            + bad_id
            + '", body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(bad_id)

    def test_valid_pattern_bad_payload_blocked(self) -> None:
        # Matches the node ID pattern but contains invalid msgpack.
        import base64

        bad_payload = (
            base64.b64encode(b"\x80\x00\x00\x00").rstrip(b"=").decode()
        )
        bad_id = f"I_{bad_payload}"
        body = _body(
            'mutation { addComment(input: {subjectId: "'
            + bad_id
            + '", body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(bad_id)


class TestNodeIdBadAllowedSet:
    """Tests for when allowed R_ IDs themselves can't be decoded."""

    def test_undecodable_allowed_r_ids_returns_parse_error(self) -> None:
        import base64 as b64

        bad_payload = b64.b64encode(b"\x80\x00\x00\x00").rstrip(b"=").decode()
        bad_allowed = frozenset({f"R_{bad_payload}"})
        body = _body(
            'mutation { addComment(input: {subjectId: "'
            + ISSUE_IN_SCOPE
            + '", body: "hi"}) { commentEdge { node { id } } } }'
        )
        assert check_repo_scope(body, bad_allowed) == _PARSE


class TestNodeIdCombinedLayers:
    """Tests for both layers working together."""

    def test_repo_id_and_subject_id_both_in_scope(self) -> None:
        body = _body(
            "mutation {"
            '  createIssue(input: {repositoryId: "R_kgDORH34qw",'
            '    title: "a"}) { issue { id } }'
            '  addComment(input: {subjectId: "'
            + ISSUE_IN_SCOPE
            + '", body: "b"}) { commentEdge { node { id } } }'
            "}"
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_repo_id_in_scope_but_subject_id_evil(self) -> None:
        body = _body(
            "mutation {"
            '  createIssue(input: {repositoryId: "R_kgDORH34qw",'
            '    title: "a"}) { issue { id } }'
            '  addComment(input: {subjectId: "'
            + ISSUE_EVIL
            + '", body: "b"}) { commentEdge { node { id } } }'
            "}"
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)

    def test_repo_id_evil_caught_before_node_id_check(self) -> None:
        body = _body(
            "mutation {"
            '  createIssue(input: {repositoryId: "R_evil",'
            '    title: "a"}) { issue { id } }'
            '  addComment(input: {subjectId: "'
            + ISSUE_IN_SCOPE
            + '", body: "b"}) { commentEdge { node { id } } }'
            "}"
        )
        # Layer 1 catches the bad repositoryId before layer 2 runs.
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_query_with_id_in_selection_set_allowed(self) -> None:
        """Field named 'id' in selection set is not an input field."""
        body = _body("query { viewer { id login } }")
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_non_node_id_string_in_id_field_blocked(self) -> None:
        """Short string in an *Id field is unrecognized — blocked."""
        body = _body(
            'mutation { updateIssue(input: {labelableId: "123",'
            ' title: "updated"}) { issue { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos("123")


# -------------------------------------------------------------------
# repositoryNameWithOwner field (pentest fix)
# -------------------------------------------------------------------


class TestRepositoryNameWithOwner:
    """Tests for the ``repositoryNameWithOwner`` string field.

    Used by mutations like ``createCommitOnBranch`` which target a
    repository by ``owner/name`` instead of by node ID.  Without this
    check, an in-scope surrogate token could bypass repo scoping.
    """

    def test_create_commit_on_branch_in_scope(self) -> None:
        body = _body(
            "mutation { createCommitOnBranch(input: "
            '{branch: {repositoryNameWithOwner: "airutorg/airut",'
            ' branchName: "main"},'
            ' message: {headline: "x"}, expectedHeadOid: "deadbeef"})'
            " { commit { oid } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_create_commit_on_branch_out_of_scope(self) -> None:
        body = _body(
            "mutation { createCommitOnBranch(input: "
            '{branch: {repositoryNameWithOwner: "evilorg/target",'
            ' branchName: "main"},'
            ' message: {headline: "x"}, expectedHeadOid: "deadbeef"})'
            " { commit { oid } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "evilorg/target"
        )

    def test_repo_name_via_variable_in_scope(self) -> None:
        body = _body(
            "mutation($nwo: String!) {"
            "  createCommitOnBranch(input: {"
            '    branch: {repositoryNameWithOwner: $nwo, branchName: "m"},'
            '    message: {headline: "x"}, expectedHeadOid: "abc"'
            "  }) { commit { oid } }"
            "}",
            variables={"nwo": "airutorg/sandbox-action"},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_repo_name_via_variable_out_of_scope(self) -> None:
        body = _body(
            "mutation($nwo: String!) {"
            "  createCommitOnBranch(input: {"
            '    branch: {repositoryNameWithOwner: $nwo, branchName: "m"},'
            '    message: {headline: "x"}, expectedHeadOid: "abc"'
            "  }) { commit { oid } }"
            "}",
            variables={"nwo": "evilorg/target"},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "evilorg/target"
        )

    def test_repo_name_via_variable_unresolved(self) -> None:
        body = _body(
            "mutation($nwo: String!) {"
            "  createCommitOnBranch(input: {"
            '    branch: {repositoryNameWithOwner: $nwo, branchName: "m"},'
            '    message: {headline: "x"}, expectedHeadOid: "abc"'
            "  }) { commit { oid } }"
            "}",
            variables={},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _UNRESOLVED

    def test_repo_name_in_variable_object_out_of_scope(self) -> None:
        body = _body(
            "mutation($input: CreateCommitOnBranchInput!) {"
            "  createCommitOnBranch(input: $input) { commit { oid } }"
            "}",
            variables={
                "input": {
                    "branch": {
                        "repositoryNameWithOwner": "evilorg/target",
                        "branchName": "main",
                    },
                    "message": {"headline": "x"},
                    "expectedHeadOid": "abc",
                }
            },
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "evilorg/target"
        )

    def test_repo_name_in_variable_object_in_scope(self) -> None:
        body = _body(
            "mutation($input: CreateCommitOnBranchInput!) {"
            "  createCommitOnBranch(input: $input) { commit { oid } }"
            "}",
            variables={
                "input": {
                    "branch": {
                        "repositoryNameWithOwner": "airutorg/airut",
                        "branchName": "main",
                    },
                    "message": {"headline": "x"},
                    "expectedHeadOid": "abc",
                }
            },
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_repo_name_empty_allowed_set_blocks(self) -> None:
        """Empty allowed_repo_full_names set blocks any repo name."""
        body = _body(
            "mutation { createCommitOnBranch(input: "
            '{branch: {repositoryNameWithOwner: "airutorg/airut",'
            ' branchName: "main"},'
            ' message: {headline: "x"}, expectedHeadOid: "deadbeef"})'
            " { commit { oid } } }"
        )
        assert check_repo_scope(body, ALLOWED) == _oos("airutorg/airut")

    def test_repo_name_case_insensitive_match(self) -> None:
        """GitHub owner/name are case-insensitive — match both ways."""
        body = _body(
            "mutation { createCommitOnBranch(input: "
            '{branch: {repositoryNameWithOwner: "AIRUTORG/AIRUT",'
            ' branchName: "main"},'
            ' message: {headline: "x"}, expectedHeadOid: "deadbeef"})'
            " { commit { oid } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_layer2_runs_when_layer1_passes(self) -> None:
        """Out-of-scope repo name blocks even with in-scope repositoryId.

        Regression for the motivating pentest vector: if Layer 1 is
        short-circuited by an in-scope ``repositoryId``, Layer 2 must
        still catch an out-of-scope ``repositoryNameWithOwner``.
        """
        body = _body(
            "mutation {"
            '  a: createIssue(input: {repositoryId: "R_kgDORH34qw",'
            '    title: "t"}) { issue { id } }'
            "  b: createCommitOnBranch(input: "
            '    {branch: {repositoryNameWithOwner: "evilorg/target",'
            '     branchName: "main"},'
            '     message: {headline: "x"}, expectedHeadOid: "abc"})'
            "     { commit { oid } }"
            "}"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "evilorg/target"
        )

    def test_repo_name_as_top_level_argument(self) -> None:
        """RepositoryNameWithOwner as a top-level argument is checked."""
        body = _body(
            'mutation { someOp(repositoryNameWithOwner: "evilorg/target")'
            " { ok } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "evilorg/target"
        )

    def test_repo_name_in_list_of_dicts_out_of_scope(self) -> None:
        body = _body(
            "mutation($input: BatchInput!) {  doBatch(input: $input) { id }}",
            variables={
                "input": {
                    "branches": [
                        {
                            "repositoryNameWithOwner": "airutorg/airut",
                            "branchName": "main",
                        },
                        {
                            "repositoryNameWithOwner": "evilorg/target",
                            "branchName": "main",
                        },
                    ]
                }
            },
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "evilorg/target"
        )


# -------------------------------------------------------------------
# Nested variable objects (MEDIUM-1 fix)
# -------------------------------------------------------------------


class TestNestedVariableObjects:
    """Tests that deeply nested variable objects are scanned."""

    def test_nested_repo_id_out_of_scope(self) -> None:
        body = _body(
            "mutation($input: SomeInput!) {  doThing(input: $input) { id }}",
            variables={
                "input": {
                    "nested": {
                        "repositoryId": "R_evil",
                    }
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_nested_node_id_out_of_scope(self) -> None:
        body = _body(
            "mutation($input: SomeInput!) {  doThing(input: $input) { id }}",
            variables={
                "input": {
                    "nested": {
                        "subjectId": ISSUE_EVIL,
                    }
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)

    def test_deeply_nested_node_id_in_scope(self) -> None:
        body = _body(
            "mutation($input: SomeInput!) {  doThing(input: $input) { id }}",
            variables={
                "input": {
                    "level1": {
                        "level2": {
                            "subjectId": ISSUE_IN_SCOPE,
                        }
                    }
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK


# -------------------------------------------------------------------
# Plural *Ids fields (MEDIUM-2 fix)
# -------------------------------------------------------------------


class TestPluralIdFields:
    """Tests for plural *Ids fields (e.g., labelIds, assigneeIds)."""

    def test_label_ids_inlined_in_scope(self) -> None:
        body = _body(
            'mutation { addLabelsToLabelable(input: {labelableId: "'
            + ISSUE_IN_SCOPE
            + '", labelIds: ["'
            + COMMENT_IN_SCOPE
            + '"]}) { labelable { labels { totalCount } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_label_ids_inlined_out_of_scope(self) -> None:
        body = _body(
            'mutation { addLabelsToLabelable(input: {labelableId: "'
            + ISSUE_IN_SCOPE
            + '", labelIds: ["'
            + COMMENT_EVIL
            + '"]}) { labelable { labels { totalCount } } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(COMMENT_EVIL)

    def test_ids_via_variable_list(self) -> None:
        body = _body(
            "mutation($ids: [ID!]!) {"
            '  addLabelsToLabelable(input: {labelableId: "'
            + ISSUE_IN_SCOPE
            + '", labelIds: $ids})'
            "    { labelable { labels { totalCount } } }"
            "}",
            variables={"ids": [COMMENT_EVIL]},
        )
        assert check_repo_scope(body, ALLOWED) == _oos(COMMENT_EVIL)

    def test_ids_in_variable_object(self) -> None:
        body = _body(
            "mutation($input: AddLabelsInput!) {"
            "  addLabelsToLabelable(input: $input)"
            "    { labelable { labels { totalCount } } }"
            "}",
            variables={
                "input": {
                    "labelableId": ISSUE_IN_SCOPE,
                    "labelIds": [COMMENT_EVIL],
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos(COMMENT_EVIL)

    def test_ids_list_with_var_ref_out_of_scope(self) -> None:
        body = _body(
            "mutation($evil: ID!) {"
            '  addLabelsToLabelable(input: {labelableId: "'
            + ISSUE_IN_SCOPE
            + '", labelIds: [$evil]})'
            "    { labelable { labels { totalCount } } }"
            "}",
            variables={"evil": COMMENT_EVIL},
        )
        assert check_repo_scope(body, ALLOWED) == _oos(COMMENT_EVIL)

    def test_ids_in_variable_object_all_in_scope(self) -> None:
        body = _body(
            "mutation($input: AddLabelsInput!) {"
            "  addLabelsToLabelable(input: $input)"
            "    { labelable { labels { totalCount } } }"
            "}",
            variables={
                "input": {
                    "labelableId": ISSUE_IN_SCOPE,
                    "labelIds": [COMMENT_IN_SCOPE, DISCUSSION_IN_SCOPE],
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK


# -------------------------------------------------------------------
# Argument-level id fields (MEDIUM-3 fix)
# -------------------------------------------------------------------


class TestArgumentLevelIds:
    """Tests for id/node ID fields as direct mutation arguments."""

    def test_argument_id_out_of_scope(self) -> None:
        body = _body(
            'mutation { deleteNode(id: "'
            + ISSUE_EVIL
            + '") { clientMutationId } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)

    def test_argument_id_in_scope(self) -> None:
        body = _body(
            'mutation { deleteNode(id: "'
            + ISSUE_IN_SCOPE
            + '") { clientMutationId } }'
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_argument_subject_id_out_of_scope(self) -> None:
        body = _body(
            'mutation { addReaction(subjectId: "'
            + ISSUE_EVIL
            + '", content: THUMBS_UP) { reaction { id } } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)


# -------------------------------------------------------------------
# List-of-dict variable recursion
# -------------------------------------------------------------------


class TestListOfDictVariables:
    """Tests that list-of-dict variables are recursed into."""

    def test_repo_id_in_list_of_dicts_out_of_scope(self) -> None:
        """RepositoryId inside a list of input objects must be caught."""
        body = _body(
            "mutation($inputs: [CreateIssueInput!]!) {"
            "  doThing(inputs: $inputs) { id }"
            "}",
            variables={
                "inputs": [
                    {
                        "repositoryId": "R_evil",
                        "title": "sneaky",
                    }
                ]
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_repo_id_in_list_of_dicts_in_scope(self) -> None:
        body = _body(
            "mutation($inputs: [CreateIssueInput!]!) {"
            "  doThing(inputs: $inputs) { id }"
            "}",
            variables={
                "inputs": [
                    {
                        "repositoryId": "R_kgDORH34qw",
                        "title": "ok",
                    },
                    {
                        "repositoryId": "R_kgDORm2NDQ",
                        "title": "also ok",
                    },
                ]
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_repo_id_in_list_of_dicts_mixed(self) -> None:
        body = _body(
            "mutation($inputs: [CreateIssueInput!]!) {"
            "  doThing(inputs: $inputs) { id }"
            "}",
            variables={
                "inputs": [
                    {
                        "repositoryId": "R_kgDORH34qw",
                        "title": "good",
                    },
                    {
                        "repositoryId": "R_evil",
                        "title": "bad",
                    },
                ]
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_node_id_in_list_of_dicts_out_of_scope(self) -> None:
        """SubjectId inside a list of input objects must be caught."""
        body = _body(
            "mutation($inputs: [AddCommentInput!]!) {"
            "  doThing(inputs: $inputs) { id }"
            "}",
            variables={
                "inputs": [
                    {
                        "subjectId": ISSUE_EVIL,
                        "body": "sneaky",
                    }
                ]
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)

    def test_node_id_in_list_of_dicts_in_scope(self) -> None:
        body = _body(
            "mutation($inputs: [AddCommentInput!]!) {"
            "  doThing(inputs: $inputs) { id }"
            "}",
            variables={
                "inputs": [
                    {
                        "subjectId": ISSUE_IN_SCOPE,
                        "body": "ok",
                    },
                    {
                        "subjectId": PR_IN_SCOPE,
                        "body": "also ok",
                    },
                ]
            },
        )
        assert check_repo_scope(body, ALLOWED) == _OK

    def test_nested_list_of_dicts_in_dict(self) -> None:
        """List of dicts nested inside a dict variable."""
        body = _body(
            "mutation($input: BatchInput!) {  doBatch(input: $input) { id }}",
            variables={
                "input": {
                    "items": [
                        {"repositoryId": "R_evil"},
                    ]
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos("R_evil")

    def test_nested_list_node_ids_in_dict(self) -> None:
        """Node IDs in list-of-dicts nested inside a dict variable."""
        body = _body(
            "mutation($input: BatchInput!) {  doBatch(input: $input) { id }}",
            variables={
                "input": {
                    "comments": [
                        {"subjectId": ISSUE_EVIL, "body": "hi"},
                    ]
                }
            },
        )
        assert check_repo_scope(body, ALLOWED) == _oos(ISSUE_EVIL)


# -------------------------------------------------------------------
# Layer 0: Query.repository(owner, name) field selection
# -------------------------------------------------------------------


class TestRepositoryFieldSelection:
    """Tests for the ``repository(owner, name)`` field selection.

    GitHub's GraphQL ``Query.repository(owner, name)`` and the chained
    ``organization(login).repository(name)`` /
    ``repositoryOwner(login).repository(name)`` /
    ``user(login).repository(name)`` paths address a repository via
    plain ``String!`` arguments instead of via any ``*Id`` or
    ``repositoryNameWithOwner`` field.  Without this check, an
    in-scope GitHub App surrogate token can read **any** repository
    the underlying installation token is authorized to see (including
    any public repository on github.com).

    Regression for the pentest finding "GraphQL query scope asymmetry".
    """

    def test_query_repository_in_scope(self) -> None:
        body = _body(
            '{ repository(owner: "airutorg", name: "airut") { description } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_query_repository_out_of_scope(self) -> None:
        body = _body(
            '{ repository(owner: "airutorg", name: "website")'
            " { description isPrivate } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_query_repository_case_insensitive(self) -> None:
        body = _body(
            '{ repository(owner: "AIRUTORG", name: "AIRUT") { description } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_query_repository_via_variables(self) -> None:
        body = _body(
            "query($o: String!, $n: String!)"
            " { repository(owner: $o, name: $n) { description } }",
            variables={"o": "airutorg", "n": "website"},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_query_repository_var_unresolved(self) -> None:
        body = _body(
            "query($o: String!, $n: String!)"
            " { repository(owner: $o, name: $n) { description } }",
            variables={"o": "airutorg"},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _UNRESOLVED

    def test_query_repository_var_wrong_type(self) -> None:
        body = _body(
            "query($o: String!, $n: String!)"
            " { repository(owner: $o, name: $n) { description } }",
            variables={"o": 42, "n": "airut"},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _PARSE

    def test_query_repository_aliased(self) -> None:
        """Field aliases must not bypass the check."""
        body = _body(
            'query { mine: repository(owner: "airutorg", name: "website")'
            " { description } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_organization_repository_in_scope(self) -> None:
        body = _body(
            '{ organization(login: "airutorg")'
            ' { repository(name: "airut") { description } } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_organization_repository_out_of_scope(self) -> None:
        body = _body(
            '{ organization(login: "airutorg")'
            ' { repository(name: "website") { description } } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_repository_owner_repository_out_of_scope(self) -> None:
        body = _body(
            '{ repositoryOwner(login: "airutorg")'
            ' { repository(name: "website") { description } } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_user_repository_out_of_scope(self) -> None:
        body = _body(
            '{ user(login: "evilperson")'
            ' { repository(name: "secret") { description } } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "evilperson/secret"
        )

    def test_chained_repository_via_variable_login_in_scope(self) -> None:
        body = _body(
            "query($login: String!, $name: String!)"
            " { organization(login: $login)"
            "   { repository(name: $name) { description } } }",
            variables={"login": "airutorg", "name": "sandbox-action"},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_viewer_repository_blocked(self) -> None:
        """``viewer.repository(name)`` has no resolvable owner — block."""
        body = _body(
            '{ viewer { repository(name: "website") { description } } }'
        )
        result = check_repo_scope(body, ALLOWED, ALLOWED_NAMES)
        assert result.verdict is ScopeVerdict.OUT_OF_SCOPE
        assert "website" in (result.detail or "")

    def test_repository_no_name_arg_ignored(self) -> None:
        """``repository`` field without a ``name`` arg is ignored."""
        # Some schemas have ``repository`` as an output field with no
        # selector arguments.  Without ``name`` we have nothing to
        # check — leave it to other layers / the operation allowlist.
        body = _body(
            "mutation { createCommitOnBranch(input: {branch: "
            '{repositoryNameWithOwner: "airutorg/airut", '
            'branchName: "main"}, message: {headline: "x"}, '
            'expectedHeadOid: "abc"}) '
            "{ commit { repository { name } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_layer0_runs_after_inscope_repo_id(self) -> None:
        """Out-of-scope repository(...) blocks even with in-scope IDs.

        Regression: Layer 1 short-circuit must not prevent Layer 0
        from catching an out-of-scope ``repository(owner, name)``
        sub-selection in the same query.
        """
        body = _body(
            "mutation {"
            '  a: createIssue(input: {repositoryId: "R_kgDORH34qw",'
            '    title: "t"}) { issue { id } }'
            '  b: repository(owner: "airutorg", name: "website")'
            "    { description }"
            "}"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_empty_allowed_names_blocks(self) -> None:
        """Empty allowed_repo_full_names blocks any repository(...)."""
        body = _body(
            '{ repository(owner: "airutorg", name: "airut") { description } }'
        )
        assert check_repo_scope(body, ALLOWED) == _oos("airutorg/airut")

    def test_repository_no_owner_no_parent_login_blocked(self) -> None:
        """``repository(name: ...)`` at root with no parent login blocks."""
        body = _body('{ repository(name: "airut") { description } }')
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<unknown>/airut"
        )

    def test_repository_owner_inline_int_value(self) -> None:
        """Inline non-string owner is fail-secure parse error."""
        body = _body('{ repository(owner: 42, name: "airut") { description } }')
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _PARSE

    def test_repository_name_inline_int_value(self) -> None:
        """Inline non-string name is fail-secure parse error."""
        body = _body(
            '{ repository(owner: "airutorg", name: 42) { description } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _PARSE

    def test_repository_name_var_wrong_type(self) -> None:
        """Variable bound to non-string name is fail-secure parse error."""
        body = _body(
            'query($n: String!) { repository(owner: "airutorg", '
            "name: $n) { description } }",
            variables={"n": 42},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _PARSE

    def test_repository_owner_var_unresolved(self) -> None:
        """Owner-only unresolved variable returns UNRESOLVED."""
        body = _body(
            "query($o: String!) { repository(owner: $o, "
            'name: "airut") { description } }',
            variables={},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _UNRESOLVED

    def test_two_repository_selections_one_out_of_scope(self) -> None:
        """Two ``repository(...)`` selections — out-of-scope one wins."""
        body = _body(
            "{"
            '  good: repository(owner: "airutorg", name: "airut")'
            "    { description }"
            '  evil: repository(owner: "airutorg", name: "website")'
            "    { description }"
            "}"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_inline_fragment_under_organization_in_scope(self) -> None:
        """Inline fragment under ``organization`` resolves parent login."""
        body = _body(
            '{ organization(login: "airutorg") {'
            "  ... on Organization {"
            '    repository(name: "airut") { description }'
            "  }"
            "} }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_inline_fragment_under_organization_out_of_scope(self) -> None:
        body = _body(
            '{ organization(login: "airutorg") {'
            "  ... on Organization {"
            '    repository(name: "website") { description }'
            "  }"
            "} }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "airutorg/website"
        )

    def test_named_fragment_spread_blocks_unresolvable_owner(self) -> None:
        """Named fragment spreads break the parent-login chain.

        The visitor walks ``ancestors`` from the spread site, not into
        the fragment definition.  A ``repository(name)`` selection
        inside a named fragment therefore has no resolvable parent
        ``login`` even when the spread is inside an in-scope
        ``organization(login: ...)``.  Locked in as fail-secure to
        prevent a future "helpfully resolve fragment definitions"
        change from silently introducing a bypass.
        """
        body = _body(
            '{ organization(login: "airutorg") {'
            "  ...RepoBits"
            "} }"
            "fragment RepoBits on Organization {"
            '  repository(name: "website") { description }'
            "}"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<unknown>/website"
        )


# -------------------------------------------------------------------
# Multi-repo enumeration (pentest Finding 1)
# -------------------------------------------------------------------


class TestMultiRepoEnumeration:
    """Tests that multi-repo enumeration fields are fail-secure blocked.

    GraphQL connections like ``organization(login).repositories``,
    ``user(login).repositories``, ``viewer.repositories`` and
    ``Query.search(type: REPOSITORY)`` return repositories without
    taking an ``owner``/``name`` argument the proxy can match against
    ``allowed_repo_full_names``.  Layer 0 only catches the singular
    ``repository(owner, name)`` field, so these plural traversals
    previously bypassed every layer of repo scope checking and let an
    in-scope surrogate token enumerate (and read) any repository the
    installation token could see.

    The same class of bypass applies to every other connection field
    that returns ``Repository`` (or repo-scoped) nodes without a
    scopeable ``owner``/``name`` argument: ``pinnedItems`` /
    ``pinnableItems`` / ``itemShowcase`` (profile showcase),
    ``starredRepositories``, ``watching``, ``repositoriesContributedTo``
    and ``topRepositories``.  All are fail-secure blocked.

    Regression for the pentest finding "GraphQL repository scope check
    is bypassed by ``organization(login).repositories.nodes`` (and
    similar plural traversals)" and the follow-up finding that
    ``pinnedItems`` / ``starredRepositories`` / ``watching`` (and
    similar repo-returning connections) were not covered by the
    original three-field denylist.
    """

    def test_organization_repositories_blocked(self) -> None:
        body = _body(
            '{ organization(login: "airutorg")'
            " { repositories(first: 5) { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:repositories>"
        )

    def test_user_repositories_blocked(self) -> None:
        body = _body(
            '{ user(login: "octocat")'
            " { repositories(first: 5) { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:repositories>"
        )

    def test_viewer_repositories_blocked(self) -> None:
        body = _body(
            "{ viewer { repositories(first: 5) { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:repositories>"
        )

    def test_repository_owner_repositories_blocked(self) -> None:
        body = _body(
            '{ repositoryOwner(login: "airutorg")'
            " { repositories(first: 5) { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:repositories>"
        )

    def test_pentest_finding_one_payload_blocked(self) -> None:
        """The exact GraphQL payload from the pentest report is blocked."""
        body = _body(
            "query {"
            '  organization(login: "airutorg") {'
            "    repositories(first: 5) {"
            "      nodes {"
            "        nameWithOwner"
            '        object(expression: "HEAD~5:public/canary.txt")'
            "          { ... on Blob { text } }"
            "        pullRequest(number: 40) { body files(first:5)"
            "          { nodes { path } } }"
            "        defaultBranchRef { target { ... on Commit"
            "          { history(first:50) { nodes { messageBody }}}}}"
            "      }"
            "    }"
            "  }"
            "}"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:repositories>"
        )

    def test_repositories_blocked_even_with_inscope_repository(self) -> None:
        """Plural connection blocks alongside an in-scope ``repository``."""
        body = _body(
            "{"
            '  in_scope: repository(owner: "airutorg", name: "airut")'
            "    { description }"
            '  evil: organization(login: "airutorg")'
            "    { repositories(first: 5) { nodes { nameWithOwner } } }"
            "}"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:repositories>"
        )

    def test_repository_forks_blocked(self) -> None:
        """``Repository.forks`` is a RepositoryConnection — enumerates forks."""
        body = _body(
            '{ repository(owner: "airutorg", name: "airut")'
            " { forks(first: 5) { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:forks>"
        )

    def test_search_blocked(self) -> None:
        body = _body(
            'query { search(query: "org:airutorg", type: REPOSITORY, first: 5)'
            " { nodes { ... on Repository { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:search>"
        )

    def test_search_aliased_blocked(self) -> None:
        """Aliases must not bypass the search block."""
        body = _body(
            'query { hits: search(query: "test", type: ISSUE, first: 5)'
            " { nodes { ... on Issue { title } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:search>"
        )

    def test_repositories_argumentless_not_blocked(self) -> None:
        """``repositories`` with no arguments is not a connection.

        Some unrelated schemas may expose a field named ``repositories``
        without the standard connection arguments.  GitHub's connection
        always takes pagination args (``first``/``last``); a bare
        ``repositories`` selection has no enumeration semantics and must
        not trigger the block.  This keeps the check focused on the
        documented attack surface.
        """
        # No arguments — not the GitHub connection shape.
        body = _body("query { something { repositories { name } } }")
        # No repository-targeting values at all -> ALLOWED.
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_pinned_items_blocked(self) -> None:
        """``User.pinnedItems`` (PinnableItemConnection) enumerates repos."""
        body = _body(
            '{ user(login: "octocat")'
            " { pinnedItems(first: 5, types: [REPOSITORY])"
            " { nodes { ... on Repository { nameWithOwner } } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:pinnedItems>"
        )

    def test_pinned_items_on_organization_blocked(self) -> None:
        """The exact follow-up pentest payload (org pinnedItems) is blocked."""
        body = _body(
            '{ organization(login: "airutorg")'
            " { pinnedItems(first: 10, types: [REPOSITORY]) { nodes {"
            "   ... on Repository { nameWithOwner"
            '     object(expression: "HEAD:public/canary.txt")'
            "       { ... on Blob { text } } } } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:pinnedItems>"
        )

    def test_pinnable_items_blocked(self) -> None:
        """``pinnableItems`` is the same connection as ``pinnedItems``."""
        body = _body(
            '{ user(login: "octocat")'
            " { pinnableItems(first: 5, types: [REPOSITORY])"
            " { nodes { ... on Repository { nameWithOwner } } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:pinnableItems>"
        )

    def test_starred_repositories_blocked(self) -> None:
        """``User.starredRepositories`` is a StarredRepositoryConnection."""
        body = _body(
            '{ user(login: "octocat")'
            " { starredRepositories(first: 5)"
            "   { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:starredRepositories>"
        )

    def test_watching_blocked(self) -> None:
        """``User.watching`` is a RepositoryConnection."""
        body = _body(
            '{ user(login: "octocat")'
            " { watching(first: 5) { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:watching>"
        )

    def test_repositories_contributed_to_blocked(self) -> None:
        """``User.repositoriesContributedTo`` is a RepositoryConnection."""
        body = _body(
            '{ user(login: "octocat")'
            " { repositoriesContributedTo(first: 5)"
            "   { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:repositoriesContributedTo>"
        )

    def test_top_repositories_blocked(self) -> None:
        """``User.topRepositories`` is a RepositoryConnection."""
        body = _body(
            '{ user(login: "octocat")'
            ' { topRepositories(first: 5, since: "2020-01-01T00:00:00Z")'
            "   { nodes { nameWithOwner } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:topRepositories>"
        )

    def test_item_showcase_blocked(self) -> None:
        """``itemShowcase`` takes no args; its ``items`` connection leaks repos.

        ``ProfileOwner.itemShowcase`` is an argument-less field whose
        ``items`` ``PinnableItemConnection`` returns the owner's pinned
        repositories.  Because the enumerating field itself carries no
        arguments, it is blocked unconditionally rather than gated on
        argument presence.
        """
        body = _body(
            '{ organization(login: "airutorg")'
            " { itemShowcase { items(first: 5)"
            "   { nodes { ... on Repository { nameWithOwner } } } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:itemShowcase>"
        )

    def test_pinned_items_aliased_blocked(self) -> None:
        """Aliases must not bypass the connection block."""
        body = _body(
            '{ u: user(login: "octocat")'
            " { pins: pinnedItems(first: 5, types: [REPOSITORY])"
            " { nodes { ... on Repository { nameWithOwner } } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<multi-repo:pinnedItems>"
        )

    def test_pinned_items_argumentless_not_blocked(self) -> None:
        """Bare argument-less ``pinnedItems`` has no connection semantics.

        Mirrors ``test_repositories_argumentless_not_blocked``: the block
        is gated on the connection shape (pagination arguments), so an
        unrelated argument-less field of the same name does not trip it.
        """
        body = _body("query { something { pinnedItems { name } } }")
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK


# -------------------------------------------------------------------
# URL-addressed node lookup (pentest Finding 3)
# -------------------------------------------------------------------


class TestResourceUrlLookup:
    """Tests that ``Query.resource(url:)`` is fail-secure blocked.

    GitHub's ``Query.resource(url: URI!)`` resolves an arbitrary URL to
    the node it addresses (a ``Repository``, ``Issue``, ``Commit``, …).
    It targets a repository by URL rather than by an
    ``owner``/``name`` argument (Layer 0), a ``repositoryId`` /
    ``repositoryNameWithOwner`` field (Layers 1–2), or a decodable
    ``*Id`` node ID (Layer 3), so none of those layers inspect it — an
    in-scope surrogate token could read **any** repository the
    installation token can see:

        query { resource(url: "https://github.com/airutorg/website")
          { ... on Repository
            { object(expression: "HEAD:public/canary.txt")
              { ... on Blob { text } } } } }

    Regression for the pentest finding "GraphQL repository scope check
    is bypassed by ``Query.resource(url:)`` URL-addressed node lookup".
    """

    def test_resource_url_blocked(self) -> None:
        body = _body(
            'query { resource(url: "https://github.com/airutorg/website")'
            " { ... on Repository {"
            '   object(expression: "HEAD:public/canary.txt")'
            "   { ... on Blob { text } } } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<url-addressed:resource>"
        )

    def test_resource_url_blocked_for_in_scope_repo(self) -> None:
        """Even an in-scope repo URL is blocked — the field is unscopeable.

        ``resource(url:)`` is fail-secure blocked regardless of the URL
        because the proxy does not parse the URL to bind it to the
        allowed set; the field is simply not a supported addressing
        shape.
        """
        body = _body(
            'query { resource(url: "https://github.com/airutorg/airut")'
            " { ... on Repository { nameWithOwner } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<url-addressed:resource>"
        )

    def test_resource_url_aliased_blocked(self) -> None:
        """Aliases must not bypass the resource block."""
        body = _body(
            'query { r: resource(url: "https://github.com/octocat/Hello-World")'
            " { ... on Repository { nameWithOwner } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<url-addressed:resource>"
        )

    def test_resource_url_variable_blocked(self) -> None:
        """A variable-supplied URL is blocked before variable resolution."""
        body = _body(
            "query($u: URI!) { resource(url: $u)"
            " { ... on Repository { nameWithOwner } } }",
            {"u": "https://github.com/airutorg/website"},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<url-addressed:resource>"
        )

    def test_resource_url_blocked_alongside_in_scope_repository(self) -> None:
        """The resource block fires even next to an in-scope selection."""
        body = _body(
            "{"
            '  ok: repository(owner: "airutorg", name: "airut") { description }'
            '  evil: resource(url: "https://github.com/airutorg/website")'
            "    { ... on Repository { nameWithOwner } }"
            "}"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<url-addressed:resource>"
        )

    def test_resource_url_in_named_fragment_blocked(self) -> None:
        """A ``resource(url:)`` reached via a named fragment is blocked.

        The whole-document AST walk visits fragment definitions, so the
        block fires regardless of how the selection is reached.
        """
        body = _body(
            "query { ...F }"
            " fragment F on Query {"
            '   resource(url: "https://github.com/airutorg/website")'
            "   { ... on Repository { nameWithOwner } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(
            "<url-addressed:resource>"
        )

    def test_resource_without_url_arg_not_blocked(self) -> None:
        """A ``resource`` field with no ``url`` argument is not the lookup.

        Only ``Query.resource(url:)`` addresses a node by URL.  An
        unrelated schema field that happens to be named ``resource``
        but takes no ``url`` argument has no cross-repo addressing
        semantics and must not trigger the block.
        """
        body = _body("query { something { resource { name } } }")
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK


# -------------------------------------------------------------------
# Case-insensitive ID field matching (pentest Finding 2)
# -------------------------------------------------------------------


class TestIdFieldCaseInsensitive:
    """Tests that ``_is_id_field`` recognises the lowercase ``ids`` form.

    GitHub's GraphQL schema uses lowercase ``ids`` for
    ``Query.nodes(ids: [ID!]!)``.  Before the fix, case-sensitive
    ``endswith("Ids")`` missed this argument and let an arbitrary node
    ID slip past Layer 3.  Regression for the pentest finding
    "``_is_id_field()`` case-sensitivity lets ``nodes(ids: [...])``
    skip Layer-3 node-ownership checks".
    """

    def test_is_id_field_lowercase_ids(self) -> None:
        assert _is_id_field("ids") is True

    def test_is_id_field_lowercase_id(self) -> None:
        assert _is_id_field("id") is True

    def test_is_id_field_uppercase_id(self) -> None:
        assert _is_id_field("ID") is True

    def test_is_id_field_uppercase_ids(self) -> None:
        assert _is_id_field("IDS") is True

    def test_is_id_field_camel_id_unchanged(self) -> None:
        assert _is_id_field("subjectId") is True
        assert _is_id_field("labelIds") is True

    def test_is_id_field_client_mutation_id_still_skipped(self) -> None:
        assert _is_id_field("clientMutationId") is False

    def test_is_id_field_git_oid_not_matched(self) -> None:
        """Git Object ID fields must not be treated as node IDs."""
        # SHA-1 commit hashes, not GitHub node IDs.  A full
        # case-insensitive ``endswith("id")`` match would over-match
        # these and break mutations like ``createCommitOnBranch`` whose
        # ``expectedHeadOid`` is a Git OID, not a node ID.
        assert _is_id_field("oid") is False
        assert _is_id_field("expectedHeadOid") is False
        assert _is_id_field("afterOid") is False
        assert _is_id_field("headRefOid") is False
        assert _is_id_field("baseRefOid") is False
        assert _is_id_field("beforeOid") is False

    def test_nodes_ids_out_of_scope_repo_blocked(self) -> None:
        """``nodes(ids: [...])`` with an out-of-scope repo node ID is blocked.

        Pentest demonstrated this with a bare repo node ID returning
        ``Albert152/programm`` — the proxy must fail-secure block it.
        """
        body = _body(
            'query { nodes(ids: ["' + PR_EVIL + '"])'
            " { ... on PullRequest { title } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(PR_EVIL)

    def test_nodes_ids_in_scope_repo_allowed(self) -> None:
        body = _body(
            'query { nodes(ids: ["' + PR_IN_SCOPE + '"])'
            " { ... on PullRequest { title } } }"
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _OK

    def test_nodes_ids_mixed_one_evil_blocked(self) -> None:
        body = _body(
            'query { nodes(ids: ["'
            + PR_IN_SCOPE
            + '", "'
            + PR_EVIL
            + '"]) { ... on PullRequest { title } } }'
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(PR_EVIL)

    def test_nodes_ids_arbitrary_node_id_failsecure_blocked(self) -> None:
        """Pentest exact payload: arbitrary node ID is fail-secure blocked."""
        arbitrary_node_id = "MDEwOlJlcG9zaXRvcnkxMjM0NTY3ODk="
        body = _body(
            'query { nodes(ids: ["'
            + arbitrary_node_id
            + '"]) { ... on Repository { nameWithOwner } } }'
        )
        result = check_repo_scope(body, ALLOWED, ALLOWED_NAMES)
        assert result.verdict is ScopeVerdict.OUT_OF_SCOPE
        assert result.detail == arbitrary_node_id

    def test_nodes_ids_via_variable_list_evil_blocked(self) -> None:
        body = _body(
            "query($ids: [ID!]!) {"
            "  nodes(ids: $ids) { ... on PullRequest { title } }"
            "}",
            variables={"ids": [PR_EVIL]},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(PR_EVIL)

    def test_variable_object_lowercase_ids_field_blocked(self) -> None:
        """Lowercase ``ids`` inside a variable object is collected."""
        body = _body(
            "mutation($input: SomeInput!) { doThing(input: $input) { id } }",
            variables={"input": {"ids": [PR_EVIL]}},
        )
        assert check_repo_scope(body, ALLOWED, ALLOWED_NAMES) == _oos(PR_EVIL)
