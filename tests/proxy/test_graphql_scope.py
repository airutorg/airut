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
    check_repo_scope,
)


ALLOWED = frozenset({"R_kgDORH34qw", "R_kgDORm2NDQ"})

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
