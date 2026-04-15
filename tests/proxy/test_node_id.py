# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for node_id — GitHub node ID decoding."""

from __future__ import annotations

import base64
import struct

import pytest
from node_id import (  # ty:ignore[unresolved-import]
    _NODE_ID_RE,
    _decode_msgpack_array,
    decode_repo_db_id,
    repo_db_ids_from_node_ids,
)


# -- Test fixtures: real repo node IDs from test suite ---------------

# These are the same R_ IDs used in test_graphql_scope.py.
# R_kgDORH34qw decodes to [0, 1149106347]
# R_kgDORm2NDQ decodes to [0, 1181584653]
REPO_1_DB_ID = 1149106347
REPO_2_DB_ID = 1181584653
EVIL_REPO_DB_ID = 999999999

# Repo whose node ID base64 payload contains URL-safe characters.
# GitHub uses URL-safe base64 (- instead of +, _ instead of /) in
# node IDs.  These exercise that decode handles both variants.
URLSAFE_REPO_DB_ID = 1149100024
URLSAFE_REPO_ID = "R_kgDORH3f-A"  # contains '-'
URLSAFE_ISSUE_ID = "I_kwDORH3f-M4AADA5"  # contains '-'
URLSAFE_UNDERSCORE_REPO_DB_ID = 1149100028
URLSAFE_UNDERSCORE_REPO_ID = "R_kgDORH3f_A"  # contains '_'

# Synthetic node IDs for in-scope repositories.
ISSUE_IN_SCOPE_1 = "I_kwDORH34q80wOQ"
PR_IN_SCOPE_2 = "PR_kwDORm2NDc4AAQky"
COMMENT_IN_SCOPE_1 = "IC_kwDORH34q80rZw"
DISCUSSION_IN_SCOPE_2 = "D_kwDORm2NDc1Wzg"
COMMIT_IN_SCOPE_1 = "C_kwDORH34q6xhYmMxMjNkZWY0NTY"

# Synthetic node IDs for an out-of-scope repository.
ISSUE_EVIL = "I_kwDOO5rJ/84AAYaf"
PR_EVIL = "PR_kwDOO5rJ/84AAVs4"
COMMENT_EVIL = "IC_kwDOO5rJ/84AAS/R"

# Non-repo-scoped IDs.
USER_ID = "U_kgDOAAjmPw"
ORG_ID = "O_kgDNMDk"


# -------------------------------------------------------------------
# _NODE_ID_RE pattern tests
# -------------------------------------------------------------------


class TestNodeIdPattern:
    """Tests for the GitHub node ID regex pattern."""

    @pytest.mark.parametrize(
        "value",
        [
            "R_kgDORH34qw",
            "I_kwDORH34q80wOQ",
            "PR_kwDORm2NDc4AAQky",
            "IC_kwDORH34q80rZw",
            "PRRC_kwABCDEF",
            URLSAFE_REPO_ID,
            URLSAFE_UNDERSCORE_REPO_ID,
            URLSAFE_ISSUE_ID,
            USER_ID,
            ORG_ID,
        ],
    )
    def test_matches_valid_node_ids(self, value: str) -> None:
        assert _NODE_ID_RE.match(value)

    @pytest.mark.parametrize(
        "value",
        [
            "not-a-node-id",
            "abc_xyz",  # lowercase prefix
            "R_ab",  # payload too short (< 4 chars)
            "12345",
            "",
            "TOOLONG_abcdef",  # prefix > 6 chars
            "R_",  # no payload
            "clientMutationId-value",
            "550e8400-e29b-41d4-a716-446655440000",  # UUID
        ],
    )
    def test_rejects_non_node_ids(self, value: str) -> None:
        assert not _NODE_ID_RE.match(value)


# -------------------------------------------------------------------
# _decode_msgpack_array tests
# -------------------------------------------------------------------


class TestDecodeMsgpackArray:
    """Tests for the minimal msgpack array decoder."""

    def test_fixint(self) -> None:
        # [0, 42]
        raw = bytes([0x92, 0x00, 0x2A])
        assert _decode_msgpack_array(raw) == [0, 42]

    def test_uint16(self) -> None:
        # [0, 1000]
        raw = bytes([0x92, 0x00, 0xCD]) + struct.pack(">H", 1000)
        assert _decode_msgpack_array(raw) == [0, 1000]

    def test_uint32(self) -> None:
        # [0, 1149106347]
        raw = bytes([0x92, 0x00, 0xCE]) + struct.pack(">I", 1149106347)
        assert _decode_msgpack_array(raw) == [0, 1149106347]

    def test_uint64(self) -> None:
        # [0, 2**33]
        raw = bytes([0x92, 0x00, 0xCF]) + struct.pack(">Q", 2**33)
        assert _decode_msgpack_array(raw) == [0, 2**33]

    def test_int32(self) -> None:
        # [0, -1] (int32)
        raw = bytes([0x92, 0x00, 0xD2]) + struct.pack(">i", -1)
        assert _decode_msgpack_array(raw) == [0, -1]

    def test_fixstr(self) -> None:
        # [0, 42, "abc"]
        raw = bytes([0x93, 0x00, 0x2A, 0xA3]) + b"abc"
        assert _decode_msgpack_array(raw) == [0, 42, "abc"]

    def test_str8(self) -> None:
        # [0, 42, "x" * 40] — str8 encoding
        s = "x" * 40
        raw = bytes([0x93, 0x00, 0x2A, 0xD9, 40]) + s.encode()
        assert _decode_msgpack_array(raw) == [0, 42, s]

    def test_empty_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="empty payload"):
            _decode_msgpack_array(b"")

    def test_not_fixarray_raises(self) -> None:
        with pytest.raises(ValueError, match="expected fixarray"):
            _decode_msgpack_array(bytes([0x80]))  # fixmap, not fixarray

    def test_truncated_array_raises(self) -> None:
        # Declares 3 elements but only provides 1
        with pytest.raises(ValueError, match="truncated array"):
            _decode_msgpack_array(bytes([0x93, 0x00]))

    def test_truncated_fixstr_raises(self) -> None:
        # fixstr claiming 5 bytes with only 2 remaining
        with pytest.raises(ValueError, match="truncated string"):
            _decode_msgpack_array(bytes([0x92, 0x00, 0xA5, 0x61, 0x62]))

    def test_truncated_str8_header_raises(self) -> None:
        # str8 marker with no length byte
        with pytest.raises(ValueError, match="truncated string"):
            _decode_msgpack_array(bytes([0x91, 0xD9]))

    def test_truncated_str8_body_raises(self) -> None:
        # str8 claiming 10 bytes with only 3 remaining
        with pytest.raises(ValueError, match="truncated string"):
            _decode_msgpack_array(bytes([0x92, 0x00, 0xD9, 10, 0x61, 0x62]))

    def test_unhandled_type_raises(self) -> None:
        # 0xC0 = msgpack nil
        with pytest.raises(ValueError, match="unhandled msgpack type"):
            _decode_msgpack_array(bytes([0x91, 0xC0]))


# -------------------------------------------------------------------
# decode_repo_db_id tests
# -------------------------------------------------------------------


class TestDecodeRepoDbId:
    """Tests for extracting repo database IDs from node IDs."""

    def test_repository_id(self) -> None:
        assert decode_repo_db_id("R_kgDORH34qw") == REPO_1_DB_ID

    def test_issue_id(self) -> None:
        assert decode_repo_db_id(ISSUE_IN_SCOPE_1) == REPO_1_DB_ID

    def test_pull_request_id(self) -> None:
        assert decode_repo_db_id(PR_IN_SCOPE_2) == REPO_2_DB_ID

    def test_issue_comment_id(self) -> None:
        assert decode_repo_db_id(COMMENT_IN_SCOPE_1) == REPO_1_DB_ID

    def test_discussion_id(self) -> None:
        assert decode_repo_db_id(DISCUSSION_IN_SCOPE_2) == REPO_2_DB_ID

    def test_commit_id(self) -> None:
        assert decode_repo_db_id(COMMIT_IN_SCOPE_1) == REPO_1_DB_ID

    def test_urlsafe_base64_hyphen_repo(self) -> None:
        """Repo node ID with '-' in URL-safe base64 payload."""
        assert decode_repo_db_id(URLSAFE_REPO_ID) == URLSAFE_REPO_DB_ID

    def test_urlsafe_base64_hyphen_issue(self) -> None:
        """Issue node ID with '-' in URL-safe base64 payload."""
        assert decode_repo_db_id(URLSAFE_ISSUE_ID) == URLSAFE_REPO_DB_ID

    def test_urlsafe_base64_underscore_repo(self) -> None:
        """Repo node ID with '_' in URL-safe base64 payload."""
        result = decode_repo_db_id(URLSAFE_UNDERSCORE_REPO_ID)
        assert result == URLSAFE_UNDERSCORE_REPO_DB_ID

    def test_evil_repo_issue(self) -> None:
        assert decode_repo_db_id(ISSUE_EVIL) == EVIL_REPO_DB_ID

    def test_user_id_returns_none(self) -> None:
        assert decode_repo_db_id(USER_ID) is None

    def test_org_id_returns_none(self) -> None:
        assert decode_repo_db_id(ORG_ID) is None

    def test_not_a_node_id_returns_none(self) -> None:
        assert decode_repo_db_id("not-a-node-id") is None

    def test_uuid_returns_none(self) -> None:
        assert decode_repo_db_id("550e8400-e29b-41d4-a716-446655440000") is None

    def test_empty_string_returns_none(self) -> None:
        assert decode_repo_db_id("") is None

    def test_bad_base64_raises(self) -> None:
        # 1 data char is invalid base64 length (1 more than a
        # multiple of 4 after stripping padding).
        with pytest.raises(ValueError, match="base64 decode failed"):
            decode_repo_db_id("R_a===")

    def test_bad_msgpack_raises(self) -> None:
        # Valid base64 but not valid msgpack (fixmap, not fixarray).
        # Pad to >= 4 base64 chars so it matches _NODE_ID_RE.
        bad_payload = (
            base64.b64encode(b"\x80\x00\x00\x00").rstrip(b"=").decode()
        )
        with pytest.raises(ValueError, match="msgpack decode failed"):
            decode_repo_db_id(f"R_{bad_payload}")

    def test_short_array_raises(self) -> None:
        # Valid msgpack array but only 1 element [42].
        # Pad with extra bytes so base64 is >= 4 chars.
        payload = (
            base64.b64encode(bytes([0x91, 0x2A, 0x00])).rstrip(b"=").decode()
        )
        with pytest.raises(ValueError, match="unexpected array length"):
            decode_repo_db_id(f"R_{payload}")

    def test_non_integer_repo_db_id_raises(self) -> None:
        # Array where element[1] is a string instead of int: [0, "bad"]
        raw = bytes([0x92, 0x00, 0xA3]) + b"bad"
        payload = base64.b64encode(raw).rstrip(b"=").decode()
        with pytest.raises(ValueError, match="non-integer repo_db_id"):
            decode_repo_db_id(f"R_{payload}")


# -------------------------------------------------------------------
# repo_db_ids_from_node_ids tests
# -------------------------------------------------------------------


class TestRepoDbIdsFromNodeIds:
    """Tests for converting R_ node IDs to database IDs."""

    def test_basic_conversion(self) -> None:
        node_ids = frozenset({"R_kgDORH34qw", "R_kgDORm2NDQ"})
        result = repo_db_ids_from_node_ids(node_ids)
        assert result == frozenset({REPO_1_DB_ID, REPO_2_DB_ID})

    def test_non_r_ids_ignored(self) -> None:
        node_ids = frozenset({"R_kgDORH34qw", "I_kwDORH34q80wOQ"})
        result = repo_db_ids_from_node_ids(node_ids)
        assert result == frozenset({REPO_1_DB_ID})

    def test_urlsafe_base64_conversion(self) -> None:
        node_ids = frozenset({URLSAFE_REPO_ID, URLSAFE_UNDERSCORE_REPO_ID})
        result = repo_db_ids_from_node_ids(node_ids)
        expected = frozenset(
            {URLSAFE_REPO_DB_ID, URLSAFE_UNDERSCORE_REPO_DB_ID}
        )
        assert result == expected

    def test_empty_set(self) -> None:
        assert repo_db_ids_from_node_ids(frozenset()) == frozenset()

    def test_bad_r_id_raises(self) -> None:
        # Pad to >= 4 base64 chars so it matches _NODE_ID_RE.
        bad_payload = (
            base64.b64encode(b"\x80\x00\x00\x00").rstrip(b"=").decode()
        )
        node_ids = frozenset({f"R_{bad_payload}"})
        with pytest.raises(ValueError):
            repo_db_ids_from_node_ids(node_ids)
