# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the request-body filter pipeline types and concrete filters.

The pure check functions (``check_operations``, ``check_and_trim_tools``)
are covered by ``test_graphql_operations.py`` and ``test_tool_domains.py``.
These tests cover the :class:`FilterResult` constructors, the two filter
adapters' ``matches`` / ``apply`` translation, and the
``is_anthropic_messages_request`` predicate. End-to-end behaviour through
``ProxyFilter.request()`` lives in ``test_proxy_filter.py``.
"""

from __future__ import annotations

import json

from graphql_operations import (  # ty:ignore[unresolved-import]
    GraphQLOperationFilter,
)
from host_match import UrlPrefixEntry  # ty:ignore[unresolved-import]
from request_filter import (  # ty:ignore[unresolved-import]
    FilterAction,
    FilterRequest,
    FilterResult,
)
from tool_domains import (  # ty:ignore[unresolved-import]
    ToolDomainFilter,
    is_anthropic_messages_request,
)


def _body(payload: object) -> bytes:
    return json.dumps(payload).encode()


# ---------------------------------------------------------------------------
# FilterResult constructors
# ---------------------------------------------------------------------------


class TestFilterResult:
    def test_passthrough_default(self) -> None:
        result = FilterResult.passthrough()
        assert result.action is FilterAction.PASS
        assert result.body is None
        assert result.log_tag is None

    def test_passthrough_with_log_tag(self) -> None:
        result = FilterResult.passthrough(log_tag="query/viewer")
        assert result.action is FilterAction.PASS
        assert result.log_tag == "query/viewer"

    def test_rewrite(self) -> None:
        result = FilterResult.rewrite(b"{}", log_tag="trimmed")
        assert result.action is FilterAction.REWRITE
        assert result.body == b"{}"
        assert result.log_tag == "trimmed"

    def test_block(self) -> None:
        result = FilterResult.block(
            error="some_error",
            message="human readable",
            detail="offender",
            log_tag="some_error tag",
        )
        assert result.action is FilterAction.BLOCK
        assert result.error == "some_error"
        assert result.message == "human readable"
        assert result.detail == "offender"
        assert result.log_tag == "some_error tag"


# ---------------------------------------------------------------------------
# GraphQLOperationFilter
# ---------------------------------------------------------------------------


class TestGraphQLOperationFilter:
    _ENTRY: UrlPrefixEntry = {
        "host": "api.github.com",
        "path": "/graphql",
        "methods": ["POST"],
        "graphql": {
            "queries": ["*"],
            "mutations": ["createIssue"],
            "subscriptions": [],
        },
    }

    def _req(self, matched_entry: UrlPrefixEntry | None) -> FilterRequest:
        return FilterRequest(
            host="api.github.com",
            path="/graphql",
            matched_entry=matched_entry,
        )

    def test_matches_entry_with_graphql_block(self) -> None:
        assert GraphQLOperationFilter().matches(self._req(self._ENTRY)) is True

    def test_does_not_match_entry_without_graphql_block(self) -> None:
        entry: UrlPrefixEntry = {"host": "api.github.com", "path": "/graphql"}
        assert GraphQLOperationFilter().matches(self._req(entry)) is False

    def test_does_not_match_when_no_entry(self) -> None:
        assert GraphQLOperationFilter().matches(self._req(None)) is False

    def test_apply_allowed_passes_through_with_tag(self) -> None:
        body = _body({"query": "query { viewer { login } }"})
        result = GraphQLOperationFilter().apply(self._req(self._ENTRY), body)
        assert result.action is FilterAction.PASS
        assert result.log_tag == "query/viewer"

    def test_apply_blocked_returns_block(self) -> None:
        body = _body(
            {"query": "mutation { deleteRepository(input: {}) { id } }"}
        )
        result = GraphQLOperationFilter().apply(self._req(self._ENTRY), body)
        assert result.action is FilterAction.BLOCK
        assert result.error == "graphql_operation_blocked"
        assert result.detail == "deleteRepository"
        assert result.log_tag == "mutation/deleteRepository"


# ---------------------------------------------------------------------------
# ToolDomainFilter
# ---------------------------------------------------------------------------


class TestToolDomainFilter:
    @staticmethod
    def _open(host: str) -> bool:
        return host == "pypi.org"

    def _filter(self) -> ToolDomainFilter:
        return ToolDomainFilter(self._open)

    def _req(self, host: str, path: str) -> FilterRequest:
        return FilterRequest(host=host, path=path, matched_entry=None)

    def test_matches_messages_request(self) -> None:
        req = self._req("api.anthropic.com", "/v1/messages")
        assert self._filter().matches(req) is True

    def test_does_not_match_other_request(self) -> None:
        req = self._req("api.github.com", "/graphql")
        assert self._filter().matches(req) is False

    def test_apply_no_tools_passes_through(self) -> None:
        body = _body({"messages": [{"role": "user", "content": "hi"}]})
        result = self._filter().apply(
            self._req("api.anthropic.com", "/v1/messages"), body
        )
        assert result.action is FilterAction.PASS
        assert result.log_tag is None

    def test_apply_trims_disallowed_domain(self) -> None:
        body = _body(
            {
                "tools": [
                    {
                        "type": "web_fetch_20250910",
                        "allowed_domains": ["pypi.org", "airut.org"],
                    }
                ]
            }
        )
        result = self._filter().apply(
            self._req("api.anthropic.com", "/v1/messages"), body
        )
        assert result.action is FilterAction.REWRITE
        assert result.body is not None
        new = json.loads(result.body)
        assert new["tools"][0]["allowed_domains"] == ["pypi.org"]
        assert result.log_tag is not None
        assert "airut.org" in result.log_tag

    def test_apply_blocked_domains_returns_block(self) -> None:
        body = _body(
            {
                "tools": [
                    {
                        "type": "web_fetch_20250910",
                        "blocked_domains": ["evil.example"],
                    }
                ]
            }
        )
        result = self._filter().apply(
            self._req("api.anthropic.com", "/v1/messages"), body
        )
        assert result.action is FilterAction.BLOCK
        assert result.error == "blocklist_tool_config_unsupported"
        assert result.detail == "web_fetch_20250910"
        assert result.log_tag is not None


# ---------------------------------------------------------------------------
# is_anthropic_messages_request
# ---------------------------------------------------------------------------


class TestIsAnthropicMessagesRequest:
    def test_matches_messages(self) -> None:
        assert (
            is_anthropic_messages_request("api.anthropic.com", "/v1/messages")
            is True
        )

    def test_matches_batches(self) -> None:
        # /v1/messages/batches is a real Anthropic endpoint nested under
        # the Messages API that also carries tools.
        assert (
            is_anthropic_messages_request(
                "api.anthropic.com", "/v1/messages/batches"
            )
            is True
        )

    def test_matches_query_string(self) -> None:
        assert (
            is_anthropic_messages_request(
                "api.anthropic.com", "/v1/messages?stream=true"
            )
            is True
        )

    def test_case_insensitive_host(self) -> None:
        assert (
            is_anthropic_messages_request("API.ANTHROPIC.COM", "/v1/messages")
            is True
        )

    def test_rejects_other_host(self) -> None:
        assert (
            is_anthropic_messages_request("api.example.com", "/v1/messages")
            is False
        )

    def test_rejects_other_path(self) -> None:
        assert (
            is_anthropic_messages_request("api.anthropic.com", "/v1/files")
            is False
        )

    def test_rejects_lookalike_path(self) -> None:
        # /v1/messages_legacy must not be treated as a Messages API call
        # — startswith("/v1/messages") would accept it without a
        # boundary check.
        assert (
            is_anthropic_messages_request(
                "api.anthropic.com", "/v1/messages_legacy"
            )
            is False
        )
