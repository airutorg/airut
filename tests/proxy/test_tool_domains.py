# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for tool_domains (Anthropic server-side-tool domain trimming)."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from tool_domains import (  # ty:ignore[unresolved-import]
    _MAX_BODY_SIZE,
    ToolConfigVerdict,
    check_and_trim_tools,
    host_get_open,
)


# Allowlist used in most tests — modelled on the actual repo allowlist
# shape so the tests double as integration evidence.
_ALLOWLIST_DOMAINS: list[str] = []
_ALLOWLIST_URL_PREFIXES: list[dict] = [
    {"host": "api.anthropic.com", "path": "/v1/messages*", "methods": ["POST"]},
    {"host": "statsig.anthropic.com", "path": "", "methods": ["POST"]},
    {"host": "pypi.org", "path": "", "methods": ["GET", "HEAD"]},
    {"host": "files.pythonhosted.org", "path": "", "methods": ["GET", "HEAD"]},
    {
        "host": "api.github.com",
        "path": "/repos/airutorg/airut*",
        "methods": [],
    },
    {"host": "claude.ai", "path": "/install.sh", "methods": ["GET"]},
    {"host": "docs.slack.dev", "path": "", "methods": ["GET", "HEAD"]},
    # Path-open, methods-open entry — should qualify even with no methods list
    {"host": "example.open.test", "path": "", "methods": []},
    # Path-open, methods include both GET and POST
    {"host": "example.mixed.test", "path": "", "methods": ["GET", "POST"]},
]


def _open(host: str) -> bool:
    """Default host_get_open closure against the test allowlist."""
    return host_get_open(host, _ALLOWLIST_DOMAINS, _ALLOWLIST_URL_PREFIXES)


def _body(payload: dict | list) -> bytes:
    return json.dumps(payload).encode()


# -------------------------------------------------------------------
# host_get_open
# -------------------------------------------------------------------


class TestHostGetOpen:
    """Tests for the host_get_open predicate."""

    def test_path_open_get_in_methods(self) -> None:
        assert _open("pypi.org") is True

    def test_path_open_methods_empty_list(self) -> None:
        assert _open("example.open.test") is True

    def test_path_open_mixed_methods(self) -> None:
        assert _open("example.mixed.test") is True

    def test_path_open_post_only(self) -> None:
        # statsig allows POST but not GET — must be rejected
        assert _open("statsig.anthropic.com") is False

    def test_path_restricted(self) -> None:
        assert _open("api.github.com") is False

    def test_path_restricted_short(self) -> None:
        assert _open("claude.ai") is False

    def test_unlisted(self) -> None:
        assert _open("airut.org") is False
        assert _open("evil.example") is False

    def test_case_insensitive_match(self) -> None:
        assert _open("PYPI.ORG") is True
        assert _open("PyPi.Org") is True

    def test_domain_list_entry(self) -> None:
        # Domain entries are unrestricted by definition.
        assert (
            host_get_open(
                "wide.open.test",
                ["wide.open.test"],
                [],
            )
            is True
        )

    def test_domain_list_wildcard(self) -> None:
        assert (
            host_get_open(
                "api.allowed.test",
                ["*.allowed.test"],
                [],
            )
            is True
        )

    def test_methods_lowercase_in_config(self) -> None:
        """Lowercase ``get`` in methods is recognised (case-insensitive)."""
        prefixes: list[dict] = [
            {"host": "lower.test", "path": "", "methods": ["get"]}
        ]
        assert host_get_open("lower.test", [], prefixes) is True


# -------------------------------------------------------------------
# UNCHANGED pass-through (no covered tools)
# -------------------------------------------------------------------


class TestUnchanged:
    """Tests that requests without covered tool entries pass through."""

    def test_no_tools_field(self) -> None:
        result = check_and_trim_tools(
            _body({"model": "claude", "messages": []}), _open
        )
        assert result.verdict is ToolConfigVerdict.UNCHANGED
        assert result.body is None

    def test_tools_is_empty_list(self) -> None:
        result = check_and_trim_tools(
            _body({"model": "claude", "tools": []}), _open
        )
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_tools_is_not_a_list(self) -> None:
        # Non-list tools field is ignored (treated as no tools).
        result = check_and_trim_tools(
            _body({"model": "claude", "tools": "oops"}), _open
        )
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_custom_tool_type_unmodified(self) -> None:
        result = check_and_trim_tools(
            _body(
                {
                    "model": "claude",
                    "tools": [
                        {"type": "custom", "name": "Bash"},
                        {"name": "Read"},  # no type field
                    ],
                }
            ),
            _open,
        )
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_non_dict_entries_skipped(self) -> None:
        # A non-dict entry in the tools list (e.g. a string slipped in by
        # mistake) is silently ignored. The covered fetcher alongside is
        # still trimmed.
        payload = {
            "tools": [
                "not a dict",
                42,
                None,
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["airut.org"],
                },
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        # The non-dict entries are preserved verbatim.
        assert new["tools"][0] == "not a dict"
        assert new["tools"][1] == 42
        assert new["tools"][2] is None
        assert new["tools"][3]["allowed_domains"] == []

    def test_mcp_tool_unmodified(self) -> None:
        result = check_and_trim_tools(
            _body(
                {
                    "tools": [
                        {
                            "type": "mcp",
                            "server_label": "fs",
                            "server_url": "http://mcp",
                        }
                    ]
                }
            ),
            _open,
        )
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_top_level_scalar_body(self) -> None:
        # A non-object/non-list JSON body has nothing to trim.
        result = check_and_trim_tools(b"true", _open)
        assert result.verdict is ToolConfigVerdict.UNCHANGED


# -------------------------------------------------------------------
# Rewrite — Rule 3 (trim allowed_domains)
# -------------------------------------------------------------------


class TestRewriteTrim:
    """Tests that allowed_domains is trimmed to host_get_open."""

    def test_only_open_hosts_unchanged_list(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["pypi.org", "files.pythonhosted.org"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        # No domains were dropped — and no forced injection happened either,
        # so the result is UNCHANGED.
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_mixed_open_and_blocked(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": [
                        "pypi.org",
                        "airut.org",
                        "api.github.com",
                    ],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        assert result.body is not None
        new = json.loads(result.body)
        assert new["tools"][0]["allowed_domains"] == ["pypi.org"]
        assert "dropped 2 of 3" in (result.log_tag or "")
        assert "airut.org" in (result.log_tag or "")
        assert "api.github.com" in (result.log_tag or "")

    def test_all_blocked_yields_empty_list(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["airut.org", "evil.example"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []

    def test_preserves_other_tool_fields(self) -> None:
        payload = {
            "model": "claude-haiku-4-5",
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "name": "web_fetch",
                    "max_uses": 1,
                    "allowed_domains": ["airut.org"],
                }
            ],
        }
        result = check_and_trim_tools(_body(payload), _open)
        new = json.loads(result.body or b"")
        assert new["model"] == "claude-haiku-4-5"
        tool = new["tools"][0]
        assert tool["type"] == "web_fetch_20250910"
        assert tool["name"] == "web_fetch"
        assert tool["max_uses"] == 1
        assert tool["allowed_domains"] == []

    def test_multiple_tools_only_fetchers_modified(self) -> None:
        payload = {
            "tools": [
                {"type": "custom", "name": "Bash"},
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["airut.org"],
                },
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0] == {"type": "custom", "name": "Bash"}
        assert new["tools"][1]["allowed_domains"] == []


# -------------------------------------------------------------------
# Rewrite — Rule 4 (force allowed_domains presence)
# -------------------------------------------------------------------


class TestForceAllowedDomains:
    """Tests that allowed_domains is injected when absent."""

    def test_no_allowed_no_blocked_forces_empty(self) -> None:
        payload = {
            "tools": [
                {"type": "web_fetch_20250910", "name": "web_fetch"},
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []
        assert "forced" in (result.log_tag or "")

    def test_empty_blocked_domains_still_forces_empty(self) -> None:
        # Edge case: blocked_domains is the empty list (no constraint),
        # allowed_domains absent. Treated the same as "neither set" so
        # the request still gets a default-deny allowed_domains: [].
        payload = {
            "tools": [
                {"type": "web_fetch_20250910", "blocked_domains": []},
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []

    def test_allowed_domains_null_treated_as_missing(self) -> None:
        payload = {
            "tools": [
                {"type": "web_fetch_20250910", "allowed_domains": None},
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []


# -------------------------------------------------------------------
# Rule 1 — reject blocked_domains
# -------------------------------------------------------------------


class TestBlockedDomainsRejected:
    """Tests that non-empty blocked_domains produces a 403."""

    def test_non_empty_blocked_domains_403(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "blocked_domains": ["evil.example"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "blocklist_tool_config_unsupported"
        assert result.detail == "web_fetch_20250910"
        assert "blocked-domains" in (result.log_tag or "")

    def test_blocked_domains_not_a_list_is_rejected(self) -> None:
        # A non-list (e.g. string) is treated as "usable blocked_domains"
        # and rejected — better to fail closed.
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "blocked_domains": "evil.example",
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "blocklist_tool_config_unsupported"

    def test_blocked_domains_alongside_allowed(self) -> None:
        # If both fields are set and blocked_domains is non-empty, reject.
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["pypi.org"],
                    "blocked_domains": ["airut.org"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "blocklist_tool_config_unsupported"


# -------------------------------------------------------------------
# Rule 2 — reject wildcards
# -------------------------------------------------------------------


class TestWildcardRejected:
    """Tests that wildcard entries produce a 403."""

    def test_star_wildcard(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["*.example.com"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "wildcard_tool_domain_unsupported"

    def test_question_wildcard(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["api?.example.com"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "wildcard_tool_domain_unsupported"

    def test_leading_dot(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": [".example.com"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "wildcard_tool_domain_unsupported"

    def test_whitespace(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["bad host.example"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "wildcard_tool_domain_unsupported"

    def test_empty_string(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": [""],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "wildcard_tool_domain_unsupported"

    def test_non_string_entry(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": [42],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "wildcard_tool_domain_unsupported"


# -------------------------------------------------------------------
# Covered tool types
# -------------------------------------------------------------------


class TestCoveredTypes:
    """Tests that the prefix list catches all expected variants."""

    def test_case_variant_tool_type(self) -> None:
        # Anthropic's tool types are lowercase today, but the trim must
        # not be bypassable by sending a case-variant of the prefix.
        payload = {
            "tools": [
                {
                    "type": "Web_Fetch_20250910",
                    "allowed_domains": ["airut.org"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []

    def test_web_fetch_versioned(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20251001",
                    "allowed_domains": ["airut.org"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN

    def test_web_search_no_allowed_domains_left_unrestricted(self) -> None:
        # web_search rejects an empty allowed_domains with a 400, so the
        # default-deny []-injection must NOT apply. With no declared
        # domains the entry is left untouched (unrestricted search).
        payload = {
            "tools": [{"type": "web_search_20250305", "name": "web_search"}]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_web_search_trim_to_empty_removes_key(self) -> None:
        # All declared domains are outside the allowlist: the trim would
        # leave [], which Anthropic 400s. The key must be removed
        # entirely so search runs unrestricted instead of failing.
        payload = {
            "tools": [
                {
                    "type": "web_search_20250305",
                    "allowed_domains": ["airut.org"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert "allowed_domains" not in new["tools"][0]
        assert "airut.org" in (result.log_tag or "")

    def test_web_search_trim_to_nonempty_keeps_subset(self) -> None:
        # A partially-allowlisted list trims to the reachable subset,
        # exactly like web_fetch — search stays scoped to those hosts.
        payload = {
            "tools": [
                {
                    "type": "web_search_20250305",
                    "allowed_domains": ["docs.slack.dev", "airut.org"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == ["docs.slack.dev"]

    def test_web_search_fully_allowlisted_passes_through(self) -> None:
        # Every declared domain is reachable — nothing to trim.
        payload = {
            "tools": [
                {
                    "type": "web_search_20250305",
                    "allowed_domains": ["docs.slack.dev", "pypi.org"],
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_web_search_explicit_empty_removed(self) -> None:
        # An agent-supplied empty list is also invalid upstream; it must
        # be removed rather than forwarded as [].
        payload = {
            "tools": [{"type": "web_search_20250305", "allowed_domains": []}]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert "allowed_domains" not in new["tools"][0]

    def test_web_search_versioned_variant_left_unrestricted(self) -> None:
        # A future date-stamped release of web_search behaves the same.
        payload = {"tools": [{"type": "web_search_20991231"}]}
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_bash_tool(self) -> None:
        # bash_* (cloud-hosted) — even though it doesn't have
        # allowed_domains today, rule 4 still injects [].
        payload = {"tools": [{"type": "bash_20250124", "name": "bash"}]}
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []

    def test_computer_tool(self) -> None:
        payload = {"tools": [{"type": "computer_20250124"}]}
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []

    def test_code_execution(self) -> None:
        payload = {"tools": [{"type": "code_execution_20250825"}]}
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []


# -------------------------------------------------------------------
# Body parsing — size and JSON errors
# -------------------------------------------------------------------


class TestBodyParsing:
    """Tests for size limit, malformed JSON, and unusual body shapes."""

    def test_oversized_body(self) -> None:
        body = b"x" * (_MAX_BODY_SIZE + 1)
        result = check_and_trim_tools(body, _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "tool_config_too_large"

    def test_body_at_size_limit_is_parsed(self) -> None:
        """A body of exactly _MAX_BODY_SIZE is still parsed, not blocked."""
        payload = {"tools": [{"type": "custom", "name": "Read"}], "pad": ""}
        body = _body(payload)
        # Grow the padding string so the encoded body is exactly at the cap.
        payload["pad"] = "x" * (_MAX_BODY_SIZE - len(body))
        body = _body(payload)
        assert len(body) == _MAX_BODY_SIZE
        result = check_and_trim_tools(body, _open)
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    @staticmethod
    def _image_payload(tools: list[dict]) -> dict:
        """A Messages body carrying a 4 MiB base64 image, as Read sends."""
        return {
            "model": "claude-opus-5",
            "tools": tools,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": "A" * (4 * 1024 * 1024),
                            },
                        }
                    ],
                }
            ],
        }

    def test_multi_megabyte_image_body_passes(self) -> None:
        """A Claude Code request carrying a read image is not blocked.

        Reading an image base64-encodes it into the ``/v1/messages``
        body, and the whole conversation is resent on every turn, so a
        cap below Anthropic's own 32 MB request limit bricks the rest of
        the session rather than just one request. Regression test for a
        1 MiB cap that 403'd these requests.
        """
        body = _body(self._image_payload([{"type": "custom", "name": "Read"}]))
        assert len(body) > 1024 * 1024
        result = check_and_trim_tools(body, _open)
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_multi_megabyte_body_is_still_trimmed(self) -> None:
        """Raising the cap must not stop the trim running on big bodies.

        Guards the security control itself: a large body carrying a
        covered tool is parsed and trimmed, not waved through.
        """
        body = _body(
            self._image_payload(
                [
                    {
                        "type": "web_fetch_20250910",
                        "allowed_domains": ["evil.example"],
                    }
                ]
            )
        )
        assert len(body) > 1024 * 1024
        result = check_and_trim_tools(body, _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []

    def test_oversized_body_with_covered_tool_is_blocked(self) -> None:
        """Over the cap, a covered tool is blocked rather than passed."""
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["evil.example"],
                }
            ],
            "pad": "x" * (_MAX_BODY_SIZE + 1),
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "tool_config_too_large"

    def test_rewrite_does_not_inflate_non_ascii(self) -> None:
        r"""A rewritten body must not balloon on non-ASCII content.

        ``json.dumps`` defaults to ``ensure_ascii=True``, which expands
        each non-ASCII character to a 6-byte ``\uXXXX`` escape. Now
        that multi-megabyte bodies are admitted, that could push a body
        Anthropic accepted past its own request limit.
        """
        text = "日本語テキスト" * 100
        payload = {
            "tools": [{"type": "web_fetch_20250910"}],
            "messages": [{"role": "user", "content": text}],
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        assert result.body is not None
        # Round-trips intact...
        new = json.loads(result.body)
        assert new["messages"][0]["content"] == text
        # ...and stays close to the original size rather than inflating.
        assert len(result.body) < len(text.encode()) * 2

    def test_rewrite_handles_lone_surrogate(self) -> None:
        r"""A lone surrogate must not break the rewrite.

        ``JSON.stringify`` emits an unpaired surrogate as ``\udXXX``
        rather than rejecting it, so a client that split a surrogate
        pair mid-string sends one. It has no UTF-8 encoding, so the
        non-escaping serialiser raises and must fall back to escaping.
        """
        raw = (
            b'{"tools":[{"type":"web_fetch_20250910",'
            b'"allowed_domains":["airut.org"]}],'
            b'"messages":[{"role":"user","content":"tail \\ud83d"}]}'
        )
        result = check_and_trim_tools(raw, _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        assert result.body is not None
        new = json.loads(result.body)
        assert new["tools"][0]["allowed_domains"] == []
        assert new["messages"][0]["content"] == "tail \ud83d"

    def test_malformed_json(self) -> None:
        result = check_and_trim_tools(b"not json{{{", _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "tool_config_invalid"

    def test_deeply_nested_body_is_blocked(self) -> None:
        """A nesting bomb fails closed instead of escaping the filter.

        ``json.loads`` recurses in C, so a body far under the size cap
        can raise ``RecursionError``. Left uncaught it would propagate
        out of the proxy hook and the original, untrimmed body would be
        forwarded — a silent bypass of this control.
        """
        depth = 50_000
        body = (b'{"a":' * depth) + b"1" + (b"}" * depth)
        # Precondition: this depth must actually exceed the
        # interpreter's C recursion limit, else the test is vacuous.
        with pytest.raises(RecursionError):
            json.loads(body)
        assert len(body) < _MAX_BODY_SIZE
        result = check_and_trim_tools(body, _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "tool_config_invalid"

    def test_invalid_utf8(self) -> None:
        result = check_and_trim_tools(b"\xff\xfe\x00\x00", _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "tool_config_invalid"

    def test_empty_body(self) -> None:
        result = check_and_trim_tools(b"", _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "tool_config_invalid"

    def test_top_level_list(self) -> None:
        # A top-level array isn't a Messages body, but we still walk
        # nested objects for tools arrays — UNCHANGED if none.
        result = check_and_trim_tools(b"[1, 2, 3]", _open)
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_deeply_nested_body_does_not_crash(self) -> None:
        """Iterative walk handles adversarial nesting without RecursionError.

        Earlier versions used recursive descent in ``_walk_for_tools`` —
        a ~12 KB body with deep object nesting would trigger
        ``RecursionError`` which would propagate out of the proxy hook
        and result in the original (un-trimmed) body being forwarded
        upstream.
        """
        import sys as _sys

        nesting = 2000
        body = b'{"a":' * nesting + b"null" + b"}" * nesting
        original = _sys.getrecursionlimit()
        _sys.setrecursionlimit(1500)
        try:
            result = check_and_trim_tools(body, _open)
        finally:
            _sys.setrecursionlimit(original)
        # No tools array reachable — quiet pass-through.
        assert result.verdict is ToolConfigVerdict.UNCHANGED

    def test_top_level_list_containing_tools(self) -> None:
        # Defence in depth for hypothetical batches-style payload
        # whose top-level is a JSON array.
        payload = [
            {
                "tools": [
                    {
                        "type": "web_fetch_20250910",
                        "allowed_domains": ["airut.org"],
                    }
                ]
            }
        ]
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new[0]["tools"][0]["allowed_domains"] == []


# -------------------------------------------------------------------
# Recursive walk — nested tools (e.g. Batches API)
# -------------------------------------------------------------------


class TestNestedToolsWalk:
    """Tests that nested ``tools`` arrays (Batches API) are processed."""

    def test_batches_style_nested_tools(self) -> None:
        payload = {
            "requests": [
                {
                    "custom_id": "a",
                    "params": {
                        "model": "claude",
                        "tools": [
                            {
                                "type": "web_fetch_20250910",
                                "allowed_domains": ["airut.org"],
                            }
                        ],
                    },
                },
                {
                    "custom_id": "b",
                    "params": {
                        "model": "claude",
                        "tools": [
                            {
                                "type": "web_search_20250305",
                                "allowed_domains": ["pypi.org", "airut.org"],
                            }
                        ],
                    },
                },
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["requests"][0]["params"]["tools"][0]["allowed_domains"] == []
        assert new["requests"][1]["params"]["tools"][0]["allowed_domains"] == [
            "pypi.org"
        ]

    def test_nested_blocked_domains_rejected(self) -> None:
        payload = {
            "requests": [
                {
                    "params": {
                        "tools": [
                            {
                                "type": "web_fetch_20250910",
                                "blocked_domains": ["evil.example"],
                            }
                        ]
                    }
                }
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED
        assert result.error == "blocklist_tool_config_unsupported"


# -------------------------------------------------------------------
# Regression: canary scenario from spec §2.1
# -------------------------------------------------------------------


class TestCanaryBypass:
    """Regression for the pentest scenario from the spec §2.1."""

    def test_airut_canary_request_trimmed(self) -> None:
        # The exact request shape captured by the pentest, against the
        # current repo allowlist (which does not include airut.org).
        payload = {
            "model": "claude-haiku-4-5",
            "max_tokens": 256,
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "name": "web_fetch",
                    "max_uses": 1,
                    "allowed_domains": ["airut.org"],
                }
            ],
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "web_fetch https://airut.org/canary.txt and return body"
                    ),
                }
            ],
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        # The canary domain is dropped, leaving an empty allowed_domains
        # which Anthropic treats as default-deny.
        assert new["tools"][0]["allowed_domains"] == []


# -------------------------------------------------------------------
# Multiple covered tools in one request
# -------------------------------------------------------------------


class TestMultipleTools:
    """Tests for multi-tool requests."""

    def test_two_fetchers_both_trimmed(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["airut.org"],
                },
                {
                    "type": "web_search_20250305",
                    "allowed_domains": ["pypi.org", "airut.org"],
                },
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == []
        assert new["tools"][1]["allowed_domains"] == ["pypi.org"]
        # Both tool tags appear in the log annotation.
        assert "web_fetch_20250910" in (result.log_tag or "")
        assert "web_search_20250305" in (result.log_tag or "")

    def test_block_short_circuits_remaining_entries(self) -> None:
        # First entry uses blocked_domains; the result must be BLOCKED
        # regardless of what later entries contain.
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "blocked_domains": ["x"],
                },
                {
                    "type": "web_search_20250305",
                    "allowed_domains": ["pypi.org"],
                },
            ]
        }
        result = check_and_trim_tools(_body(payload), _open)
        assert result.verdict is ToolConfigVerdict.BLOCKED


# -------------------------------------------------------------------
# Custom host_get_open
# -------------------------------------------------------------------


def _custom_open_factory(allowed: set[str]) -> Callable[[str], bool]:
    def _fn(host: str) -> bool:
        return host in allowed

    return _fn


class TestCustomOpenPredicate:
    """Tests that the predicate is honoured exactly as supplied."""

    def test_predicate_allowlist_used(self) -> None:
        payload = {
            "tools": [
                {
                    "type": "web_fetch_20250910",
                    "allowed_domains": ["allowed.test", "blocked.test"],
                }
            ]
        }
        result = check_and_trim_tools(
            _body(payload),
            _custom_open_factory({"allowed.test"}),
        )
        assert result.verdict is ToolConfigVerdict.REWRITTEN
        new = json.loads(result.body or b"")
        assert new["tools"][0]["allowed_domains"] == ["allowed.test"]
