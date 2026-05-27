# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Anthropic server-side-tool domain trimming.

The Anthropic Messages API exposes server-side tools (``web_fetch_*``,
``web_search_*``, etc.) that fetch arbitrary URLs from Anthropic's
egress and return content in the API response. Because the airut
network proxy never sees those upstream fetches, an agent with access
to ``api.anthropic.com /v1/messages*`` can use these tools to read
internet resources that the airut network allowlist denies.

This module parses ``/v1/messages*`` POST bodies and:

1. **Trims** each covered tool's ``allowed_domains`` to the intersection
   of the agent's declared list and the set of hosts the airut allowlist
   permits for HTTP ``GET`` on every path.
2. **Rejects** any covered tool entry that uses ``blocked_domains``
   (cannot be safely reconciled with a positive allowlist).
3. **Rejects** any wildcard / glob-shaped entry in ``allowed_domains``.
4. **Forces** ``allowed_domains: []`` (default-deny) for covered tool
   entries that declare neither ``allowed_domains`` nor a usable
   ``blocked_domains``.

See ``spec/anthropic-tool-domain-trim.md`` for the full design.
"""

from __future__ import annotations

import enum
import json
from collections.abc import Callable
from dataclasses import dataclass

from host_match import UrlPrefixEntry, match_host_pattern


type _JsonValue = (
    str | int | float | bool | None | list[_JsonValue] | dict[str, _JsonValue]
)


# Tool ``type`` prefixes covered by the trim. Each prefix matches any
# date-versioned release (e.g. ``web_fetch_20250910``). New entries must
# be added when Anthropic ships new server-side fetcher tools.
_COVERED_TOOL_PREFIXES: tuple[str, ...] = (
    "web_fetch_",
    "web_search_",
    "computer_",
    "bash_",
    "code_execution_",
)


# Maximum request body size accepted for parsing. Larger bodies are
# rejected to bound parser CPU (mirrors graphql_operations._MAX_BODY_SIZE).
_MAX_BODY_SIZE = 1024 * 1024


class ToolConfigVerdict(enum.Enum):
    """Result of a tool-config check."""

    UNCHANGED = "unchanged"  # No covered tools — body passes through as-is.
    REWRITTEN = "rewritten"  # Covered tools found and trimmed; body modified.
    BLOCKED = "blocked"  # Request must be 403'd.


@dataclass(frozen=True)
class ToolConfigResult:
    """Structured result from ``check_and_trim_tools()``.

    Attributes:
        verdict: The check outcome.
        body: Re-serialised JSON body when ``verdict == REWRITTEN``.
        error: Stable error code returned to the client when
            ``verdict == BLOCKED``.
        message: Human-readable error message returned to the client.
        detail: Short tag (e.g. tool ``type``) describing the offending
            entry; surfaced in log annotations and in the JSON response.
        log_tag: Bracket-inner text for the network log annotation
            (e.g. ``"web_fetch_20250910: dropped 1 of 1 domains:
            airut.org"``).
    """

    verdict: ToolConfigVerdict
    body: bytes | None = None
    error: str | None = None
    message: str | None = None
    detail: str | None = None
    log_tag: str | None = None


def host_get_open(
    host: str,
    domains: list[str],
    url_prefixes: list[UrlPrefixEntry],
) -> bool:
    """Return True iff ``host`` is allowlisted for unrestricted ``GET``.

    An allowlist entry qualifies if it:

    1. matches ``host`` via :func:`host_match.match_host_pattern`, and
    2. has no path restriction (``path == ""`` or absent), and
    3. has either an empty / absent ``methods`` list (any method) or
       includes ``"GET"`` in ``methods``.

    Domain-list entries (the top-level ``domains`` array in the
    allowlist) are unrestricted by definition and always qualify when
    their pattern matches.

    Path-restricted entries (e.g. ``/repos/airutorg/airut*``) do NOT
    qualify: ``allowed_domains`` on Anthropic's side is host-only, so
    we cannot delegate any host whose airut allowlist entry constrains
    the path or method.
    """
    for domain in domains:
        if match_host_pattern(domain, host):
            return True

    for entry in url_prefixes:
        if entry.get("path", ""):
            continue  # path-restricted
        if not match_host_pattern(entry.get("host", ""), host):
            continue
        methods = entry.get("methods", [])
        if not methods:
            return True
        if any(m.upper() == "GET" for m in methods):
            return True

    return False


def _is_covered_tool_type(tool_type: object) -> bool:
    """Return True if ``tool_type`` matches one of the covered prefixes.

    The match is case-insensitive — Anthropic's tool types are lowercase
    today, but the threat model assumes we cannot rely on Anthropic
    enforcing canonicalisation, and treating ``"Web_Fetch_20250910"`` as
    a non-covered type would create a trivial bypass.
    """
    if not isinstance(tool_type, str):
        return False
    lowered = tool_type.lower()
    return any(lowered.startswith(p) for p in _COVERED_TOOL_PREFIXES)


def _is_wildcard_entry(domain: str) -> bool:
    """Return True if ``domain`` looks like a wildcard / glob.

    Rejects anything containing ``*``, ``?``, whitespace, or a leading
    ``.`` — and the empty string, which is never a valid hostname.
    Anthropic's API already rejects literal ``*`` today but may add
    wildcard syntax later; we don't want to be subtly out-of-sync with
    whatever syntax they pick.
    """
    if not domain:
        return True
    if domain[0] == ".":
        return True
    return any(c in "*?" or c.isspace() for c in domain)


def _process_tools_array(
    tools: list[_JsonValue],
    host_get_open_fn: Callable[[str], bool],
    annotations: list[str],
) -> ToolConfigResult | None:
    """Apply rules 1–4 to each covered entry in a single ``tools`` array.

    Mutates entries in place. Returns a BLOCKED result on rule 1 or 2
    violation, or None on success (with modifications appended to
    ``annotations``).
    """
    for entry in tools:
        if not isinstance(entry, dict):
            continue
        tool_type = entry.get("type")
        if not _is_covered_tool_type(tool_type):
            continue
        assert isinstance(tool_type, str)

        # Rule 1: reject any usable blocked_domains. An empty list is
        # treated as "not set" for trim purposes (we still force
        # allowed_domains presence below), but a non-empty list is
        # rejected outright — a blocklist cannot be reconciled with a
        # positive allowlist.
        if "blocked_domains" in entry:
            blocked = entry["blocked_domains"]
            if not isinstance(blocked, list) or len(blocked) > 0:
                return ToolConfigResult(
                    ToolConfigVerdict.BLOCKED,
                    error="blocklist_tool_config_unsupported",
                    message=(
                        "Server-side tool 'blocked_domains' is not "
                        "supported by the airut network proxy. Use "
                        "'allowed_domains' instead — it will be trimmed "
                        "to the intersection of the declared list and "
                        "the airut network allowlist."
                    ),
                    detail=tool_type,
                    log_tag=f"{tool_type}: blocked-domains",
                )

        allowed = entry.get("allowed_domains")
        if not isinstance(allowed, list):
            # Rule 4 (extended): no usable allowed_domains — inject
            # an explicit default-deny so any future Anthropic default
            # that fails open is contained.
            entry["allowed_domains"] = []
            annotations.append(f"{tool_type}: forced allowed_domains: []")
            continue

        # Rule 2: reject wildcard / glob-shaped entries.
        for d in allowed:
            if not isinstance(d, str) or _is_wildcard_entry(d):
                return ToolConfigResult(
                    ToolConfigVerdict.BLOCKED,
                    error="wildcard_tool_domain_unsupported",
                    message=(
                        "Server-side tool 'allowed_domains' entries must "
                        "be bare hostnames. Wildcard syntax (including "
                        "'*', '?', whitespace, or a leading '.') is not "
                        "supported by the airut network proxy."
                    ),
                    detail=tool_type,
                    log_tag=f"{tool_type}: wildcard",
                )

        # Rule 3: trim to the intersection with host_get_open.
        original: list[str] = list(allowed)
        trimmed = [d for d in original if host_get_open_fn(d)]
        if trimmed != original:
            dropped = [d for d in original if d not in trimmed]
            entry["allowed_domains"] = trimmed
            annotations.append(
                f"{tool_type}: dropped {len(dropped)} of "
                f"{len(original)} domains: {','.join(dropped)}"
            )

    return None


def _walk_for_tools(
    root: _JsonValue,
    host_get_open_fn: Callable[[str], bool],
    annotations: list[str],
) -> ToolConfigResult | None:
    """Iteratively process any ``tools`` array reachable from ``root``.

    Uses an explicit stack so that adversarially nested JSON cannot
    trigger a ``RecursionError`` (which would propagate out of the
    proxy hook and result in the original body being forwarded
    unfiltered — the worst possible failure mode for this security
    control).

    Whenever a key named ``tools`` whose value is a list is encountered,
    :func:`_process_tools_array` is applied to it. The walk handles both
    the top-level Messages API shape (``{"tools": [...]}``) and the
    Batches API shape (``{"requests": [{"params": {"tools": [...]}},
    ...]}``).
    """
    stack: list[_JsonValue] = [root]
    while stack:
        obj = stack.pop()
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "tools" and isinstance(value, list):
                    block = _process_tools_array(
                        value, host_get_open_fn, annotations
                    )
                    if block is not None:
                        return block
                else:
                    stack.append(value)
        elif isinstance(obj, list):
            for item in obj:
                stack.append(item)
    return None


def check_and_trim_tools(
    request_body: bytes,
    host_get_open_fn: Callable[[str], bool],
) -> ToolConfigResult:
    """Parse a ``/v1/messages*`` POST body and apply the tool-domain trim.

    Args:
        request_body: Raw HTTP request body bytes.
        host_get_open_fn: Callable returning True if a host is permitted
            by the airut network allowlist for unconstrained ``GET``
            access (see ``host_get_open``).

    Returns:
        ToolConfigResult describing the outcome:

        * ``UNCHANGED``: no covered tool entries were found — the
          original body must be forwarded unmodified.
        * ``REWRITTEN``: at least one covered entry was trimmed or had
          ``allowed_domains`` forced; ``body`` carries the re-serialised
          JSON to forward upstream.
        * ``BLOCKED``: the request must be 403'd; ``error``, ``message``
          and ``detail`` describe the reason.
    """
    if len(request_body) > _MAX_BODY_SIZE:
        return ToolConfigResult(
            ToolConfigVerdict.BLOCKED,
            error="tool_config_too_large",
            message=(
                "Request body exceeds the 1 MiB size limit for "
                "Anthropic Messages tool-config parsing."
            ),
            detail="<too-large>",
            log_tag="<too-large>",
        )

    try:
        body = json.loads(request_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ToolConfigResult(
            ToolConfigVerdict.BLOCKED,
            error="tool_config_invalid",
            message=(
                "Request body is not valid JSON. The airut network "
                "proxy parses Anthropic Messages request bodies to "
                "trim server-side tool 'allowed_domains'."
            ),
            detail="<invalid-json>",
            log_tag="<invalid-json>",
        )

    # Scalars (string, int, bool, None) have no tools to trim — pass.
    if not isinstance(body, (dict, list)):
        return ToolConfigResult(ToolConfigVerdict.UNCHANGED)

    annotations: list[str] = []
    block = _walk_for_tools(body, host_get_open_fn, annotations)
    if block is not None:
        return block

    if not annotations:
        # No covered tool entries — quiet pass-through.
        return ToolConfigResult(ToolConfigVerdict.UNCHANGED)

    # Re-serialise with compact separators to keep the rewritten body
    # close to the original on the wire.
    new_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    return ToolConfigResult(
        ToolConfigVerdict.REWRITTEN,
        body=new_body,
        log_tag="; ".join(annotations),
    )
