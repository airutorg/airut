# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Request-body filter pipeline for the network proxy.

Service-specific request-body inspection (the GraphQL operation
allowlist, the Anthropic server-side-tool domain trim, and future
payload filters) is expressed as a list of :class:`RequestBodyFilter`
objects. ``ProxyFilter`` runs them in order on every allowlisted
request and translates each :class:`FilterResult` into a pass-through,
an in-place body rewrite, or a 403.

Keeping the gating, body-rewrite, and 403 handling in one pipeline —
rather than open-coded per filter in ``ProxyFilter.request()`` — means a
new payload filter is a small class plus one registry entry, with no
new inline special-casing.

This pipeline covers **request-body authorization** only. Credential
transformation (AWS re-signing, GitHub App tokens, masked-secret token
replacement) is a separate concern keyed off the replacement map and
stays in ``ProxyFilter``.

See ``spec/request-body-filters.md`` for the full design.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Protocol

from host_match import UrlPrefixEntry


class FilterAction(enum.Enum):
    """What the pipeline should do with a request after a filter runs."""

    PASS = "pass"  # Forward the request unchanged.
    REWRITE = "rewrite"  # Forward the request with a rewritten body.
    BLOCK = "block"  # Reject the request with a 403.


@dataclass(frozen=True)
class FilterRequest:
    """The request context a filter sees.

    Decoupled from mitmproxy's flow object so filters are unit-testable
    without the proxy. The body is passed separately to
    :meth:`RequestBodyFilter.apply` because not every filter needs it to
    decide whether it applies.

    Attributes:
        host: Request hostname (``flow.request.pretty_host``).
        path: Request path including any query string
            (``flow.request.path``).
        matched_entry: The ``url_prefixes`` entry that allowlisted this
            request, or None when a top-level ``domains`` entry matched.
    """

    host: str
    path: str
    matched_entry: UrlPrefixEntry | None


@dataclass(frozen=True)
class FilterResult:
    """The outcome of running one filter against a request body.

    Construct via :meth:`passthrough`, :meth:`rewrite`, or
    :meth:`block` rather than instantiating directly — the constructors
    keep the field combinations valid (e.g. ``REWRITE`` always carries a
    ``body``).

    Attributes:
        action: What the pipeline should do.
        body: Re-serialised request body, set iff ``action`` is
            ``REWRITE``.
        error: Stable error code for the 403 JSON, set iff ``action`` is
            ``BLOCK``.
        message: Human-readable explanation for the 403 JSON.
        detail: Short tag describing the offending input; surfaced in
            the 403 JSON and (optionally) the log annotation.
        log_tag: Bracket-inner text for the network-log annotation. May
            be set on any action, including ``PASS`` (e.g. the GraphQL
            operation tag is logged even when the operation is allowed).
    """

    action: FilterAction
    body: bytes | None = None
    error: str | None = None
    message: str | None = None
    detail: str | None = None
    log_tag: str | None = None

    @classmethod
    def passthrough(cls, log_tag: str | None = None) -> FilterResult:
        """Forward the request unchanged, optionally logging ``log_tag``."""
        return cls(FilterAction.PASS, log_tag=log_tag)

    @classmethod
    def rewrite(cls, body: bytes, log_tag: str | None = None) -> FilterResult:
        """Forward the request with ``body`` swapped in."""
        return cls(FilterAction.REWRITE, body=body, log_tag=log_tag)

    @classmethod
    def block(
        cls,
        error: str,
        message: str,
        detail: str | None = None,
        log_tag: str | None = None,
    ) -> FilterResult:
        """Reject the request with a 403 carrying ``error`` / ``message``."""
        return cls(
            FilterAction.BLOCK,
            error=error,
            message=message,
            detail=detail,
            log_tag=log_tag,
        )


class RequestBodyFilter(Protocol):
    """A service-specific request-body filter.

    Implementations gate themselves via :meth:`matches` (on the request,
    not on shared proxy state) and inspect / rewrite / reject the body in
    :meth:`apply`. They must not mutate the flow directly — the pipeline
    owns translating the :class:`FilterResult` into proxy actions.
    """

    name: str
    """Log namespace, emitted as ``[{name}: {log_tag}]``."""

    def matches(self, req: FilterRequest) -> bool:
        """Return True if this filter should run for ``req``."""
        ...

    def apply(self, req: FilterRequest, body: bytes) -> FilterResult:
        """Inspect ``body`` and return the action the pipeline should take."""
        ...
