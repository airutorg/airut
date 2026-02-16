# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Typed network allowlist with YAML parsing and JSON serialization.

Provides typed representations of the network allowlist, decoupled from
the YAML configuration format.  The host-side code reads YAML from the
git mirror and calls ``parse_allowlist_yaml()``.  The proxy container
reads JSON via ``_load_allowlist()`` after the host serializes the
allowlist with ``serialize_allowlist_json()``.

This module is the single source of truth for allowlist parsing and
serialization.  The proxy container does not depend on PyYAML.
"""

import json
from dataclasses import dataclass

import yaml


@dataclass(frozen=True)
class AllowlistDomain:
    """A domain allowed for all paths and methods.

    Supports fnmatch wildcards (e.g., ``*.github.com``).
    """

    host: str


@dataclass(frozen=True)
class AllowlistUrlPattern:
    """A URL pattern with optional path and method restrictions.

    Host and path support fnmatch wildcards.
    Empty path means all paths.  Empty methods means all methods.
    """

    host: str
    path: str = ""
    methods: tuple[str, ...] = ()


@dataclass(frozen=True)
class Allowlist:
    """Network allowlist defining which hosts/paths/methods are reachable."""

    domains: tuple[AllowlistDomain, ...]
    url_patterns: tuple[AllowlistUrlPattern, ...]


def parse_allowlist_yaml(data: bytes) -> Allowlist:
    """Parse ``.airut/network-allowlist.yaml`` into a typed ``Allowlist``.

    Args:
        data: Raw YAML bytes from the git mirror.

    Returns:
        Parsed ``Allowlist``.

    Raises:
        ValueError: If the YAML is invalid or missing required fields.
    """
    try:
        config = yaml.safe_load(data)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid allowlist YAML: {e}") from e

    if config is None:
        config = {}

    raw_domains = config.get("domains", [])
    raw_prefixes = config.get("url_prefixes", [])

    domains = tuple(AllowlistDomain(host=d) for d in raw_domains)

    url_patterns: list[AllowlistUrlPattern] = []
    for entry in raw_prefixes:
        methods_raw = entry.get("methods", [])
        url_patterns.append(
            AllowlistUrlPattern(
                host=entry.get("host", ""),
                path=entry.get("path", ""),
                methods=tuple(methods_raw),
            )
        )

    return Allowlist(domains=domains, url_patterns=tuple(url_patterns))


def serialize_allowlist_json(allowlist: Allowlist) -> bytes:
    """Serialize ``Allowlist`` to JSON for proxy consumption.

    The JSON format mirrors the YAML structure so the proxy filter
    can use the same field names:

    .. code-block:: json

        {
            "domains": ["api.anthropic.com"],
            "url_prefixes": [
                {"host": "pypi.org", "path": "", "methods": ["GET", "HEAD"]}
            ]
        }

    Args:
        allowlist: Typed allowlist to serialize.

    Returns:
        JSON bytes.
    """
    data = {
        "domains": [d.host for d in allowlist.domains],
        "url_prefixes": [
            {
                "host": p.host,
                "path": p.path,
                "methods": list(p.methods),
            }
            for p in allowlist.url_patterns
        ],
    }
    return json.dumps(data).encode()
