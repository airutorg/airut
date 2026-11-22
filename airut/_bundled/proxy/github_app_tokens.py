# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""GitHub App installation routing and token state for the proxy.

A GitHub App credential carries no installation ID.  The proxy discovers
the App's installations from its JWT, decides which of them the
credential may use, and sends each request with the token of the one
installation it targets:

- REST, git and raw-content requests by the account in the URL
  (:func:`request_owner`).
- GraphQL requests by repository scope (:func:`route_graphql`): the
  first installation whose repository set the request passes
  :func:`graphql_scope.check_repo_scope` for.

:class:`GitHubAppTokens` holds the per-proxy caches (installation lists
per credential, tokens per installation).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import unquote, urlsplit

from github_app import (
    CachedToken,
    Installation,
    fetch_app_installations,
    fetch_app_owner,
    fetch_installation_repos,
    fetch_installation_token,
    generate_jwt,
    is_token_valid,
)
from graphql_scope import ScopeResult, ScopeVerdict, check_repo_scope


# How long a discovered installation list is reused before the proxy asks
# GitHub again.  Matches the installation token lifetime, so an App
# installed on a new account mid-session is picked up within an hour.
_INSTALLATIONS_TTL_SECONDS = 3600

# Path segments followed by the target account on API-style paths
# (``/repos/{owner}/...``, ``/orgs/{org}/...``).
_OWNER_PREFIX_SEGMENTS = frozenset({"repos", "orgs"})

# GraphQL endpoint paths: ``/graphql`` (github.com), ``/api/graphql`` (GHES).
_GRAPHQL_PATHS = frozenset({"/graphql", "/api/graphql"})
_REPEATED_SLASHES = re.compile(r"/{2,}")

# Repository name in a ``repositories`` entry meaning "every repository
# of this account's installation" (``my-org/*``).
ALL_REPOSITORIES = "*"

# Scope result for a GraphQL request that passes against the union of the
# installations' repository sets but against no single one: it addresses
# repositories of several installations, which no one token can serve.
MULTI_INSTALLATION = ScopeResult(
    ScopeVerdict.OUT_OF_SCOPE, "<multi-installation>"
)


@dataclass(frozen=True)
class InstallationList:
    """Cached result of installation discovery for one credential."""

    installations: tuple[Installation, ...]
    fetched_at: float  # Unix timestamp


@dataclass(frozen=True)
class Candidate:
    """An installation a request may be sent with, and its token."""

    installation: Installation
    token: CachedToken
    cache_status: Literal["cached", "refreshed"]


def owner_installations(
    discovered: Sequence[Installation], app_owner: str
) -> tuple[Installation, ...]:
    """Pick the installations on the App owner's account (the default).

    Used when the credential has no ``repositories`` list.  A public App
    can be installed by anyone; trusting such third-party installations
    would hand the agent a working token for an attacker's account.

    Args:
        discovered: Installations returned by
            :func:`github_app.fetch_app_installations`.
        app_owner: Login of the account owning the App.

    Returns:
        The owner's installations (at most one in practice), with all
        their repositories.
    """
    owner_lower = app_owner.lower()
    return tuple(
        inst
        for inst in sorted(discovered, key=lambda inst: inst.id)
        if inst.account.lower() == owner_lower
    )


def listed_installations(
    discovered: Sequence[Installation], repositories: Sequence[str]
) -> tuple[Installation, ...]:
    """Pick the installations on the accounts ``repositories`` names.

    Each ``owner/name`` entry selects the installation on ``owner``
    (case-insensitive) and narrows its tokens to ``name``; ``owner/*``
    selects it with all its repositories.  Installations on accounts
    with no entry are dropped, so listing an account is how a
    credential opts into installations beyond the owner's.

    Args:
        discovered: Installations returned by
            :func:`github_app.fetch_app_installations`.
        repositories: Configured ``owner/name`` / ``owner/*`` entries.

    Returns:
        Selected installations sorted by installation ID, so the first
        entry is the stable default for requests that do not identify
        an account.
    """
    names_by_owner: dict[str, list[str]] = {}
    for full_name in repositories:
        owner, _, name = full_name.partition("/")
        names_by_owner.setdefault(owner.lower(), []).append(name)

    selected: list[Installation] = []
    for inst in sorted(discovered, key=lambda inst: inst.id):
        names = names_by_owner.get(inst.account.lower())
        if names is None:
            continue
        narrowed = None if ALL_REPOSITORIES in names else tuple(names)
        selected.append(Installation(inst.id, inst.account, narrowed))
    return tuple(selected)


def is_installation_list_fresh(cached: InstallationList | None) -> bool:
    """Check whether a cached installation list can be reused.

    Args:
        cached: Cached installation list, or None if none is cached.

    Returns:
        True if the list exists and is younger than the TTL.
    """
    if cached is None:
        return False
    return time.time() < cached.fetched_at + _INSTALLATIONS_TTL_SECONDS


def _api_location(base_url: str) -> tuple[str, bool]:
    """Return ``(api_host, is_ghes)`` for a credential's API base URL.

    github.com serves the API on a dedicated host (``api.github.com``);
    GHES serves it under ``/api/`` on the same host as git and the web
    UI, which shows as a path in ``base_url``
    (``https://ghe.example.com/api/v3``).
    """
    base = urlsplit(base_url)
    return (base.hostname or "").lower(), bool(base.path.strip("/"))


def is_graphql_path(path: str) -> bool:
    """Check whether a decoded request path is a GraphQL endpoint.

    ``/graphql`` (github.com) and ``/api/graphql`` (GHES), on any scoped
    host.  Repeated and trailing slashes are ignored.  Matching broadly
    is fail-secure: a non-GraphQL request misidentified as GraphQL is
    blocked by the scope check rather than forwarded unchecked.

    Args:
        path: Percent-decoded request path without the query string.

    Returns:
        True for a GraphQL endpoint.
    """
    normalized = _REPEATED_SLASHES.sub("/", path).rstrip("/")
    return normalized in _GRAPHQL_PATHS


def request_owner(host: str, path: str, base_url: str) -> str | None:
    """Extract the account a non-GraphQL GitHub request targets.

    Recognized shapes:

    - ``/repos/{owner}/...`` and ``/orgs/{org}/...`` on any host (REST
      API, ``uploads.github.com``, GHES ``/api/v3`` and
      ``/api/uploads``).
    - ``/{owner}/...`` on non-API hosts (git over HTTPS on
      ``github.com``, ``raw.githubusercontent.com``,
      ``codeload.github.com``, GHES git paths).

    Other paths on the API host (``/user``, ``/search/...``,
    ``/rate_limit``, ``/repositories/{id}``, …) are account-agnostic and
    return None.

    Routing only decides which installation's token is sent; GitHub
    enforces what that token can access, so a wrong guess fails at
    GitHub rather than widening access.

    Args:
        host: Request hostname.
        path: Request path (may include a query string).
        base_url: Credential's API base URL.

    Returns:
        The account login, or None when the request does not name one.
    """
    api_host, is_ghes = _api_location(base_url)
    segments = [
        unquote(segment)
        for segment in path.split("?", 1)[0].split("/")
        if segment
    ]

    is_api = False
    if host.lower() == api_host:
        if not is_ghes:
            is_api = True
        elif segments and segments[0] == "api":
            # Drop "api" and the API kind (v3, uploads, graphql).
            is_api = True
            segments = segments[2:]

    if len(segments) >= 2 and segments[0] in _OWNER_PREFIX_SEGMENTS:
        return segments[1]
    if is_api or not segments:
        return None
    return segments[0]


def choose_installation(
    installations: Sequence[Installation], owner: str | None
) -> Installation:
    """Pick the installation whose account matches ``owner``.

    Falls back to the first (lowest-ID) installation when ``owner`` is
    None or no installation is on that account — e.g. reading a public
    repository the App is not installed on.

    Args:
        installations: Non-empty usable installations, ordered by ID.
        owner: Target account login, or None.

    Returns:
        The selected installation.
    """
    if owner is not None:
        owner_lower = owner.lower()
        for inst in installations:
            if inst.account.lower() == owner_lower:
                return inst
    return installations[0]


def route_graphql(
    content: bytes, candidates: Sequence[Candidate]
) -> Candidate | ScopeResult:
    """Scope-check a GraphQL body and pick the installation to send it with.

    The body is checked against each candidate's repository set in order
    and routed to the first it passes for.  A request addressing no
    repository passes for all and so uses the first (default)
    installation; one addressing a repository passes only for the
    installation owning it.  The request is therefore only ever sent
    with a token whose own repository set it passed.

    If it passes for none, the check is re-run against the union of all
    sets to tell an out-of-scope repository apart from a request that
    spans several installations (:data:`MULTI_INSTALLATION`).

    Args:
        content: Raw GraphQL request body.
        candidates: Non-empty candidates, ordered by installation ID.

    Returns:
        The selected candidate, or the blocking scope result.
    """
    result = MULTI_INSTALLATION  # Overwritten: candidates is non-empty.
    for candidate in candidates:
        result = check_repo_scope(
            content,
            candidate.token.repo_node_ids,
            candidate.token.repo_full_names,
        )
        if result.verdict is ScopeVerdict.ALLOWED:
            return candidate
        if result.verdict is not ScopeVerdict.OUT_OF_SCOPE:
            # Not a repository mismatch (parse error, unresolved
            # variable, undecodable allowed set): block fail-secure
            # rather than trying the remaining installations.
            return result
    if len(candidates) == 1:
        return result

    union = check_repo_scope(
        content,
        frozenset(i for c in candidates for i in c.token.repo_node_ids),
        frozenset(n for c in candidates for n in c.token.repo_full_names),
    )
    return (
        MULTI_INSTALLATION if union.verdict is ScopeVerdict.ALLOWED else union
    )


class GitHubAppTokens:
    """Installation lists and tokens for the proxy's GitHub App credentials.

    Installation lists are cached per credential surrogate for
    ``_INSTALLATIONS_TTL_SECONDS``; tokens per (surrogate, installation
    ID) until near expiry.
    """

    def __init__(self, log: Callable[[str], None]) -> None:
        """Initialize empty caches.

        Args:
            log: Loud logger for non-fatal failures.
        """
        self._log = log
        self._installations: dict[str, InstallationList] = {}
        self._tokens: dict[tuple[str, int], CachedToken] = {}

    def candidates(
        self,
        surrogate: str,
        config: Mapping[str, object],
        host: str,
        path: str,
        *,
        graphql: bool,
    ) -> list[Candidate]:
        """Return tokens for the installations a request may use.

        For GraphQL this is every usable installation (routing needs all
        repository sets, see :func:`route_graphql`); otherwise the one
        installation on the account in the URL.

        Args:
            surrogate: Credential surrogate.
            config: The credential's replacement map entry.
            host: Request hostname.
            path: Request path.
            graphql: Whether the request is a GraphQL request.

        Returns:
            Non-empty candidates, ordered by installation ID.

        Raises:
            ValueError: If the App has no usable installation.
            Exception: Any JWT or GitHub API failure.  The cached
                installation list is dropped, so the next request
                rediscovers (the failure may come from an installation
                that has since been removed).
        """
        try:
            installations = self._installations_for(surrogate, config)
            if graphql:
                targets: Sequence[Installation] = installations
            else:
                owner = request_owner(host, path, str(config["base_url"]))
                targets = (choose_installation(installations, owner),)
            return [self._token(surrogate, config, inst) for inst in targets]
        except Exception:
            self._installations.pop(surrogate, None)
            raise

    def _installations_for(
        self, surrogate: str, config: Mapping[str, object]
    ) -> tuple[Installation, ...]:
        """Return the usable installations, discovering them if needed."""
        cached = self._installations.get(surrogate)
        if cached is not None and is_installation_list_fresh(cached):
            return cached.installations

        base_url = str(config["base_url"])
        jwt = generate_jwt(str(config["app_id"]), str(config["private_key"]))
        repositories = config.get("repositories")
        discovered = fetch_app_installations(base_url, jwt)
        if isinstance(repositories, list):
            installations = listed_installations(
                discovered, [str(r) for r in repositories]
            )
        else:
            installations = owner_installations(
                discovered, fetch_app_owner(base_url, jwt)
            )
        if not installations:
            raise ValueError(
                "GitHub App has no usable installation (not installed on "
                "the App owner's account or on an account listed in "
                "repositories, or suspended)"
            )
        self._installations[surrogate] = InstallationList(
            installations=installations, fetched_at=time.time()
        )
        return installations

    def _token(
        self,
        surrogate: str,
        config: Mapping[str, object],
        inst: Installation,
    ) -> Candidate:
        """Return a valid token for one installation, refreshing if needed."""
        key = (surrogate, inst.id)
        cached = self._tokens.get(key)
        if cached is not None and is_token_valid(cached):
            return Candidate(inst, cached, "cached")

        base_url = str(config["base_url"])
        permissions = config.get("permissions")
        repositories = (
            list(inst.repositories) if inst.repositories is not None else None
        )
        jwt = generate_jwt(str(config["app_id"]), str(config["private_key"]))
        token, expires_at = fetch_installation_token(
            base_url,
            inst.id,
            jwt,
            permissions={str(k): str(v) for k, v in permissions.items()}
            if isinstance(permissions, dict) and permissions
            else None,
            repositories=repositories,
        )
        # Resolve repo node IDs and full names for GraphQL scoping.
        try:
            repo_node_ids, repo_full_names = fetch_installation_repos(
                base_url, token, configured_repos=repositories
            )
        except Exception as e:
            self._log(
                f"GitHub App repo node ID resolution failed for "
                f"installation {inst.id} ({inst.account}): {e}"
            )
            repo_node_ids = frozenset()
            repo_full_names = frozenset()
        entry = CachedToken(
            token=token,
            expires_at=expires_at,
            repo_node_ids=repo_node_ids,
            repo_full_names=repo_full_names,
        )
        self._tokens[key] = entry
        return Candidate(inst, entry, "refreshed")
