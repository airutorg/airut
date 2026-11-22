# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for GitHub App installation routing and token state."""

import json
import time
from unittest.mock import MagicMock, patch

# Bare imports, as inside the proxy container: the module under test
# imports its siblings by bare name, so dataclass identity (and equality)
# only holds for classes imported the same way.
import github_app_tokens  # ty:ignore[import-not-found]
import pytest
from github_app import (  # ty:ignore[import-not-found]
    CachedToken,
    Installation,
)
from github_app_tokens import (  # ty:ignore[import-not-found]
    _INSTALLATIONS_TTL_SECONDS,
    MULTI_INSTALLATION,
    Candidate,
    GitHubAppTokens,
    InstallationList,
    choose_installation,
    is_graphql_path,
    is_installation_list_fresh,
    listed_installations,
    owner_installations,
    request_owner,
    route_graphql,
)
from graphql_scope import ScopeVerdict  # ty:ignore[import-not-found]


_DISCOVERED = (
    Installation(30, "orgC"),
    Installation(10, "orgA"),
    Installation(20, "orgB"),
)


class TestOwnerInstallations:
    """Tests for owner_installations function."""

    def test_owner_account_only(self) -> None:
        """Only the App owner's installation is used, case-insensitively."""
        assert owner_installations(_DISCOVERED, "ORGB") == (
            Installation(20, "orgB"),
        )

    def test_owner_not_installed(self) -> None:
        """No installation is usable when the owner has none."""
        assert owner_installations(_DISCOVERED, "other") == ()


class TestListedInstallations:
    """Tests for listed_installations function."""

    def test_filters_and_narrows(self) -> None:
        """Entries pick accounts (case-insensitive) and bare names."""
        result = listed_installations(
            _DISCOVERED, ["ORGC/one", "orgA/two", "orgc/three"]
        )
        # Sorted by ID; orgB is not listed, so it is dropped.
        assert result == (
            Installation(10, "orgA", ("two",)),
            Installation(30, "orgC", ("one", "three")),
        )

    def test_wildcard_keeps_all_repositories(self) -> None:
        """``owner/*`` selects the installation without narrowing."""
        result = listed_installations(
            _DISCOVERED, ["orgA/*", "orgA/two", "orgB/x"]
        )
        assert result == (
            Installation(10, "orgA", None),
            Installation(20, "orgB", ("x",)),
        )

    def test_matching_nothing(self) -> None:
        """No installation is usable when no listed owner is installed."""
        assert listed_installations(_DISCOVERED, ["x/y"]) == ()


class TestIsInstallationListFresh:
    """Tests for is_installation_list_fresh function."""

    def test_none_is_stale(self) -> None:
        assert is_installation_list_fresh(None) is False

    def test_recent_is_fresh(self) -> None:
        cached = InstallationList((), fetched_at=time.time())
        assert is_installation_list_fresh(cached) is True

    def test_past_ttl_is_stale(self) -> None:
        cached = InstallationList(
            (), fetched_at=time.time() - _INSTALLATIONS_TTL_SECONDS - 1
        )
        assert is_installation_list_fresh(cached) is False


class TestIsGraphqlPath:
    """Tests for is_graphql_path function."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/graphql", True),
            ("/api/graphql", True),
            # Slash variants are normalized so they cannot skip the check.
            ("/graphql/", True),
            ("//graphql", True),
            ("//api//graphql/", True),
            ("/graphql/x", False),
            ("/api/v3/graphql", False),
            ("/", False),
        ],
    )
    def test_paths(self, path: str, expected: bool) -> None:
        assert is_graphql_path(path) is expected


class TestRequestOwner:
    """Tests for request_owner function."""

    @pytest.mark.parametrize(
        ("host", "path", "expected"),
        [
            # REST API on the dedicated API host
            ("api.github.com", "/repos/orgA/app/pulls?x=1", "orgA"),
            ("api.github.com", "/orgs/orgA/members", "orgA"),
            ("api.github.com", "/repos/org%41/app", "orgA"),
            ("api.github.com", "/repos", None),
            ("api.github.com", "/user", None),
            ("api.github.com", "/search/issues?q=x", None),
            ("api.github.com", "/repositories/123", None),
            ("api.github.com", "/", None),
            ("API.GITHUB.COM", "/rate_limit", None),
            # Upload host uses the REST shape
            ("uploads.github.com", "/repos/orgA/app/releases/1", "orgA"),
            # Git, raw and codeload hosts lead with the owner
            ("github.com", "/orgA/app.git/info/refs", "orgA"),
            ("raw.githubusercontent.com", "/orgA/app/main/f", "orgA"),
            ("codeload.github.com", "/orgA/app/tar.gz/main", "orgA"),
            ("github.com", "/", None),
        ],
    )
    def test_github_com(
        self, host: str, path: str, expected: str | None
    ) -> None:
        assert request_owner(host, path, "https://api.github.com") == expected

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/api/v3/repos/orgA/app", "orgA"),
            ("/api/v3/orgs/orgA", "orgA"),
            ("/api/uploads/repos/orgA/app/releases/1/assets", "orgA"),
            ("/api/v3/user", None),
            # Git paths share the GHES host with the API
            ("/orgA/app.git/git-receive-pack", "orgA"),
        ],
    )
    def test_ghes(self, path: str, expected: str | None) -> None:
        base_url = "https://ghe.example.com/api/v3"
        assert request_owner("ghe.example.com", path, base_url) == expected


class TestChooseInstallation:
    """Tests for choose_installation function."""

    _INSTALLATIONS = (Installation(1, "orgA"), Installation(2, "orgB"))

    def test_matches_owner_case_insensitively(self) -> None:
        assert choose_installation(self._INSTALLATIONS, "ORGB").id == 2

    def test_unknown_owner_uses_first(self) -> None:
        assert choose_installation(self._INSTALLATIONS, "other").id == 1

    def test_no_owner_uses_first(self) -> None:
        assert choose_installation(self._INSTALLATIONS, None).id == 1


def _candidate(
    installation_id: int, account: str, node_id: str, full_name: str
) -> Candidate:
    token = CachedToken(
        token=f"ghs_{installation_id}",
        expires_at=time.time() + 3600,
        repo_node_ids=frozenset({node_id}),
        repo_full_names=frozenset({full_name}),
    )
    return Candidate(Installation(installation_id, account), token, "cached")


def _body(query: str) -> bytes:
    return json.dumps({"query": query}).encode()


class TestRouteGraphql:
    """Tests for route_graphql function."""

    _A = _candidate(1, "orgA", "R_kgDORH34qw", "orgA/app")
    _B = _candidate(2, "orgB", "R_kgDORm2NDQ", "orgB/lib")

    def test_routes_to_owning_installation(self) -> None:
        body = _body('query { repository(owner: "orgB", name: "lib") { id } }')
        assert route_graphql(body, [self._A, self._B]) is self._B

    def test_no_repository_uses_first(self) -> None:
        body = _body("query { viewer { login } }")
        assert route_graphql(body, [self._A, self._B]) is self._A

    def test_spanning_installations(self) -> None:
        body = _body(
            "query {"
            ' a: repository(owner: "orgA", name: "app") { id }'
            ' b: repository(owner: "orgB", name: "lib") { id }'
            "}"
        )
        assert route_graphql(body, [self._A, self._B]) == MULTI_INSTALLATION

    def test_out_of_scope_reports_union_detail(self) -> None:
        body = _body(
            "query {"
            ' a: repository(owner: "orgA", name: "app") { id }'
            ' b: repository(owner: "evil", name: "x") { id }'
            "}"
        )
        result = route_graphql(body, [self._A, self._B])
        assert result.verdict is ScopeVerdict.OUT_OF_SCOPE
        assert result.detail == "evil/x"

    def test_single_candidate_reports_its_result(self) -> None:
        body = _body('query { repository(owner: "orgB", name: "lib") { id } }')
        result = route_graphql(body, [self._A])
        assert result.detail == "orgB/lib"

    def test_unparseable_body_stops_early(self) -> None:
        """A body-level failure is reported without checking others."""
        with patch(
            "github_app_tokens.check_repo_scope",
            wraps=github_app_tokens.check_repo_scope,
        ) as check:
            result = route_graphql(b"not json", [self._A, self._B])
        assert result.verdict is ScopeVerdict.PARSE_ERROR
        check.assert_called_once()


class TestGitHubAppTokens:
    """Tests for GitHubAppTokens failure handling."""

    _CONFIG = {
        "app_id": "Iv23li",
        "private_key": "key",
        "base_url": "https://api.github.com",
    }

    def test_failure_drops_cached_installation_list(self) -> None:
        """A token failure forces rediscovery on the next request.

        The failing installation may have been removed; a stale list
        would otherwise keep failing until its TTL ran out.
        """
        tokens = GitHubAppTokens(MagicMock())
        tokens._installations["s"] = InstallationList(
            (Installation(1, "orgA"),), fetched_at=time.time()
        )
        with (
            patch("github_app_tokens.generate_jwt", return_value="jwt"),
            patch(
                "github_app_tokens.fetch_installation_token",
                side_effect=OSError("gone"),
            ),
            pytest.raises(OSError, match="gone"),
        ):
            tokens.candidates(
                "s", self._CONFIG, "api.github.com", "/user", graphql=False
            )
        assert "s" not in tokens._installations
