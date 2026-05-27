# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackAuthorizer."""

from unittest.mock import MagicMock

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from airut.gateway.slack.authorizer import SlackAuthorizer


def _mock_client() -> MagicMock:
    """Create a mock WebClient."""
    return MagicMock(spec=WebClient)


def _user_info_response(
    *,
    user_id: str = "U123",
    team_id: str = "T001",
    is_bot: bool = False,
    is_restricted: bool = False,
    is_ultra_restricted: bool = False,
    deleted: bool = False,
    display_name: str = "Test User",
) -> dict:
    return {
        "user": {
            "id": user_id,
            "team_id": team_id,
            "is_bot": is_bot,
            "is_restricted": is_restricted,
            "is_ultra_restricted": is_ultra_restricted,
            "deleted": deleted,
            "name": "testuser",
            "profile": {
                "display_name": display_name,
                "real_name": "Test User Real",
            },
        }
    }


class TestBaselineChecks:
    def test_rejects_bot_users(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response(is_bot=True)
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized
        assert "bot" in reason

    def test_rejects_deactivated_users(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response(deleted=True)
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized
        assert "deactivated" in reason

    def test_rejects_external_users(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response(team_id="T999")
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized
        assert "external" in reason

    def test_rejects_on_user_info_failure(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = SlackApiError(
            message="error", response=MagicMock(status_code=500, data={})
        )

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized
        assert "failed to fetch" in reason


class TestWorkspaceMembersRule:
    def test_allows_full_members(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert authorized
        assert reason == ""

    def test_rejects_multi_channel_guests(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response(is_restricted=True)
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized
        assert "no authorization rule matched" in reason

    def test_rejects_single_channel_guests(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response(
            is_ultra_restricted=True
        )
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized


class TestUserIdRule:
    def test_allows_matching_user(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_id": "U123"}],
        )
        authorized, _ = authorizer.authorize("U123")
        assert authorized

    def test_rejects_non_matching_user(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_id": "U999"}],
        )
        authorized, _ = authorizer.authorize("U123")
        assert not authorized


class TestUserGroupRule:
    def test_allows_group_member(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "engineering", "id": "G001"}]
        }
        client.usergroups_users_list.return_value = {"users": ["U123", "U456"]}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_group": "engineering"}],
        )
        authorized, _ = authorizer.authorize("U123")
        assert authorized

    def test_rejects_non_member(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "engineering", "id": "G001"}]
        }
        client.usergroups_users_list.return_value = {"users": ["U456"]}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_group": "engineering"}],
        )
        authorized, _ = authorizer.authorize("U123")
        assert not authorized

    def test_unknown_group_rejects(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.return_value = {"usergroups": []}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_group": "nonexistent"}],
        )
        authorized, _ = authorizer.authorize("U123")
        assert not authorized


class TestGroupCacheNotFound:
    def test_cached_group_not_found_rejects(self) -> None:
        """When group IDs are cached but handle is not among them."""
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "design", "id": "G002"}]
        }

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_group": "engineering"}],
        )
        # First call populates the group IDs cache
        authorized, _ = authorizer.authorize("U123")
        assert not authorized

        # Second call hits the cached path (group IDs already loaded)
        authorized2, _ = authorizer.authorize("U123")
        assert not authorized2
        # usergroups.list should only be called once (cached)
        assert client.usergroups_list.call_count == 1


class TestRuleOrder:
    def test_first_match_wins(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[
                {"user_id": "U999"},  # No match
                {"user_id": "U123"},  # Match
            ],
        )
        authorized, _ = authorizer.authorize("U123")
        assert authorized

    def test_no_rules_match_rejects(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_id": "U999"}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized
        assert "no authorization rule matched" in reason


class TestCaching:
    def test_group_members_cached(self) -> None:
        """Repeated authorize hits group member cache."""
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "eng", "id": "G001"}]
        }
        client.usergroups_users_list.return_value = {"users": ["U123"]}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_group": "eng"}],
        )
        authorizer.authorize("U123")
        authorizer.authorize("U123")  # hits cache

        # Only called once (cache hit on second call)
        assert client.usergroups_users_list.call_count == 1

    def test_user_info_cached(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorizer.authorize("U123")
        authorizer.authorize("U123")

        assert client.users_info.call_count == 1

    def test_workspace_team_id_cached(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorizer.authorize("U123")
        authorizer.authorize("U456")

        assert client.auth_test.call_count == 1

    def test_provided_team_id_skips_api_call(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
            workspace_team_id="T001",
        )
        authorizer.authorize("U123")
        client.auth_test.assert_not_called()


class TestDisplayName:
    def test_returns_display_name(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response(
            display_name="Alice"
        )
        client.auth_test.return_value = {"team_id": "T001"}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorizer.authorize("U123")
        assert authorizer.get_display_name("U123") == "Alice"

    def test_returns_user_id_when_not_cached(self) -> None:
        client = _mock_client()
        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        assert authorizer.get_display_name("U123") == "U123"

    def test_group_stale_cache_fallback(self) -> None:
        """When group API fails after initial load, stale cache is used."""
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "eng", "id": "G001"}]
        }
        # First call succeeds
        client.usergroups_users_list.return_value = {"users": ["U123"]}

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_group": "eng"}],
        )
        authorized, _ = authorizer.authorize("U123")
        assert authorized

        # Expire the cache by manipulating internal state
        for entry in authorizer._group_cache.values():
            entry.expires_at = 0

        # Second call fails — should use stale cache
        client.usergroups_users_list.side_effect = SlackApiError(
            message="rate_limited",
            response=MagicMock(status_code=429, data={}),
        )
        authorized2, _ = authorizer.authorize("U123")
        assert authorized2


class TestAuthTestFailure:
    def test_auth_test_failure_rejects_fail_closed(self) -> None:
        """When auth.test fails, authorization is denied (fail-closed)."""
        client = _mock_client()
        client.users_info.return_value = _user_info_response(team_id="T999")
        client.auth_test.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"workspace_members": True}],
        )
        authorized, reason = authorizer.authorize("U123")
        assert not authorized
        assert "auth.test failed" in reason


class TestUsergroupsListFailure:
    def test_usergroups_list_failure_rejects(self) -> None:
        """When usergroups.list fails, group rule rejects."""
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.side_effect = SlackApiError(
            message="error",
            response=MagicMock(status_code=500, data={}),
        )

        authorizer = SlackAuthorizer(
            client=client,
            rules=[{"user_group": "engineering"}],
        )
        authorized, _ = authorizer.authorize("U123")
        assert not authorized


class TestGetUserInfo:
    def test_returns_full_user_info(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response(
            display_name="Alice"
        )

        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        info = authorizer.get_user_info("U123")
        assert info is not None
        assert info.display_name == "Alice"
        assert info.real_name == "Test User Real"
        assert info.name == "testuser"

    def test_returns_none_on_failure(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = SlackApiError(
            message="error", response=MagicMock(status_code=500, data={})
        )

        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        assert authorizer.get_user_info("U123") is None

    def test_real_name_falls_back_to_user_real_name(self) -> None:
        """real_name uses top-level user.real_name when profile lacks it."""
        client = _mock_client()
        client.users_info.return_value = {
            "user": {
                "id": "U123",
                "team_id": "T001",
                "name": "handle",
                "real_name": "Top Level",
                "profile": {"display_name": ""},
            }
        }

        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        info = authorizer.get_user_info("U123")
        assert info is not None
        assert info.real_name == "Top Level"
        # display_name falls back to real_name when profile name is empty
        assert info.display_name == "Top Level"
        assert info.name == "handle"


class TestLookupGroupId:
    def test_resolves_handle(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "eng", "id": "G001"}]
        }

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.lookup_group_id("eng") == "G001"

    def test_unknown_handle_returns_none(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {"usergroups": []}

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.lookup_group_id("eng") is None

    def test_caches_after_first_lookup(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "eng", "id": "G001"}]
        }

        authorizer = SlackAuthorizer(client=client, rules=[])
        authorizer.lookup_group_id("eng")
        authorizer.lookup_group_id("other")
        assert client.usergroups_list.call_count == 1

    def test_api_failure_returns_none(self) -> None:
        client = _mock_client()
        client.usergroups_list.side_effect = SlackApiError(
            message="error", response=MagicMock(status_code=500, data={})
        )

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.lookup_group_id("eng") is None


class TestResolveChannelId:
    def test_resolves_name(self) -> None:
        client = _mock_client()
        client.conversations_list.return_value = {
            "channels": [
                {"name": "general", "id": "C1"},
                {"name": "random", "id": "C2"},
            ]
        }

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.resolve_channel_id("general") == "C1"
        assert authorizer.resolve_channel_id("random") == "C2"
        # Second batch of lookups served from cache.
        assert client.conversations_list.call_count == 1

    def test_unknown_name_returns_none(self) -> None:
        client = _mock_client()
        client.conversations_list.return_value = {
            "channels": [{"name": "general", "id": "C1"}]
        }

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.resolve_channel_id("nope") is None

    def test_paginates(self) -> None:
        client = _mock_client()
        client.conversations_list.side_effect = [
            {
                "channels": [{"name": "general", "id": "C1"}],
                "response_metadata": {"next_cursor": "page2"},
            },
            {"channels": [{"name": "eng", "id": "C9"}]},
        ]

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.resolve_channel_id("eng") == "C9"
        assert client.conversations_list.call_count == 2

    def test_skips_malformed_channels(self) -> None:
        client = _mock_client()
        client.conversations_list.return_value = {
            "channels": [
                {"name": "general"},  # missing id
                {"id": "C2"},  # missing name
                {"name": "ok", "id": "C3"},
            ]
        }

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.resolve_channel_id("general") is None
        assert authorizer.resolve_channel_id("ok") == "C3"

    def test_api_failure_returns_none(self) -> None:
        client = _mock_client()
        client.conversations_list.side_effect = SlackApiError(
            message="error", response=MagicMock(status_code=500, data={})
        )

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.resolve_channel_id("general") is None

    def test_cache_expiry_refetches(self) -> None:
        client = _mock_client()
        client.conversations_list.return_value = {
            "channels": [{"name": "general", "id": "C1"}]
        }

        authorizer = SlackAuthorizer(client=client, rules=[])
        assert authorizer.resolve_channel_id("general") == "C1"

        # Expire the channel cache to force a refetch.
        assert authorizer._channel_ids is not None
        authorizer._channel_ids.expires_at = 0
        assert authorizer.resolve_channel_id("general") == "C1"
        assert client.conversations_list.call_count == 2


class TestBotUserId:
    def test_resolves_from_auth_test(self) -> None:
        client = _mock_client()
        client.auth_test.return_value = {
            "team_id": "T001",
            "user_id": "UBOT",
        }
        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        assert authorizer.get_bot_user_id() == "UBOT"

    def test_shares_single_auth_test_with_team_id(self) -> None:
        client = _mock_client()
        client.users_info.return_value = _user_info_response()
        client.auth_test.return_value = {
            "team_id": "T001",
            "user_id": "UBOT",
        }
        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        authorizer.authorize("U123")
        assert authorizer.get_bot_user_id() == "UBOT"
        # One auth.test call serves both team-ID and bot-ID resolution.
        assert client.auth_test.call_count == 1

    def test_none_when_auth_test_fails(self) -> None:
        client = _mock_client()
        client.auth_test.side_effect = SlackApiError(
            message="error", response=MagicMock(status_code=500, data={})
        )
        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        assert authorizer.get_bot_user_id() is None

    def test_none_when_user_id_absent(self) -> None:
        client = _mock_client()
        client.auth_test.return_value = {"team_id": "T001"}
        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        assert authorizer.get_bot_user_id() is None


class TestCandidateGroupMembers:
    def test_unions_configured_group_members(self) -> None:
        client = _mock_client()
        client.auth_test.return_value = {"team_id": "T001"}
        client.usergroups_list.return_value = {
            "usergroups": [
                {"handle": "engineering", "id": "G001"},
                {"handle": "design", "id": "G002"},
            ]
        }
        client.usergroups_users_list.side_effect = lambda usergroup: {
            "G001": {"users": ["U1", "U2"]},
            "G002": {"users": ["U2", "U3"]},
        }[usergroup]

        authorizer = SlackAuthorizer(
            client=client,
            rules=[
                {"user_group": "engineering"},
                {"user_group": "design"},
            ],
        )
        assert authorizer.candidate_group_member_ids() == {"U1", "U2", "U3"}

    def test_empty_when_no_group_rules(self) -> None:
        client = _mock_client()
        authorizer = SlackAuthorizer(
            client=client, rules=[{"workspace_members": True}]
        )
        assert authorizer.candidate_group_member_ids() == set()

    def test_skips_unresolvable_group(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {"usergroups": []}
        authorizer = SlackAuthorizer(
            client=client, rules=[{"user_group": "ghost"}]
        )
        assert authorizer.candidate_group_member_ids() == set()
