# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for SlackAuthorizer."""

from unittest.mock import MagicMock

import pytest

from airut.gateway.slack.authorizer import (
    AuthorizationError,
    SlackAuthorizer,
)


def _make_user_info(
    *,
    user_id: str = "U12345678",
    is_bot: bool = False,
    is_restricted: bool = False,
    is_ultra_restricted: bool = False,
    team_id: str = "T000001",
    deleted: bool = False,
    display_name: str = "Test User",
    real_name: str = "Test User",
) -> dict:
    return {
        "user": {
            "id": user_id,
            "is_bot": is_bot,
            "is_restricted": is_restricted,
            "is_ultra_restricted": is_ultra_restricted,
            "team_id": team_id,
            "deleted": deleted,
            "profile": {
                "display_name": display_name,
                "real_name": real_name,
            },
        }
    }


def _make_client(
    user_info: dict | None = None,
    team_id: str = "T000001",
) -> MagicMock:
    client = MagicMock()
    client.users_info.return_value = user_info or _make_user_info()
    client.auth_test.return_value = {"team_id": team_id}
    return client


class TestWorkspaceMembersRule:
    def test_allows_full_member(self) -> None:
        client = _make_client()
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        info = authorizer.authorize("U12345678")
        assert info.user_id == "U12345678"
        assert info.display_name == "Test User"

    def test_rejects_guest(self) -> None:
        client = _make_client(user_info=_make_user_info(is_restricted=True))
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="no authorization rule"):
            authorizer.authorize("U12345678")

    def test_rejects_ultra_restricted(self) -> None:
        client = _make_client(
            user_info=_make_user_info(is_ultra_restricted=True)
        )
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="no authorization rule"):
            authorizer.authorize("U12345678")


class TestUserIdRule:
    def test_allows_matching_user(self) -> None:
        client = _make_client()
        authorizer = SlackAuthorizer(
            rules=[{"user_id": "U12345678"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        info = authorizer.authorize("U12345678")
        assert info.user_id == "U12345678"

    def test_rejects_non_matching_user(self) -> None:
        client = _make_client()
        authorizer = SlackAuthorizer(
            rules=[{"user_id": "U99999999"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="no authorization rule"):
            authorizer.authorize("U12345678")


class TestUserGroupRule:
    def test_allows_group_member(self) -> None:
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [
                {"id": "G001", "handle": "engineering"},
            ]
        }
        client.usergroups_users_list.return_value = {
            "users": ["U12345678", "U87654321"]
        }
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "engineering"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        info = authorizer.authorize("U12345678")
        assert info.user_id == "U12345678"

    def test_rejects_non_member(self) -> None:
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [
                {"id": "G001", "handle": "engineering"},
            ]
        }
        client.usergroups_users_list.return_value = {"users": ["U87654321"]}
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "engineering"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="no authorization rule"):
            authorizer.authorize("U12345678")

    def test_handles_missing_group(self) -> None:
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [
                {"id": "G001", "handle": "other"},
            ]
        }
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "engineering"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="no authorization rule"):
            authorizer.authorize("U12345678")


class TestBaselineChecks:
    def test_rejects_bot(self) -> None:
        client = _make_client(user_info=_make_user_info(is_bot=True))
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="bot users"):
            authorizer.authorize("U12345678")

    def test_rejects_deactivated(self) -> None:
        client = _make_client(user_info=_make_user_info(deleted=True))
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="deactivated"):
            authorizer.authorize("U12345678")

    def test_rejects_external_user(self) -> None:
        client = _make_client(user_info=_make_user_info(team_id="T_DIFFERENT"))
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError, match="external user"):
            authorizer.authorize("U12345678")


class TestMultipleRules:
    def test_first_match_wins(self) -> None:
        """User in group matches even if user_id rule doesn't."""
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"id": "G001", "handle": "eng"}]
        }
        client.usergroups_users_list.return_value = {"users": ["U12345678"]}
        authorizer = SlackAuthorizer(
            rules=[
                {"user_group": "eng"},
                {"user_id": "U99999999"},
            ],
            bot_client=client,
            workspace_team_id="T000001",
        )
        info = authorizer.authorize("U12345678")
        assert info.user_id == "U12345678"

    def test_fallback_to_user_id(self) -> None:
        """User not in group but matches user_id rule."""
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"id": "G001", "handle": "eng"}]
        }
        client.usergroups_users_list.return_value = {"users": ["U87654321"]}
        authorizer = SlackAuthorizer(
            rules=[
                {"user_group": "eng"},
                {"user_id": "U12345678"},
            ],
            bot_client=client,
            workspace_team_id="T000001",
        )
        info = authorizer.authorize("U12345678")
        assert info.user_id == "U12345678"


class TestCaching:
    def test_user_info_cached(self) -> None:
        client = _make_client()
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        authorizer.authorize("U12345678")
        authorizer.authorize("U12345678")

        # Only one API call despite two authorize calls
        assert client.users_info.call_count == 1

    def test_group_ids_resolved_once(self) -> None:
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"id": "G001", "handle": "eng"}]
        }
        client.usergroups_users_list.return_value = {"users": ["U12345678"]}
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "eng"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        authorizer.authorize("U12345678")
        authorizer.authorize("U12345678")

        # Group list resolved only once
        assert client.usergroups_list.call_count == 1


class TestTeamIdResolution:
    def test_resolves_team_id_lazily(self) -> None:
        client = _make_client()
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id=None,
        )
        authorizer.authorize("U12345678")
        client.auth_test.assert_called_once()

    def test_team_id_provided_skips_api_call(self) -> None:
        client = _make_client()
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        authorizer.authorize("U12345678")
        client.auth_test.assert_not_called()


class TestGroupResolution:
    def test_resolve_group_ids_called_once(self) -> None:
        """_resolve_group_ids is idempotent."""
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"id": "G001", "handle": "eng"}]
        }
        client.usergroups_users_list.return_value = {"users": ["U12345678"]}
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "eng"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        # First authorize resolves groups
        authorizer.authorize("U12345678")
        # Authorize a different user — groups should not be re-resolved
        client2_info = _make_user_info(user_id="U87654321")
        client.users_info.return_value = client2_info
        authorizer._user_cache.clear()
        with pytest.raises(AuthorizationError):
            authorizer.authorize("U87654321")

        # usergroups_list called only once
        assert client.usergroups_list.call_count == 1

    def test_no_groups_in_rules_skips_resolution(self) -> None:
        """If no user_group rules, _resolve_group_ids returns early."""
        client = _make_client()
        authorizer = SlackAuthorizer(
            rules=[{"workspace_members": True}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        # Directly invoke to cover the early-return path
        authorizer._resolve_group_ids()
        client.usergroups_list.assert_not_called()

    def test_unresolved_group_handle_logged(self) -> None:
        """Warns when configured group handle not found in workspace."""
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"id": "G001", "handle": "other_group"}]
        }
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "missing_group"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError):
            authorizer.authorize("U12345678")

    def test_usergroups_list_failure_handled(self) -> None:
        """API failure in usergroups_list is handled gracefully."""
        client = _make_client()
        client.usergroups_list.side_effect = Exception("API error")
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "eng"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        with pytest.raises(AuthorizationError):
            authorizer.authorize("U12345678")

    def test_get_group_members_returns_stale_on_failure(self) -> None:
        """Returns stale cache when usergroups.users.list fails."""
        client = _make_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"id": "G001", "handle": "eng"}]
        }
        # First call succeeds
        client.usergroups_users_list.return_value = {"users": ["U12345678"]}
        authorizer = SlackAuthorizer(
            rules=[{"user_group": "eng"}],
            bot_client=client,
            workspace_team_id="T000001",
        )
        info = authorizer.authorize("U12345678")
        assert info.user_id == "U12345678"

        # Expire the group cache and user cache
        authorizer._group_cache_fetched_at["eng"] = 0
        authorizer._user_cache.clear()

        # Second call fails — should return stale cache
        client.usergroups_users_list.side_effect = Exception("API error")
        info2 = authorizer.authorize("U12345678")
        assert info2.user_id == "U12345678"


class TestAuthorizationError:
    def test_error_attributes(self) -> None:
        err = AuthorizationError(
            user_id="U123",
            display_name="Bob",
            reason="not allowed",
        )
        assert err.user_id == "U123"
        assert err.display_name == "Bob"
        assert err.reason == "not allowed"
        assert str(err) == "not allowed"

    def test_default_message(self) -> None:
        err = AuthorizationError(user_id="U123")
        assert str(err) == "authorization failed"
