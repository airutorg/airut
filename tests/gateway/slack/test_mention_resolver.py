# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for MentionResolver."""

from unittest.mock import MagicMock

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from airut.gateway.slack.authorizer import SlackAuthorizer, UserInfo
from airut.gateway.slack.mention_resolver import MentionResolver


def _mock_client() -> MagicMock:
    return MagicMock(spec=WebClient)


def _user(
    user_id: str,
    *,
    display_name: str = "",
    real_name: str = "",
    name: str = "",
    is_bot: bool = False,
) -> UserInfo:
    return UserInfo(
        user_id=user_id,
        team_id="T001",
        is_bot=is_bot,
        is_restricted=False,
        is_ultra_restricted=False,
        deleted=False,
        display_name=display_name,
        real_name=real_name,
        name=name,
    )


def _users_info_side_effect(directory: dict[str, str]):
    """Return a users_info stub resolving ``user`` to a display name."""

    def _side_effect(*, user: str) -> dict:
        display = directory.get(user)
        if display is None:
            raise SlackApiError(
                message="user_not_found",
                response=MagicMock(status_code=404, data={}),
            )
        return {
            "user": {
                "id": user,
                "team_id": "T001",
                "name": user.lower(),
                "profile": {"display_name": display, "real_name": display},
            }
        }

    return _side_effect


def _resolver(
    client: MagicMock, *, bot_user_id: str | None = None
) -> MentionResolver:
    authorizer = SlackAuthorizer(client=client, rules=[])
    return MentionResolver(authorizer, bot_user_id=bot_user_id)


class TestResolveInUsers:
    def test_resolves_user_to_display_name(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = _users_info_side_effect(
            {"U123": "Alice"}
        )
        resolver = _resolver(client)
        assert resolver.resolve_in("hi <@U123>") == "hi @Alice"

    def test_labeled_user_prefers_display_name(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = _users_info_side_effect(
            {"U123": "Alice"}
        )
        resolver = _resolver(client)
        assert resolver.resolve_in("hi <@U123|alice_handle>") == "hi @Alice"

    def test_unknown_user_falls_back_to_id(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = _users_info_side_effect({})
        resolver = _resolver(client)
        assert resolver.resolve_in("hi <@U999>") == "hi @U999"

    def test_empty_display_name_falls_back_to_id(self) -> None:
        client = _mock_client()
        client.users_info.return_value = {
            "user": {
                "id": "U123",
                "team_id": "T001",
                "name": "",
                "profile": {"display_name": "", "real_name": ""},
            }
        }
        resolver = _resolver(client)
        assert resolver.resolve_in("hi <@U123>") == "hi @U123"


class TestResolveInChannels:
    def test_labeled_channel(self) -> None:
        resolver = _resolver(_mock_client())
        assert resolver.resolve_in("see <#C123|general>") == "see #general"

    def test_unlabeled_channel_falls_back_to_id(self) -> None:
        resolver = _resolver(_mock_client())
        assert resolver.resolve_in("see <#C123>") == "see #C123"


class TestResolveInSpecials:
    def test_subteam_with_handle(self) -> None:
        resolver = _resolver(_mock_client())
        assert (
            resolver.resolve_in("ping <!subteam^S9|engineering>")
            == "ping @engineering"
        )

    def test_subteam_without_handle_falls_back_to_id(self) -> None:
        resolver = _resolver(_mock_client())
        assert resolver.resolve_in("ping <!subteam^S9>") == "ping @S9"

    def test_broadcast_tokens(self) -> None:
        resolver = _resolver(_mock_client())
        assert (
            resolver.resolve_in("<!channel> <!here> <!everyone>")
            == "@channel @here @everyone"
        )

    def test_unknown_special_left_intact(self) -> None:
        resolver = _resolver(_mock_client())
        assert (
            resolver.resolve_in("at <!date^1234^{date}|fallback>")
            == "at <!date^1234^{date}|fallback>"
        )


class TestResolveInLinks:
    def test_bare_url(self) -> None:
        resolver = _resolver(_mock_client())
        assert (
            resolver.resolve_in("<https://example.com>")
            == "https://example.com"
        )

    def test_labeled_url(self) -> None:
        resolver = _resolver(_mock_client())
        assert (
            resolver.resolve_in("<https://example.com|docs>")
            == "docs (https://example.com)"
        )


class TestResolveInBotMention:
    def test_strips_bot_mention_from_invocation(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = _users_info_side_effect({})
        resolver = _resolver(client, bot_user_id="UBOT")
        assert (
            resolver.resolve_in("<@UBOT> please help", strip_bot_mention=True)
            == "please help"
        )

    def test_strips_labeled_bot_mention_mid_text(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = _users_info_side_effect({})
        resolver = _resolver(client, bot_user_id="UBOT")
        assert (
            resolver.resolve_in(
                "hey <@UBOT|airut> there", strip_bot_mention=True
            )
            == "hey there"
        )

    def test_preserves_bot_mention_in_history(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = _users_info_side_effect(
            {"UBOT": "Airut"}
        )
        resolver = _resolver(client, bot_user_id="UBOT")
        assert (
            resolver.resolve_in("<@UBOT> earlier", strip_bot_mention=False)
            == "@Airut earlier"
        )

    def test_strip_without_bot_id_is_noop(self) -> None:
        client = _mock_client()
        client.users_info.side_effect = _users_info_side_effect({"U1": "Alice"})
        resolver = _resolver(client)  # no bot_user_id
        assert (
            resolver.resolve_in("<@U1> hi", strip_bot_mention=True)
            == "@Alice hi"
        )


class TestRewriteOutUsers:
    def test_single_user_match_display_name(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="Alice")]
        assert resolver.rewrite_out("ping @Alice", candidates) == "ping <@U1>"

    def test_case_insensitive_match(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="Alice")]
        assert resolver.rewrite_out("ping @alice", candidates) == "ping <@U1>"

    def test_match_falls_through_to_real_name(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="ali", real_name="Alexa")]
        assert resolver.rewrite_out("ping @Alexa", candidates) == "ping <@U1>"

    def test_match_falls_through_to_handle(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="", real_name="", name="bob")]
        assert resolver.rewrite_out("ping @bob", candidates) == "ping <@U1>"

    def test_ambiguous_match_left_alone(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [
            _user("U1", display_name="Sam"),
            _user("U2", display_name="Sam"),
        ]
        assert resolver.rewrite_out("ping @Sam", candidates) == "ping @Sam"

    def test_duplicate_same_user_is_single_match(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [
            _user("U1", display_name="Sam"),
            _user("U1", display_name="Sam"),
        ]
        assert resolver.rewrite_out("ping @Sam", candidates) == "ping <@U1>"

    def test_bot_user_excluded_from_match(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {"usergroups": []}
        resolver = _resolver(client)
        candidates = [_user("UBOT", display_name="Airut", is_bot=True)]
        assert resolver.rewrite_out("ping @Airut", candidates) == "ping @Airut"

    def test_no_match_left_alone(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {"usergroups": []}
        resolver = _resolver(client)
        assert resolver.rewrite_out("ping @nobody", []) == "ping @nobody"


class TestRewriteOutGroups:
    def test_group_handle_rewritten(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "engineering", "id": "S5"}]
        }
        resolver = _resolver(client)
        assert (
            resolver.rewrite_out("cc @engineering", [])
            == "cc <!subteam^S5|engineering>"
        )

    def test_user_match_takes_precedence_over_group(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {
            "usergroups": [{"handle": "eng", "id": "S5"}]
        }
        resolver = _resolver(client)
        candidates = [_user("U1", display_name="eng")]
        assert resolver.rewrite_out("@eng", candidates) == "<@U1>"
        # User matched, so the group lookup is never consulted.
        client.usergroups_list.assert_not_called()


class TestRewriteOutChannels:
    def test_channel_name_rewritten(self) -> None:
        client = _mock_client()
        client.conversations_list.return_value = {
            "channels": [{"name": "general", "id": "C1"}]
        }
        resolver = _resolver(client)
        assert resolver.rewrite_out("see #general", []) == "see <#C1|general>"

    def test_unknown_channel_left_alone(self) -> None:
        client = _mock_client()
        client.conversations_list.return_value = {"channels": []}
        resolver = _resolver(client)
        assert resolver.rewrite_out("see #nope", []) == "see #nope"


class TestRewriteOutBroadcastAndBoundaries:
    def test_broadcast_tokens_not_rewritten(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="here")]
        assert (
            resolver.rewrite_out("@channel @here @everyone", candidates)
            == "@channel @here @everyone"
        )

    def test_email_not_rewritten(self) -> None:
        client = _mock_client()
        client.usergroups_list.return_value = {"usergroups": []}
        resolver = _resolver(client)
        candidates = [_user("U1", display_name="example")]
        # The '@' follows a word char, so it is not a mention boundary.
        assert (
            resolver.rewrite_out("mail alice@example", candidates)
            == "mail alice@example"
        )

    def test_url_fragment_not_rewritten(self) -> None:
        client = _mock_client()
        client.conversations_list.return_value = {
            "channels": [{"name": "section", "id": "C1"}]
        }
        resolver = _resolver(client)
        assert (
            resolver.rewrite_out("see docs.html#section", [])
            == "see docs.html#section"
        )


class TestRewriteOutCodeSkipping:
    def test_inline_code_span_skipped(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="Alice")]
        assert (
            resolver.rewrite_out("`@Alice` and @Alice", candidates)
            == "`@Alice` and <@U1>"
        )

    def test_fenced_block_skipped(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="Alice")]
        text = "before @Alice\n```\n@Alice\n```\nafter @Alice"
        result = resolver.rewrite_out(text, candidates)
        assert result == "before <@U1>\n```\n@Alice\n```\nafter <@U1>"

    def test_indented_fence_toggles(self) -> None:
        resolver = _resolver(_mock_client())
        candidates = [_user("U1", display_name="Alice")]
        text = "  ```\n@Alice\n  ```\n@Alice"
        result = resolver.rewrite_out(text, candidates)
        assert result == "  ```\n@Alice\n  ```\n<@U1>"
