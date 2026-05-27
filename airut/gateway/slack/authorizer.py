# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack authorization rule evaluation with cached API data.

Evaluates authorization rules (``workspace_members``, ``user_group``,
``user_id``) against Slack user info with TTL-based caching to minimize
API calls.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


logger = logging.getLogger(__name__)

#: Cache TTL in seconds for user info and group membership.
_CACHE_TTL = 300  # 5 minutes


@dataclass(frozen=True)
class UserInfo:
    """Cached Slack user info relevant to authorization.

    Attributes:
        user_id: Slack user ID.
        team_id: Workspace ID the user belongs to.
        is_bot: Whether the user is a bot.
        is_restricted: Whether the user is a multi-channel guest.
        is_ultra_restricted: Whether the user is a single-channel guest.
        deleted: Whether the user is deactivated.
        display_name: Human-readable display name.
        real_name: The user's real name (profile real name).
        name: The Slack handle (login name).
    """

    user_id: str
    team_id: str
    is_bot: bool
    is_restricted: bool
    is_ultra_restricted: bool
    deleted: bool
    display_name: str
    real_name: str = ""
    name: str = ""


@dataclass
class _CacheEntry[T]:
    """TTL cache entry."""

    value: T
    expires_at: float


class SlackAuthorizer:
    """Evaluates authorization rules with cached Slack API data.

    Performs baseline rejection checks (bots, deactivated, external users)
    before evaluating configured rules in order (first match wins).

    Args:
        client: Slack ``WebClient`` for API calls.
        rules: Authorization rules from config.
        workspace_team_id: The workspace's team ID for external user
            detection.  Resolved lazily from the first ``auth.test``
            call if not provided.
    """

    def __init__(
        self,
        client: WebClient,
        rules: Sequence[dict[str, str | bool]],
        workspace_team_id: str | None = None,
    ) -> None:
        self._client = client
        self._rules = rules
        self._workspace_team_id = workspace_team_id
        self._lock = threading.Lock()

        # Bot's own user ID, resolved lazily from the same auth.test call
        # that resolves the workspace team ID.
        self._bot_user_id: str | None = None

        # User info cache: user_id -> _CacheEntry[UserInfo]
        self._user_cache: dict[str, _CacheEntry[UserInfo]] = {}

        # Group membership cache: group_id -> _CacheEntry[set[str]]
        self._group_cache: dict[str, _CacheEntry[set[str]]] = {}

        # Group handle -> group ID mapping (resolved lazily)
        self._group_ids: dict[str, str] | None = None

        # Channel name -> channel ID mapping, bulk-loaded with TTL.
        self._channel_ids: _CacheEntry[dict[str, str]] | None = None

    def authorize(self, user_id: str) -> tuple[bool, str]:
        """Check whether a user is authorized.

        Args:
            user_id: Slack user ID to check.

        Returns:
            Tuple of (authorized, reason).  ``authorized`` is True if
            access is granted, False otherwise.  ``reason`` is a
            human-readable explanation (empty when authorized).
        """
        user_info = self._get_user_info(user_id)
        if user_info is None:
            return False, "failed to fetch user info"

        # Baseline checks: always reject
        if user_info.is_bot:
            return False, "bot users are not allowed"
        if user_info.deleted:
            return False, "deactivated users are not allowed"

        workspace_id = self._get_workspace_team_id()
        if workspace_id is None:
            return (
                False,
                "cannot verify workspace membership (auth.test failed)",
            )
        if user_info.team_id != workspace_id:
            return False, "external users are not allowed"

        # Evaluate rules in order, first match wins
        for rule in self._rules:
            if "workspace_members" in rule:
                if rule["workspace_members"] is True:
                    if (
                        not user_info.is_restricted
                        and not user_info.is_ultra_restricted
                    ):
                        return True, ""

            elif "user_group" in rule:
                group_handle = str(rule["user_group"])
                if self._is_in_group(user_id, group_handle):
                    return True, ""

            elif "user_id" in rule:
                if str(rule["user_id"]) == user_id:
                    return True, ""

        return False, "no authorization rule matched"

    def get_display_name(self, user_id: str) -> str:
        """Return cached display name for a user, falling back to ID.

        Args:
            user_id: Slack user ID.

        Returns:
            Display name or the raw user ID if not cached.
        """
        with self._lock:
            entry = self._user_cache.get(user_id)
        if entry is not None:
            return entry.value.display_name or user_id
        return user_id

    def get_user_info(self, user_id: str) -> UserInfo | None:
        """Return user info, fetching and caching it on a miss.

        Args:
            user_id: Slack user ID.

        Returns:
            UserInfo or None if the API call fails.
        """
        return self._get_user_info(user_id)

    def lookup_group_id(self, handle: str) -> str | None:
        """Resolve a user group handle to its ID, quietly on a miss.

        Reuses the lazily-populated handle-to-ID cache (loaded once via
        ``usergroups.list``).  Unlike :meth:`_resolve_group_id`, this does
        not log a warning when the handle is absent, so it is safe to call
        for arbitrary ``@token`` candidates during outbound rewriting.

        Args:
            handle: User group handle (without the leading ``@``).

        Returns:
            Group ID or None if the handle is not a known user group.
        """
        with self._lock:
            if self._group_ids is not None:
                return self._group_ids.get(handle)

        try:
            resp = self._client.usergroups_list()
            groups = resp.get("usergroups", [])
            resolved = {
                g["handle"]: g["id"]
                for g in groups
                if "handle" in g and "id" in g
            }
        except SlackApiError as e:
            logger.warning("Failed to list user groups: %s", e)
            resolved = {}

        with self._lock:
            self._group_ids = resolved
        return resolved.get(handle)

    def resolve_channel_id(self, name: str) -> str | None:
        """Resolve a channel name to its ID via a TTL-cached bulk lookup.

        The full channel list is fetched lazily via ``conversations.list``
        (paginated) and cached for the same TTL as user info.  Requires the
        ``channels:read`` scope; if the call fails the cache is left empty
        and the method returns None, disabling channel rewriting gracefully.

        Args:
            name: Channel name without the leading ``#``.

        Returns:
            Channel ID or None if no channel by that name is known.
        """
        now = time.monotonic()

        with self._lock:
            entry = self._channel_ids
            if entry is not None and entry.expires_at > now:
                return entry.value.get(name)

        channels: dict[str, str] = {}
        try:
            cursor: str | None = None
            while True:
                resp = self._client.conversations_list(
                    types="public_channel,private_channel",
                    exclude_archived=True,
                    limit=1000,
                    cursor=cursor,
                )
                for channel in resp.get("channels", []):
                    if "name" in channel and "id" in channel:
                        channels[channel["name"]] = channel["id"]
                cursor = resp.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break
        except SlackApiError as e:
            logger.warning("Failed to list channels: %s", e)

        with self._lock:
            self._channel_ids = _CacheEntry(
                value=channels, expires_at=now + _CACHE_TTL
            )
        return channels.get(name)

    def candidate_group_member_ids(self) -> set[str]:
        """Return user IDs of members of every configured ``user_group`` rule.

        Used to seed the outbound mention-rewriting candidate set so the bot
        can ``@``-mention authorized group members even when they have not
        posted in the current thread.  Reuses the cached group-membership
        data; groups that fail to resolve contribute nothing.

        Returns:
            Union of member user IDs across all ``user_group`` rules.
        """
        members: set[str] = set()
        for rule in self._rules:
            if "user_group" in rule:
                group_id = self._resolve_group_id(str(rule["user_group"]))
                if group_id is not None:
                    members |= self._get_group_members(group_id)
        return members

    def _get_user_info(self, user_id: str) -> UserInfo | None:
        """Fetch user info with TTL cache.

        Args:
            user_id: Slack user ID.

        Returns:
            UserInfo or None if the API call fails.
        """
        now = time.monotonic()

        with self._lock:
            entry = self._user_cache.get(user_id)
            if entry is not None and entry.expires_at > now:
                return entry.value

        # Cache miss or expired — fetch from API (outside lock)
        try:
            resp = self._client.users_info(user=user_id)
            user = resp["user"]

            profile = user.get("profile", {})
            name = user.get("name", "")
            real_name = profile.get("real_name") or user.get("real_name", "")
            display_name = profile.get("display_name") or real_name or name

            info = UserInfo(
                user_id=user_id,
                team_id=user.get("team_id", ""),
                is_bot=user.get("is_bot", False),
                is_restricted=user.get("is_restricted", False),
                is_ultra_restricted=user.get("is_ultra_restricted", False),
                deleted=user.get("deleted", False),
                display_name=display_name,
                real_name=real_name,
                name=name,
            )

            with self._lock:
                self._user_cache[user_id] = _CacheEntry(
                    value=info, expires_at=now + _CACHE_TTL
                )
            return info

        except SlackApiError as e:
            logger.warning("Failed to fetch user info for %s: %s", user_id, e)
            return None

    def get_bot_user_id(self) -> str | None:
        """Return the bot's own Slack user ID, resolving lazily.

        Shares the single ``auth.test`` call with workspace team-ID
        resolution.  Used by the listener (mention pre-filter) and the
        adapter (stripping the bot's own mention from invocations).

        Returns:
            The bot user ID, or None if ``auth.test`` has not yet
            succeeded.
        """
        _, bot_user_id = self._resolve_identity()
        return bot_user_id

    def _get_workspace_team_id(self) -> str | None:
        """Get the workspace team ID, resolving lazily via auth.test.

        Returns:
            Workspace team ID or None if the API call fails.
        """
        team_id, _ = self._resolve_identity()
        return team_id

    def _resolve_identity(self) -> tuple[str | None, str | None]:
        """Resolve workspace team ID and bot user ID via one auth.test.

        Cached after the first success; failures leave both unset so a
        later call retries.

        Returns:
            ``(team_id, bot_user_id)``; either element is None if
            ``auth.test`` has not yet succeeded.
        """
        with self._lock:
            if self._workspace_team_id is not None:
                return self._workspace_team_id, self._bot_user_id

        try:
            resp = self._client.auth_test()
            team_id = resp.get("team_id", "")
            bot_user_id = resp.get("user_id", "") or None
            with self._lock:
                self._workspace_team_id = team_id
                self._bot_user_id = bot_user_id
            return team_id, bot_user_id
        except SlackApiError as e:
            logger.warning(
                "Failed to resolve Slack identity (auth.test): %s", e
            )
            return None, None

    def _is_in_group(self, user_id: str, group_handle: str) -> bool:
        """Check if a user is a member of a user group.

        Args:
            user_id: Slack user ID.
            group_handle: User group handle (e.g. ``engineering``).

        Returns:
            True if the user is in the group.
        """
        group_id = self._resolve_group_id(group_handle)
        if group_id is None:
            return False

        members = self._get_group_members(group_id)
        return user_id in members

    def _resolve_group_id(self, handle: str) -> str | None:
        """Resolve a configured group handle to its ID, warning on a miss.

        Used by authorization rule evaluation, where a missing handle
        indicates a misconfigured rule worth surfacing in the logs.

        Args:
            handle: User group handle (without ``@``).

        Returns:
            Group ID or None if not found.
        """
        group_id = self.lookup_group_id(handle)
        if group_id is None:
            logger.warning("User group '%s' not found in workspace", handle)
        return group_id

    def _get_group_members(self, group_id: str) -> set[str]:
        """Fetch group members with TTL cache.

        Falls back to stale cache on API failure.

        Args:
            group_id: Slack user group ID.

        Returns:
            Set of user IDs in the group.
        """
        now = time.monotonic()

        with self._lock:
            entry = self._group_cache.get(group_id)
            if entry is not None and entry.expires_at > now:
                return entry.value

        stale_value = entry.value if entry is not None else set()

        try:
            resp = self._client.usergroups_users_list(usergroup=group_id)
            members = set(resp.get("users", []))

            with self._lock:
                self._group_cache[group_id] = _CacheEntry(
                    value=members, expires_at=now + _CACHE_TTL
                )
            return members

        except SlackApiError as e:
            logger.warning(
                "Failed to fetch group %s members, using stale cache: %s",
                group_id,
                e,
            )
            return stale_value
