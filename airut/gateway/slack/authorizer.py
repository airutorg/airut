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
    """

    user_id: str
    team_id: str
    is_bot: bool
    is_restricted: bool
    is_ultra_restricted: bool
    deleted: bool
    display_name: str


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

        # User info cache: user_id -> _CacheEntry[UserInfo]
        self._user_cache: dict[str, _CacheEntry[UserInfo]] = {}

        # Group membership cache: group_id -> _CacheEntry[set[str]]
        self._group_cache: dict[str, _CacheEntry[set[str]]] = {}

        # Group handle -> group ID mapping (resolved lazily)
        self._group_ids: dict[str, str] | None = None

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
            display_name = (
                profile.get("display_name")
                or profile.get("real_name")
                or user.get("name", "")
            )

            info = UserInfo(
                user_id=user_id,
                team_id=user.get("team_id", ""),
                is_bot=user.get("is_bot", False),
                is_restricted=user.get("is_restricted", False),
                is_ultra_restricted=user.get("is_ultra_restricted", False),
                deleted=user.get("deleted", False),
                display_name=display_name,
            )

            with self._lock:
                self._user_cache[user_id] = _CacheEntry(
                    value=info, expires_at=now + _CACHE_TTL
                )
            return info

        except SlackApiError as e:
            logger.warning("Failed to fetch user info for %s: %s", user_id, e)
            return None

    def _get_workspace_team_id(self) -> str | None:
        """Get the workspace team ID, resolving lazily via auth.test.

        Returns:
            Workspace team ID or None if the API call fails.
        """
        with self._lock:
            if self._workspace_team_id is not None:
                return self._workspace_team_id

        try:
            resp = self._client.auth_test()
            team_id = resp.get("team_id", "")
            with self._lock:
                self._workspace_team_id = team_id
            return team_id
        except SlackApiError as e:
            logger.warning("Failed to resolve workspace team_id: %s", e)
            return None

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
        """Resolve a group handle to its ID via usergroups.list.

        Resolved once and cached for the process lifetime.

        Args:
            handle: User group handle (without ``@``).

        Returns:
            Group ID or None if not found.
        """
        with self._lock:
            if self._group_ids is not None:
                group_id = self._group_ids.get(handle)
                if group_id is None:
                    logger.warning(
                        "User group '%s' not found in workspace", handle
                    )
                return group_id

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

        group_id = resolved.get(handle)
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
