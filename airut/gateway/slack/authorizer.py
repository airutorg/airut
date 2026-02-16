# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Slack authorization rule evaluation and user info caching.

Evaluates authorization rules (workspace_members, user_group, user_id)
against Slack user data. Caches user info and group membership to avoid
redundant API calls.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)

#: Default cache TTL for user info and group membership (seconds).
_CACHE_TTL = 300  # 5 minutes


@dataclass
class UserInfo:
    """Cached Slack user information.

    Attributes:
        user_id: Slack user ID (e.g., U12345678).
        display_name: Display name for dashboard.
        is_bot: Whether the user is a bot.
        is_restricted: Multi-channel guest.
        is_ultra_restricted: Single-channel guest.
        team_id: Workspace team ID.
        deleted: Whether the user is deactivated.
        fetched_at: Timestamp when this info was fetched.
    """

    user_id: str
    display_name: str
    is_bot: bool
    is_restricted: bool
    is_ultra_restricted: bool
    team_id: str
    deleted: bool
    fetched_at: float


class SlackAuthorizer:
    """Evaluates Slack authorization rules with caching.

    Caches user info from ``users.info`` and group membership from
    ``usergroups.users.list`` to minimize API calls.

    Args:
        rules: Authorization rules from config.
        bot_client: Slack WebClient for API calls.
        workspace_team_id: Expected workspace team ID for external user
            rejection. Resolved lazily from ``auth.test`` if not provided.
    """

    def __init__(
        self,
        rules: list[dict[str, str | bool]],
        bot_client: Any,
        workspace_team_id: str | None = None,
    ) -> None:
        self._rules = rules
        self._client = bot_client
        self._workspace_team_id = workspace_team_id

        # Caches
        self._user_cache: dict[str, UserInfo] = {}
        self._user_cache_lock = threading.Lock()

        # group_handle -> set of user IDs
        self._group_cache: dict[str, set[str]] = {}
        self._group_cache_lock = threading.Lock()
        self._group_cache_fetched_at: dict[str, float] = {}

        # group_handle -> group_id mapping
        self._group_ids: dict[str, str] = {}
        self._groups_resolved = False

    def _resolve_team_id(self) -> str:
        """Resolve workspace team ID via auth.test if not provided."""
        if self._workspace_team_id is None:
            response = self._client.auth_test()
            self._workspace_team_id = response["team_id"]
        return self._workspace_team_id

    def _get_user_info(self, user_id: str) -> UserInfo:
        """Get user info, using cache if fresh.

        Args:
            user_id: Slack user ID.

        Returns:
            UserInfo from cache or API.
        """
        now = time.time()
        with self._user_cache_lock:
            cached = self._user_cache.get(user_id)
            if cached and (now - cached.fetched_at) < _CACHE_TTL:
                return cached

        # Fetch from API (outside lock)
        response = self._client.users_info(user=user_id)
        user = response["user"]

        profile = user.get("profile", {})
        display_name = (
            profile.get("display_name") or profile.get("real_name") or user_id
        )

        info = UserInfo(
            user_id=user_id,
            display_name=display_name,
            is_bot=user.get("is_bot", False),
            is_restricted=user.get("is_restricted", False),
            is_ultra_restricted=user.get("is_ultra_restricted", False),
            team_id=user.get("team_id", ""),
            deleted=user.get("deleted", False),
            fetched_at=now,
        )

        with self._user_cache_lock:
            self._user_cache[user_id] = info
        return info

    def _resolve_group_ids(self) -> None:
        """Resolve group handles to group IDs via usergroups.list.

        Called once at first authorization check. Logs warnings for
        unresolved groups but does not raise.
        """
        if self._groups_resolved:
            return
        self._groups_resolved = True

        needed_groups: set[str] = set()
        for rule in self._rules:
            handle = rule.get("user_group")
            if isinstance(handle, str):
                needed_groups.add(handle)

        if not needed_groups:
            return

        try:
            response = self._client.usergroups_list()
            for group in response.get("usergroups", []):
                handle = group.get("handle", "")
                if handle in needed_groups:
                    self._group_ids[handle] = group["id"]
        except Exception as e:
            logger.warning("Failed to resolve user groups: %s", e)
            return

        for handle in needed_groups:
            if handle not in self._group_ids:
                logger.warning(
                    "Configured user_group '%s' not found in workspace",
                    handle,
                )

    def _get_group_members(self, group_handle: str) -> set[str]:
        """Get group member set, using cache if fresh.

        Args:
            group_handle: Slack user group handle (e.g., "engineering").

        Returns:
            Set of user IDs in the group. Empty if group not found.
        """
        now = time.time()
        with self._group_cache_lock:
            fetched_at = self._group_cache_fetched_at.get(group_handle, 0)
            if (now - fetched_at) < _CACHE_TTL and (
                group_handle in self._group_cache
            ):
                return self._group_cache[group_handle]

        self._resolve_group_ids()
        group_id = self._group_ids.get(group_handle)
        if group_id is None:
            return set()

        try:
            response = self._client.usergroups_users_list(usergroup=group_id)
            members = set(response.get("users", []))
        except Exception as e:
            logger.warning(
                "Failed to fetch members for group '%s': %s",
                group_handle,
                e,
            )
            # Return stale cache if available
            with self._group_cache_lock:
                return self._group_cache.get(group_handle, set())

        with self._group_cache_lock:
            self._group_cache[group_handle] = members
            self._group_cache_fetched_at[group_handle] = now
        return members

    def authorize(self, user_id: str) -> UserInfo:
        """Check if a user is authorized.

        Applies baseline checks (bot, external, deactivated) then
        evaluates rules in order. First match grants access.

        Args:
            user_id: Slack user ID.

        Returns:
            UserInfo if authorized.

        Raises:
            AuthorizationError: If authorization fails.
        """
        info = self._get_user_info(user_id)

        # Baseline checks (always applied)
        if info.is_bot:
            raise AuthorizationError(
                user_id=user_id,
                display_name=info.display_name,
                reason="bot users are not allowed",
            )
        if info.deleted:
            raise AuthorizationError(
                user_id=user_id,
                display_name=info.display_name,
                reason="deactivated user",
            )

        team_id = self._resolve_team_id()
        if info.team_id != team_id:
            raise AuthorizationError(
                user_id=user_id,
                display_name=info.display_name,
                reason="external user (team_id mismatch)",
            )

        # Evaluate rules in order, first match grants access
        for rule in self._rules:
            key = next(iter(rule))
            value = rule[key]

            if key == "workspace_members" and value is True:
                if not info.is_restricted and not info.is_ultra_restricted:
                    return info

            elif key == "user_group" and isinstance(value, str):
                members = self._get_group_members(value)
                if user_id in members:
                    return info

            elif key == "user_id" and value == user_id:
                return info

        raise AuthorizationError(
            user_id=user_id,
            display_name=info.display_name,
            reason="no authorization rule matched",
        )


class AuthorizationError(Exception):
    """Raised when Slack authorization fails.

    Attributes:
        user_id: Slack user ID.
        display_name: Display name for logging.
        reason: Human-readable rejection reason.
    """

    def __init__(
        self,
        *,
        user_id: str,
        display_name: str = "",
        reason: str = "",
    ) -> None:
        self.user_id = user_id
        self.display_name = display_name
        self.reason = reason
        super().__init__(reason or "authorization failed")
