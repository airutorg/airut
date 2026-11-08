# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Reflect channel listener health in repository status.

Listeners expose their health only through ``ChannelListener.status``.
``ChannelHealthMonitor`` polls it and sets the status of each started
repo, so a listener that loses its connection shows up on the dashboard
and in ``/api/health`` instead of the repo looking live.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import replace

from airut.dashboard.tracker import RepoState, RepoStatus
from airut.dashboard.versioned import VersionedStore
from airut.gateway.channel import ChannelHealth, ChannelStatus


logger = logging.getLogger(__name__)

#: Seconds between channel health polls.
POLL_INTERVAL = 5.0

#: Returns a repo's listener statuses by channel type, or None if the
#: repo has no running handler.
type StatusLookup = Callable[[str], Mapping[str, ChannelStatus] | None]


def repo_health(
    statuses: Mapping[str, ChannelStatus],
) -> tuple[RepoStatus, str | None, str | None]:
    """Derive a started repo's status from its channel listeners' health.

    FAILED if any listener has failed, DEGRADED if any is otherwise not
    connected (reconnecting, or not yet connected), LIVE when all are
    connected.

    Args:
        statuses: Listener status per channel type.

    Returns:
        Tuple of (status, error_type, error_message).  The error fields
        describe the channels responsible for the status and are None
        when LIVE.
    """
    unhealthy = {
        channel_type: status
        for channel_type, status in statuses.items()
        if status.health == ChannelHealth.FAILED
    }
    repo_status = RepoStatus.FAILED
    if not unhealthy:
        unhealthy = {
            channel_type: status
            for channel_type, status in statuses.items()
            if status.health != ChannelHealth.CONNECTED
        }
        repo_status = RepoStatus.DEGRADED
    if not unhealthy:
        return RepoStatus.LIVE, None, None

    error_type = next(
        (s.error_type for s in unhealthy.values() if s.error_type), None
    )
    error_message = "; ".join(
        f"{channel_type}: {status.message or status.health.value}"
        for channel_type, status in unhealthy.items()
    )
    return repo_status, error_type, error_message


class ChannelHealthMonitor:
    """Polls channel listener health into the repos store.

    Only LIVE and DEGRADED repos are updated.  Reload states take
    precedence (listeners are being restarted), and a FAILED repo stays
    failed until a reload or restart replaces its listeners.

    Args:
        repos_store: Store holding the repo states to update.
        get_channel_statuses: Returns a repo's listener statuses by
            channel type, or None if the repo has no running handler.
        shutdown_event: Stops ``run()`` when set.
        interval: Seconds between polls.
    """

    def __init__(
        self,
        repos_store: VersionedStore[tuple[RepoState, ...]],
        get_channel_statuses: StatusLookup,
        shutdown_event: threading.Event,
        interval: float = POLL_INTERVAL,
    ) -> None:
        self._repos_store = repos_store
        self._get_channel_statuses = get_channel_statuses
        self._shutdown_event = shutdown_event
        self._interval = interval

    def run(self) -> None:
        """Poll every *interval* seconds until shutdown."""
        while not self._shutdown_event.wait(timeout=self._interval):
            try:
                self.refresh()
            except Exception:
                logger.exception("Error refreshing channel health")

    def refresh(self) -> None:
        """Update each started repo's status from its listeners' health.

        Writes the store only when something changed, so an unchanged
        poll does not wake dashboard clients.
        """
        self._repos_store.modify(
            lambda states: tuple(self._with_channel_health(s) for s in states)
        )

    def _with_channel_health(self, state: RepoState) -> RepoState:
        """Return *state* with status and error from its listeners.

        A repo whose listener statuses cannot be read keeps its state,
        so it does not hold up updates for the other repos.
        """
        if state.status not in (RepoStatus.LIVE, RepoStatus.DEGRADED):
            return state
        try:
            statuses = self._get_channel_statuses(state.repo_id)
        except Exception:
            logger.exception(
                "Repo '%s': failed to read channel health", state.repo_id
            )
            return state
        if statuses is None:
            return state
        status, error_type, error_message = repo_health(statuses)
        return replace(
            state,
            status=status,
            error_type=error_type,
            error_message=error_message,
        )
