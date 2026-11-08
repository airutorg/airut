# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for channel_health module (listener health → repo status)."""

import threading
from collections.abc import Mapping
from unittest.mock import MagicMock

import pytest

from airut.dashboard.tracker import RepoState, RepoStatus
from airut.dashboard.versioned import VersionClock, VersionedStore
from airut.gateway.channel import ChannelHealth, ChannelStatus
from airut.gateway.service.channel_health import (
    ChannelHealthMonitor,
    repo_health,
)


def _status(
    health: ChannelHealth, message: str = "", error_type: str | None = None
) -> ChannelStatus:
    return ChannelStatus(health=health, message=message, error_type=error_type)


class TestRepoHealth:
    """Mapping from channel listener health to repo status."""

    def test_all_connected_is_live(self) -> None:
        statuses = {
            "email": _status(ChannelHealth.CONNECTED),
            "slack": _status(ChannelHealth.CONNECTED),
        }
        assert repo_health(statuses) == (RepoStatus.LIVE, None, None)

    def test_starting_counts_as_degraded(self) -> None:
        """A listener not yet connected degrades; health names it."""
        assert repo_health({"email": _status(ChannelHealth.STARTING)}) == (
            RepoStatus.DEGRADED,
            None,
            "email: starting",
        )

    def test_failed_takes_precedence(self) -> None:
        """Any FAILED listener fails the repo; only failed ones are named."""
        result = repo_health(
            {
                "email": _status(
                    ChannelHealth.DEGRADED,
                    "IMAP reconnecting (attempt 1): lost",
                    "IMAPConnectionError",
                ),
                "slack": _status(ChannelHealth.FAILED, "stopped"),
            }
        )

        assert result == (RepoStatus.FAILED, None, "slack: stopped")

    def test_multiple_degraded_channels(self) -> None:
        """Every degraded channel is named; the first error type is kept."""
        result = repo_health(
            {
                "email": _status(ChannelHealth.DEGRADED, "IMAP down"),
                "slack": _status(
                    ChannelHealth.DEGRADED, "WebSocket closed", "OSError"
                ),
            }
        )

        assert result == (
            RepoStatus.DEGRADED,
            "OSError",
            "email: IMAP down; slack: WebSocket closed",
        )


class _Fixture:
    """A monitor over a one-repo store with a settable listener status."""

    def __init__(
        self,
        status: RepoStatus,
        error_message: str | None = None,
        error_type: str | None = None,
    ) -> None:
        state = RepoState(
            repo_id="repo",
            status=status,
            error_message=error_message,
            error_type=error_type,
        )
        self.store: VersionedStore[tuple[RepoState, ...]] = VersionedStore(
            (state,), VersionClock()
        )
        self.listener = _status(ChannelHealth.CONNECTED)
        self.shutdown = threading.Event()
        self.monitor = ChannelHealthMonitor(
            self.store, self._statuses, self.shutdown
        )

    def _statuses(self, repo_id: str) -> dict[str, ChannelStatus] | None:
        return {"email": self.listener} if repo_id == "repo" else None

    @property
    def state(self) -> RepoState:
        (state,) = self.store.get().value
        return state


class TestChannelHealthMonitor:
    def test_disconnected_listener_degrades_repo(self) -> None:
        """A reconnecting listener turns a LIVE repo DEGRADED.

        Regression: listener health was never read, so a repo whose
        IMAP listener had lost its connection still showed as live.
        """
        f = _Fixture(RepoStatus.LIVE)
        f.listener = _status(
            ChannelHealth.DEGRADED,
            "IMAP reconnecting (attempt 4): Connection refused",
            "IMAPConnectionError",
        )

        f.monitor.refresh()

        assert f.state.status == RepoStatus.DEGRADED
        assert f.state.error_type == "IMAPConnectionError"
        assert f.state.error_message == (
            "email: IMAP reconnecting (attempt 4): Connection refused"
        )

    def test_reconnected_listener_restores_live(self) -> None:
        """A DEGRADED repo returns to LIVE and drops the error."""
        f = _Fixture(
            RepoStatus.DEGRADED,
            error_message="email: IMAP reconnecting (attempt 1): lost",
            error_type="IMAPConnectionError",
        )

        f.monitor.refresh()

        assert f.state.status == RepoStatus.LIVE
        assert f.state.error_message is None
        assert f.state.error_type is None

    def test_failed_listener_fails_repo(self) -> None:
        """A listener that has stopped for good marks the repo FAILED."""
        f = _Fixture(RepoStatus.LIVE)
        f.listener = _status(
            ChannelHealth.FAILED, "Email listener stopped unexpectedly"
        )

        f.monitor.refresh()

        assert f.state.status == RepoStatus.FAILED
        assert f.state.error_message == (
            "email: Email listener stopped unexpectedly"
        )

    @pytest.mark.parametrize(
        "status",
        [RepoStatus.RELOADING, RepoStatus.RELOAD_PENDING, RepoStatus.FAILED],
    )
    def test_leaves_other_statuses_alone(self, status: RepoStatus) -> None:
        """Reload states and FAILED are not overridden by listener health."""
        f = _Fixture(status)
        version = f.store.get().version

        f.monitor.refresh()

        assert f.state.status == status
        assert f.store.get().version == version

    def test_repo_without_handler_untouched(self) -> None:
        """A store entry with no running handler is left as is."""
        f = _Fixture(RepoStatus.LIVE)
        f.store.update((RepoState(repo_id="other", status=RepoStatus.LIVE),))

        f.monitor.refresh()

        assert f.store.get().value[0].status == RepoStatus.LIVE

    def test_unreadable_repo_does_not_block_others(self) -> None:
        """A repo whose statuses raise keeps its state; others update."""
        f = _Fixture(RepoStatus.LIVE)
        f.store.update(
            (
                RepoState(repo_id="broken", status=RepoStatus.LIVE),
                RepoState(repo_id="repo", status=RepoStatus.LIVE),
            )
        )
        f.listener = _status(ChannelHealth.DEGRADED, "down")
        lookup = f.monitor._get_channel_statuses

        def flaky(repo_id: str) -> Mapping[str, ChannelStatus] | None:
            if repo_id == "broken":
                raise AttributeError("no client")
            return lookup(repo_id)

        f.monitor._get_channel_statuses = flaky

        f.monitor.refresh()

        broken, repo = f.store.get().value
        assert broken.status == RepoStatus.LIVE
        assert repo.status == RepoStatus.DEGRADED

    def test_unchanged_health_does_not_write_store(self) -> None:
        """An unchanged poll leaves the store version (and SSE) alone."""
        f = _Fixture(RepoStatus.LIVE)
        version = f.store.get().version

        f.monitor.refresh()

        assert f.store.get().version == version

    def test_run_polls_until_shutdown(self) -> None:
        """run() refreshes each interval and survives errors."""
        f = _Fixture(RepoStatus.LIVE)
        wait = MagicMock(side_effect=[False, False, True])
        f.shutdown.wait = wait
        refresh = MagicMock(side_effect=[RuntimeError("boom"), None])
        f.monitor.refresh = refresh

        f.monitor.run()

        assert refresh.call_count == 2
        wait.assert_called_with(timeout=5.0)
