# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the Scheduler class."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

import pytest

from airut.gateway.config import ScheduleConfig, ScheduleDelivery
from airut.gateway.scheduler.cron import CronExpression
from airut.gateway.scheduler.service import (
    _MAX_SLEEP_SECONDS,
    Scheduler,
    _local_tz,
    _ResolvedSchedule,
)


def _make_schedule_config(
    cron: str = "0 9 * * 1-5",
    prompt: str | None = "Test prompt",
    timezone: str | None = "UTC",
) -> ScheduleConfig:
    """Create a test ScheduleConfig."""
    return ScheduleConfig(
        cron=cron,
        deliver=ScheduleDelivery(to="user@example.com", channel="email"),
        timezone=timezone,
        prompt=prompt,
    )


def _make_service() -> MagicMock:
    """Create a mock GatewayService whose submit_task runs on its pool.

    ``submit_task`` returns None, as the real one does, when the pool
    is not running.
    """
    svc = MagicMock()
    svc.repo_handlers = {}
    svc.pool = MagicMock()
    svc.tracker = MagicMock()

    def submit_task(
        task_id: str, fn: Callable[..., None], /, *args: object
    ) -> Future[None] | None:
        pool = svc.pool
        return None if pool is None else pool.submit(fn, *args)

    svc.submit_task.side_effect = submit_task
    return svc


class TestSchedulerInit:
    """Test Scheduler initialization."""

    def test_init(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        assert scheduler._service is svc
        assert scheduler._schedules == {}
        assert scheduler._thread is None

    def test_build_repo_schedules(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)

        schedules = {"daily": _make_schedule_config()}
        scheduler._build_repo_schedules("test-repo", schedules)

        assert "test-repo" in scheduler._schedules
        assert "daily" in scheduler._schedules["test-repo"]
        resolved = scheduler._schedules["test-repo"]["daily"]
        assert resolved.repo_id == "test-repo"
        assert resolved.name == "daily"
        assert isinstance(resolved.cron, CronExpression)
        assert resolved.tz == ZoneInfo("UTC")

    def test_build_repo_schedules_skips_disabled(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)

        enabled = _make_schedule_config()
        disabled = ScheduleConfig(
            cron="0 9 * * 1-5",
            deliver=ScheduleDelivery(to="user@example.com", channel="email"),
            enable=False,
            timezone="UTC",
            prompt="Test prompt",
        )
        schedules = {"active": enabled, "inactive": disabled}
        scheduler._build_repo_schedules("test-repo", schedules)

        assert "test-repo" in scheduler._schedules
        assert "active" in scheduler._schedules["test-repo"]
        assert "inactive" not in scheduler._schedules["test-repo"]

    def test_build_repo_schedules_all_disabled(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)

        disabled = ScheduleConfig(
            cron="0 9 * * 1-5",
            deliver=ScheduleDelivery(to="user@example.com", channel="email"),
            enable=False,
            timezone="UTC",
            prompt="Test prompt",
        )
        scheduler._build_repo_schedules("test-repo", {"task": disabled})
        assert "test-repo" not in scheduler._schedules

    def test_build_repo_schedules_empty(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        scheduler._build_repo_schedules("test-repo", {})
        assert "test-repo" not in scheduler._schedules

    def test_build_repo_schedules_invalid_cron(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        config = ScheduleConfig(
            cron="invalid",
            deliver=ScheduleDelivery(channel="email", to="a@b.com"),
            prompt="test",
        )
        scheduler._build_repo_schedules("test-repo", {"bad": config})
        assert "test-repo" not in scheduler._schedules


class TestSchedulerLifecycle:
    """Test Scheduler start/stop."""

    def test_start_creates_thread(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        scheduler.start()
        assert scheduler._thread is not None
        assert scheduler._thread.is_alive()
        scheduler.stop()
        assert not scheduler._thread.is_alive()

    def test_start_builds_from_repo_handlers(self) -> None:
        svc = _make_service()
        handler = MagicMock()
        handler.config.schedules = {"daily": _make_schedule_config()}
        svc.repo_handlers = {"test-repo": handler}

        scheduler = Scheduler(svc)
        scheduler.start()

        assert "test-repo" in scheduler._schedules
        assert "daily" in scheduler._schedules["test-repo"]
        scheduler.stop()

    def test_stop_is_idempotent(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        scheduler.start()
        scheduler.stop()
        scheduler.stop()  # should not raise


class TestSchedulerRepoManagement:
    """Test rebuild_repo and remove_repo."""

    def test_rebuild_repo(self) -> None:
        svc = _make_service()
        handler = MagicMock()
        handler.config.schedules = {"daily": _make_schedule_config()}
        svc.repo_handlers = {"test-repo": handler}

        scheduler = Scheduler(svc)
        scheduler._build_repo_schedules(
            "test-repo", {"old": _make_schedule_config()}
        )
        assert "old" in scheduler._schedules["test-repo"]

        scheduler.rebuild_repo("test-repo")
        assert "daily" in scheduler._schedules["test-repo"]
        assert "old" not in scheduler._schedules["test-repo"]

    def test_rebuild_repo_no_handler(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        scheduler._build_repo_schedules(
            "test-repo", {"old": _make_schedule_config()}
        )

        scheduler.rebuild_repo("test-repo")
        assert "test-repo" not in scheduler._schedules

    def test_remove_repo(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        scheduler._build_repo_schedules(
            "test-repo", {"daily": _make_schedule_config()}
        )
        assert "test-repo" in scheduler._schedules

        scheduler.remove_repo("test-repo")
        assert "test-repo" not in scheduler._schedules

    def test_remove_repo_nonexistent(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        scheduler.remove_repo("nonexistent")  # should not raise


class TestSchedulerDispatch:
    """Test schedule firing and dispatch."""

    def test_tick_dispatches_due_schedules(self) -> None:
        svc = _make_service()
        future = MagicMock()
        svc.pool.submit.return_value = future

        scheduler = Scheduler(svc)
        # Create a schedule that fires immediately
        now = datetime.now(tz=UTC)
        resolved = _ResolvedSchedule(
            repo_id="test-repo",
            name="daily",
            config=_make_schedule_config(),
            cron=CronExpression("* * * * *"),
            tz=ZoneInfo("UTC"),
            next_fire=now - timedelta(minutes=1),
        )

        handler = MagicMock()
        svc.repo_handlers = {"test-repo": handler}
        scheduler._schedules = {"test-repo": {"daily": resolved}}

        scheduler._tick()

        svc.tracker.add_task.assert_called_once()
        svc.tracker.set_authenticating.assert_called_once()
        svc.pool.submit.assert_called_once()
        task_id = svc.tracker.add_task.call_args[0][0]
        assert svc.submit_task.call_args[0][0] == task_id

    def test_tick_skips_future_schedules(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)

        now = datetime.now(tz=UTC)
        resolved = _ResolvedSchedule(
            repo_id="test-repo",
            name="daily",
            config=_make_schedule_config(),
            cron=CronExpression("* * * * *"),
            tz=ZoneInfo("UTC"),
            next_fire=now + timedelta(hours=1),
        )
        scheduler._schedules = {"test-repo": {"daily": resolved}}

        scheduler._tick()
        svc.submit_task.assert_not_called()

    def test_dispatch_not_submitted_is_not_tracked(self) -> None:
        """A run the pool did not accept does not block later fires.

        Completing its tracker task is submit_task()'s job, covered with
        a real tracker in test_config_reload.py.
        """
        svc = _make_service()
        svc.pool = None
        svc.repo_handlers = {"test-repo": MagicMock()}

        scheduler = Scheduler(svc)
        scheduler._dispatch(_make_resolved("daily"))

        svc.submit_task.assert_called_once()
        assert scheduler._dispatched == {}

    def test_dispatch_no_handler(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)

        resolved = _ResolvedSchedule(
            repo_id="missing",
            name="daily",
            config=_make_schedule_config(),
            cron=CronExpression("* * * * *"),
            tz=ZoneInfo("UTC"),
            next_fire=datetime.now(tz=UTC),
        )
        scheduler._dispatch(resolved)
        svc.submit_task.assert_not_called()

    def test_compute_sleep_empty(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        assert scheduler._compute_sleep() == _MAX_SLEEP_SECONDS

    def test_compute_sleep_soon(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        now = datetime.now(tz=UTC)
        resolved = _ResolvedSchedule(
            repo_id="test",
            name="daily",
            config=_make_schedule_config(),
            cron=CronExpression("* * * * *"),
            tz=ZoneInfo("UTC"),
            next_fire=now + timedelta(seconds=10),
        )
        scheduler._schedules = {"test": {"daily": resolved}}
        sleep = scheduler._compute_sleep()
        assert sleep < _MAX_SLEEP_SECONDS
        assert sleep >= 0.1

    def test_compute_sleep_overdue(self) -> None:
        svc = _make_service()
        scheduler = Scheduler(svc)
        now = datetime.now(tz=UTC)
        resolved = _ResolvedSchedule(
            repo_id="test",
            name="daily",
            config=_make_schedule_config(),
            cron=CronExpression("* * * * *"),
            tz=ZoneInfo("UTC"),
            next_fire=now - timedelta(minutes=5),
        )
        scheduler._schedules = {"test": {"daily": resolved}}
        sleep = scheduler._compute_sleep()
        assert sleep == 0.1


_EXECUTE = "airut.gateway.scheduler.execution.execute_scheduled_task"


def _make_resolved(name: str, repo_id: str = "test-repo") -> _ResolvedSchedule:
    """Create a resolved schedule that is due now."""
    return _ResolvedSchedule(
        repo_id=repo_id,
        name=name,
        config=_make_schedule_config(),
        cron=CronExpression("* * * * *"),
        tz=ZoneInfo("UTC"),
        next_fire=datetime.now(tz=UTC),
    )


@dataclass
class _Busy:
    """Scheduler backed by a real single-worker pool that can be blocked."""

    svc: MagicMock
    pool: ThreadPoolExecutor
    scheduler: Scheduler
    release: threading.Event

    def occupy_worker(self) -> None:
        """Block the only worker so dispatched runs have to queue."""
        self.pool.submit(self.release.wait)

    def drain(self) -> None:
        """Unblock the worker and wait for every queued run to finish."""
        self.release.set()
        self.pool.shutdown(wait=True)


@pytest.fixture
def busy() -> Iterator[_Busy]:
    svc = _make_service()
    pool = ThreadPoolExecutor(max_workers=1)
    svc.pool = pool
    svc.repo_handlers = {"test-repo": MagicMock()}
    state = _Busy(svc, pool, Scheduler(svc), threading.Event())
    try:
        yield state
    finally:
        # Never leave a blocked worker behind: interpreter exit joins it.
        state.drain()


class TestSchedulerQueueBound:
    """At most one run per schedule waits for a free worker."""

    def test_skips_fire_while_previous_run_waits_for_worker(
        self, busy: _Busy
    ) -> None:
        busy.occupy_worker()
        execute = MagicMock()
        sched = _make_resolved("hourly")

        with patch(_EXECUTE, execute):
            busy.scheduler._dispatch(sched)
            busy.scheduler._dispatch(sched)
            busy.scheduler._dispatch(sched)

        assert busy.svc.tracker.add_task.call_count == 1
        busy.drain()
        execute.assert_called_once()

    def test_skipped_fire_logs_and_advances_next_fire(
        self, busy: _Busy, caplog: pytest.LogCaptureFixture
    ) -> None:
        busy.occupy_worker()
        sched = _make_resolved("hourly")
        busy.scheduler._schedules = {"test-repo": {"hourly": sched}}

        with patch(_EXECUTE, MagicMock()):
            busy.scheduler._tick()
            sched.next_fire = datetime.now(tz=UTC) - timedelta(minutes=1)
            with caplog.at_level(
                logging.WARNING, logger="airut.gateway.scheduler.service"
            ):
                busy.scheduler._tick()

        assert busy.svc.tracker.add_task.call_count == 1
        assert "previous run is still waiting for a free worker" in caplog.text
        # The skipped fire still moves to the next cron slot.
        assert sched.next_fire > datetime.now(tz=UTC)

    def test_started_run_does_not_block_next_fire(self, busy: _Busy) -> None:
        started = threading.Event()

        def fake_execute(*args: object) -> None:
            started.set()
            busy.release.wait()

        sched = _make_resolved("hourly")
        with patch(_EXECUTE, fake_execute):
            busy.scheduler._dispatch(sched)
            assert started.wait(timeout=5)
            # Queues behind the running instance...
            busy.scheduler._dispatch(sched)
            # ...and further fires are skipped while it waits.
            busy.scheduler._dispatch(sched)

        assert busy.svc.tracker.add_task.call_count == 2

    def test_other_schedules_still_queue(self, busy: _Busy) -> None:
        busy.svc.repo_handlers["other-repo"] = MagicMock()
        busy.occupy_worker()

        with patch(_EXECUTE, lambda *args: None):
            busy.scheduler._dispatch(_make_resolved("a"))
            busy.scheduler._dispatch(_make_resolved("b"))
            busy.scheduler._dispatch(_make_resolved("a", repo_id="other-repo"))

        assert busy.svc.tracker.add_task.call_count == 3

    def test_dispatches_again_after_run_completes(self, busy: _Busy) -> None:
        sched = _make_resolved("hourly")

        with patch(_EXECUTE, lambda *args: None):
            busy.scheduler._dispatch(sched)
            busy.drain()
            assert busy.scheduler._dispatched == {}

            busy.pool = ThreadPoolExecutor(max_workers=1)
            busy.svc.pool = busy.pool
            busy.scheduler._dispatch(sched)

        assert busy.svc.tracker.add_task.call_count == 2

    def test_queued_run_survives_rebuild_repo(self, busy: _Busy) -> None:
        busy.svc.repo_handlers["test-repo"].config.schedules = {
            "hourly": _make_schedule_config()
        }
        scheduler = busy.scheduler
        scheduler.rebuild_repo("test-repo")
        busy.occupy_worker()

        with patch(_EXECUTE, lambda *args: None):
            scheduler._dispatch(scheduler._schedules["test-repo"]["hourly"])
            scheduler.rebuild_repo("test-repo")
            scheduler._dispatch(scheduler._schedules["test-repo"]["hourly"])

        assert busy.svc.tracker.add_task.call_count == 1

    def test_completion_of_older_run_keeps_newer_entry(self) -> None:
        scheduler = Scheduler(_make_service())
        key = ("test-repo", "hourly")
        older: Future[None] = Future()
        newer: Future[None] = Future()
        scheduler._dispatched[key] = newer

        scheduler._on_run_done(key, older)

        assert scheduler._dispatched[key] is newer


class TestSchedulerExceptionPaths:
    """Test error handling in scheduler run loop and tick."""

    def test_run_loop_catches_tick_exception(self) -> None:
        """Exception in _tick() is caught and loop continues."""
        svc = _make_service()
        scheduler = Scheduler(svc)

        call_count = 0

        def mock_tick() -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("tick boom")
            # Second call: signal stop
            scheduler._stop_event.set()

        with (
            patch.object(scheduler, "_tick", mock_tick),
            patch.object(scheduler, "_compute_sleep", lambda: 0.1),
        ):
            scheduler._run()

        # Should have called tick at least twice (error + stop)
        assert call_count >= 2

    def test_tick_handles_next_fire_runtime_error(self) -> None:
        """RuntimeError from next_fire_time is caught gracefully."""
        svc = _make_service()
        future = MagicMock()
        svc.pool.submit.return_value = future
        handler = MagicMock()
        svc.repo_handlers = {"test": handler}

        scheduler = Scheduler(svc)
        now = datetime.now(tz=UTC)

        bad_cron = MagicMock(spec=CronExpression)
        bad_cron.next_fire_time.side_effect = RuntimeError("no next fire")

        resolved = _ResolvedSchedule(
            repo_id="test",
            name="daily",
            config=_make_schedule_config(),
            cron=bad_cron,
            tz=ZoneInfo("UTC"),
            next_fire=now - timedelta(minutes=1),
        )
        scheduler._schedules = {"test": {"daily": resolved}}

        # Should not raise
        scheduler._tick()

        # Dispatch still happened
        svc.submit_task.assert_called_once()


class TestLocalTimezone:
    """Tests for _local_tz() timezone detection."""

    def test_tz_env_variable(self) -> None:
        """Uses TZ environment variable when set."""
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"TZ": "America/New_York"}):
            result = _local_tz()
        assert result == ZoneInfo("America/New_York")

    def test_tz_env_invalid_falls_through(self) -> None:
        """Invalid TZ value falls through to next method."""
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"TZ": "Invalid/Zone"}):
            result = _local_tz()
        assert isinstance(result, ZoneInfo)

    def test_etc_timezone_file(self) -> None:
        """Reads /etc/timezone when TZ is not set."""
        import os
        from pathlib import Path
        from unittest.mock import patch

        mock_read = MagicMock(return_value="Europe/Helsinki\n")
        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(Path, "read_text", mock_read),
        ):
            env = os.environ.copy()
            env.pop("TZ", None)
            with patch.dict(os.environ, env, clear=True):
                result = _local_tz()
        assert result == ZoneInfo("Europe/Helsinki")

    def test_fallback_to_utc(self) -> None:
        """Falls back to UTC when all methods fail."""
        import os
        from pathlib import Path
        from unittest.mock import patch

        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(Path, "read_text", side_effect=FileNotFoundError),
            patch.object(Path, "resolve", side_effect=FileNotFoundError),
        ):
            result = _local_tz()
        assert result == ZoneInfo("UTC")

    def test_etc_localtime_symlink(self) -> None:
        """Resolves /etc/localtime symlink to timezone name."""
        import os
        from pathlib import Path, PurePosixPath
        from unittest.mock import patch

        mock_path = PurePosixPath("/usr/share/zoneinfo/Asia/Tokyo")
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(Path, "read_text", side_effect=FileNotFoundError),
            patch.object(Path, "resolve", return_value=mock_path),
        ):
            result = _local_tz()
        assert result == ZoneInfo("Asia/Tokyo")

    def test_none_timezone_uses_local(self) -> None:
        """Scheduler uses _local_tz when config.timezone is None."""
        import os
        from unittest.mock import patch

        svc = _make_service()
        config = _make_schedule_config(timezone=None)
        handler = MagicMock()
        handler.config.repo_id = "test-repo"
        handler.config.schedules = {"daily": config}
        svc.repo_handlers = {"test-repo": handler}

        with patch.dict(os.environ, {"TZ": "America/Chicago"}):
            scheduler = Scheduler(svc)
            scheduler.rebuild_repo("test-repo")

        with scheduler._lock:
            sched = scheduler._schedules["test-repo"]["daily"]
            assert sched.tz == ZoneInfo("America/Chicago")


class TestSchedulerPackageExports:
    """Test scheduler package exports."""

    def test_exports_scheduler(self) -> None:
        import airut.gateway.scheduler as sched_pkg

        assert sched_pkg.Scheduler is Scheduler

    def test_exports_cron_expression(self) -> None:
        import airut.gateway.scheduler as sched_pkg

        assert sched_pkg.CronExpression is CronExpression
