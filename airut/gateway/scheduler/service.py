# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Cron scheduler for periodic tasks.

Runs a background thread that sleeps until the next scheduled fire
time, then submits tasks to the gateway's shared executor pool.
The scheduler is a service-level component, not a channel adapter.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo

from airut.gateway.scheduler.cron import CronExpression


if TYPE_CHECKING:
    from airut.gateway.config import ScheduleConfig
    from airut.gateway.service.gateway import GatewayService

logger = logging.getLogger(__name__)

#: Maximum sleep between wake-ups (seconds).  Ensures the scheduler
#: picks up schedules added by config reload within a bounded delay.
_MAX_SLEEP_SECONDS = 60.0


def _local_tz() -> ZoneInfo:
    """Return the server's local timezone as a ZoneInfo.

    Checks ``TZ`` environment variable, ``/etc/timezone``, and
    ``/etc/localtime`` symlink.  Falls back to UTC if the local
    zone cannot be determined.
    """
    import os

    tz_env = os.environ.get("TZ")
    if tz_env:
        try:
            return ZoneInfo(tz_env)
        except (KeyError, Exception):
            pass
    try:
        tz_name = Path("/etc/timezone").read_text().strip()
        if tz_name:
            return ZoneInfo(tz_name)
    except Exception:
        pass
    try:
        link = Path("/etc/localtime").resolve()
        parts = link.parts
        if "zoneinfo" in parts:
            idx = parts.index("zoneinfo")
            tz_name = "/".join(parts[idx + 1 :])
            return ZoneInfo(tz_name)
    except Exception:
        pass
    return ZoneInfo("UTC")


@dataclass
class _ResolvedSchedule:
    """Internal schedule state with pre-parsed cron and next fire time."""

    repo_id: str
    name: str
    config: ScheduleConfig
    cron: CronExpression
    tz: ZoneInfo
    next_fire: datetime  # timezone-aware, in UTC for comparison


class Scheduler:
    """Cron scheduler for periodic tasks.

    Runs a background thread that sleeps until the next scheduled fire
    time, then submits tasks to the gateway's shared executor pool.
    """

    def __init__(self, service: GatewayService) -> None:
        self._service = service
        self._lock = threading.Lock()
        self._schedules: dict[str, dict[str, _ResolvedSchedule]] = {}
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the scheduler background thread."""
        # Build initial schedules from current config
        for repo_id, handler in self._service.repo_handlers.items():
            self._build_repo_schedules(repo_id, handler.config.schedules)

        active = sum(len(v) for v in self._schedules.values())
        if active > 0:
            logger.info("Scheduler starting with %d active schedule(s)", active)
        else:
            logger.info("Scheduler starting (no active schedules)")

        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="Scheduler",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the scheduler thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Scheduler stopped")

    def rebuild_repo(self, repo_id: str) -> None:
        """Rebuild schedules for a repo after config reload.

        Removes all existing schedules for the repo and re-parses
        from the new config.
        """
        handler = self._service.repo_handlers.get(repo_id)
        schedules = handler.config.schedules if handler else {}
        with self._lock:
            self._schedules.pop(repo_id, None)
        self._build_repo_schedules(repo_id, schedules)
        active = len(self._schedules.get(repo_id, {}))
        logger.info(
            "Scheduler: rebuilt repo '%s' (%d schedule(s))",
            repo_id,
            active,
        )

    def remove_repo(self, repo_id: str) -> None:
        """Remove all schedules for a repo."""
        with self._lock:
            removed = self._schedules.pop(repo_id, {})
        if removed:
            logger.info(
                "Scheduler: removed %d schedule(s) for repo '%s'",
                len(removed),
                repo_id,
            )

    def _build_repo_schedules(
        self,
        repo_id: str,
        schedules: dict[str, ScheduleConfig],
    ) -> None:
        """Parse schedule configs and compute initial fire times."""
        now = datetime.now(tz=UTC)
        repo_schedules: dict[str, _ResolvedSchedule] = {}

        for name, config in schedules.items():
            if not config.enable:
                logger.info("Schedule '%s/%s': disabled", repo_id, name)
                continue
            try:
                cron = CronExpression(config.cron)
                tz = (
                    ZoneInfo(config.timezone)
                    if config.timezone
                    else _local_tz()
                )
                next_fire = cron.next_fire_time(now, tz)
                repo_schedules[name] = _ResolvedSchedule(
                    repo_id=repo_id,
                    name=name,
                    config=config,
                    cron=cron,
                    tz=tz,
                    next_fire=next_fire,
                )
                logger.info(
                    "Schedule '%s/%s': next fire at %s",
                    repo_id,
                    name,
                    next_fire.isoformat(),
                )
            except (ValueError, KeyError) as e:
                logger.error(
                    "Schedule '%s/%s': failed to initialize: %s",
                    repo_id,
                    name,
                    e,
                )

        if repo_schedules:
            with self._lock:
                self._schedules[repo_id] = repo_schedules

    def _run(self) -> None:
        """Scheduler thread main loop."""
        logger.debug("Scheduler thread started")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:
                logger.exception("Scheduler tick failed")

            # Sleep until next fire or max sleep
            sleep_seconds = self._compute_sleep()
            self._stop_event.wait(timeout=sleep_seconds)

        logger.debug("Scheduler thread exiting")

    def _tick(self) -> None:
        """Check for due schedules and dispatch them."""
        now = datetime.now(tz=UTC)
        due: list[_ResolvedSchedule] = []

        with self._lock:
            for repo_schedules in self._schedules.values():
                for sched in repo_schedules.values():
                    if sched.next_fire <= now:
                        due.append(sched)

        for sched in due:
            self._dispatch(sched)

            # Recompute next fire time.  This mutates outside the lock;
            # a concurrent rebuild_repo() may discard this object, making
            # the write benign.
            now = datetime.now(tz=UTC)
            try:
                sched.next_fire = sched.cron.next_fire_time(now, sched.tz)
                logger.info(
                    "Schedule '%s/%s': next fire at %s",
                    sched.repo_id,
                    sched.name,
                    sched.next_fire.isoformat(),
                )
            except RuntimeError:
                logger.error(
                    "Schedule '%s/%s': could not compute next fire time",
                    sched.repo_id,
                    sched.name,
                )

    def _compute_sleep(self) -> float:
        """Compute seconds until next fire or max sleep."""
        now = datetime.now(tz=UTC)
        earliest = _MAX_SLEEP_SECONDS

        with self._lock:
            for repo_schedules in self._schedules.values():
                for sched in repo_schedules.values():
                    delta = (sched.next_fire - now).total_seconds()
                    if delta < earliest:
                        earliest = delta

        return max(0.1, min(earliest, _MAX_SLEEP_SECONDS))

    def _dispatch(self, sched: _ResolvedSchedule) -> None:
        """Submit a scheduled task to the executor pool."""
        pool = self._service._executor_pool
        if pool is None:
            logger.error(
                "Schedule '%s/%s': executor pool not available",
                sched.repo_id,
                sched.name,
            )
            return

        handler = self._service.repo_handlers.get(sched.repo_id)
        if handler is None:
            logger.error(
                "Schedule '%s/%s': repo handler not found",
                sched.repo_id,
                sched.name,
            )
            return

        task_id = uuid.uuid4().hex[:12]
        self._service.tracker.add_task(
            task_id,
            f"scheduled: {sched.name}",
            repo_id=sched.repo_id,
            sender="scheduler",
        )
        # Scheduled tasks bypass the authentication queue, so
        # transition through AUTHENTICATING immediately so that
        # execute_scheduled_task can call set_executing().
        self._service.tracker.set_authenticating(task_id)

        logger.info(
            "Schedule '%s/%s': dispatching task %s",
            sched.repo_id,
            sched.name,
            task_id,
        )

        from airut.gateway.scheduler.execution import execute_scheduled_task

        future = pool.submit(
            execute_scheduled_task,
            self._service,
            handler,
            sched.name,
            sched.config,
            task_id,
        )

        with self._service._futures_lock:
            self._service._pending_futures.add(future)
        future.add_done_callback(self._service._on_future_complete)
