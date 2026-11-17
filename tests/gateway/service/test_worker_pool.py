# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the gateway's shared worker pool."""

import concurrent.futures
import logging
import threading
from collections.abc import Iterable, Iterator
from concurrent.futures import Future
from unittest.mock import DEFAULT, MagicMock, patch

import pytest

from airut.gateway.service.worker_pool import WorkerPool


@pytest.fixture
def pool() -> Iterator[WorkerPool]:
    pool = WorkerPool()
    try:
        yield pool
    finally:
        pool.shutdown(cancel_futures=True)


def _noop() -> None:
    pass


class TestLifecycle:
    def test_not_running_before_start(self) -> None:
        pool = WorkerPool()

        assert not pool.running
        assert pool.max_workers is None
        assert pool.submit(_noop) is None

    def test_start(self, pool: WorkerPool) -> None:
        pool.start(2)

        assert pool.running
        assert pool.max_workers == 2

    def test_shutdown_detaches(self, pool: WorkerPool) -> None:
        pool.start(1)

        pool.shutdown(cancel_futures=False)

        assert not pool.running
        assert pool.max_workers is None
        assert pool.submit(_noop) is None

    @pytest.mark.parametrize("cancel", [True, False])
    def test_shutdown_passes_cancel_futures(self, cancel: bool) -> None:
        pool = WorkerPool()
        with patch(
            "airut.gateway.service.worker_pool.ThreadPoolExecutor"
        ) as executor_cls:
            pool.start(1)
            pool.shutdown(cancel_futures=cancel)

        executor_cls.return_value.shutdown.assert_called_once_with(
            wait=False, cancel_futures=cancel
        )

    def test_shutdown_when_not_running(self) -> None:
        WorkerPool().shutdown(cancel_futures=True)  # Does not raise.


class TestSubmit:
    def test_runs_and_tracks_until_done(self, pool: WorkerPool) -> None:
        pool.start(1)
        release = threading.Event()
        calls: list[tuple[int, str]] = []

        def work(a: int, *, b: str) -> None:
            calls.append((a, b))
            release.wait(timeout=5)

        try:
            future = pool.submit(work, 1, b="x")
            assert future is not None
            assert pool._futures == {future}
        finally:
            release.set()

        # Callbacks run in registration order, so _on_done has run once
        # this one has.
        seen = threading.Event()
        future.add_done_callback(lambda f: seen.set())
        assert seen.wait(timeout=5)
        assert calls == [(1, "x")]
        assert pool._futures == set()

    def test_logs_worker_failure(
        self, pool: WorkerPool, caplog: pytest.LogCaptureFixture
    ) -> None:
        pool.start(1)

        def fail() -> None:
            raise RuntimeError("boom")

        with caplog.at_level(logging.ERROR):
            future = pool.submit(fail)
            assert future is not None
            seen = threading.Event()
            future.add_done_callback(lambda f: seen.set())
            assert seen.wait(timeout=5)

        assert "Worker task failed: boom" in caplog.text
        assert pool._futures == set()

    def test_holds_lock_while_submitting(self, pool: WorkerPool) -> None:
        pool.start(1)
        assert pool._executor is not None
        executor = pool._executor
        locked: list[bool] = []

        def record_lock(*args: object) -> object:
            locked.append(pool._lock.locked())
            return DEFAULT

        with patch.object(
            executor, "submit", wraps=executor.submit, side_effect=record_lock
        ):
            pool.submit(_noop)

        assert locked == [True]


class TestResize:
    def test_swaps_under_lock_before_shutting_down_old(self) -> None:
        pool = WorkerPool()
        pool.start(1)
        old = pool._executor
        assert old is not None
        events: list[tuple[str, object]] = []

        class RecordingLock:
            def __enter__(self) -> None:
                events.append(("lock", pool._executor))

            def __exit__(self, *exc: object) -> None:
                events.append(("unlock", pool._executor))

        def record_shutdown(**kwargs: object) -> object:
            events.append(("shutdown", pool._executor))
            return DEFAULT

        with (
            patch.object(pool, "_lock", RecordingLock()),
            patch.object(
                old, "shutdown", wraps=old.shutdown, side_effect=record_shutdown
            ),
        ):
            pool.resize(3)

        new = pool._executor
        try:
            assert new is not None
            assert new is not old
            assert pool.max_workers == 3
            # Swapped under the lock; the old executor is shut down after,
            # without cancelling its queue.
            assert events == [
                ("lock", old),
                ("unlock", new),
                ("shutdown", new),
            ]
        finally:
            pool.shutdown(cancel_futures=True)

    def test_work_queued_on_old_executor_still_runs(
        self, pool: WorkerPool
    ) -> None:
        pool.start(1)
        release = threading.Event()
        ran = threading.Event()

        def block() -> None:
            release.wait(timeout=5)

        try:
            pool.submit(block)  # Occupy the only worker.
            queued = pool.submit(ran.set)
            assert queued is not None

            pool.resize(2)
            release.set()

            assert ran.wait(timeout=5)
        finally:
            release.set()

    def test_starts_when_not_running(self, pool: WorkerPool) -> None:
        pool.resize(2)

        assert pool.running
        assert pool.max_workers == 2


class TestDrain:
    def test_no_pending_does_not_wait(self) -> None:
        pool = WorkerPool()
        with patch("concurrent.futures.wait") as wait:
            pool.drain(5)

        wait.assert_not_called()

    def test_follow_up_gets_rest_of_grace(self) -> None:
        """Work submitted during the wait is waited for too.

        A task finishing during the wait drains its conversation's
        queued message into the pool; the drain must wait for that new
        future too, but only until the original deadline.
        """
        pool = WorkerPool()
        first: Future[None] = Future()
        follow_up: Future[None] = Future()
        pool._futures.add(first)
        clock = [100.0]
        waits: list[tuple[set[Future[None]], float]] = []

        def fake_wait(futures: Iterable[Future[None]], timeout: float) -> None:
            waits.append((set(futures), timeout))
            if first in futures:
                # The first task finishes 2s in, draining its follow-up.
                clock[0] += 2
                pool._futures.add(follow_up)
                first.set_result(None)
            else:
                follow_up.set_result(None)

        with (
            patch("time.monotonic", side_effect=lambda: clock[0]),
            patch("concurrent.futures.wait", side_effect=fake_wait),
        ):
            pool.drain(5)

        assert waits == [({first}, 5), ({follow_up}, 3)]

    def test_cancels_pending_at_deadline(self) -> None:
        pool = WorkerPool()
        done: Future[None] = Future()
        done.set_result(None)
        pending: Future[None] = Future()
        pool._futures.update({done, pending})
        clock = [0.0]

        def fake_wait(futures: Iterable[Future[None]], timeout: float) -> None:
            clock[0] += timeout

        with (
            patch("time.monotonic", side_effect=lambda: clock[0]),
            patch("concurrent.futures.wait", side_effect=fake_wait),
        ):
            pool.drain(1)

        assert pending.cancelled()
        assert not done.cancelled()


class TestOnDone:
    def _future(self) -> MagicMock:
        future = MagicMock(spec=concurrent.futures.Future)
        future.exception.return_value = None
        return future

    def test_stops_tracking_only_that_future(self) -> None:
        pool = WorkerPool()
        f1, f2 = self._future(), self._future()
        pool._futures.update({f1, f2})

        pool._on_done(f1)

        assert pool._futures == {f2}

    def test_logs_exception(self, caplog: pytest.LogCaptureFixture) -> None:
        pool = WorkerPool()
        future = self._future()
        future.exception.return_value = RuntimeError("boom")

        with caplog.at_level(logging.ERROR):
            pool._on_done(future)

        assert "Worker task failed: boom" in caplog.text

    def test_handles_cancelled(self) -> None:
        pool = WorkerPool()
        future = self._future()
        future.exception.side_effect = concurrent.futures.CancelledError()
        pool._futures.add(future)

        pool._on_done(future)

        assert not pool._futures
