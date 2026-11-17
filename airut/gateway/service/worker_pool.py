# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared worker pool for message processing and scheduled runs.

Wraps a ``ThreadPoolExecutor`` that can be replaced while the gateway
runs (server reload) and detached on shutdown, and tracks submitted
futures for the shutdown drain.

Every submission reads the executor and submits under ``_lock``.  An
executor is shut down only after it has been swapped out under that
lock, so an executor read under the lock is always live: work never
lands on one that has been shut down.  ``_lock`` is a leaf (only the
executor's internal locks are taken while holding it).
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor


logger = logging.getLogger(__name__)

_THREAD_NAME_PREFIX = "ClaudeWorker"


class WorkerPool:
    """The gateway's shared worker pool.

    Not running until ``start()`` (or ``resize()``), and again after
    ``shutdown()``.
    """

    def __init__(self) -> None:
        self._executor: ThreadPoolExecutor | None = None
        self._max_workers: int | None = None
        self._lock = threading.Lock()
        self._futures: set[Future[None]] = set()
        self._futures_lock = threading.Lock()

    @property
    def running(self) -> bool:
        """Whether submissions are accepted."""
        return self._executor is not None

    @property
    def max_workers(self) -> int | None:
        """Worker count of the current executor, or None if not running."""
        return self._max_workers

    def start(self, max_workers: int) -> None:
        """Create the executor.

        Called once, at boot on the main thread.  Assigns without the
        lock: replacing None cannot strand work, and a signal-driven
        ``stop()`` on the main thread must never find the lock held.

        Args:
            max_workers: Number of worker threads.
        """
        self._max_workers = max_workers
        self._executor = _new_executor(max_workers)
        logger.info("Started execution pool with %d workers", max_workers)

    def resize(self, max_workers: int) -> None:
        """Replace the executor with one of ``max_workers`` workers.

        Work submitted just before the swap stays queued on the old
        executor, whose workers finish that queue, so concurrency can
        briefly exceed the new limit.  The old executor is never shut
        down with ``cancel_futures``: a cancelled run's tracker task
        would stay active forever.  A pool that is not running is
        started.

        Args:
            max_workers: Number of worker threads for the new executor.
        """
        old = self._swap(_new_executor(max_workers), max_workers)
        if old is not None:
            old.shutdown(wait=False)
        logger.info("Recreated execution pool with %d workers", max_workers)

    def submit[**P](
        self,
        fn: Callable[P, None],
        /,
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> Future[None] | None:
        """Run ``fn(*args, **kwargs)`` on the pool and track its future.

        Args:
            fn: Function to run on a worker thread.
            *args: Positional arguments for ``fn``.
            **kwargs: Keyword arguments for ``fn``.

        Returns:
            The future, or None if the pool is not running.
        """
        with self._lock:
            executor = self._executor
            if executor is None:
                return None
            future = executor.submit(fn, *args, **kwargs)

        with self._futures_lock:
            self._futures.add(future)
        # Outside both locks: runs at once if the future is done.
        future.add_done_callback(self._on_done)
        return future

    def drain(self, timeout: float) -> None:
        """Wait for submitted work until none remains or time runs out.

        Waits against a single deadline, re-reading the tracked futures
        each round: work finishing during the wait may submit more (a
        drained follow-up message), and that gets the rest of the
        grace period.  Futures still pending at the deadline are
        cancelled, which only affects those not yet started.

        Args:
            timeout: Grace period in seconds.
        """
        deadline = time.monotonic() + timeout
        pending = self._undone()
        if not pending:
            return
        logger.info(
            "Waiting for %d pending executions (timeout: %ds)...",
            len(pending),
            timeout,
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            concurrent.futures.wait(pending, timeout=remaining)
            pending = self._undone()
            if not pending:
                return

        logger.warning(
            "%d executions did not complete within timeout", len(pending)
        )
        for future in pending:
            future.cancel()

    def shutdown(self, *, cancel_futures: bool) -> None:
        """Detach the executor, then shut it down without waiting.

        Later submissions find no executor.

        Args:
            cancel_futures: Cancel work still queued on the executor.
        """
        old = self._swap(None, None)
        if old is not None:
            old.shutdown(wait=False, cancel_futures=cancel_futures)
            logger.info("Execution pool shut down")

    def _swap(
        self, new: ThreadPoolExecutor | None, max_workers: int | None
    ) -> ThreadPoolExecutor | None:
        """Install ``new`` under the lock and return the old executor.

        Once this returns, no submission can reach the old executor, so
        the caller may shut it down.
        """
        with self._lock:
            old, self._executor = self._executor, new
            self._max_workers = max_workers
        return old

    def _undone(self) -> set[Future[None]]:
        """Snapshot tracked futures that have not completed yet.

        A completed future may still be tracked until its done-callback
        runs.
        """
        with self._futures_lock:
            return {f for f in self._futures if not f.done()}

    def _on_done(self, future: Future[None]) -> None:
        """Stop tracking a finished future and log its failure, if any."""
        with self._futures_lock:
            self._futures.discard(future)

        try:
            exception = future.exception()
        except concurrent.futures.CancelledError:
            logger.debug("Worker task was cancelled")
            return
        if exception:
            logger.error("Worker task failed: %s", exception)


def _new_executor(max_workers: int) -> ThreadPoolExecutor:
    return ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix=_THREAD_NAME_PREFIX
    )
