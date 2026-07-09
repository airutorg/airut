# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Threading helpers shared across the gateway components."""

from __future__ import annotations

import threading


def join_if_started(thread: threading.Thread | None, timeout: float) -> bool:
    """Join ``thread`` unless it was never started.

    stop()/shutdown code usually runs on a different thread than the one
    that called ``start()``, so it can observe a ``Thread`` object in the
    window after it was assigned to an attribute but before its
    ``start()`` ran. ``Thread.join()`` on a not-yet-started thread raises
    ``RuntimeError("cannot join thread before it is started")``.

    ``is_alive()`` cannot be used to guard the join: it is ``False`` for
    both a never-started thread *and* one that already finished, but the
    latter is perfectly safe to join. stop() is never the thread being
    joined, so the only ``RuntimeError`` ``join()`` can raise here is the
    not-yet-started one — catch it and treat it as "nothing to wait for".

    Args:
        thread: The thread to join, or ``None``.
        timeout: Maximum number of seconds to wait for the join.

    Returns:
        ``True`` if the thread had been started (the join was attempted;
        the thread may still be alive if it did not finish within
        ``timeout``). ``False`` if ``thread`` was ``None`` or had not
        been started.
    """
    if thread is None:
        return False
    try:
        thread.join(timeout=timeout)
    except RuntimeError:
        return False
    return True
