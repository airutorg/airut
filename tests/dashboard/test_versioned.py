# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib.dashboard.versioned."""

import threading
import time
from dataclasses import dataclass

from airut.dashboard.versioned import VersionClock, Versioned, VersionedStore


class TestVersionClock:
    """Tests for VersionClock."""

    def test_initial_version_is_zero(self) -> None:
        clock = VersionClock()
        assert clock.version == 0

    def test_tick_increments_version(self) -> None:
        clock = VersionClock()
        v1 = clock.tick()
        assert v1 == 1
        v2 = clock.tick()
        assert v2 == 2

    def test_tick_returns_new_version(self) -> None:
        clock = VersionClock()
        for expected in range(1, 6):
            assert clock.tick() == expected
        assert clock.version == 5

    def test_wait_returns_immediately_when_already_advanced(self) -> None:
        clock = VersionClock()
        clock.tick()
        clock.tick()
        result = clock.wait(0, timeout=0.01)
        assert result == 2

    def test_wait_returns_none_on_timeout(self) -> None:
        clock = VersionClock()
        result = clock.wait(0, timeout=0.01)
        assert result is None

    def test_wait_wakes_on_tick(self) -> None:
        clock = VersionClock()
        results: list[int | None] = []

        def waiter() -> None:
            results.append(clock.wait(0, timeout=5.0))

        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.02)
        clock.tick()
        t.join(timeout=1.0)
        assert not t.is_alive()
        assert results == [1]

    def test_wait_handles_server_restart(self) -> None:
        """Return immediately when client has stale version."""
        clock = VersionClock()
        clock.tick()  # version=1
        # Client thinks version is 999 (from previous server)
        result = clock.wait(999, timeout=0.01)
        assert result == 1

    def test_multiple_waiters_all_wake(self) -> None:
        clock = VersionClock()
        results: list[int | None] = []
        lock = threading.Lock()

        def waiter() -> None:
            r = clock.wait(0, timeout=5.0)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=waiter) for _ in range(5)]
        for t in threads:
            t.start()
        time.sleep(0.02)
        clock.tick()
        for t in threads:
            t.join(timeout=1.0)
        assert all(not t.is_alive() for t in threads)
        assert len(results) == 5
        assert all(r == 1 for r in results)

    def test_version_is_monotonic_under_concurrent_ticks(self) -> None:
        clock = VersionClock()
        versions: list[int] = []
        lock = threading.Lock()

        def ticker() -> None:
            for _ in range(100):
                v = clock.tick()
                with lock:
                    versions.append(v)

        threads = [threading.Thread(target=ticker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(versions) == 400
        # All versions should be unique
        assert len(set(versions)) == 400
        assert clock.version == 400


class TestVersioned:
    """Tests for Versioned dataclass."""

    def test_versioned_holds_value_and_version(self) -> None:
        v = Versioned(version=42, value="hello")
        assert v.version == 42
        assert v.value == "hello"

    def test_versioned_is_immutable(self) -> None:
        v = Versioned(version=1, value="test")
        try:
            v.version = 2  # type: ignore[misc]
            assert False, "Should have raised"
        except AttributeError:
            pass


@dataclass(frozen=True)
class _SampleState:
    """Frozen dataclass for testing VersionedStore."""

    name: str
    count: int = 0


class TestVersionedStore:
    """Tests for VersionedStore."""

    def test_initial_value(self) -> None:
        clock = VersionClock()
        store = VersionedStore(_SampleState(name="init"), clock)
        snap = store.get()
        assert snap.version == 0
        assert snap.value.name == "init"

    def test_update_changes_value_and_version(self) -> None:
        clock = VersionClock()
        store = VersionedStore(_SampleState(name="init"), clock)
        new_version = store.update(_SampleState(name="updated", count=1))
        assert new_version == 1
        snap = store.get()
        assert snap.version == 1
        assert snap.value.name == "updated"
        assert snap.value.count == 1

    def test_update_ticks_shared_clock(self) -> None:
        clock = VersionClock()
        store_a = VersionedStore(_SampleState(name="a"), clock)
        store_b = VersionedStore(_SampleState(name="b"), clock)
        store_a.update(_SampleState(name="a2"))
        assert clock.version == 1
        store_b.update(_SampleState(name="b2"))
        assert clock.version == 2
        # Store versions are independent per-store
        assert store_a.get().version == 1
        assert store_b.get().version == 2

    def test_concurrent_updates(self) -> None:
        clock = VersionClock()
        store = VersionedStore(_SampleState(name="init"), clock)

        def updater(n: int) -> None:
            for i in range(50):
                store.update(_SampleState(name=f"t{n}", count=i))

        threads = [
            threading.Thread(target=updater, args=(n,)) for n in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 200 updates total
        assert clock.version == 200
        snap = store.get()
        assert snap.version == 200

    def test_update_wakes_clock_waiters(self) -> None:
        clock = VersionClock()
        store = VersionedStore(_SampleState(name="init"), clock)
        results: list[int | None] = []

        def waiter() -> None:
            results.append(clock.wait(0, timeout=5.0))

        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.02)
        store.update(_SampleState(name="updated"))
        t.join(timeout=1.0)
        assert not t.is_alive()
        assert results == [1]

    def test_get_returns_consistent_snapshot(self) -> None:
        clock = VersionClock()
        store = VersionedStore(_SampleState(name="v0"), clock)
        store.update(_SampleState(name="v1"))
        store.update(_SampleState(name="v2"))
        snap = store.get()
        # Should see version 2 and value "v2"
        assert snap.version == 2
        assert snap.value.name == "v2"
