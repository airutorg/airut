# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the SeenKeyCache deduplication helper."""

from airut.gateway.dedup import DEFAULT_DEDUP_CAPACITY, SeenKeyCache


class TestSeenKeyCache:
    def test_claim_first_time_is_true(self) -> None:
        cache = SeenKeyCache()
        assert cache.claim("a") is True

    def test_claim_repeat_is_false(self) -> None:
        cache = SeenKeyCache()
        assert cache.claim("a") is True
        assert cache.claim("a") is False

    def test_distinct_keys_are_independent(self) -> None:
        cache = SeenKeyCache()
        assert cache.claim("a") is True
        assert cache.claim("b") is True

    def test_tuple_keys_supported(self) -> None:
        cache = SeenKeyCache()
        assert cache.claim(("C1", "T1")) is True
        assert cache.claim(("C1", "T1")) is False
        assert cache.claim(("C1", "T2")) is True

    def test_len_reflects_retained_keys(self) -> None:
        cache = SeenKeyCache()
        assert len(cache) == 0
        cache.claim("a")
        cache.claim("b")
        cache.claim("a")  # repeat does not grow the cache
        assert len(cache) == 2

    def test_eviction_evicts_oldest(self) -> None:
        cache = SeenKeyCache(capacity=2)
        assert cache.claim("a") is True
        assert cache.claim("b") is True
        assert len(cache) == 2
        # Third key pushes the cache over capacity; oldest ("a") evicted.
        assert cache.claim("c") is True
        assert len(cache) == 2
        # "b" is still remembered, "a" can be claimed again.
        assert cache.claim("b") is False
        assert cache.claim("a") is True

    def test_default_capacity(self) -> None:
        cache = SeenKeyCache()
        for i in range(DEFAULT_DEDUP_CAPACITY):
            assert cache.claim(i) is True
        assert len(cache) == DEFAULT_DEDUP_CAPACITY
        # One more key evicts the oldest; total stays at capacity.
        assert cache.claim("overflow") is True
        assert len(cache) == DEFAULT_DEDUP_CAPACITY
        assert cache.claim(0) is True
