from __future__ import annotations

import time
from unittest.mock import patch

from vibewall.cache.store import TTLCache


class TestTTLCacheBasic:
    def test_get_missing_key(self) -> None:
        cache = TTLCache()
        assert cache.get("nonexistent") is None

    def test_set_and_get(self) -> None:
        cache = TTLCache()
        cache.set("key", "value", ttl=60)
        assert cache.get("key") == "value"

    def test_overwrite_existing_key(self) -> None:
        cache = TTLCache()
        cache.set("key", "old", ttl=60)
        cache.set("key", "new", ttl=60)
        assert cache.get("key") == "new"

    def test_delete(self) -> None:
        cache = TTLCache()
        cache.set("key", "value", ttl=60)
        cache.delete("key")
        assert cache.get("key") is None

    def test_delete_nonexistent(self) -> None:
        cache = TTLCache()
        cache.delete("nonexistent")  # should not raise

    def test_clear(self) -> None:
        cache = TTLCache()
        cache.set("a", 1, ttl=60)
        cache.set("b", 2, ttl=60)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None


class TestTTLExpiration:
    def test_expired_entry_returns_none(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "value", ttl=10)

        with patch("vibewall.cache.store.time.monotonic", return_value=now + 11):
            assert cache.get("key") is None

    def test_not_yet_expired_returns_value(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "value", ttl=10)

        with patch("vibewall.cache.store.time.monotonic", return_value=now + 9):
            assert cache.get("key") == "value"

    def test_expired_entry_is_deleted_on_get(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "value", ttl=10)

        with patch("vibewall.cache.store.time.monotonic", return_value=now + 11):
            cache.get("key")
            assert "key" not in cache._data


class TestCleanup:
    def test_cleanup_removes_expired(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("expired1", "a", ttl=5)
            cache.set("expired2", "b", ttl=10)
            cache.set("alive", "c", ttl=100)

        with patch("vibewall.cache.store.time.monotonic", return_value=now + 15):
            removed = cache.cleanup()
            assert removed == 2
            assert cache.get("alive") == "c"
            assert cache.get("expired1") is None

    def test_cleanup_nothing_expired(self) -> None:
        cache = TTLCache()
        cache.set("a", 1, ttl=60)
        assert cache.cleanup() == 0


class TestEviction:
    def test_evicts_oldest_when_at_capacity(self) -> None:
        cache = TTLCache(max_entries=3)
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("a", 1, ttl=10)   # expires at now+10
            cache.set("b", 2, ttl=20)   # expires at now+20
            cache.set("c", 3, ttl=30)   # expires at now+30

        # Adding a 4th entry should evict "a" (closest to expiration)
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 1):
            cache.set("d", 4, ttl=50)
            assert cache.get("a") is None
            assert cache.get("b") == 2
            assert cache.get("d") == 4

    def test_evicts_expired_first_before_oldest(self) -> None:
        cache = TTLCache(max_entries=3)
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("a", 1, ttl=5)
            cache.set("b", 2, ttl=100)
            cache.set("c", 3, ttl=100)

        # "a" is expired, cleanup should free space without evicting "b" or "c"
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 10):
            cache.set("d", 4, ttl=100)
            assert cache.get("a") is None
            assert cache.get("b") == 2
            assert cache.get("c") == 3
            assert cache.get("d") == 4

    def test_overwrite_does_not_evict(self) -> None:
        cache = TTLCache(max_entries=2)
        cache.set("a", 1, ttl=60)
        cache.set("b", 2, ttl=60)
        # Overwriting existing key shouldn't trigger eviction
        cache.set("a", 10, ttl=60)
        assert cache.get("a") == 10
        assert cache.get("b") == 2


class TestGetWithFreshness:
    def test_missing_key_returns_none(self) -> None:
        cache = TTLCache()
        assert cache.get_with_freshness("x") is None

    def test_expired_returns_none(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=10)
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 11):
            assert cache.get_with_freshness("key") is None

    def test_fresh_entry_not_near_expiry(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=100)
        # 50% remaining → not near expiry
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 50):
            result = cache.get_with_freshness("key")
            assert result is not None
            value, near_expiry = result
            assert value == "val"
            assert near_expiry is False

    def test_near_expiry_within_20_percent(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=100)
        # 15% remaining → near expiry
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 85):
            result = cache.get_with_freshness("key")
            assert result is not None
            _, near_expiry = result
            assert near_expiry is True

    def test_exactly_at_20_percent_not_near_expiry(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=100)
        # Exactly 20% remaining → not near_expiry (< not <=)
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 80):
            result = cache.get_with_freshness("key")
            assert result is not None
            _, near_expiry = result
            assert near_expiry is False

    def test_ttl_stored_in_entry(self) -> None:
        cache = TTLCache()
        cache.set("key", "val", ttl=42)
        assert cache._data["key"].ttl == 42.0
