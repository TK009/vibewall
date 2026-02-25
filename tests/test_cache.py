from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

from vibewall.cache.store import SQLiteCache, TTLCache


# Helper to create a cache and open it
@pytest.fixture
async def cache(tmp_path):
    c = SQLiteCache(db_path=str(tmp_path / "test.db"), max_entries=50000)
    await c.open()
    yield c
    await c.close()


@pytest.fixture
async def memory_cache():
    c = SQLiteCache(db_path=":memory:", max_entries=50000)
    await c.open()
    yield c
    await c.close()


class TestBasic:
    async def test_get_missing_key(self, memory_cache: SQLiteCache) -> None:
        assert memory_cache.get("nonexistent") is None

    async def test_set_and_get(self, memory_cache: SQLiteCache) -> None:
        memory_cache.set("key", "value", ttl=60)
        assert memory_cache.get("key") == "value"

    async def test_overwrite_existing_key(self, memory_cache: SQLiteCache) -> None:
        memory_cache.set("key", "old", ttl=60)
        memory_cache.set("key", "new", ttl=60)
        assert memory_cache.get("key") == "new"

    async def test_delete(self, memory_cache: SQLiteCache) -> None:
        memory_cache.set("key", "value", ttl=60)
        memory_cache.delete("key")
        assert memory_cache.get("key") is None

    async def test_delete_nonexistent(self, memory_cache: SQLiteCache) -> None:
        memory_cache.delete("nonexistent")  # should not raise

    async def test_clear(self, memory_cache: SQLiteCache) -> None:
        memory_cache.set("a", 1, ttl=60)
        memory_cache.set("b", 2, ttl=60)
        memory_cache.clear()
        assert memory_cache.get("a") is None
        assert memory_cache.get("b") is None


class TestExpiration:
    async def test_expired_entry_returns_none(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("key", "value", ttl=10)
        with patch("vibewall.cache.store.time.time", return_value=now + 11):
            assert memory_cache.get("key") is None

    async def test_not_yet_expired_returns_value(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("key", "value", ttl=10)
        with patch("vibewall.cache.store.time.time", return_value=now + 9):
            assert memory_cache.get("key") == "value"

    async def test_expired_entry_is_deleted_on_get(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("key", "value", ttl=10)
        with patch("vibewall.cache.store.time.time", return_value=now + 11):
            memory_cache.get("key")
            assert "key" not in memory_cache._data


class TestCleanup:
    async def test_cleanup_removes_expired(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("expired1", "a", ttl=5)
            memory_cache.set("expired2", "b", ttl=10)
            memory_cache.set("alive", "c", ttl=100)
        with patch("vibewall.cache.store.time.time", return_value=now + 15):
            removed = memory_cache.cleanup()
            assert removed == 2
            assert memory_cache.get("alive") == "c"
            assert memory_cache.get("expired1") is None

    async def test_cleanup_nothing_expired(self, memory_cache: SQLiteCache) -> None:
        memory_cache.set("a", 1, ttl=60)
        assert memory_cache.cleanup() == 0


class TestEviction:
    async def test_evicts_oldest_when_at_capacity(self) -> None:
        cache = SQLiteCache(db_path=":memory:", max_entries=3)
        await cache.open()
        try:
            now = time.time()
            with patch("vibewall.cache.store.time.time", return_value=now):
                cache.set("a", 1, ttl=10)
                cache.set("b", 2, ttl=20)
                cache.set("c", 3, ttl=30)
            with patch("vibewall.cache.store.time.time", return_value=now + 1):
                cache.set("d", 4, ttl=50)
                assert cache.get("a") is None
                assert cache.get("b") == 2
                assert cache.get("d") == 4
        finally:
            await cache.close()

    async def test_evicts_expired_first_before_oldest(self) -> None:
        cache = SQLiteCache(db_path=":memory:", max_entries=3)
        await cache.open()
        try:
            now = time.time()
            with patch("vibewall.cache.store.time.time", return_value=now):
                cache.set("a", 1, ttl=5)
                cache.set("b", 2, ttl=100)
                cache.set("c", 3, ttl=100)
            with patch("vibewall.cache.store.time.time", return_value=now + 10):
                cache.set("d", 4, ttl=100)
                assert cache.get("a") is None
                assert cache.get("b") == 2
                assert cache.get("c") == 3
                assert cache.get("d") == 4
        finally:
            await cache.close()

    async def test_overwrite_does_not_evict(self) -> None:
        cache = SQLiteCache(db_path=":memory:", max_entries=2)
        await cache.open()
        try:
            cache.set("a", 1, ttl=60)
            cache.set("b", 2, ttl=60)
            cache.set("a", 10, ttl=60)
            assert cache.get("a") == 10
            assert cache.get("b") == 2
        finally:
            await cache.close()


class TestGetWithFreshness:
    async def test_missing_key_returns_none(self, memory_cache: SQLiteCache) -> None:
        assert memory_cache.get_with_freshness("x") is None

    async def test_expired_returns_none(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("key", "val", ttl=10)
        with patch("vibewall.cache.store.time.time", return_value=now + 11):
            assert memory_cache.get_with_freshness("key") is None

    async def test_fresh_entry_not_near_expiry(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("key", "val", ttl=100)
        with patch("vibewall.cache.store.time.time", return_value=now + 50):
            result = memory_cache.get_with_freshness("key")
            assert result is not None
            value, near_expiry = result
            assert value == "val"
            assert near_expiry is False

    async def test_near_expiry_within_20_percent(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("key", "val", ttl=100)
        with patch("vibewall.cache.store.time.time", return_value=now + 85):
            result = memory_cache.get_with_freshness("key")
            assert result is not None
            _, near_expiry = result
            assert near_expiry is True

    async def test_exactly_at_20_percent_not_near_expiry(self, memory_cache: SQLiteCache) -> None:
        now = time.time()
        with patch("vibewall.cache.store.time.time", return_value=now):
            memory_cache.set("key", "val", ttl=100)
        with patch("vibewall.cache.store.time.time", return_value=now + 80):
            result = memory_cache.get_with_freshness("key")
            assert result is not None
            _, near_expiry = result
            assert near_expiry is False

    async def test_ttl_stored_in_entry(self, memory_cache: SQLiteCache) -> None:
        memory_cache.set("key", "val", ttl=42)
        assert memory_cache._data["key"].ttl == 42.0


class TestPersistence:
    async def test_data_persists_across_restarts(self, tmp_path) -> None:
        db = str(tmp_path / "persist.db")

        c1 = SQLiteCache(db_path=db)
        await c1.open()
        c1.set("key1", "value1", ttl=3600)
        c1.set("key2", {"nested": True}, ttl=3600)
        await c1.close()

        c2 = SQLiteCache(db_path=db)
        await c2.open()
        assert c2.get("key1") == "value1"
        assert c2.get("key2") == {"nested": True}
        await c2.close()

    async def test_expired_entries_not_loaded(self, tmp_path) -> None:
        db = str(tmp_path / "expire.db")

        now = time.time()
        c1 = SQLiteCache(db_path=db)
        await c1.open()
        with patch("vibewall.cache.store.time.time", return_value=now):
            c1.set("short", "gone", ttl=1)
            c1.set("long", "here", ttl=3600)
        await c1.close()

        # Simulate time passing beyond the short TTL
        c2 = SQLiteCache(db_path=db)
        with patch("vibewall.cache.store.time.time", return_value=now + 5):
            await c2.open()
            assert c2.get("short") is None
            assert c2.get("long") == "here"
        await c2.close()


class TestCheckResultPersistence:
    async def test_check_result_round_trip(self, tmp_path) -> None:
        from vibewall.models import CheckResult, CheckStatus
        db = str(tmp_path / "cr.db")

        raw = CheckResult.ok("found", registry_data={"name": "test"})
        display = CheckResult.sus("downgraded")
        pair = (raw, display)

        c1 = SQLiteCache(db_path=db)
        await c1.open()
        c1.set("npm_registry:test", pair, ttl=3600)
        await c1.close()

        c2 = SQLiteCache(db_path=db)
        await c2.open()
        result = c2.get("npm_registry:test")
        assert result is not None
        assert isinstance(result, tuple)
        r0, r1 = result
        assert isinstance(r0, CheckResult)
        assert r0.status == CheckStatus.OK
        assert r0.data["registry_data"] == {"name": "test"}
        assert isinstance(r1, CheckResult)
        assert r1.status == CheckStatus.SUS
        await c2.close()


class TestAlias:
    def test_ttlcache_is_sqlitecache(self) -> None:
        assert TTLCache is SQLiteCache
