from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vibewall.cache.serde import deserialize, serialize

logger = logging.getLogger(__name__)


@dataclass
class _Entry:
    value: Any
    expires_at: float
    ttl: float = 0.0
    updated_at: float = 0.0


class SQLiteCache:
    """L1 in-memory dict + L2 SQLite persistent cache.

    All public get/set/delete/clear methods are synchronous (matching the
    old TTLCache API) so callers in runner.py need zero changes.  SQLite
    writes are fire-and-forget background tasks.
    """

    _SCHEMA_VERSION = "1"

    def __init__(
        self,
        db_path: str = "~/.vibewall/cache.db",
        max_entries: int = 50000,
        cleanup_interval: int = 300,
    ) -> None:
        self._db_path = db_path
        self._max_entries = max_entries
        self._cleanup_interval = cleanup_interval
        self._data: dict[str, _Entry] = {}
        self._db: Any = None  # aiosqlite connection
        self._cleanup_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------
    # Async lifecycle
    # ------------------------------------------------------------------

    async def open(self) -> None:
        import aiosqlite

        if self._db_path == ":memory:":
            resolved = ":memory:"
        else:
            resolved = str(Path(self._db_path).expanduser())
            Path(resolved).parent.mkdir(parents=True, exist_ok=True)

        self._db = await aiosqlite.connect(resolved)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._migrate()
        await self._warm_l1()
        self._loop = asyncio.get_running_loop()
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def close(self) -> None:
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        if self._db is not None:
            await self._db.close()
            self._db = None

    # ------------------------------------------------------------------
    # Sync public API (unchanged from TTLCache)
    # ------------------------------------------------------------------

    def get(self, key: str) -> Any | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        if time.time() > entry.expires_at:
            del self._data[key]
            self._bg_delete(key)
            return None
        return entry.value

    def get_with_freshness(self, key: str) -> tuple[Any, bool] | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        now = time.time()
        if now > entry.expires_at:
            del self._data[key]
            self._bg_delete(key)
            return None
        remaining = entry.expires_at - now
        near_expiry = entry.ttl > 0 and remaining < entry.ttl * 0.2
        return (entry.value, near_expiry)

    def set(self, key: str, value: Any, ttl: int) -> None:
        if len(self._data) >= self._max_entries and key not in self._data:
            self.cleanup()
            if len(self._data) >= self._max_entries:
                self._evict_oldest(len(self._data) - self._max_entries + 1)
        now = time.time()
        expires_at = now + ttl
        self._data[key] = _Entry(
            value=value, expires_at=expires_at, ttl=float(ttl), updated_at=now,
        )
        self._bg_set(key, value, float(ttl), expires_at, now)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._bg_delete(key)

    def clear(self) -> None:
        self._data.clear()
        self._bg_clear()

    def cleanup(self) -> int:
        now = time.time()
        expired = [k for k, v in self._data.items() if now > v.expires_at]
        for k in expired:
            del self._data[k]
        return len(expired)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_oldest(self, count: int) -> None:
        if not self._data or count <= 0:
            return
        by_expiry = sorted(self._data.items(), key=lambda kv: kv[1].expires_at)
        for k, _ in by_expiry[:count]:
            del self._data[k]

    def _fire_and_forget(self, coro: Any) -> None:
        if self._db is None or self._loop is None:
            return
        try:
            task = self._loop.create_task(coro)
            task.add_done_callback(lambda t: _log_bg_error(t))
        except RuntimeError:
            pass  # loop closed

    def _bg_set(
        self, key: str, value: Any, ttl: float, expires_at: float, updated_at: float,
    ) -> None:
        if self._db is None:
            return

        async def _do() -> None:
            if self._db is None:
                return
            blob = serialize(value)
            await self._db.execute(
                "INSERT OR REPLACE INTO cache_entries "
                "(key, value, ttl, expires_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (key, blob, ttl, expires_at, updated_at),
            )
            await self._db.commit()

        self._fire_and_forget(_do())

    def _bg_delete(self, key: str) -> None:
        if self._db is None:
            return

        async def _do() -> None:
            if self._db is None:
                return
            await self._db.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
            await self._db.commit()

        self._fire_and_forget(_do())

    def _bg_clear(self) -> None:
        if self._db is None:
            return

        async def _do() -> None:
            if self._db is None:
                return
            await self._db.execute("DELETE FROM cache_entries")
            await self._db.commit()

        self._fire_and_forget(_do())

    # ------------------------------------------------------------------
    # Migration & warm-up
    # ------------------------------------------------------------------

    async def _migrate(self) -> None:
        assert self._db is not None
        await self._db.execute(
            "CREATE TABLE IF NOT EXISTS cache_meta "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        await self._db.execute(
            "CREATE TABLE IF NOT EXISTS cache_entries ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT NOT NULL,"
            "  ttl REAL NOT NULL,"
            "  expires_at REAL NOT NULL,"
            "  updated_at REAL NOT NULL"
            ")"
        )
        await self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_expires_at "
            "ON cache_entries(expires_at)"
        )
        # Set schema version
        await self._db.execute(
            "INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?, ?)",
            ("schema_version", self._SCHEMA_VERSION),
        )
        await self._db.commit()

    async def _warm_l1(self) -> None:
        assert self._db is not None
        now = time.time()
        # Delete expired rows first
        await self._db.execute(
            "DELETE FROM cache_entries WHERE expires_at < ?", (now,)
        )
        await self._db.commit()
        cursor = await self._db.execute(
            "SELECT key, value, ttl, expires_at, updated_at FROM cache_entries"
        )
        rows = await cursor.fetchall()
        for key, raw, ttl, expires_at, updated_at in rows:
            try:
                value = deserialize(raw)
            except Exception:
                logger.warning("cache_deserialize_error", extra={"key": key})
                continue
            self._data[key] = _Entry(
                value=value,
                expires_at=expires_at,
                ttl=ttl,
                updated_at=updated_at,
            )
        # Respect max_entries after warm-up
        if len(self._data) > self._max_entries:
            self._evict_oldest(len(self._data) - self._max_entries)

    # ------------------------------------------------------------------
    # Background cleanup loop
    # ------------------------------------------------------------------

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(self._cleanup_interval)
            self.cleanup()
            if self._db is not None:
                try:
                    await self._db.execute(
                        "DELETE FROM cache_entries WHERE expires_at < ?",
                        (time.time(),),
                    )
                    await self._db.commit()
                except Exception:
                    logger.exception("cache_cleanup_error")


def _log_bg_error(task: asyncio.Task) -> None:  # type: ignore[type-arg]
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("cache_bg_write_error: %s", exc)


# Backwards-compatible alias
TTLCache = SQLiteCache
