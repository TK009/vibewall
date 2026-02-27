from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from vibewall.cache.serde import deserialize, serialize
from vibewall.exceptions import CacheError

logger = logging.getLogger(__name__)

_FLUSH_INTERVAL = 0.5  # seconds between batch flushes


class _Op(Enum):
    SET = "set"
    DELETE = "delete"
    CLEAR = "clear"


@dataclass
class _WriteOp:
    op: _Op
    key: str = ""
    value: str = ""
    ttl: float = 0.0
    expires_at: float = 0.0
    updated_at: float = 0.0


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
    writes are batched and flushed periodically in the background.
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
        self._flush_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._loop: asyncio.AbstractEventLoop | None = None
        self._write_queue: deque[_WriteOp] = deque()

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
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def close(self) -> None:
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        # Drain any remaining queued writes
        await self._flush_writes()
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
            self._enqueue_delete(key)
            return None
        return entry.value

    def get_with_freshness(self, key: str) -> tuple[Any, bool] | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        now = time.time()
        if now > entry.expires_at:
            del self._data[key]
            self._enqueue_delete(key)
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
        self._enqueue_set(key, value, float(ttl), expires_at, now)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._enqueue_delete(key)

    def clear(self) -> None:
        self._data.clear()
        self._write_queue.clear()
        self._write_queue.append(_WriteOp(op=_Op.CLEAR))

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

    def _enqueue_set(
        self, key: str, value: Any, ttl: float, expires_at: float, updated_at: float,
    ) -> None:
        if self._db is None:
            return
        try:
            blob = serialize(value)
        except (TypeError, ValueError) as exc:
            logger.warning("cache_serialize_skip", extra={"key": key, "error": str(exc)})
            return
        self._write_queue.append(_WriteOp(
            op=_Op.SET, key=key, value=blob,
            ttl=ttl, expires_at=expires_at, updated_at=updated_at,
        ))

    def _enqueue_delete(self, key: str) -> None:
        if self._db is None:
            return
        self._write_queue.append(_WriteOp(op=_Op.DELETE, key=key))

    async def _flush_writes(self) -> None:
        if self._db is None or not self._write_queue:
            return
        try:
            while self._write_queue:
                op = self._write_queue.popleft()
                if op.op is _Op.SET:
                    await self._db.execute(
                        "INSERT OR REPLACE INTO cache_entries "
                        "(key, value, ttl, expires_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (op.key, op.value, op.ttl, op.expires_at, op.updated_at),
                    )
                elif op.op is _Op.DELETE:
                    await self._db.execute(
                        "DELETE FROM cache_entries WHERE key = ?", (op.key,),
                    )
                elif op.op is _Op.CLEAR:
                    await self._db.execute("DELETE FROM cache_entries")
            await self._db.commit()
        except CacheError:
            logger.exception("cache_flush_error")
        except Exception:
            logger.exception("cache_flush_error")

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(_FLUSH_INTERVAL)
            await self._flush_writes()

    # ------------------------------------------------------------------
    # Migration & warm-up
    # ------------------------------------------------------------------

    async def _migrate(self) -> None:
        assert self._db is not None
        await self._db.execute(
            "CREATE TABLE IF NOT EXISTS cache_meta "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        # Check existing schema version
        cursor = await self._db.execute(
            "SELECT value FROM cache_meta WHERE key = 'schema_version'"
        )
        row = await cursor.fetchone()
        existing_version = row[0] if row else None

        if existing_version == self._SCHEMA_VERSION:
            return

        # Fresh database or needs migration
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
        # Future migrations would go here, keyed on existing_version
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
            except CacheError:
                logger.warning("cache_deserialize_error", extra={"key": key})
                continue
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
                except CacheError:
                    logger.exception("cache_cleanup_error")
                except Exception:
                    logger.exception("cache_cleanup_error")


# Backwards-compatible alias
TTLCache = SQLiteCache
