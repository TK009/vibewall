from __future__ import annotations

import sqlite3
import time

import pytest

from vibewall.cache.merge import merge_databases
from vibewall.cache.serde import serialize


def _init_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache_meta "
        "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache_entries ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL,"
        "  ttl REAL NOT NULL,"
        "  expires_at REAL NOT NULL,"
        "  updated_at REAL NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_expires_at "
        "ON cache_entries(expires_at)"
    )
    conn.execute(
        "INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?, ?)",
        ("schema_version", "1"),
    )
    conn.commit()
    conn.close()


def _insert(path: str, key: str, value: str, ttl: float, updated_at: float) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT OR REPLACE INTO cache_entries "
        "(key, value, ttl, expires_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (key, serialize(value), ttl, updated_at + ttl, updated_at),
    )
    conn.commit()
    conn.close()


def _get(path: str, key: str) -> tuple | None:
    conn = sqlite3.connect(path)
    row = conn.execute(
        "SELECT value, updated_at FROM cache_entries WHERE key = ?", (key,)
    ).fetchone()
    conn.close()
    return row


class TestMerge:
    def test_merge_new_entries(self, tmp_path) -> None:
        target = str(tmp_path / "target.db")
        source = str(tmp_path / "source.db")
        _init_db(target)
        _init_db(source)

        now = time.time()
        _insert(target, "a", "target_a", 3600, now)
        _insert(source, "b", "source_b", 3600, now)

        count = merge_databases(target, source)
        assert count == 1

        assert _get(target, "a") is not None
        assert _get(target, "b") is not None

    def test_merge_newer_overwrites(self, tmp_path) -> None:
        target = str(tmp_path / "target.db")
        source = str(tmp_path / "source.db")
        _init_db(target)
        _init_db(source)

        now = time.time()
        _insert(target, "key", "old", 3600, now)
        _insert(source, "key", "new", 3600, now + 10)

        count = merge_databases(target, source)
        assert count == 1

        row = _get(target, "key")
        assert row is not None
        from vibewall.cache.serde import deserialize
        assert deserialize(row[0]) == "new"

    def test_merge_older_does_not_overwrite(self, tmp_path) -> None:
        target = str(tmp_path / "target.db")
        source = str(tmp_path / "source.db")
        _init_db(target)
        _init_db(source)

        now = time.time()
        _insert(target, "key", "current", 3600, now + 10)
        _insert(source, "key", "old", 3600, now)

        count = merge_databases(target, source)
        assert count == 0

        row = _get(target, "key")
        assert row is not None
        from vibewall.cache.serde import deserialize
        assert deserialize(row[0]) == "current"

    def test_merge_empty_source(self, tmp_path) -> None:
        target = str(tmp_path / "target.db")
        source = str(tmp_path / "source.db")
        _init_db(target)
        _init_db(source)

        _insert(target, "a", "val", 3600, time.time())
        count = merge_databases(target, source)
        assert count == 0

    def test_merge_creates_target_if_missing(self, tmp_path) -> None:
        target = str(tmp_path / "newdir" / "target.db")
        source = str(tmp_path / "source.db")
        _init_db(source)

        now = time.time()
        _insert(source, "key", "val", 3600, now)

        count = merge_databases(target, source)
        assert count == 1
        assert _get(target, "key") is not None
