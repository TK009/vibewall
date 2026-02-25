"""Merge two SQLite cache databases using last-write-wins semantics."""
from __future__ import annotations

import sqlite3
from pathlib import Path


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the cache schema if it doesn't exist."""
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


def merge_databases(target_path: str, source_path: str) -> int:
    """Merge *source_path* into *target_path*.

    If the target database does not exist, it is created with the
    required schema.  Entries from the source overwrite the target when
    the source's ``updated_at`` is newer.  Returns the number of rows
    inserted or replaced.
    """
    Path(target_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target_path)
    try:
        _ensure_schema(conn)
        conn.execute("ATTACH DATABASE ? AS source", (source_path,))
        cursor = conn.execute(
            """
            INSERT OR REPLACE INTO cache_entries
                (key, value, ttl, expires_at, updated_at)
            SELECT s.key, s.value, s.ttl, s.expires_at, s.updated_at
            FROM source.cache_entries s
            LEFT JOIN cache_entries t ON s.key = t.key
            WHERE t.key IS NULL OR s.updated_at > t.updated_at
            """
        )
        count = cursor.rowcount
        conn.commit()
        conn.execute("DETACH DATABASE source")
        return count
    finally:
        conn.close()
