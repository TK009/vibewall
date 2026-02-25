"""Merge two SQLite cache databases using last-write-wins semantics."""
from __future__ import annotations

import sqlite3


def merge_databases(target_path: str, source_path: str) -> int:
    """Merge *source_path* into *target_path*.

    Entries from the source overwrite the target when the source's
    ``updated_at`` is newer.  Returns the number of rows inserted or
    replaced.
    """
    conn = sqlite3.connect(target_path)
    try:
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
