from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass
class _Entry:
    value: Any
    expires_at: float
    ttl: float = 0.0


class TTLCache:
    """In-memory cache with per-entry TTL and max-size eviction."""

    def __init__(self, max_entries: int = 50000) -> None:
        self._data: dict[str, _Entry] = {}
        self._max_entries = max_entries

    def get(self, key: str) -> Any | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            del self._data[key]
            return None
        return entry.value

    def get_with_freshness(self, key: str) -> tuple[Any, bool] | None:
        """Return (value, near_expiry) or None if missing/expired.

        ``near_expiry`` is True when the remaining TTL is less than 20%
        of the original TTL.
        """
        entry = self._data.get(key)
        if entry is None:
            return None
        now = time.monotonic()
        if now > entry.expires_at:
            del self._data[key]
            return None
        remaining = entry.expires_at - now
        near_expiry = entry.ttl > 0 and remaining < entry.ttl * 0.2
        return (entry.value, near_expiry)

    def set(self, key: str, value: Any, ttl: int) -> None:
        if len(self._data) >= self._max_entries and key not in self._data:
            self.cleanup()
            # If still at capacity after cleanup, evict oldest entries
            if len(self._data) >= self._max_entries:
                self._evict_oldest(len(self._data) - self._max_entries + 1)
        self._data[key] = _Entry(value=value, expires_at=time.monotonic() + ttl, ttl=float(ttl))

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()

    def cleanup(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        now = time.monotonic()
        expired = [k for k, v in self._data.items() if now > v.expires_at]
        for k in expired:
            del self._data[k]
        return len(expired)

    def _evict_oldest(self, count: int) -> None:
        """Evict the entries closest to expiration."""
        if not self._data or count <= 0:
            return
        by_expiry = sorted(self._data.items(), key=lambda kv: kv[1].expires_at)
        for k, _ in by_expiry[:count]:
            del self._data[k]
