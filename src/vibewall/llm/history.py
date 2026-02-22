from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from vibewall.models import CheckResult


@dataclass(frozen=True)
class HistoryEntry:
    scope: str
    target: str
    results: tuple[tuple[str, CheckResult], ...]
    outcome: str  # "allowed" or "blocked"


class RequestHistory:
    def __init__(self, maxlen: int = 50) -> None:
        self._entries: deque[HistoryEntry] = deque(maxlen=maxlen)

    def add(self, entry: HistoryEntry) -> None:
        self._entries.append(entry)

    def recent(self, n: int = 12) -> list[HistoryEntry]:
        items = list(self._entries)
        items.reverse()
        return items[:n]
