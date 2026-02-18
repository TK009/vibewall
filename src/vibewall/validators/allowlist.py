from __future__ import annotations

from pathlib import Path


class AllowBlockList:
    """Manages allowlist and blocklist lookups."""

    def __init__(self, allowlist_path: Path | None = None, blocklist_path: Path | None = None) -> None:
        self._allowlist: frozenset[str] = frozenset()
        self._blocklist: frozenset[str] = frozenset()
        if allowlist_path and allowlist_path.exists():
            self._allowlist = frozenset(self._load(allowlist_path))
        if blocklist_path and blocklist_path.exists():
            self._blocklist = frozenset(self._load(blocklist_path))

    @staticmethod
    def _load(path: Path) -> set[str]:
        entries: set[str] = set()
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line.lower())
        return entries

    def is_allowed(self, name: str) -> bool:
        return name.lower() in self._allowlist

    def is_blocked(self, name: str) -> bool:
        return name.lower() in self._blocklist

    @property
    def allowlist(self) -> frozenset[str]:
        return self._allowlist
