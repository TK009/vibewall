from __future__ import annotations

from abc import ABC, abstractmethod

from vibewall.models import CheckContext, CheckResult


class BaseCheck(ABC):
    name: str
    abbrev: str = "???"
    depends_on: list[str] = []
    scope: str  # "npm" or "url"

    @abstractmethod
    async def run(self, target: str, context: CheckContext) -> CheckResult:
        """Run the check. context holds results/data from dependencies."""
        ...
