from __future__ import annotations

from abc import ABC, abstractmethod

from vibewall.models import CheckContext, CheckResult


class BaseCheck(ABC):
    name: str
    abbrev: str = "???"
    depends_on: list[str] = []
    scope: str  # "npm" or "url"
    default_action: str = "block"
    default_cache_ttl: int | None = None  # None = use global default

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "abbrev", "???") == "???":
            raise TypeError(
                f"{cls.__name__} must define a class-level 'abbrev' attribute"
            )

    @abstractmethod
    async def run(
        self, target: str, context: CheckContext, *, version: str | None = None
    ) -> CheckResult:
        """Run the check. context holds results/data from dependencies."""
        ...
