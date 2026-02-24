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
    default_ignore_allowlist: bool = False

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "abbrev", "???") == "???":
            raise TypeError(
                f"{cls.__name__} must define a class-level 'abbrev' attribute"
            )

    def get_result_ttl(self, result: CheckResult, default_ttl: int) -> int:
        """Override for result-aware TTL. Default: return default_ttl.

        Note: ERR results are handled by the runner (using cache.error_ttl)
        before this method is called.
        """
        return default_ttl

    @abstractmethod
    async def run(self, target: str, context: CheckContext) -> CheckResult:
        """Run the check. context holds results/data from dependencies."""
        ...
