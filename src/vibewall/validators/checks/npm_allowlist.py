from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck


class NpmAllowlistCheck(BaseCheck):
    name = "npm_allowlist"
    abbrev = "ALW"
    depends_on: list[str] = []
    scope = "npm"

    def __init__(self, lists: AllowBlockList, **kwargs) -> None:
        self._lists = lists

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        if self._lists.is_allowed(target):
            return CheckResult.ok(
                f"package '{target}' is allowlisted", allowlisted=True
            )
        return CheckResult.ok(
            f"package '{target}' is not allowlisted", allowlisted=False
        )
