from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck


class NpmBlocklistCheck(BaseCheck):
    name = "npm_blocklist"
    depends_on: list[str] = []
    scope = "npm"

    def __init__(self, lists: AllowBlockList, **kwargs) -> None:
        self._lists = lists

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        if self._lists.is_blocked(target):
            return CheckResult.fail(f"package '{target}' is blocklisted")
        return CheckResult.ok(f"package '{target}' is not blocklisted")
