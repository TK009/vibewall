from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck


class PypiBlocklistCheck(BaseCheck):
    name = "pypi_blocklist"
    abbrev = "BLK"
    depends_on: list[str] = []
    scope = "pypi"

    def __init__(self, pypi_lists: AllowBlockList, **kwargs) -> None:
        self._lists = pypi_lists

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        if self._lists.is_blocked(target):
            return CheckResult.fail(f"package '{target}' is blocklisted")
        return CheckResult.ok(f"package '{target}' is not blocklisted")
