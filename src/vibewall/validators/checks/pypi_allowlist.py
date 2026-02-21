from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck


class PypiAllowlistCheck(BaseCheck):
    name = "pypi_allowlist"
    abbrev = "ALW"
    depends_on: list[str] = []
    scope = "pypi"

    def __init__(self, pypi_lists: AllowBlockList, **kwargs) -> None:
        self._lists = pypi_lists

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        if self._lists.is_allowed(target):
            return CheckResult.ok(
                f"package '{target}' is allowlisted", allowlisted=True
            )
        return CheckResult.ok(
            f"package '{target}' is not allowlisted", allowlisted=False
        )
