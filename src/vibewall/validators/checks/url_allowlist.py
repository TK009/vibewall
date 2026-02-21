from __future__ import annotations

from urllib.parse import urlparse

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck


class UrlAllowlistCheck(BaseCheck):
    name = "url_allowlist"
    abbrev = "ALW"
    depends_on: list[str] = []
    scope = "url"

    def __init__(self, url_lists: AllowBlockList, **kwargs) -> None:
        self._lists = url_lists

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        domain = urlparse(target).hostname or ""
        if self._lists.is_allowed(domain):
            return CheckResult.ok(
                f"domain '{domain}' is allowlisted", allowlisted=True
            )
        return CheckResult.ok(
            f"domain '{domain}' is not allowlisted", allowlisted=False
        )
