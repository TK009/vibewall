from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck


class UrlBlocklistCheck(BaseCheck):
    name = "url_blocklist"
    abbrev = "BLK"
    depends_on: list[str] = []
    scope = "url"

    def __init__(self, url_lists: AllowBlockList, **kwargs) -> None:
        self._lists = url_lists

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        domain = _extract_domain(target)
        if self._lists.is_blocked(domain):
            return CheckResult.fail(f"domain '{domain}' is blocklisted")
        return CheckResult.ok(f"domain '{domain}' is not blocklisted")


def _extract_domain(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).hostname or ""
