from __future__ import annotations

import asyncio
from urllib.parse import quote

import aiohttp
import structlog

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck

logger = structlog.get_logger()


class NpmDownloadsCheck(BaseCheck):
    name = "npm_downloads"
    abbrev = " DL"
    depends_on: list[str] = []
    scope = "npm"
    default_action = "warn"
    default_cache_ttl = 86400

    def __init__(
        self, session: aiohttp.ClientSession, min_weekly: int = 10, **kwargs
    ) -> None:
        self._session = session
        self._min_weekly = min_weekly

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        encoded = quote(target, safe="@")
        url = f"https://api.npmjs.org/downloads/point/last-week/{encoded}"
        try:
            async with self._session.get(
                url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return CheckResult.err(
                        f"downloads API returned {resp.status}, failing open"
                    )
                data = await resp.json()
                downloads = data.get("downloads", 0)

                if downloads < self._min_weekly:
                    return CheckResult.fail(
                        f"package '{target}' has only {downloads} weekly downloads "
                        f"(minimum: {self._min_weekly})",
                        downloads=downloads,
                    )

                return CheckResult.ok(
                    f"package '{target}' has {downloads} weekly downloads",
                    downloads=downloads,
                )
        except asyncio.TimeoutError:
            logger.warning("npm_downloads_timeout", package=target)
            return CheckResult.err("downloads request timed out")
        except aiohttp.ClientError as e:
            logger.warning("npm_downloads_error", package=target, error=str(e))
            return CheckResult.err(f"downloads request failed: {e}")
