from __future__ import annotations

import asyncio
from urllib.parse import quote

import aiohttp
import structlog

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck

logger = structlog.get_logger()


class PypiRegistryCheck(BaseCheck):
    name = "pypi_registry"
    abbrev = "REG"
    depends_on: list[str] = []
    scope = "pypi"
    default_action = "warn"
    default_cache_ttl = 86400

    def __init__(self, session: aiohttp.ClientSession, **kwargs) -> None:
        self._session = session

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        encoded = quote(target, safe="")
        url = f"https://pypi.org/pypi/{encoded}/json"
        try:
            async with self._session.get(
                url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json() if resp.status == 200 else {}
                return CheckResult.ok(
                    f"registry returned {resp.status}",
                    registry_data=data,
                    status_code=resp.status,
                )
        except asyncio.TimeoutError:
            logger.warning("pypi_registry_timeout", package=target)
            return CheckResult.err("registry request timed out")
        except aiohttp.ClientError as e:
            logger.warning("pypi_registry_error", package=target, error=str(e))
            return CheckResult.err(f"registry request failed: {e}")
