from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog
import whois

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck

logger = structlog.get_logger()


class UrlDomainAgeCheck(BaseCheck):
    name = "url_domain_age"
    abbrev = "AGE"
    depends_on = ["url_dns"]
    scope = "url"
    default_cache_ttl = 604800

    def __init__(self, min_days: int = 30, **kwargs) -> None:
        self._min_days = min_days

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        from urllib.parse import urlparse

        domain = urlparse(target).hostname or ""
        loop = asyncio.get_running_loop()
        try:
            w = await asyncio.wait_for(
                loop.run_in_executor(None, whois.whois, domain), timeout=3
            )
            creation = w.creation_date
            if creation is None:
                return CheckResult.ok("WHOIS has no creation date, passing")
            if isinstance(creation, list):
                creation = creation[0]
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            if age_days < self._min_days:
                return CheckResult.fail(
                    f"domain is only {age_days} days old (minimum: {self._min_days})"
                )
            return CheckResult.ok(f"domain age: {age_days} days")
        except asyncio.TimeoutError:
            return CheckResult.err("WHOIS timed out, failing open")
        except Exception as e:  # whois lib raises varied exceptions
            logger.warning("whois_error", domain=domain, error=type(e).__name__, detail=str(e))
            return CheckResult.err(f"WHOIS error: {e}, failing open")
