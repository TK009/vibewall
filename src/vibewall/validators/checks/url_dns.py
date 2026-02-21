from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

import structlog

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck

logger = structlog.get_logger()


class UrlDnsCheck(BaseCheck):
    name = "url_dns"
    abbrev = "DNS"
    depends_on: list[str] = []
    scope = "url"

    def __init__(self, **kwargs) -> None:
        pass

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        domain = urlparse(target).hostname or ""
        if not domain:
            return CheckResult.fail("could not parse domain from URL")

        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(loop.getaddrinfo(domain, None), timeout=5)
            return CheckResult.ok(f"domain '{domain}' resolved")
        except socket.gaierror:
            return CheckResult.fail(
                f"domain '{domain}' failed DNS resolution (does not exist)"
            )
        except asyncio.TimeoutError:
            logger.warning("dns_timeout", domain=domain)
            return CheckResult.err("DNS lookup timed out, failing open")
