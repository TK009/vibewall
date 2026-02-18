from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp
import structlog
import whois

from vibewall.cache.store import TTLCache
from vibewall.config import UrlConfig, CacheConfig
from vibewall.models import ValidationResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseValidator

logger = structlog.get_logger()


class UrlValidator(BaseValidator):
    def __init__(
        self,
        config: UrlConfig,
        cache_config: CacheConfig,
        cache: TTLCache,
        lists: AllowBlockList,
    ) -> None:
        self._config = config
        self._cache_config = cache_config
        self._cache = cache
        self._lists = lists
        # trust_env=False ensures requests bypass HTTP_PROXY and don't loop
        # back through the proxy itself.
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(trust_env=False)
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def validate(self, url: str) -> ValidationResult:
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        if not domain:
            return ValidationResult.block("could not parse domain from URL")

        # 1. Blocklist/allowlist by domain
        if self._lists.is_blocked(domain):
            return ValidationResult.block(f"domain '{domain}' is blocklisted")
        if self._lists.is_allowed(domain):
            return ValidationResult.allow(f"domain '{domain}' is allowlisted")

        # 2. Cache
        cache_key = f"url:{domain}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        # 3. DNS resolution
        dns_result = await self._check_dns(domain)
        if not dns_result.allowed:
            self._cache.set(cache_key, dns_result, self._cache_config.url_ttl)
            return dns_result

        # 4. HTTP HEAD + WHOIS in parallel
        head_task = self._check_head(url)
        whois_task = self._check_whois(domain)
        head_result, whois_result = await asyncio.gather(head_task, whois_task)

        if not head_result.allowed:
            self._cache.set(cache_key, head_result, self._cache_config.url_ttl)
            return head_result

        if not whois_result.allowed:
            self._cache.set(cache_key, whois_result, self._cache_config.whois_ttl)
            return whois_result

        result = ValidationResult.allow(f"domain '{domain}' passed all checks")
        self._cache.set(cache_key, result, self._cache_config.url_ttl)
        return result

    async def _check_dns(self, domain: str) -> ValidationResult:
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.getaddrinfo(domain, None),
                timeout=5,
            )
            return ValidationResult.allow("DNS resolved")
        except socket.gaierror:
            return ValidationResult.block(f"domain '{domain}' failed DNS resolution (does not exist)")
        except asyncio.TimeoutError:
            return ValidationResult.allow("DNS lookup timed out, failing open")

    async def _check_head(self, url: str) -> ValidationResult:
        try:
            session = await self._get_session()
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=True) as resp:
                if resp.status >= 500:
                    return ValidationResult.allow(f"HEAD returned {resp.status}, failing open")
                return ValidationResult.allow(f"HEAD returned {resp.status}")
        except asyncio.TimeoutError:
            return ValidationResult.allow("HEAD request timed out, failing open")
        except aiohttp.ClientError as e:
            # Fail open — a transient TLS/connection error shouldn't block
            # legitimate sites.
            logger.warning("head_request_error", url=url, error=str(e))
            return ValidationResult.allow(f"HEAD request failed: {e}, failing open")

    async def _check_whois(self, domain: str) -> ValidationResult:
        loop = asyncio.get_running_loop()
        try:
            w = await asyncio.wait_for(
                loop.run_in_executor(None, whois.whois, domain),
                timeout=3,
            )
            creation = w.creation_date
            if creation is None:
                return ValidationResult.allow("WHOIS has no creation date, failing open")
            if isinstance(creation, list):
                creation = creation[0]
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            if age_days < self._config.min_domain_age_days:
                return ValidationResult.block(
                    f"domain is only {age_days} days old (minimum: {self._config.min_domain_age_days})"
                )
            return ValidationResult.allow(f"domain age: {age_days} days")
        except asyncio.TimeoutError:
            return ValidationResult.allow("WHOIS timed out, failing open")
        except Exception as e:
            logger.warning("whois_error", domain=domain, error=str(e))
            return ValidationResult.allow(f"WHOIS error: {e}, failing open")
