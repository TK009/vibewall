from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from urllib.parse import quote

import aiohttp
import structlog
from rapidfuzz.distance import Levenshtein

from vibewall.cache.store import TTLCache
from vibewall.config import NpmConfig, CacheConfig
from vibewall.models import ValidationResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseValidator

logger = structlog.get_logger()

# Minimum package name length to apply typosquatting checks.
# Short names produce too many false positives (e.g. "zod" vs "nod").
_MIN_TYPOSQUAT_NAME_LEN = 6


class NpmValidator(BaseValidator):
    def __init__(
        self,
        config: NpmConfig,
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

    async def validate(self, package_name: str) -> ValidationResult:
        # 1. Blocklist
        if self._lists.is_blocked(package_name):
            return ValidationResult.block(f"package '{package_name}' is blocklisted")

        # 2. Allowlist
        if self._lists.is_allowed(package_name):
            return ValidationResult.allow(f"package '{package_name}' is allowlisted")

        # 3. Cache
        cache_key = f"npm:{package_name}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        # 4. Registry + download checks
        result = await self._check_registry(package_name)

        ttl = (
            self._cache_config.npm_positive_ttl
            if result.allowed
            else self._cache_config.npm_negative_ttl
        )
        self._cache.set(cache_key, result, ttl)
        return result

    async def _check_registry(self, package_name: str) -> ValidationResult:
        try:
            session = await self._get_session()

            # URL-encode the package name to prevent path injection
            # (scoped packages like @scope/name contain /)
            encoded_name = quote(package_name, safe="@")
            registry_url = f"https://registry.npmjs.org/{encoded_name}"
            async with session.get(registry_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 404:
                    return ValidationResult.block(
                        f"package '{package_name}' does not exist on npm registry (hallucinated)"
                    )
                if resp.status != 200:
                    logger.warning("npm_registry_error", package=package_name, status=resp.status)
                    return ValidationResult.allow(f"registry returned {resp.status}, failing open")
                registry_data = await resp.json()

            # Typosquatting check
            typosquat_result = self._check_typosquatting(package_name)
            if typosquat_result is not None:
                return typosquat_result

            # Package age check
            time_data = registry_data.get("time", {})
            created_str = time_data.get("created")
            if created_str:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days < self._config.min_package_age_days:
                    return ValidationResult.block(
                        f"package '{package_name}' is only {age_days} days old "
                        f"(minimum: {self._config.min_package_age_days})"
                    )

            # Download count check
            downloads_url = f"https://api.npmjs.org/downloads/point/last-week/{encoded_name}"
            async with session.get(downloads_url, timeout=aiohttp.ClientTimeout(total=10)) as dl_resp:
                if dl_resp.status == 200:
                    dl_data = await dl_resp.json()
                    downloads = dl_data.get("downloads", 0)
                    if downloads < self._config.min_weekly_downloads:
                        return ValidationResult.block(
                            f"package '{package_name}' has only {downloads} weekly downloads "
                            f"(minimum: {self._config.min_weekly_downloads})"
                        )

        except asyncio.TimeoutError:
            logger.warning("npm_validation_timeout", package=package_name)
            return ValidationResult.allow("validation timed out, failing open")
        except aiohttp.ClientError as e:
            logger.warning("npm_validation_error", package=package_name, error=str(e))
            return ValidationResult.allow(f"validation error: {e}, failing open")

        return ValidationResult.allow(f"package '{package_name}' passed all checks")

    def _check_typosquatting(self, package_name: str) -> ValidationResult | None:
        # Skip typosquatting check for short names — edit distance 2 from a
        # 3-4 char name covers too much of the namespace (false positives).
        if len(package_name) < _MIN_TYPOSQUAT_NAME_LEN:
            return None

        max_dist = self._config.max_typosquat_distance
        for known in self._lists.allowlist:
            if known == package_name:
                continue
            # rapidfuzz score_cutoff: returns max_dist+1 when actual distance
            # exceeds cutoff, so `dist <= max_dist` means "within threshold".
            dist = Levenshtein.distance(package_name, known, score_cutoff=max_dist)
            if dist <= max_dist:
                return ValidationResult.block(
                    f"package '{package_name}' looks like a typosquat of '{known}' "
                    f"(edit distance: {dist})"
                )
        return None
