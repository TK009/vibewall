from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from helpers import _simple_response
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.checks.npm_blocklist import NpmBlocklistCheck
from vibewall.validators.checks.npm_allowlist import NpmAllowlistCheck
from vibewall.validators.checks.npm_registry import NpmRegistryCheck
from vibewall.validators.checks.npm_existence import NpmExistenceCheck
from vibewall.validators.checks.npm_typosquat import NpmTyposquatCheck
from vibewall.validators.checks.npm_age import NpmAgeCheck
from vibewall.validators.checks.npm_downloads import NpmDownloadsCheck


class TestNpmBlocklist:
    @pytest.mark.asyncio
    async def test_blocked(self, npm_lists: AllowBlockList) -> None:
        check = NpmBlocklistCheck(lists=npm_lists)
        result = await check.run("evil-package", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "blocklisted" in result.reason

    @pytest.mark.asyncio
    async def test_not_blocked(self, npm_lists: AllowBlockList) -> None:
        check = NpmBlocklistCheck(lists=npm_lists)
        result = await check.run("safe-package", CheckContext())
        assert result.status == CheckStatus.OK


class TestNpmAllowlist:
    @pytest.mark.asyncio
    async def test_allowlisted(self, npm_lists: AllowBlockList) -> None:
        check = NpmAllowlistCheck(lists=npm_lists)
        result = await check.run("lodash", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["allowlisted"] is True

    @pytest.mark.asyncio
    async def test_not_allowlisted(self, npm_lists: AllowBlockList) -> None:
        check = NpmAllowlistCheck(lists=npm_lists)
        result = await check.run("unknown-pkg", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["allowlisted"] is False


class TestNpmRegistry:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        session = MagicMock()
        session.get = MagicMock(
            return_value=_simple_response(200, {"name": "lodash"})
        )
        check = NpmRegistryCheck(session=session)
        result = await check.run("lodash", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["registry_data"] == {"name": "lodash"}
        assert result.data["status_code"] == 200

    @pytest.mark.asyncio
    async def test_404(self) -> None:
        session = MagicMock()
        session.get = MagicMock(return_value=_simple_response(404))
        check = NpmRegistryCheck(session=session)
        result = await check.run("nonexistent", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["status_code"] == 404

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        import asyncio
        session = MagicMock()
        resp = AsyncMock()
        resp.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError)
        session.get = MagicMock(return_value=resp)
        check = NpmRegistryCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.ERR


class TestNpmExistence:
    @pytest.mark.asyncio
    async def test_exists(self) -> None:
        ctx = CheckContext()
        ctx.add("npm_registry", CheckResult.ok("ok", registry_data={}, status_code=200))
        check = NpmExistenceCheck()
        result = await check.run("lodash", ctx)
        assert result.status == CheckStatus.OK

    @pytest.mark.asyncio
    async def test_not_found(self) -> None:
        ctx = CheckContext()
        ctx.add("npm_registry", CheckResult.ok("ok", registry_data={}, status_code=404))
        check = NpmExistenceCheck()
        result = await check.run("fake-pkg", ctx)
        assert result.status == CheckStatus.FAIL
        assert "hallucinated" in result.reason


class TestNpmTyposquat:
    @pytest.mark.asyncio
    async def test_typosquat_detected(self, npm_lists: AllowBlockList) -> None:
        ctx = CheckContext()
        ctx.add("npm_registry", CheckResult.ok("ok", registry_data={}, status_code=200))
        ctx.add("npm_allowlist", CheckResult.ok("not allowlisted", allowlisted=False))
        check = NpmTyposquatCheck(lists=npm_lists, max_distance=2)
        result = await check.run("expresx", ctx)
        assert result.status == CheckStatus.FAIL
        assert "typosquat" in result.reason

    @pytest.mark.asyncio
    async def test_short_name_skipped(self, npm_lists: AllowBlockList) -> None:
        ctx = CheckContext()
        ctx.add("npm_registry", CheckResult.ok("ok"))
        ctx.add("npm_allowlist", CheckResult.ok("not allowlisted", allowlisted=False))
        check = NpmTyposquatCheck(lists=npm_lists, max_distance=2)
        result = await check.run("ract", ctx)
        assert result.status == CheckStatus.OK

    @pytest.mark.asyncio
    async def test_allowlisted_skipped(self, npm_lists: AllowBlockList) -> None:
        ctx = CheckContext()
        ctx.add("npm_registry", CheckResult.ok("ok"))
        ctx.add("npm_allowlist", CheckResult.ok("allowlisted", allowlisted=True))
        check = NpmTyposquatCheck(lists=npm_lists, max_distance=2)
        result = await check.run("expresx", ctx)
        assert result.status == CheckStatus.OK


class TestNpmAge:
    @pytest.mark.asyncio
    async def test_old_package(self) -> None:
        ctx = CheckContext()
        ctx.add("npm_registry", CheckResult.ok(
            "ok", registry_data={"time": {"created": "2020-01-01T00:00:00Z"}}, status_code=200
        ))
        check = NpmAgeCheck(min_days=7)
        result = await check.run("lodash", ctx)
        assert result.status == CheckStatus.OK

    @pytest.mark.asyncio
    async def test_young_package(self) -> None:
        from datetime import datetime, timezone, timedelta
        young = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        ctx = CheckContext()
        ctx.add("npm_registry", CheckResult.ok(
            "ok", registry_data={"time": {"created": young}}, status_code=200
        ))
        check = NpmAgeCheck(min_days=7)
        result = await check.run("new-pkg", ctx)
        assert result.status == CheckStatus.FAIL
        assert "days old" in result.reason


class TestNpmDownloads:
    @pytest.mark.asyncio
    async def test_popular(self) -> None:
        session = MagicMock()
        session.get = MagicMock(
            return_value=_simple_response(200, {"downloads": 100000})
        )
        check = NpmDownloadsCheck(session=session, min_weekly=10)
        result = await check.run("lodash", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["downloads"] == 100000

    @pytest.mark.asyncio
    async def test_low_downloads(self) -> None:
        session = MagicMock()
        session.get = MagicMock(
            return_value=_simple_response(200, {"downloads": 2})
        )
        check = NpmDownloadsCheck(session=session, min_weekly=10)
        result = await check.run("obscure-pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "downloads" in result.reason
