from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from helpers import _simple_response
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.checks.pypi_blocklist import PypiBlocklistCheck
from vibewall.validators.checks.pypi_allowlist import PypiAllowlistCheck
from vibewall.validators.checks.pypi_registry import PypiRegistryCheck
from vibewall.validators.checks.pypi_existence import PypiExistenceCheck
from vibewall.validators.checks.pypi_typosquat import PypiTyposquatCheck
from vibewall.validators.checks.pypi_age import PypiAgeCheck
from vibewall.validators.checks.pypi_downloads import PypiDownloadsCheck
from vibewall.validators.checks.pypi_advisories import PypiAdvisoriesCheck


class TestPypiBlocklist:
    async def test_blocked(self, pypi_lists: AllowBlockList) -> None:
        check = PypiBlocklistCheck(pypi_lists=pypi_lists)
        result = await check.run("evil-package", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "blocklisted" in result.reason

    async def test_not_blocked(self, pypi_lists: AllowBlockList) -> None:
        check = PypiBlocklistCheck(pypi_lists=pypi_lists)
        result = await check.run("safe-package", CheckContext())
        assert result.status == CheckStatus.OK


class TestPypiAllowlist:
    async def test_allowlisted(self, pypi_lists: AllowBlockList) -> None:
        check = PypiAllowlistCheck(pypi_lists=pypi_lists)
        result = await check.run("requests", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["allowlisted"] is True

    async def test_not_allowlisted(self, pypi_lists: AllowBlockList) -> None:
        check = PypiAllowlistCheck(pypi_lists=pypi_lists)
        result = await check.run("unknown-pkg", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["allowlisted"] is False


class TestPypiRegistry:
    async def test_success(self) -> None:
        session = MagicMock()
        session.get = MagicMock(
            return_value=_simple_response(200, {"info": {"name": "requests"}})
        )
        check = PypiRegistryCheck(session=session)
        result = await check.run("requests", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["registry_data"] == {"info": {"name": "requests"}}
        assert result.data["status_code"] == 200

    async def test_404(self) -> None:
        session = MagicMock()
        session.get = MagicMock(return_value=_simple_response(404))
        check = PypiRegistryCheck(session=session)
        result = await check.run("nonexistent", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["status_code"] == 404

    async def test_timeout(self) -> None:
        import asyncio
        session = MagicMock()
        resp = AsyncMock()
        resp.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError)
        session.get = MagicMock(return_value=resp)
        check = PypiRegistryCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.ERR


class TestPypiExistence:
    async def test_exists(self) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok("ok", registry_data={}, status_code=200))
        check = PypiExistenceCheck()
        result = await check.run("requests", ctx)
        assert result.status == CheckStatus.OK

    async def test_not_found(self) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok("ok", registry_data={}, status_code=404))
        check = PypiExistenceCheck()
        result = await check.run("fake-pkg", ctx)
        assert result.status == CheckStatus.FAIL
        assert "hallucinated" in result.reason


class TestPypiTyposquat:
    async def test_typosquat_detected(self, pypi_lists: AllowBlockList) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok("ok", registry_data={}, status_code=200))
        ctx.add("pypi_allowlist", CheckResult.ok("not allowlisted", allowlisted=False))
        check = PypiTyposquatCheck(pypi_lists=pypi_lists, max_distance=2)
        result = await check.run("requets", ctx)
        assert result.status == CheckStatus.FAIL
        assert "typosquat" in result.reason

    async def test_short_name_skipped(self, pypi_lists: AllowBlockList) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok("ok"))
        ctx.add("pypi_allowlist", CheckResult.ok("not allowlisted", allowlisted=False))
        check = PypiTyposquatCheck(pypi_lists=pypi_lists, max_distance=2)
        result = await check.run("flsk", ctx)
        assert result.status == CheckStatus.OK

    async def test_allowlisted_skipped(self, pypi_lists: AllowBlockList) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok("ok"))
        ctx.add("pypi_allowlist", CheckResult.ok("allowlisted", allowlisted=True))
        check = PypiTyposquatCheck(pypi_lists=pypi_lists, max_distance=2)
        result = await check.run("requets", ctx)
        assert result.status == CheckStatus.OK


class TestPypiAge:
    async def test_old_package(self) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok(
            "ok",
            registry_data={
                "releases": {
                    "1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
                }
            },
            status_code=200,
        ))
        check = PypiAgeCheck(min_days=7)
        result = await check.run("requests", ctx)
        assert result.status == CheckStatus.OK

    async def test_young_package(self) -> None:
        from datetime import datetime, timezone, timedelta
        young = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok(
            "ok",
            registry_data={
                "releases": {
                    "0.1": [{"upload_time_iso_8601": young}],
                }
            },
            status_code=200,
        ))
        check = PypiAgeCheck(min_days=7)
        result = await check.run("new-pkg", ctx)
        assert result.status == CheckStatus.FAIL
        assert "days old" in result.reason

    async def test_no_releases(self) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok(
            "ok", registry_data={"releases": {}}, status_code=200,
        ))
        check = PypiAgeCheck(min_days=7, missing_date="fail")
        result = await check.run("empty-pkg", ctx)
        assert result.status == CheckStatus.ERR

    async def test_no_releases_pass(self) -> None:
        ctx = CheckContext()
        ctx.add("pypi_registry", CheckResult.ok(
            "ok", registry_data={"releases": {}}, status_code=200,
        ))
        check = PypiAgeCheck(min_days=7, missing_date="pass")
        result = await check.run("empty-pkg", ctx)
        assert result.status == CheckStatus.OK


class TestPypiDownloads:
    async def test_popular(self) -> None:
        session = MagicMock()
        session.get = MagicMock(
            return_value=_simple_response(200, {"data": {"last_week": 100000}})
        )
        check = PypiDownloadsCheck(session=session, min_weekly=10)
        result = await check.run("requests", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["downloads"] == 100000

    async def test_low_downloads(self) -> None:
        session = MagicMock()
        session.get = MagicMock(
            return_value=_simple_response(200, {"data": {"last_week": 2}})
        )
        check = PypiDownloadsCheck(session=session, min_weekly=10)
        result = await check.run("obscure-pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "downloads" in result.reason


class TestPypiAdvisories:
    async def test_no_vulns(self) -> None:
        session = MagicMock()
        session.post = MagicMock(
            return_value=_simple_response(200, {"vulns": []})
        )
        check = PypiAdvisoriesCheck(session=session)
        result = await check.run("requests", CheckContext())
        assert result.status == CheckStatus.OK

    async def test_critical_vuln(self) -> None:
        session = MagicMock()
        session.post = MagicMock(
            return_value=_simple_response(200, {
                "vulns": [{
                    "id": "PYSEC-2021-001",
                    "summary": "critical vuln",
                    "database_specific": {"severity": "CRITICAL"},
                }]
            })
        )
        check = PypiAdvisoriesCheck(session=session)
        result = await check.run("vuln-pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "actionable" in result.reason

    async def test_low_vuln_allowed(self) -> None:
        session = MagicMock()
        session.post = MagicMock(
            return_value=_simple_response(200, {
                "vulns": [{
                    "id": "PYSEC-2021-002",
                    "summary": "low vuln",
                    "database_specific": {"severity": "LOW"},
                }]
            })
        )
        check = PypiAdvisoriesCheck(session=session, severity_low="allow")
        result = await check.run("minor-vuln-pkg", CheckContext())
        assert result.status == CheckStatus.OK

    async def test_api_error(self) -> None:
        session = MagicMock()
        session.post = MagicMock(
            return_value=_simple_response(500)
        )
        check = PypiAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.ERR
