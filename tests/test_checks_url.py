from __future__ import annotations

import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.rules import RuleSet
from vibewall.validators.checks.url_rules import UrlRulesCheck
from vibewall.validators.checks.url_dns import UrlDnsCheck
from vibewall.validators.checks.url_domain_age import UrlDomainAgeCheck


class TestUrlRules:
    @pytest.mark.asyncio
    async def test_blocked(self, ruleset: RuleSet) -> None:
        check = UrlRulesCheck(ruleset=ruleset)
        result = await check.run("https://evil.example.com/payload", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "block" in result.reason

    @pytest.mark.asyncio
    async def test_not_blocked(self, ruleset: RuleSet) -> None:
        check = UrlRulesCheck(ruleset=ruleset)
        result = await check.run("https://safe.example.com/page", CheckContext())
        assert result.status == CheckStatus.OK

    @pytest.mark.asyncio
    async def test_allowlisted(self, ruleset: RuleSet) -> None:
        check = UrlRulesCheck(ruleset=ruleset)
        result = await check.run("https://github.com/some/repo", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["allowlisted"] is True

    @pytest.mark.asyncio
    async def test_not_allowlisted(self, ruleset: RuleSet) -> None:
        check = UrlRulesCheck(ruleset=ruleset)
        result = await check.run("https://unknown.com/page", CheckContext())
        assert result.status == CheckStatus.OK
        assert result.data["allowlisted"] is False


class TestUrlDns:
    @pytest.mark.asyncio
    async def test_dns_failure(self) -> None:
        async def fake_getaddrinfo(*args):
            raise socket.gaierror("Name resolution failed")

        loop_mock = MagicMock()
        loop_mock.getaddrinfo = fake_getaddrinfo

        with patch("asyncio.get_running_loop", return_value=loop_mock):
            check = UrlDnsCheck()
            result = await check.run("https://nonexistent.test/page", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "DNS" in result.reason

    @pytest.mark.asyncio
    async def test_dns_success(self) -> None:
        async def fake_getaddrinfo(*args):
            return [("AF_INET", None, None, None, ("1.2.3.4", 0))]

        loop_mock = MagicMock()
        loop_mock.getaddrinfo = fake_getaddrinfo

        with patch("asyncio.get_running_loop", return_value=loop_mock):
            check = UrlDnsCheck()
            result = await check.run("https://example.com/page", CheckContext())
        assert result.status == CheckStatus.OK


class TestUrlDomainAge:
    @pytest.mark.asyncio
    async def test_young_domain(self) -> None:
        young_date = datetime.now(timezone.utc) - timedelta(days=5)
        mock_whois = MagicMock()
        mock_whois.creation_date = young_date

        async def fake_run_in_executor(executor, fn, *args):
            return mock_whois

        loop_mock = MagicMock()
        loop_mock.run_in_executor = fake_run_in_executor

        with patch("asyncio.get_running_loop", return_value=loop_mock):
            check = UrlDomainAgeCheck(min_days=30)
            ctx = CheckContext()
            ctx.add("url_dns", CheckResult.ok("resolved"))
            result = await check.run("https://new-domain.xyz/page", ctx)
        assert result.status == CheckStatus.FAIL
        assert "days old" in result.reason

    @pytest.mark.asyncio
    async def test_old_domain(self) -> None:
        old_date = datetime.now(timezone.utc) - timedelta(days=365)
        mock_whois = MagicMock()
        mock_whois.creation_date = old_date

        async def fake_run_in_executor(executor, fn, *args):
            return mock_whois

        loop_mock = MagicMock()
        loop_mock.run_in_executor = fake_run_in_executor

        with patch("asyncio.get_running_loop", return_value=loop_mock):
            check = UrlDomainAgeCheck(min_days=30)
            ctx = CheckContext()
            ctx.add("url_dns", CheckResult.ok("resolved"))
            result = await check.run("https://old-domain.com/page", ctx)
        assert result.status == CheckStatus.OK

    @pytest.mark.asyncio
    async def test_whois_error_fails_open(self) -> None:
        async def fake_run_in_executor(executor, fn, *args):
            raise Exception("WHOIS server unreachable")

        loop_mock = MagicMock()
        loop_mock.run_in_executor = fake_run_in_executor

        with patch("asyncio.get_running_loop", return_value=loop_mock):
            check = UrlDomainAgeCheck(min_days=30)
            ctx = CheckContext()
            ctx.add("url_dns", CheckResult.ok("resolved"))
            result = await check.run("https://flaky.com/page", ctx)
        assert result.status == CheckStatus.ERR
