from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from vibewall.models import CheckContext, CheckStatus
from vibewall.validators.checks.npm_advisories import (
    NpmAdvisoriesCheck,
    _cvss_to_severity,
    _extract_severity,
)


def _simple_response(status, json_data=None):
    resp = AsyncMock()
    resp.status = status
    if json_data is not None:
        resp.json = AsyncMock(return_value=json_data)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _make_session(status=200, json_data=None):
    session = MagicMock()
    session.post = MagicMock(return_value=_simple_response(status, json_data))
    return session


class TestCvssToSeverity:
    def test_critical(self) -> None:
        assert _cvss_to_severity(9.0) == "CRITICAL"
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_high(self) -> None:
        assert _cvss_to_severity(7.0) == "HIGH"
        assert _cvss_to_severity(8.9) == "HIGH"

    def test_moderate(self) -> None:
        assert _cvss_to_severity(4.0) == "MODERATE"
        assert _cvss_to_severity(6.9) == "MODERATE"

    def test_low(self) -> None:
        assert _cvss_to_severity(0.0) == "LOW"
        assert _cvss_to_severity(3.9) == "LOW"


class TestExtractSeverity:
    def test_database_specific_severity(self) -> None:
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        assert _extract_severity(vuln) == "CRITICAL"

    def test_database_specific_case_insensitive(self) -> None:
        vuln = {"database_specific": {"severity": "high"}}
        assert _extract_severity(vuln) == "HIGH"

    def test_cvss_v3_score(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert _extract_severity(vuln) == "CRITICAL"

    def test_fallback_to_high(self) -> None:
        vuln = {}
        assert _extract_severity(vuln) == "HIGH"

    def test_invalid_database_severity_falls_through(self) -> None:
        vuln = {"database_specific": {"severity": "UNKNOWN"}}
        assert _extract_severity(vuln) == "HIGH"


class TestNpmAdvisoriesCheck:
    async def test_no_vulns(self) -> None:
        session = _make_session(200, {"vulns": []})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("lodash", CheckContext())
        assert result.status == CheckStatus.OK
        assert "no known advisories" in result.reason

    async def test_no_vulns_key_missing(self) -> None:
        session = _make_session(200, {})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("lodash", CheckContext())
        assert result.status == CheckStatus.OK

    async def test_critical_vuln_blocks(self) -> None:
        session = _make_session(200, {"vulns": [
            {"id": "GHSA-1", "summary": "RCE", "database_specific": {"severity": "CRITICAL"}},
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("bad-pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert "1 actionable" in result.reason
        assert result.data["action_override"] == "block"

    async def test_low_vuln_allowed(self) -> None:
        session = _make_session(200, {"vulns": [
            {"id": "GHSA-2", "summary": "minor issue", "database_specific": {"severity": "LOW"}},
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.OK
        assert "below threshold" in result.reason

    async def test_high_vuln_warns(self) -> None:
        session = _make_session(200, {"vulns": [
            {"id": "GHSA-3", "summary": "XSS", "database_specific": {"severity": "HIGH"}},
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert result.data["action_override"] == "warn"

    async def test_mixed_severities_uses_most_restrictive(self) -> None:
        session = _make_session(200, {"vulns": [
            {"id": "GHSA-low", "summary": "low", "database_specific": {"severity": "LOW"}},
            {"id": "GHSA-crit", "summary": "critical", "database_specific": {"severity": "CRITICAL"}},
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert result.data["action_override"] == "block"

    async def test_custom_severity_actions(self) -> None:
        session = _make_session(200, {"vulns": [
            {"id": "GHSA-4", "summary": "moderate issue", "database_specific": {"severity": "MODERATE"}},
        ]})
        check = NpmAdvisoriesCheck(
            session=session,
            severity_medium="block",
        )
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert result.data["action_override"] == "block"

    async def test_api_error_fails_open(self) -> None:
        session = _make_session(500)
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.ERR
        assert "500" in result.reason

    async def test_timeout_fails_open(self) -> None:
        session = MagicMock()
        resp = AsyncMock()
        resp.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError)
        session.post = MagicMock(return_value=resp)
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.ERR
        assert "timed out" in result.reason

    async def test_client_error_fails_open(self) -> None:
        import aiohttp
        session = MagicMock()
        resp = AsyncMock()
        resp.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("connection reset"))
        session.post = MagicMock(return_value=resp)
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        assert result.status == CheckStatus.ERR
        assert "failed" in result.reason

    async def test_version_included_in_osv_payload(self) -> None:
        session = _make_session(200, {"vulns": []})
        check = NpmAdvisoriesCheck(session=session)
        await check.run("lodash", CheckContext(), version="4.17.21")
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["version"] == "4.17.21"

    async def test_no_version_omits_version_field(self) -> None:
        session = _make_session(200, {"vulns": []})
        check = NpmAdvisoriesCheck(session=session)
        await check.run("lodash", CheckContext())
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "version" not in payload

    async def test_version_filters_unaffected_vulns(self) -> None:
        session = _make_session(200, {"vulns": [
            {
                "id": "GHSA-old",
                "summary": "old vuln",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"versions": ["3.0.0", "3.1.0"]}],
            },
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("lodash", CheckContext(), version="4.17.21")
        assert result.status == CheckStatus.OK
        assert "no known advisories" in result.reason

    async def test_version_keeps_affected_vulns(self) -> None:
        session = _make_session(200, {"vulns": [
            {
                "id": "GHSA-bad",
                "summary": "bad vuln",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"versions": ["4.17.21", "4.17.20"]}],
            },
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("lodash", CheckContext(), version="4.17.21")
        assert result.status == CheckStatus.FAIL

    async def test_version_no_affected_data_assumes_affected(self) -> None:
        session = _make_session(200, {"vulns": [
            {
                "id": "GHSA-unk",
                "summary": "unknown",
                "database_specific": {"severity": "HIGH"},
            },
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("lodash", CheckContext(), version="4.17.21")
        assert result.status == CheckStatus.FAIL

    async def test_advisories_data_in_result(self) -> None:
        session = _make_session(200, {"vulns": [
            {
                "id": "GHSA-5",
                "summary": "prototype pollution",
                "details": "detailed description",
                "database_specific": {"severity": "HIGH"},
            },
        ]})
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run("pkg", CheckContext())
        advisories = result.data["advisories"]
        assert len(advisories) == 1
        assert advisories[0]["id"] == "GHSA-5"
        assert advisories[0]["severity"] == "HIGH"
        assert advisories[0]["summary"] == "prototype pollution"
