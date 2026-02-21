from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from vibewall.models import CheckContext, CheckStatus
from vibewall.validators.checks.pypi_advisories import PypiAdvisoriesCheck


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


class TestPypiAdvisoriesCheck:
    async def test_no_vulns(self) -> None:
        session = _make_session(200, {"vulns": []})
        check = PypiAdvisoriesCheck(session=session)
        result = await check.run("requests", CheckContext())
        assert result.status == CheckStatus.OK
        assert "no known advisories" in result.reason

    async def test_version_included_in_osv_payload(self) -> None:
        session = _make_session(200, {"vulns": []})
        check = PypiAdvisoriesCheck(session=session)
        await check.run("requests@2.28.0", CheckContext(version="2.28.0"))
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["version"] == "2.28.0"
        assert payload["package"]["name"] == "requests"
        assert payload["package"]["ecosystem"] == "PyPI"

    async def test_no_version_omits_version_field(self) -> None:
        session = _make_session(200, {"vulns": []})
        check = PypiAdvisoriesCheck(session=session)
        await check.run("requests", CheckContext())
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "version" not in payload

    async def test_version_filters_unaffected_vulns(self) -> None:
        session = _make_session(200, {"vulns": [
            {
                "id": "PYSEC-old",
                "summary": "old vuln",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"versions": ["2.20.0", "2.21.0"]}],
            },
        ]})
        check = PypiAdvisoriesCheck(session=session)
        result = await check.run("requests", CheckContext(version="2.28.0"))
        assert result.status == CheckStatus.OK
        assert "no known advisories" in result.reason

    async def test_version_keeps_affected_vulns(self) -> None:
        session = _make_session(200, {"vulns": [
            {
                "id": "PYSEC-bad",
                "summary": "bad vuln",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"versions": ["2.28.0", "2.27.0"]}],
            },
        ]})
        check = PypiAdvisoriesCheck(session=session)
        result = await check.run("requests", CheckContext(version="2.28.0"))
        assert result.status == CheckStatus.FAIL

    async def test_critical_vuln_blocks(self) -> None:
        session = _make_session(200, {"vulns": [
            {"id": "PYSEC-1", "summary": "RCE", "database_specific": {"severity": "CRITICAL"}},
        ]})
        check = PypiAdvisoriesCheck(session=session)
        result = await check.run("bad-pkg", CheckContext())
        assert result.status == CheckStatus.FAIL
        assert result.data["action_override"] == "block"
