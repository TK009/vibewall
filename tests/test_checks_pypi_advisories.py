from __future__ import annotations

from helpers import _make_session
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.checks.pypi_advisories import PypiAdvisoriesCheck


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


class TestPypiAdvisoryResultTTL:
    def test_ok_short_ttl(self) -> None:
        check = PypiAdvisoriesCheck.__new__(PypiAdvisoriesCheck)
        result = CheckResult.ok("no advisories")
        assert check.get_result_ttl(result, 3600) == max(300, 3600 // 4)

    def test_fail_all_fixed(self) -> None:
        check = PypiAdvisoriesCheck.__new__(PypiAdvisoriesCheck)
        result = CheckResult.fail(
            "1 advisory",
            advisories=[{"has_fix": True, "id": "CVE-1"}],
        )
        assert check.get_result_ttl(result, 3600) == 7200
