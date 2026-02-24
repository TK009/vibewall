from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from helpers import _make_session, _simple_response
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.checks.npm_advisories import NpmAdvisoriesCheck


_FAST_XML_PARSER_OSV = {"vulns": [
    {
        "id": "GHSA-jmr7-xgp7-cmfj",
        "summary": "DoS through entity expansion in DOCTYPE",
        "database_specific": {"severity": "HIGH"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        "affected": [{
            "package": {"name": "fast-xml-parser", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "4.1.3"}, {"fixed": "5.3.6"},
            ]}],
        }],
    },
    {
        "id": "GHSA-m7jm-9gc2-mpf2",
        "summary": "Entity encoding bypass via regex injection",
        "database_specific": {"severity": "CRITICAL"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"}],
        "affected": [{
            "package": {"name": "fast-xml-parser", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "4.1.3"}, {"fixed": "5.3.5"},
            ]}],
        }],
    },
]}


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
        await check.run("lodash@4.17.21", CheckContext(version="4.17.21"))
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["version"] == "4.17.21"
        assert payload["package"]["name"] == "lodash"

    async def test_no_version_omits_version_field(self) -> None:
        session = _make_session(200, {"vulns": []})
        check = NpmAdvisoriesCheck(session=session)
        await check.run("lodash", CheckContext())
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "version" not in payload

    async def test_versioned_target_strips_at_version_for_api(self) -> None:
        """The addon passes 'pkg@1.0.0' as target for cache isolation.
        The check must strip the @version suffix for the OSV API call."""
        session = _make_session(200, {"vulns": []})
        check = NpmAdvisoriesCheck(session=session)
        await check.run("@babel/core@7.24.0", CheckContext(version="7.24.0"))
        call_kwargs = session.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["package"]["name"] == "@babel/core"
        assert payload["version"] == "7.24.0"

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
        result = await check.run("lodash", CheckContext(version="4.17.21"))
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
        result = await check.run("lodash", CheckContext(version="4.17.21"))
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
        result = await check.run("lodash", CheckContext(version="4.17.21"))
        assert result.status == CheckStatus.FAIL

    async def test_real_osv_response_fast_xml_parser(self) -> None:
        """Test with a realistic OSV response based on fast-xml-parser@5.3.4.

        This response has two vulns with only CVSS vector strings (no plain
        numeric scores), and only ranges (no explicit versions list) in the
        affected entries.  Exercises:
          - database_specific.severity extraction (HIGH + CRITICAL)
          - CVSS vector string is NOT misinterpreted as a numeric score
          - affects_version with ranges-only conservatively matches
          - most-restrictive action wins (CRITICAL → block with defaults)
        """
        osv_response = _FAST_XML_PARSER_OSV
        session = _make_session(200, osv_response)
        check = NpmAdvisoriesCheck(session=session)
        result = await check.run(
            "fast-xml-parser@5.3.4", CheckContext(version="5.3.4"),
        )

        assert result.status == CheckStatus.FAIL
        assert result.data["action_override"] == "block"
        advisories = result.data["advisories"]
        assert len(advisories) == 2
        severities = {a["severity"] for a in advisories}
        assert severities == {"HIGH", "CRITICAL"}
        ids = {a["id"] for a in advisories}
        assert "GHSA-jmr7-xgp7-cmfj" in ids
        assert "GHSA-m7jm-9gc2-mpf2" in ids

    async def test_real_osv_response_with_config_severity_actions(self) -> None:
        """With vibewall.toml severity settings (critical=ask, high=warn),
        the most restrictive action should be 'ask', not 'block'."""
        session = _make_session(200, _FAST_XML_PARSER_OSV)
        check = NpmAdvisoriesCheck(
            session=session,
            severity_low="allow",
            severity_medium="warn",
            severity_high="warn",
            severity_critical="ask-block",
        )
        result = await check.run(
            "fast-xml-parser@5.3.4", CheckContext(version="5.3.4"),
        )

        assert result.status == CheckStatus.FAIL
        assert result.data["action_override"] == "ask-block"
        # Verify per-advisory actions reflect config
        advisories = result.data["advisories"]
        by_id = {a["id"]: a for a in advisories}
        assert by_id["GHSA-jmr7-xgp7-cmfj"]["action"] == "warn"
        assert by_id["GHSA-m7jm-9gc2-mpf2"]["action"] == "ask-block"

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


class TestAdvisoryRunnerIntegration:
    """End-to-end tests running npm_advisories through CheckRunner with config."""

    async def test_ask_block_triggers_prompt(self) -> None:
        """With severity_critical='ask-block', the runner should invoke on_ask
        and downgrade to SUS when the user approves."""
        from vibewall.cache.store import TTLCache
        from vibewall.config import VibewallConfig, ValidatorConfig
        from vibewall.validators.runner import CheckRunner

        session = _make_session(200, _FAST_XML_PARSER_OSV)
        check = NpmAdvisoriesCheck(
            session=session,
            severity_low="allow",
            severity_medium="warn",
            severity_high="warn",
            severity_critical="ask-block",
        )

        config = VibewallConfig()
        config.validators["npm_advisories"] = ValidatorConfig(
            action="block", params={},
        )
        runner = CheckRunner([check], config, TTLCache(max_entries=100))

        on_ask = AsyncMock(return_value=True)  # user approves
        pipeline = await runner.run(
            "npm", "fast-xml-parser@5.3.4",
            on_ask=on_ask,
            version="5.3.4",
            check_names={"npm_advisories"},
        )

        on_ask.assert_called_once()
        # Approved ask → SUS (warning), request allowed through
        assert pipeline.run_result.allowed is True
        check_results = dict(pipeline.run_result.results)
        assert check_results["npm_advisories"].status == CheckStatus.SUS

    async def test_ask_block_denied_blocks(self) -> None:
        """When the user denies an ask-block prompt, the request should be blocked."""
        from vibewall.cache.store import TTLCache
        from vibewall.config import VibewallConfig, ValidatorConfig
        from vibewall.validators.runner import CheckRunner

        session = _make_session(200, _FAST_XML_PARSER_OSV)
        check = NpmAdvisoriesCheck(
            session=session,
            severity_low="allow",
            severity_medium="warn",
            severity_high="warn",
            severity_critical="ask-block",
        )

        config = VibewallConfig()
        config.validators["npm_advisories"] = ValidatorConfig(
            action="block", params={},
        )
        runner = CheckRunner([check], config, TTLCache(max_entries=100))

        on_ask = AsyncMock(return_value=False)  # user denies
        pipeline = await runner.run(
            "npm", "fast-xml-parser@5.3.4",
            on_ask=on_ask,
            version="5.3.4",
            check_names={"npm_advisories"},
        )

        on_ask.assert_called_once()
        assert pipeline.run_result.allowed is False
        check_results = dict(pipeline.run_result.results)
        assert check_results["npm_advisories"].status == CheckStatus.FAIL

    async def test_ask_block_no_callback_blocks(self) -> None:
        """Without an on_ask callback (headless mode), ask-block should block."""
        from vibewall.cache.store import TTLCache
        from vibewall.config import VibewallConfig, ValidatorConfig
        from vibewall.validators.runner import CheckRunner

        session = _make_session(200, _FAST_XML_PARSER_OSV)
        check = NpmAdvisoriesCheck(
            session=session,
            severity_low="allow",
            severity_medium="warn",
            severity_high="warn",
            severity_critical="ask-block",
        )

        config = VibewallConfig()
        config.validators["npm_advisories"] = ValidatorConfig(
            action="block", params={},
        )
        runner = CheckRunner([check], config, TTLCache(max_entries=100))

        # No on_ask callback — simulates headless / no TTY
        pipeline = await runner.run(
            "npm", "fast-xml-parser@5.3.4",
            version="5.3.4",
            check_names={"npm_advisories"},
        )

        assert pipeline.run_result.allowed is False


class TestNpmAdvisoryResultTTL:
    def test_ok_short_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.ok("no advisories")
        ttl = check.get_result_ttl(result, 3600)
        assert ttl == max(300, 3600 // 4)  # 900

    def test_fail_all_fixed_long_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.fail(
            "1 advisory",
            advisories=[{"has_fix": True, "id": "CVE-1"}],
        )
        assert check.get_result_ttl(result, 3600) == 7200

    def test_fail_unfixed_default_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.fail(
            "1 advisory",
            advisories=[{"has_fix": False, "id": "CVE-1"}],
        )
        assert check.get_result_ttl(result, 3600) == 3600

    def test_fail_mixed_fix_default_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.fail(
            "2 advisories",
            advisories=[
                {"has_fix": True, "id": "CVE-1"},
                {"has_fix": False, "id": "CVE-2"},
            ],
        )
        # Any unfixed → default TTL
        assert check.get_result_ttl(result, 3600) == 3600
