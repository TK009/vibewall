from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vibewall.cache.store import TTLCache
from vibewall.config import LlmConfig, ValidatorConfig, VibewallConfig
from vibewall.llm.client import LlmClient
from vibewall.llm.history import HistoryEntry, RequestHistory
from vibewall.llm.prompt import build_llm_prompt
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.action import _parse_llm_decision, batch_ask_llm
from vibewall.validators.base import BaseCheck
from vibewall.validators.runner import CheckRunner


# ---------------------------------------------------------------------------
# _parse_llm_decision
# ---------------------------------------------------------------------------

class TestParseLlmDecision:
    def test_structured_allow(self) -> None:
        assert _parse_llm_decision("DECISION: ALLOW\nLooks safe.") == "ALLOW"

    def test_structured_block(self) -> None:
        assert _parse_llm_decision("DECISION: BLOCK\nToo risky.") == "BLOCK"

    def test_structured_warn(self) -> None:
        assert _parse_llm_decision("DECISION: WARN\nNot sure.") == "WARN"

    def test_structured_case_insensitive(self) -> None:
        assert _parse_llm_decision("decision: allow\nOk") == "ALLOW"

    def test_no_decision_line_returns_empty(self) -> None:
        assert _parse_llm_decision("I would BLOCK this package.") == ""

    def test_decision_line_after_prose(self) -> None:
        assert _parse_llm_decision("Let me think...\nDECISION: BLOCK\nBecause risky.") == "BLOCK"

    def test_ambiguous_returns_empty(self) -> None:
        assert _parse_llm_decision("I'm not sure what to do.") == ""

    def test_empty_response(self) -> None:
        assert _parse_llm_decision("") == ""


# ---------------------------------------------------------------------------
# RequestHistory
# ---------------------------------------------------------------------------

class TestRequestHistory:
    def test_add_and_recent(self) -> None:
        history = RequestHistory(maxlen=5)
        for i in range(3):
            history.add(HistoryEntry(
                scope="npm", target=f"pkg-{i}",
                results=(("check", CheckResult.ok("ok")),),
                outcome="allowed",
            ))
        recent = history.recent(2)
        assert len(recent) == 2
        # newest first
        assert recent[0].target == "pkg-2"
        assert recent[1].target == "pkg-1"

    def test_eviction(self) -> None:
        history = RequestHistory(maxlen=3)
        for i in range(5):
            history.add(HistoryEntry(
                scope="npm", target=f"pkg-{i}",
                results=(), outcome="allowed",
            ))
        recent = history.recent(10)
        assert len(recent) == 3
        assert recent[0].target == "pkg-4"

    def test_recent_default(self) -> None:
        history = RequestHistory(maxlen=50)
        for i in range(20):
            history.add(HistoryEntry(
                scope="npm", target=f"pkg-{i}",
                results=(), outcome="allowed",
            ))
        recent = history.recent()
        assert len(recent) == 12  # default n=12


# ---------------------------------------------------------------------------
# build_llm_prompt
# ---------------------------------------------------------------------------

class TestBuildLlmPrompt:
    def test_contains_target_and_scope(self) -> None:
        system, user = build_llm_prompt(
            "npm", "lodash",
            [("npm_age", CheckResult.fail("too new"))],
        )
        assert "lodash" in user
        assert "npm" in user
        assert "DECISION" in system

    def test_contains_check_results(self) -> None:
        _, user = build_llm_prompt(
            "npm", "evil-pkg",
            [
                ("npm_age", CheckResult.fail("too new")),
                ("npm_downloads", CheckResult.sus("low downloads")),
            ],
        )
        assert "npm_age" in user
        assert "too new" in user
        assert "npm_downloads" in user

    def test_contains_history(self) -> None:
        entries = [
            HistoryEntry(
                scope="npm", target="prev-pkg",
                results=(("npm_age", CheckResult.ok("old enough")),),
                outcome="allowed",
            ),
        ]
        _, user = build_llm_prompt(
            "npm", "test-pkg",
            [("npm_age", CheckResult.fail("too new"))],
            history=entries,
        )
        assert "prev-pkg" in user
        assert "allowed" in user

    def test_no_history(self) -> None:
        _, user = build_llm_prompt(
            "npm", "test-pkg",
            [("npm_age", CheckResult.fail("too new"))],
            history=None,
        )
        assert "history" not in user.lower()


# ---------------------------------------------------------------------------
# batch_ask_llm
# ---------------------------------------------------------------------------

class TestBatchAskLlm:
    @pytest.fixture
    def config(self) -> VibewallConfig:
        cfg = VibewallConfig()
        cfg.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
        }
        return cfg

    @pytest.fixture
    def config_allow(self) -> VibewallConfig:
        cfg = VibewallConfig()
        cfg.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-allow"),
        }
        return cfg

    def _mock_client(self, response: str) -> LlmClient:
        client = MagicMock(spec=LlmClient)
        client.ask = AsyncMock(return_value=response)
        return client

    async def test_llm_allow_response(self, config: VibewallConfig) -> None:
        client = self._mock_client("DECISION: ALLOW\nLooks fine.")
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config, client, None)
        assert decision == "ALLOW"
        assert resolved[0][1].status == CheckStatus.SUS

    async def test_llm_block_response(self, config: VibewallConfig) -> None:
        client = self._mock_client("DECISION: BLOCK\nToo risky.")
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config, client, None)
        assert decision == "BLOCK"
        assert resolved[0][1].status == CheckStatus.FAIL

    async def test_llm_warn_response(self, config: VibewallConfig) -> None:
        client = self._mock_client("DECISION: WARN\nNot sure.")
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config, client, None)
        assert decision == "WARN"
        assert resolved[0][1].status == CheckStatus.SUS

    async def test_error_fallback_ask_llm_block(self, config: VibewallConfig) -> None:
        client = MagicMock(spec=LlmClient)
        client.ask = AsyncMock(side_effect=RuntimeError("boom"))
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config, client, None)
        assert decision == ""
        assert resolved[0][1].status == CheckStatus.FAIL

    async def test_error_fallback_ask_llm_allow(self, config_allow: VibewallConfig) -> None:
        client = MagicMock(spec=LlmClient)
        client.ask = AsyncMock(side_effect=RuntimeError("boom"))
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config_allow, client, None)
        assert decision == ""
        assert resolved[0][1].status == CheckStatus.SUS

    async def test_no_client_fallback_block(self, config: VibewallConfig) -> None:
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config, None, None)
        assert decision == ""
        assert resolved[0][1].status == CheckStatus.FAIL

    async def test_no_client_fallback_allow(self, config_allow: VibewallConfig) -> None:
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config_allow, None, None)
        assert decision == ""
        assert resolved[0][1].status == CheckStatus.SUS

    async def test_unrecognized_decision_fallback_block(self, config: VibewallConfig) -> None:
        client = self._mock_client("I'm not sure what to do here.")
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config, client, None)
        assert decision == ""
        assert resolved[0][1].status == CheckStatus.FAIL

    async def test_unrecognized_decision_fallback_allow(self, config_allow: VibewallConfig) -> None:
        client = self._mock_client("I'm not sure what to do here.")
        pending = [("npm_age", CheckResult.fail("too new"))]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], config_allow, client, None)
        assert decision == ""
        assert resolved[0][1].status == CheckStatus.SUS

    async def test_empty_pending_returns_empty(self, config: VibewallConfig) -> None:
        client = self._mock_client("DECISION: BLOCK")
        decision, resolved = await batch_ask_llm("npm", "test-pkg", [], [], config, client, None)
        assert decision == ""
        assert resolved == []
        client.ask.assert_not_called()

    async def test_batch_multiple_checks_single_call(self) -> None:
        """Multiple pending checks should result in exactly one LLM call."""
        cfg = VibewallConfig()
        cfg.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
            "npm_downloads": ValidatorConfig(action="ask-llm-block"),
        }
        client = MagicMock(spec=LlmClient)
        client.ask = AsyncMock(return_value="DECISION: ALLOW\nAll fine.")
        pending = [
            ("npm_age", CheckResult.fail("too new")),
            ("npm_downloads", CheckResult.fail("low downloads")),
        ]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], cfg, client, None)
        assert decision == "ALLOW"
        assert len(resolved) == 2
        assert all(r.status == CheckStatus.SUS for _, r in resolved)
        client.ask.assert_called_once()

    async def test_batch_mixed_actions(self) -> None:
        """Different ask-llm-allow/block actions get correct fallbacks."""
        cfg = VibewallConfig()
        cfg.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
            "npm_downloads": ValidatorConfig(action="ask-llm-allow"),
        }
        client = self._mock_client("DECISION: BLOCK\nRisky.")
        pending = [
            ("npm_age", CheckResult.fail("too new")),
            ("npm_downloads", CheckResult.fail("low downloads")),
        ]
        decision, resolved = await batch_ask_llm("npm", "test-pkg", pending, [], cfg, client, None)
        assert decision == "BLOCK"
        # Both should get BLOCK → FAIL
        assert resolved[0][1].status == CheckStatus.FAIL
        assert resolved[1][1].status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# LlmClient
# ---------------------------------------------------------------------------

class TestLlmConfigRepr:
    def test_masks_long_key(self) -> None:
        cfg = LlmConfig(api_key="sk-abc123def456")
        r = repr(cfg)
        assert "sk-abc123def456" not in r
        assert "...f456" in r

    def test_masks_short_key(self) -> None:
        assert "***" in repr(LlmConfig(api_key="ab"))

    def test_masks_empty_key(self) -> None:
        assert "***" in repr(LlmConfig(api_key=""))


class TestLlmClient:
    async def test_anthropic_provider(self) -> None:
        config = LlmConfig(provider="anthropic", api_key="test-key", model="test-model")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={
            "content": [{"text": "DECISION: ALLOW\nOk"}],
        })
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.post = MagicMock(return_value=mock_resp)

        client = LlmClient(config, session)
        result = await client.ask("system", "user")
        assert result == "DECISION: ALLOW\nOk"

        # Verify headers
        call_kwargs = session.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert headers["x-api-key"] == "test-key"
        assert "anthropic-version" in headers

    async def test_openai_provider(self) -> None:
        config = LlmConfig(provider="openai", api_key="test-key", model="gpt-4")
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={
            "choices": [{"message": {"content": "DECISION: BLOCK\nRisky"}}],
        })
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.post = MagicMock(return_value=mock_resp)

        client = LlmClient(config, session)
        result = await client.ask("system", "user")
        assert result == "DECISION: BLOCK\nRisky"

        call_kwargs = session.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert headers["Authorization"] == "Bearer test-key"

    async def test_semaphore_limits_concurrency(self) -> None:
        import asyncio
        from contextlib import asynccontextmanager

        config = LlmConfig(provider="anthropic", api_key="k", model="m", max_concurrent=2)
        peak = 0
        active = 0

        @asynccontextmanager
        async def _fake_post(url, **kwargs):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.05)
            active -= 1

            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json = AsyncMock(return_value={
                "content": [{"text": "ok"}],
            })
            yield mock_resp

        session = MagicMock()
        session.post = _fake_post

        client = LlmClient(config, session)
        await asyncio.gather(*[client.ask("sys", "usr") for _ in range(5)])
        assert peak <= 2


# ---------------------------------------------------------------------------
# Runner integration
# ---------------------------------------------------------------------------

class StubCheck(BaseCheck):
    abbrev = "STB"

    def __init__(
        self, name: str, scope: str,
        depends_on: list[str] | None = None,
        result: CheckResult | None = None,
    ):
        self.name = name
        self.scope = scope
        self.depends_on = depends_on or []
        self._result = result or CheckResult.ok("stub ok")

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        return self._result


class TestRunnerLlmIntegration:
    async def test_ask_llm_block_with_mock_client(self) -> None:
        config = VibewallConfig()
        config.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
        }

        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))

        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="DECISION: BLOCK\nRisky package")

        history = RequestHistory()
        runner = CheckRunner(
            [check], config, TTLCache(),
            llm_client=mock_client, history=history,
        )
        result = await runner.run("npm", "suspicious-pkg")
        assert result.blocked

    async def test_ask_llm_allow_with_mock_client(self) -> None:
        config = VibewallConfig()
        config.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
        }

        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))

        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="DECISION: ALLOW\nLooks fine")

        history = RequestHistory()
        runner = CheckRunner(
            [check], config, TTLCache(),
            llm_client=mock_client, history=history,
        )
        result = await runner.run("npm", "safe-pkg")
        assert result.allowed

    async def test_history_recorded_after_run(self) -> None:
        config = VibewallConfig()
        config.validators = {
            "npm_age": ValidatorConfig(action="block"),
        }
        check = StubCheck("npm_age", "npm", result=CheckResult.ok("ok"))

        history = RequestHistory()
        runner = CheckRunner([check], config, TTLCache(), history=history)
        await runner.run("npm", "test-pkg")

        recent = history.recent(1)
        assert len(recent) == 1
        assert recent[0].target == "test-pkg"
        assert recent[0].scope == "npm"
        assert recent[0].outcome == "allowed"

    async def test_no_llm_client_falls_through(self) -> None:
        """When no LLM client, ask-llm-block should fall back to FAIL (block)."""
        config = VibewallConfig()
        config.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
        }
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))

        runner = CheckRunner([check], config, TTLCache())
        result = await runner.run("npm", "test-pkg")
        assert result.blocked

    async def test_multiple_llm_checks_single_call(self) -> None:
        """Multiple ask-llm checks should produce exactly one LLM call."""
        config = VibewallConfig()
        config.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
            "npm_downloads": ValidatorConfig(action="ask-llm-block"),
        }
        checks = [
            StubCheck("npm_age", "npm", result=CheckResult.fail("too new")),
            StubCheck("npm_downloads", "npm", result=CheckResult.fail("low")),
        ]
        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="DECISION: BLOCK\nRisky")

        history = RequestHistory()
        runner = CheckRunner(
            checks, config, TTLCache(),
            llm_client=mock_client, history=history,
        )
        result = await runner.run("npm", "test-pkg")
        assert result.blocked
        mock_client.ask.assert_called_once()


# ---------------------------------------------------------------------------
# LLM decision caching
# ---------------------------------------------------------------------------

class TestLlmDecisionCaching:
    def _make_runner(
        self, mock_client: LlmClient, cache: TTLCache, cache_ttl: int = 120,
    ) -> CheckRunner:
        config = VibewallConfig()
        config.llm = LlmConfig(api_key="test-key", cache_ttl=cache_ttl)
        config.validators = {
            "npm_age": ValidatorConfig(action="ask-llm-block"),
        }
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        return CheckRunner(
            [check], config, cache,
            llm_client=mock_client, history=RequestHistory(),
        )

    async def test_cached_decision_reused(self) -> None:
        """Second run for same target reuses cached LLM decision."""
        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="DECISION: ALLOW\nOk")
        cache = TTLCache()
        runner = self._make_runner(mock_client, cache)

        r1 = await runner.run("npm", "test-pkg")
        assert r1.allowed
        assert mock_client.ask.call_count == 1

        r2 = await runner.run("npm", "test-pkg")
        assert r2.allowed
        # LLM should NOT be called a second time
        assert mock_client.ask.call_count == 1

    async def test_ttl_zero_disables_caching(self) -> None:
        """With cache_ttl=0, every request calls the LLM."""
        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="DECISION: ALLOW\nOk")
        cache = TTLCache()
        runner = self._make_runner(mock_client, cache, cache_ttl=0)

        await runner.run("npm", "test-pkg")
        await runner.run("npm", "test-pkg")
        assert mock_client.ask.call_count == 2

    async def test_different_targets_separate_cache(self) -> None:
        """Different targets get independent cache entries."""
        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="DECISION: BLOCK\nRisky")
        cache = TTLCache()
        runner = self._make_runner(mock_client, cache)

        r1 = await runner.run("npm", "pkg-a")
        assert r1.blocked

        r2 = await runner.run("npm", "pkg-b")
        assert r2.blocked

        # Both targets should have triggered separate LLM calls
        assert mock_client.ask.call_count == 2

    async def test_empty_decision_not_cached(self) -> None:
        """Fallback (empty) decisions should not be cached."""
        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="I'm not sure what to do.")
        cache = TTLCache()
        runner = self._make_runner(mock_client, cache)

        await runner.run("npm", "test-pkg")
        await runner.run("npm", "test-pkg")
        # Empty decision → not cached → LLM called both times
        assert mock_client.ask.call_count == 2

    async def test_cached_block_decision_applied(self) -> None:
        """Cached BLOCK decision correctly blocks on reuse."""
        mock_client = MagicMock(spec=LlmClient)
        mock_client.ask = AsyncMock(return_value="DECISION: BLOCK\nNo")
        cache = TTLCache()
        runner = self._make_runner(mock_client, cache)

        r1 = await runner.run("npm", "test-pkg")
        assert r1.blocked

        r2 = await runner.run("npm", "test-pkg")
        assert r2.blocked
        assert mock_client.ask.call_count == 1
