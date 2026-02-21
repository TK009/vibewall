from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vibewall.cache.store import TTLCache
from vibewall.config import LlmConfig, ValidatorConfig, VibewallConfig
from vibewall.llm.client import LlmClient
from vibewall.llm.history import HistoryEntry, RequestHistory
from vibewall.llm.prompt import build_llm_prompt
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.action import _parse_llm_decision, maybe_ask_llm
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

    def test_keyword_fallback_block(self) -> None:
        assert _parse_llm_decision("I would BLOCK this package.") == "BLOCK"

    def test_keyword_fallback_allow(self) -> None:
        assert _parse_llm_decision("I think we should allow it.") == "ALLOW"

    def test_keyword_fallback_warn(self) -> None:
        assert _parse_llm_decision("This deserves a warn.") == "WARN"

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
                results=[("check", CheckResult.ok("ok"))],
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
                results=[], outcome="allowed",
            ))
        recent = history.recent(10)
        assert len(recent) == 3
        assert recent[0].target == "pkg-4"

    def test_recent_default(self) -> None:
        history = RequestHistory(maxlen=50)
        for i in range(20):
            history.add(HistoryEntry(
                scope="npm", target=f"pkg-{i}",
                results=[], outcome="allowed",
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
                results=[("npm_age", CheckResult.ok("old enough"))],
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
# maybe_ask_llm
# ---------------------------------------------------------------------------

class TestMaybeAskLlm:
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
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            config, client, None,
        )
        assert result.status == CheckStatus.SUS

    async def test_llm_block_response(self, config: VibewallConfig) -> None:
        client = self._mock_client("DECISION: BLOCK\nToo risky.")
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            config, client, None,
        )
        assert result.status == CheckStatus.FAIL

    async def test_llm_warn_response(self, config: VibewallConfig) -> None:
        client = self._mock_client("DECISION: WARN\nNot sure.")
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            config, client, None,
        )
        assert result.status == CheckStatus.SUS

    async def test_error_fallback_ask_llm_block(self, config: VibewallConfig) -> None:
        client = MagicMock(spec=LlmClient)
        client.ask = AsyncMock(side_effect=RuntimeError("boom"))
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            config, client, None,
        )
        # ask-llm-block → fallback to FAIL
        assert result.status == CheckStatus.FAIL

    async def test_error_fallback_ask_llm_allow(self, config_allow: VibewallConfig) -> None:
        client = MagicMock(spec=LlmClient)
        client.ask = AsyncMock(side_effect=RuntimeError("boom"))
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            config_allow, client, None,
        )
        # ask-llm-allow → fallback to SUS
        assert result.status == CheckStatus.SUS

    async def test_no_client_fallback_block(self, config: VibewallConfig) -> None:
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            config, None, None,
        )
        # ask-llm-block with no client → FAIL
        assert result.status == CheckStatus.FAIL

    async def test_no_client_fallback_allow(self, config_allow: VibewallConfig) -> None:
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            config_allow, None, None,
        )
        # ask-llm-allow with no client → SUS
        assert result.status == CheckStatus.SUS

    async def test_non_fail_passthrough(self, config: VibewallConfig) -> None:
        client = self._mock_client("DECISION: BLOCK")
        ok_result = CheckResult.ok("all good")
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            ok_result, [],
            config, client, None,
        )
        assert result.status == CheckStatus.OK
        client.ask.assert_not_called()

    async def test_non_llm_action_passthrough(self) -> None:
        cfg = VibewallConfig()
        cfg.validators = {"npm_age": ValidatorConfig(action="block")}
        client = self._mock_client("DECISION: ALLOW")
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new"), [],
            cfg, client, None,
        )
        assert result.status == CheckStatus.FAIL
        client.ask.assert_not_called()

    async def test_action_override(self) -> None:
        """action_override in result data should take precedence over config."""
        cfg = VibewallConfig()
        cfg.validators = {"npm_age": ValidatorConfig(action="block")}
        client = self._mock_client("DECISION: ALLOW\nok")
        result = await maybe_ask_llm(
            "npm_age", "test-pkg", "npm",
            CheckResult.fail("too new", action_override="ask-llm-block"), [],
            cfg, client, None,
        )
        assert result.status == CheckStatus.SUS


# ---------------------------------------------------------------------------
# LlmClient
# ---------------------------------------------------------------------------

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
