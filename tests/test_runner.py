from __future__ import annotations

import pytest

from vibewall.cache.store import TTLCache
from vibewall.config import ValidatorConfig, VibewallConfig
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.base import BaseCheck
from vibewall.validators.runner import CheckRunner


class StubCheck(BaseCheck):
    abbrev = "STB"

    def __init__(self, name: str, scope: str, depends_on: list[str] | None = None, result: CheckResult | None = None):
        self.name = name
        self.scope = scope
        self.depends_on = depends_on or []
        self._result = result or CheckResult.ok("stub ok")
        self.called = False

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        self.called = True
        return self._result


@pytest.fixture
def runner_config() -> VibewallConfig:
    return VibewallConfig.load(None)


class TestTopologicalLayers:
    def test_no_deps_single_layer(self, runner_config: VibewallConfig) -> None:
        a = StubCheck("npm_blocklist", "npm")
        b = StubCheck("npm_allowlist", "npm")
        runner = CheckRunner([a, b], runner_config, TTLCache())
        layers = runner._topological_layers([a, b])
        assert len(layers) == 1
        assert set(c.name for c in layers[0]) == {"npm_blocklist", "npm_allowlist"}

    def test_deps_create_layers(self, runner_config: VibewallConfig) -> None:
        registry = StubCheck("npm_registry", "npm")
        existence = StubCheck("npm_existence", "npm", depends_on=["npm_registry"])
        runner = CheckRunner([registry, existence], runner_config, TTLCache())
        layers = runner._topological_layers([registry, existence])
        assert len(layers) == 2
        assert layers[0][0].name == "npm_registry"
        assert layers[1][0].name == "npm_existence"


class TestCheckRunner:
    @pytest.mark.asyncio
    async def test_all_pass(self, runner_config: VibewallConfig) -> None:
        a = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("not blocked"))
        b = StubCheck("npm_allowlist", "npm", result=CheckResult.ok("not allowlisted", allowlisted=False))
        runner = CheckRunner([a, b], runner_config, TTLCache())
        result = await runner.run("npm", "lodash")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_blocklist_fail_blocks(self, runner_config: VibewallConfig) -> None:
        a = StubCheck("npm_blocklist", "npm", result=CheckResult.fail("blocklisted"))
        b = StubCheck("npm_registry", "npm")
        runner = CheckRunner([a, b], runner_config, TTLCache())
        result = await runner.run("npm", "evil-pkg")
        assert result.blocked
        assert "blocklisted" in result.reason

    @pytest.mark.asyncio
    async def test_allowlist_short_circuits(self, runner_config: VibewallConfig) -> None:
        allowlist = StubCheck("npm_allowlist", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm")
        existence = StubCheck("npm_existence", "npm", depends_on=["npm_registry"])
        runner = CheckRunner([allowlist, registry, existence], runner_config, TTLCache())
        result = await runner.run("npm", "lodash")
        assert result.allowed
        assert "allowlisted" in result.reason
        assert not existence.called

    @pytest.mark.asyncio
    async def test_fail_with_warn_action_allows(self, runner_config: VibewallConfig) -> None:
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low downloads"))
        runner = CheckRunner([downloads], runner_config, TTLCache())
        result = await runner.run("npm", "obscure-pkg")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_err_fails_open(self, runner_config: VibewallConfig) -> None:
        registry = StubCheck("npm_registry", "npm", result=CheckResult.err("timeout"))
        runner = CheckRunner([registry], runner_config, TTLCache())
        result = await runner.run("npm", "some-pkg")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_caching(self, runner_config: VibewallConfig) -> None:
        cache = TTLCache()
        check = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("not blocked"))
        runner = CheckRunner([check], runner_config, cache)

        await runner.run("npm", "pkg")
        assert check.called

        check.called = False
        result2 = await runner.run("npm", "pkg")
        assert not check.called
        assert result2.allowed

    @pytest.mark.asyncio
    async def test_dependency_data_passed(self, runner_config: VibewallConfig) -> None:
        registry = StubCheck(
            "npm_registry", "npm",
            result=CheckResult.ok("ok", registry_data={"name": "test"}, status_code=200),
        )

        class DepCheck(BaseCheck):
            name = "npm_existence"
            abbrev = "EXS"
            depends_on = ["npm_registry"]
            scope = "npm"
            def __init__(self): pass
            async def run(self, target, context):
                data = context.data("npm_registry")
                if data.get("status_code") == 200:
                    return CheckResult.ok("exists")
                return CheckResult.fail("not found")

        dep_check = DepCheck()
        runner = CheckRunner([registry, dep_check], runner_config, TTLCache())
        result = await runner.run("npm", "test-pkg")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_no_checks_allows(self, runner_config: VibewallConfig) -> None:
        runner = CheckRunner([], runner_config, TTLCache())
        result = await runner.run("npm", "anything")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_scope_filtering(self, runner_config: VibewallConfig) -> None:
        npm_check = StubCheck("npm_blocklist", "npm")
        url_check = StubCheck("url_blocklist", "url")
        runner = CheckRunner([npm_check, url_check], runner_config, TTLCache())
        await runner.run("npm", "lodash")
        assert npm_check.called
        assert not url_check.called

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["ask-block", "ask-allow"])
    async def test_ask_approved_downgrades_to_sus(self, runner_config: VibewallConfig, action: str) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action=action)
        runner = CheckRunner([check], runner_config, TTLCache())

        async def approve(name, target, result):
            return True

        result = await runner.run("npm", "new-pkg", on_ask=approve)
        assert result.allowed
        assert result.results[0][1].status == CheckStatus.SUS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["ask-block", "ask-allow"])
    async def test_ask_denied_stays_fail(self, runner_config: VibewallConfig, action: str) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action=action)
        runner = CheckRunner([check], runner_config, TTLCache())

        async def deny(name, target, result):
            return False

        result = await runner.run("npm", "new-pkg", on_ask=deny)
        assert result.blocked

    @pytest.mark.asyncio
    async def test_ask_block_no_callback_stays_fail(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-block")
        runner = CheckRunner([check], runner_config, TTLCache())

        result = await runner.run("npm", "new-pkg", on_ask=None)
        assert result.blocked

    @pytest.mark.asyncio
    async def test_ask_allow_no_callback_allows(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-allow")
        runner = CheckRunner([check], runner_config, TTLCache())

        result = await runner.run("npm", "new-pkg", on_ask=None)
        assert result.allowed
        assert result.results[0][1].status == CheckStatus.SUS

    @pytest.mark.asyncio
    async def test_ask_block_callback_exception_stays_fail(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-block")
        runner = CheckRunner([check], runner_config, TTLCache())

        async def explode(name, target, result):
            raise RuntimeError("boom")

        result = await runner.run("npm", "new-pkg", on_ask=explode)
        assert result.blocked

    @pytest.mark.asyncio
    async def test_ask_allow_callback_exception_allows(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-allow")
        runner = CheckRunner([check], runner_config, TTLCache())

        async def explode(name, target, result):
            raise RuntimeError("boom")

        result = await runner.run("npm", "new-pkg", on_ask=explode)
        assert result.allowed
        assert result.results[0][1].status == CheckStatus.SUS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["ask-block", "ask-allow"])
    async def test_ask_approved_is_cached_as_sus(self, runner_config: VibewallConfig, action: str) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action=action)
        cache = TTLCache()
        runner = CheckRunner([check], runner_config, cache)

        ask_count = 0

        async def approve(name, target, result):
            nonlocal ask_count
            ask_count += 1
            return True

        await runner.run("npm", "new-pkg", on_ask=approve)
        assert ask_count == 1

        # Second run should use cache — no prompt
        result2 = await runner.run("npm", "new-pkg", on_ask=approve)
        assert ask_count == 1  # not called again
        assert result2.allowed
