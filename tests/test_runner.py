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
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed

    @pytest.mark.asyncio
    async def test_blocklist_fail_blocks(self, runner_config: VibewallConfig) -> None:
        a = StubCheck("npm_blocklist", "npm", result=CheckResult.fail("blocklisted"))
        b = StubCheck("npm_registry", "npm")
        runner = CheckRunner([a, b], runner_config, TTLCache())
        pipeline = await runner.run("npm", "evil-pkg")
        assert pipeline.run_result.blocked
        assert "blocklisted" in pipeline.run_result.reason

    @pytest.mark.asyncio
    async def test_allowlist_short_circuits(self, runner_config: VibewallConfig) -> None:
        allowlist = StubCheck("npm_allowlist", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm")
        existence = StubCheck("npm_existence", "npm", depends_on=["npm_registry"])
        runner = CheckRunner([allowlist, registry, existence], runner_config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed
        assert "allowlisted" in pipeline.run_result.reason
        assert not existence.called

    @pytest.mark.asyncio
    async def test_fail_with_warn_action_allows(self, runner_config: VibewallConfig) -> None:
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low downloads"))
        runner = CheckRunner([downloads], runner_config, TTLCache())
        pipeline = await runner.run("npm", "obscure-pkg")
        assert pipeline.run_result.allowed

    @pytest.mark.asyncio
    async def test_err_fails_open(self, runner_config: VibewallConfig) -> None:
        registry = StubCheck("npm_registry", "npm", result=CheckResult.err("timeout"))
        runner = CheckRunner([registry], runner_config, TTLCache())
        pipeline = await runner.run("npm", "some-pkg")
        assert pipeline.run_result.allowed

    @pytest.mark.asyncio
    async def test_caching(self, runner_config: VibewallConfig) -> None:
        cache = TTLCache()
        check = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("not blocked"))
        runner = CheckRunner([check], runner_config, cache)

        await runner.run("npm", "pkg")
        assert check.called

        check.called = False
        pipeline2 = await runner.run("npm", "pkg")
        assert not check.called
        assert pipeline2.run_result.allowed

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
        pipeline = await runner.run("npm", "test-pkg")
        assert pipeline.run_result.allowed

    @pytest.mark.asyncio
    async def test_no_checks_allows(self, runner_config: VibewallConfig) -> None:
        runner = CheckRunner([], runner_config, TTLCache())
        pipeline = await runner.run("npm", "anything")
        assert pipeline.run_result.allowed

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

        pipeline = await runner.run("npm", "new-pkg", on_ask=approve)
        assert pipeline.run_result.allowed
        assert pipeline.run_result.results[0][1].status == CheckStatus.SUS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["ask-block", "ask-allow"])
    async def test_ask_denied_stays_fail(self, runner_config: VibewallConfig, action: str) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action=action)
        runner = CheckRunner([check], runner_config, TTLCache())

        async def deny(name, target, result):
            return False

        pipeline = await runner.run("npm", "new-pkg", on_ask=deny)
        assert pipeline.run_result.blocked

    @pytest.mark.asyncio
    async def test_ask_block_no_callback_stays_fail(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-block")
        runner = CheckRunner([check], runner_config, TTLCache())

        pipeline = await runner.run("npm", "new-pkg", on_ask=None)
        assert pipeline.run_result.blocked

    @pytest.mark.asyncio
    async def test_ask_allow_no_callback_allows(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-allow")
        runner = CheckRunner([check], runner_config, TTLCache())

        pipeline = await runner.run("npm", "new-pkg", on_ask=None)
        assert pipeline.run_result.allowed
        assert pipeline.run_result.results[0][1].status == CheckStatus.SUS

    @pytest.mark.asyncio
    async def test_ask_block_callback_exception_stays_fail(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-block")
        runner = CheckRunner([check], runner_config, TTLCache())

        async def explode(name, target, result):
            raise RuntimeError("boom")

        pipeline = await runner.run("npm", "new-pkg", on_ask=explode)
        assert pipeline.run_result.blocked

    @pytest.mark.asyncio
    async def test_ask_allow_callback_exception_allows(self, runner_config: VibewallConfig) -> None:
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("too new"))
        runner_config.validators["npm_age"] = ValidatorConfig(action="ask-allow")
        runner = CheckRunner([check], runner_config, TTLCache())

        async def explode(name, target, result):
            raise RuntimeError("boom")

        pipeline = await runner.run("npm", "new-pkg", on_ask=explode)
        assert pipeline.run_result.allowed
        assert pipeline.run_result.results[0][1].status == CheckStatus.SUS

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
        pipeline2 = await runner.run("npm", "new-pkg", on_ask=approve)
        assert ask_count == 1  # not called again
        assert pipeline2.run_result.allowed


class TestIgnoreAllowlist:
    @pytest.mark.asyncio
    async def test_allowlisted_still_runs_ignore_allowlist_checks(self) -> None:
        """Checks with ignore_allowlist=True run even when target is allowlisted."""
        config = VibewallConfig()
        config.validators = {
            "npm_allowlist": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_advisories": ValidatorConfig(action="block", ignore_allowlist=True),
            "npm_downloads": ValidatorConfig(action="warn"),
        }
        # allowlist + registry in layer 0; advisories + downloads in layer 1 (depend on registry)
        allowlist = StubCheck("npm_allowlist", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        advisories = StubCheck("npm_advisories", "npm", depends_on=["npm_registry"], result=CheckResult.ok("no advisories"))
        downloads = StubCheck("npm_downloads", "npm", depends_on=["npm_registry"], result=CheckResult.ok("ok"))
        runner = CheckRunner([allowlist, registry, advisories, downloads], config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed
        assert advisories.called
        assert not downloads.called  # no ignore_allowlist, should be skipped

    @pytest.mark.asyncio
    async def test_allowlisted_skips_checks_without_ignore_allowlist(self) -> None:
        """Checks without ignore_allowlist are skipped when target is allowlisted."""
        config = VibewallConfig()
        config.validators = {
            "npm_allowlist": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_existence": ValidatorConfig(action="block"),
            "npm_age": ValidatorConfig(action="block"),
        }
        allowlist = StubCheck("npm_allowlist", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        existence = StubCheck("npm_existence", "npm", depends_on=["npm_registry"], result=CheckResult.ok("exists"))
        age = StubCheck("npm_age", "npm", depends_on=["npm_registry"], result=CheckResult.ok("old enough"))
        runner = CheckRunner([allowlist, registry, existence, age], config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed
        assert "allowlisted" in pipeline.run_result.reason
        assert not existence.called
        assert not age.called

    @pytest.mark.asyncio
    async def test_ignore_allowlist_fail_blocks_allowlisted_target(self) -> None:
        """A FAIL from an ignore_allowlist check overrides the allowlist decision."""
        config = VibewallConfig()
        config.validators = {
            "npm_allowlist": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_advisories": ValidatorConfig(action="block", ignore_allowlist=True),
        }
        allowlist = StubCheck("npm_allowlist", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        advisories = StubCheck("npm_advisories", "npm", depends_on=["npm_registry"], result=CheckResult.fail("critical vulnerability found"))
        runner = CheckRunner([allowlist, registry, advisories], config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.blocked
        assert "vulnerability" in pipeline.run_result.reason

    @pytest.mark.asyncio
    async def test_ignore_allowlist_warn_action_allows(self) -> None:
        """A FAIL from an ignore_allowlist check with warn action is downgraded, target still allowed."""
        config = VibewallConfig()
        config.validators = {
            "npm_allowlist": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_advisories": ValidatorConfig(action="warn", ignore_allowlist=True),
        }
        allowlist = StubCheck("npm_allowlist", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        advisories = StubCheck("npm_advisories", "npm", depends_on=["npm_registry"], result=CheckResult.fail("medium vulnerability"))
        runner = CheckRunner([allowlist, registry, advisories], config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed
