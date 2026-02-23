from __future__ import annotations

import asyncio
import time

import pytest

from helpers import CustomTTLCheck, StubCheck
from vibewall.cache.store import TTLCache
from vibewall.config import ValidatorConfig, VibewallConfig
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.base import BaseCheck
from vibewall.validators.runner import CheckRunner


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


class TestBaseCheckDefaultTTL:
    def test_default_returns_default_ttl(self) -> None:
        check = StubCheck("test", "npm")
        result = CheckResult.ok("ok")
        assert check.get_result_ttl(result, 600) == 600


class TestRunnerResultAwareTTL:
    async def test_result_ttl_used_for_caching(self) -> None:
        """Runner uses check.get_result_ttl when setting cache entries."""
        check = CustomTTLCheck(
            "npm_blocklist", "npm",
            result=CheckResult.ok("ok"),
            ttl_map={CheckStatus.OK: 42},
        )
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        await runner.run("npm", "pkg")

        # Verify the TTL was applied by checking entry exists
        entry = cache._data.get("npm_blocklist:pkg")
        assert entry is not None
        assert entry.ttl == 42.0


class TestBackgroundRefresh:
    async def test_near_expiry_triggers_refresh(self) -> None:
        """When a cache hit is near-expiry, runner spawns a background refresh."""
        check = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("ok"))
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        # First run populates cache
        await runner.run("npm", "pkg")
        assert check.call_count == 1

        # Manually expire the entry to near-expiry (< 20% remaining)
        entry = cache._data["npm_blocklist:pkg"]
        entry.expires_at = time.monotonic() + 1  # very close to expiring
        entry.ttl = 100.0  # original TTL was 100s

        # Second run should get cache hit but schedule refresh
        check.call_count = 0
        await runner.run("npm", "pkg")
        assert check.call_count == 0  # served from cache

        # Wait for background task
        await asyncio.sleep(0.05)
        assert check.call_count == 1  # refresh happened

    async def test_duplicate_refresh_prevented(self) -> None:
        """Multiple near-expiry hits for the same key don't spawn duplicate refreshes."""
        check = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("ok"), delay=0.1)
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        # Populate cache
        await runner.run("npm", "pkg")
        assert check.call_count == 1

        # Make near-expiry
        entry = cache._data["npm_blocklist:pkg"]
        entry.expires_at = time.monotonic() + 1
        entry.ttl = 100.0

        # Two concurrent runs
        check.call_count = 0
        await asyncio.gather(
            runner.run("npm", "pkg"),
            runner.run("npm", "pkg"),
        )

        await asyncio.sleep(0.2)
        # Only one refresh should have been spawned
        assert check.call_count == 1


class TestShutdown:
    async def test_shutdown_cancels_tasks(self) -> None:
        check = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("ok"), delay=10)
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        # Populate cache, then make near-expiry to trigger refresh
        await runner.run("npm", "pkg")
        entry = cache._data["npm_blocklist:pkg"]
        entry.expires_at = time.monotonic() + 1
        entry.ttl = 100.0

        check._delay = 10  # slow refresh
        await runner.run("npm", "pkg")

        assert len(runner._background_tasks) > 0
        await runner.shutdown()
        assert len(runner._background_tasks) == 0


class TestBackgroundEligible:
    def test_warn_leaf_is_eligible(self) -> None:
        """A warn-action check with no dependents is background-eligible."""
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low"))
        config = VibewallConfig.load(None)
        # npm_downloads has default action "warn" in the config
        runner = CheckRunner([downloads], config, TTLCache())
        eligible = runner._get_background_eligible([downloads])
        assert "npm_downloads" in eligible

    def test_block_action_not_eligible(self) -> None:
        """A block-action check is never background-eligible."""
        blocklist = StubCheck("npm_blocklist", "npm")
        config = VibewallConfig.load(None)
        runner = CheckRunner([blocklist], config, TTLCache())
        eligible = runner._get_background_eligible([blocklist])
        assert "npm_blocklist" not in eligible

    def test_depended_on_not_eligible(self) -> None:
        """A warn check that others depend on is not background-eligible."""
        registry = StubCheck("npm_registry", "npm")
        existence = StubCheck("npm_existence", "npm", depends_on=["npm_registry"])
        config = VibewallConfig.load(None)
        # Force registry to warn action
        config.validators["npm_registry"] = ValidatorConfig(action="warn")
        runner = CheckRunner([registry, existence], config, TTLCache())
        eligible = runner._get_background_eligible([registry, existence])
        assert "npm_registry" not in eligible

    def test_ask_action_not_eligible(self) -> None:
        """ask-* actions are not background-eligible."""
        check = StubCheck("npm_age", "npm", result=CheckResult.fail("new"))
        config = VibewallConfig.load(None)
        config.validators["npm_age"] = ValidatorConfig(action="ask-allow")
        runner = CheckRunner([check], config, TTLCache())
        eligible = runner._get_background_eligible([check])
        assert "npm_age" not in eligible


class TestBackgroundWarnExecution:
    async def test_bg_warn_checks_dont_affect_decision(self) -> None:
        """Background warn checks are excluded from the block/allow decision."""
        # npm_downloads default action is "warn" and has no dependents
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low"), delay=0.05)
        blocklist = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("not blocked"))
        config = VibewallConfig.load(None)
        runner = CheckRunner([blocklist, downloads], config, TTLCache())

        pipeline = await runner.run("npm", "pkg")
        result = pipeline.run_result

        # Request should be allowed — downloads is background and excluded
        assert result.allowed

        # Background event should exist
        assert pipeline.background is not None

        # Wait for background to complete
        await asyncio.wait_for(pipeline.background.wait(), timeout=1)

    async def test_bg_warn_results_cached(self) -> None:
        """Background warn checks cache their results."""
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low"), delay=0.05)
        blocklist = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("not blocked"))
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([blocklist, downloads], config, cache)

        pipeline = await runner.run("npm", "pkg")
        await asyncio.wait_for(pipeline.background.wait(), timeout=1)

        # Result should be cached
        cached = cache.get("npm_downloads:pkg")
        assert cached is not None

    async def test_bg_warn_calls_on_check_done(self) -> None:
        """Background checks notify via on_check_done when they complete."""
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low"), delay=0.05)
        blocklist = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("not blocked"))
        config = VibewallConfig.load(None)
        runner = CheckRunner([blocklist, downloads], config, TTLCache())

        notified = {}

        def on_done(name, result):
            notified[name] = result

        pipeline = await runner.run("npm", "pkg", on_check_done=on_done)

        # blocklist should be notified synchronously
        assert "npm_blocklist" in notified

        # downloads may not be done yet — wait
        await asyncio.wait_for(pipeline.background.wait(), timeout=1)
        assert "npm_downloads" in notified

    async def test_no_bg_event_when_all_sync(self) -> None:
        """When there are no background-eligible checks, background is None."""
        blocklist = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("ok"))
        config = VibewallConfig.load(None)
        runner = CheckRunner([blocklist], config, TTLCache())

        pipeline = await runner.run("npm", "pkg")
        assert pipeline.background is None

    async def test_cached_bg_check_not_spawned(self) -> None:
        """When a background-eligible check is cached, it's served from cache normally."""
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low"))
        blocklist = StubCheck("npm_blocklist", "npm", result=CheckResult.ok("ok"))
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([blocklist, downloads], config, cache)

        # First run
        pipeline1 = await runner.run("npm", "pkg")
        if pipeline1.background:
            await asyncio.wait_for(pipeline1.background.wait(), timeout=1)

        downloads.call_count = 0

        # Second run — both should be cached
        pipeline2 = await runner.run("npm", "pkg")
        assert downloads.call_count == 0
        # No background tasks needed since everything is cached
        assert pipeline2.background is None
