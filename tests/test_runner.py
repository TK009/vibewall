from __future__ import annotations

import asyncio
import time

import pytest

from helpers import CustomTTLCheck, ExplodingCheck, StubCheck
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
        a = StubCheck("npm_rules", "npm")
        b = StubCheck("npm_registry", "npm")
        runner = CheckRunner([a, b], runner_config, TTLCache())
        layers = runner._topological_layers([a, b])
        assert len(layers) == 1
        assert set(c.name for c in layers[0]) == {"npm_rules", "npm_registry"}

    def test_deps_create_layers(self, runner_config: VibewallConfig) -> None:
        registry = StubCheck("npm_registry", "npm")
        existence = StubCheck("npm_existence", "npm", depends_on=("npm_registry",))
        runner = CheckRunner([registry, existence], runner_config, TTLCache())
        layers = runner._topological_layers([registry, existence])
        assert len(layers) == 2
        assert layers[0][0].name == "npm_registry"
        assert layers[1][0].name == "npm_existence"


class TestCheckRunner:
    @pytest.mark.asyncio
    async def test_all_pass(self, runner_config: VibewallConfig) -> None:
        a = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        b = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        runner = CheckRunner([a, b], runner_config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed

    @pytest.mark.asyncio
    async def test_blocklist_fail_blocks(self, runner_config: VibewallConfig) -> None:
        a = StubCheck("npm_rules", "npm", result=CheckResult.fail("blocklisted"))
        b = StubCheck("npm_registry", "npm")
        runner = CheckRunner([a, b], runner_config, TTLCache())
        pipeline = await runner.run("npm", "evil-pkg")
        assert pipeline.run_result.blocked
        assert "blocklisted" in pipeline.run_result.reason

    @pytest.mark.asyncio
    async def test_allowlist_short_circuits(self, runner_config: VibewallConfig) -> None:
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm")
        existence = StubCheck("npm_existence", "npm", depends_on=("npm_registry",))
        runner = CheckRunner([rules, registry, existence], runner_config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed
        assert "allowlisted" in pipeline.run_result.reason
        assert existence.call_count == 0

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
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        runner = CheckRunner([check], runner_config, cache)

        await runner.run("npm", "pkg")
        assert check.call_count == 1

        check.call_count = 0
        pipeline2 = await runner.run("npm", "pkg")
        assert check.call_count == 0
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
        npm_check = StubCheck("npm_rules", "npm")
        url_check = StubCheck("url_rules", "url")
        runner = CheckRunner([npm_check, url_check], runner_config, TTLCache())
        await runner.run("npm", "lodash")
        assert npm_check.call_count > 0
        assert url_check.call_count == 0

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
            "npm_rules": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_advisories": ValidatorConfig(action="block", ignore_allowlist=True),
            "npm_downloads": ValidatorConfig(action="warn"),
        }
        # rules + registry in layer 0; advisories + downloads in layer 1 (depend on registry)
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        advisories = StubCheck("npm_advisories", "npm", depends_on=("npm_registry",), result=CheckResult.ok("no advisories"))
        downloads = StubCheck("npm_downloads", "npm", depends_on=("npm_registry",), result=CheckResult.ok("ok"))
        runner = CheckRunner([rules, registry, advisories, downloads], config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed
        assert advisories.call_count > 0
        assert downloads.call_count == 0  # no ignore_allowlist, should be skipped

    @pytest.mark.asyncio
    async def test_allowlisted_skips_checks_without_ignore_allowlist(self) -> None:
        """Checks without ignore_allowlist are skipped when target is allowlisted."""
        config = VibewallConfig()
        config.validators = {
            "npm_rules": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_existence": ValidatorConfig(action="block"),
            "npm_age": ValidatorConfig(action="block"),
        }
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        existence = StubCheck("npm_existence", "npm", depends_on=("npm_registry",), result=CheckResult.ok("exists"))
        age = StubCheck("npm_age", "npm", depends_on=("npm_registry",), result=CheckResult.ok("old enough"))
        runner = CheckRunner([rules, registry, existence, age], config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.allowed
        assert "allowlisted" in pipeline.run_result.reason
        assert existence.call_count == 0
        assert age.call_count == 0

    @pytest.mark.asyncio
    async def test_ignore_allowlist_fail_blocks_allowlisted_target(self) -> None:
        """A FAIL from an ignore_allowlist check overrides the allowlist decision."""
        config = VibewallConfig()
        config.validators = {
            "npm_rules": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_advisories": ValidatorConfig(action="block", ignore_allowlist=True),
        }
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        advisories = StubCheck("npm_advisories", "npm", depends_on=("npm_registry",), result=CheckResult.fail("critical vulnerability found"))
        runner = CheckRunner([rules, registry, advisories], config, TTLCache())
        pipeline = await runner.run("npm", "lodash")
        assert pipeline.run_result.blocked
        assert "vulnerability" in pipeline.run_result.reason

    @pytest.mark.asyncio
    async def test_ignore_allowlist_warn_action_allows(self) -> None:
        """A FAIL from an ignore_allowlist check with warn action is downgraded, target still allowed."""
        config = VibewallConfig()
        config.validators = {
            "npm_rules": ValidatorConfig(action="block"),
            "npm_registry": ValidatorConfig(action="warn"),
            "npm_advisories": ValidatorConfig(action="warn", ignore_allowlist=True),
        }
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("allowlisted", allowlisted=True))
        registry = StubCheck("npm_registry", "npm", result=CheckResult.ok("ok"))
        advisories = StubCheck("npm_advisories", "npm", depends_on=("npm_registry",), result=CheckResult.fail("medium vulnerability"))
        runner = CheckRunner([rules, registry, advisories], config, TTLCache())
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
            "npm_rules", "npm",
            result=CheckResult.ok("ok"),
            ttl_map={CheckStatus.OK: 42},
        )
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        await runner.run("npm", "pkg")

        # Verify the TTL was applied by checking entry exists
        entry = cache._data.get("npm_rules:pkg")
        assert entry is not None
        assert entry.ttl == 42.0


class TestErrorTTL:
    async def test_err_result_uses_error_ttl(self) -> None:
        """ERR results are cached with cache.error_ttl, not the default TTL."""
        check = StubCheck("npm_rules", "npm", result=CheckResult.err("timeout"))
        config = VibewallConfig.load(None)
        config.cache.error_ttl = 30
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        await runner.run("npm", "pkg")

        entry = cache._data.get("npm_rules:pkg")
        assert entry is not None
        assert entry.ttl == 30.0

    async def test_err_result_ignores_per_validator_ttl(self) -> None:
        """ERR results use global error_ttl even if the validator has a custom cache_ttl."""
        check = StubCheck("npm_registry", "npm", result=CheckResult.err("network error"))
        config = VibewallConfig.load(None)
        config.cache.error_ttl = 15
        config.validators["npm_registry"] = ValidatorConfig(action="block", cache_ttl=86400)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        await runner.run("npm", "pkg")

        entry = cache._data.get("npm_registry:pkg")
        assert entry is not None
        assert entry.ttl == 15.0

    async def test_ok_result_still_uses_default_ttl(self) -> None:
        """Non-ERR results continue to use the normal TTL."""
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("fine"))
        config = VibewallConfig.load(None)
        config.cache.error_ttl = 15
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        await runner.run("npm", "pkg")

        entry = cache._data.get("npm_rules:pkg")
        assert entry is not None
        assert entry.ttl == float(config.cache.default_ttl)


class TestBackgroundRefresh:
    async def test_near_expiry_triggers_refresh(self) -> None:
        """When a cache hit is near-expiry, runner spawns a background refresh."""
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("ok"))
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        # First run populates cache
        await runner.run("npm", "pkg")
        assert check.call_count == 1

        # Manually expire the entry to near-expiry (< 20% remaining)
        entry = cache._data["npm_rules:pkg"]
        entry.expires_at = time.time() + 1  # very close to expiring
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
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("ok"), delay=0.1)
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        # Populate cache
        await runner.run("npm", "pkg")
        assert check.call_count == 1

        # Make near-expiry
        entry = cache._data["npm_rules:pkg"]
        entry.expires_at = time.time() + 1
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


    async def test_refresh_exception_caches_err(self) -> None:
        """When a background refresh raises, an ERR result replaces the stale entry."""
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("ok"))
        config = VibewallConfig.load(None)
        config.cache.error_ttl = 20
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        # Populate cache
        await runner.run("npm", "pkg")
        assert check.call_count == 1

        # Make near-expiry to trigger refresh
        entry = cache._data["npm_rules:pkg"]
        entry.expires_at = time.time() + 1
        entry.ttl = 100.0

        # Replace check with one that raises
        exploding = ExplodingCheck("npm_rules", "npm")
        runner._checks["npm_rules"] = exploding

        await runner.run("npm", "pkg")
        await asyncio.sleep(0.05)

        # The refresh should have cached an ERR result
        new_entry = cache._data.get("npm_rules:pkg")
        assert new_entry is not None
        raw, display = new_entry.value
        assert raw.status == CheckStatus.ERR
        assert new_entry.ttl == 20.0


class TestShutdown:
    async def test_shutdown_cancels_tasks(self) -> None:
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("ok"), delay=10)
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([check], config, cache)

        # Populate cache, then make near-expiry to trigger refresh
        await runner.run("npm", "pkg")
        entry = cache._data["npm_rules:pkg"]
        entry.expires_at = time.time() + 1
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
        rules = StubCheck("npm_rules", "npm")
        config = VibewallConfig.load(None)
        runner = CheckRunner([rules], config, TTLCache())
        eligible = runner._get_background_eligible([rules])
        assert "npm_rules" not in eligible

    def test_depended_on_not_eligible(self) -> None:
        """A warn check that others depend on is not background-eligible."""
        registry = StubCheck("npm_registry", "npm")
        existence = StubCheck("npm_existence", "npm", depends_on=("npm_registry",))
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
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        config = VibewallConfig.load(None)
        runner = CheckRunner([rules, downloads], config, TTLCache())

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
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([rules, downloads], config, cache)

        pipeline = await runner.run("npm", "pkg")
        await asyncio.wait_for(pipeline.background.wait(), timeout=1)

        # Result should be cached
        cached = cache.get("npm_downloads:pkg")
        assert cached is not None

    async def test_bg_warn_calls_on_check_done(self) -> None:
        """Background checks notify via on_check_done when they complete."""
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low"), delay=0.05)
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        config = VibewallConfig.load(None)
        runner = CheckRunner([rules, downloads], config, TTLCache())

        notified = {}

        def on_done(name, result):
            notified[name] = result

        pipeline = await runner.run("npm", "pkg", on_check_done=on_done)

        # rules should be notified synchronously
        assert "npm_rules" in notified

        # downloads may not be done yet — wait
        await asyncio.wait_for(pipeline.background.wait(), timeout=1)
        assert "npm_downloads" in notified

    async def test_no_bg_event_when_all_sync(self) -> None:
        """When there are no background-eligible checks, background is None."""
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("ok"))
        config = VibewallConfig.load(None)
        runner = CheckRunner([rules], config, TTLCache())

        pipeline = await runner.run("npm", "pkg")
        assert pipeline.background is None

    async def test_bg_exception_caches_err_with_error_ttl(self) -> None:
        """When a background check raises, an ERR result is cached with error_ttl."""
        downloads = ExplodingCheck("npm_downloads", "npm", delay=0.05)
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        config = VibewallConfig.load(None)
        config.cache.error_ttl = 25
        cache = TTLCache()
        runner = CheckRunner([rules, downloads], config, cache)

        pipeline = await runner.run("npm", "pkg")
        assert pipeline.background is not None
        await asyncio.wait_for(pipeline.background.wait(), timeout=1)

        entry = cache._data.get("npm_downloads:pkg")
        assert entry is not None
        raw, display = entry.value
        assert raw.status == CheckStatus.ERR
        assert entry.ttl == 25.0

    async def test_bg_exception_notifies_on_check_done(self) -> None:
        """When a background check raises, on_check_done is still called with an ERR result."""
        downloads = ExplodingCheck("npm_downloads", "npm", delay=0.05)
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        config = VibewallConfig.load(None)
        runner = CheckRunner([rules, downloads], config, TTLCache())

        notified = {}
        def on_done(name, result):
            notified[name] = result

        pipeline = await runner.run("npm", "pkg", on_check_done=on_done)
        await asyncio.wait_for(pipeline.background.wait(), timeout=1)

        assert "npm_downloads" in notified
        assert notified["npm_downloads"].status == CheckStatus.ERR

    async def test_cached_bg_check_not_spawned(self) -> None:
        """When a background-eligible check is cached, it's served from cache normally."""
        downloads = StubCheck("npm_downloads", "npm", result=CheckResult.fail("low"))
        rules = StubCheck("npm_rules", "npm", result=CheckResult.ok("ok"))
        config = VibewallConfig.load(None)
        cache = TTLCache()
        runner = CheckRunner([rules, downloads], config, cache)

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
