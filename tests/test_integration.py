"""Integration tests: real CheckRunner + real SQLiteCache + StubChecks."""
from __future__ import annotations

import pytest

from helpers import StubCheck
from vibewall.cache.store import SQLiteCache
from vibewall.config import ValidatorConfig, VibewallConfig
from vibewall.models import CheckResult, CheckStatus
from vibewall.validators.runner import CheckRunner


@pytest.fixture
async def cache(tmp_path):
    c = SQLiteCache(db_path=str(tmp_path / "integration.db"))
    await c.open()
    yield c
    await c.close()


@pytest.fixture
def config() -> VibewallConfig:
    return VibewallConfig.load(None)


class TestPipelineIntegration:
    async def test_full_run_and_cache_hit(self, config: VibewallConfig, cache: SQLiteCache) -> None:
        """First run executes check, second run serves from cache."""
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        runner = CheckRunner([check], config, cache)

        pipeline1 = await runner.run("npm", "lodash")
        assert pipeline1.run_result.allowed
        assert check.call_count == 1

        # Second run should be a cache hit
        pipeline2 = await runner.run("npm", "lodash")
        assert pipeline2.run_result.allowed
        assert check.call_count == 1  # not called again

    async def test_cache_persistence_across_runner_calls(self, config: VibewallConfig, tmp_path) -> None:
        """Cache persists between runner instances sharing the same DB."""
        db_path = str(tmp_path / "persist.db")

        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))

        # First runner + cache
        cache1 = SQLiteCache(db_path=db_path)
        await cache1.open()
        runner1 = CheckRunner([check], config, cache1)
        await runner1.run("npm", "pkg")
        assert check.call_count == 1
        await cache1.close()

        # Second runner + cache (same DB)
        cache2 = SQLiteCache(db_path=db_path)
        await cache2.open()
        check.call_count = 0
        runner2 = CheckRunner([check], config, cache2)
        pipeline = await runner2.run("npm", "pkg")
        assert check.call_count == 0  # served from persisted cache
        assert pipeline.run_result.allowed
        await cache2.close()

    async def test_near_expiry_refresh_through_pipeline(self, config: VibewallConfig, cache: SQLiteCache) -> None:
        """Near-expiry triggers background refresh through the full pipeline."""
        check = StubCheck("npm_rules", "npm", result=CheckResult.ok("no rule matched", allowlisted=False))
        runner = CheckRunner([check], config, cache)

        # Populate cache
        await runner.run("npm", "pkg")
        assert check.call_count == 1

        # Simulate near-expiry
        cache.force_near_expiry("npm_rules:pkg")

        # Run again — should serve from cache but trigger refresh
        check.call_count = 0
        pipeline = await runner.run("npm", "pkg")
        assert pipeline.run_result.allowed
        assert check.call_count == 0  # served from cache

        # Wait for background refresh
        await runner.wait_for_refresh("npm_rules", "pkg")
        assert check.call_count == 1  # refresh happened

    async def test_multi_scope_isolation(self, config: VibewallConfig, cache: SQLiteCache) -> None:
        """NPM and PyPI checks don't interfere with each other."""
        npm_check = StubCheck("npm_rules", "npm", result=CheckResult.ok("npm ok", allowlisted=False))
        pypi_check = StubCheck("pypi_rules", "pypi", result=CheckResult.fail("pypi blocked"))

        runner = CheckRunner([npm_check, pypi_check], config, cache)

        npm_result = await runner.run("npm", "lodash")
        assert npm_result.run_result.allowed
        assert npm_check.call_count == 1
        assert pypi_check.call_count == 0

        pypi_result = await runner.run("pypi", "evil-pkg")
        assert pypi_result.run_result.blocked
        assert pypi_check.call_count == 1
        assert npm_check.call_count == 1  # unchanged
