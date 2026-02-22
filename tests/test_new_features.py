"""Tests for result-aware TTL, near-expiry cache refresh, and background warn checks."""
from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

from vibewall.cache.store import TTLCache
from vibewall.config import ValidatorConfig, VibewallConfig
from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.base import BaseCheck
from vibewall.validators.checks._osv import has_fix
from vibewall.validators.checks.npm_advisories import NpmAdvisoriesCheck
from vibewall.validators.checks.pypi_advisories import PypiAdvisoriesCheck
from vibewall.validators.runner import CheckRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class StubCheck(BaseCheck):
    abbrev = "STB"

    def __init__(
        self,
        name: str,
        scope: str,
        depends_on: list[str] | None = None,
        result: CheckResult | None = None,
        delay: float = 0,
    ):
        self.name = name
        self.scope = scope
        self.depends_on = depends_on or []
        self._result = result or CheckResult.ok("stub ok")
        self._delay = delay
        self.call_count = 0

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        self.call_count += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        return self._result


class CustomTTLCheck(StubCheck):
    """StubCheck with a custom get_result_ttl."""

    def __init__(self, *args, ttl_map: dict[CheckStatus, int] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._ttl_map = ttl_map or {}

    def get_result_ttl(self, result: CheckResult, default_ttl: int) -> int:
        return self._ttl_map.get(result.status, default_ttl)


# ---------------------------------------------------------------------------
# Feature 1: has_fix helper
# ---------------------------------------------------------------------------

class TestHasFix:
    def test_has_fix_true(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.2.3"},
                    ]
                }]
            }]
        }
        assert has_fix(vuln) is True

    def test_has_fix_false_no_fixed_event(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                    ]
                }]
            }]
        }
        assert has_fix(vuln) is False

    def test_has_fix_false_no_affected(self) -> None:
        assert has_fix({}) is False

    def test_has_fix_false_empty_ranges(self) -> None:
        vuln = {"affected": [{"ranges": []}]}
        assert has_fix(vuln) is False


# ---------------------------------------------------------------------------
# Feature 1: get_result_ttl on advisory checks
# ---------------------------------------------------------------------------

class TestAdvisoryResultTTL:
    def test_npm_ok_short_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.ok("no advisories")
        ttl = check.get_result_ttl(result, 3600)
        assert ttl == max(300, 3600 // 4)  # 900

    def test_npm_err_default_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.err("timeout")
        assert check.get_result_ttl(result, 3600) == 3600

    def test_npm_fail_all_fixed_long_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.fail(
            "1 advisory",
            advisories=[{"has_fix": True, "id": "CVE-1"}],
        )
        assert check.get_result_ttl(result, 3600) == 7200

    def test_npm_fail_unfixed_default_ttl(self) -> None:
        check = NpmAdvisoriesCheck.__new__(NpmAdvisoriesCheck)
        result = CheckResult.fail(
            "1 advisory",
            advisories=[{"has_fix": False, "id": "CVE-1"}],
        )
        assert check.get_result_ttl(result, 3600) == 3600

    def test_npm_fail_mixed_fix_default_ttl(self) -> None:
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

    def test_pypi_ok_short_ttl(self) -> None:
        check = PypiAdvisoriesCheck.__new__(PypiAdvisoriesCheck)
        result = CheckResult.ok("no advisories")
        assert check.get_result_ttl(result, 3600) == max(300, 3600 // 4)

    def test_pypi_fail_all_fixed(self) -> None:
        check = PypiAdvisoriesCheck.__new__(PypiAdvisoriesCheck)
        result = CheckResult.fail(
            "1 advisory",
            advisories=[{"has_fix": True, "id": "CVE-1"}],
        )
        assert check.get_result_ttl(result, 3600) == 7200


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


# ---------------------------------------------------------------------------
# Feature 2: get_with_freshness
# ---------------------------------------------------------------------------

class TestGetWithFreshness:
    def test_missing_key_returns_none(self) -> None:
        cache = TTLCache()
        assert cache.get_with_freshness("x") is None

    def test_expired_returns_none(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=10)
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 11):
            assert cache.get_with_freshness("key") is None

    def test_fresh_entry_not_near_expiry(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=100)
        # 50% remaining → not near expiry
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 50):
            result = cache.get_with_freshness("key")
            assert result is not None
            value, near_expiry = result
            assert value == "val"
            assert near_expiry is False

    def test_near_expiry_within_20_percent(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=100)
        # 15% remaining → near expiry
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 85):
            result = cache.get_with_freshness("key")
            assert result is not None
            _, near_expiry = result
            assert near_expiry is True

    def test_exactly_at_20_percent_not_near_expiry(self) -> None:
        cache = TTLCache()
        now = time.monotonic()
        with patch("vibewall.cache.store.time.monotonic", return_value=now):
            cache.set("key", "val", ttl=100)
        # Exactly 20% remaining → not near_expiry (< not <=)
        with patch("vibewall.cache.store.time.monotonic", return_value=now + 80):
            result = cache.get_with_freshness("key")
            assert result is not None
            _, near_expiry = result
            assert near_expiry is False

    def test_ttl_stored_in_entry(self) -> None:
        cache = TTLCache()
        cache.set("key", "val", ttl=42)
        assert cache._data["key"].ttl == 42.0


# ---------------------------------------------------------------------------
# Feature 2: Background cache refresh
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Feature 2: shutdown
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Feature 3: Background warn checks
# ---------------------------------------------------------------------------

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
