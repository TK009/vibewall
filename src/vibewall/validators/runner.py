from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import structlog

from vibewall.cache.store import TTLCache
from vibewall.config import VibewallConfig
from vibewall.models import CheckContext, CheckResult, CheckStatus, RunResult
from vibewall.validators.action import maybe_ask, maybe_downgrade
from vibewall.validators.base import BaseCheck
from vibewall.validators.checks import SCOPE_ORDER

logger = structlog.get_logger()

OnCheckDone = Callable[[str, CheckResult | None], None] | None
OnAsk = Callable[[str, str, CheckResult], Awaitable[bool]] | None

# Checks whose FAIL result should short-circuit (stop further checks)
_BLOCKLIST_CHECKS = {"npm_blocklist", "url_blocklist"}
# Checks whose OK result should short-circuit (target is trusted)
_ALLOWLIST_CHECKS = {"npm_allowlist", "url_allowlist"}

class CheckRunner:
    def __init__(
        self,
        checks: list[BaseCheck],
        config: VibewallConfig,
        cache: TTLCache,
    ) -> None:
        self._checks = {c.name: c for c in checks}
        self._config = config
        self._cache = cache

    def get_enabled_check_names(self, scope: str) -> list[str]:
        """Return ordered list of enabled check names for a scope."""
        enabled = self._get_enabled_checks(scope)
        order = SCOPE_ORDER.get(scope, [])
        names = {c.name for c in enabled}
        return [n for n in order if n in names]

    async def run(
        self,
        scope: str,
        target: str,
        on_check_done: OnCheckDone = None,
        on_ask: OnAsk = None,
    ) -> RunResult:
        enabled = self._get_enabled_checks(scope)
        if not enabled:
            return RunResult(
                allowed=True, reason="no checks configured", results=[]
            )

        timeout = self._config.pipeline_timeout
        try:
            return await asyncio.wait_for(
                self._run_checks(enabled, target, on_check_done, on_ask),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.error(
                "pipeline_timeout", scope=scope, target=target,
                timeout=timeout,
            )
            return RunResult(
                allowed=True, reason="pipeline timed out, failing open", results=[]
            )

    async def _run_checks(
        self,
        enabled: list[BaseCheck],
        target: str,
        on_check_done: OnCheckDone = None,
        on_ask: OnAsk = None,
    ) -> RunResult:
        all_enabled_names = {c.name for c in enabled}
        layers = self._topological_layers(enabled)
        # context keeps raw results (dependencies need original FAIL status),
        # all_results keeps display results (FAIL downgraded to SUS for warns/asks).
        context = CheckContext()
        all_results: list[tuple[str, CheckResult]] = []
        completed_names: set[str] = set()

        for layer in layers:
            # Check cache first
            to_run: list[BaseCheck] = []
            for check in layer:
                cached = self._cache.get(f"{check.name}:{target}")
                if cached is not None:
                    raw, display = cached
                    all_results.append((check.name, display))
                    context.add(check.name, raw)
                    completed_names.add(check.name)
                    self._notify(on_check_done, check.name, display)
                else:
                    to_run.append(check)

            if to_run:
                results = await asyncio.gather(
                    *[check.run(target, context) for check in to_run]
                )
                for check, result in zip(to_run, results):
                    display = await maybe_ask(check.name, target, result, self._config, on_ask)
                    display = maybe_downgrade(check.name, display, self._config)
                    all_results.append((check.name, display))
                    context.add(check.name, result)
                    completed_names.add(check.name)
                    ttl = self._get_ttl(check.name)
                    # Cache both raw and display: raw is needed by
                    # dependent checks via context, display is the
                    # post-decision result (approved asks cached as SUS).
                    self._cache.set(f"{check.name}:{target}", (result, display), ttl)
                    self._notify(on_check_done, check.name, display)

            # Short-circuit evaluation after each layer
            for check in layer:
                result = context.get(check.name)
                if result is None:
                    continue
                if self._should_short_circuit(check.name, result):
                    # Signal skipped checks
                    for name in all_enabled_names - completed_names:
                        self._notify(on_check_done, name, None)
                    return self._finalize(all_results, short_circuit=(check.name, result))

        return self._finalize(all_results)

    @staticmethod
    def _notify(
        on_check_done: OnCheckDone,
        name: str,
        result: CheckResult | None,
    ) -> None:
        if on_check_done is None:
            return
        try:
            on_check_done(name, result)
        except Exception:
            logger.exception("on_check_done_callback_error", check=name)

    def _get_enabled_checks(self, scope: str) -> list[BaseCheck]:
        """Get checks for the given scope that are enabled or needed as deps."""
        # First, find explicitly enabled checks for this scope
        enabled_names: set[str] = set()
        for name, check in self._checks.items():
            if check.scope != scope:
                continue
            if self._config.is_enabled(name):
                enabled_names.add(name)

        # Then add any dependencies that enabled checks need
        to_process = list(enabled_names)
        while to_process:
            name = to_process.pop()
            check = self._checks.get(name)
            if check is None:
                continue
            for dep in check.depends_on:
                if dep not in enabled_names and dep in self._checks:
                    enabled_names.add(dep)
                    to_process.append(dep)

        return [self._checks[n] for n in enabled_names if n in self._checks]

    def _topological_layers(self, checks: list[BaseCheck]) -> list[list[BaseCheck]]:
        """Sort checks into execution layers via Kahn's algorithm."""
        check_map = {c.name: c for c in checks}
        names = set(check_map.keys())

        # Compute in-degree (only count deps that are in our check set)
        in_degree: dict[str, int] = {}
        for c in checks:
            in_degree[c.name] = sum(1 for d in c.depends_on if d in names)

        layers: list[list[BaseCheck]] = []
        remaining = set(names)

        while remaining:
            layer_names = [n for n in remaining if in_degree[n] == 0]
            if not layer_names:
                # Cycle detected — this indicates a programming bug in check dependencies
                logger.error(
                    "check_dependency_cycle",
                    remaining=[check_map[n].name for n in remaining],
                )
                layers.append([check_map[n] for n in remaining])
                break

            layers.append([check_map[n] for n in layer_names])
            for n in layer_names:
                remaining.discard(n)
            # Recompute in-degree for remaining nodes
            for n in remaining:
                in_degree[n] = sum(
                    1 for d in check_map[n].depends_on if d in remaining
                )

        return layers

    def _get_ttl(self, check_name: str) -> int:
        vc = self._config.get_validator(check_name)
        if vc and vc.cache_ttl is not None:
            return vc.cache_ttl
        return self._config.cache.default_ttl

    def _should_short_circuit(self, check_name: str, result: CheckResult) -> bool:
        # Blocklist FAIL → stop immediately
        if check_name in _BLOCKLIST_CHECKS and result.status == CheckStatus.FAIL:
            return True
        # Allowlist OK → stop (target is trusted)
        if check_name in _ALLOWLIST_CHECKS and result.status == CheckStatus.OK:
            if result.data.get("allowlisted", False):
                return True
        return False

    def _finalize(
        self,
        results: list[tuple[str, CheckResult]],
        short_circuit: tuple[str, CheckResult] | None = None,
    ) -> RunResult:
        """Convert individual results into a final allow/block decision."""
        # If short-circuited by allowlist/blocklist, use that as the reason
        if short_circuit is not None:
            sc_name, sc_result = short_circuit
            if sc_name in _BLOCKLIST_CHECKS and sc_result.status == CheckStatus.FAIL:
                return RunResult(
                    allowed=False, reason=sc_result.reason, results=results
                )
            if sc_name in _ALLOWLIST_CHECKS:
                return RunResult(
                    allowed=True, reason=sc_result.reason, results=results
                )

        blocking_reasons: list[str] = []
        warn_reasons: list[str] = []
        error_reasons: list[str] = []

        for name, result in results:
            if result.status == CheckStatus.FAIL:
                blocking_reasons.append(result.reason)
            elif result.status == CheckStatus.SUS:
                warn_reasons.append(result.reason)
            elif result.status == CheckStatus.ERR:
                error_reasons.append(result.reason)

        if blocking_reasons:
            return RunResult(
                allowed=False,
                reason=blocking_reasons[0],
                results=results,
                warnings=warn_reasons,
                errors=error_reasons,
            )

        reason = "all checks passed"
        for name, result in reversed(results):
            if result.status == CheckStatus.OK:
                reason = result.reason
                break

        return RunResult(
            allowed=True,
            reason=reason,
            results=results,
            warnings=warn_reasons,
            errors=error_reasons,
        )
