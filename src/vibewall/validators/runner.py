from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import structlog

from vibewall.cache.store import TTLCache
from vibewall.config import VibewallConfig
from vibewall.exceptions import CheckError
from vibewall.models import CheckContext, CheckResult, CheckStatus, PipelineResult, RunResult
from vibewall.llm.history import HistoryEntry
from vibewall.validators.action import (
    resolve_llm_per_check,
    batch_ask_llm,
    is_ask_llm_action,
    maybe_ask,
    maybe_downgrade,
)
from vibewall.validators.base import BaseCheck
from vibewall.validators.checks import SCOPE_ORDER

if TYPE_CHECKING:
    from vibewall.llm.client import LlmClient
    from vibewall.llm.history import RequestHistory

logger = structlog.get_logger()


class _BgCounter:
    """Mutable counter that signals an event when it reaches zero."""

    __slots__ = ("_n", "_event")

    def __init__(self, event: asyncio.Event) -> None:
        self._n = 0
        self._event = event

    def inc(self) -> None:
        self._n += 1

    def dec(self) -> None:
        self._n -= 1
        if self._n <= 0:
            self._event.set()


OnCheckDone = Callable[[str, CheckResult | None], None] | None
OnAsk = Callable[[str, str, CheckResult], Awaitable[bool]] | None

# Checks whose FAIL result should short-circuit (stop further checks)
_BLOCKLIST_CHECKS = {"npm_rules", "pypi_rules", "url_rules"}
# Checks whose OK result should short-circuit (target is trusted)
_ALLOWLIST_CHECKS = {"npm_rules", "pypi_rules", "url_rules"}

class CheckRunner:
    def __init__(
        self,
        checks: list[BaseCheck],
        config: VibewallConfig,
        cache: TTLCache,
        llm_client: LlmClient | None = None,
        history: RequestHistory | None = None,
    ) -> None:
        self._checks = {c.name: c for c in checks}
        self._config = config
        self._cache = cache
        self._llm_client = llm_client
        self._history = history
        self._tg: asyncio.TaskGroup | None = None
        self._refreshing: set[str] = set()
        self._refresh_events: dict[str, asyncio.Event] = {}

    @property
    def is_running(self) -> bool:
        """Whether the runner's task group is active."""
        return self._tg is not None

    async def wait_for_refresh(self, check_name: str, target: str, timeout: float = 5.0) -> bool:
        """Wait for a background refresh to complete.

        Must be called after a ``run()`` that triggered the refresh.
        Returns True if a refresh was awaited, False if no refresh was pending.
        """
        cache_key = f"{check_name}:{target}"
        event = self._refresh_events.get(cache_key)
        if event is None:
            return False
        await asyncio.wait_for(event.wait(), timeout=timeout)
        return True

    async def start(self) -> None:
        """Initialize the background task group. Called at proxy startup."""
        self._tg = asyncio.TaskGroup()
        await self._tg.__aenter__()

    async def _ensure_started(self) -> asyncio.TaskGroup:
        """Lazily initialize the task group if not already started."""
        if self._tg is None:
            await self.start()
        return self._tg  # type: ignore[return-value]

    async def __aenter__(self) -> "CheckRunner":
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.shutdown()

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
        *,
        version: str | None = None,
        method: str | None = None,
        check_names: set[str] | None = None,
    ) -> PipelineResult:
        enabled = self._get_enabled_checks(scope)
        if check_names is not None:
            enabled = [c for c in enabled if c.name in check_names]
        if not enabled:
            return PipelineResult(
                run_result=RunResult(
                    allowed=True, reason="no checks configured", results=[]
                ),
            )

        timeout = self._config.pipeline_timeout
        try:
            return await asyncio.wait_for(
                self._run_checks(
                    scope, enabled, target, on_check_done, on_ask,
                    version=version, method=method,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.error(
                "pipeline_timeout", scope=scope, target=target,
                timeout=timeout,
            )
            return PipelineResult(
                run_result=RunResult(
                    allowed=True, reason="pipeline timed out, failing open", results=[]
                ),
            )

    async def _run_checks(
        self,
        scope: str,
        enabled: list[BaseCheck],
        target: str,
        on_check_done: OnCheckDone = None,
        on_ask: OnAsk = None,
        *,
        version: str | None = None,
        method: str | None = None,
    ) -> PipelineResult:
        all_enabled_names = {c.name for c in enabled}
        layers = self._topological_layers(enabled)
        bg_eligible = self._get_background_eligible(enabled)
        # context keeps raw results (dependencies need original FAIL status),
        # all_results keeps display results (FAIL downgraded to SUS for warns/asks).
        context = CheckContext(version=version, method=method)
        all_results: list[tuple[str, CheckResult]] = []
        completed_names: set[str] = set()
        bg_event: asyncio.Event | None = None
        bg_counter: _BgCounter | None = None
        # Set when an allowlist short-circuit fires; remaining layers are
        # filtered to only run checks with ignore_allowlist=True.
        allowlist_sc: tuple[str, CheckResult] | None = None

        for layer in layers:
            # When in allowlist mode, filter layer to ignore_allowlist checks only
            if allowlist_sc is not None:
                layer = [c for c in layer if self._has_ignore_allowlist(c.name)]
                if not layer:
                    continue

            # Check cache first
            to_run: list[BaseCheck] = []
            for check in layer:
                cache_key = f"{check.name}:{target}"
                hit = self._cache.get_with_freshness(cache_key)
                if hit is not None:
                    (raw, display), near_expiry = hit
                    # Background-eligible cached results are still included
                    # since they don't need re-running.
                    all_results.append((check.name, display))
                    context.add(check.name, raw)
                    completed_names.add(check.name)
                    self._notify(on_check_done, check.name, display)
                    if near_expiry:
                        await self._schedule_refresh(check, target, context)
                else:
                    to_run.append(check)

            # Split into sync and background checks
            to_run_sync = [c for c in to_run if c.name not in bg_eligible]
            to_run_bg = [c for c in to_run if c.name in bg_eligible]

            # Launch background warn checks
            for check in to_run_bg:
                if bg_event is None:
                    bg_event = asyncio.Event()
                    bg_counter = _BgCounter(bg_event)
                bg_counter.inc()
                await self._spawn_background_check(
                    check, target, context, on_check_done, bg_counter,
                )
                completed_names.add(check.name)

            if to_run_sync:
                results = await asyncio.gather(
                    *[check.run(target, context) for check in to_run_sync]
                )
                for check, result in zip(to_run_sync, results):
                    display = await maybe_ask(check.name, target, result, self._config, on_ask)
                    # Defer LLM decisions to post-loop batch; only
                    # downgrade non-LLM checks here.
                    if not self._is_llm_action(check.name, display):
                        display = maybe_downgrade(check.name, display, self._config)
                    all_results.append((check.name, display))
                    # Safe: add() is called sequentially after gather completes,
                    # never from within concurrent tasks.  See CheckContext docstring.
                    context.add(check.name, result)
                    completed_names.add(check.name)
                    ttl = self._get_result_ttl(check, result)
                    # Cache raw + pre-LLM display; LLM decisions are
                    # applied fresh each request via _apply_llm_decisions.
                    self._cache.set(f"{check.name}:{target}", (result, display), ttl)
                    self._notify(on_check_done, check.name, display)

            # Short-circuit evaluation after each layer (sync checks only)
            if allowlist_sc is None:
                for check in layer:
                    if check.name in bg_eligible:
                        continue
                    result = context.get(check.name)
                    if result is None:
                        continue
                    if self._should_short_circuit(check.name, result):
                        if check.name in _ALLOWLIST_CHECKS:
                            # Allowlist: continue but only run ignore_allowlist checks
                            allowlist_sc = (check.name, result)
                            # Signal skipped checks that won't run
                            for name in all_enabled_names - completed_names:
                                if not self._has_ignore_allowlist(name):
                                    self._notify(on_check_done, name, None)
                            break
                        else:
                            # Blocklist: immediate return (unchanged)
                            for name in all_enabled_names - completed_names:
                                self._notify(on_check_done, name, None)
                            run_result = self._finalize(all_results, short_circuit=(check.name, result))
                            self._record_history(scope, target, all_results, run_result)
                            return PipelineResult(run_result=run_result, background=bg_event)

        # Batch LLM adjudication after all sync checks complete
        all_results = await self._apply_llm_decisions(
            scope, target, all_results, on_check_done,
        )

        run_result = self._finalize(all_results, short_circuit=allowlist_sc)
        self._record_history(scope, target, all_results, run_result)
        return PipelineResult(run_result=run_result, background=bg_event)

    def _is_llm_action(self, check_name: str, result: CheckResult) -> bool:
        """Check if this result's action is an ask-llm-* variant."""
        if result.status != CheckStatus.FAIL:
            return False
        vc = self._config.get_validator(check_name)
        action = result.data.get("action_override") or (vc.action if vc else "block")
        return is_ask_llm_action(action)

    def _llm_cache_ttl(self) -> int:
        """Return the LLM decision cache TTL (0 = disabled)."""
        if self._config.llm is not None:
            return self._config.llm.cache_ttl
        return 0

    async def _apply_llm_decisions(
        self,
        scope: str,
        target: str,
        all_results: list[tuple[str, CheckResult]],
        on_check_done: OnCheckDone = None,
    ) -> list[tuple[str, CheckResult]]:
        """Collect ask-llm-* FAILs, make one LLM call, update results."""
        pending_indices: list[int] = []
        pending_items: list[tuple[str, CheckResult]] = []

        for i, (name, result) in enumerate(all_results):
            if self._is_llm_action(name, result):
                pending_indices.append(i)
                pending_items.append((name, result))

        if not pending_items:
            return all_results

        cache_key = f"llm:{scope}:{target}"
        ttl = self._llm_cache_ttl()

        # Check LLM decision cache
        cached_decision: str | None = None
        if ttl > 0:
            cached_decision = self._cache.get(cache_key)

        if cached_decision is not None:
            logger.info(
                "llm_cache_hit", target=target, decision=cached_decision,
            )
            resolved = [
                (name, resolve_llm_per_check(name, result, cached_decision, self._config))
                for name, result in pending_items
            ]
        else:
            decision, resolved = await batch_ask_llm(
                scope, target, pending_items, all_results,
                self._config, self._llm_client,
                self._history.recent() if self._history else None,
            )
            if ttl > 0 and decision:
                self._cache.set(cache_key, decision, ttl)

        updated = list(all_results)
        for idx, (name, new_result) in zip(pending_indices, resolved):
            new_result = maybe_downgrade(name, new_result, self._config)
            updated[idx] = (name, new_result)
            self._notify(on_check_done, name, new_result)
        return updated

    def _record_history(
        self,
        scope: str,
        target: str,
        all_results: list[tuple[str, CheckResult]],
        run_result: RunResult,
    ) -> None:
        if self._history is None:
            return
        self._history.add(HistoryEntry(
            scope=scope,
            target=target,
            results=tuple(all_results),
            outcome="allowed" if run_result.allowed else "blocked",
        ))

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

    def _get_base_ttl(self, check_name: str) -> int:
        vc = self._config.get_validator(check_name)
        if vc and vc.cache_ttl is not None:
            return vc.cache_ttl
        return self._config.cache.default_ttl

    def _get_result_ttl(self, check: BaseCheck, result: CheckResult) -> int:
        if result.status == CheckStatus.ERR:
            return self._config.cache.error_ttl
        base_ttl = self._get_base_ttl(check.name)
        return check.get_result_ttl(result, base_ttl)

    def _get_background_eligible(self, enabled: list[BaseCheck]) -> set[str]:
        """Identify checks eligible for background execution.

        A check is background-eligible when:
        (a) no other enabled check depends on it, AND
        (b) its action is ``"warn"`` (not block, ask-*, or ask-llm-*).
        """
        enabled_names = {c.name for c in enabled}
        depended_on: set[str] = set()
        for c in enabled:
            for dep in c.depends_on:
                if dep in enabled_names:
                    depended_on.add(dep)

        eligible: set[str] = set()
        for c in enabled:
            if c.name in depended_on:
                continue
            vc = self._config.get_validator(c.name)
            action = vc.action if vc else c.default_action
            if action == "warn":
                eligible.add(c.name)
        return eligible

    async def _spawn_background_check(
        self,
        check: BaseCheck,
        target: str,
        context: CheckContext,
        on_check_done: OnCheckDone,
        bg_counter: _BgCounter,
    ) -> asyncio.Task:  # type: ignore[type-arg]
        """Run a single warn check in the background."""
        async def _do_bg() -> None:
            try:
                result = await check.run(target, context)
                display = maybe_downgrade(check.name, result, self._config)
                ttl = self._get_result_ttl(check, result)
                self._cache.set(f"{check.name}:{target}", (result, display), ttl)
                self._notify(on_check_done, check.name, display)
            except CheckError:
                logger.exception("background_check_error", check=check.name, target=target)
                err = CheckResult.err(f"{check.name} raised an exception")
                display = maybe_downgrade(check.name, err, self._config)
                ttl = self._get_result_ttl(check, err)
                self._cache.set(f"{check.name}:{target}", (err, display), ttl)
                self._notify(on_check_done, check.name, display)
            except Exception:
                logger.exception("background_check_error", check=check.name, target=target)
                err = CheckResult.err(f"{check.name} raised an exception")
                display = maybe_downgrade(check.name, err, self._config)
                ttl = self._get_result_ttl(check, err)
                self._cache.set(f"{check.name}:{target}", (err, display), ttl)
                self._notify(on_check_done, check.name, display)
            finally:
                bg_counter.dec()

        tg = await self._ensure_started()
        return tg.create_task(_do_bg())

    async def _schedule_refresh(
        self, check: BaseCheck, target: str, context: CheckContext,
    ) -> None:
        """Spawn a background task to refresh a near-expiry cache entry."""
        cache_key = f"{check.name}:{target}"
        if cache_key in self._refreshing:
            return
        self._refreshing.add(cache_key)
        event = asyncio.Event()
        self._refresh_events[cache_key] = event
        refresh_ctx = CheckContext(version=context.version)

        async def _do_refresh() -> None:
            try:
                result = await check.run(target, refresh_ctx)
                display = maybe_downgrade(check.name, result, self._config)
                ttl = self._get_result_ttl(check, result)
                self._cache.set(cache_key, (result, display), ttl)
            except CheckError:
                logger.exception("background_refresh_error", check=check.name, target=target)
                err = CheckResult.err(f"{check.name} raised an exception")
                display = maybe_downgrade(check.name, err, self._config)
                ttl = self._get_result_ttl(check, err)
                self._cache.set(cache_key, (err, display), ttl)
            except Exception:
                logger.exception("background_refresh_error", check=check.name, target=target)
                err = CheckResult.err(f"{check.name} raised an exception")
                display = maybe_downgrade(check.name, err, self._config)
                ttl = self._get_result_ttl(check, err)
                self._cache.set(cache_key, (err, display), ttl)
            finally:
                self._refreshing.discard(cache_key)
                event.set()
                self._refresh_events.pop(cache_key, None)

        tg = await self._ensure_started()
        tg.create_task(_do_refresh())

    async def shutdown(self) -> None:
        """Cancel all background tasks and shut down the task group."""
        if self._tg is not None:
            try:
                await self._tg.__aexit__(
                    type(asyncio.CancelledError()),
                    asyncio.CancelledError(),
                    None,
                )
            except BaseException:
                pass
            self._tg = None
        self._refreshing.clear()
        self._refresh_events.clear()

    def _has_ignore_allowlist(self, check_name: str) -> bool:
        """Return True if the check's config has ignore_allowlist enabled."""
        vc = self._config.get_validator(check_name)
        if vc is not None:
            return vc.ignore_allowlist
        return False

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
                # Check if any ignore_allowlist check returned FAIL,
                # which overrides the allowlist decision
                blocking_reasons = [
                    r.reason for name, r in results
                    if r.status == CheckStatus.FAIL and self._has_ignore_allowlist(name)
                ]
                if blocking_reasons:
                    warn_reasons = [r.reason for _, r in results if r.status == CheckStatus.SUS]
                    error_reasons = [r.reason for _, r in results if r.status == CheckStatus.ERR]
                    return RunResult(
                        allowed=False, reason=blocking_reasons[0],
                        results=results, warnings=warn_reasons, errors=error_reasons,
                    )
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
