from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import structlog

from vibewall.config import VibewallConfig
from vibewall.llm.prompt import build_llm_prompt
from vibewall.models import CheckResult, CheckStatus

if TYPE_CHECKING:
    from vibewall.llm.client import LlmClient
    from vibewall.llm.history import HistoryEntry

logger = structlog.get_logger()

OnAsk = Callable[[str, str, CheckResult], Awaitable[bool]] | None


def maybe_downgrade(check_name: str, result: CheckResult, config: VibewallConfig) -> CheckResult:
    """Downgrade FAIL → SUS when the validator action is 'warn'.

    Note: ask-allow / ask-block actions are handled separately by ``maybe_ask``.
    """
    if result.status != CheckStatus.FAIL:
        return result
    vc = config.get_validator(check_name)
    action = result.data.get("action_override") or (vc.action if vc else "block")
    if action == "warn":
        return CheckResult(status=CheckStatus.SUS, reason=result.reason, data=result.data)
    return result


def is_ask_action(action: str) -> bool:
    """Return True if the action is an ask variant."""
    return action in ("ask-allow", "ask-block")


async def maybe_ask(
    check_name: str,
    target: str,
    result: CheckResult,
    config: VibewallConfig,
    on_ask: OnAsk,
) -> CheckResult:
    """Prompt user for ask-allow/ask-block FAILs.

    - ask-allow: default to SUS (allow) when no callback / exception / timeout
    - ask-block: default to FAIL (block) when no callback / exception / timeout
    In both cases, user approval → SUS, user denial → FAIL.
    """
    if result.status != CheckStatus.FAIL:
        return result
    vc = config.get_validator(check_name)
    action = result.data.get("action_override") or (vc.action if vc else "block")
    if not is_ask_action(action):
        return result

    allow_result = CheckResult(status=CheckStatus.SUS, reason=result.reason, data=result.data)
    block_result = result
    fallback = allow_result if action == "ask-allow" else block_result

    if on_ask is None:
        return fallback
    try:
        approved = await on_ask(check_name, target, result)
    except Exception:
        logger.exception("on_ask_callback_error", check=check_name)
        return fallback
    if approved:
        return allow_result
    return block_result


def is_ask_llm_action(action: str) -> bool:
    """Return True if the action is an ask-llm variant."""
    return action in ("ask-llm-allow", "ask-llm-block")


def _parse_llm_decision(response: str) -> str:
    """Extract decision from LLM response.

    Looks for ``DECISION: ALLOW|BLOCK|WARN`` on a line.  Returns empty
    string when the structured line is absent -- callers use this to
    apply the action-appropriate fallback.
    """
    for line in response.splitlines():
        m = re.match(r"^\s*DECISION:\s*(ALLOW|BLOCK|WARN)\b", line, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return ""


def _resolve_llm_per_check(
    name: str,
    result: CheckResult,
    decision: str,
    config: VibewallConfig,
) -> CheckResult:
    """Apply a single LLM decision to one check result."""
    vc = config.get_validator(name)
    action = result.data.get("action_override") or (vc.action if vc else "block")
    allow_result = CheckResult(status=CheckStatus.SUS, reason=result.reason, data=result.data)
    block_result = result
    fallback = allow_result if action == "ask-llm-allow" else block_result

    if decision == "ALLOW":
        return allow_result
    if decision == "BLOCK":
        return block_result
    if decision == "WARN":
        return allow_result
    # Empty / unrecognized → action-appropriate fallback
    return fallback


async def batch_ask_llm(
    scope: str,
    target: str,
    pending: list[tuple[str, CheckResult]],
    all_results: list[tuple[str, CheckResult]],
    config: VibewallConfig,
    llm_client: LlmClient | None,
    history: list[HistoryEntry] | None,
) -> tuple[str, list[tuple[str, CheckResult]]]:
    """Adjudicate all ask-llm-* FAILs in one LLM call.

    Makes a single LLM request with all check results and applies the
    decision to each pending item.  Falls back per-check on error or
    when no client is configured.

    Returns ``(decision, resolved)`` where *decision* is the raw LLM
    decision string (``"ALLOW"``, ``"BLOCK"``, ``"WARN"``, or ``""``
    for fallback/error) and *resolved* is the list of per-check results.
    """
    if not pending:
        return ("", [])

    def _fallbacks() -> tuple[str, list[tuple[str, CheckResult]]]:
        resolved = []
        for name, result in pending:
            resolved.append((name, _resolve_llm_per_check(name, result, "", config)))
        return ("", resolved)

    if llm_client is None:
        return _fallbacks()

    try:
        system_prompt, user_prompt = build_llm_prompt(
            scope, target, all_results, history,
        )
        response = await llm_client.ask(system_prompt, user_prompt)
        decision = _parse_llm_decision(response)
        logger.info(
            "llm_batch_decision",
            target=target,
            pending_checks=[n for n, _ in pending],
            decision=decision,
        )
        return (decision, [
            (name, _resolve_llm_per_check(name, result, decision, config))
            for name, result in pending
        ])
    except Exception:
        logger.exception("batch_ask_llm_error", target=target)
        return _fallbacks()
