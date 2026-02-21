from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import structlog

from vibewall.config import VibewallConfig
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

    Looks for ``DECISION: ALLOW|BLOCK|WARN`` on a line, falls back to
    keyword scanning.
    """
    for line in response.splitlines():
        m = re.match(r"^\s*DECISION:\s*(ALLOW|BLOCK|WARN)\b", line, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    # Keyword fallback
    upper = response.upper()
    if "BLOCK" in upper:
        return "BLOCK"
    if "ALLOW" in upper:
        return "ALLOW"
    if "WARN" in upper:
        return "WARN"
    return ""


async def maybe_ask_llm(
    check_name: str,
    target: str,
    scope: str,
    result: CheckResult,
    all_results: list[tuple[str, CheckResult]],
    config: VibewallConfig,
    llm_client: LlmClient | None,
    history: list[HistoryEntry] | None,
) -> CheckResult:
    """Delegate allow/block decision to an LLM for ask-llm-* actions.

    - ask-llm-allow: on LLM/error fallback → SUS (allow)
    - ask-llm-block: on LLM/error fallback → FAIL (block)
    LLM ALLOW → SUS, BLOCK → FAIL, WARN → SUS.
    """
    if result.status != CheckStatus.FAIL:
        return result
    vc = config.get_validator(check_name)
    action = result.data.get("action_override") or (vc.action if vc else "block")
    if not is_ask_llm_action(action):
        return result

    allow_result = CheckResult(status=CheckStatus.SUS, reason=result.reason, data=result.data)
    block_result = result
    fallback = allow_result if action == "ask-llm-allow" else block_result

    if llm_client is None:
        return fallback

    try:
        from vibewall.llm.prompt import build_llm_prompt

        system_prompt, user_prompt = build_llm_prompt(
            scope, target, all_results, history,
        )
        response = await llm_client.ask(system_prompt, user_prompt)
        decision = _parse_llm_decision(response)
        logger.info(
            "llm_decision",
            check=check_name,
            target=target,
            decision=decision,
        )
        if decision == "ALLOW":
            return allow_result
        if decision == "BLOCK":
            return block_result
        # WARN or unrecognized → treat as SUS
        return allow_result
    except Exception:
        logger.exception("ask_llm_error", check=check_name, target=target)
        return fallback
