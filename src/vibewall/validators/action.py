from __future__ import annotations

from collections.abc import Awaitable, Callable

import structlog

from vibewall.config import VibewallConfig
from vibewall.models import CheckResult, CheckStatus

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
