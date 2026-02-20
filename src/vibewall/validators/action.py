from __future__ import annotations

from collections.abc import Awaitable, Callable

import structlog

from vibewall.config import VibewallConfig
from vibewall.models import CheckResult, CheckStatus

logger = structlog.get_logger()

OnAsk = Callable[[str, str, CheckResult], Awaitable[bool]] | None


def maybe_downgrade(check_name: str, result: CheckResult, config: VibewallConfig) -> CheckResult:
    """Downgrade FAIL → SUS when the validator action is 'warn'."""
    if result.status != CheckStatus.FAIL:
        return result
    vc = config.get_validator(check_name)
    action = result.data.get("action_override") or (vc.action if vc else "block")
    if action == "warn":
        return CheckResult(status=CheckStatus.SUS, reason=result.reason, data=result.data)
    return result


async def maybe_ask(
    check_name: str,
    target: str,
    result: CheckResult,
    config: VibewallConfig,
    on_ask: OnAsk,
) -> CheckResult:
    """Prompt user for action='ask' FAILs. Returns SUS if approved, FAIL if denied."""
    if result.status != CheckStatus.FAIL:
        return result
    vc = config.get_validator(check_name)
    action = result.data.get("action_override") or (vc.action if vc else "block")
    if action != "ask":
        return result
    if on_ask is None:
        # No interactive mode (no TTY / no display) → treat as block
        return result
    try:
        approved = await on_ask(check_name, target, result)
    except Exception:
        logger.exception("on_ask_callback_error", check=check_name)
        return result
    if approved:
        return CheckResult(status=CheckStatus.SUS, reason=result.reason, data=result.data)
    return result
