from __future__ import annotations

import asyncio
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vibewall.models import CheckResult

# Severity ordering for notification display
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}

# Data keys to skip in notification body (already in reason string or internal)
_SKIP_DATA_KEYS = {
    "action_override", "advisories",  # handled specially
    "registry_data", "status_code",   # internal/bulk data
    "allowlisted",                    # internal routing flag
}


def _format_check_details(results: list[tuple[str, CheckResult]]) -> str:
    """Build a notification body from check results, including advisory details."""
    from vibewall.models import CheckStatus

    lines: list[str] = []
    for name, cr in results:
        if cr.status in (CheckStatus.OK, CheckStatus.ERR):
            continue

        lines.append(f"{name}: {cr.reason}")

        if not cr.data:
            continue

        advisories = cr.data.get("advisories")
        if advisories and isinstance(advisories, list):
            for adv in advisories:
                sev = adv.get("severity", "UNKNOWN").upper()
                vuln_id = adv.get("id", "unknown")
                summary = adv.get("summary", "")
                line = f"  [{sev}] {vuln_id}"
                if summary:
                    line += f" — {summary}"
                lines.append(line)

        for key, value in cr.data.items():
            if key in _SKIP_DATA_KEYS:
                continue
            lines.append(f"  {key}: {value}")

    return "\n".join(lines)


class Notifier:
    """Desktop notifications via notify-send for blocked, warned, and ask-mode requests."""

    def __init__(self, enabled: bool = True, expire_ms: int = 10000) -> None:
        self._available: bool | None = None  # lazy detect
        self._enabled = enabled
        self._expire_ms = expire_ms

    async def _is_available(self) -> bool:
        """Check once if notify-send is on PATH (cache result)."""
        if self._available is None:
            self._available = shutil.which("notify-send") is not None
        return self._available and self._enabled

    async def notify_blocked(
        self,
        scope: str,
        target: str,
        reason: str,
        results: list[tuple[str, CheckResult]] | None = None,
    ) -> None:
        """Fire-and-forget notification for blocked requests."""
        if not await self._is_available():
            return
        body = _format_check_details(results) if results else reason
        asyncio.create_task(self._send(
            urgency="critical",
            summary=f"Blocked: {target}",
            body=body,
        ))

    async def notify_warned(
        self,
        scope: str,
        target: str,
        warnings: list[str],
        results: list[tuple[str, CheckResult]] | None = None,
    ) -> None:
        """Fire-and-forget notification for warned requests."""
        if not await self._is_available():
            return
        body = _format_check_details(results) if results else "\n".join(warnings)
        asyncio.create_task(self._send(
            urgency="normal",
            summary=f"Warning: {target}",
            body=body,
        ))

    async def prompt_ask(self, check_name: str, target: str, reason: str) -> bool | None:
        """Interactive notification with Allow/Block buttons.

        Returns True (allow), False (block), or None (dismissed/timeout).
        Uses --action and --wait so notify-send blocks until user clicks.
        """
        if not await self._is_available():
            return None
        proc = await asyncio.create_subprocess_exec(
            "notify-send",
            "--app-name=vibewall",
            "--urgency=critical",
            f"--expire-time={self._expire_ms}",
            "--action=allow=Allow",
            "--action=block=Block",
            "--wait",
            f"Ask: {target}",
            f"{check_name}: {reason}",
            stdout=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        action = stdout.decode().strip() if stdout else ""
        if action == "allow":
            return True
        elif action == "block":
            return False
        return None  # dismissed or timeout

    async def _send(self, urgency: str, summary: str, body: str) -> None:
        """Run notify-send as async subprocess. Errors are silently ignored."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "notify-send",
                "--app-name=vibewall",
                f"--urgency={urgency}",
                f"--expire-time={self._expire_ms}",
                summary,
                body,
            )
            await proc.wait()
        except Exception:
            pass
