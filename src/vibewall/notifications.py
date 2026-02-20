from __future__ import annotations

import asyncio
import shutil


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

    async def notify_blocked(self, scope: str, target: str, reason: str) -> None:
        """Fire-and-forget notification for blocked requests."""
        if not await self._is_available():
            return
        asyncio.create_task(self._send(
            urgency="critical",
            summary=f"Blocked: {target}",
            body=reason,
        ))

    async def notify_warned(self, scope: str, target: str, warnings: list[str]) -> None:
        """Fire-and-forget notification for warned requests."""
        if not await self._is_available():
            return
        body = "\n".join(warnings)
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
